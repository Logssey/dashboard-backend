package com.logssey.runtime.operations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RuntimeOperationsRepository {

    private static final long MAINTENANCE_LOCK_ID = 4_921_870_301L;

    private final JdbcClient jdbcClient;

    public RuntimeOperationsRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("""
                        SELECT user_id FROM dashboard_users
                        WHERE login_id = :loginId AND role = 'ADMIN'
                        """)
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    public boolean acquireMaintenanceLock() {
        return jdbcClient.sql("SELECT pg_try_advisory_xact_lock(:lockId)")
                .param("lockId", MAINTENANCE_LOCK_ID)
                .query(Boolean.class)
                .single();
    }

    public long purgeDuePayloads(int batchSize) {
        return jdbcClient.sql("""
                        WITH due AS (
                            SELECT raw_event_id
                            FROM runtime_raw_events
                            WHERE payload_purged_at IS NULL
                              AND payload_retention_until <= CURRENT_TIMESTAMP
                            ORDER BY payload_retention_until, raw_event_id
                            LIMIT :batchSize
                            FOR UPDATE SKIP LOCKED
                        ), purged AS (
                            UPDATE runtime_raw_events raw
                            SET payload = jsonb_build_object(
                                    'purged', true,
                                    'sha256', raw.payload_sha256,
                                    'purgedAt', CURRENT_TIMESTAMP),
                                masked_fields = '[]'::jsonb,
                                payload_purged_at = CURRENT_TIMESTAMP
                            FROM due
                            WHERE raw.raw_event_id = due.raw_event_id
                            RETURNING raw.raw_event_id
                        )
                        SELECT count(*) FROM purged
                        """)
                .param("batchSize", batchSize)
                .query(Long.class)
                .single();
    }

    public long deleteRateWindowsBefore(Instant cutoff) {
        return jdbcClient.sql("""
                        DELETE FROM runtime_ingest_rate_windows
                        WHERE window_started_at < :cutoff
                        """)
                .param("cutoff", utc(cutoff))
                .update();
    }

    public long payloadBacklog() {
        return jdbcClient.sql("""
                        SELECT count(*) FROM runtime_raw_events
                        WHERE payload_purged_at IS NULL
                          AND payload_retention_until <= CURRENT_TIMESTAMP
                        """)
                .query(Long.class)
                .single();
    }

    public Instant oldestDuePayload() {
        OffsetDateTime value = jdbcClient.sql("""
                        SELECT min(payload_retention_until) FROM runtime_raw_events
                        WHERE payload_purged_at IS NULL
                          AND payload_retention_until <= CURRENT_TIMESTAMP
                        """)
                .query(OffsetDateTime.class)
                .optional()
                .orElse(null);
        return value == null ? null : value.toInstant();
    }

    public OperationalCounts countsSince(Instant since) {
        return jdbcClient.sql("""
                        WITH raw AS (
                            SELECT count(*) AS stored,
                                   count(*) FILTER (WHERE processing_status = 'GROUPED') AS grouped,
                                   count(*) FILTER (WHERE processing_status = 'SUPPRESSED') AS suppressed,
                                   count(*) FILTER (WHERE processing_status = 'IGNORED') AS ignored,
                                   count(*) FILTER (WHERE processing_status = 'FAILED') AS failed
                            FROM runtime_raw_events
                            WHERE received_at >= :since
                        ), limited AS (
                            SELECT COALESCE(sum(rate_limited_count), 0) AS rate_limited
                            FROM runtime_ingest_rate_windows
                            WHERE updated_at >= :since
                        )
                        SELECT raw.stored + limited.rate_limited AS received,
                               raw.grouped,
                               raw.suppressed,
                               limited.rate_limited,
                               raw.ignored,
                               raw.failed
                        FROM raw CROSS JOIN limited
                        """)
                .param("since", utc(since))
                .query((rs, rowNum) -> new OperationalCounts(
                        rs.getLong("received"), rs.getLong("grouped"), rs.getLong("suppressed"),
                        rs.getLong("rate_limited"), rs.getLong("ignored"), rs.getLong("failed")))
                .single();
    }

    public void recordMaintenance(String triggeredBy, Long actorUserId, long payloadsPurged,
                                  long rateWindowsDeleted, long remainingBacklog,
                                  Instant startedAt, Instant completedAt) {
        jdbcClient.sql("""
                        INSERT INTO runtime_maintenance_runs
                            (job_type, triggered_by, actor_user_id, payloads_purged,
                             rate_windows_deleted, remaining_payload_backlog, started_at, completed_at)
                        VALUES
                            ('RETENTION', :triggeredBy, :actorUserId, :payloadsPurged,
                             :rateWindowsDeleted, :remainingBacklog, :startedAt, :completedAt)
                        """)
                .param("triggeredBy", triggeredBy)
                .param("actorUserId", actorUserId)
                .param("payloadsPurged", payloadsPurged)
                .param("rateWindowsDeleted", rateWindowsDeleted)
                .param("remainingBacklog", remainingBacklog)
                .param("startedAt", utc(startedAt))
                .param("completedAt", utc(completedAt))
                .update();
    }

    public Optional<MaintenanceRun> lastMaintenance() {
        return jdbcClient.sql("""
                        SELECT completed_at, payloads_purged, rate_windows_deleted, remaining_payload_backlog
                        FROM runtime_maintenance_runs
                        WHERE job_type = 'RETENTION'
                        ORDER BY completed_at DESC, maintenance_run_id DESC
                        LIMIT 1
                        """)
                .query((rs, rowNum) -> maintenance(rs))
                .optional();
    }

    private static MaintenanceRun maintenance(ResultSet rs) throws SQLException {
        return new MaintenanceRun(
                rs.getObject("completed_at", OffsetDateTime.class).toInstant(),
                rs.getLong("payloads_purged"), rs.getLong("rate_windows_deleted"),
                rs.getLong("remaining_payload_backlog"));
    }

    private static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    public record OperationalCounts(long received, long grouped, long suppressed,
                                    long rateLimited, long ignored, long failed) {
    }

    public record MaintenanceRun(Instant completedAt, long payloadsPurged,
                                 long rateWindowsDeleted, long remainingPayloadBacklog) {
    }
}
