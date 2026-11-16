package com.logssey.compliance;

import static com.logssey.compliance.ComplianceJobDtos.ClaimedJob;
import static com.logssey.compliance.ComplianceJobDtos.JobSummary;
import static com.logssey.compliance.ComplianceJobDtos.ScanScope;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Repository
public class ComplianceJobRepository {

    private static final String JOB_COLUMNS = """
            job_id, environment, provider, status, scope::text AS scope_json,
            attempt_count, max_attempts, requested_by_login, error_code, run_id,
            created_at, started_at, finished_at
            """;

    private final JdbcClient jdbc;
    private final JsonMapper json = JsonMapper.builder().build();

    public ComplianceJobRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    long insert(String targetKey, String environment, ScanScope scope, String requestedBy) {
        return jdbc.sql("""
                        INSERT INTO compliance_scan_jobs
                            (target_key, environment, provider, status, scope, requested_by_login)
                        VALUES (:targetKey, :environment, 'aws', 'QUEUED', CAST(:scope AS jsonb), :requestedBy)
                        RETURNING job_id
                        """)
                .param("targetKey", targetKey)
                .param("environment", environment)
                .param("scope", writeScope(scope))
                .param("requestedBy", requestedBy)
                .query(Long.class)
                .single();
    }

    List<JobSummary> jobs(String targetKey, int limit) {
        return jdbc.sql("SELECT " + JOB_COLUMNS + " FROM compliance_scan_jobs "
                        + "WHERE target_key = :targetKey ORDER BY created_at DESC, job_id DESC LIMIT :limit")
                .param("targetKey", targetKey)
                .param("limit", limit)
                .query(this::jobRow)
                .list();
    }

    Optional<JobSummary> job(String targetKey, long jobId) {
        return jdbc.sql("SELECT " + JOB_COLUMNS + " FROM compliance_scan_jobs "
                        + "WHERE target_key = :targetKey AND job_id = :jobId")
                .param("targetKey", targetKey)
                .param("jobId", jobId)
                .query(this::jobRow)
                .optional();
    }

    boolean cancel(String targetKey, long jobId) {
        return jdbc.sql("""
                        UPDATE compliance_scan_jobs
                        SET status = 'CANCELLED', finished_at = clock_timestamp(), error_code = NULL,
                            lease_token = NULL, lease_until = NULL, worker_id = NULL
                        WHERE target_key = :targetKey AND job_id = :jobId
                          AND status IN ('QUEUED', 'LEASED')
                        """)
                .param("targetKey", targetKey)
                .param("jobId", jobId)
                .update() == 1;
    }

    void failExhaustedLeases(String targetKey) {
        jdbc.sql("""
                        UPDATE compliance_scan_jobs
                        SET status = 'FAILED', error_code = 'LEASE_EXPIRED', finished_at = clock_timestamp(),
                            lease_token = NULL, lease_until = NULL, worker_id = NULL
                        WHERE target_key = :targetKey AND status = 'LEASED'
                          AND lease_until <= clock_timestamp() AND attempt_count >= max_attempts
                        """)
                .param("targetKey", targetKey)
                .update();
    }

    Optional<ClaimedJob> claim(String targetKey, String workerId, UUID token, int leaseSeconds,
                               String prowlerVersion) {
        return jdbc.sql("""
                        WITH candidate AS (
                            SELECT job_id
                            FROM compliance_scan_jobs
                            WHERE target_key = :targetKey
                              AND available_at <= clock_timestamp()
                              AND attempt_count < max_attempts
                              AND (status = 'QUEUED'
                                   OR (status = 'LEASED' AND lease_until <= clock_timestamp()))
                            ORDER BY available_at, job_id
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                        )
                        UPDATE compliance_scan_jobs job
                        SET status = 'LEASED', attempt_count = attempt_count + 1,
                            lease_token = :token, lease_generation = lease_generation + 1,
                            lease_until = clock_timestamp() + make_interval(secs => :leaseSeconds),
                            worker_id = :workerId, started_at = COALESCE(started_at, clock_timestamp()),
                            error_code = NULL
                        FROM candidate
                        WHERE job.job_id = candidate.job_id
                        RETURNING job.job_id, job.environment, job.scope::text AS scope_json,
                                  job.lease_token, job.lease_generation, job.lease_until
                        """)
                .param("targetKey", targetKey)
                .param("token", token)
                .param("leaseSeconds", leaseSeconds)
                .param("workerId", workerId)
                .query((rs, row) -> new ClaimedJob(
                        rs.getLong("job_id"), rs.getString("environment"), readScope(rs.getString("scope_json")),
                        rs.getObject("lease_token", UUID.class), rs.getLong("lease_generation"),
                        rs.getObject("lease_until", OffsetDateTime.class), prowlerVersion))
                .optional();
    }

    Optional<OffsetDateTime> heartbeat(long jobId, UUID token, long generation, int leaseSeconds) {
        return jdbc.sql("""
                        UPDATE compliance_scan_jobs
                        SET lease_until = clock_timestamp() + make_interval(secs => :leaseSeconds)
                        WHERE job_id = :jobId AND status = 'LEASED' AND lease_token = :token
                          AND lease_generation = :generation AND lease_until > clock_timestamp()
                        RETURNING lease_until
                        """)
                .param("jobId", jobId)
                .param("token", token)
                .param("generation", generation)
                .param("leaseSeconds", leaseSeconds)
                .query(OffsetDateTime.class)
                .optional();
    }

    Optional<LockedJob> lockLease(long jobId, UUID token, long generation) {
        return jdbc.sql("""
                        SELECT job_id, environment, requested_by_login, attempt_count, max_attempts
                        FROM compliance_scan_jobs
                        WHERE job_id = :jobId AND status = 'LEASED' AND lease_token = :token
                          AND lease_generation = :generation AND lease_until > clock_timestamp()
                        FOR UPDATE
                        """)
                .param("jobId", jobId)
                .param("token", token)
                .param("generation", generation)
                .query((rs, row) -> new LockedJob(rs.getLong("job_id"), rs.getString("environment"),
                        rs.getString("requested_by_login"), rs.getInt("attempt_count"), rs.getInt("max_attempts")))
                .optional();
    }

    void succeed(long jobId, long runId) {
        jdbc.sql("""
                        UPDATE compliance_scan_jobs
                        SET status = 'SUCCEEDED', run_id = :runId, finished_at = clock_timestamp(),
                            lease_token = NULL, lease_until = NULL, worker_id = NULL, error_code = NULL
                        WHERE job_id = :jobId AND status = 'LEASED'
                        """)
                .param("jobId", jobId)
                .param("runId", runId)
                .update();
    }

    void failOrRetry(long jobId, boolean retry, String errorCode, int retryDelaySeconds) {
        if (retry) {
            jdbc.sql("""
                            UPDATE compliance_scan_jobs
                            SET status = 'QUEUED', error_code = :errorCode,
                                available_at = clock_timestamp() + make_interval(secs => :retryDelaySeconds),
                                lease_token = NULL, lease_until = NULL, worker_id = NULL
                            WHERE job_id = :jobId AND status = 'LEASED'
                            """)
                    .param("jobId", jobId)
                    .param("errorCode", errorCode)
                    .param("retryDelaySeconds", retryDelaySeconds)
                    .update();
        } else {
            jdbc.sql("""
                            UPDATE compliance_scan_jobs
                            SET status = 'FAILED', error_code = :errorCode, finished_at = clock_timestamp(),
                                lease_token = NULL, lease_until = NULL, worker_id = NULL
                            WHERE job_id = :jobId AND status = 'LEASED'
                            """)
                    .param("jobId", jobId)
                    .param("errorCode", errorCode)
                    .update();
        }
    }

    private JobSummary jobRow(ResultSet rs, int row) throws SQLException {
        long runId = rs.getLong("run_id");
        Long nullableRunId = rs.wasNull() ? null : runId;
        return new JobSummary(rs.getLong("job_id"), rs.getString("environment"), rs.getString("provider"),
                rs.getString("status"), readScope(rs.getString("scope_json")), rs.getInt("attempt_count"),
                rs.getInt("max_attempts"), rs.getString("requested_by_login"), rs.getString("error_code"),
                nullableRunId, rs.getObject("created_at", OffsetDateTime.class),
                rs.getObject("started_at", OffsetDateTime.class), rs.getObject("finished_at", OffsetDateTime.class));
    }

    private String writeScope(ScanScope scope) {
        try {
            return json.writeValueAsString(scope);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("점검 범위를 직렬화할 수 없습니다.", e);
        }
    }

    private ScanScope readScope(String value) {
        try {
            return json.readValue(value, ScanScope.class);
        } catch (JacksonException e) {
            throw new IllegalStateException("저장된 점검 범위를 읽을 수 없습니다.", e);
        }
    }

    record LockedJob(long jobId, String environment, String requestedBy, int attemptCount, int maxAttempts) {}
}
