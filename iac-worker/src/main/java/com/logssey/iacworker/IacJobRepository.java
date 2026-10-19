package com.logssey.iacworker;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class IacJobRepository {

    private static final String COLUMNS = """
            job_id, kind, run_id, attempt_no, max_attempts, status, lease_owner, lease_until
            """;

    private final JdbcTemplate jdbc;

    IacJobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    List<JobRow> lockAvailable(OffsetDateTime now, int limit, IacJobKind kind) {
        return jdbc.query("SELECT " + COLUMNS + """
                FROM iac_jobs
                WHERE status = 'PENDING' AND available_at <= ? AND kind = ?
                ORDER BY available_at, job_id
                LIMIT ? FOR UPDATE SKIP LOCKED
                """, (rs, row) -> jobRow(rs), now, kind.name(), limit);
    }

    List<JobRow> lockExpired(OffsetDateTime now, int limit) {
        return jdbc.query("SELECT " + COLUMNS + """
                FROM iac_jobs
                WHERE status = 'LEASED' AND lease_until <= ?
                ORDER BY lease_until, job_id
                LIMIT ? FOR UPDATE SKIP LOCKED
                """, (rs, row) -> jobRow(rs), now, limit);
    }

    Optional<JobRow> lockJob(long jobId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM iac_jobs WHERE job_id = ? FOR UPDATE",
                rs -> rs.next() ? Optional.of(jobRow(rs)) : Optional.empty(), jobId);
    }

    ClaimedIacJob claim(JobRow row, OffsetDateTime leaseUntil, String token) {
        jdbc.update("""
                UPDATE iac_jobs
                SET status = 'LEASED', lease_owner = ?, lease_until = ?, attempt_no = attempt_no + 1,
                    last_error_code = NULL
                WHERE job_id = ?
                """, token, leaseUntil, row.jobId());
        return new ClaimedIacJob(row.jobId(), IacJobKind.valueOf(row.kind()), row.runId(),
                row.attemptNo() + 1, token, leaseUntil);
    }

    boolean renew(long jobId, String token, Duration leaseDuration) {
        return jdbc.update("""
                UPDATE iac_jobs SET lease_until = clock_timestamp() + (? * INTERVAL '1 millisecond')
                WHERE job_id = ? AND status = 'LEASED' AND lease_owner = ?
                  AND lease_until > clock_timestamp()
                """, leaseDuration.toMillis(), jobId, token) == 1;
    }

    void finish(JobRow row, OffsetDateTime now) {
        jdbc.update("""
                UPDATE iac_jobs SET status = 'SUCCEEDED', lease_owner = NULL, lease_until = NULL,
                                    last_error_code = NULL, finished_at = ?
                WHERE job_id = ?
                """, now, row.jobId());
    }

    void retry(JobRow row, OffsetDateTime availableAt, String code) {
        jdbc.update("""
                UPDATE iac_jobs
                SET status = 'PENDING', available_at = ?, lease_owner = NULL, lease_until = NULL,
                    last_error_code = ?
                WHERE job_id = ?
                """, availableAt, code, row.jobId());
    }

    /** A run whose analysis cannot finish becomes ERROR, which the PR check reports as failed (NFR-4). */
    void failPermanently(JobRow row, OffsetDateTime now, String code) {
        jdbc.update("""
                UPDATE iac_jobs
                SET status = 'FAILED', lease_owner = NULL, lease_until = NULL,
                    last_error_code = ?, finished_at = ?
                WHERE job_id = ?
                """, code, now, row.jobId());
        if (row.runId() != null) {
            jdbc.update("""
                    UPDATE iac_runs SET status = 'ERROR', finished_at = ?
                    WHERE run_id = ? AND status NOT IN ('DONE', 'SUPERSEDED')
                    """, now, row.runId());
        }
    }

    int deleteExpiredPlans(OffsetDateTime now) {
        return jdbc.update("DELETE FROM iac_plan_payloads WHERE expires_at <= ?", now);
    }

    private static JobRow jobRow(ResultSet rs) throws SQLException {
        return new JobRow(rs.getLong("job_id"), rs.getString("kind"), rs.getObject("run_id", Long.class),
                rs.getInt("attempt_no"), rs.getInt("max_attempts"), rs.getString("status"),
                rs.getString("lease_owner"), rs.getObject("lease_until", OffsetDateTime.class));
    }

    record JobRow(long jobId, String kind, Long runId, int attemptNo, int maxAttempts, String status,
                  String leaseOwner, OffsetDateTime leaseUntil) {

        boolean isLiveLease(String token, OffsetDateTime now) {
            return "LEASED".equals(status) && token != null && token.equals(leaseOwner)
                    && leaseUntil != null && leaseUntil.isAfter(now);
        }
    }
}
