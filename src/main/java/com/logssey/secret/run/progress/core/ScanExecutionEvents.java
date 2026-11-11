package com.logssey.secret.run.progress.core;

import org.springframework.jdbc.core.JdbcTemplate;

/** SQL enforces the live attempt fence and allocates a commit-ordered cursor under the run lock. */
public final class ScanExecutionEvents {
    private final JdbcTemplate jdbc;

    public ScanExecutionEvents(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public boolean append(long jobId, String token, long generation, Long runScopeId,
                          ScanExecutionObserver.Stage stage, ScanExecutionObserver.Operation operation,
                          ScanExecutionObserver.Outcome outcome, Integer httpStatus, String reason,
                          Long processed, Long total, Long duration) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT secret_record_execution_event(?,?::uuid,?,?,?,?,?,?,?,?,?,?,?)
                """, Boolean.class, jobId, token, generation, runScopeId, stage.name(),
                operation.name(), outcome.name(), httpStatus, reason, processed, total, duration,
                java.util.UUID.randomUUID().toString()));
    }
}
