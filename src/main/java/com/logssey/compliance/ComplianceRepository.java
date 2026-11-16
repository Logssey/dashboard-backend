package com.logssey.compliance;

import static com.logssey.compliance.ComplianceDtos.ResultCounts;
import static com.logssey.compliance.ComplianceDtos.ResultItem;
import static com.logssey.compliance.ComplianceDtos.RunSummary;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class ComplianceRepository {

    private static final String RUN_COLUMNS = """
            run_id, environment, status, source, product, scanner_version,
            result_count, pass_count, fail_count, error_count, needs_review_count,
            duplicate_count, warning_count, created_by_login, finished_at
            """;

    private final JdbcClient jdbc;
    private final JdbcTemplate batch;

    public ComplianceRepository(JdbcClient jdbc, JdbcTemplate batch) {
        this.jdbc = jdbc;
        this.batch = batch;
    }

    boolean isAdmin(String loginId) {
        if (loginId == null) return false;
        return Boolean.TRUE.equals(jdbc.sql("""
                        SELECT EXISTS (
                            SELECT 1 FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN'
                        )
                        """)
                .param("loginId", loginId)
                .query(Boolean.class)
                .single());
    }

    long insertRun(String targetKey, String environment, String status, String product, String scannerVersion,
                   String sha256, ProwlerOcsfNormalizer.NormalizedImport normalized, ResultCounts counts,
                   String loginId) {
        return jdbc.sql("""
                        INSERT INTO compliance_runs (
                            target_key, environment, status, source, product, scanner_version, artifact_sha256,
                            input_count, result_count, duplicate_count, warning_count,
                            pass_count, fail_count, error_count, needs_review_count, created_by_login)
                        VALUES (:targetKey, :environment, :status, 'PROWLER_OCSF', :product, :scannerVersion, :sha256,
                            :inputCount, :resultCount, :duplicateCount, :warningCount,
                            :passCount, :failCount, :errorCount, :needsReviewCount, :loginId)
                        RETURNING run_id
                        """)
                .param("targetKey", targetKey)
                .param("environment", environment)
                .param("status", status)
                .param("product", product)
                .param("scannerVersion", scannerVersion)
                .param("sha256", sha256)
                .param("inputCount", normalized.inputCount())
                .param("resultCount", normalized.results().size())
                .param("duplicateCount", normalized.duplicateCount())
                .param("warningCount", normalized.warningCount())
                .param("passCount", counts.pass())
                .param("failCount", counts.fail())
                .param("errorCount", counts.error())
                .param("needsReviewCount", counts.needsReview())
                .param("loginId", loginId)
                .query(Long.class)
                .single();
    }

    void insertResults(long runId, List<ProwlerOcsfNormalizer.NormalizedResult> results) {
        batch.batchUpdate("""
                        INSERT INTO compliance_results (
                            run_id, check_id, title, provider, result, asset, current_value, expected_value,
                            observed_at, region, severity, fingerprint, asset_uid, asset_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, results, 500, (statement, result) -> bindResult(statement, runId, result));
    }

    private static void bindResult(PreparedStatement statement, long runId,
                                   ProwlerOcsfNormalizer.NormalizedResult result) throws SQLException {
        statement.setLong(1, runId);
        statement.setString(2, result.checkId());
        statement.setString(3, result.title());
        statement.setString(4, result.provider());
        statement.setString(5, result.result());
        statement.setString(6, result.asset());
        statement.setString(7, result.currentValue());
        statement.setString(8, result.expectedValue());
        statement.setObject(9, result.observedAt());
        statement.setString(10, result.region());
        statement.setString(11, result.severity());
        statement.setString(12, result.fingerprint());
        statement.setString(13, result.assetUid());
        statement.setString(14, result.assetType());
    }

    void insertAssessments(long runId, List<AssessmentInput> assessments) {
        batch.batchUpdate("""
                        INSERT INTO compliance_control_assessments (
                            run_id, framework_id, control_id, status, mapped_check_count,
                            observed_check_count, failed_check_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, assessments, 500, (statement, assessment) -> {
                            statement.setLong(1, runId);
                            statement.setString(2, assessment.frameworkId());
                            statement.setString(3, assessment.controlId());
                            statement.setString(4, assessment.status());
                            statement.setInt(5, assessment.mappedCheckCount());
                            statement.setInt(6, assessment.observedCheckCount());
                            statement.setInt(7, assessment.failedCheckCount());
                        });
    }

    Optional<RunSummary> latestRun(String targetKey, String environment) {
        String environmentFilter = environment.equals("ALL") ? "" : " AND environment = :environment";
        var spec = jdbc.sql("SELECT " + RUN_COLUMNS + " FROM compliance_runs WHERE target_key = :targetKey"
                        + environmentFilter + " ORDER BY finished_at DESC, run_id DESC LIMIT 1")
                .param("targetKey", targetKey);
        if (!environment.equals("ALL")) spec = spec.param("environment", environment);
        return spec.query(this::runRow).optional();
    }

    List<RunSummary> runs(String targetKey, String environment, int limit) {
        String environmentFilter = environment.equals("ALL") ? "" : " AND environment = :environment";
        var spec = jdbc.sql("SELECT " + RUN_COLUMNS + " FROM compliance_runs WHERE target_key = :targetKey"
                        + environmentFilter + " ORDER BY finished_at DESC, run_id DESC LIMIT :limit")
                .param("targetKey", targetKey)
                .param("limit", limit);
        if (!environment.equals("ALL")) spec = spec.param("environment", environment);
        return spec.query(this::runRow).list();
    }

    Optional<RunSummary> run(String targetKey, long runId) {
        return jdbc.sql("SELECT " + RUN_COLUMNS
                        + " FROM compliance_runs WHERE target_key = :targetKey AND run_id = :runId")
                .param("targetKey", targetKey)
                .param("runId", runId)
                .query(this::runRow)
                .optional();
    }

    List<AssessmentCount> assessmentCounts(long runId) {
        return jdbc.sql("""
                        SELECT framework_id, status, count(*) AS count
                        FROM compliance_control_assessments
                        WHERE run_id = :runId
                        GROUP BY framework_id, status
                        """)
                .param("runId", runId)
                .query((rs, row) -> new AssessmentCount(rs.getString("framework_id"),
                        rs.getString("status"), rs.getInt("count")))
                .list();
    }

    List<AssessmentRow> assessments(long runId, List<String> frameworkIds) {
        return jdbc.sql("""
                        SELECT framework_id, control_id, status, mapped_check_count,
                               observed_check_count, failed_check_count
                        FROM compliance_control_assessments
                        WHERE run_id = :runId AND framework_id IN (:frameworkIds)
                        ORDER BY framework_id, control_id
                        """)
                .param("runId", runId)
                .param("frameworkIds", frameworkIds)
                .query((rs, row) -> new AssessmentRow(
                        rs.getString("framework_id"), rs.getString("control_id"), rs.getString("status"),
                        rs.getInt("mapped_check_count"), rs.getInt("observed_check_count"),
                        rs.getInt("failed_check_count")))
                .list();
    }

    List<ResultItem> results(long runId, int limit) {
        return jdbc.sql("""
                        SELECT result_id, check_id, title, provider, result, asset, current_value, expected_value,
                               observed_at, region, severity, asset_type
                        FROM compliance_results
                        WHERE run_id = :runId
                        ORDER BY CASE result WHEN 'FAIL' THEN 0 WHEN 'ERROR' THEN 1
                                             WHEN 'NEEDS_REVIEW' THEN 2 ELSE 3 END,
                                 observed_at DESC, result_id DESC
                        LIMIT :limit
                        """)
                .param("runId", runId)
                .param("limit", limit)
                .query((rs, row) -> new ResultItem(
                        rs.getLong("result_id"), rs.getString("check_id"), rs.getString("title"),
                        rs.getString("provider"), rs.getString("result"), rs.getString("asset"),
                        rs.getString("current_value"), rs.getString("expected_value"),
                        rs.getObject("observed_at", OffsetDateTime.class), rs.getString("region"),
                        rs.getString("severity"), rs.getString("asset_type")))
                .list();
    }

    List<ResultItem> reportResults(long runId, int limit) {
        return jdbc.sql("""
                        SELECT result_id, check_id, title, provider, result, asset, current_value, expected_value,
                               observed_at, region, severity, asset_type
                        FROM compliance_results
                        WHERE run_id = :runId AND result <> 'PASS'
                        ORDER BY CASE result WHEN 'FAIL' THEN 0 WHEN 'ERROR' THEN 1 ELSE 2 END,
                                 observed_at DESC, result_id DESC
                        LIMIT :limit
                        """)
                .param("runId", runId)
                .param("limit", limit)
                .query((rs, row) -> new ResultItem(
                        rs.getLong("result_id"), rs.getString("check_id"), rs.getString("title"),
                        rs.getString("provider"), rs.getString("result"), rs.getString("asset"),
                        rs.getString("current_value"), rs.getString("expected_value"),
                        rs.getObject("observed_at", OffsetDateTime.class), rs.getString("region"),
                        rs.getString("severity"), rs.getString("asset_type")))
                .list();
    }

    private RunSummary runRow(ResultSet rs, int row) throws SQLException {
        return new RunSummary(
                rs.getLong("run_id"), rs.getString("environment"), rs.getString("status"),
                rs.getString("source"), rs.getString("product"), rs.getString("scanner_version"),
                new ResultCounts(rs.getLong("result_count"), rs.getLong("pass_count"),
                        rs.getLong("fail_count"), rs.getLong("error_count"),
                        rs.getLong("needs_review_count")),
                rs.getInt("duplicate_count"), rs.getInt("warning_count"),
                rs.getString("created_by_login"), rs.getObject("finished_at", OffsetDateTime.class));
    }

    public record AssessmentInput(String frameworkId, String controlId, String status, int mappedCheckCount,
                                  int observedCheckCount, int failedCheckCount) {}
    record AssessmentCount(String frameworkId, String status, int count) {}
    record AssessmentRow(String frameworkId, String controlId, String status, int mappedCheckCount,
                         int observedCheckCount, int failedCheckCount) {}
}
