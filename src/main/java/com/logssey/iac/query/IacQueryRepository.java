package com.logssey.iac.query;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@Repository
public class IacQueryRepository {

    private final JdbcTemplate jdbc;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public IacQueryRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    boolean isAdmin(String loginId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN')",
                Boolean.class, loginId));
    }

    long openPaths(Integer tier) {
        return jdbc.queryForObject("""
                SELECT count(*) FROM iac_attack_paths WHERE status = 'OPEN' AND (?::smallint IS NULL OR tier = ?)
                """, Long.class, tier, tier);
    }

    /** 열린 경로 + 매일 점검(last_job_id)에서 나온 열린 발견 건. */
    Map<String, Long> severityCounts() {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW")) counts.put(severity, 0L);
        jdbc.query("""
                SELECT severity, count(*) AS n FROM (
                    SELECT severity FROM iac_attack_paths WHERE status = 'OPEN'
                    UNION ALL
                    SELECT severity FROM iac_findings
                    WHERE status = 'OPEN' AND severity IS NOT NULL AND last_job_id IS NOT NULL
                ) open GROUP BY severity
                """, rs -> { counts.put(rs.getString("severity"), rs.getLong("n")); });
        return counts;
    }

    Optional<OffsetDateTime> lastSucceeded(String kind) {
        return Optional.ofNullable(jdbc.queryForObject("""
                SELECT max(finished_at) FROM iac_jobs WHERE kind = ? AND status = 'SUCCEEDED'
                """, OffsetDateTime.class, kind));
    }

    List<IacPathResponse> paths(String status, Integer tier, long afterPathId, int limit) {
        return jdbc.query("""
                SELECT p.path_id, p.status, p.tier, p.severity, p.length, p.hops::text AS hops,
                       a.arn, a.kind, p.first_seen_at, p.last_seen_at
                FROM iac_attack_paths p JOIN iac_data_assets a ON a.data_asset_id = p.target_data_asset_id
                WHERE p.status = ? AND (?::smallint IS NULL OR p.tier = ?) AND p.path_id > ?
                ORDER BY p.path_id
                LIMIT ?
                """, (rs, row) -> new IacPathResponse(rs.getLong("path_id"), rs.getString("status"), rs.getInt("tier"),
                rs.getString("severity"), rs.getInt("length"), json(rs.getString("hops")),
                new IacPathResponse.Target(rs.getString("arn"), rs.getString("kind")),
                rs.getObject("first_seen_at", OffsetDateTime.class), rs.getObject("last_seen_at", OffsetDateTime.class)),
                status, tier, tier, afterPathId, limit);
    }

    List<Long> enabledRepoIds(String fullName) {
        return jdbc.queryForList("""
                SELECT repo_id FROM iac_repos WHERE enabled AND (?::text IS NULL OR full_name = ?) ORDER BY repo_id
                """, Long.class, fullName, fullName);
    }

    Optional<RunRow> latestRun(long repoId, int prNumber) {
        return jdbc.query("""
                SELECT run_id, head_sha, status, verdict, highest_severity, coalesce(finished_at, created_at) AS checked_at
                FROM iac_runs WHERE repo_id = ? AND pr_number = ?
                ORDER BY run_id DESC LIMIT 1
                """, (rs, row) -> new RunRow(rs.getLong("run_id"), rs.getString("head_sha"), rs.getString("status"),
                rs.getString("verdict"), rs.getString("highest_severity"),
                rs.getObject("checked_at", OffsetDateTime.class)), repoId, prNumber).stream().findFirst();
    }

    List<IacPullRequestResponse.GateFinding> gateFindings(long runId) {
        return jdbc.query("""
                SELECT rule_id, enforcement, severity, resource_address FROM iac_findings
                WHERE last_run_id = ? AND source = 'GATE' AND status = 'OPEN'
                ORDER BY CASE enforcement WHEN 'BLOCK' THEN 0 ELSE 1 END, rule_id, resource_address
                """, (rs, row) -> new IacPullRequestResponse.GateFinding(rs.getString("rule_id"),
                rs.getString("enforcement"), rs.getString("severity"), rs.getString("resource_address")), runId);
    }

    /** evidence 의 causeAction 은 cause.action 으로 옮기고, 나머지(시뮬레이터 판정)만 evidence 로 돌려준다. */
    List<IacPullRequestResponse.PathChange> pathChanges(long runId) {
        return jdbc.query("""
                SELECT change, tier, rule_id, severity, hops::text AS hops, cause_address,
                       evidence ->> 'causeAction' AS cause_action, (evidence - 'causeAction')::text AS evidence
                FROM iac_run_path_changes WHERE run_id = ?
                ORDER BY CASE change WHEN 'ADDED' THEN 0 WHEN 'SHORTENED' THEN 1 ELSE 2 END, tier, change_id
                """, (rs, row) -> new IacPullRequestResponse.PathChange(rs.getString("change"), rs.getInt("tier"),
                rs.getString("rule_id"), rs.getString("severity"), json(rs.getString("hops")),
                new IacPullRequestResponse.Cause(rs.getString("cause_address"), rs.getString("cause_action")),
                json(rs.getString("evidence"))), runId);
    }

    /** 분석 작업이 남긴 결과의 한 부분 (resources: plan 리소스 수, state: ③ State 영향). */
    JsonNode analysisStats(long runId, String key) {
        return json(jdbc.query("""
                SELECT (stats -> ?)::text FROM iac_jobs
                WHERE run_id = ? AND kind = 'ANALYZE_RUN' AND status = 'SUCCEEDED'
                ORDER BY job_id DESC LIMIT 1
                """, (rs, row) -> rs.getString(1), key, runId).stream().findFirst().orElse(null));
    }

    /** 가장 최근 CHECK_STATE 결과와 시각. */
    Optional<LatestJob> latestJob(String kind) {
        return jdbc.query("""
                SELECT finished_at, stats::text AS stats FROM iac_jobs
                WHERE kind = ? AND status = 'SUCCEEDED' ORDER BY finished_at DESC, job_id DESC LIMIT 1
                """, (rs, row) -> new LatestJob(rs.getObject("finished_at", OffsetDateTime.class),
                json(rs.getString("stats"))), kind).stream().findFirst();
    }

    record LatestJob(OffsetDateTime finishedAt, JsonNode stats) {
    }

    private JsonNode json(String value) {
        return value == null ? null : mapper.readTree(value);
    }

    record RunRow(long runId, String headSha, String status, String verdict, String highestSeverity,
                  OffsetDateTime checkedAt) {
    }
}
