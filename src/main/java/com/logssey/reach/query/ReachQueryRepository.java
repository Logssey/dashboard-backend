package com.logssey.reach.query;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Optional;

import com.logssey.reach.query.dto.ReachFindingResponse;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reach 조회 SQL (API-04 목록, API-05 상세, API-08 요약).
 * 기준 범위는 대상마다 PR이 아닌 최신 SUCCEEDED 스캔이다 (DB 스키마 5절, ARD SR-09). 목록과 요약이 같은 CURRENT_FINDINGS를 써서 숫자가 맞는다
 */
@Repository
public class ReachQueryRepository {
    /**
     * 대상마다 최신 SUCCEEDED 스캔의 Finding + 현재 판정 + 검토 (DB 스키마 5절). 목록과 요약이 같이 쓴다.
     * PR 검사의 스캔은 그 PR의 결과로만 두고 넣지 않는다 (ARD SR-09).
     * Finding은 last_scan_id가 아니라 그 스캔의 도구 판정으로 잇는다. 같은 레포 커밋을 PR로 다시 스캔하면
     * last_scan_id가 PR 스캔으로 바뀌어도 기준 스캔의 Finding이 빠지지 않는다 (API-03 counts와 같은 기준)
     */
    static final String CURRENT_FINDINGS ="""
     WITH latest AS (
                SELECT DISTINCT ON (target_id) target_id, scan_id
                FROM reach_scans WHERE scan_status = 'SUCCEEDED' AND trigger_type <> 'PR'
                ORDER BY target_id, finished_at DESC, scan_id DESC
            )
            SELECT f.finding_id, l.scan_id AS last_scan_id, f.target_id, f.purl, f.component_name, f.component_version,
                   f.vulnerability_id, f.severity, f.fixed_versions, f.deployment, f.first_seen_at,
                   v.status, v.method, v.summary, v.not_analyzed_reason,
                   r.review_state, r.status AS review_status, r.proposal::text AS proposal, r.reset_reason,
                   CASE v.status WHEN 'REACHABLE' THEN 0 WHEN 'UNKNOWN' THEN 1 WHEN 'UNREACHABLE' THEN 2 ELSE 3 END AS status_rank,
                   CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END AS severity_rank,
                   -- CVE가 아닌 ID(GHSA 등)는 맨 뒤로. NULL이면 커서의 행 비교가 깨져서 큰 값으로 채운다
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d+-\\d+$' THEN split_part(f.vulnerability_id, '-', 2)::int END, 2147483647) AS cve_year,
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d+-\\d+$' THEN split_part(f.vulnerability_id, '-', 3)::int END, 2147483647) AS cve_number
            FROM reach_findings f
            JOIN latest l ON l.target_id = f.target_id
             AND EXISTS (SELECT 1 FROM reach_verdicts lv
                         WHERE lv.finding_id = f.finding_id AND lv.scan_id = l.scan_id
                           AND lv.method IS DISTINCT FROM 'MANUAL')
            JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current
            JOIN reach_reviews r ON r.finding_id = f.finding_id
    """;

    /** 기본 정렬: 상태 -> 심각도 -> CVE(연도·번호를 숫자로) -> id (Reach API 명세 2-5). */
    private static final String DEFAULT_ORDER = 
    " ORDER BY status_rank, severity_rank, cve_year, cve_number, finding_id";

    private final JdbcClient jdbcClient;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public ReachQueryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    boolean isAdmin(String loginId){
        return Boolean.TRUE.equals(jdbcClient
            .sql("SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN')")
            .param("loginId", loginId)
            .query(Boolean.class)
            .single());

    }

    private ReachFindingResponse finding(ResultSet rs, int rowNum) throws SQLException {
        String status = rs.getString("status");
        String reviewStatus = rs.getString("review_status");
        return new ReachFindingResponse(
                rs.getLong("finding_id"),
                rs.getLong("last_scan_id"),
                rs.getLong("target_id"),
                new ReachFindingResponse.Component(rs.getString("purl"), rs.getString("component_name"),
                        rs.getString("component_version")),
                new ReachFindingResponse.Vulnerability(rs.getString("vulnerability_id"), rs.getString("severity"),
                        strings(rs.getArray("fixed_versions"))),
                rs.getString("deployment"),
                new ReachFindingResponse.Verdict(status, rs.getString("method"), rs.getString("summary"),
                        rs.getString("not_analyzed_reason")),
                // 사람 판정이 있고 현재 판정과 다르면 true (FR-08)
                new ReachFindingResponse.Review(rs.getString("review_state"),
                        reviewStatus != null && !reviewStatus.equals(status),
                        json(rs.getString("proposal")), rs.getString("reset_reason")),
                rs.getObject("first_seen_at", OffsetDateTime.class));
    }

    private static List<String> strings(Array array) throws SQLException {
        return array == null ? List.of() : List.of((String[]) array.getArray());
    }

    private JsonNode json(String value) {
        return value == null ? null : mapper.readTree(value);
    }
    /** 목록 한 행 + 커서용 정렬 키 */
    record Row(ReachFindingResponse item, int statusRank, int severityRank, int cveYear, int cveNumber) {}

    private record Where(String sql, Map<String, Object> params) {}

    List<Row> findings(ReachFindingFilter filter, ReachFindingCursor after, int limit) {
        var where = where(filter, after);
        var params = new HashMap<>(where.params());
        params.put("limit", limit);
        return jdbcClient.sql("SELECT * FROM (" + CURRENT_FINDINGS + ") c" + where.sql() + DEFAULT_ORDER + " LIMIT :limit")
                .params(params)
                .query(this::row)
                .list();
    }

    long countFindings(ReachFindingFilter filter) {
        var where = where(filter, null);   // 개수는 커서와 무관하게 필터 전체
        return jdbcClient.sql("SELECT count(*) FROM (" + CURRENT_FINDINGS + ") c" + where.sql())
                .params(where.params())
                .query(Long.class)
                .single();
    }

    private Where where(ReachFindingFilter filter, ReachFindingCursor after) {
        var conditions = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        in(conditions, params, "status", filter.status());
        in(conditions, params, "severity", filter.severity());
        in(conditions, params, "review_state", filter.reviewState());
        in(conditions, params, "deployment", filter.deployment());
        if (filter.cveContains() != null) {
            // ILIKE 대신 strpos: 입력의 % _ 를 와일드카드로 해석하지 않는다
            conditions.add("strpos(lower(vulnerability_id), lower(:cveContains)) > 0");
            params.put("cveContains", filter.cveContains());
        }
        if (after != null) {
            conditions.add("(status_rank, severity_rank, cve_year, cve_number, finding_id)"
                    + " > (:afterStatus, :afterSeverity, :afterYear, :afterNumber, :afterId)");
            params.put("afterStatus", after.statusRank());
            params.put("afterSeverity", after.severityRank());
            params.put("afterYear", after.cveYear());
            params.put("afterNumber", after.cveNumber());
            params.put("afterId", after.findingId());
        }
        return new Where(conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions), params);
    }

    /** 값이 있을 때만 "열 IN (...)"을 붙인다. 빈 IN ()은 SQL 오류다 */
    private static void in(List<String> conditions, Map<String, Object> params, String column, List<String> values) {
        if (values.isEmpty()) return;
        conditions.add(column + " IN (:" + column + ")");
        params.put(column, values);
    }

    private Row row(ResultSet rs, int rowNum) throws SQLException {
        return new Row(finding(rs, rowNum), rs.getInt("status_rank"), rs.getInt("severity_rank"),
                rs.getInt("cve_year"), rs.getInt("cve_number"));
    }

    /** 요약용 한 줄: 상태·심각도·방식·검토·배포·사유 조합과 그 개수 */
    record SummaryRow(
            String status,
            String severity,
            String method,
            String reviewState,
            String deployment,
            String notAnalyzedReason,
            long count) {}

    /** API-08. 목록과 같은 CURRENT_FINDINGS를 조합별로 센다. 차원별 합계는 Service가 낸다 */
    List<SummaryRow> summaryRows(List<String> deployment) {
        var where = deployment.isEmpty() ? "" : " WHERE deployment IN (:deployment)";
        var spec = jdbcClient.sql("""
                SELECT status, severity, method, review_state, deployment, not_analyzed_reason, count(*) AS n
                FROM (%s) c%s
                GROUP BY status, severity, method, review_state, deployment, not_analyzed_reason
                """.formatted(CURRENT_FINDINGS, where));
        if (!deployment.isEmpty()) spec = spec.param("deployment", deployment);
        return spec.query((rs, i) -> new SummaryRow(rs.getString("status"), rs.getString("severity"),
                        rs.getString("method"), rs.getString("review_state"), rs.getString("deployment"),
                        rs.getString("not_analyzed_reason"), rs.getLong("n")))
                .list();
    }

    /** API-05 상세.
     * 목록(CURRENT_FINDINGS)과 달리 최신 스캔으로 좁히지 않아, 옛 스캔의 Finding도 id로 열린다.
     * 근거는 ord 순서의 JSON 배열로 묶고(없으면[]), 같은 스캔에서 CVE가 같은 다른 Finding의 id도 함께 준다.
     */
    private static final String FINDING_DETAIL = """
        SELECT f.finding_id, f.last_scan_id, f.target_id, f.purl, f.component_name, f.component_version, f.ecosystem,
               f.vulnerability_id, f.severity, f.severity_note, f.vuln_title, f.affected_feature, f.fixed_versions,
               f.deployment, f.sources, f.upgrade::text AS upgrade, f.first_seen_at, f.last_seen_at,
               v.status, v.method, v.summary, v.not_analyzed_reason, v.rule_id,
               v.callgraph::text AS callgraph, v.engine::text AS engine, v.analyzed_at,
               (SELECT COALESCE(jsonb_agg(
                           jsonb_strip_nulls(jsonb_build_object(
                               'order', e.ord, 'kind', e.kind, 'summary', e.summary,
                               'factId', e.fact_id, 'ruleId', e.rule_id, 'informational', e.informational))
                           || e.detail
                           ORDER BY e.ord), '[]'::jsonb)
                  FROM reach_evidence e WHERE e.verdict_id = v.verdict_id)::text AS evidence,
               r.review_state, r.status AS review_status, r.note, r.reviewed_at, r.version,
               r.proposal::text AS proposal, r.reset_reason,
               r.carried_from_finding_id, r.carried_from_scan_id, cr.reviewed_at AS carried_reviewed_at,
               u.user_id AS reviewer_id, u.display_name AS reviewer_name,
               ARRAY(SELECT o.finding_id FROM reach_findings o
                     WHERE o.last_scan_id = f.last_scan_id AND o.vulnerability_id = f.vulnerability_id
                       AND o.finding_id <> f.finding_id
                     ORDER BY o.finding_id) AS same_cve
        FROM reach_findings f
        JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current
        JOIN reach_reviews r ON r.finding_id = f.finding_id
        LEFT JOIN dashboard_users u ON u.user_id = r.reviewer_user_id
        LEFT JOIN reach_reviews cr ON cr.finding_id = r.carried_from_finding_id
        WHERE f.finding_id = :findingId
        """;

        Optional<ReachFindingDetailResponse> finding(long findingId) {
    return jdbcClient.sql(FINDING_DETAIL).param("findingId", findingId).query(this::detail).optional();
    }
    /** 
     * API-05 상세 한 행 → 응답. JSONB 칸은 SQL에서 ::text로 받아 json()으로 바꾼다 
    */
    private ReachFindingDetailResponse detail(ResultSet rs, int rowNum) throws SQLException {
        String status = rs.getString("status");
        String reviewStatus = rs.getString("review_status");
        // 두 칸은 같이 있거나 같이 없다 (V34 ck_reach_reviews_carried). NULL일 수 있는 BIGINT라 getObject로 읽는다
        Long carriedId = rs.getObject("carried_from_finding_id", Long.class);
        var carriedFrom = carriedId == null ? null : new ReachFindingDetailResponse.CarriedFrom(carriedId,
                rs.getLong("carried_from_scan_id"), rs.getObject("carried_reviewed_at", OffsetDateTime.class));

        return new ReachFindingDetailResponse(
                rs.getLong("finding_id"), rs.getLong("last_scan_id"), rs.getLong("target_id"),
                new ReachFindingDetailResponse.Component(rs.getString("purl"), rs.getString("component_name"),
                        rs.getString("component_version"), rs.getString("ecosystem")),
                new ReachFindingDetailResponse.Vulnerability(rs.getString("vulnerability_id"), rs.getString("severity"),
                        rs.getString("severity_note"), rs.getString("vuln_title"), rs.getString("affected_feature"),
                        strings(rs.getArray("fixed_versions"))),
                rs.getString("deployment"),
                strings(rs.getArray("sources")),
                new ReachFindingDetailResponse.Verdict(status, rs.getString("method"), rs.getString("summary"),
                        rs.getString("not_analyzed_reason"), rs.getString("rule_id"),
                        json(rs.getString("callgraph")), json(rs.getString("evidence")),
                        rs.getObject("analyzed_at", OffsetDateTime.class), json(rs.getString("engine"))),
                // 사람 판정이 있고 현재 판정과 다르면 true (FR-08, 목록과 같은 규칙)
                new ReachFindingDetailResponse.Review(rs.getString("review_state"), reviewStatus, rs.getString("note"),
                        reviewer(rs), rs.getObject("reviewed_at", OffsetDateTime.class), rs.getInt("version"),
                        reviewStatus != null && !reviewStatus.equals(status),
                        json(rs.getString("proposal")), carriedFrom, rs.getString("reset_reason"),
                        null),   // history는 Service가 include=reviewHistory일 때만 채운다
                json(rs.getString("upgrade")),
                // ARRAY(SELECT ...)는 결과가 없어도 NULL이 아니라 빈 배열이다. BIGINT 배열이라 Long[]
                List.of((Long[]) rs.getArray("same_cve").getArray()),
                rs.getObject("first_seen_at", OffsetDateTime.class),
                rs.getObject("last_seen_at", OffsetDateTime.class));
    }

    /** API-05 include=reviewHistory. 새것부터. version은 Finding마다 겹치지 않는다 (uq_reach_review_history_version) */
    List<ReachFindingDetailResponse.History> reviewHistory(long findingId) {
        return jdbcClient.sql("""
                        SELECT h.review_state, h.status, h.note, h.proposal::text AS proposal, h.reviewed_at,
                               h.version, h.change_kind, u.user_id AS reviewer_id, u.display_name AS reviewer_name
                        FROM reach_review_history h
                        LEFT JOIN dashboard_users u ON u.user_id = h.reviewer_user_id
                        WHERE h.finding_id = :findingId
                        ORDER BY h.version DESC
                        """)
                .param("findingId", findingId)
                .query((rs, i) -> new ReachFindingDetailResponse.History(rs.getString("review_state"),
                        rs.getString("status"), rs.getString("note"), json(rs.getString("proposal")), reviewer(rs),
                        rs.getObject("reviewed_at", OffsetDateTime.class), rs.getInt("version"),
                        rs.getString("change_kind")))
                .list();
    }

    /** 검토 전이거나 서버가 되돌린 기록이면 reviewer_id가 NULL. getLong은 NULL을 0으로 주므로 wasNull()로 확인한다 */
    private static ReachFindingDetailResponse.Reviewer reviewer(ResultSet rs) throws SQLException {
        long id = rs.getLong("reviewer_id");
        return rs.wasNull() ? null : new ReachFindingDetailResponse.Reviewer(id, rs.getString("reviewer_name"));
    }
}