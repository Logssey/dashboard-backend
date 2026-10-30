package com.logssey.reach.query;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

import com.logssey.reach.query.dto.ReachFindingResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reach 조회 SQL (API-04 목록, API-05 상세, API-08 요약).
 * 기준 범위는 대상마다 최신 SUCCEEDED 스캔이다 (DB 스키마 5절). 목록과 요약이 같은 CURRENT_FINDINGS를 써서 숫자가 맞는다
 */
@Repository
public class ReachQueryRepository {
    /** 대상마다 최신 SUCCEEDED 스캔의 Finding + 현재 판정 + 검토 (DB 스키마 5절). 목록과 요약이 같이 쓴다. */
    static final String CURRENT_FINDINGS ="""
     WITH latest AS (
                SELECT DISTINCT ON (target_id) scan_id
                FROM reach_scans WHERE scan_status = 'SUCCEEDED'
                ORDER BY target_id, finished_at DESC, scan_id DESC
            )
            SELECT f.finding_id, f.last_scan_id, f.target_id, f.purl, f.component_name, f.component_version,
                   f.vulnerability_id, f.severity, f.fixed_versions, f.deployment, f.first_seen_at,
                   v.status, v.method, v.summary, v.not_analyzed_reason,
                   r.review_state, r.status AS review_status, r.proposal::text AS proposal, r.reset_reason,
                   CASE v.status WHEN 'REACHABLE' THEN 0 WHEN 'UNKNOWN' THEN 1 WHEN 'UNREACHABLE' THEN 2 ELSE 3 END AS status_rank,
                   CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END AS severity_rank,
                   -- CVE가 아닌 ID(GHSA 등)는 맨 뒤로. NULL이면 커서의 행 비교가 깨져서 큰 값으로 채운다
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d+-\\d+$' THEN split_part(f.vulnerability_id, '-', 2)::int END, 2147483647) AS cve_year,
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d+-\\d+$' THEN split_part(f.vulnerability_id, '-', 3)::int END, 2147483647) AS cve_number
            FROM reach_findings f
            JOIN latest l ON l.scan_id = f.last_scan_id
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
}