package com.logssey.reach.export;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import com.logssey.reach.export.dto.ReachOcsfFindingResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Reach OCSF 내보내기 SQL (API-11) */
@Repository
public class ReachExportRepository {
    /**
     * 그 스캔이 낸 도구 판정 + Finding + 지금 검토 + 대상. 스캔 상태(API-03 counts)와 같은 기준이라
     * 판정의 scan_id로 고르고 MANUAL(사람 판정)은 뺀다 (DB 스키마 5절: 지난 스캔은 그 스캔의 도구 판정으로).
     * method가 NULL(NOT_ANALYZED)인 행도 남겨야 해서 <>가 아니라 IS DISTINCT FROM
     */
    private static final String SCAN_FINDINGS = """
            SELECT f.finding_id, f.purl, f.component_name, f.component_version, f.vulnerability_id, f.severity,
                   f.deployment, v.status, v.method, v.summary, r.review_state, s.finished_at,
                   t.target_type, t.repo_name, t.repo_path, t.repo_commit, t.image_repository, t.image_digest
            FROM reach_verdicts v
            JOIN reach_findings f ON f.finding_id = v.finding_id
            JOIN reach_reviews r ON r.finding_id = v.finding_id
            JOIN reach_scans s ON s.scan_id = v.scan_id
            JOIN reach_targets t ON t.target_id = s.target_id
            WHERE v.scan_id = :scanId AND v.method IS DISTINCT FROM 'MANUAL'
            """;

    private final JdbcClient jdbcClient;

    public ReachExportRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    boolean isAdmin(String loginId) {
        return Boolean.TRUE.equals(jdbcClient
                .sql("SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN')")
                .param("loginId", loginId)
                .query(Boolean.class)
                .single());
    }

    /** 없는 스캔이면 빈 값 */
    Optional<String> scanStatus(long scanId) {
        return jdbcClient.sql("SELECT scan_status FROM reach_scans WHERE scan_id = :scanId")
                .param("scanId", scanId)
                .query(String.class)
                .optional();
    }

    /** finding_id 오름차순 keyset. afterId가 있으면 그 다음부터 */
    List<ReachOcsfFindingResponse> findings(long scanId, List<String> statuses, Long afterId, int limit) {
        var conditions = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        params.put("scanId", scanId);
        params.put("limit", limit);
        if (!statuses.isEmpty()) {   // 빈 IN ()은 SQL 오류다
            conditions.add(" AND v.status IN (:statuses)");
            params.put("statuses", statuses);
        }
        if (afterId != null) {
            conditions.add(" AND f.finding_id > :afterId");
            params.put("afterId", afterId);
        }
        return jdbcClient.sql(SCAN_FINDINGS + String.join("", conditions) + " ORDER BY f.finding_id LIMIT :limit")
                .params(params)
                .query(this::finding)
                .list();
    }

    private ReachOcsfFindingResponse finding(ResultSet rs, int rowNum) throws SQLException {
        long id = rs.getLong("finding_id");
        String name = rs.getString("component_name");
        String version = rs.getString("component_version");
        String vulnerabilityId = rs.getString("vulnerability_id");
        return new ReachOcsfFindingResponse(
                "Vulnerability Finding",
                new ReachOcsfFindingResponse.Metadata(new ReachOcsfFindingResponse.Product("Reach", "Logssey")),
                rs.getObject("finished_at", OffsetDateTime.class),
                new ReachOcsfFindingResponse.FindingInfo(String.valueOf(id), vulnerabilityId + " " + name + " " + version),
                List.of(new ReachOcsfFindingResponse.Vulnerability(new ReachOcsfFindingResponse.Cve(vulnerabilityId),
                        List.of(new ReachOcsfFindingResponse.AffectedPackage(name, version, rs.getString("purl"))))),
                List.of(new ReachOcsfFindingResponse.Resource(resourceUid(rs))),
                new ReachOcsfFindingResponse.Unmapped(new ReachOcsfFindingResponse.Reach(
                        rs.getString("severity"), rs.getString("status"), rs.getString("method"),
                        rs.getString("summary"), rs.getString("review_state"), rs.getString("deployment"),
                        "/api/v1/reach/findings/" + id)));
    }

    /** Logssey 자산 ID 형식은 합의 전이라(명세 5-2) 5-3 예시처럼 저장소@digest, 레포는 이름[/하위 경로]@커밋 */
    private static String resourceUid(ResultSet rs) throws SQLException {
        if ("IMAGE".equals(rs.getString("target_type"))) {
            return rs.getString("image_repository") + "@" + rs.getString("image_digest");
        }
        String path = rs.getString("repo_path");
        return rs.getString("repo_name") + (path == null ? "" : "/" + path) + "@" + rs.getString("repo_commit");
    }
}
