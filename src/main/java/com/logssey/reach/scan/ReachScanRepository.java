package com.logssey.reach.scan;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Reach 스캔 조회 SQL (API-02 이력, API-03 상세). 둘이 SCANS와 countRows를 같이 쓴다 */
@Repository
public class ReachScanRepository {
    /**
     * 스캔 + 대상. 상세는 WHERE만 붙이고, 목록은 감싸서 필터·정렬을 붙인다. JSONB 칸은 ::text로 받아 json()으로 바꾼다.
     * created_key·finished_key는 목록 정렬·커서용 정수(마이크로초). 안 끝난 스캔의 finished_at은 NULL이라
     * 커서의 행 비교가 깨져서 가장 큰 값으로 채운다(내림차순에서 맨 위, 오름차순에서 맨 아래)
     */
    static final String SCANS = """
            SELECT s.scan_id, s.scan_status, s.trigger_type, s.rescan_of_scan_id,
                   (extract(epoch FROM s.created_at) * 1000000)::bigint AS created_key,
                   COALESCE((extract(epoch FROM s.finished_at) * 1000000)::bigint, 9223372036854775807) AS finished_key,
                   s.stages::text AS stages, s.tools::text AS tools, s.analysis::text AS analysis,
                   s.requested_by_kind, s.requested_by_user_id, s.requested_by_repository, s.requested_by_subject,
                   s.failure_code, s.failure_stage, s.failure_message, s.created_at, s.started_at, s.finished_at,
                   t.target_id, t.target_type, t.app, t.repo_name, t.repo_path, t.repo_commit,
                   t.image_repository, t.image_digest, t.image_revision, t.image_created_at,
                   t.source_tree, t.display_name,
                   lr.run_status AS l3_status, lr.error AS l3_error, lr.scenario AS l3_scenario,
                   lr.observed_at AS l3_observed_at, lr.counts::text AS l3_counts
            FROM reach_scans s
            JOIN reach_targets t ON t.target_id = s.target_id
            LEFT JOIN reach_l3_runs lr ON lr.scan_id = s.scan_id
            """;

    private final JdbcClient jdbcClient;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public ReachScanRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    boolean isAdmin(String loginId) {
        return Boolean.TRUE.equals(jdbcClient
                .sql("SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN')")
                .param("loginId", loginId)
                .query(Boolean.class)
                .single());
    }

    Optional<ReachScanResponse> scan(long scanId) {
        return jdbcClient.sql(SCANS + " WHERE s.scan_id = :scanId")
                .param("scanId", scanId)
                .query(this::scanRow)
                .optional();
    }

    /** 목록 한 행 + 커서용 정렬 키(고른 정렬의 created_key 또는 finished_key) */
    record Row(ReachScanResponse item, long sortKey) {}

    private record Where(String sql, Map<String, Object> params) {}

    /** 정렬 키 열과 방향. 같은 키면 scan_id로 같은 방향으로 가른다 */
    private record Order(String key, boolean desc) {}

    /**
     * ORDER BY의 열 이름은 파라미터(:name)로 넘길 수 없어 문자열로 붙인다.
     * 사용자 값을 그대로 붙이면 SQL 인젝션이라 정해진 넷 중에서만 고른다(그 밖의 값은 필터가 이미 400)
     */
    private static Order order(String sort) {
        return switch (sort) {
            case "createdAt" -> new Order("created_key", false);
            case "-finishedAt" -> new Order("finished_key", true);
            case "finishedAt" -> new Order("finished_key", false);
            default -> new Order("created_key", true);   // -createdAt (기본)
        };
    }

    boolean targetExists(long targetId) {
        return Boolean.TRUE.equals(jdbcClient
                .sql("SELECT EXISTS (SELECT 1 FROM reach_targets WHERE target_id = :targetId)")
                .param("targetId", targetId)
                .query(Boolean.class)
                .single());
    }

    /** API-02 목록 */
    List<Row> scans(ReachScanFilter filter, ReachScanCursor after, int limit) {
        var order = order(filter.sort());
        var where = where(filter, after, order);
        var params = new HashMap<>(where.params());
        params.put("limit", limit);
        String dir = order.desc() ? " DESC" : " ASC";
        return jdbcClient.sql("SELECT * FROM (" + SCANS + ") c" + where.sql()
                        + " ORDER BY " + order.key() + dir + ", scan_id" + dir + " LIMIT :limit")
                .params(params)
                .query((rs, i) -> new Row(scanRow(rs, i), rs.getLong(order.key())))
                .list();
    }

    /** include=total. 커서와 무관하게 필터 전체를 센다 */
    long countScans(ReachScanFilter filter) {
        var where = where(filter, null, order(filter.sort()));
        return jdbcClient.sql("SELECT count(*) FROM (" + SCANS + ") c" + where.sql())
                .params(where.params())
                .query(Long.class)
                .single();
    }

    private Where where(ReachScanFilter filter, ReachScanCursor after, Order order) {
        var conditions = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        if (filter.target() != null) {
            conditions.add("target_id = :target");
            params.put("target", filter.target());
        }
        in(conditions, params, "scan_status", filter.scanStatus());
        in(conditions, params, "trigger_type", filter.trigger());
        // Instant를 OffsetDateTime으로 바꿔 넘겨야 드라이버가 timestamptz로 맞춘다
        if (filter.from() != null) {
            conditions.add("created_at >= :from");
            params.put("from", OffsetDateTime.ofInstant(filter.from(), ZoneOffset.UTC));
        }
        if (filter.to() != null) {
            conditions.add("created_at < :to");
            params.put("to", OffsetDateTime.ofInstant(filter.to(), ZoneOffset.UTC));
        }
        if (after != null) {
            // 내림차순이면 마지막 행보다 작은 쪽, 오름차순이면 큰 쪽이 다음 페이지
            conditions.add("(" + order.key() + ", scan_id) " + (order.desc() ? "<" : ">") + " (:afterKey, :afterId)");
            params.put("afterKey", after.sortKey());
            params.put("afterId", after.scanId());
        }
        return new Where(conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions), params);
    }

    /** 값이 있을 때만 "열 IN (...)"을 붙인다. 빈 IN ()은 SQL 오류다 */
    private static void in(List<String> conditions, Map<String, Object> params, String column, List<String> values) {
        if (values.isEmpty()) return;
        conditions.add(column + " IN (:" + column + ")");
        params.put(column, values);
    }

    /** 개수용 한 줄: 스캔·상태·심각도·검토 조합과 그 개수 */
    record CountRow(long scanId, String status, String severity, String reviewState, long count) {}

    /**
     * 스캔마다 그 스캔이 낸 도구 판정을 조합별로 센다. 합계는 Service가 낸다.
     * reach_findings.last_scan_id로 세면 Finding이 다음 스캔에 또 나올 때 예전 스캔의 개수가 줄어서, 판정의 scan_id로 센다.
     * MANUAL(사람 판정)은 빼서 스캔 결과는 스캔이 낸 값으로 둔다. method가 NULL(NOT_ANALYZED)인 행도 세야 해서 <>가 아니라 IS DISTINCT FROM.
     * 검토는 Finding마다 지금 한 행뿐이라 byReviewState는 지금의 검토 상태다.
     * 스캔 id를 목록으로 받아 이력(API-02) 한 페이지도 쿼리 한 번으로 센다
     */
    List<CountRow> countRows(List<Long> scanIds) {
        if (scanIds.isEmpty()) return List.of();   // 빈 IN ()은 SQL 오류다
        return jdbcClient.sql("""
                        SELECT v.scan_id, v.status, f.severity, r.review_state, count(*) AS n
                        FROM reach_verdicts v
                        JOIN reach_findings f ON f.finding_id = v.finding_id
                        JOIN reach_reviews r ON r.finding_id = v.finding_id
                        WHERE v.scan_id IN (:scanIds) AND v.method IS DISTINCT FROM 'MANUAL'
                        GROUP BY v.scan_id, v.status, f.severity, r.review_state
                        """)
                .param("scanIds", scanIds)
                .query((rs, i) -> new CountRow(rs.getLong("scan_id"), rs.getString("status"),
                        rs.getString("severity"), rs.getString("review_state"), rs.getLong("n")))
                .list();
    }

    /** NULL일 수 있는 BIGINT는 getObject(…, Long.class)로 읽는다. getLong은 NULL을 0으로 준다 */
    private ReachScanResponse scanRow(ResultSet rs, int rowNum) throws SQLException {
        String type = rs.getString("target_type");
        var target = new ReachScanResponse.Target(rs.getLong("target_id"), type, rs.getString("app"),
                "REPO".equals(type)
                        ? new ReachScanResponse.Repo(rs.getString("repo_name"), rs.getString("repo_path"),
                                rs.getString("repo_commit"))
                        : null,
                "IMAGE".equals(type)
                        ? new ReachScanResponse.Image(rs.getString("image_repository"), rs.getString("image_digest"),
                                rs.getString("image_revision"), rs.getObject("image_created_at", OffsetDateTime.class))
                        : null,
                rs.getString("source_tree"), rs.getString("display_name"));

        String status = rs.getString("scan_status");
        var failure = "FAILED".equals(status)
                ? new ReachScanResponse.Failure(rs.getString("failure_code"), rs.getString("failure_stage"),
                        rs.getString("failure_message"))
                : null;

        return new ReachScanResponse(
                rs.getLong("scan_id"), status, rs.getString("trigger_type"),
                rs.getObject("rescan_of_scan_id", Long.class),
                target,
                json(rs.getString("stages")), json(rs.getString("tools")), json(rs.getString("analysis")),
                null,   // counts는 Service가 SUCCEEDED일 때만 채운다
                failure,
                new ReachScanResponse.RequestedBy(rs.getString("requested_by_kind"),
                        rs.getObject("requested_by_user_id", Long.class),
                        rs.getString("requested_by_repository"), rs.getString("requested_by_subject")),
                rs.getString("l3_status") == null ? null : new ReachScanResponse.L3(rs.getString("l3_status"),
                        rs.getString("l3_error"), rs.getString("l3_scenario"),
                        rs.getObject("l3_observed_at", OffsetDateTime.class), json(rs.getString("l3_counts"))),
                rs.getObject("created_at", OffsetDateTime.class),
                rs.getObject("started_at", OffsetDateTime.class),
                rs.getObject("finished_at", OffsetDateTime.class));
    }

    private JsonNode json(String value) {
        return value == null ? null : mapper.readTree(value);
    }
}
