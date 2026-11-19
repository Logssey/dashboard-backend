package com.logssey.reach.query;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import java.util.Optional;

import com.logssey.reach.query.dto.ReachFindingResponse;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reach 조회 SQL (API-04 목록, API-05 상세, API-08 요약).
 * 기준 범위는 대상마다 PR이 아닌 최신 SUCCEEDED 스캔이다 (DB 스키마 5절, ARD SR-09). scanId·target으로 좁힐 수 있다.
 * 목록과 요약이 같은 CURRENT_FINDINGS를 써서 숫자가 맞는다
 */
@Repository
public class ReachQueryRepository {
    /**
     * 기준 범위(latest)의 Finding + 현재 판정 + 검토 (DB 스키마 5절). 목록과 요약이 같이 쓴다. latest는 {@link #latest}.
     * Finding은 last_scan_id가 아니라 그 스캔의 도구 판정으로 잇는다. 같은 레포 커밋을 PR로 다시 스캔하면
     * last_scan_id가 PR 스캔으로 바뀌어도 기준 스캔의 Finding이 빠지지 않는다 (API-03 counts와 같은 기준)
     */
    private static final String CURRENT_FINDINGS ="""
     WITH latest AS (
                %s
            )
            SELECT f.finding_id, l.scan_id AS last_scan_id, f.target_id, f.purl, f.component_name, f.component_version,
                   f.vulnerability_id, f.severity, f.fixed_versions, f.deployment, f.first_seen_at,
                   v.status, v.method, v.summary, v.not_analyzed_reason,
                   r.review_state, r.status AS review_status, r.proposal::text AS proposal, r.reset_reason,
                   x.reached AS l3_reached, x.regions_checked AS l3_regions_checked, x.startup_only AS l3_startup_only,
                   CASE v.status WHEN 'REACHABLE' THEN 0 WHEN 'UNKNOWN' THEN 1 WHEN 'UNREACHABLE' THEN 2 ELSE 3 END AS status_rank,
                   CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END AS severity_rank,
                   -- CVE가 아닌 ID(GHSA 등)는 맨 뒤로. NULL이면 커서의 행 비교가 깨져서 큰 값으로 채운다
                   -- 숫자가 9자리를 넘으면 int로 바꿀 수 없어(목록 전체가 500) CVE가 아닌 ID처럼 맨 뒤로 보낸다
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d{1,9}-\\d{1,9}$' THEN split_part(f.vulnerability_id, '-', 2)::int END, 2147483647) AS cve_year,
                   COALESCE(CASE WHEN f.vulnerability_id ~ '^CVE-\\d{1,9}-\\d{1,9}$' THEN split_part(f.vulnerability_id, '-', 3)::int END, 2147483647) AS cve_number
            FROM reach_findings f
            JOIN latest l ON l.target_id = f.target_id
             AND EXISTS (SELECT 1 FROM reach_verdicts lv
                         WHERE lv.finding_id = f.finding_id AND lv.scan_id = l.scan_id
                           AND lv.method IS DISTINCT FROM 'MANUAL')
            JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current
            JOIN reach_reviews r ON r.finding_id = f.finding_id
            LEFT JOIN reach_l3_results x ON x.finding_id = f.finding_id
    """;

    /**
     * 기본 범위의 기준 (API-04·08 basis). running이면 L1의 신선한 조회에서 실행 중인 digest를 앱마다 먼저 쓴다.
     * L1이 꺼진 설치는 Service가 LATEST로 만든다
     */
    record Basis(boolean running, String cluster, List<String> namespaces, String fresh) {
        static final Basis LATEST = new Basis(false, null, List.of(), null);
    }

    /** app·대상 종류(REPO/IMAGE)마다 PR이 아닌 최신 SUCCEEDED 스캔 (basis=LATEST, 그리고 RUNNING의 대신 쓰는 값) */
    private static final String NEWEST = """
            SELECT DISTINCT ON (t.app, t.target_type) s.target_id, s.scan_id, t.app, t.target_type, t.image_digest
            FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
            WHERE s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR'
            ORDER BY t.app, t.target_type, s.finished_at DESC, s.scan_id DESC""";

    /**
     * basis=RUNNING의 기준 스캔 (PRD 목표 3 "실제 배포물 기준").
     * 실행 중 digest(L1 재계산과 같은 신선도)의 이미지 대상마다 PR이 아닌 최신 SUCCEEDED 스캔을 쓴다. 같은 앱이 두 digest로
     * 돌면 둘 다다. 실행 중 스캔이 없는 앱의 이미지와 레포 대상은 NEWEST를 그대로 쓴다(running=false)
     */
    private static final String RUNNING_SCOPE = """
            WITH running AS (
                SELECT DISTINCT w.image_digest
                FROM reach_workloads w
                JOIN reach_workload_observations o ON o.cluster = w.cluster AND o.namespace = w.namespace
                WHERE o.cluster = :basisCluster AND o.namespace IN (:basisNamespaces)
                  AND o.observed_at > now() - CAST(:basisFresh AS interval)
            ), running_scans AS (
                SELECT DISTINCT ON (t.target_id) s.target_id, s.scan_id, t.app, t.target_type, t.image_digest
                FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                WHERE s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR' AND t.target_type = 'IMAGE'
                  AND t.image_digest IN (SELECT image_digest FROM running)
                ORDER BY t.target_id, s.finished_at DESC, s.scan_id DESC
            ), newest AS (
                %s
            )
            SELECT target_id, scan_id, app, target_type, image_digest, true AS running FROM running_scans
            UNION ALL
            SELECT n.target_id, n.scan_id, n.app, n.target_type, n.image_digest, false AS running FROM newest n
            WHERE n.target_type = 'REPO' OR NOT EXISTS (SELECT 1 FROM running_scans r WHERE r.app = n.app)""".formatted(NEWEST);

    /** 기본 범위의 스캔 목록 (app, target_type, target_id, scan_id, image_digest, running) */
    private static String scopeScans(Basis basis) {
        return basis.running() ? RUNNING_SCOPE
                : "SELECT n.target_id, n.scan_id, n.app, n.target_type, n.image_digest, false AS running FROM (" + NEWEST + ") n";
    }

    /**
     * 기준 범위 (API-04·08 scanId·target·basis).
     * scanId가 있으면 그 스캔 하나다. PR 검사의 스캔도 이렇게 지정하면 본다 (API-12 findingsUrl).
     * target이 있으면 그 대상의 PR이 아닌 최신 스캔이다. 스캔이 있는지·끝났는지는 Service가 먼저 확인한다.
     * 둘 다 없으면 기본 범위다(basis). LATEST는 app·대상 종류(REPO/IMAGE)마다 PR이 아닌 최신 SUCCEEDED 스캔 하나(ARD SR-09):
     * 이미지를 다시 빌드하면 digest마다 대상이 생기는데, 대상마다로 두면 옛 이미지의 Finding이 요약에 계속 쌓여서다.
     * RUNNING은 실행 중 이미지의 스캔을 앱마다 먼저 쓴다(RUNNING_SCOPE)
     */
    private static String latest(Long scanId, Long target, Basis basis) {
        if (scanId != null) return "SELECT target_id, scan_id FROM reach_scans WHERE scan_id = :scopeScan";
        if (target == null) return "SELECT target_id, scan_id FROM (" + scopeScans(basis) + ") scope";
        return """
                SELECT DISTINCT ON (t.app, t.target_type) s.target_id, s.scan_id
                FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                WHERE s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR' AND s.target_id = :scopeTarget
                ORDER BY t.app, t.target_type, s.finished_at DESC, s.scan_id DESC""";
    }

    static String currentFindings(Long scanId, Long target, Basis basis) {
        return CURRENT_FINDINGS.formatted(latest(scanId, target, basis));
    }

    /** latest()가 쓰는 파라미터를 넣는다 */
    private static void scope(Map<String, Object> params, Long scanId, Long target, Basis basis) {
        if (scanId != null) params.put("scopeScan", scanId);
        else if (target != null) params.put("scopeTarget", target);
        else basisParams(params, basis);
    }

    private static void basisParams(Map<String, Object> params, Basis basis) {
        if (!basis.running()) return;
        params.put("basisCluster", basis.cluster());
        params.put("basisNamespaces", basis.namespaces());
        params.put("basisFresh", basis.fresh());
    }

    /** 기본 범위로 쓴 스캔 (API-08 basis.scans) */
    record ScopeScan(String app, String targetType, long targetId, long scanId, String imageDigest, boolean running) {}

    List<ScopeScan> scopeScanList(Basis basis) {
        var params = new HashMap<String, Object>();
        basisParams(params, basis);
        return jdbcClient.sql("SELECT * FROM (" + scopeScans(basis) + ") scope ORDER BY app, target_type, running DESC, scan_id")
                .params(params)
                .query((rs, i) -> new ScopeScan(rs.getString("app"), rs.getString("target_type"), rs.getLong("target_id"),
                        rs.getLong("scan_id"), rs.getString("image_digest"), rs.getBoolean("running")))
                .list();
    }

    /** 신선한 조회가 하나라도 있나. 없으면 RUNNING을 줄 수 없어 LATEST와 같다 (API-08 basis.applied) */
    boolean hasFreshObservation(Basis basis) {
        if (!basis.running()) return false;
        var params = new HashMap<String, Object>();
        basisParams(params, basis);
        return Boolean.TRUE.equals(jdbcClient.sql("""
                        SELECT EXISTS (SELECT 1 FROM reach_workload_observations o
                                       WHERE o.cluster = :basisCluster AND o.namespace IN (:basisNamespaces)
                                         AND o.observed_at > now() - CAST(:basisFresh AS interval))""")
                .params(params)
                .query(Boolean.class)
                .single());
    }

    /** 실행 중인데 PR이 아닌 성공 스캔이 없는 워크로드 (API-08 basis.unscannedRunning). repository는 API-07과 같은 식 */
    record UnscannedWorkload(String namespace, String name, String container, String imageRepository, String imageDigest) {}

    List<UnscannedWorkload> unscannedRunning(Basis basis) {
        if (!basis.running()) return List.of();
        var params = new HashMap<String, Object>();
        basisParams(params, basis);
        return jdbcClient.sql("""
                        SELECT w.namespace, w.name, w.container, w.image_digest,
                               regexp_replace(regexp_replace(split_part(w.image, '@', 1), ':[^/:]*$', ''),
                                              '^(localhost|[^/]*[.:][^/]*)/', '') AS repository
                        FROM reach_workloads w
                        JOIN reach_workload_observations o ON o.cluster = w.cluster AND o.namespace = w.namespace
                        WHERE o.cluster = :basisCluster AND o.namespace IN (:basisNamespaces)
                          AND o.observed_at > now() - CAST(:basisFresh AS interval)
                          AND NOT EXISTS (SELECT 1 FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                                          WHERE t.target_type = 'IMAGE' AND t.image_digest = w.image_digest
                                            AND s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR')
                        ORDER BY w.namespace, w.name, w.container, w.image_digest""")
                .params(params)
                .query((rs, i) -> new UnscannedWorkload(rs.getString("namespace"), rs.getString("name"),
                        rs.getString("container"), rs.getString("repository"), rs.getString("image_digest")))
                .list();
    }

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

    boolean targetExists(long targetId) {
        return Boolean.TRUE.equals(jdbcClient
                .sql("SELECT EXISTS (SELECT 1 FROM reach_targets WHERE target_id = :targetId)")
                .param("targetId", targetId)
                .query(Boolean.class)
                .single());
    }

    /** 범위로 지정한 스캔의 대상과 상태 */
    record ScanState(long targetId, String status) {}

    Optional<ScanState> scanState(long scanId) {
        return jdbcClient.sql("SELECT target_id, scan_status FROM reach_scans WHERE scan_id = :scanId")
                .param("scanId", scanId)
                .query((rs, i) -> new ScanState(rs.getLong("target_id"), rs.getString("scan_status")))
                .optional();
    }

    /** 대상 하나의 기준 스캔 (API-08 scope.scanId). 없으면 null */
    Long baselineScan(long targetId) {
        return jdbcClient.sql(latest(null, targetId, Basis.LATEST))
                .param("scopeTarget", targetId)
                .query((rs, i) -> rs.getLong("scan_id"))
                .optional()
                .orElse(null);
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
                // L3 결과가 없으면 null (앱을 띄워 본 적 없는 이미지, 판정 데이터 없는 CVE)
                rs.getString("l3_reached") == null ? null : new ReachFindingResponse.L3(rs.getString("l3_reached"),
                        rs.getBoolean("l3_regions_checked"), rs.getBoolean("l3_startup_only")),
                rs.getObject("first_seen_at", OffsetDateTime.class));
    }

    /** 배열 안의 NULL은 버린다. List.of는 null 원소에서 NPE를 내서 그 행이 든 목록·상세가 500이 된다 */
    private static List<String> strings(Array array) throws SQLException {
        return array == null ? List.of()
                : Arrays.stream((String[]) array.getArray()).filter(Objects::nonNull).toList();
    }

    /** INTEGER[] 칸. NOT NULL DEFAULT '{}'라 보통 빈 배열이지만 strings()처럼 NULL 원소는 뺀다 */
    private static List<Integer> integers(Array array) throws SQLException {
        return array == null ? List.of()
                : Arrays.stream((Integer[]) array.getArray()).filter(Objects::nonNull).toList();
    }

    private JsonNode json(String value) {
        return value == null ? null : mapper.readTree(value);
    }
    /** 목록 한 행 + 커서용 정렬 키 */
    record Row(ReachFindingResponse item, int statusRank, int severityRank, int cveYear, int cveNumber) {}

    private record Where(String sql, Map<String, Object> params) {}

    List<Row> findings(ReachFindingFilter filter, Basis basis, ReachFindingCursor after, int limit) {
        var where = where(filter, basis, after);
        var params = new HashMap<>(where.params());
        params.put("limit", limit);
        return jdbcClient.sql("SELECT * FROM (" + currentFindings(filter.scanId(), filter.target(), basis) + ") c"
                        + where.sql() + DEFAULT_ORDER + " LIMIT :limit")
                .params(params)
                .query(this::row)
                .list();
    }

    long countFindings(ReachFindingFilter filter, Basis basis) {
        var where = where(filter, basis, null);   // 개수는 커서와 무관하게 필터 전체
        return jdbcClient.sql("SELECT count(*) FROM (" + currentFindings(filter.scanId(), filter.target(), basis) + ") c" + where.sql())
                .params(where.params())
                .query(Long.class)
                .single();
    }

    private Where where(ReachFindingFilter filter, Basis basis, ReachFindingCursor after) {
        var conditions = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        scope(params, filter.scanId(), filter.target(), basis);
        in(conditions, params, "status", filter.status());
        in(conditions, params, "severity", filter.severity());
        in(conditions, params, "review_state", filter.reviewState());
        in(conditions, params, "deployment", filter.deployment());
        in(conditions, params, "l3_reached", filter.l3());
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
    List<SummaryRow> summaryRows(Long scanId, Long target, Basis basis, List<String> deployment) {
        var params = new HashMap<String, Object>();
        scope(params, scanId, target, basis);
        var where = deployment.isEmpty() ? "" : " WHERE deployment IN (:deployment)";
        if (!deployment.isEmpty()) params.put("deployment", deployment);
        var spec = jdbcClient.sql("""
                SELECT status, severity, method, review_state, deployment, not_analyzed_reason, count(*) AS n
                FROM (%s) c%s
                GROUP BY status, severity, method, review_state, deployment, not_analyzed_reason
                """.formatted(currentFindings(scanId, target, basis), where))
                .params(params);
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
               f.component_path,
               f.vulnerability_id, f.severity, f.severity_note, f.vuln_title, f.vuln_description, f.affected_feature,
               f.fixed_versions, f.cwe_ids, f.reference_urls,
               f.deployment, f.sources, f.upgrade::text AS upgrade, f.first_seen_at, f.last_seen_at,
               v.status, v.method, v.summary, v.not_analyzed_reason, v.rule_id, v.vuln_function_ids,
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
               x.reached AS l3_reached, x.regions_checked AS l3_regions_checked, x.startup_only AS l3_startup_only,
               x.detail::text AS l3_detail, x.scan_id AS l3_scan_id,
               lr.scenario AS l3_scenario, lr.observation_method AS l3_method, lr.observed_at AS l3_observed_at,
               lr.detail::text AS l3_run_detail,
               ARRAY(SELECT o.finding_id FROM reach_findings o
                     WHERE o.last_scan_id = f.last_scan_id AND o.vulnerability_id = f.vulnerability_id
                       AND o.finding_id <> f.finding_id
                     ORDER BY o.finding_id) AS same_cve
        FROM reach_findings f
        JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current
        JOIN reach_reviews r ON r.finding_id = f.finding_id
        LEFT JOIN dashboard_users u ON u.user_id = r.reviewer_user_id
        LEFT JOIN reach_reviews cr ON cr.finding_id = r.carried_from_finding_id
        LEFT JOIN reach_l3_results x ON x.finding_id = f.finding_id
        LEFT JOIN reach_l3_runs lr ON lr.scan_id = x.scan_id
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
                        rs.getString("component_version"), rs.getString("ecosystem"), rs.getString("component_path")),
                new ReachFindingDetailResponse.Vulnerability(rs.getString("vulnerability_id"), rs.getString("severity"),
                        rs.getString("severity_note"), rs.getString("vuln_title"), rs.getString("vuln_description"),
                        rs.getString("affected_feature"), strings(rs.getArray("fixed_versions")),
                        strings(rs.getArray("cwe_ids")), strings(rs.getArray("reference_urls"))),
                rs.getString("deployment"),
                strings(rs.getArray("sources")),
                new ReachFindingDetailResponse.Verdict(status, rs.getString("method"), rs.getString("summary"),
                        rs.getString("not_analyzed_reason"), rs.getString("rule_id"),
                        integers(rs.getArray("vuln_function_ids")),
                        json(rs.getString("callgraph")), json(rs.getString("evidence")),
                        rs.getObject("analyzed_at", OffsetDateTime.class), json(rs.getString("engine"))),
                // 사람 판정이 있고 현재 판정과 다르면 true (FR-08, 목록과 같은 규칙)
                new ReachFindingDetailResponse.Review(rs.getString("review_state"), reviewStatus, rs.getString("note"),
                        reviewer(rs), rs.getObject("reviewed_at", OffsetDateTime.class), rs.getInt("version"),
                        reviewStatus != null && !reviewStatus.equals(status),
                        json(rs.getString("proposal")), carriedFrom, rs.getString("reset_reason"),
                        null),   // history는 Service가 include=reviewHistory일 때만 채운다
                l3(rs),
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
    /** L3 결과와 그 실행의 근거 항목. 결과가 없으면 null */
    private ReachFindingDetailResponse.L3 l3(ResultSet rs) throws SQLException {
        String reached = rs.getString("l3_reached");
        if (reached == null) return null;
        JsonNode detail = json(rs.getString("l3_detail"));
        JsonNode run = json(rs.getString("l3_run_detail"));
        JsonNode note = detail.get("note");
        return new ReachFindingDetailResponse.L3(reached, rs.getBoolean("l3_regions_checked"),
                rs.getBoolean("l3_startup_only"),
                detail.get("during"), detail.get("functions"), detail.get("regions"), detail.get("paths"),
                note == null || !note.isString() ? null : note.asString(),
                new ReachFindingDetailResponse.L3Run(rs.getLong("l3_scan_id"), rs.getString("l3_scenario"),
                        rs.getString("l3_method"), rs.getObject("l3_observed_at", OffsetDateTime.class),
                        run.get("build"), run.get("configKeys"), run.get("invocations"),
                        run.get("rematch") != null && run.get("rematch").asBoolean()));
    }

    private static ReachFindingDetailResponse.Reviewer reviewer(ResultSet rs) throws SQLException {
        long id = rs.getLong("reviewer_id");
        return rs.wasNull() ? null : new ReachFindingDetailResponse.Reviewer(id, rs.getString("reviewer_name"));
    }
}