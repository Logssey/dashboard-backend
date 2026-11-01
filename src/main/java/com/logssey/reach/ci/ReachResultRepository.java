package com.logssey.reach.ci;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Reach 결과 적재 SQL (API-13, DB 스키마 4절 적재 규칙). Service가 한 트랜잭션으로 부른다.
 * 배열·JSONB 칸은 JSON 문자열로 넘겨 SQL에서 바꾼다. 자바 배열을 넘기면 Spring이 (?, ?, …)로 펼칠 수 있어서다.
 * JdbcClient는 paramSource(record)와 param(이름, 값)을 같이 쓰면 예외라서, 칸이 많은 INSERT만 record로 넘긴다
 */
@Repository
public class ReachResultRepository {

    private final JdbcClient jdbcClient;

    public ReachResultRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("SELECT user_id FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN'")
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    /** 검사와 그 스캔. app은 검토 이어받기 키다 (DB 스키마 3-2: MVP의 서비스 단위) */
    record CheckState(long scanId, boolean uploaded, String scanStatus, long targetId, String app) {}

    /** 같은 검사에 동시에 올리면 두 번째 요청은 첫 트랜잭션이 끝날 때까지 기다렸다가 uploaded를 본다 */
    Optional<CheckState> lockCheck(long checkId) {
        return jdbcClient.sql("""
                        SELECT c.scan_id, c.results_uploaded_at IS NOT NULL AS uploaded, s.scan_status, s.target_id, t.app
                        FROM reach_ci_checks c
                        JOIN reach_scans s ON s.scan_id = c.scan_id
                        JOIN reach_targets t ON t.target_id = s.target_id
                        WHERE c.check_id = :checkId
                        FOR UPDATE OF c, s
                        """)
                .param("checkId", checkId)
                .query((rs, i) -> new CheckState(rs.getLong("scan_id"), rs.getBoolean("uploaded"),
                        rs.getString("scan_status"), rs.getLong("target_id"), rs.getString("app")))
                .optional();
    }

    /** 러너가 돈 단계와 도구 기록. JSON 문자열로 받는다 (analysis는 없을 수 있다) */
    record ScanRecord(String tools, String analysis, String stages) {}

    void startScan(long scanId, ScanRecord record) {
        jdbcClient.sql("""
                        UPDATE reach_scans
                        SET scan_status = 'RUNNING', started_at = COALESCE(started_at, now()),
                            tools = CAST(:tools AS jsonb), analysis = CAST(:analysis AS jsonb), stages = CAST(:stages AS jsonb)
                        WHERE scan_id = :scanId
                        """)
                .param("scanId", scanId)
                .param("tools", record.tools())
                .param("analysis", record.analysis())
                .param("stages", record.stages())
                .update();
    }

    void succeedScan(long scanId) {
        jdbcClient.sql("UPDATE reach_scans SET scan_status = 'SUCCEEDED', finished_at = now() WHERE scan_id = :scanId")
                .param("scanId", scanId)
                .update();
    }

    /** 러너가 보낸 실패 사유로 끝낸다. 결과 행은 넣지 않는다 */
    void failScan(long scanId, ScanRecord record, ReachResultBundle.Failure failure) {
        jdbcClient.sql("""
                        UPDATE reach_scans
                        SET scan_status = 'FAILED', started_at = COALESCE(started_at, now()), finished_at = now(),
                            tools = CAST(:tools AS jsonb), analysis = CAST(:analysis AS jsonb), stages = CAST(:stages AS jsonb),
                            failure_code = :code, failure_stage = :stage, failure_message = :message
                        WHERE scan_id = :scanId
                        """)
                .param("scanId", scanId)
                .param("tools", record.tools())
                .param("analysis", record.analysis())
                .param("stages", record.stages())
                .param("code", failure.code())
                .param("stage", failure.stage())
                .param("message", failure.message())
                .update();
    }

    /**
     * 적재 중에 서버 오류가 나면 Service가 앞 트랜잭션을 되돌린 뒤 새 트랜잭션으로 부른다 (DB 스키마 4절 6단계: 스캔만 FAILED로 남긴다).
     * 그사이 다른 요청이 끝냈으면 건드리지 않는다
     */
    void failAfterError(long checkId) {
        jdbcClient.sql("""
                        UPDATE reach_scans s
                        SET scan_status = 'FAILED', started_at = COALESCE(s.started_at, now()), finished_at = now(),
                            failure_code = 'INTERNAL_ERROR', failure_stage = 'REPORT',
                            failure_message = 'Saving the uploaded results failed'
                        FROM reach_ci_checks c
                        WHERE c.check_id = :checkId AND s.scan_id = c.scan_id AND s.scan_status IN ('QUEUED', 'RUNNING')
                        """)
                .param("checkId", checkId)
                .update();
        markUploaded(checkId);
    }

    /** 같은 검사에 다시 올리면 409 (명세 API-13) */
    void markUploaded(long checkId) {
        jdbcClient.sql("UPDATE reach_ci_checks SET results_uploaded_at = now() WHERE check_id = :checkId AND results_uploaded_at IS NULL")
                .param("checkId", checkId)
                .update();
    }

    /** Finding 칸. 배열과 upgrade는 JSON 문자열이다. paramSource()는 param()과 같이 쓸 수 없어 id도 여기에 둔다 */
    record FindingInput(long targetId, long scanId, String purl, String name, String version, String ecosystem, String path,
                        String vulnerabilityId, String severity, String severityNote, String title, String description,
                        String affectedFeature, String fixedVersions, String cweIds, String referenceUrls,
                        String sources, String deployment, String upgrade) {

        /** 검사할 때는 대상·스캔을 모르고 0으로 두었다가 적재할 때 채운다 */
        FindingInput withIds(long targetId, long scanId) {
            return new FindingInput(targetId, scanId, purl, name, version, ecosystem, path, vulnerabilityId, severity,
                    severityNote, title, description, affectedFeature, fixedVersions, cweIds, referenceUrls, sources,
                    deployment, upgrade);
        }
    }

    record UpsertedFinding(long id, boolean inserted) {}

    /**
     * (대상, purl, 취약점 ID)로 찾아 있으면 스캐너 값과 마지막 스캔·시각을 바꾸고, 없으면 만든다 (DB 스키마 4절 3단계).
     * first_seen_at은 처음 만들 때만 쓴다. xmax = 0이면 이번에 새로 넣은 행이다(PostgreSQL에서 갱신한 행은 xmax가 채워진다)
     */
    UpsertedFinding upsertFinding(FindingInput f) {
        return jdbcClient.sql("""
                        INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                                    component_path, vulnerability_id, severity, severity_note, vuln_title,
                                                    vuln_description, affected_feature, fixed_versions, cwe_ids,
                                                    reference_urls, sources, deployment, upgrade, last_scan_id,
                                                    first_seen_at, last_seen_at)
                        VALUES (:targetId, :purl, :name, :version, :ecosystem, :path, :vulnerabilityId, :severity,
                                :severityNote, :title, :description, :affectedFeature,
                                ARRAY(SELECT jsonb_array_elements_text(CAST(:fixedVersions AS jsonb))),
                                ARRAY(SELECT jsonb_array_elements_text(CAST(:cweIds AS jsonb))),
                                ARRAY(SELECT jsonb_array_elements_text(CAST(:referenceUrls AS jsonb))),
                                ARRAY(SELECT jsonb_array_elements_text(CAST(:sources AS jsonb))),
                                :deployment, CAST(:upgrade AS jsonb), :scanId, now(), now())
                        ON CONFLICT (target_id, purl, vulnerability_id) DO UPDATE
                        SET component_name = EXCLUDED.component_name, component_version = EXCLUDED.component_version,
                            ecosystem = EXCLUDED.ecosystem, component_path = EXCLUDED.component_path,
                            severity = EXCLUDED.severity, severity_note = EXCLUDED.severity_note,
                            vuln_title = EXCLUDED.vuln_title, vuln_description = EXCLUDED.vuln_description,
                            affected_feature = EXCLUDED.affected_feature, fixed_versions = EXCLUDED.fixed_versions,
                            cwe_ids = EXCLUDED.cwe_ids, reference_urls = EXCLUDED.reference_urls,
                            sources = EXCLUDED.sources, deployment = EXCLUDED.deployment, upgrade = EXCLUDED.upgrade,
                            last_scan_id = EXCLUDED.last_scan_id, last_seen_at = EXCLUDED.last_seen_at
                        RETURNING finding_id, xmax = 0 AS inserted
                        """)
                .paramSource(f)
                .query((rs, i) -> new UpsertedFinding(rs.getLong("finding_id"), rs.getBoolean("inserted")))
                .single();
    }

    /** 도구 판정 칸. vulnFunctionIds·callgraph·engine은 JSON 문자열이다 */
    record VerdictInput(long findingId, long scanId, String status, String method, String notAnalyzedReason, String summary, String ruleId,
                        String vulnFunctionIds, String callgraph, String engine, String evidenceHash,
                        OffsetDateTime analyzedAt) {

        VerdictInput withIds(long findingId, long scanId) {
            return new VerdictInput(findingId, scanId, status, method, notAnalyzedReason, summary, ruleId,
                    vulnFunctionIds, callgraph, engine, evidenceHash, analyzedAt);
        }
    }

    /** 현재 판정으로 올리는 것은 Service가 검토를 본 뒤에 한다 */
    long insertToolVerdict(VerdictInput v) {
        return jdbcClient.sql("""
                        INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                                    rule_id, vuln_function_ids, callgraph, engine, evidence_hash,
                                                    is_current, analyzed_at)
                        VALUES (:findingId, :scanId, :status, :method, :notAnalyzedReason, :summary, :ruleId,
                                ARRAY(SELECT jsonb_array_elements_text(CAST(:vulnFunctionIds AS jsonb))::int),
                                CAST(:callgraph AS jsonb), CAST(:engine AS jsonb), :evidenceHash,
                                false, COALESCE(:analyzedAt, now()))
                        RETURNING verdict_id
                        """)
                .paramSource(v)
                .query(Long.class)
                .single();
    }

    /** 근거 한 줄. detail은 3-5의 나머지 필드를 API 이름 그대로 담은 JSON 문자열이다 */
    record EvidenceInput(int ord, String kind, String summary, String factId, String ruleId, boolean informational,
                         String detail) {}

    void insertEvidence(long verdictId, List<EvidenceInput> evidence) {
        for (var e : evidence) {
            jdbcClient.sql("""
                            INSERT INTO reach_evidence (verdict_id, ord, kind, summary, fact_id, rule_id, informational, detail)
                            VALUES (:verdictId, :ord, :kind, :summary, :factId, :ruleId, :informational, CAST(:detail AS jsonb))
                            """)
                    .param("verdictId", verdictId)
                    .param("ord", e.ord())
                    .param("kind", e.kind())
                    .param("summary", e.summary())
                    .param("factId", e.factId())
                    .param("ruleId", e.ruleId())
                    .param("informational", e.informational())
                    .param("detail", e.detail())
                    .update();
        }
    }

    /** 이어받을 검토. 다른 Finding의 사람 판정과 그 검토가 본 도구 판정 */
    record CarrySource(long findingId, long scanId, String reviewState, String status, String note,
                       long reviewerUserId, OffsetDateTime reviewedAt, Long baseVerdictId) {}

    /**
     * 같은 app·purl·취약점 ID를 가진 가장 최근 다른 Finding (DB 스키마 4절 5단계). 그 Finding이 검토 전이면 이어받지 않는다.
     * 이미지 digest가 바뀌거나 커밋이 바뀌면 대상이 달라 Finding이 새로 생기는데, 그때 사람 검토를 다시 하지 않게 하려는 것이다
     */
    Optional<CarrySource> carrySource(String app, String purl, String vulnerabilityId, long findingId) {
        return jdbcClient.sql("""
                        SELECT f.finding_id, f.last_scan_id, r.review_state, r.status, r.note, r.reviewer_user_id,
                               r.reviewed_at, r.base_verdict_id
                        FROM reach_findings f
                        JOIN reach_targets t ON t.target_id = f.target_id
                        JOIN reach_reviews r ON r.finding_id = f.finding_id
                        WHERE t.app = :app AND f.purl = :purl AND f.vulnerability_id = :vulnerabilityId
                          AND f.finding_id <> :findingId
                        ORDER BY f.last_seen_at DESC, f.finding_id DESC
                        LIMIT 1
                        """)
                .param("app", app)
                .param("purl", purl)
                .param("vulnerabilityId", vulnerabilityId)
                .param("findingId", findingId)
                .query((rs, i) -> new CarrySource(rs.getLong("finding_id"), rs.getLong("last_scan_id"),
                        rs.getString("review_state"), rs.getString("status"), rs.getString("note"),
                        rs.getLong("reviewer_user_id"), rs.getObject("reviewed_at", OffsetDateTime.class),
                        rs.getObject("base_verdict_id", Long.class)))
                .optional()
                .filter(source -> !"UNREVIEWED".equals(source.reviewState()));
    }

    /** 새 Finding의 검토 전 행 (version 1). 처음 행이라 이력은 남기지 않는다 (API-05 이력과 같은 규칙) */
    void insertReview(long findingId, long baseVerdictId, String proposal) {
        jdbcClient.sql("""
                        INSERT INTO reach_reviews (finding_id, proposal, base_verdict_id)
                        VALUES (:findingId, CAST(:proposal AS jsonb), :baseVerdictId)
                        """)
                .param("findingId", findingId)
                .param("proposal", proposal)
                .param("baseVerdictId", baseVerdictId)
                .update();
    }

    /** 이어받은 검토 (version 1). 검토자·시각도 복사한다: 사람 판정이면 둘 다 있어야 한다 (V34 ck_reach_reviews_human) */
    void insertCarriedReview(long findingId, CarrySource source) {
        jdbcClient.sql("""
                        INSERT INTO reach_reviews (finding_id, review_state, status, note, reviewer_user_id, reviewed_at,
                                                   base_verdict_id, carried_from_finding_id, carried_from_scan_id)
                        VALUES (:findingId, :reviewState, :status, :note, :reviewerUserId, :reviewedAt,
                                :baseVerdictId, :carriedFindingId, :carriedScanId)
                        """)
                .param("findingId", findingId)
                .param("reviewState", source.reviewState())
                .param("status", source.status())
                .param("note", source.note())
                .param("reviewerUserId", source.reviewerUserId())
                .param("reviewedAt", source.reviewedAt())
                .param("baseVerdictId", source.baseVerdictId())
                .param("carriedFindingId", source.findingId())
                .param("carriedScanId", source.scanId())
                .update();
    }

    /** 지금 검토와 그 검토가 본 도구 판정의 상태·근거 해시 */
    record ReviewState(String reviewState, String status, String note, Long reviewerUserId,
                       String baseStatus, String baseEvidenceHash) {}

    ReviewState reviewState(long findingId) {
        return jdbcClient.sql("""
                        SELECT r.review_state, r.status, r.note, r.reviewer_user_id, b.status AS base_status,
                               b.evidence_hash AS base_evidence_hash
                        FROM reach_reviews r
                        LEFT JOIN reach_verdicts b ON b.verdict_id = r.base_verdict_id
                        WHERE r.finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .query((rs, i) -> new ReviewState(rs.getString("review_state"), rs.getString("status"),
                        rs.getString("note"), rs.getObject("reviewer_user_id", Long.class),
                        rs.getString("base_status"), rs.getString("base_evidence_hash")))
                .single();
    }

    /** 도구 판정이 바뀌어 사람 판정을 검토 전으로 되돌린다. 사람 판정은 이력(앞 version)에 남는다 */
    void resetReview(long findingId, String reason, long verdictId, String proposal) {
        jdbcClient.sql("""
                        UPDATE reach_reviews
                        SET review_state = 'UNREVIEWED', status = NULL, note = NULL, reviewer_user_id = NULL,
                            reviewed_at = NULL, proposal = CAST(:proposal AS jsonb), reset_reason = :reason,
                            base_verdict_id = :verdictId, version = version + 1, updated_at = now()
                        WHERE finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .param("reason", reason)
                .param("verdictId", verdictId)
                .param("proposal", proposal)
                .update();
    }

    /** 방금 만든·바꾼 검토 행을 그대로 이력에 복사한다. changeKind는 CARRIED 또는 RESET */
    void insertHistory(long findingId, String changeKind) {
        jdbcClient.sql("""
                        INSERT INTO reach_review_history (finding_id, version, review_state, status, note, proposal,
                                                          reviewer_user_id, reviewed_at, change_kind)
                        SELECT finding_id, version, review_state, status, note, proposal,
                               reviewer_user_id, reviewed_at, :changeKind
                        FROM reach_reviews WHERE finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .param("changeKind", changeKind)
                .update();
    }

    boolean currentIsManual(long findingId) {
        return Boolean.TRUE.equals(jdbcClient.sql("""
                        SELECT EXISTS (SELECT 1 FROM reach_verdicts
                                       WHERE finding_id = :findingId AND is_current AND method = 'MANUAL')
                        """)
                .param("findingId", findingId)
                .query(Boolean.class)
                .single());
    }

    /** Finding마다 현재 판정은 하나라서 항상 끄기 → 켜기 순서다 (uq_reach_verdicts_current) */
    void makeCurrent(long findingId, long verdictId) {
        jdbcClient.sql("UPDATE reach_verdicts SET is_current = false WHERE finding_id = :findingId AND is_current")
                .param("findingId", findingId)
                .update();
        jdbcClient.sql("UPDATE reach_verdicts SET is_current = true WHERE verdict_id = :verdictId")
                .param("verdictId", verdictId)
                .update();
    }

    /** 도구가 판정하지 않은 Finding에 남아 있는 사람 판정 (API-06 예외와 같은 MANUAL 행) */
    long insertManualVerdict(long findingId, long scanId, String status, String summary, long userId) {
        return jdbcClient.sql("""
                        INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, is_current,
                                                    analyzed_at, created_by_user_id)
                        VALUES (:findingId, :scanId, :status, 'MANUAL', :summary, false, now(), :userId)
                        RETURNING verdict_id
                        """)
                .param("findingId", findingId)
                .param("scanId", scanId)
                .param("status", status)
                .param("summary", summary)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }
}
