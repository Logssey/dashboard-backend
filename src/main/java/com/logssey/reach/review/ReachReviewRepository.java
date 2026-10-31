package com.logssey.reach.review;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.Optional;

import com.logssey.reach.query.dto.ReachFindingDetailResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Reach 사람 검토 기록 (API-06). 판정 바꾸기는 Finding마다 현재 판정이 하나라서 항상 끄기 → 켜기 순서다 */
@Repository
public class ReachReviewRepository {

    private final JdbcClient jdbcClient;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public ReachReviewRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** 검토 행을 잠근 뒤의 지금 상태. 현재 판정이 MANUAL인지 보려고 method도 읽는다 */
    record State(int version, long lastScanId, String currentMethod) {}

    /** MANUAL이 아닌 판정 중 가장 최근 것 */
    record ToolVerdict(long id, String status) {}

    Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("SELECT user_id FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN'")
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    /** 같은 Finding을 동시에 저장하면 두 번째 요청은 첫 트랜잭션이 끝날 때까지 여기서 기다린다 */
    Optional<State> lockReview(long findingId) {
        return jdbcClient.sql("""
                        SELECT r.version, f.last_scan_id, v.method
                        FROM reach_reviews r
                        JOIN reach_findings f ON f.finding_id = r.finding_id
                        JOIN reach_verdicts v ON v.finding_id = r.finding_id AND v.is_current
                        WHERE r.finding_id = :findingId
                        FOR UPDATE OF r
                        """)
                .param("findingId", findingId)
                .query((rs, i) -> new State(rs.getInt("version"), rs.getLong("last_scan_id"), rs.getString("method")))
                .optional();
    }

    ToolVerdict latestToolVerdict(long findingId) {
        return jdbcClient.sql("""
                        SELECT verdict_id, status FROM reach_verdicts
                        WHERE finding_id = :findingId AND method IS DISTINCT FROM 'MANUAL'
                        ORDER BY analyzed_at DESC, verdict_id DESC
                        LIMIT 1
                        """)
                .param("findingId", findingId)
                .query((rs, i) -> new ToolVerdict(rs.getLong("verdict_id"), rs.getString("status")))
                .single();
    }

    void turnOffCurrentVerdict(long findingId) {
        jdbcClient.sql("UPDATE reach_verdicts SET is_current = false WHERE finding_id = :findingId AND is_current")
                .param("findingId", findingId)
                .update();
    }

    void turnOnVerdict(long verdictId) {
        jdbcClient.sql("UPDATE reach_verdicts SET is_current = true WHERE verdict_id = :verdictId")
                .param("verdictId", verdictId)
                .update();
    }

    /** NOT_ANALYZED Finding에 사람이 넣은 판정 (API 명세 API-06 예외). MANUAL은 engine·evidence_hash 없이 만든 사람이 필요하다 (V34) */
    void insertManualVerdict(long findingId, long scanId, String status, String summary, long userId) {
        jdbcClient.sql("""
                        INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, is_current,
                                                    analyzed_at, created_by_user_id)
                        VALUES (:findingId, :scanId, :status, 'MANUAL', :summary, true, now(), :userId)
                        """)
                .param("findingId", findingId)
                .param("scanId", scanId)
                .param("status", status)
                .param("summary", summary)
                .param("userId", userId)
                .update();
    }

    /** 사람이 다시 기록하면 되돌린 이유와 이어받은 기록은 비운다 (API 명세 3-10) */
    int updateReview(long findingId, ReachReviewRequest request, long userId, long toolVerdictId) {
        return jdbcClient.sql("""
                        UPDATE reach_reviews
                        SET review_state = :reviewState, status = :status, note = :note,
                            proposal = CAST(:proposal AS jsonb), reviewer_user_id = :userId, reviewed_at = now(),
                            version = version + 1, base_verdict_id = :toolVerdictId, reset_reason = NULL,
                            carried_from_finding_id = NULL, carried_from_scan_id = NULL, updated_at = now()
                        WHERE finding_id = :findingId AND version = :version
                        """)
                .param("reviewState", request.reviewState())
                .param("status", request.status())
                .param("note", request.note())
                .param("proposal", request.proposal() == null ? null : mapper.writeValueAsString(request.proposal()))
                .param("userId", userId)
                .param("toolVerdictId", toolVerdictId)
                .param("findingId", findingId)
                .param("version", request.version())
                .update();
    }

    /** 방금 바꾼 검토 행을 그대로 이력에 복사한다 */
    void insertHistory(long findingId) {
        jdbcClient.sql("""
                        INSERT INTO reach_review_history (finding_id, version, review_state, status, note, proposal,
                                                          reviewer_user_id, reviewed_at, change_kind)
                        SELECT finding_id, version, review_state, status, note, proposal,
                               reviewer_user_id, reviewed_at, 'HUMAN'
                        FROM reach_reviews WHERE finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .update();
    }

    /** 응답용. 상세(API-05)의 review와 같은 모양 */
    ReachFindingDetailResponse.Review review(long findingId) {
        return jdbcClient.sql("""
                        SELECT r.review_state, r.status, r.note, r.reviewed_at, r.version,
                               r.proposal::text AS proposal, r.reset_reason,
                               u.user_id AS reviewer_id, u.display_name AS reviewer_name, v.status AS verdict_status
                        FROM reach_reviews r
                        JOIN reach_verdicts v ON v.finding_id = r.finding_id AND v.is_current
                        LEFT JOIN dashboard_users u ON u.user_id = r.reviewer_user_id
                        WHERE r.finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .query(this::reviewRow)
                .single();
    }

    private ReachFindingDetailResponse.Review reviewRow(ResultSet rs, int rowNum) throws SQLException {
        String status = rs.getString("status");
        long reviewerId = rs.getLong("reviewer_id");
        var reviewer = rs.wasNull() ? null : new ReachFindingDetailResponse.Reviewer(reviewerId, rs.getString("reviewer_name"));
        return new ReachFindingDetailResponse.Review(
                rs.getString("review_state"), status, rs.getString("note"), reviewer,
                rs.getObject("reviewed_at", OffsetDateTime.class), rs.getInt("version"),
                // 사람 판정이 있고 현재 판정과 다르면 true (FR-08). MANUAL 판정이면 같으니 false
                status != null && !status.equals(rs.getString("verdict_status")),
                json(rs.getString("proposal")), rs.getString("reset_reason"));
    }

    private JsonNode json(String value) {
        return value == null ? null : mapper.readTree(value);
    }
}
