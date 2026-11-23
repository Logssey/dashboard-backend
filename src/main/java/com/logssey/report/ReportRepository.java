package com.logssey.report;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import tools.jackson.databind.json.JsonMapper;

@Repository
public class ReportRepository {

    private final JdbcTemplate jdbc;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public ReportRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    record Admin(long userId, String displayName) {
    }

    Optional<Admin> admin(String loginId) {
        return jdbc.query("SELECT user_id, display_name FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN'",
                (rs, row) -> new Admin(rs.getLong("user_id"), rs.getString("display_name")), loginId).stream().findFirst();
    }

    long insert(ReportContent content, long userId) {
        return jdbc.queryForObject("""
                INSERT INTO report_snapshots (part, name, period_from, period_to, content, created_by, created_at)
                VALUES (?, ?, ?, ?, ?::jsonb, ?, ?) RETURNING report_id
                """, Long.class, content.part().name(), content.name(), content.periodFrom(), content.periodTo(),
                mapper.writeValueAsString(content), userId, content.createdAt());
    }

    record Row(long reportId, ReportPart part, String name, LocalDate periodFrom, LocalDate periodTo,
               OffsetDateTime createdAt, ReportContent content) {
    }

    /** 삭제한 리포트는 목록에 나오지 않는다 */
    List<Row> latest(int limit) {
        return jdbc.query("""
                SELECT report_id, part, name, period_from, period_to, created_at, content::text AS content
                FROM report_snapshots WHERE deleted_at IS NULL ORDER BY created_at DESC, report_id DESC LIMIT ?
                """, (rs, row) -> row(rs), limit);
    }

    Optional<Row> find(long reportId) {
        return jdbc.query("""
                SELECT report_id, part, name, period_from, period_to, created_at, content::text AS content
                FROM report_snapshots WHERE report_id = ? AND deleted_at IS NULL
                """, (rs, row) -> row(rs), reportId).stream().findFirst();
    }

    /** 본문을 비우고 누가 언제 지웠는지만 남긴다. 건별 AI 대응 방법도 지운다. 이미 지운 것이면 false */
    boolean softDelete(long reportId, long userId) {
        boolean deleted = jdbc.update("""
                UPDATE report_snapshots SET content = '{}'::jsonb, deleted_at = now(), deleted_by = ?
                WHERE report_id = ? AND deleted_at IS NULL
                """, userId, reportId) == 1;
        if (deleted) jdbc.update("DELETE FROM report_finding_advice WHERE report_id = ?", reportId);
        return deleted;
    }

    /** 리포트에 붙은 건별 AI 대응 방법 (finding ID → 대응 방법) */
    java.util.Map<String, ReportAdvice> findingAdvice(long reportId) {
        java.util.Map<String, ReportAdvice> result = new java.util.LinkedHashMap<>();
        jdbc.query("SELECT finding_id, content::text AS content FROM report_finding_advice WHERE report_id = ? ORDER BY created_at",
                rs -> { result.put(rs.getString("finding_id"), mapper.readValue(rs.getString("content"), ReportAdvice.class)); },
                reportId);
        return result;
    }

    /** 먼저 저장된 것이 있으면 그것을 남긴다 (동시에 두 번 눌러도 하나만) */
    void saveFindingAdvice(long reportId, String findingId, ReportAdvice advice, long userId) {
        jdbc.update("""
                INSERT INTO report_finding_advice (report_id, finding_id, content, created_by) VALUES (?, ?, ?::jsonb, ?)
                ON CONFLICT (report_id, finding_id) DO NOTHING
                """, reportId, findingId, mapper.writeValueAsString(advice), userId);
    }

    void audit(long reportId, long userId, String eventType) {
        jdbc.update("INSERT INTO report_audit_events (report_id, user_id, event_type) VALUES (?, ?, ?)",
                reportId, userId, eventType);
    }

    private Row row(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new Row(rs.getLong("report_id"), ReportPart.valueOf(rs.getString("part")), rs.getString("name"),
                rs.getObject("period_from", LocalDate.class), rs.getObject("period_to", LocalDate.class),
                rs.getObject("created_at", OffsetDateTime.class),
                mapper.readValue(rs.getString("content"), ReportContent.class));
    }
}
