package com.logssey.remediation;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import jakarta.validation.constraints.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** 담당자와 수행 기록만 관리한다. 탐지 판정·위험 수용·해결 여부는 원래 검사 기능이 결정한다. */
@Service
public class ActionRecordService {
    public record Person(long userId, String displayName) {}
    public record Update(@NotNull @PositiveOrZero Long version, @NotNull @PositiveOrZero Long sourceVersion,
                         @Positive Long assigneeUserId,
                         @NotNull @Pattern(regexp = "NOT_STARTED|IN_PROGRESS|AWAITING_CHECK|RECORDED") String status,
                         @NotNull @Size(max = 2000) String note, boolean confirmed) {}
    public record Record(Long assigneeUserId, String status, String note, long version) {}
    public record Source(String title, String status, long version, Long assigneeUserId, OffsetDateTime lastSeenAt) {}
    public record History(long version, Long assigneeUserId, String status, String note, String actorName, OffsetDateTime recordedAt) {}
    public record Detail(Record record, Source source, List<Person> assignees, List<History> history,
                         ActionVerification.Result verification, List<ActionVerification.Candidate> checks) {}
    public record LinkCheck(@NotNull @PositiveOrZero Long version, @Positive long scanId) {}
    public record Item(String kind, long id, String title, Long assigneeUserId, String assigneeName,
                       String status, OffsetDateTime updatedAt, ActionVerification.Result verification) {}
    public record Page(List<Item> items, long total, int page, int size) {}

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    public ActionRecordService(JdbcTemplate jdbc, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
    }

    public Detail get(String login, String kind, long id) {
        actor(login);
        validateTarget(kind, id);
        return detail(kind, id, source(kind, id, false));
    }

    public Page list(String login, String area, String assignee, int page) {
        long user = actor(login);
        if (!Set.of("IAC", "IMAGE").contains(area) || !Set.of("ALL", "ME", "UNASSIGNED").contains(assignee) || page<0 || page>10000) invalid();
        String where = (area.equals("IMAGE") ? "a.kind='IMAGE'" : "a.kind IN ('IAC_PATH','IAC_FINDING')")
                + (assignee.equals("ME") ? " AND CASE WHEN a.kind='IAC_FINDING' THEN f.assignee_user_id ELSE a.assignee_user_id END="+user
                    : assignee.equals("UNASSIGNED") ? " AND CASE WHEN a.kind='IAC_FINDING' THEN f.assignee_user_id ELSE a.assignee_user_id END IS NULL" : "");
        String from = """
             FROM security_action_records a
             LEFT JOIN iac_findings f ON a.kind='IAC_FINDING' AND f.finding_id=a.target_id
             LEFT JOIN reach_findings i ON a.kind='IMAGE' AND i.finding_id=a.target_id
             LEFT JOIN dashboard_users u ON u.user_id=CASE WHEN a.kind='IAC_FINDING' THEN f.assignee_user_id ELSE a.assignee_user_id END
             WHERE
             """+where;
        long total=jdbc.queryForObject("SELECT count(*)"+from,Long.class);
        var rows=jdbc.query("""
             SELECT a.kind,a.target_id,COALESCE(f.resource_address,i.vulnerability_id || ' · ' || i.component_name,'공격 경로 #' || a.target_id),
               CASE WHEN a.kind='IAC_FINDING' THEN f.assignee_user_id ELSE a.assignee_user_id END,u.display_name,a.status,a.updated_at
             """+from+" ORDER BY a.updated_at DESC,a.kind,a.target_id LIMIT 30 OFFSET ?",
             (rs,n)->new Item(rs.getString(1),rs.getLong(2),rs.getString(3),rs.getObject(4,Long.class),rs.getString(5),rs.getString(6),rs.getObject(7,OffsetDateTime.class),null),page*30);
        var verifier=new ActionVerification(jdbc);
        return new Page(rows.stream().map(i->new Item(i.kind(),i.id(),i.title(),i.assigneeUserId(),i.assigneeName(),i.status(),i.updatedAt(),verifier.read(i.kind(),i.id()))).toList(),total,page,30);
    }

    public Detail link(String login,String kind,long id,LinkCheck request) {
        long user=actor(login); validateTarget(kind,id);
        if (!kind.equals("IMAGE") || request==null || request.version()==null || request.version()<0 || request.scanId()<=0) invalid();
        return tx.execute(ignored->{
            var source=source(kind,id,true);
            var rows=jdbc.queryForList("SELECT version,status,updated_at FROM security_action_records WHERE kind=? AND target_id=? FOR UPDATE",kind,id);
            if(rows.isEmpty() || ((Number)rows.getFirst().get("version")).longValue()!=request.version()) conflict();
            var row=rows.getFirst();
            if(!Set.of("AWAITING_CHECK","RECORDED").contains(row.get("status"))) invalid();
            new ActionVerification(jdbc).image(id,request.scanId(),ActionVerification.time(row,"updated_at"));
            jdbc.update("INSERT INTO security_action_verifications(kind,target_id,action_version,scan_id,actor_user_id) VALUES (?,?,?,?,?)",kind,id,request.version(),request.scanId(),user);
            return detail(kind,id,source);
        });
    }

    public Detail save(String login, String kind, long id, Update request) {
        long actor = actor(login);
        validateTarget(kind, id);
        // Service calls (including background callers) must enforce the same rules as MVC validation.
        if (request == null || request.version() == null || request.version() < 0 || request.sourceVersion() == null
                || request.sourceVersion() < 0 || request.status() == null
                || !Set.of("NOT_STARTED", "IN_PROGRESS", "AWAITING_CHECK", "RECORDED").contains(request.status())
                || request.note() == null || request.note().length() > 2000) invalid();
        if (!request.status().equals("NOT_STARTED") && request.assigneeUserId() == null) invalid();
        if ((request.status().equals("AWAITING_CHECK") || request.status().equals("RECORDED")) && request.note().isBlank()) invalid();
        if (request.status().equals("RECORDED") && !request.confirmed()) invalid();
        return Objects.requireNonNull(tx.execute(ignored -> {
            Source source = source(kind, id, true); // Serializes first saves as well as updates.
            if (source.version() != request.sourceVersion()) conflict();
            if (request.assigneeUserId() != null && !Boolean.TRUE.equals(jdbc.queryForObject(
                    "SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE user_id = ? AND role = 'ADMIN')",
                    Boolean.class, request.assigneeUserId()))) invalid();
            jdbc.update("""
                    INSERT INTO security_action_records(kind, target_id, image_finding_id, iac_path_id, iac_finding_id)
                    VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING
                    """, kind, id, kind.equals("IMAGE") ? id : null, kind.equals("IAC_PATH") ? id : null,
                    kind.equals("IAC_FINDING") ? id : null);
            Record before = record(kind, id, source);
            if (before.version() != request.version()) conflict();
            String note = request.note().strip();
            // Retrying a successful save after a lost response conflicts; it never adds a duplicate history entry.
            jdbc.update("""
                    UPDATE security_action_records SET assignee_user_id = ?, status = ?, note = ?,
                        version = version + 1, updated_at = now(), updated_by = ? WHERE kind = ? AND target_id = ?
                    """, request.assigneeUserId(), request.status(), note, actor, kind, id);
            if (kind.equals("IAC_FINDING") && !Objects.equals(source.assigneeUserId(), request.assigneeUserId())) {
                jdbc.update("UPDATE iac_findings SET assignee_user_id = ?, version = version + 1 WHERE finding_id = ?",
                        request.assigneeUserId(), id);
                jdbc.update("""
                        INSERT INTO iac_audit_events(actor_kind, actor_user_id, entity_type, entity_id, event_type, before_safe, after_safe)
                        VALUES ('USER', ?, 'FINDING', ?, 'FINDING_UPDATED',
                          jsonb_build_object('assigneeUserId', ?::bigint), jsonb_build_object('assigneeUserId', ?::bigint))
                        """, actor, id, source.assigneeUserId(), request.assigneeUserId());
            }
            jdbc.update("""
                    INSERT INTO security_action_history(kind, target_id, version, assignee_user_id, status, note, actor_user_id)
                    SELECT kind, target_id, version, assignee_user_id, status, note, ?
                    FROM security_action_records WHERE kind = ? AND target_id = ?
                    """, actor, kind, id);
            return detail(kind, id, source(kind, id, false));
        }));
    }

    private Detail detail(String kind, long id, Source source) {
        return new Detail(record(kind, id, source), source,
                jdbc.query("SELECT user_id, display_name FROM dashboard_users WHERE role = 'ADMIN' ORDER BY display_name, user_id",
                        (rs, n) -> new Person(rs.getLong(1), rs.getString(2))),
                jdbc.query("""
                        SELECT h.version, h.assignee_user_id, h.status, h.note, u.display_name, h.recorded_at
                        FROM security_action_history h JOIN dashboard_users u ON u.user_id = h.actor_user_id
                        WHERE h.kind = ? AND h.target_id = ? ORDER BY h.version DESC LIMIT 50
                        """, (rs, n) -> new History(rs.getLong(1), rs.getObject(2, Long.class), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getObject(6, OffsetDateTime.class)), kind, id),
                new ActionVerification(jdbc).read(kind,id),
                kind.equals("IMAGE") ? new ActionVerification(jdbc).candidates(id) : List.of());
    }

    private Record record(String kind, long id, Source source) {
        return jdbc.query("SELECT assignee_user_id, status, note, version FROM security_action_records WHERE kind = ? AND target_id = ?",
                (rs, n) -> new Record(kind.equals("IAC_FINDING") ? source.assigneeUserId() : rs.getObject(1, Long.class),
                        rs.getString(2), rs.getString(3), rs.getLong(4)), kind, id).stream().findFirst()
                .orElse(new Record(source.assigneeUserId(), "NOT_STARTED", "", 0));
    }

    private Source source(String kind, long id, boolean lock) {
        String sql = switch (kind) {
            case "IMAGE" -> "SELECT vulnerability_id || ' · ' || component_name AS title, 'IMAGE_REVIEW' AS status, 0::bigint AS version, NULL::bigint AS assignee_user_id, last_seen_at FROM reach_findings WHERE finding_id = ?";
            case "IAC_PATH" -> "SELECT '공격 경로 #' || path_id AS title, status, 0::bigint AS version, NULL::bigint AS assignee_user_id, last_seen_at FROM iac_attack_paths WHERE path_id = ?";
            case "IAC_FINDING" -> "SELECT COALESCE(resource_address, rule_id) AS title, status, version, assignee_user_id, last_seen_at FROM iac_findings WHERE finding_id = ?";
            default -> throw new ApiException(ErrorCode.INVALID_INPUT);
        };
        return jdbc.query(sql + (lock ? " FOR UPDATE" : ""), (rs, n) -> new Source(rs.getString("title"), rs.getString("status"),
                rs.getLong("version"), rs.getObject("assignee_user_id", Long.class), rs.getObject("last_seen_at", OffsetDateTime.class)),
                id).stream().findFirst().orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    private long actor(String login) {
        if (login == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN'",
                (rs, n) -> rs.getLong(1), login).stream().findFirst().orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
    private void validateTarget(String kind, long id) {
        if (id <= 0 || kind == null || !Set.of("IMAGE", "IAC_PATH", "IAC_FINDING").contains(kind)) invalid();
    }
    private void invalid() { throw new ApiException(ErrorCode.INVALID_INPUT); }
    private void conflict() { throw new ApiException(ErrorCode.CONFLICT, "다른 변경이 먼저 저장됐습니다. 최신 내용을 확인한 뒤 다시 저장하세요."); }
}
