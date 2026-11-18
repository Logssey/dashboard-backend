package com.logssey.iac.job;

import java.time.OffsetDateTime;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class IacJobRepository {

    private final JdbcTemplate jdbc;

    public IacJobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN'",
                (rs, row) -> rs.getLong("user_id"), loginId).stream().findFirst();
    }

    long insertCollectGraph(Long actor, String status, OffsetDateTime startedAt, OffsetDateTime finishedAt,
                            String statsJson) {
        return jdbc.queryForObject("""
                INSERT INTO iac_jobs (kind, trigger_type, requested_by_user_id, status, attempt_no,
                                      available_at, stats, created_at, finished_at)
                VALUES ('COLLECT_GRAPH', 'SCHEDULED', ?, ?, 1, ?, ?::jsonb, ?, ?)
                RETURNING job_id
                """, Long.class, actor, status, startedAt, statsJson, startedAt, finishedAt);
    }

    /** 같은 종류의 대기·진행 중인 작업이 있으면 그것을, 없으면 새로 등록한 작업을 돌려준다. */
    long enqueueOnce(String kind, Long actor) {
        return enqueueOnce(kind, "SCHEDULED", actor);
    }

    long enqueueOnce(String kind, String trigger, Long actor) {
        // 한 번에 하나만 기다리게 해 수집이 몰려도 작업이 쌓이지 않게 한다
        jdbc.query("SELECT pg_advisory_xact_lock(hashtext('iac_' || ?))", rs -> null, kind);
        return jdbc.query("""
                SELECT job_id FROM iac_jobs WHERE kind = ? AND status IN ('PENDING', 'LEASED')
                ORDER BY job_id LIMIT 1
                """, (rs, row) -> rs.getLong("job_id"), kind).stream().findFirst()
                .orElseGet(() -> jdbc.queryForObject("""
                        INSERT INTO iac_jobs (kind, trigger_type, requested_by_user_id)
                        VALUES (?, ?, ?) RETURNING job_id
                        """, Long.class, kind, trigger, actor));
    }

    /** actor 가 없으면(수집기) SYSTEM 으로 남긴다 */
    void audit(Long actor, long jobId, String eventType, String key, String value) {
        jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, actor_user_id, entity_type, entity_id, event_type, after_safe)
                VALUES (?, ?, 'JOB', ?, ?, jsonb_build_object(?::text, ?::text))
                """, actor == null ? "SYSTEM" : "USER", actor, jobId, eventType, key, value);
    }
}
