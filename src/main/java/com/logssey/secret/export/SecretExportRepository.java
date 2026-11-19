package com.logssey.secret.export;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecretExportRepository {
    private final JdbcTemplate jdbc;

    public SecretExportRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    /** 스냅샷을 만들 때 저장한 키별 열람 가능 위치. 위치 번호 → 키 번호. */
    public Map<Long, Long> memberships(UUID snapshotId) {
        var result = new LinkedHashMap<Long, Long>();
        jdbc.query("""
                SELECT occurrence_id, subject_id FROM secret_snapshot_location_memberships
                WHERE snapshot_id = ? AND subject_type = 'CredentialSet'
                ORDER BY subject_id, occurrence_id
                """, rs -> { result.put(rs.getLong(1), rs.getLong(2)); }, snapshotId);
        return result;
    }

    /** 위치 권한 검사를 통과한 위치의 공개 범위(BROAD·BOUNDED·UNKNOWN). 위치 API 버전과 무관하게 같은 값을 읽는다. */
    public String exposureRange(long occurrenceId) {
        return jdbc.query("SELECT exposure_range FROM secret_occurrences WHERE occurrence_id = ?",
                (rs, row) -> rs.getString(1), occurrenceId).stream().findFirst().orElse("UNKNOWN");
    }

    /** 누가·언제(occurred_at 기본값)·형식·건수·필터. 검색어 원문과 위치 좌표는 남기지 않는다. */
    public void audit(long actorUserId, String safeChangesJson) {
        jdbc.update("""
                INSERT INTO secret_audit_events(event_type, actor_user_id, target_type, safe_changes)
                VALUES ('SECRETS_EXPORTED', ?, 'INVENTORY_EXPORT', CAST(? AS jsonb))
                """, actorUserId, safeChangesJson);
    }
}
