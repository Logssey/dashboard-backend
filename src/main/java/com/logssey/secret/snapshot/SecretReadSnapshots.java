package com.logssey.secret.snapshot;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/** Persistent snapshots contain only authorized public projections, never source references. */
@Service
public class SecretReadSnapshots {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;

    public SecretReadSnapshots(JdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public record Header(UUID snapshotId, String scope, long ownerUserId, OffsetDateTime asOf,
                         OffsetDateTime expiresAt, boolean restrictedCoverage) {}

    public record Subject(String type, long id, Long credentialSetId, Map<String, Object> facts) {}

    /** The caller must read the source rows in this same REPEATABLE_READ transaction. */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public Header create(long userId, String scope, Map<String, String> filters,
                         String authorizationRevision, boolean restrictedCoverage, List<Subject> subjects) {
        // Serialize a user's creation sequence so concurrent requests cannot exceed five active snapshots.
        // A competing REPEATABLE_READ creator retries after serialization instead of creating a sixth snapshot.
        jdbc.update("""
                INSERT INTO secret_snapshot_owner_locks(user_id,epoch) VALUES (?,1)
                ON CONFLICT(user_id) DO UPDATE SET epoch=secret_snapshot_owner_locks.epoch+1
                """, userId);
        jdbc.update("DELETE FROM secret_query_snapshots WHERE owner_user_id = ? AND expires_at <= now()", userId);
        jdbc.update("""
                DELETE FROM secret_query_snapshots WHERE snapshot_id IN (
                    SELECT snapshot_id FROM secret_query_snapshots WHERE owner_user_id = ?
                    ORDER BY created_at DESC, snapshot_id DESC OFFSET 4)
                """, userId);
        UUID id = UUID.randomUUID();
        OffsetDateTime asOf = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime expires = asOf.plusMinutes(15);
        String canonical = canonicalFilters(filters);
        jdbc.update("""
                INSERT INTO secret_query_snapshots(snapshot_id,scope,owner_user_id,case_origin,as_of,
                    created_at,expires_at,authorization_revision,scope_version_digest,normalized_filters,
                    filter_digest,partial_coverage,restricted_coverage,coverage_status)
                VALUES (?,?,?,?,?,?,?,?,?,CAST(? AS jsonb),?,NULL,?,'UNKNOWN')
                """, id, scope, userId, filters.get("origin"), asOf, asOf, expires,
                authorizationRevision, authorizationRevision, canonical, digest(canonical), restrictedCoverage);
        List<Object[]> args = new ArrayList<>();
        int ordinal = 0;
        for (Subject subject : subjects) {
            args.add(new Object[]{id, subject.type(), subject.id(), subject.credentialSetId(),
                    String.format("%020d", ordinal++), json.writeValueAsString(subject.facts())});
        }
        jdbc.batchUpdate("""
                INSERT INTO secret_snapshot_subjects(snapshot_id,subject_type,subject_id,credential_set_id,
                    safe_sort_key,safe_facts) VALUES (?,?,?,?,?,CAST(? AS jsonb))
                """, args);
        return new Header(id, scope, userId, asOf, expires, restrictedCoverage);
    }

    @Transactional(readOnly = true)
    public Header require(String supplied, long userId, String scope, Map<String, String> filters,
                          String authorizationRevision) {
        UUID id;
        try { id = UUID.fromString(supplied); }
        catch (RuntimeException badId) { throw new ApiException(ErrorCode.INVALID_INPUT); }
        var rows = jdbc.query("""
                SELECT * FROM secret_query_snapshots WHERE snapshot_id = ? AND owner_user_id = ? AND scope = ?
                """, (rs, row) -> new Stored(new Header(id, scope, userId,
                    rs.getObject("as_of", OffsetDateTime.class), rs.getObject("expires_at", OffsetDateTime.class),
                    rs.getBoolean("restricted_coverage")), rs.getString("authorization_revision"),
                    rs.getString("filter_digest")), id, userId, scope);
        if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var stored = rows.getFirst();
        if (!stored.header().expiresAt().isAfter(OffsetDateTime.now(ZoneOffset.UTC))
                || !stored.authorizationRevision().equals(authorizationRevision)) {
            throw new ApiException(ErrorCode.CONFLICT, "조회 기준이 만료되었어요. 새로고침해 주세요.");
        }
        if (!stored.filterDigest().equals(digest(canonicalFilters(filters)))) {
            throw new ApiException(ErrorCode.CONFLICT, "조회 조건이 달라졌어요. 새 기준으로 조회해 주세요.");
        }
        return stored.header();
    }

    public long count(Header header, String type) {
        return jdbc.queryForObject("""
                SELECT count(*) FROM secret_snapshot_subjects WHERE snapshot_id = ? AND subject_type = ?
                """, Long.class, header.snapshotId(), type);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> page(Header header, String type, int page, int size) {
        return jdbc.query("""
                SELECT safe_facts::text FROM secret_snapshot_subjects
                WHERE snapshot_id = ? AND subject_type = ? ORDER BY safe_sort_key, subject_id LIMIT ? OFFSET ?
                """, (rs, row) -> json.readValue(rs.getString(1), Map.class),
                header.snapshotId(), type, size, (long) page * size);
    }

    /** Revision uses permission records and readable scope revisions, never hidden occurrence activity. */
    public String authorizationRevision(long userId) {
        List<String> facts = jdbc.query("""
                SELECT 'G:' || grant_id || ':' || role || ':' || coalesce(connection_id::text,'*')
                       || ':' || coalesce(revoked_at::text,'ACTIVE') AS fact
                FROM secret_role_grants WHERE user_id = ?
                UNION ALL
                SELECT 'A:' || c.case_id || ':' || c.assigned_user_id || ':' || c.is_current
                FROM secret_response_cases c WHERE c.assigned_user_id = ?
                UNION ALL
                SELECT 'T:' || membership_id || ':' || team_name || ':' || coalesce(removed_at::text,'ACTIVE')
                FROM secret_team_memberships WHERE user_id = ?
                UNION ALL
                SELECT 'S:' || s.scope_id || ':' || s.response_origin_version || ':' || s.enabled
                FROM secret_connection_scopes s WHERE EXISTS (
                    SELECT 1 FROM secret_role_grants g WHERE g.user_id = ? AND g.revoked_at IS NULL
                    AND (g.connection_id IS NULL OR g.connection_id = s.connection_id))
                ORDER BY fact
                """, (rs, row) -> rs.getString(1), userId, userId, userId, userId);
        return digest(String.join("\n", facts));
    }

    public static Map<String, Object> facts(Object... pairs) {
        var result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    public static String digest(String text) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private String canonicalFilters(Map<String, String> filters) {
        return json.writeValueAsString(new TreeMap<>(filters));
    }

    private record Stored(Header header, String authorizationRevision, String filterDigest) {}
}
