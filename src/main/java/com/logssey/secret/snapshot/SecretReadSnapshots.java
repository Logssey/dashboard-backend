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
import com.logssey.secret.access.SecretOccurrenceAccessSql;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

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

    public record Subject(String type, long id, Long credentialSetId, Map<String, Object> facts,
                          List<Long> visibleOccurrenceIds) {
        public Subject(String type,long id,Long credentialSetId,Map<String,Object> facts) {
            this(type,id,credentialSetId,facts,List.of());
        }
    }

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
        jdbc.update("DELETE FROM secret_snapshot_retirements WHERE owner_user_id=? AND retired_at < now()-interval '24 hours'",userId);
        jdbc.update("""
            WITH retired AS(DELETE FROM secret_query_snapshots WHERE owner_user_id=? AND expires_at<=now() RETURNING snapshot_id,owner_user_id)
            INSERT INTO secret_snapshot_retirements(snapshot_id,owner_user_id) SELECT snapshot_id,owner_user_id FROM retired ON CONFLICT DO NOTHING
            """,userId);
        jdbc.update("""
                WITH retired AS(DELETE FROM secret_query_snapshots WHERE snapshot_id IN (
                    SELECT snapshot_id FROM secret_query_snapshots WHERE owner_user_id = ?
                    ORDER BY created_at DESC, snapshot_id DESC OFFSET 4) RETURNING snapshot_id,owner_user_id)
                INSERT INTO secret_snapshot_retirements(snapshot_id,owner_user_id) SELECT snapshot_id,owner_user_id FROM retired ON CONFLICT DO NOTHING
                """, userId);
        UUID id = UUID.randomUUID();
        OffsetDateTime asOf = jdbc.queryForObject("SELECT CURRENT_TIMESTAMP",OffsetDateTime.class);
        OffsetDateTime expires = asOf.plusMinutes(15);
        // A snapshot must expire when a policy on one of its already-visible members changes validity.
        // Do not use hidden occurrences or a global activity counter to choose this boundary.
        var visibleIds=subjects.stream().flatMap(subject->subject.visibleOccurrenceIds().stream()).distinct().toList();
        if(!visibleIds.isEmpty()) {
            var deadline=new NamedParameterJdbcTemplate(jdbc).queryForObject("""
                    SELECT MIN(deadline) FROM (
                        SELECT p.valid_until AS deadline
                        FROM secret_occurrences o JOIN secret_scope_policy_bindings b ON b.scope_id=o.scope_id AND b.effective_until IS NULL
                        JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
                        WHERE o.occurrence_id IN (:ids) AND p.status='ACTIVE' AND p.valid_until>now()
                        UNION ALL
                        SELECT p.valid_from AS deadline
                        FROM secret_occurrences o JOIN secret_scope_policy_bindings b ON b.scope_id=o.scope_id AND b.effective_until IS NULL
                        JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
                        WHERE o.occurrence_id IN (:ids) AND p.status='ACTIVE' AND p.valid_from>now()
                        UNION ALL
                        SELECT d.reuse_expires_at AS deadline
                        FROM secret_finding_dispositions d JOIN secret_current_raw_findings f ON f.finding_id=d.finding_id
                        WHERE f.occurrence_id IN (:ids) AND d.is_current AND d.revoked_at IS NULL AND d.reuse_expires_at>now()
                    ) boundaries
                    """,Map.of("ids",visibleIds),OffsetDateTime.class);
            if(deadline!=null && deadline.isBefore(expires)) expires=deadline;
        }
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
        List<Object[]> memberships=new ArrayList<>();
        for(Subject subject:subjects) for(Long occurrenceId:subject.visibleOccurrenceIds())
            memberships.add(new Object[]{id,subject.type(),subject.id(),occurrenceId});
        jdbc.batchUpdate("""
                INSERT INTO secret_snapshot_location_memberships(snapshot_id,subject_type,subject_id,occurrence_id)
                VALUES (?,?,?,?)
                """,memberships);
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
        if (rows.isEmpty()) {
            if(Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_snapshot_retirements WHERE snapshot_id=? AND owner_user_id=?)",Boolean.class,id,userId)))
                throw new com.logssey.secret.query.SecretReadConflict(com.logssey.secret.query.SecretReadConflict.Reason.SNAPSHOT_EXPIRED);
            throw new ApiException(ErrorCode.NOT_FOUND);
        }
        var stored = rows.getFirst();
        if (!stored.header().expiresAt().isAfter(OffsetDateTime.now(ZoneOffset.UTC)))
            throw new com.logssey.secret.query.SecretReadConflict(com.logssey.secret.query.SecretReadConflict.Reason.SNAPSHOT_EXPIRED);
        if(!stored.authorizationRevision().equals(authorizationRevision))
            throw new com.logssey.secret.query.SecretReadConflict(com.logssey.secret.query.SecretReadConflict.Reason.SNAPSHOT_ACCESS_CHANGED);
        if (!stored.filterDigest().equals(digest(canonicalFilters(filters)))) {
            throw new com.logssey.secret.query.SecretReadConflict(com.logssey.secret.query.SecretReadConflict.Reason.SNAPSHOT_MISMATCH);
        }
        boolean lostLocation=Boolean.TRUE.equals(new NamedParameterJdbcTemplate(jdbc).queryForObject("""
                SELECT EXISTS(SELECT 1 FROM secret_snapshot_location_memberships m
                JOIN secret_occurrences o ON o.occurrence_id=m.occurrence_id
                WHERE m.snapshot_id=:snapshotId AND NOT (LOCATION_ACCESS))
                """.replace("LOCATION_ACCESS",SecretOccurrenceAccessSql.predicate("o",":userId")),
                Map.of("snapshotId",id,"userId",userId),Boolean.class));
        if(lostLocation) throw new com.logssey.secret.query.SecretReadConflict(com.logssey.secret.query.SecretReadConflict.Reason.SNAPSHOT_ACCESS_CHANGED);
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
                SELECT 'T:' || membership_id || ':' || team_name || ':' || coalesce(removed_at::text,'ACTIVE')
                FROM secret_team_memberships WHERE user_id = ?
                UNION ALL
                SELECT 'S:' || s.scope_id || ':' || s.response_origin_version || ':' || s.enabled
                FROM secret_connection_scopes s WHERE EXISTS (
                    SELECT 1 FROM secret_role_grants g WHERE g.user_id = ? AND g.revoked_at IS NULL
                    AND (g.connection_id IS NULL OR g.connection_id = s.connection_id))
                ORDER BY fact
                """, (rs, row) -> rs.getString(1), userId, userId, userId);
        return digest(String.join("\n", facts));
    }

    @Transactional
    public void invalidateOccurrence(long occurrenceId) {
        jdbc.update("""
                UPDATE secret_query_snapshots s SET expires_at=GREATEST(now(),s.created_at+interval '1 microsecond')
                WHERE s.expires_at>now() AND EXISTS (
                    SELECT 1 FROM secret_snapshot_location_memberships m
                    WHERE m.snapshot_id=s.snapshot_id AND m.occurrence_id=?)
                """,occurrenceId);
    }

    @Transactional
    public void invalidateScope(long scopeId) {
        jdbc.update("""
                UPDATE secret_query_snapshots s SET expires_at=GREATEST(now(),s.created_at+interval '1 microsecond')
                WHERE s.expires_at>now() AND EXISTS (
                    SELECT 1 FROM secret_snapshot_location_memberships m JOIN secret_occurrences o ON o.occurrence_id=m.occurrence_id
                    WHERE m.snapshot_id=s.snapshot_id AND o.scope_id=?)
                """,scopeId);
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
