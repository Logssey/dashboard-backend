package com.logssey.runtime.policy;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import com.logssey.runtime.policy.dto.RuntimeSuppressionResponse;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RuntimeSuppressionRepository {

    private final JdbcClient jdbcClient;

    public RuntimeSuppressionRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("""
                        SELECT user_id FROM dashboard_users
                        WHERE login_id = :loginId AND role = 'ADMIN'
                        """)
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    public boolean ruleExists(String ruleKey) {
        return jdbcClient.sql("SELECT count(*) FROM runtime_rules WHERE rule_key = :ruleKey")
                .param("ruleKey", ruleKey)
                .query(Long.class)
                .single() == 1;
    }

    public Optional<IdempotentSuppression> findByIdempotency(long actorId, String idempotencyKey) {
        return jdbcClient.sql("""
                        SELECT suppression_id, request_digest
                        FROM runtime_suppressions
                        WHERE created_by_user_id = :actorId AND idempotency_key = :idempotencyKey
                        """)
                .param("actorId", actorId)
                .param("idempotencyKey", idempotencyKey)
                .query((rs, rowNum) -> new IdempotentSuppression(
                        rs.getLong("suppression_id"), rs.getString("request_digest")))
                .optional();
    }

    public Optional<Long> insert(long actorId, ValidatedSuppression request, String requestDigest) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_suppressions
                            (rule_key, cluster_id, namespace, workload_name, process_executable,
                             target_name_prefix, operation, reason_code, evidence_ref, comment,
                             created_by_user_id, idempotency_key, request_digest, expires_at)
                        VALUES
                            (:ruleKey, :clusterId, :namespace, :workloadName, :processExecutable,
                             :targetNamePrefix, :operation, :reasonCode, :evidenceRef, :comment,
                             :actorId, :idempotencyKey, :requestDigest, :expiresAt)
                        ON CONFLICT (created_by_user_id, idempotency_key) DO NOTHING
                        RETURNING suppression_id
                        """)
                .param("ruleKey", request.ruleKey())
                .param("clusterId", request.clusterId())
                .param("namespace", request.namespace())
                .param("workloadName", request.workloadName())
                .param("processExecutable", request.processExecutable())
                .param("targetNamePrefix", request.targetNamePrefix())
                .param("operation", request.operation())
                .param("reasonCode", request.reasonCode())
                .param("evidenceRef", request.evidenceRef())
                .param("comment", request.comment())
                .param("actorId", actorId)
                .param("idempotencyKey", request.idempotencyKey())
                .param("requestDigest", requestDigest)
                .param("expiresAt", utc(request.expiresAt()))
                .query(Long.class)
                .optional();
    }

    public List<RuntimeSuppressionResponse> findAll(boolean activeOnly) {
        return jdbcClient.sql("""
                        SELECT * FROM runtime_suppressions
                        WHERE (:all OR (revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP))
                        ORDER BY created_at DESC, suppression_id DESC
                        LIMIT 500
                        """)
                .param("all", !activeOnly)
                .query((rs, rowNum) -> response(rs))
                .list();
    }

    public Optional<RuntimeSuppressionResponse> find(long suppressionId) {
        return jdbcClient.sql("SELECT * FROM runtime_suppressions WHERE suppression_id = :suppressionId")
                .param("suppressionId", suppressionId)
                .query((rs, rowNum) -> response(rs))
                .optional();
    }

    public Optional<CurrentSuppression> findCurrentForUpdate(long suppressionId) {
        return jdbcClient.sql("""
                        SELECT version, revoked_at
                        FROM runtime_suppressions
                        WHERE suppression_id = :suppressionId
                        FOR UPDATE
                        """)
                .param("suppressionId", suppressionId)
                .query((rs, rowNum) -> new CurrentSuppression(
                        rs.getLong("version"), rs.getObject("revoked_at") != null))
                .optional();
    }

    public int revoke(long suppressionId, long actorId, long expectedVersion, String reason) {
        return jdbcClient.sql("""
                        UPDATE runtime_suppressions
                        SET revoked_by_user_id = :actorId,
                            revoked_at = CURRENT_TIMESTAMP,
                            revoke_reason = :reason,
                            version = version + 1
                        WHERE suppression_id = :suppressionId
                          AND version = :expectedVersion
                          AND revoked_at IS NULL
                        """)
                .param("actorId", actorId)
                .param("reason", reason)
                .param("suppressionId", suppressionId)
                .param("expectedVersion", expectedVersion)
                .update();
    }

    private static RuntimeSuppressionResponse response(ResultSet rs) throws SQLException {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime expiresAt = rs.getObject("expires_at", OffsetDateTime.class);
        OffsetDateTime revokedAt = rs.getObject("revoked_at", OffsetDateTime.class);
        String status = revokedAt != null ? "REVOKED" : !expiresAt.isAfter(now) ? "EXPIRED" : "ACTIVE";
        return new RuntimeSuppressionResponse(
                rs.getLong("suppression_id"), rs.getString("rule_key"), rs.getString("cluster_id"),
                rs.getString("namespace"), rs.getString("workload_name"), rs.getString("process_executable"),
                rs.getString("target_name_prefix"), rs.getString("operation"), rs.getString("reason_code"),
                rs.getString("evidence_ref"), rs.getString("comment"), rs.getLong("created_by_user_id"),
                format(rs.getObject("created_at", OffsetDateTime.class)), format(expiresAt),
                nullableLong(rs, "revoked_by_user_id"), format(revokedAt), rs.getString("revoke_reason"),
                status, rs.getLong("version"));
    }

    private static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static String format(OffsetDateTime value) {
        return value == null ? null : value.toInstant().toString();
    }

    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    public record ValidatedSuppression(
            String ruleKey,
            String clusterId,
            String namespace,
            String workloadName,
            String processExecutable,
            String targetNamePrefix,
            String operation,
            String reasonCode,
            String evidenceRef,
            String comment,
            Instant expiresAt,
            String idempotencyKey) {
    }

    public record IdempotentSuppression(long suppressionId, String requestDigest) {
    }

    public record CurrentSuppression(long version, boolean revoked) {
    }
}
