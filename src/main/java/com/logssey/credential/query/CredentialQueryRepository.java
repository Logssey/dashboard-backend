package com.logssey.credential.query;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** 키 목록 조회. detection_events는 읽지 않는다 (Secret 결과는 일반 탐지 이력과 분리) */
@Repository
public class CredentialQueryRepository {

    private final JdbcClient jdbcClient;

    public CredentialQueryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public List<StoredCredential> findAllCredentials() {
        return jdbcClient.sql("""
                        SELECT credential_id, issuer, credential_type, external_id, display_name,
                               owner, owner_team, environment,
                               issued_at, expiry_policy, expires_at, last_used_at, status,
                               source, masked_value, storage_location,
                               (fingerprint IS NOT NULL) AS secret_seen
                        FROM credentials
                        ORDER BY credential_id
                        """)
                .query((rs, rowNum) -> toStoredCredential(rs))
                .list();
    }

    private static StoredCredential toStoredCredential(ResultSet rs) throws SQLException {
        CollectedCredential credential = new CollectedCredential(
                rs.getString("issuer"),
                rs.getString("credential_type"),
                rs.getString("external_id"),
                rs.getString("display_name"),
                rs.getString("owner"),
                instant(rs, "issued_at"),
                ExpiryPolicy.valueOf(rs.getString("expiry_policy")),
                instant(rs, "expires_at"),
                instant(rs, "last_used_at"),
                CredentialStatus.valueOf(rs.getString("status")),
                null,
                null);
        return new StoredCredential(
                rs.getLong("credential_id"),
                credential,
                rs.getString("owner_team"),
                rs.getString("environment"),
                rs.getString("source"),
                rs.getString("masked_value"),
                rs.getString("storage_location"),
                rs.getBoolean("secret_seen"));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value != null ? value.toInstant() : null;
    }
}
