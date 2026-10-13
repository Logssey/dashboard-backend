package com.logssey.credential.scan;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * 페이지에서 발견한 키를 credentials에 저장한다 (source = SCAN).
 * 같은 키(같은 발급자 + 같은 식별자, 또는 같은 지문)가 이미 있으면 새로 만들지 않고 발견 위치·시각만 갱신한다.
 * 키 원문은 저장하지 않는다 (Secret ADR-S005). 환경은 비워 둔다 (UNKNOWN, PROD로 가정하지 않음).
 */
@Repository
public class LeakCredentialRepository {

    private final JdbcClient jdbcClient;

    public LeakCredentialRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** @return 새로 저장했으면 true, 이미 있어서 갱신했으면 false */
    public boolean upsert(LeakedCredential leak, Instant now) {
        OffsetDateTime collectedAt = OffsetDateTime.ofInstant(now, ZoneOffset.UTC);
        Optional<Long> existing = findExisting(leak);
        if (existing.isPresent()) {
            jdbcClient.sql("""
                            UPDATE credentials
                            SET storage_location = :location,
                                fingerprint = COALESCE(fingerprint, :fingerprint),
                                last_collected_at = :now,
                                updated_at = :now
                            WHERE credential_id = :id
                            """)
                    .param("location", leak.storageLocation())
                    .param("fingerprint", leak.fingerprint())
                    .param("now", collectedAt)
                    .param("id", existing.get())
                    .update();
            return false;
        }
        jdbcClient.sql("""
                        INSERT INTO credentials
                            (issuer, credential_type, classification, display_name, external_id, masked_value,
                             fingerprint, storage_location, status, source, expiry_policy, last_collected_at)
                        VALUES
                            (:issuer, :type, 'SECRET', :displayName, :externalId, :masked,
                             :fingerprint, :location, 'UNKNOWN', 'SCAN', 'UNKNOWN', :now)
                        """)
                .param("issuer", leak.issuer())
                .param("type", leak.credentialType())
                .param("displayName", leak.displayName())
                .param("externalId", leak.externalId())
                .param("masked", leak.maskedValue())
                .param("fingerprint", leak.fingerprint())
                .param("location", leak.storageLocation())
                .param("now", collectedAt)
                .update();
        return true;
    }

    private Optional<Long> findExisting(LeakedCredential leak) {
        if (leak.externalId() != null) {
            return jdbcClient.sql("SELECT credential_id FROM credentials WHERE issuer = :issuer AND external_id = :externalId")
                    .param("issuer", leak.issuer())
                    .param("externalId", leak.externalId())
                    .query(Long.class)
                    .optional();
        }
        if (leak.fingerprint() != null) {
            return jdbcClient.sql("SELECT credential_id FROM credentials WHERE fingerprint = :fingerprint")
                    .param("fingerprint", leak.fingerprint())
                    .query(Long.class)
                    .optional();
        }
        return Optional.empty();
    }
}
