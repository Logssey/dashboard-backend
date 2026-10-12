package com.logssey.credential.event;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** 키 위험 판단에 필요한 조회와 탐지 이벤트 저장 */
@Repository
public class CredentialRiskRepository {

    private static final Pattern SECRETS_DISPLAY_ID = Pattern.compile("^SEC-(\\d+)$");

    private final JdbcClient jdbcClient;

    public CredentialRiskRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** 같은 탐지인지 판단하는 기준: 같은 키 + 같은 제목 */
    public record EventKey(long credentialId, String title) {
    }

    public List<StoredCredential> findAllCredentials() {
        return jdbcClient.sql("""
                        SELECT c.credential_id, c.issuer, c.credential_type, c.external_id, c.display_name,
                               c.owner, c.owner_team, c.environment, c.asset_id,
                               c.issued_at, c.expiry_policy, c.expires_at, c.last_used_at, c.status,
                               c.source, c.masked_value, c.storage_location,
                               (c.fingerprint IS NOT NULL) AS secret_exposed,
                               a.environment AS asset_environment
                        FROM credentials c
                        LEFT JOIN assets a ON a.asset_id = c.asset_id
                        ORDER BY c.credential_id
                        """)
                .query((rs, rowNum) -> toStoredCredential(rs))
                .list();
    }

    /** 키에 연결된 탐지 이벤트 한 건 (키 목록의 "위험" 칸) */
    public record LinkedEvent(long eventId, long credentialId, String displayId, String severity, String title,
                              String reviewStatus) {
    }

    public List<LinkedEvent> findLinkedEvents() {
        return jdbcClient.sql("""
                        SELECT event_id, credential_id, display_id, severity, title, review_status
                        FROM detection_events
                        WHERE credential_id IS NOT NULL
                        ORDER BY event_id
                        """)
                .query((rs, rowNum) -> new LinkedEvent(
                        rs.getLong("event_id"),
                        rs.getLong("credential_id"),
                        rs.getString("display_id"),
                        rs.getString("severity"),
                        rs.getString("title"),
                        rs.getString("review_status")))
                .list();
    }

    public Set<EventKey> findExistingEventKeys() {
        return new HashSet<>(jdbcClient.sql("""
                        SELECT credential_id, title FROM detection_events WHERE credential_id IS NOT NULL
                        """)
                .query((rs, rowNum) -> new EventKey(rs.getLong("credential_id"), rs.getString("title")))
                .list());
    }

    /** 지금까지 쓴 SEC- 번호 중 가장 큰 값. 없으면 0 */
    public int findMaxSecretsNumber() {
        List<String> displayIds = jdbcClient.sql("""
                        SELECT display_id FROM detection_events WHERE display_id LIKE 'SEC-%'
                        """)
                .query(String.class)
                .list();
        int max = 0;
        for (String displayId : displayIds) {
            Matcher matcher = SECRETS_DISPLAY_ID.matcher(displayId);
            if (matcher.matches()) {
                max = Math.max(max, Integer.parseInt(matcher.group(1)));
            }
        }
        return max;
    }

    public void insertEvent(NewDetectionEvent event) {
        jdbcClient.sql("""
                        INSERT INTO detection_events
                            (asset_id, credential_id, display_id, severity, title, environment, owner_team,
                             detected_at, domain, evidence, recommendation)
                        VALUES
                            (:assetId, :credentialId, :displayId, :severity, :title, :environment, :ownerTeam,
                             :detectedAt, :domain, :evidence, :recommendation)
                        """)
                .param("assetId", event.assetId())
                .param("credentialId", event.credentialId())
                .param("displayId", event.displayId())
                .param("severity", event.severity())
                .param("title", event.title())
                .param("environment", event.environment())
                .param("ownerTeam", event.ownerTeam())
                .param("detectedAt", OffsetDateTime.ofInstant(event.detectedAt(), ZoneOffset.UTC))
                .param("domain", event.domain())
                .param("evidence", event.evidence())
                .param("recommendation", event.recommendation())
                .update();
    }

    private static StoredCredential toStoredCredential(ResultSet rs) throws SQLException {
        long assetId = rs.getLong("asset_id");
        Long nullableAssetId = rs.wasNull() ? null : assetId;
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
                nullableAssetId,
                rs.getString("asset_environment"),
                rs.getString("source"),
                rs.getString("masked_value"),
                rs.getString("storage_location"),
                rs.getBoolean("secret_exposed"));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value != null ? value.toInstant() : null;
    }
}
