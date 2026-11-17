package com.logssey.compliance;

import static com.logssey.compliance.ComplianceTargetDtos.TargetExecutionSnapshot;
import static com.logssey.compliance.ComplianceTargetDtos.TargetSummary;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Repository
public class ComplianceTargetRepository {

    private static final String COLUMNS = """
            target_key, display_name, provider, aws_account_id, role_arn, external_id,
            default_regions::text AS default_regions_json, enabled, connection_status,
            connection_error_code, connection_checked_at, version, created_at, updated_at
            """;

    private final JdbcClient jdbc;
    private final JsonMapper json = JsonMapper.builder().build();

    public ComplianceTargetRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    List<TargetSummary> list() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM compliance_targets ORDER BY display_name, target_key")
                .query(this::summary).list();
    }

    Optional<TargetSummary> find(String targetKey) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM compliance_targets WHERE target_key = :targetKey")
                .param("targetKey", targetKey).query(this::summary).optional();
    }

    Optional<TargetExecutionSnapshot> executionSnapshot(String targetKey) {
        return jdbc.sql("""
                        SELECT target_key, aws_account_id, role_arn, external_id,
                               default_regions::text AS default_regions_json, version,
                               enabled, connection_status
                        FROM compliance_targets WHERE target_key = :targetKey
                        """)
                .param("targetKey", targetKey)
                .query((rs, row) -> new TargetExecutionSnapshot(
                        rs.getString("target_key"), rs.getString("aws_account_id"),
                        rs.getString("role_arn"), rs.getString("external_id"),
                        readRegions(rs.getString("default_regions_json")), rs.getLong("version"),
                        rs.getBoolean("enabled"), rs.getString("connection_status")))
                .optional();
    }

    TargetSummary insert(String targetKey, String displayName, String accountId, String roleArn,
                         String externalId, List<String> defaultRegions, String loginId) {
        return jdbc.sql("""
                        INSERT INTO compliance_targets (
                            target_key, display_name, provider, aws_account_id, role_arn, external_id,
                            default_regions, created_by_login, updated_by_login)
                        VALUES (:targetKey, :displayName, 'aws', :accountId, :roleArn, :externalId,
                            CAST(:regions AS jsonb), :loginId, :loginId)
                        RETURNING %s
                        """.formatted(COLUMNS))
                .param("targetKey", targetKey).param("displayName", displayName)
                .param("accountId", accountId).param("roleArn", roleArn).param("externalId", externalId)
                .param("regions", writeRegions(defaultRegions)).param("loginId", loginId)
                .query(this::summary).single();
    }

    Optional<TargetSummary> update(String targetKey, long expectedVersion, String displayName,
                                   String accountId, String roleArn, List<String> defaultRegions,
                                   boolean enabled, String loginId) {
        return jdbc.sql("""
                        UPDATE compliance_targets
                        SET display_name = :displayName, aws_account_id = :accountId, role_arn = :roleArn,
                            default_regions = CAST(:regions AS jsonb), enabled = :enabled,
                            connection_status = CASE
                                WHEN aws_account_id <> :accountId OR role_arn <> :roleArn
                                THEN 'NOT_TESTED' ELSE connection_status END,
                            connection_error_code = CASE
                                WHEN aws_account_id <> :accountId OR role_arn <> :roleArn
                                THEN NULL ELSE connection_error_code END,
                            connection_checked_at = CASE
                                WHEN aws_account_id <> :accountId OR role_arn <> :roleArn
                                THEN NULL ELSE connection_checked_at END,
                            version = version + 1, updated_by_login = :loginId,
                            updated_at = clock_timestamp()
                        WHERE target_key = :targetKey AND version = :expectedVersion
                        RETURNING %s
                        """.formatted(COLUMNS))
                .param("targetKey", targetKey).param("expectedVersion", expectedVersion)
                .param("displayName", displayName).param("accountId", accountId).param("roleArn", roleArn)
                .param("regions", writeRegions(defaultRegions)).param("enabled", enabled)
                .param("loginId", loginId).query(this::summary).optional();
    }

    boolean markVerifying(String targetKey, long version, String loginId) {
        return jdbc.sql("""
                        UPDATE compliance_targets
                        SET connection_status = 'VERIFYING', connection_error_code = NULL,
                            updated_by_login = :loginId, updated_at = clock_timestamp()
                        WHERE target_key = :targetKey AND version = :version
                          AND connection_status <> 'VERIFYING'
                        """)
                .param("targetKey", targetKey).param("version", version).param("loginId", loginId)
                .update() == 1;
    }

    boolean markVerified(String targetKey, long version, String accountId) {
        return jdbc.sql("""
                        UPDATE compliance_targets
                        SET connection_status = 'VERIFIED', connection_error_code = NULL,
                            connection_checked_at = clock_timestamp(), updated_at = clock_timestamp()
                        WHERE target_key = :targetKey AND version = :version AND aws_account_id = :accountId
                        """)
                .param("targetKey", targetKey).param("version", version).param("accountId", accountId)
                .update() == 1;
    }

    void markFailed(String targetKey, long version, String errorCode) {
        jdbc.sql("""
                        UPDATE compliance_targets
                        SET connection_status = 'FAILED', connection_error_code = :errorCode,
                            connection_checked_at = clock_timestamp(), updated_at = clock_timestamp()
                        WHERE target_key = :targetKey AND version = :version
                        """)
                .param("targetKey", targetKey).param("version", version).param("errorCode", errorCode)
                .update();
    }

    void markNotTested(String targetKey, long version) {
        jdbc.sql("""
                        UPDATE compliance_targets
                        SET connection_status = 'NOT_TESTED', connection_error_code = NULL,
                            connection_checked_at = NULL, updated_at = clock_timestamp()
                        WHERE target_key = :targetKey AND version = :version
                        """)
                .param("targetKey", targetKey).param("version", version).update();
    }

    private TargetSummary summary(ResultSet rs, int row) throws SQLException {
        return new TargetSummary(
                rs.getString("target_key"), rs.getString("display_name"), rs.getString("provider"),
                rs.getString("aws_account_id"), rs.getString("role_arn"), rs.getString("external_id"),
                readRegions(rs.getString("default_regions_json")), rs.getBoolean("enabled"),
                rs.getString("connection_status"), rs.getString("connection_error_code"),
                rs.getObject("connection_checked_at", OffsetDateTime.class), rs.getLong("version"),
                rs.getObject("created_at", OffsetDateTime.class), rs.getObject("updated_at", OffsetDateTime.class));
    }

    private String writeRegions(List<String> regions) {
        try {
            return json.writeValueAsString(regions);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("기본 리전을 직렬화할 수 없습니다.", e);
        }
    }

    private List<String> readRegions(String value) {
        try {
            return json.readValue(value, json.getTypeFactory().constructCollectionType(List.class, String.class));
        } catch (JacksonException e) {
            throw new IllegalStateException("저장된 기본 리전을 읽을 수 없습니다.", e);
        }
    }
}
