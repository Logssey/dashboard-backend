package com.logssey.secret.connection;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

class SecretConnectionTestRepositoryTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static SecretConnectionTestRepository repository;

    @BeforeAll
    static void database() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        repository = new SecretConnectionTestRepository(jdbc);
    }

    @AfterAll
    static void close() {
        POSTGRES.stop();
    }

    @Test
    void awsScopeSummaryFlagsUnsupportedAndMixedAccountScopes() {
        Long id = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('AWS', 'test', 'aws-profile:test', 'ACTIVE', 1)
                RETURNING connection_id
                """, Long.class);
        addScope(id, "AWS_SECRETS_MANAGER_METADATA", "aws://123456789012/ap-northeast-2/secrets-manager/all",
                "CURRENT_STATE_ONLY");
        addScope(id, "IAM_ACCESS_KEY_METADATA", "aws://123456789012/global/iam/access-keys",
                "CURRENT_STATE_ONLY");
        var supported = repository.awsScopes(id);
        assertThat(supported.count()).isEqualTo(2);
        assertThat(supported.invalidCount()).isZero();
        assertThat(supported.accountCount()).isEqualTo(1);

        addScope(id, "IAM_ACCESS_KEY_METADATA", "aws://999999999999/global/iam/access-keys",
                "CURRENT_STATE_ONLY");
        assertThat(repository.awsScopes(id).accountCount()).isEqualTo(2);

        addScope(id, "AWS_S3_BUCKET_METADATA", "aws://123456789012/global/s3/buckets?bad=1",
                "CURRENT_STATE_ONLY");
        assertThat(repository.awsScopes(id).invalidCount()).isEqualTo(1);
    }

    private static void addScope(long connectionId, String type, String ref, String history) {
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
                VALUES (?, ?, 1, ?, ?, ?, true)
                """, connectionId, "scope-" + System.nanoTime(), type, ref, history);
    }
}
