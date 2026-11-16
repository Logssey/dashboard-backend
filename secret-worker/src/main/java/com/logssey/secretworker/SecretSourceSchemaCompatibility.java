package com.logssey.secretworker;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Prevents source execution against a schema that cannot isolate branch locations. */
@Component
@DependsOnDatabaseInitialization
@ConditionalOnProperty(name="logssey.secret.executor.enabled",havingValue="true")
final class SecretSourceSchemaCompatibility implements InitializingBean {
    private final JdbcTemplate jdbc;

    SecretSourceSchemaCompatibility(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    @Override public void afterPropertiesSet() {
        boolean ready;
        try {
            ready=Boolean.TRUE.equals(jdbc.queryForObject("""
                    SELECT EXISTS(SELECT 1 FROM information_schema.columns
                      WHERE table_schema=current_schema() AND table_name='secret_occurrences'
                        AND column_name='source_context_key')
                      AND EXISTS(SELECT 1 FROM information_schema.columns
                      WHERE table_schema=current_schema() AND table_name='secret_run_scopes'
                        AND column_name='snapshot_approved_ref')
                    """,Boolean.class));
        } catch (RuntimeException failure) {
            throw new IllegalStateException("SECRET_SOURCE_SCHEMA_CHECK_UNAVAILABLE");
        }
        if (!ready) throw new IllegalStateException("SECRET_SOURCE_SCHEMA_REQUIRES_V55");
    }
}
