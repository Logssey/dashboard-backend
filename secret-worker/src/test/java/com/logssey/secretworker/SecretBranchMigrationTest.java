package com.logssey.secretworker;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

class SecretBranchMigrationTest {
    @Test
    void upgradeRetainsAmbiguousHistoryAndReconstructsOnlyConsistentBranchCoordinates() {
        try(var pg=new com.logssey.secret.testing.SecretTestPostgres()) {
            pg.start();
            var source=new DriverManagerDataSource(pg.getJdbcUrl(),pg.getUsername(),pg.getPassword());
            Flyway.configure().dataSource(source).target("61").load().migrate();
            var jdbc=new JdbcTemplate(source);
            assertThatThrownBy(() -> new SecretSourceSchemaCompatibility(jdbc).afterPropertiesSet())
                    .hasMessage("SECRET_SOURCE_SCHEMA_REQUIRES_V65");
            long connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Legacy','unused','ACTIVE',1) RETURNING connection_id",Long.class);
            long main=scope(jdbc,connection,"main"),feature=scope(jdbc,connection,"feature");
            long mainRun=run(jdbc,connection),featureRun=run(jdbc,connection);
            long mainTool=tool(jdbc,mainRun,main),featureTool=tool(jdbc,featureRun,feature);
            long key=jdbc.queryForObject("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at) VALUES('GITHUB','GITHUB_CLASSIC_PAT','CONFIRMED',decode(repeat('ab',32),'hex'),'test-v1','GitHub masked',clock_timestamp(),clock_timestamp()) RETURNING credential_set_id",Long.class);
            long consistent=occurrence(jdbc,key,connection,main,mainRun,"L1");
            long ambiguous=occurrence(jdbc,key,connection,main,featureRun,"L2");
            finding(jdbc,consistent,mainRun,mainTool,"consistent");
            finding(jdbc,ambiguous,mainRun,mainTool,"ambiguous-main");
            finding(jdbc,ambiguous,featureRun,featureTool,"ambiguous-feature");

            Flyway.configure().dataSource(source).load().migrate();
            assertThatCode(() -> new SecretSourceSchemaCompatibility(jdbc).afterPropertiesSet())
                    .doesNotThrowAnyException();

            assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings",Long.class)).isEqualTo(3);
            assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isEqualTo(2);
            assertThat(jdbc.queryForMap("SELECT source_context_ref,source_context_status FROM secret_occurrences WHERE occurrence_id=?",consistent))
                    .containsEntry("source_context_ref","github://Logssey/project/main/src/")
                    .containsEntry("source_context_status","RECONSTRUCTED");
            assertThat(jdbc.queryForMap("SELECT source_context_ref,source_context_status,presence_status FROM secret_occurrences WHERE occurrence_id=?",ambiguous))
                    .containsEntry("source_context_ref",null).containsEntry("source_context_status","UNKNOWN")
                    .containsEntry("presence_status","UNKNOWN");
        }
    }

    private long scope(JdbcTemplate jdbc,long connection,String branch) {
        return jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled) VALUES(?,?,1,'GITHUB_REPOSITORY_FILES',?,'CURRENT_COMMIT_ONLY',true) RETURNING scope_id",
                Long.class,connection,branch,"github://Logssey/project/"+branch+"/src/");
    }
    private long run(JdbcTemplate jdbc,long connection) {
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',?,clock_timestamp(),clock_timestamp(),1,1,'SUCCEEDED',clock_timestamp()) RETURNING job_id",Long.class,connection);
        return jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,clock_timestamp(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED') RETURNING run_id",Long.class,job,connection);
    }
    private long tool(JdbcTemplate jdbc,long run,long scope) {
        long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'SUCCEEDED') RETURNING run_scope_id",Long.class,run,scope);
        return jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status) VALUES(?,'GITLEAKS','8.30.1',?,'SUCCEEDED') RETURNING tool_run_id",Long.class,rs,"a".repeat(64));
    }
    private long occurrence(JdbcTemplate jdbc,long key,long connection,long scope,long run,String location) {
        return jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id) VALUES(?,?,?,'Logssey/project/src/key.env',?,'UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',clock_timestamp(),clock_timestamp(),?) RETURNING occurrence_id",Long.class,key,connection,scope,location,run);
    }
    private void finding(JdbcTemplate jdbc,long occurrence,long run,long tool,String findingKey) {
        jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,?,'github-pat','8.30.1',clock_timestamp())",occurrence,run,tool,findingKey);
    }
}
