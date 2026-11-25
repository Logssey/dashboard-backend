package com.logssey.secretworker;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import static org.assertj.core.api.Assertions.assertThat;

class SecretBranchPresenceTest {
    private static final com.logssey.secret.testing.SecretTestPostgres PG=new com.logssey.secret.testing.SecretTestPostgres();
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private static final String CONFIG="a".repeat(64);
    private static final byte[] CONTENT=("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=" // gitleaks:allow -- fixed synthetic fixture
            +"aB3/".repeat(10)+"\n").getBytes(StandardCharsets.UTF_8);
    private static final List<GitleaksFinding> FINDINGS=List.of(
            new GitleaksFinding("aws-access-token",1,1,19,38),new GitleaksFinding("generic-api-key",2,2,1,60));
    private SecretJobExecutionService execution;
    private SecretFindingRepository findings;
    private long connection,main,feature;

    @BeforeAll static void database() {
        PG.start();
        var source=new DriverManagerDataSource(PG.getJdbcUrl(),PG.getUsername(),PG.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        jdbc=new JdbcTemplate(source);transactions=new DataSourceTransactionManager(source);
    }
    @AfterAll static void close() { PG.stop(); }
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        execution=new SecretJobExecutionService(new SecretJobRepository(jdbc),
                new SecretJobProperties(false,Duration.ofSeconds(30),Duration.ofMinutes(5),10,
                        Duration.ofSeconds(1),Duration.ofMinutes(1)),transactions);
        findings=new SecretFindingRepository(jdbc,new TransactionTemplate(transactions),
                new SecretFindingNormalizer(new byte[32],"test-v1"));
        connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Branches','unused','ACTIVE',1) RETURNING connection_id",Long.class);
        main=scope("main");feature=scope("feature%2Fsecret");
    }

    @Test void sameKeyAndFileHaveIndependentBranchLocationsAndPresence() {
        scan(main,true);scan(feature,true);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT source_context_key) FROM secret_occurrences",Long.class)).isEqualTo(2);
        scan(main,false);
        assertThat(presence(main)).isEqualTo("MISSING");
        assertThat(presence(feature)).isEqualTo("PRESENT");
        scan(feature,true);
        assertThat(presence(main)).isEqualTo("MISSING");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isEqualTo(2);
    }

    @Test void aChangedBranchCannotReuseOrRetireThePreviousBranchLocation() {
        scan(main,true);
        long old=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences",Long.class);
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Logssey/project/renamed/src/',revision=revision+1 WHERE scope_id=?",main);
        scan(main,true);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT source_context_ref FROM secret_occurrences WHERE occurrence_id=?",String.class,old))
                .isEqualTo("github://Logssey/project/main/src/");
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?",String.class,old))
                .isEqualTo("UNKNOWN");
    }

    @Test void aFreshObservationKeepsAmbiguousLegacyLocationHistorySeparate() {
        scan(main,true);
        long legacy=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences",Long.class);
        jdbc.update("UPDATE secret_occurrences SET source_context_ref=NULL,source_context_status='UNKNOWN',presence_status='UNKNOWN' WHERE occurrence_id=?",legacy);
        scan(main,true);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForMap("SELECT source_context_ref,source_context_status,presence_status FROM secret_occurrences WHERE occurrence_id=?",legacy))
                .containsEntry("source_context_ref",null).containsEntry("source_context_status","UNKNOWN")
                .containsEntry("presence_status","UNKNOWN");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences WHERE source_context_status='OBSERVED' AND presence_status='PRESENT'",Long.class)).isEqualTo(1);
    }

    private long scope(String branch) {
        return jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled) VALUES(?,?,1,'GITHUB_REPOSITORY_FILES',?,'CURRENT_COMMIT_ONLY',true) RETURNING scope_id",
                Long.class,connection,branch,"github://Logssey/project/"+branch+"/src/");
    }

    private void scan(long scope,boolean found) {
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status) VALUES('FULL_SCAN',?,clock_timestamp(),clock_timestamp(),0,1,'PENDING') RETURNING job_id",Long.class,connection);
        long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,clock_timestamp(),clock_timestamp(),'PENDING','PENDING','PENDING','PENDING') RETURNING run_id",Long.class,job,connection);
        long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'PENDING') RETURNING run_scope_id",Long.class,run,scope);
        var claim=execution.claimNextJob("GITHUB").orElseThrow();
        jdbc.update("UPDATE secret_run_scopes SET collection_status='RUNNING',started_at=clock_timestamp() WHERE run_scope_id=?",rs);
        long tool=findings.beginGitleaksRun(rs,"8.30.1",CONFIG,Instant.now());
        if(found) findings.recordObject(tool,"Logssey/project/src/config.env","blob-v1",CONTENT,
                new GitleaksScanResult("8.30.1",CONFIG,FINDINGS),Instant.now());
        jdbc.update("UPDATE secret_findings SET detected_at=clock_timestamp()-interval '1 second' WHERE run_id=?",run);
        findings.finishToolRun(tool,"SUCCEEDED",null,Instant.now());
        jdbc.update("UPDATE secret_run_scopes SET collection_status='SUCCEEDED',object_count=?,finished_at=clock_timestamp() WHERE run_scope_id=?",found?1:0,rs);
        jdbc.update("UPDATE secret_scan_runs SET collection_status='SUCCEEDED',detection_status=?,validation_status='SKIPPED' WHERE run_id=?",found?"SUCCEEDED":"SKIPPED",run);
        assertThat(execution.recordScopeEvidence(job,claim.leaseToken(),rs,false)).isTrue();
        assertThat(execution.complete(job,claim.leaseToken())).isTrue();
    }

    private String presence(long scope) {
        return jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE scope_id=?",String.class,scope);
    }
}
