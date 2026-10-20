package com.logssey.secretworker;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import com.logssey.secretworker.detection.*;
import com.logssey.secretworker.detector.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import static org.assertj.core.api.Assertions.*;
/** Real lease completion, persisted detector provenance and consecutive source snapshots. No external services. */
class SecretFullScanPresenceTest {
 static final PostgreSQLContainer DB=new PostgreSQLContainer("postgres:18.6");static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
 static final String CONFIG="a".repeat(64),ENGINE="8.30.1";
 static final byte[] PAIR=("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY="+"aB3/".repeat(10)+"\n").getBytes(StandardCharsets.UTF_8);
 static final byte[] PARTIAL="AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n".getBytes(StandardCharsets.UTF_8);
 static final List<GitleaksFinding> PAIR_FINDINGS=List.of(new GitleaksFinding("aws-access-token",1,1,19,38),new GitleaksFinding("generic-api-key",2,2,1,60));
 SecretJobExecutionService execution;long connection,scope,partialOccurrence,canonicalOccurrence,canonicalKey,firstRun;
 record Attempt(long job,long run,long runScope,long tool,String token,SecretFindingRepository repository,String engine,String config){}
 @BeforeAll static void database(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);}
 @AfterAll static void stop(){DB.stop();}
 @BeforeEach void baseline(){
  jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
  execution=new SecretJobExecutionService(new SecretJobRepository(jdbc),new SecretJobProperties(false,Duration.ofSeconds(30),Duration.ofMinutes(5),10,Duration.ofSeconds(1),Duration.ofSeconds(8)),tm);
  connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Test','unused','ACTIVE',1) RETURNING connection_id",Long.class);
  scope=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled) VALUES(?,'test',1,'GITHUB_REPOSITORY_FILES','github://example/example/main/src/','CURRENT_COMMIT_ONLY',true) RETURNING scope_id",Long.class,connection);
  var first=start(ENGINE,CONFIG,"test-v1");firstRun=first.run;
  first.repository.recordObject(first.tool,"repo/partial.txt","sha-1",PARTIAL,new GitleaksScanResult(ENGINE,CONFIG,List.of(PAIR_FINDINGS.getFirst())),Instant.now());
  first.repository.recordObject(first.tool,"repo/canonical.txt","sha-1",PAIR,new GitleaksScanResult(ENGINE,CONFIG,PAIR_FINDINGS),Instant.now());
  partialOccurrence=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id) WHERE k.component_state='CANDIDATE'",Long.class);
  canonicalOccurrence=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id) WHERE k.component_state='CONFIRMED'",Long.class);
  canonicalKey=jdbc.queryForObject("SELECT credential_set_id FROM secret_credential_sets WHERE component_state='CONFIRMED'",Long.class);
  finish(first,2,"SUCCEEDED","SUCCEEDED");jdbc.update("UPDATE secret_occurrences SET exposure_status='ABNORMAL' WHERE occurrence_id=?",canonicalOccurrence);
 }
 @Test void canonicalAlreadyExistsAndTheNextFullScanRetiresTheOldPartialWithoutMergingHistory(){
  var next=start(ENGINE,CONFIG,"test-v1");
  next.repository.recordObject(next.tool,"repo/partial.txt","sha-2",PAIR,new GitleaksScanResult(ENGINE,CONFIG,PAIR_FINDINGS),Instant.now());
  finish(next,1,"SUCCEEDED","SUCCEEDED");
  assertPresence(partialOccurrence,"MISSING");assertPresence(canonicalOccurrence,"MISSING");
  assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets",Long.class)).isEqualTo(2);
  assertThat(jdbc.queryForObject("SELECT component_state FROM secret_credential_sets k JOIN secret_occurrences o USING(credential_set_id) WHERE o.occurrence_id=?",String.class,partialOccurrence)).isEqualTo("CANDIDATE");
  assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences WHERE presence_status='PRESENT' AND credential_set_id=?",Long.class,canonicalKey)).isEqualTo(1);
  assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,canonicalOccurrence)).isEqualTo("ABNORMAL");
  assertThat(jdbc.queryForObject("SELECT first_seen_run_id FROM secret_credential_sets WHERE credential_set_id=?",Long.class,canonicalKey)).isEqualTo(firstRun);
  assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets WHERE first_seen_run_id=?",Long.class,next.run)).isZero();
 }
 @Test void comparableCompleteEmptySourceCanProveAbsence(){
  var next=start(ENGINE,CONFIG,"test-v1");finish(next,0,"SUCCEEDED","SKIPPED");assertPresence(partialOccurrence,"MISSING");assertPresence(canonicalOccurrence,"MISSING");
 }
 @Test void partialFullScanAndPermanentFailureLeaveUnseenValueLocationsUnknown(){
  var partial=start(ENGINE,CONFIG,"test-v1");finish(partial,1,"PARTIAL","PARTIAL");assertPresence(partialOccurrence,"UNKNOWN");assertPresence(canonicalOccurrence,"UNKNOWN");
  var failed=start(ENGINE,CONFIG,"test-v1");assertThat(execution.fail(failed.job,failed.token,SecretJobFailureCode.SOURCE_UNAVAILABLE,false)).isTrue();assertPresence(partialOccurrence,"UNKNOWN");
 }
 @Test void changedEngineConfigHmacScopeOrOriginCannotInheritOldAbsenceEvidence(){
  for(String mismatch:List.of("engine","config","hmac","revision","origin","connection","legacy")){
   if(!mismatch.equals("engine"))baseline();
   if(mismatch.equals("revision"))jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=?",scope);
   if(mismatch.equals("origin"))jdbc.update("UPDATE secret_connection_scopes SET response_origin_version=response_origin_version+1 WHERE scope_id=?",scope);
   if(mismatch.equals("connection"))jdbc.update("UPDATE secret_connections SET scope_version=scope_version+1 WHERE connection_id=?",connection);
   if(mismatch.equals("legacy"))jdbc.update("UPDATE secret_tool_runs SET fingerprint_key_version=NULL");
   var next=start(mismatch.equals("engine")?"8.31.0":ENGINE,mismatch.equals("config")?"b".repeat(64):CONFIG,mismatch.equals("hmac")?"test-v2":"test-v1");
   finish(next,0,"SUCCEEDED","SKIPPED");assertPresence(partialOccurrence,"UNKNOWN");assertPresence(canonicalOccurrence,"UNKNOWN");
  }
 }
 @Test void actualPositiveObservationStaysPresentEvenWhenOtherCollectionIsIncomplete(){
  var next=start(ENGINE,CONFIG,"test-v1");next.repository.recordObject(next.tool,"repo/canonical.txt","sha-2",PAIR,new GitleaksScanResult(ENGINE,CONFIG,PAIR_FINDINGS),Instant.now());
  finish(next,1,"PARTIAL","PARTIAL");assertPresence(canonicalOccurrence,"PRESENT");assertPresence(partialOccurrence,"UNKNOWN");
 }
 @Test void aSuccessfulScopeCannotProveAbsenceWhenAnotherScopeMakesTheFullRunPartial(){
  var next=start(ENGINE,CONFIG,"test-v1");
  long extra=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled) VALUES(?,'extra',1,'GITHUB_REPOSITORY_FILES','github://example/another/main/src/',true) RETURNING scope_id",Long.class,connection);
  jdbc.update("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,started_at,finished_at) VALUES(?,?,'PARTIAL',1,clock_timestamp(),clock_timestamp())",next.run,extra);
  next.repository.finishToolRun(next.tool,"SUCCEEDED",null,Instant.now());
  jdbc.update("UPDATE secret_run_scopes SET collection_status='SUCCEEDED',object_count=0,finished_at=clock_timestamp() WHERE run_scope_id=?",next.runScope);
  jdbc.update("UPDATE secret_scan_runs SET collection_status='PARTIAL',detection_status='PARTIAL',validation_status='SKIPPED' WHERE run_id=?",next.run);
  execution.recordScopeEvidence(next.job,next.token,next.runScope,false);assertThat(execution.complete(next.job,next.token)).isTrue();
  assertPresence(partialOccurrence,"UNKNOWN");assertPresence(canonicalOccurrence,"UNKNOWN");
 }
 @Test void latestIncomparablePositiveCannotBeBypassedByAnOlderSuccessfulBaseline(){
  var changed=start(ENGINE,"b".repeat(64),"test-v1");
  changed.repository.recordObject(changed.tool,"repo/canonical.txt","sha-2",PAIR,new GitleaksScanResult(ENGINE,"b".repeat(64),PAIR_FINDINGS),Instant.now());
  finish(changed,1,"PARTIAL","PARTIAL");assertPresence(canonicalOccurrence,"PRESENT");
  var next=start(ENGINE,CONFIG,"test-v1");finish(next,0,"SUCCEEDED","SKIPPED");assertPresence(canonicalOccurrence,"UNKNOWN");
 }
 private Attempt start(String engine,String config,String hmac){
  long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status) VALUES('FULL_SCAN',?,clock_timestamp(),clock_timestamp(),0,1,'PENDING') RETURNING job_id",Long.class,connection);
  long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status) SELECT ?,connection_id,'MANUAL',scope_version,clock_timestamp(),clock_timestamp(),'PENDING','PENDING','PENDING','PENDING' FROM secret_connections WHERE connection_id=? RETURNING run_id",Long.class,job,connection);
  long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'PENDING') RETURNING run_scope_id",Long.class,run,scope);
  var claim=execution.claimNextJob().orElseThrow();assertThat(claim.jobId()).isEqualTo(job);
  jdbc.update("UPDATE secret_run_scopes SET collection_status='RUNNING',started_at=clock_timestamp() WHERE run_scope_id=?",rs);
  var repository=new SecretFindingRepository(jdbc,new TransactionTemplate(tm),new SecretFindingNormalizer(new byte[32],hmac));
  long tool=repository.beginGitleaksRun(rs,engine,config,Instant.now());
  return new Attempt(job,run,rs,tool,claim.leaseToken(),repository,engine,config);
 }
 private void finish(Attempt a,int objects,String collection,String detection){
  a.repository.finishToolRun(a.tool,collection.equals("SUCCEEDED")?"SUCCEEDED":"PARTIAL",null,Instant.now());
  jdbc.update("UPDATE secret_run_scopes SET collection_status=?,object_count=?,finished_at=clock_timestamp() WHERE run_scope_id=?",collection,objects,a.runScope);
  jdbc.update("UPDATE secret_scan_runs SET collection_status=?,detection_status=?,validation_status='SKIPPED' WHERE run_id=?",collection,detection,a.run);
  assertThat(execution.recordScopeEvidence(a.job,a.token,a.runScope,false)).isTrue();assertThat(execution.complete(a.job,a.token)).isTrue();
 }
 private void assertPresence(long occurrence,String expected){assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?",String.class,occurrence)).isEqualTo(expected);}
}
