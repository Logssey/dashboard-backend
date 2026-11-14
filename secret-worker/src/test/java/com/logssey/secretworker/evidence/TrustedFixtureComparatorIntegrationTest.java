package com.logssey.secretworker.evidence;

import java.time.*;
import java.util.*;
import com.logssey.secretworker.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import static org.assertj.core.api.Assertions.*;

class TrustedFixtureComparatorIntegrationTest {
 static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");static JdbcTemplate jdbc;static DataSourceTransactionManager tx;
 TrustedFixtureManifestRegistrar registrar;long connection,scope,run,runScope,tool;byte[] fingerprint;
 @BeforeAll static void start(){POSTGRES.start();var ds=new DriverManagerDataSource(POSTGRES.getJdbcUrl(),POSTGRES.getUsername(),POSTGRES.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tx=new DataSourceTransactionManager(ds);}
 @AfterAll static void stop(){POSTGRES.stop();}
 @BeforeEach void setup(){jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
  jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','unused','Security','ADMIN')");
  jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,'MANUAL')");
  connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','private-repo','protected-auth','ACTIVE',1) RETURNING connection_id",Long.class);
  scope=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at) VALUES(?,'fixture',1,'GITHUB_REPOSITORY_FILES','github://private-repo/protected-path',true,'TEST',1,now()) RETURNING scope_id",Long.class,connection);
  long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status) VALUES('FULL_SCAN',?,now()-interval '1 minute',now()-interval '1 minute',0,3,'PENDING') RETURNING job_id",Long.class,connection);
  run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SKIPPED','PENDING') RETURNING run_id",Long.class,job,connection);
  runScope=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at,detection_stage_status,validation_stage_status,validation_required) VALUES(?,?,'SUCCEEDED',1,now(),'SUCCEEDED','SKIPPED',false) RETURNING run_scope_id",Long.class,run,scope);
  tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at) VALUES(?,'GITLEAKS','8.30.1','test-config','SUCCEEDED',1,now()) RETURNING tool_run_id",Long.class,runScope);
  fingerprint=new byte[32];Arrays.fill(fingerprint,(byte)7);registrar=new TrustedFixtureManifestRegistrar(jdbc,tx);
 }
 @Test void realWorkerCompletionCreatesAnUnassignedWarningWithoutDefaults(){long key=key("CONFIRMED",fingerprint);complete();
  assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);assertThat(count("secret_investigation_tasks")).isEqualTo(1);
  assertThat(jdbc.queryForMap("SELECT assignee_user_id,due_at,status FROM secret_cross_environment_alerts")).containsEntry("assignee_user_id",null).containsEntry("due_at",null).containsEntry("status","SUSPECTED_REAL");
  assertThat(jdbc.queryForObject("SELECT credential_set_id FROM secret_cross_environment_alerts",Long.class)).isEqualTo(key);
 }
 @Test void approvedExactProtectedIdentityCanAutoAttestButSameMaskedSuffixCannot(){
  long exact=key("CONFIRMED",fingerprint);byte[] other=fingerprint.clone();other[0]=8;long different=key("CONFIRMED",other);
  register(fingerprint,true);complete();
  assertThat(jdbc.queryForObject("SELECT match_result FROM secret_fixture_match_evidence WHERE credential_set_id=?",String.class,exact)).isEqualTo("MATCH");
  assertThat(jdbc.queryForObject("SELECT match_result FROM secret_fixture_match_evidence WHERE credential_set_id=?",String.class,different)).isEqualTo("NO_MATCH");
  assertThat(jdbc.queryForObject("SELECT credential_set_id FROM secret_current_fixture_attestations",Long.class)).isEqualTo(exact);
  assertThat(jdbc.queryForObject("SELECT credential_set_id FROM secret_cross_environment_alerts",Long.class)).isEqualTo(different);
  new TransactionTemplate(tx).executeWithoutResult(s->new TrustedFixtureComparator(jdbc).compareRun(run,OffsetDateTime.now()));
  assertThat(count("secret_fixture_match_evidence")).isEqualTo(2);
 }
 @Test void matchWithoutApprovedAutoPolicyWaitsForHumanAttestation(){key("CONFIRMED",fingerprint);register(fingerprint,false);complete();
  assertThat(jdbc.queryForObject("SELECT match_result FROM secret_fixture_match_evidence",String.class)).isEqualTo("MATCH");
  assertThat(count("secret_test_fixture_attestations")).isZero();assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);
 }
 @Test void candidateAndMetadataNeverBecomeFixtureOrRealKeyWarnings(){key("CANDIDATE",fingerprint);key("METADATA_ONLY",null);complete();
  assertThat(count("secret_cross_environment_alerts")).isZero();assertThat(count("secret_fixture_match_evidence")).isZero();
 }
 @Test void revokedOrExpiredManifestDoesNotProveSyntheticIdentity(){key("CONFIRMED",fingerprint);long manifest=register(fingerprint,true);
  jdbc.update("UPDATE secret_fixture_manifests SET approval_status='REVOKED',revoked_at=now() WHERE manifest_id=?",manifest);complete();
  assertThat(count("secret_fixture_match_evidence")).isZero();assertThat(count("secret_current_fixture_attestations")).isZero();assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);
 }
 @Test void operatorApprovalRequiresTheScopesLiveSecurityGrant(){key("CONFIRMED",fingerprint);jdbc.update("UPDATE secret_role_grants SET revoked_at=now()");
  assertThatThrownBy(()->register(fingerprint,true)).isInstanceOf(IllegalStateException.class).hasMessage("FIXTURE_REGISTRATION_FAILED").hasNoCause();
  assertThat(count("secret_fixture_manifests")).isZero();
 }
 long register(byte[] bytes,boolean auto){return registrar.registerApproved("FIXTURE:APPROVED_TEST",1,OffsetDateTime.now().minusDays(1),OffsetDateTime.now().plusDays(1),auto,
  List.of(new TrustedFixtureManifestRegistrar.Identity(scope,1,"AWS","AWS_ACCESS_KEY_PAIR","test-v1",bytes)));}
 void complete(){var execution=SecretJobTestSupport.execution(jdbc,new SecretJobProperties(false,Duration.ofSeconds(30),Duration.ofMinutes(5),10,Duration.ofSeconds(1),Duration.ofSeconds(8)),tx);
  var claimed=execution.claimNextJob("GITHUB").orElseThrow();assertThat(execution.complete(claimed.jobId(),claimed.leaseToken())).isTrue();}
 long key(String state,byte[] bytes){long key=jdbc.queryForObject("""
  INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,candidate_locator,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
  VALUES('AWS','AWS_ACCESS_KEY_PAIR',?,CASE WHEN ?='CONFIRMED' THEN ?::bytea END,CASE WHEN ?='CANDIDATE' THEN ?::bytea END,
   CASE WHEN ?='METADATA_ONLY' THEN NULL ELSE 'test-v1' END,'AWS ••••1234',now(),now()) RETURNING credential_set_id
  """,Long.class,state,state,bytes,state,bytes,state);
  long occurrence=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id) VALUES(?,?,?,'private-repo/protected-path',gen_random_uuid()::text,'UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now(),?) RETURNING occurrence_id",Long.class,key,connection,scope,run);
  jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,gen_random_uuid()::text,'aws-access-token','1',now())",occurrence,run,tool);return key;
 }
 static long count(String table){return jdbc.queryForObject("SELECT count(*) FROM "+table,Long.class);}
}
