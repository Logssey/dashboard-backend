package com.logssey.secret.evidence;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.investigation.*;
import com.logssey.secret.fixture.*;
import com.logssey.secret.alert.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import static org.assertj.core.api.Assertions.*;

class SecretInvestigationEvidenceIntegrationTest {
 static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");static JdbcTemplate jdbc;static DataSourceTransactionManager tx;
 SecretInvestigationService tasks;SecretFixtureService fixtures;SecretCrossEnvironmentAlertService alerts;SecretAccessService access;
 @BeforeAll static void start(){POSTGRES.start();var ds=new DriverManagerDataSource(POSTGRES.getJdbcUrl(),POSTGRES.getUsername(),POSTGRES.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tx=new DataSourceTransactionManager(ds);}
 @AfterAll static void stop(){POSTGRES.stop();}
 @BeforeEach void reset(){jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
  jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','unused','Security','ADMIN'),('scoped','unused','Scoped','ADMIN'),('operations','unused','Operations','ADMIN')");
  jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,'MANUAL')");
  access=new SecretAccessService(jdbc);var command=new SecretCommandExecutor(jdbc,tx);tasks=new SecretInvestigationService(jdbc,access,command);fixtures=new SecretFixtureService(jdbc,access,command);alerts=new SecretCrossEnvironmentAlertService(jdbc,access,command);
 }
 @Test void completeCurrentTestValuesCreateExactlyOneUnassignedAlertAndTask(){
  var f=fixture("CONFIRMED",true);reconcile(f.run);reconcile(f.run);
  assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);assertThat(count("secret_investigation_tasks")).isEqualTo(1);
  var task=jdbc.queryForMap("SELECT * FROM secret_investigation_tasks");assertThat(task.get("assignee_user_id")).isNull();assertThat(task.get("due_at")).isNull();
  assertThat(items(tasks.list("security","OVERDUE","ALL",0,20))).isEmpty();
  assertThat(items(alerts.list("security","OPEN","ALL",0,20))).hasSize(1);
  var candidate=fixture("CANDIDATE",true);reconcile(candidate.run);var metadata=fixture("METADATA_ONLY",true);reconcile(metadata.run);var noFinding=fixture("CONFIRMED",false);reconcile(noFinding.run);
  assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);
 }
 @Test void internalRequestsReuseOpenQuestionsAndNeverGrantTargetAccess(){
  var f=fixture("CONFIRMED",true);
  jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(3,'OPERATIONS',?,1,'MANUAL')",f.connection);
  long version=jdbc.queryForObject("SELECT response_origin_version FROM secret_connection_scopes WHERE scope_id=?",Long.class,f.scope);
  var request=new SecretInvestigationRequests.Request("SCOPE",f.scope,"SOURCE_CLASSIFICATION",null,null,"TICKET:SEC-123",version,"handoff-first");
  var first=tasks.request("operations",request);
  var replay=tasks.request("operations",request);
  var repeat=tasks.request("operations",new SecretInvestigationRequests.Request("SCOPE",f.scope,"SOURCE_CLASSIFICATION",null,null,null,version,"handoff-second"));
  assertThat(first.get("taskId")).isEqualTo(replay.get("taskId")).isEqualTo(repeat.get("taskId"));
  assertThat(count("secret_investigation_tasks")).isEqualTo(1);
  assertThat(tasks.detail("operations",(Long)first.get("taskId")).get("creationSource")).isEqualTo("HUMAN_HANDOFF");
  assertCode(ErrorCode.NOT_FOUND,()->tasks.request("scoped",request));
  assertCode(ErrorCode.NOT_FOUND,()->tasks.request("operations",new SecretInvestigationRequests.Request("OCCURRENCE",f.occurrence,"OWNER_UNKNOWN",null,null,null,0L,"no-values")));
 }
 @Test void ownerEvidenceNeedsSecurityAcceptanceBeforeClosingAndDoesNotDecideExposure(){
  var f=fixture("CONFIRMED",true);long version=jdbc.queryForObject("SELECT exposure_assessment_version FROM secret_occurrences WHERE occurrence_id=?",Long.class,f.occurrence);
  long task=(Long)tasks.request("security",new SecretInvestigationRequests.Request("OCCURRENCE",f.occurrence,"OWNER_UNKNOWN",null,null,null,version,"owner-question")).get("taskId");
  tasks.evidence("security",task,new SecretInvestigationRequests.Evidence("TICKET:SEC-123","OWNER_CONFIRMATION",OffsetDateTime.now(),0L,"owner-evidence"));
  long evidence=one("SELECT history_id FROM secret_investigation_history WHERE event_type='EVIDENCE_ADDED'");
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->tasks.close("security",task,new SecretInvestigationRequests.Close(1L,null,null,"unaccepted",null,null,evidence)));
  tasks.acceptEvidence("security",task,new SecretInvestigationRequests.AcceptEvidence(evidence,1L,"owner-accept"));
  long accepted=one("SELECT history_id FROM secret_investigation_history WHERE event_type='EVIDENCE_ACCEPTED'");
  tasks.close("security",task,new SecretInvestigationRequests.Close(2L,null,null,"owner-close",null,null,accepted));
  assertThat(tasks.detail("security",task).get("status")).isEqualTo("CLOSED");
  assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,f.occurrence)).isEqualTo("UNKNOWN");
 }
 @Test void staleAndForeignHandoffInputsCannotCreateOrCloseTasks(){
  var f=fixture("CONFIRMED",true);long version=jdbc.queryForObject("SELECT exposure_assessment_version FROM secret_occurrences WHERE occurrence_id=?",Long.class,f.occurrence);
  assertCode(ErrorCode.CONFLICT,()->tasks.request("security",new SecretInvestigationRequests.Request("OCCURRENCE",f.occurrence,"OWNER_UNKNOWN",null,null,null,version+1,"stale-target")));
  assertThat(count("secret_investigation_tasks")).isZero();
  assertCode(ErrorCode.INVALID_INPUT,()->tasks.request("security",new SecretInvestigationRequests.Request("OCCURRENCE",f.occurrence,"OWNER_UNKNOWN",null,null,"https://example.invalid/raw",version,"bad-ref")));
 }
 @Test void providerProofPromotesTheExistingAlertAndAcknowledgementCannotCloseIt(){
  var f=fixture("CONFIRMED",true);reconcile(f.run);long alert=one("SELECT alert_id FROM secret_cross_environment_alerts");
  realProof(f);reconcile(f.run);assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);
  assertThat(alerts.detail("security",alert).get("status")).isEqualTo("CONFIRMED_REAL");
  long version=(Long)alerts.detail("security",alert).get("version");alerts.acknowledge("security",alert,new SecretCrossEnvironmentAlertRequests.Acknowledge("EVIDENCE_REVIEWED",version,"ack-once"));
  assertThat(alerts.detail("security",alert).get("status")).isEqualTo("CONFIRMED_REAL");
  assertThat(jdbc.queryForObject("SELECT closed_at FROM secret_cross_environment_alerts",OffsetDateTime.class)).isNull();
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->alerts.close("security",alert,new SecretCrossEnvironmentAlertRequests.Close(version+1,"CREDENTIAL_RETIRED",List.of(),List.of(),List.of(),null,one("SELECT task_id FROM secret_investigation_tasks"),"no-retirement")));
 }
 @Test void matchingProtectedWorkerEvidenceIsRequiredAndAttestationIsIdempotent(){
  var f=fixture("CONFIRMED",true);reconcile(f.run);
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,999L,1L,999L,"fake-match")));
  long manifest=manifest(f,false),match=match(f,manifest,"MATCH");
  var request=new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"attest-once");var first=fixtures.attest("security",f.key,request);var replay=fixtures.attest("security",f.key,request);
  assertThat(first).isEqualTo(replay);assertThat(count("secret_test_fixture_attestations")).isEqualTo(1);
  assertThat(fixtures.list("security",f.key).get("fixtureStatus")).isEqualTo("VERIFIED_SYNTHETIC");
  String output=fixtures.list("security",f.key).toString();assertThat(output).doesNotContain("protected_fingerprint","protected_manifest_ref","protected-match","private-repo");
  assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_audit_events WHERE event_type='FIXTURE_ATTESTED'",Long.class)).isEqualTo(1);
 }
 @Test void suffixLikeIdentityAndRevokedOrChangedScopeCannotEstablishSyntheticStatus(){
  var f=fixture("CONFIRMED",true);long manifest=manifest(f,false),match=match(f,manifest,"NO_MATCH");
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"suffix-not-proof")));
  assertThat(fixtures.list("security",f.key).get("fixtureStatus")).isEqualTo("POSSIBLE_REAL");
  jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",f.scope);
  assertCode(ErrorCode.CONFLICT,()->fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"stale-scope")));
 }
 @Test void approvedManifestIsImmutableAndRevocationInvalidatesExistingAttestation(){
  var f=fixture("CONFIRMED",true);long manifest=manifest(f,false),match=match(f,manifest,"MATCH");fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"prove"));
  assertThatThrownBy(()->jdbc.update("UPDATE secret_fixture_manifest_identities SET protected_fingerprint=? WHERE manifest_id=?",new byte[32],manifest)).isInstanceOf(org.springframework.dao.DataAccessException.class);
  jdbc.update("UPDATE secret_fixture_manifests SET approval_status='REVOKED',revoked_at=now() WHERE manifest_id=?",manifest);
  assertThat(fixtures.list("security",f.key).get("fixtureStatus")).isEqualTo("POSSIBLE_REAL");
  assertThat(((Map<?,?>)items(fixtures.list("security",f.key)).getFirst()).get("isCurrentlyValid")).isEqualTo(false);
 }
 @Test void fixtureProofClosesOnlyAlertAndNewSuspicionLinksAPreviousAlert(){
  var f=fixture("CONFIRMED",true);reconcile(f.run);long alert=one("SELECT alert_id FROM secret_cross_environment_alerts"),task=one("SELECT task_id FROM secret_investigation_tasks");
  long manifest=manifest(f,false),match=match(f,manifest,"MATCH");long attestation=(Long)fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"attest-close")).get("attestationId");
  alerts.close("security",alert,new SecretCrossEnvironmentAlertRequests.Close(0L,"VERIFIED_SYNTHETIC",List.of(attestation),List.of(),List.of(),null,task,"close-alert"));
  assertThat(tasks.detail("security",task).get("status")).isEqualTo("OPEN");reconcile(f.run);assertThat(count("secret_cross_environment_alerts")).isEqualTo(1);
  jdbc.update("UPDATE secret_fixture_manifests SET approval_status='REVOKED',revoked_at=now() WHERE manifest_id=?",manifest);reconcile(f.run);
  assertThat(count("secret_cross_environment_alerts")).isEqualTo(2);assertThat(jdbc.queryForObject("SELECT previous_alert_id FROM secret_cross_environment_alerts WHERE closed_at IS NULL",Long.class)).isEqualTo(alert);
 }
 @Test void realIssuerProofOverridesAnEarlierSyntheticAttestation(){
  var f=fixture("CONFIRMED",true);long manifest=manifest(f,false),match=match(f,manifest,"MATCH");fixtures.attest("security",f.key,new SecretFixtureService.Attest(f.scope,1L,manifest,1L,match,"before-real"));
  realProof(f);reconcile(f.run);assertThat(fixtures.list("security",f.key).get("fixtureStatus")).isEqualTo("CONFIRMED_REAL");
  assertThat(one("SELECT count(*) FROM secret_current_fixture_attestations")).isZero();assertThat(alerts.detail("security",one("SELECT alert_id FROM secret_cross_environment_alerts")).get("status")).isEqualTo("CONFIRMED_REAL");
 }
 @Test void humanMoreInfoNeedsAnEligibleOwnerAndDueDateAndEvidenceAloneCannotResolve(){
  var f=fixture("CONFIRMED",true);long task=new TransactionTemplate(tx).execute(s->tasks.createHumanTaskTx(new SecretPrincipal(1),f.occurrence,"POLICY_UNKNOWN",1,OffsetDateTime.now().plusDays(1),"TICKET:SEC-123"));
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->tasks.assign("security",task,new SecretInvestigationRequests.Assignment(null,null,"UNASSIGNED",0L,"clear-human")));
  var evidence=new SecretInvestigationRequests.Evidence("POLICY:SECRET-12","POLICY_REFERENCE",OffsetDateTime.now(),0L,"evidence-once");tasks.evidence("security",task,evidence);tasks.evidence("security",task,evidence);
  assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_investigation_history WHERE event_type='EVIDENCE_ADDED'",Long.class)).isEqualTo(1);
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->tasks.close("security",task,new SecretInvestigationRequests.Close(1L,999L,null,"no-decision")));
  assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,f.occurrence)).isEqualTo("UNKNOWN");
  assertCode(ErrorCode.INVALID_INPUT,()->tasks.evidence("security",task,new SecretInvestigationRequests.Evidence("https://example.com/raw-secret","OWNER_CONFIRMATION",OffsetDateTime.now(),1L,"bad-ref")));
 }
 @Test void scopeRestorationTaskRequiresANewSuccessfulSameRevisionFullScope(){
  var f=fixture("CONFIRMED",true);long task=jdbc.queryForObject("INSERT INTO secret_investigation_tasks(target_type,scope_id,missing_reason_code,creation_source) VALUES('SCOPE',?,'SOURCE_PERMISSION','SCOPE_RESTORE') RETURNING task_id",Long.class,f.scope);
  long oldScope=one("SELECT run_scope_id FROM secret_run_scopes WHERE run_id="+f.run);
  assertCode(ErrorCode.EVIDENCE_REQUIRED,()->tasks.close("security",task,new SecretInvestigationRequests.Close(0L,null,oldScope,"old-scope-proof")));
  var restored=repeatRun(f);
  tasks.close("security",task,new SecretInvestigationRequests.Close(0L,null,restored.runScope,"restored-scope"));assertThat(tasks.detail("security",task).get("status")).isEqualTo("CLOSED");
 }
 @Test void automaticFollowUpCanHaveADueDateWithoutInventingAnOwner(){
  var f=fixture("CONFIRMED",true);reconcile(f.run);long task=one("SELECT task_id FROM secret_investigation_tasks");
  tasks.assign("security",task,new SecretInvestigationRequests.Assignment(null,OffsetDateTime.now().plusDays(1),"DUE_DATE_CHANGE",0L,"due-without-owner"));
  var detail=tasks.detail("security",task);assertThat(detail.get("assigneeUserId")).isNull();assertThat(detail.get("dueAt")).isNotNull();
  long alert=one("SELECT alert_id FROM secret_cross_environment_alerts");
  alerts.assign("security",alert,new SecretCrossEnvironmentAlertRequests.Assignment(null,OffsetDateTime.now().plusDays(1),"DUE_DATE_CHANGE",0L,"alert-due-only"));
  assertThat(alerts.detail("security",alert).get("assigneeUserId")).isNull();
 }
 @Test void scopedSecurityCannotSeeOtherLocationsOrManageTheirSharedAlert(){
  var first=fixture("CONFIRMED",true);reconcile(first.run);var second=fixtureForKey(first.key,true);
  reconcile(second.run);long alert=one("SELECT alert_id FROM secret_cross_environment_alerts");jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(2,'SECURITY',?,1,'MANUAL')",first.connection);
  var detail=alerts.detail("scoped",alert);assertThat((List<?>)detail.get("locations")).hasSize(1);assertThat(detail.get("restrictedCoverage")).isEqualTo(true);
  assertThat(((Map<?,?>)detail.get("capabilities")).get("canAssign")).isEqualTo(false);
  assertCode(ErrorCode.FORBIDDEN,()->alerts.acknowledge("scoped",alert,new SecretCrossEnvironmentAlertRequests.Acknowledge("OWNER_NOTIFIED",0L,"partial-ack")));
  assertCode(ErrorCode.NOT_FOUND,()->fixtures.list("operations",first.key));
 }

 record Fixture(long connection,long scope,long key,long occurrence,long run,long runScope){}
 Fixture fixture(String state,boolean finding){long key=jdbc.queryForObject("""
  INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,candidate_locator,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
  VALUES('AWS','AWS_ACCESS_KEY_PAIR',?,CASE WHEN ?='CONFIRMED' THEN ?::bytea END,CASE WHEN ?='CANDIDATE' THEN ?::bytea END,
   CASE WHEN ?='METADATA_ONLY' THEN NULL ELSE 'test-v1' END,'AWS ••••1234',now(),now()) RETURNING credential_set_id
  """,Long.class,state,state,identity(),state,identity(),state);return fixtureForKey(key,finding);}
 Fixture fixtureForKey(long key,boolean finding){long c=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','private-repo','protected-ref','ACTIVE',1) RETURNING connection_id",Long.class);
  long s=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at) VALUES(?,gen_random_uuid()::text,1,'GITHUB_REPOSITORY_FILES','github://private-repo/raw-path',true,'TEST',1,now()) RETURNING scope_id",Long.class,c);
  long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',?,clock_timestamp(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class,c);
  long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,?,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',clock_timestamp()) RETURNING run_id",Long.class,job,c);
  long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at,detection_stage_status,validation_stage_status,validation_required) VALUES(?,?,'SUCCEEDED',1,clock_timestamp(),'SUCCEEDED','SKIPPED',false) RETURNING run_scope_id",Long.class,run,s);
  long o=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id) VALUES(?,?,?,'private-repo/raw-path','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now(),?) RETURNING occurrence_id",Long.class,key,c,s,run);
  long tr=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at) VALUES(?,'GITLEAKS','8.30.1','test-hash','SUCCEEDED',1,now()) RETURNING tool_run_id",Long.class,rs);
  if(finding)jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,gen_random_uuid()::text,'aws-access-token','1',clock_timestamp())",o,run,tr);
  return new Fixture(c,s,key,o,run,rs);
 }
 Fixture repeatRun(Fixture f){
  long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',?,clock_timestamp(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class,f.connection);
  long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,?,'MANUAL',1,now(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',clock_timestamp()) RETURNING run_id",Long.class,job,f.connection);
  long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at,detection_stage_status,validation_stage_status,validation_required) VALUES(?,?,'SUCCEEDED',1,clock_timestamp(),'SUCCEEDED','SKIPPED',false) RETURNING run_scope_id",Long.class,run,f.scope);
  long tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at) VALUES(?,'GITLEAKS','8.30.1','test-hash','SUCCEEDED',1,now()) RETURNING tool_run_id",Long.class,rs);
  jdbc.update("UPDATE secret_occurrences SET last_seen_run_id=?,last_seen_at=clock_timestamp() WHERE occurrence_id=?",run,f.occurrence);
  jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,gen_random_uuid()::text,'aws-access-token','1',clock_timestamp())",f.occurrence,run,tool);
  return new Fixture(f.connection,f.scope,f.key,f.occurrence,run,rs);
 }
 long manifest(Fixture f,boolean auto){long m=jdbc.queryForObject("INSERT INTO secret_fixture_manifests(version,protected_manifest_ref,approval_status,valid_from,valid_until,allow_auto_attestation) VALUES(1,'FIXTURE:APPROVED_TEST','DRAFT',now()-interval '1 day',now()+interval '30 days',?) RETURNING manifest_id",Long.class,auto);
  jdbc.update("INSERT INTO secret_fixture_manifest_identities(manifest_id,manifest_version,scope_id,scope_revision,issuer,credential_type,fingerprint_key_version,protected_fingerprint) SELECT ?,1,?,1,issuer,credential_type,fingerprint_key_version,fingerprint FROM secret_credential_sets WHERE credential_set_id=?",m,f.scope,f.key);
  jdbc.update("UPDATE secret_fixture_manifests SET approval_status='APPROVED',approved_by_user_id=1 WHERE manifest_id=?",m);return m;}
 long match(Fixture f,long m,String result){return jdbc.queryForObject("INSERT INTO secret_fixture_match_evidence(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,run_scope_id,comparator_id,comparator_version,match_result,protected_match_ref,observed_at) VALUES(?,?,1,?,1,?,'LOGSSEY_PROTECTED_IDENTITY','1',?,'protected-match:test',now()) RETURNING match_evidence_id",Long.class,f.key,f.scope,m,f.runScope,result);}
 void realProof(Fixture f){jdbc.update("INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code) SELECT ?,?,job_id,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),'VALID','AUTHENTICATED' FROM secret_scan_runs WHERE run_id=?",f.key,f.run,f.run);}
 void reconcile(long run){jdbc.queryForObject("SELECT secret_reconcile_test_alerts(?)",Long.class,run);}
 static byte[] identity(){byte[] bytes=new byte[32];new java.security.SecureRandom().nextBytes(bytes);return bytes;}
 static long count(String table){return one("SELECT count(*) FROM "+table);}static long one(String sql){return jdbc.queryForObject(sql,Long.class);}
 @SuppressWarnings("unchecked") static List<Map<String,Object>> items(Map<String,Object> page){return (List<Map<String,Object>>)page.get("items");}
 static void assertCode(ErrorCode code,Runnable action){assertThatThrownBy(action::run).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.errorCode()).isEqualTo(code));}
}
