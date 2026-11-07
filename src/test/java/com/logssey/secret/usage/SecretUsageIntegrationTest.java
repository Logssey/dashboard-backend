package com.logssey.secret.usage;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.risk.SecretRiskCommands;
import com.logssey.secret.usage.core.SecretUsageContext;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

class SecretUsageIntegrationTest {
    static final com.logssey.secret.testing.SecretTestPostgres DB=new com.logssey.secret.testing.SecretTestPostgres();
    static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
    SecretUsageService service;SecretUsageContext contexts;MockMvc mvc;OffsetDateTime end,start;long history;
    final JsonMapper json=JsonMapper.builder().findAndAddModules().build();
    @BeforeAll static void start(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);Flyway.configure().dataSource(ds).load().migrate();}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void fixture()throws Exception{
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','hash','Security','ADMIN'),('source-only','hash','Source','ADMIN'),('remediator','hash','Remediator','ADMIN')");
        jdbc.update("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Source','fixture-source-private','ACTIVE',1),('AWS','Collector','fixture-collector-private','ACTIVE',1)");
        jdbc.update("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled) VALUES(1,'source',1,'GITHUB_REPOSITORY_FILES','github://Sample/repository/main/src/','CURRENT_COMMIT_ONLY',true),(2,'iam',1,'IAM_ACCESS_KEY_METADATA','aws://123456789012/global/iam/access-keys','CURRENT_STATE_ONLY',true)");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,1,'MANUAL'),(1,'OPERATIONS',2,1,'MANUAL'),(2,'SECURITY',1,1,'MANUAL'),(3,'REMEDIATOR',1,1,'MANUAL')");
        jdbc.update("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,aws_key_id_fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at) VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),'fixture','AWS ••••1234',clock_timestamp(),clock_timestamp())");
        jdbc.update("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,latest_object_version,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(1,1,1,'protected-source','L1','v1','DEV','UNKNOWN','UNKNOWN','PRESENT',clock_timestamp(),clock_timestamp())");
        long task=jdbc.queryForObject("INSERT INTO secret_investigation_tasks(target_type,occurrence_id,missing_reason_code,creation_source,version) VALUES('OCCURRENCE',1,'EVIDENCE_INCOMPLETE','HUMAN_HANDOFF',1) RETURNING task_id",Long.class);
        history=jdbc.queryForObject("INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version) VALUES(?,'EVIDENCE_ADDED',1,'{}','TICKET:SEC-123',1) RETURNING history_id",Long.class,task);
        identityProof();
        registerTarget(1);
        contexts=new SecretUsageContext(jdbc);end=contexts.now().minusSeconds(1);start=end.minusDays(7);
        service=service(true);mvc=MockMvcBuilders.standaloneSetup(new SecretUsageController(service)).setControllerAdvice(new GlobalExceptionHandler()).build();
    }
    private SecretUsageService service(boolean enabled){return new SecretUsageService(jdbc,new SecretAccessService(jdbc),new SecretRiskCommands(jdbc,tm),enabled);}
    private void registerTarget(long approver)throws Exception{
        String sql=Files.readString(Path.of("deploy/register-usage-target.sql")).replace(":'occurrence_id'","'1'").replace(":'collector_scope_id'","'2'").replace(":'approved_user_id'","'"+approver+"'").replace(":'region'","'ap-northeast-2'");
        jdbc.execute(sql);
    }
    @Test void operatorTemplateRegistersApprovedManualTargetWithRecurringDisabledAndRejectsMissingCollectorGrant()throws Exception{
        assertThat(jdbc.queryForMap("SELECT enabled,schedule_enabled,account_ref,region FROM secret_usage_targets")).containsEntry("enabled",true).containsEntry("schedule_enabled",false).containsEntry("region","ap-northeast-2");
        long before=jdbc.queryForObject("SELECT revision FROM secret_usage_targets",Long.class);registerTarget(2);
        assertThat(jdbc.queryForObject("SELECT revision FROM secret_usage_targets",Long.class)).isEqualTo(before);
        var model=service.read("security",1,1,1,20);
        assertThat(model.get("targetOptions").toString()).contains("…9012").doesNotContain("123456789012","fixture-collector-private","aws://");
        assertThat(model.toString()).doesNotContain("fixture-source-private","protected-source","fingerprint");
        assertThat(service.read("source-only",1,1,1,20).get("targetOptions")).isEqualTo(List.of());
    }
    @Test void disabledUnsupportedAndNoRequestAreDistinctAndNeverCreateJob(){
        var disabled=service(false).read("security",1,1,1,20);assertThat(disabled.get("observationStatus")).isEqualTo("NOT_REQUESTED");
        assertThat(disabled.get("capabilities").toString()).contains("USAGE_COLLECTION_DISABLED","canRequest=false");
        assertThatThrownBy(()->service(false).request("security",1,request("disabled"))).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_credential_sets SET issuer='NOTION',credential_type='NOTION_INTEGRATION_TOKEN',aws_key_id_fingerprint=NULL WHERE credential_set_id=1");
        assertThat(service.read("security",1,1,1,20).get("support").toString()).contains("UNSUPPORTED","PROVIDER_USAGE_UNSUPPORTED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_requests",Long.class)).isZero();
    }
    @Test void requestIsAtomicIdempotentPurposeScopedAndReturnsLiveStatusWithoutScanRun(){
        String policy=policy();var first=service.request("security",1,request("same"));var again=service.request("security",1,request("same"));
        assertThat(again.get("requestId")).isEqualTo(first.get("requestId"));assertThat(first).containsEntry("status","PENDING").containsEntry("credentialId",1L).containsEntry("occurrenceId",1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE purpose='USAGE_OBSERVATION'",Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs r JOIN secret_jobs j USING(job_id) WHERE j.purpose='USAGE_OBSERVATION'",Long.class)).isZero();
        assertThatThrownBy(()->service.request("security",1,new SecretUsageContracts.Request(1L,1L,start.plusHours(1),end,1L,1L,"same"))).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.errorCode()).isEqualTo(ErrorCode.CONFLICT));
        complete(number(first,"requestId"),"COMPLETE","NOT_OBSERVED_IN_SCOPE",0);
        assertThat(service.request("security",1,request("same"))).containsEntry("status","COMPLETE").containsEntry("observationStatus","NOT_OBSERVED_IN_SCOPE").containsEntry("eventCount",0);
        assertThat(policy()).isEqualTo(policy);assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence",Long.class)).isZero();
    }
    @Test void sourceAndCollectorRevisionOrAccessRevocationInvalidateReplayAndHideProviderFacts(){
        var request=service.request("security",1,request("revocation"));long id=number(request,"requestId");provider(id,UUID.randomUUID(),end.minusMinutes(2));complete(id,"PARTIAL","OBSERVED",1);
        assertThat(items(service.read("security",1,1,1,20))).hasSize(1);
        assertThat(items(service.read("source-only",1,1,1,20))).isEmpty();
        assertThatThrownBy(()->service.status("source-only",id)).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=2");
        assertThat(items(service.read("security",1,1,1,20))).isEmpty();assertThat(service.status("security",id)).containsEntry("currentApplicable",false).containsEntry("observationStatus","UNAVAILABLE");
        assertThatThrownBy(()->service.request("security",1,request("revocation"))).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE user_id=1 AND connection_id=2");
        assertThatThrownBy(()->service.status("security",id)).isInstanceOf(ApiException.class);
    }
    @Test void paginationKeepsDeduplicatedOldProviderEventsVisibleOnRepeatedRequest(){
        long first=number(service.request("security",1,request("first")),"requestId");UUID event=UUID.randomUUID();provider(first,event,end.minusHours(1));provider(first,UUID.randomUUID(),end.minusHours(2));complete(first,"COMPLETE","OBSERVED",2);
        long second=number(service.request("security",1,request("second")),"requestId");provider(second,event,end.minusHours(1));complete(second,"COMPLETE","OBSERVED",1);
        var model=service.read("security",1,1,1,1);assertThat(items(model)).hasSize(1);assertThat(((Map<?,?>)model.get("observations")).get("totalElements")).isEqualTo(2L);
        assertThat(items(service.read("security",1,1,2,1))).hasSize(1);
        assertThat(((Map<?,?>)model.get("latestRequest")).get("requestId")).isEqualTo(second);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isEqualTo(2L);
    }
    @Test void narrowerCurrentWindowExcludesOldEventsWithoutErasingRetainedProvenance(){
        OffsetDateTime recentStart=start;start=end.minusDays(80);
        long wide=number(service.request("security",1,request("wide")),"requestId");provider(wide,UUID.randomUUID(),end.minusDays(30));provider(wide,UUID.randomUUID(),end.minusDays(2));complete(wide,"COMPLETE","OBSERVED",2);
        assertThat(items(service.read("security",1,1,1,20))).hasSize(2);
        start=recentStart;long narrow=number(service.request("security",1,request("narrow")),"requestId");complete(narrow,"COMPLETE","OBSERVED",1);
        var visible=items(service.read("security",1,1,1,20));assertThat(visible).hasSize(1);assertThat(visible.getFirst().toString()).contains("ap-northeast-2","…9012").doesNotContain("123456789012");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isEqualTo(2L);
    }
    @Test void manualFactsRemainManualUnresolvedAndDecisionsAreAppendOnlyCasWithNoRiskMutation(){
        var created=service.submit("security",1,manual("manual"));long id=number(created,"observationId");
        assertThat(created).containsEntry("sourceKind","MANUAL").containsEntry("bindingLevel","PRINCIPAL_ONLY").containsEntry("coverageStatus","UNKNOWN").containsEntry("observationRevision",0L);
        assertThat(service.submit("security",1,manual("manual")).get("observationId")).isEqualTo(id);
        assertThatThrownBy(()->service.decide("security",id,new SecretUsageContracts.Decision("ACCEPT",0L,"IDENTITY_MISMATCH","inconsistent"))).isInstanceOf(ApiException.class);
        assertThatThrownBy(()->jdbc.update("INSERT INTO secret_usage_decisions(observation_id,observation_revision,actor_user_id,decision,reason_code) VALUES(?,1,1,'REJECT','REVIEWED_USAGE')",id)).isInstanceOf(DataAccessException.class);
        var accept=new SecretUsageContracts.Decision("ACCEPT",0L,"REVIEWED_USAGE","accept");var accepted=service.decide("security",id,accept);
        assertThat(accepted).containsEntry("reviewStatus","ACCEPTED").containsEntry("bindingLevel","PRINCIPAL_ONLY").containsEntry("sourceKind","MANUAL");
        assertThat(service.decide("security",id,accept).get("observationRevision")).isEqualTo(1L);
        assertThatThrownBy(()->service.decide("security",id,new SecretUsageContracts.Decision("REJECT",0L,"INSUFFICIENT_EVIDENCE","stale"))).isInstanceOf(ApiException.class);
        var withdrawn=service.decide("security",id,new SecretUsageContracts.Decision("WITHDRAW",1L,"WITHDRAWN_BY_REVIEWER","withdraw"));
        assertThat(withdrawn).containsEntry("reviewStatus","WITHDRAWN");assertThat((List<?>)withdrawn.get("decisionHistory")).hasSize(2);
        assertThatThrownBy(()->jdbc.update("UPDATE secret_usage_observations SET action_result='SUCCESS' WHERE observation_id=?",id)).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(()->jdbc.update("DELETE FROM secret_usage_decisions WHERE observation_id=?",id)).isInstanceOf(DataAccessException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence",Long.class)).isZero();
    }
    @Test void assignedRemediatorCanSubmitButCannotReviewAndLosingAssignmentBlocksReplay(){
        jdbc.update("INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,assigned_user_id) VALUES(1,1,1,'UNAPPROVED_SOURCE_LOCATION','PRODUCTION',3)");
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,assigned_user_id) VALUES(1,1,1,3)");
        jdbc.update("UPDATE secret_investigation_tasks SET requested_by_user_id=3 WHERE task_id=(SELECT task_id FROM secret_investigation_history WHERE history_id=?)",history);
        var created=service.submit("remediator",1,manual("assigned"));long id=number(created,"observationId");assertThat(created.get("allowedDecisions")).isEqualTo(List.of());
        assertThatThrownBy(()->service.decide("remediator",id,new SecretUsageContracts.Decision("ACCEPT",0L,"REVIEWED_USAGE","no-review"))).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_case_occurrences SET assigned_user_id=NULL WHERE occurrence_id=1");
        assertThatThrownBy(()->service.submit("remediator",1,manual("assigned"))).isInstanceOf(ApiException.class);
    }
    @Test void assignedRemediatorCannotSeeOrSubmitScopeInvestigationOrOtherRequestersPrivateHistory(){
        jdbc.update("INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,assigned_user_id) VALUES(1,1,1,'UNAPPROVED_SOURCE_LOCATION','PRODUCTION',3)");
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,assigned_user_id) VALUES(1,1,1,3)");
        long task=jdbc.queryForObject("INSERT INTO secret_investigation_tasks(target_type,scope_id,missing_reason_code,creation_source,version) VALUES('SCOPE',1,'EVIDENCE_INCOMPLETE','HUMAN_HANDOFF',1) RETURNING task_id",Long.class);
        long scopeHistory=jdbc.queryForObject("INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version) VALUES(?,'EVIDENCE_ADDED',1,'{}','TICKET:SEC-999',1) RETURNING history_id",Long.class,task);
        var scopeManual=new SecretUsageContracts.Manual(1L,1L,1L,new SecretUsageContracts.Ref("INVESTIGATION_HISTORY",scopeHistory),new SecretUsageContracts.Ref("APPROVED_SCOPE",1L),start,end,end.minusHours(1),"API_CALL","SUCCESS","UNATTRIBUTED","scope-record");
        service.submit("security",1,scopeManual);service.submit("security",1,manual("another-requester"));
        var hidden=service.read("remediator",1,1,1,20);
        assertThat((List<?>)hidden.get("availableSourceRefs")).isEmpty();assertThat(items(hidden)).isEmpty();
        assertThatThrownBy(()->service.submit("remediator",1,scopeManual)).isInstanceOf(ApiException.class);
        assertThatThrownBy(()->service.submit("remediator",1,manual("another-requester"))).isInstanceOf(ApiException.class);
        assertThat(items(service.read("security",1,1,1,20))).hasSize(2);
    }
    @Test void credentialAndSourceVersionChangesNeverTransferHistoryToNewKey(){
        long id=number(service.request("security",1,request("old-key")),"requestId");provider(id,UUID.randomUUID(),end.minusMinutes(1));complete(id,"COMPLETE","OBSERVED",1);
        jdbc.update("UPDATE secret_credential_sets SET fingerprint=decode(repeat('03',32),'hex') WHERE credential_set_id=1");
        assertThat(jdbc.queryForObject("SELECT aws_key_id_fingerprint IS NULL FROM secret_credential_sets WHERE credential_set_id=1",Boolean.class)).isTrue();
        assertThat(items(service.read("security",1,1,1,20))).isEmpty();assertThat(service.status("security",id)).containsEntry("currentApplicable",false);
        assertThatThrownBy(()->service.request("security",1,request("new-key"))).isInstanceOf(ApiException.class);
    }
    @Test void missingCurrentIdentityRequiresValidationInsteadOfPretendingKeyCollectionWillFixIt(){
        jdbc.update("UPDATE secret_connections SET validation_revision=validation_revision+1 WHERE connection_id=1");
        var model=service.read("security",1,1,1,20);
        assertThat(model.get("keyIdentifierStatus")).isEqualTo("PROTECTED_REFERENCE_AVAILABLE");
        assertThat(model.get("capabilities").toString()).contains("FRESH_IDENTITY_VALIDATION_REQUIRED","canRequest=false");
        assertThatThrownBy(()->service.request("security",1,request("identity-missing"))).isInstanceOf(ApiException.class);
        var manual=service.submit("security",1,manual("unresolved-manual"));assertThat(manual.get("bindingLevel")).isEqualTo("UNRESOLVED");
    }
    @Test void iamLastUsedRemainsSeparateFromEventCoverageAndRequiresCollectorScopeAccess(){
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',2,now(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class);
        long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,2,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED',now()) RETURNING run_id",Long.class,job);
        jdbc.update("INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status) VALUES(?,2,1,'SUCCEEDED')",run);
        jdbc.update("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(1,2,2,'protected-iam','metadata','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())");
        jdbc.update("INSERT INTO secret_aws_access_key_observations(credential_set_id,run_id,key_status,last_used_at,last_used_service,last_used_region,observed_at) VALUES(1,?,'ACTIVE',now()-interval '1 day','ec2','ap-northeast-2',now())",run);
        var allowed=service.read("security",1,1,1,20);assertThat(allowed.get("iamLastUsed")).isNotNull();assertThat(allowed.get("observationStatus")).isEqualTo("NOT_REQUESTED");assertThat(items(allowed)).isEmpty();
        assertThat(service.read("source-only",1,1,1,20).get("iamLastUsed")).isNull();
        jdbc.update("UPDATE secret_connection_scopes SET enabled=false WHERE scope_id=2");assertThat(service.read("security",1,1,1,20).get("iamLastUsed")).isNull();
    }
    @Test void apiRejectsFreeFormTokenLogUrlAndExactBindingClaimsBeforePersistence()throws Exception{
        var body=json.convertValue(manual("http"),Map.class);var unsafe=new LinkedHashMap<String,Object>(body);unsafe.put("bindingLevel","EXACT_CREDENTIAL");
        mvc.perform(post("/api/v1/secrets/1/usage-observations").principal(()->"security").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(unsafe))).andExpect(status().isBadRequest());
        unsafe=new LinkedHashMap<>(body);unsafe.put("sourceRef",Map.of("type","INVESTIGATION_HISTORY","id",history,"url","https://example.invalid/raw"));
        mvc.perform(post("/api/v1/secrets/1/usage-observations").principal(()->"security").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(unsafe))).andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/secrets/1/usage-requests").principal(()->"security").contentType(MediaType.APPLICATION_JSON).content("{\"occurrenceId\":1,\"accessKeyId\":\"not-a-key\"}")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/secrets/1/usage").principal(()->"security").param("occurrenceId","1")).andExpect(status().isOk()).andExpect(jsonPath("observationStatus").value("NOT_REQUESTED"));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isZero();
    }
    @Test void missingFactsCannotBecomeExactOrZeroCompleteThroughDatabaseNullSemantics(){
        var c=contexts.occurrence(1);String version=SecretUsageContext.sourceVersion(c);
        assertThatThrownBy(()->jdbc.update("""
INSERT INTO secret_usage_observations(source_kind,occurrence_id,credential_set_id,credential_revision,scope_revision,submitted_by_user_id,source_context_version,binding_level,coverage_status,action_code,action_result,actor_attribution,event_at,window_start,window_end)
VALUES('MANUAL',1,1,1,1,1,?,'UNRESOLVED','UNKNOWN','API_CALL','UNKNOWN','UNATTRIBUTED',?,?,?)
""",version,end.minusHours(1),start,end)).isInstanceOf(DataAccessException.class);
        long id=number(service.request("security",1,request("not-zero")),"requestId");
        assertThatThrownBy(()->jdbc.update("UPDATE secret_usage_requests SET observation_status='NOT_OBSERVED_IN_SCOPE',coverage_status='PARTIAL' WHERE request_id=?",id)).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(()->jdbc.update("UPDATE secret_usage_requests SET window_start=window_start-interval '1 hour' WHERE request_id=?",id)).isInstanceOf(DataAccessException.class);
    }
    private SecretUsageContracts.Request request(String key){return new SecretUsageContracts.Request(1L,1L,start,end,1L,1L,key);}
    private SecretUsageContracts.Manual manual(String key){return new SecretUsageContracts.Manual(1L,1L,1L,new SecretUsageContracts.Ref("INVESTIGATION_HISTORY",history),new SecretUsageContracts.Ref("APPROVED_SCOPE",1L),start,end,end.minusHours(1),"API_CALL","SUCCESS","UNATTRIBUTED",key);}
    private void complete(long id,String state,String observation,int count){jdbc.update("UPDATE secret_usage_requests SET status=?,observation_status=?,coverage_status=?,binding_level='EXACT_CREDENTIAL',event_count=?,completed_at=clock_timestamp() WHERE request_id=?",state,observation,"PARTIAL".equals(state)?"PARTIAL":"COMPLETE",count,id);jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=clock_timestamp() WHERE job_id=(SELECT job_id FROM secret_usage_requests WHERE request_id=?)",id);}
    private void provider(long request,UUID event,OffsetDateTime eventAt){jdbc.update("""
INSERT INTO secret_usage_observations(source_kind,request_id,occurrence_id,credential_set_id,credential_revision,scope_revision,collector_connection_id,account_ref,region,provider_event_id,source_context_version,binding_level,coverage_status,action_code,operation_code,action_result,actor_attribution,service_code,event_at,window_start,window_end)
SELECT 'PROVIDER',r.request_id,r.occurrence_id,r.credential_set_id,r.credential_revision,r.scope_revision,t.collector_connection_id,t.account_ref,t.region,?,r.source_context_version,'EXACT_CREDENTIAL','COMPLETE','RESOURCE_READ','DescribeInstances','SUCCESS','UNATTRIBUTED','EC2',?,r.window_start,r.window_end FROM secret_usage_requests r JOIN secret_usage_targets t USING(target_id) WHERE r.request_id=? ON CONFLICT DO NOTHING
""",event,eventAt,request);}
    private List<?> items(Map<String,Object> model){return (List<?>)((Map<?,?>)model.get("observations")).get("items");}
    private static long number(Map<String,Object> value,String key){return ((Number)value.get(key)).longValue();}
    private String policy(){return jdbc.queryForObject("SELECT COALESCE(string_agg(policy_version||':'||encode(content_hash,'hex'),',' ORDER BY policy_version),'') FROM secret_severity_policies",String.class);}
    private void identityProof(){
        jdbc.update("UPDATE secret_connections SET validation_enabled=true,validation_profile_version='fixture' WHERE connection_id=1");
        jdbc.update("UPDATE secret_connection_scopes SET validation_approved=true,validation_profile_version='fixture',validation_approved_by_user_id=1,validation_approved_at=clock_timestamp() WHERE scope_id=1");
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',1,clock_timestamp(),clock_timestamp(),1,3,'SUCCEEDED',clock_timestamp()) RETURNING job_id",Long.class);
        long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,1,'MANUAL',1,clock_timestamp(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED',clock_timestamp()) RETURNING run_id",Long.class,job);
        long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status) VALUES(?,1,1,'SUCCEEDED') RETURNING run_scope_id",Long.class,run);
        long tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status) VALUES(?,'GITLEAKS','fixture','fixture','SUCCEEDED') RETURNING tool_run_id",Long.class,rs);
        long finding=jdbc.queryForObject("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(1,?,?,?,'fixture','1',clock_timestamp()) RETURNING finding_id",Long.class,run,tool,UUID.randomUUID().toString());
        long attempt=jdbc.queryForObject("""
INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,request_sent_at,scope_id,occurrence_id,source_finding_id,credential_revision,scope_revision,validation_revision,validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,evidence_version)
VALUES(1,?,?,'FIXTURE_IDENTITY','1','FIXTURE_IDENTITY',now(),now(),now(),'VALID','AUTHENTICATED',now(),1,1,?,1,1,1,1,'fixture',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),?,1,1,gen_random_uuid(),true,1) RETURNING attempt_id
""",Long.class,run,job,finding,UUID.randomUUID().toString());
        jdbc.update("INSERT INTO secret_credential_identities(validation_attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,provider,principal_type,account_ref,principal_ref,principal_id,safe_claims,observed_at,expires_at) VALUES(?,1,1,1,1,'AWS','IAM_USER','123456789012','arn:aws:iam::123456789012:user/fixture','AIDAFIXTURE','{}',now(),now()+interval '6 hours')",attempt);
    }
}
