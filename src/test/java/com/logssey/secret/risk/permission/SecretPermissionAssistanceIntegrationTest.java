package com.logssey.secret.risk.permission;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.logssey.common.error.ApiException;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.permission.core.SecretPermissionContext;
import com.logssey.secret.risk.*;
import com.logssey.secret.risk.core.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

class SecretPermissionAssistanceIntegrationTest {
    @Test void manuallyConfirmedPublicPriorityUsesDatabaseTimeDuringApplicationClockLag(){
        var observed=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);
        evidence.submit("security",occurrence,new SecretRiskEvidenceService.Submission(revision(),"clock-public-source","ACCESS_SCOPE","OCCURRENCE",observed,observed.plusHours(1),"TICKET:SEC-123",Map.of("audienceClass","BROAD","coverageStatus","PARTIAL","publicAccessConfirmed",true,"boundedPrincipalCount",0),List.of(),null,observed.minusMinutes(5),observed.plusMinutes(30)));
        var applicationNow=observed.minusMinutes(2);
        try(var applicationClock=mockStatic(OffsetDateTime.class,CALLS_REAL_METHODS)){
            applicationClock.when(()->OffsetDateTime.now(ZoneOffset.UTC)).thenReturn(applicationNow);
            var risk=new SecretRiskQueryService(jdbc,new SecretAccessService(jdbc)).risk("security",occurrence);
            var experience=(Map<?,?>)risk.get("riskExperience");var priority=(Map<?,?>)experience.get("workPriority");
            assertThat(priority.get("level")).isEqualTo("PRIORITY");
            assertThat(priority.get("targetBasis")).isEqualTo("PRIORITY_SIGNAL_OBSERVED");
            assertThat(priority.get("acknowledgeDueAt")).isNotNull();
            assertThat((OffsetDateTime)experience.get("readAt")).isAfterOrEqualTo(observed);
            assertThat(risk.get("severity")).isNull();
        }
    }
    @Test void futurePublicObservationStillCannotEstablishADeadline(){
        var runScope=jdbc.queryForMap("SELECT rs.run_scope_id,rs.run_id FROM secret_run_scopes rs JOIN secret_validation_attempts a USING(run_id) WHERE a.attempt_id=?",attempt);
        jdbc.update("UPDATE secret_occurrences SET latest_object_version='fixture-blob',last_seen_run_id=? WHERE occurrence_id=?",runScope.get("run_id"),occurrence);
        var future=jdbc.queryForObject("SELECT clock_timestamp()+interval '2 minutes'",OffsetDateTime.class);
        new SecretRiskObservationWriter(jdbc).githubRepositoryAccess(occurrence,((Number)runScope.get("run_scope_id")).longValue(),true,true,future);
        var risk=new SecretRiskQueryService(jdbc,new SecretAccessService(jdbc)).risk("security",occurrence);
        var priority=(Map<?,?>)((Map<?,?>)risk.get("riskExperience")).get("workPriority");
        assertThat(priority.get("level")).isEqualTo("PRIORITY");
        assertThat(priority.get("targetBasis")).isEqualTo("UNCONFIRMED");
        assertThat(priority.get("targetBasisAt")).isNull();
        assertThat(priority.get("acknowledgeDueAt")).isNull();
        assertThat(risk.get("severity")).isNull();
    }
    @Test void databaseObservedPrioritySurvivesApplicationClockLag(){
        var runScope=jdbc.queryForMap("SELECT rs.run_scope_id,rs.run_id FROM secret_run_scopes rs JOIN secret_validation_attempts a USING(run_id) WHERE a.attempt_id=?",attempt);
        jdbc.update("UPDATE secret_occurrences SET latest_object_version='fixture-blob',last_seen_run_id=? WHERE occurrence_id=?",runScope.get("run_id"),occurrence);
        var dbObserved=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);
        new SecretRiskObservationWriter(jdbc).githubRepositoryAccess(occurrence,((Number)runScope.get("run_scope_id")).longValue(),true,true,dbObserved);
        var applicationNow=dbObserved.minusMinutes(2);
        try(var applicationClock=mockStatic(OffsetDateTime.class,CALLS_REAL_METHODS)){
            applicationClock.when(()->OffsetDateTime.now(ZoneOffset.UTC)).thenReturn(applicationNow);
            var query=new SecretRiskQueryService(jdbc,new SecretAccessService(jdbc));
            var risk=query.risk("security",occurrence);var experience=(Map<?,?>)risk.get("riskExperience");
            var priority=(Map<?,?>)experience.get("workPriority");
            assertThat(priority.get("level")).isEqualTo("PRIORITY");
            assertThat(priority.get("targetBasis")).describedAs("DB=%s; app=%s; read=%s",priorityTiming(),applicationNow,experience.get("readAt"))
                    .isEqualTo("PRIORITY_SIGNAL_OBSERVED");
            assertThat(priority.get("acknowledgeDueAt")).isNotNull();
            assertThat((OffsetDateTime)experience.get("readAt")).isAfterOrEqualTo(dbObserved);
            var again=(Map<?,?>)((Map<?,?>)query.risk("security",occurrence).get("riskExperience")).get("workPriority");
            assertThat(again.get("targetBasisAt")).isEqualTo(priority.get("targetBasisAt"));
            assertThat(again.get("acknowledgeDueAt")).isEqualTo(priority.get("acknowledgeDueAt"));
            assertThat(risk.get("severity")).isNull();
        }
    }
    @Test void publicMetadataIsOnlyAPrioritySignalAndRepeatedScansDoNotPostponeItsDeadline(){
        var runScope=jdbc.queryForMap("SELECT rs.run_scope_id,rs.run_id FROM secret_run_scopes rs JOIN secret_validation_attempts a USING(run_id) WHERE a.attempt_id=?",attempt);
        jdbc.update("UPDATE secret_occurrences SET latest_object_version='fixture-blob',last_seen_run_id=? WHERE occurrence_id=?",runScope.get("run_id"),occurrence);
        var writer=new SecretRiskObservationWriter(jdbc);
        writer.githubRepositoryAccess(occurrence,((Number)runScope.get("run_scope_id")).longValue(),true,true,databaseNow());
        var query=new SecretRiskQueryService(jdbc,new SecretAccessService(jdbc));
        var risk=query.risk("security",occurrence);var experience=(Map<?,?>)risk.get("riskExperience");
        var priority=(Map<?,?>)experience.get("workPriority");
        assertThat(priority.get("level")).isEqualTo("PRIORITY");
        assertThat(priority.get("targetBasis")).describedAs("Priority timing: %s; readAt=%s", priorityTiming(), experience.get("readAt")).isEqualTo("PRIORITY_SIGNAL_OBSERVED");
        assertThat(priority.get("acknowledgeDueAt")).isNotNull();
        var access=(Map<?,?>)((Map<?,?>)risk.get("analysisContext")).get("access");
        assertThat(access.get("range")).isEqualTo("UNKNOWN");
        assertThat(access.get("repositoryPublicObserved")).isEqualTo(true);
        assertThat(access.get("coexistenceStatus")).isEqualTo("UNCONFIRMED");
        assertThat(risk.get("severity")).isNull();
        long next=identityProof();
        var nextScope=jdbc.queryForMap("SELECT rs.run_scope_id,rs.run_id FROM secret_run_scopes rs JOIN secret_validation_attempts a USING(run_id) WHERE a.attempt_id=?",next);
        jdbc.update("UPDATE secret_occurrences SET last_seen_at=clock_timestamp(),last_seen_run_id=? WHERE occurrence_id=?",nextScope.get("run_id"),occurrence);
        writer.githubRepositoryAccess(occurrence,((Number)nextScope.get("run_scope_id")).longValue(),true,true,databaseNow());
        var again=(Map<?,?>)((Map<?,?>)query.risk("security",occurrence).get("riskExperience")).get("workPriority");
        assertThat(again.get("targetBasisAt")).isEqualTo(priority.get("targetBasisAt"));
        assertThat(again.get("acknowledgeDueAt")).isEqualTo(priority.get("acknowledgeDueAt"));
    }
    @Test void publicAuthenticationSignalHasAStableDeadlineWithoutInventingSeverity(){
        var at=databaseNow();
        evidence.submit("security",occurrence,new SecretRiskEvidenceService.Submission(revision(),"public-source","ACCESS_SCOPE","OCCURRENCE",at,at.plusHours(1),"TICKET:SEC-123",Map.of("audienceClass","BROAD","coverageStatus","PARTIAL","publicAccessConfirmed",true,"boundedPrincipalCount",0),List.of(),null,at.minusMinutes(5),at.plusMinutes(30)));
        var query=new SecretRiskQueryService(jdbc,new SecretAccessService(jdbc));
        var risk=query.risk("security",occurrence);
        var experience=(Map<?,?>)risk.get("riskExperience");var priority=(Map<?,?>)experience.get("workPriority");
        assertThat(priority.get("level")).isEqualTo("PRIORITY");
        assertThat(priority.get("targetBasis")).describedAs("Priority timing: %s; readAt=%s", priorityTiming(), experience.get("readAt")).isEqualTo("PRIORITY_SIGNAL_OBSERVED");
        assertThat(priority.get("acknowledgeDueAt")).isNotNull();
        assertThat(risk.get("severity")).isNull();
        var again=(Map<?,?>)((Map<?,?>)query.risk("security",occurrence).get("riskExperience")).get("workPriority");
        assertThat(again.get("targetBasisAt")).isEqualTo(priority.get("targetBasisAt"));
        assertThat(again.get("acknowledgeDueAt")).isEqualTo(priority.get("acknowledgeDueAt"));
    }
    static final com.logssey.secret.testing.SecretTestPostgres DB=new com.logssey.secret.testing.SecretTestPostgres();
    static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
    SecretPermissionAssistanceService service;SecretRiskEvidenceService evidence;long occurrence,attempt;
    @BeforeAll static void start(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);Flyway.configure().dataSource(ds).load().migrate();}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void fixture()throws Exception{
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','hash','Security','ADMIN'),('outsider','hash','Outsider','ADMIN')");
        jdbc.update("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version,validation_enabled,validation_profile_version) VALUES('GITHUB','Approved repository','fixture-app','ACTIVE',1,true,'fixture')");
        jdbc.update("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at,validation_approved,validation_profile_version,validation_approved_by_user_id,validation_approved_at) VALUES(1,'source',1,'GITHUB_REPOSITORY_FILES','github://Sample/repository/main/src/',true,'PRODUCTION',1,now(),true,'fixture',1,now())");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,1,'MANUAL')");
        jdbc.update("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at) VALUES('GITHUB','GITHUB_CLASSIC_PAT','CONFIRMED',decode(repeat('01',32),'hex'),'fixture','GitHub ••••1234',now(),now())");
        occurrence=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(1,1,1,'protected','L1','DEV','ABNORMAL','BOUNDED','PRESENT',now(),now()) RETURNING occurrence_id",Long.class);
        String migration=Files.readString(Path.of("src/main/resources/db/migration/V27__secret_severity_assessment.sql"));jdbc.execute(migration.substring(migration.indexOf("INSERT INTO secret_severity_policies"),migration.indexOf("CREATE TABLE secret_severity_assessments")).replace("'severity-v2','ACTIVE'","'severity-v2','DRAFT'"));jdbc.update("UPDATE secret_severity_policies SET state='ACTIVE' WHERE policy_version='severity-v2'");
        var access=new SecretAccessService(jdbc);var commands=new SecretRiskCommands(jdbc,tm);evidence=new SecretRiskEvidenceService(jdbc,access,commands);service=new SecretPermissionAssistanceService(jdbc,access,commands,evidence,true);
        attempt=identityProof();
        jdbc.update("INSERT INTO secret_credential_identities(validation_attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,provider,principal_type,principal_ref,principal_id,safe_claims,observed_at,expires_at) VALUES(?,?,1,1,1,'GITHUB','GITHUB_USER','github-user:123','123','{\"tokenKind\":\"CLASSIC\",\"scopes\":[\"repo\"],\"scopesComplete\":true}',now(),now()+interval '6 hours')",attempt,occurrence);
    }
    @Test void requestIsLeasedJobOnlyAndCandidateCannotChangeSeverityOrBypassHumanProof(){
        String policy=policy();var c=service.context("security",occurrence);var request=new SecretPermissionAssistanceService.Request((String)c.get("contextVersion"),"same-request",1L);
        var first=service.request("security",occurrence,request);var again=service.request("security",occurrence,request);
        assertThat(((Number)again.get("requestId")).longValue()).isEqualTo(((Number)first.get("requestId")).longValue());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE kind='ENRICH'",Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs r JOIN secret_jobs j USING(job_id) WHERE j.kind='ENRICH'",Long.class)).isZero();
        long observation=publish(first,List.of("RESOURCE_ADMINISTRATION"));var preview=service.preview("security",occurrence,observation);
        assertThat(preview).containsEntry("canConfirm",false);
        assertThat(preview.get("blockedReasonCodes").toString()).contains("ASSET_CLASSIFICATION_REQUIRED","PERMISSION_ASSERTION_REQUIRED","RESTRICTION_PROOF_REQUIRED");
        assertThatThrownBy(()->service.confirm("security",occurrence,observation,confirm(preview,List.of(),"unsafe-checkbox"))).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence WHERE kind='PERMISSION_MAPPING'",Long.class)).isZero();
        assertThat(policy()).isEqualTo(policy);
        assertThat(service.context("security",occurrence).toString()).doesNotContain("github-user:123","fixture-app","protected");
    }
    @Test void partialObservationSavesADraftAndRemainsAvailableForSupplementation() {
        var context=service.context("security",occurrence);
        var request=service.request("security",occurrence,new SecretPermissionAssistanceService.Request(
                context.get("contextVersion").toString(),"partial-request",1L));
        long observation=publish(request,List.of());
        var preview=service.preview("security",occurrence,observation);
        assertThat(preview).containsEntry("canSavePartial",true).containsEntry("canConfirm",false);
        var body=new SecretPermissionAssistanceService.Confirm(preview.get("contextVersion").toString(),
                ((Number)preview.get("evidenceRevision")).longValue(),"partial-save",true,null,null,null,
                Map.of("capability","UNKNOWN","targetScope","UNKNOWN","permissionCoverage","PARTIAL",
                        "targetCoverage","UNKNOWN","restrictionCoverage","UNKNOWN","classificationCoverage","UNKNOWN"),
                List.of(),null,null,true);
        var saved=service.confirm("security",occurrence,observation,body);
        assertThat(saved).containsEntry("status","SAVED_PARTIAL").containsEntry("referenceSource","INTERNAL");
        assertThat(jdbc.queryForObject("SELECT verification_level FROM secret_risk_evidence WHERE evidence_id=?",String.class,
                saved.get("evidenceId"))).isEqualTo("MANUAL_SUBMITTED");
        assertThat(service.confirm("security",occurrence,observation,body)).containsEntry("evidenceId",saved.get("evidenceId"));
        var reopened=service.preview("security",occurrence,observation);
        assertThat(reopened).containsEntry("canSavePartial",true);
        var draft=(Map<String,Object>)reopened.get("latestDraft");
        assertThat(draft).containsEntry("canRestore",true).containsEntry("evidenceRevision",saved.get("evidenceRevision"));
        assertThat(draft.get("facts")).isEqualTo(body.facts());
        jdbc.update("UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE occurrence_id=?",occurrence);
        draft=(Map<String,Object>)service.preview("security",occurrence,observation).get("latestDraft");
        assertThat(draft).containsEntry("canRestore",false).containsEntry("reasonCode","EVIDENCE_REVISION_CHANGED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_permission_decisions WHERE decision='DRAFTED'",Long.class)).isEqualTo(1L);
    }

    @Test void realManualSupplementAfterObservationCanConfirmWithoutBackdatingAndReplaysAreAclBound(){
        jdbc.update("INSERT INTO secret_exposure_assessments(occurrence_id,from_status,decision,reason_code,scope_origin,scope_revision,decision_source,evidence_refs,actor_user_id,version) VALUES(?,'UNKNOWN','ABNORMAL','UNAPPROVED_SOURCE_LOCATION','PRODUCTION',1,'HUMAN','[]',1,1)",occurrence);
        var accessAt=databaseNow();evidence.submit("security",occurrence,new SecretRiskEvidenceService.Submission(revision(),"access-range","ACCESS_SCOPE","OCCURRENCE",accessAt,accessAt.plusHours(1),"TICKET:SEC-123",Map.of("audienceClass","BOUNDED","coverageStatus","COMPLETE","publicAccessConfirmed",false,"boundedPrincipalCount",2),List.of(),null,accessAt.minusMinutes(5),accessAt.plusHours(1)));
        var context=service.context("security",occurrence);var request=service.request("security",occurrence,new SecretPermissionAssistanceService.Request((String)context.get("contextVersion"),"request",1L));
        long observation=publish(request,List.of("RESOURCE_ADMINISTRATION"));String before=policy();
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'SECURITY',NULL,1,'MANUAL')");
        long asset=jdbc.queryForObject("INSERT INTO assets(name,provider,asset_type,environment) VALUES('Permission fixture','GITHUB','REPOSITORY','DEV') RETURNING asset_id",Long.class);
        var now=databaseNow();
        long classification=((Number)evidence.submit("security",occurrence,new SecretRiskEvidenceService.Submission(revision(),"classification","ASSET_CLASSIFICATION","OCCURRENCE",now,now.plusHours(1),"TICKET:SEC-123",Map.of("environment","DEV","sensitive",false,"important",false,"testOnly",false),List.of(),asset,now.minusMinutes(5),now.plusHours(1))).get("evidenceId")).longValue();
        long history=providerReference();var refs=List.of(new SecretRiskProvenance.Ref("VALIDATION_ATTEMPT",attempt,1,"BINDS_IDENTITY"),new SecretRiskProvenance.Ref("RISK_EVIDENCE",classification,1,"CLASSIFIES"),new SecretRiskProvenance.Ref("INVESTIGATION_HISTORY",history,2,"ASSERTS"),new SecretRiskProvenance.Ref("INVESTIGATION_HISTORY",history,2,"LIMITS"));
        var preview=service.preview("security",occurrence,observation);assertThat(preview).containsEntry("canConfirm",true);
        var body=confirm(preview,refs,"confirm");var accepted=service.confirm("security",occurrence,observation,body);assertThat(accepted).containsEntry("status","CONFIRMED");
        assertThat(service.confirm("security",occurrence,observation,body)).containsEntry("status","CONFIRMED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence WHERE kind='PERMISSION_MAPPING' AND source_kind='MANUAL' AND verification_level='MANUAL_ACCEPTED' AND mapping_version='manual-evidence-v1'",Long.class)).isEqualTo(1L);
        new TransactionTemplate(tm).executeWithoutResult(status->{long job=jdbc.queryForObject("SELECT secret_queue_assessment(?)",Long.class,occurrence);new SecretRiskAssessmentStore(jdbc).assess(occurrence,revision(),job);});
        assertThat(jdbc.queryForMap("SELECT matched_rule_id,severity FROM secret_severity_assessments WHERE record_kind='AUTO_RESULT' ORDER BY assessment_id DESC LIMIT 1")).containsEntry("matched_rule_id","R03").containsEntry("severity","HIGH");
        assertThat(policy()).isEqualTo(before);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=1");
        assertThatThrownBy(()->service.confirm("security",occurrence,observation,body)).isInstanceOf(ApiException.class);
    }
    @Test void sourceRevisionAndCollectorRevocationInvalidateObservationAndNoCapabilityCannotBeAttested(){
        var c=service.context("security",occurrence);var request=service.request("security",occurrence,new SecretPermissionAssistanceService.Request((String)c.get("contextVersion"),"request",1L));
        long observation=publish(request,List.of());var preview=service.preview("security",occurrence,observation);
        assertThat(preview.get("blockedReasonCodes").toString()).contains("NO_SUPPORTED_CAPABILITY");
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=1");
        var stale=service.preview("security",occurrence,observation);assertThat(stale).containsEntry("canConfirm",false);assertThat(stale.get("blockedReasonCodes").toString()).contains("CONTEXT_CHANGED","FRESH_IDENTITY_VALIDATION_REQUIRED");
        assertThatThrownBy(()->service.status("outsider",occurrence,((Number)request.get("requestId")).longValue())).isInstanceOf(ApiException.class);
    }
    @Test void staleIdentityShowsValidationBeforeCollectorSetupAndCannotEnqueue(){
        String before=policy();
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=1");
        var context=service.context("security",occurrence);
        assertThat(context.get("capabilities").toString()).contains("FRESH_IDENTITY_VALIDATION_REQUIRED")
                .doesNotContain("APPROVED_COLLECTOR_REQUIRED");
        assertThat(context.get("requestReadiness").toString()).contains("VALIDATE_CREDENTIAL", "WAITING");
        assertThatThrownBy(()->service.request("security",occurrence,
                new SecretPermissionAssistanceService.Request((String)context.get("contextVersion"),"stale-identity",1L)))
                .isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_permission_requests",Long.class)).isZero();
        assertThat(policy()).isEqualTo(before);
        assertThat(context.toString()).doesNotContain("github-user:123","fixture-app","protected");
    }
    private Map<String,Object> priorityTiming(){return jdbc.queryForMap("""
SELECT clock_timestamp() AS db_now,
 (SELECT first_seen_at FROM secret_occurrences WHERE occurrence_id=?) AS first_seen_at,
 (SELECT count(*) FROM secret_current_risk_evidence WHERE occurrence_id=? AND kind='ACCESS_SCOPE') AS public_rows,
 (SELECT max(observed_at) FROM secret_current_risk_evidence WHERE occurrence_id=? AND kind='ACCESS_SCOPE') AS public_observed_at,
 (SELECT max(recorded_at) FROM secret_current_risk_evidence WHERE occurrence_id=? AND kind='ACCESS_SCOPE') AS public_recorded_at,
 (SELECT max(source_presence_observed_at) FROM secret_current_risk_evidence WHERE occurrence_id=? AND kind='ACCESS_SCOPE') AS source_observed_at,
 (SELECT count(*) FROM secret_current_validation_attempts WHERE occurrence_id=?) AS validation_rows,
 (SELECT max(completed_at) FROM secret_current_validation_attempts WHERE occurrence_id=?) AS validation_completed_at
""",occurrence,occurrence,occurrence,occurrence,occurrence,occurrence,occurrence);}
    private long publish(Map<String,Object> request,List<String> caps){var json=new JsonMapper();return jdbc.queryForObject("INSERT INTO secret_permission_observations(request_id,status,safe_facts,observed_at,expires_at,observer_version) VALUES(?,'PARTIAL',?::jsonb,clock_timestamp(),clock_timestamp()+interval '1 hour','fixture') RETURNING observation_id",Long.class,request.get("requestId"),json.writeValueAsString(Map.of("capabilities",caps,"coverage",Map.of("permissionCoverage","PARTIAL","targetCoverage","UNKNOWN","restrictionCoverage","UNKNOWN","classificationCoverage","UNKNOWN"),"reasonCodes",List.of("EFFECTIVE_PERMISSION_NOT_PROVEN"))));}
    private OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    private SecretPermissionAssistanceService.Confirm confirm(
            Map<String,Object> preview,List<SecretRiskProvenance.Ref> refs,String key) {
        var observedAt = databaseNow();
        return new SecretPermissionAssistanceService.Confirm(
                (String)preview.get("contextVersion"),
                ((Number)preview.get("evidenceRevision")).longValue(),
                key, true, null, observedAt, observedAt.plusMinutes(30),
                Map.of("capability","RESOURCE_ADMINISTRATION","targetScope","ACCOUNT",
                        "permissionCoverage","COMPLETE","targetCoverage","COMPLETE",
                        "restrictionCoverage","COMPLETE","classificationCoverage","COMPLETE"),
                refs, observedAt.minusMinutes(5), observedAt.plusMinutes(20));
    }
    private long revision(){return jdbc.queryForObject("SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",Long.class,occurrence);}
    private String policy(){return jdbc.queryForObject("SELECT policy_version||encode(content_hash,'hex')||permission_mapping_manifest::text FROM secret_severity_policies WHERE state='ACTIVE'",String.class);}
    private long providerReference(){long task=jdbc.queryForObject("INSERT INTO secret_investigation_tasks(target_type,occurrence_id,missing_reason_code,creation_source,version) VALUES('OCCURRENCE',?,'EVIDENCE_INCOMPLETE','HUMAN_HANDOFF',2) RETURNING task_id",Long.class,occurrence);long original=jdbc.queryForObject("INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version) VALUES(?,'EVIDENCE_ADDED',1,'{\"evidenceKind\":\"PROVIDER_REFERENCE\"}','TICKET:SEC-123',1) RETURNING history_id",Long.class,task);return jdbc.queryForObject("INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version) VALUES(?,'EVIDENCE_ACCEPTED',1,jsonb_build_object('acceptedHistoryId',?::bigint),'TICKET:SEC-123',2) RETURNING history_id",Long.class,task,original);}
    private long identityProof(){long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',1,now(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class);long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,1,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED',now()) RETURNING run_id",Long.class,job);long runScope=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status) VALUES(?,1,1,'SUCCEEDED') RETURNING run_scope_id",Long.class,run);long tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status) VALUES(?,'GITLEAKS','fixture','fixture','SUCCEEDED') RETURNING tool_run_id",Long.class,runScope);long finding=jdbc.queryForObject("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,?,'fixture','1',now()) RETURNING finding_id",Long.class,occurrence,run,tool,UUID.randomUUID().toString());return jdbc.queryForObject("""
INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,request_sent_at,scope_id,occurrence_id,source_finding_id,credential_revision,scope_revision,validation_revision,validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,evidence_version)
VALUES(1,?,?,'FIXTURE_IDENTITY','1','FIXTURE_IDENTITY',now(),now(),now(),'VALID','AUTHENTICATED',now(),1,?,?,1,1,1,1,'fixture',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),?,1,1,gen_random_uuid(),true,1) RETURNING attempt_id
""",Long.class,run,job,occurrence,finding,UUID.randomUUID().toString());}
}
