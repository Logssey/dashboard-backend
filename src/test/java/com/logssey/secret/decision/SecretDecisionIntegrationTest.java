package com.logssey.secret.decision;

import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.investigation.*;
import com.logssey.secret.query.*;
import com.logssey.secret.snapshot.*;
import com.logssey.secret.policy.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import static com.logssey.secret.decision.SecretDecisionContracts.*;
import static org.assertj.core.api.Assertions.*;

class SecretDecisionIntegrationTest {
    static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;static DataSourceTransactionManager manager;
    SecretDecisionService service;SecretInvestigationService tasks;
    @BeforeAll static void start() {
        POSTGRES.start();var ds=new DriverManagerDataSource(POSTGRES.getJdbcUrl(),POSTGRES.getUsername(),POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);manager=new DataSourceTransactionManager(ds);
    }
    @AfterAll static void stop() {POSTGRES.stop();}
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE secret_connections,secret_storage_policies,dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("""
            INSERT INTO dashboard_users(login_id,password_hash,display_name,role)
            VALUES('security','unused','Security','ADMIN'),('reviewer','unused','Reviewer','ADMIN'),
                  ('operator','unused','Operator','ADMIN'),('scoped','unused','Scoped','ADMIN')
            """);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,'MANUAL'),(2,'SECURITY',1,'MANUAL'),(3,'OPERATIONS',1,'MANUAL')");
        var access=new SecretAccessService(jdbc);var commands=new SecretCommandExecutor(jdbc,manager);
        var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().findAndAddModules().build());
        tasks=new SecretInvestigationService(jdbc,access,commands);
        service=new SecretDecisionService(jdbc,access,snapshots,tasks,new SecretLocationRepository(jdbc),
            JsonMapper.builder().findAndAddModules().build(),manager);
    }
    @Test void collectedUnclassifiedLocationCanCreateCaseWithoutInventedClassificationOrPolicy() {
        var f=fixture("CONFIRMED","UNCLASSIFIED");
        assertThat(service.context("security",f.occurrence).allowedDecisions()).contains("ABNORMAL").doesNotContain("NORMAL");
        var opened=service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","unclassified"));
        assertThat(opened.caseOperation()).isEqualTo("CREATED");
        assertThat(jdbc.queryForObject("SELECT case_origin FROM secret_response_cases WHERE case_id=?",String.class,opened.caseId())).isEqualTo("UNCLASSIFIED");
        assertThat(jdbc.queryForObject("SELECT response_origin FROM secret_connection_scopes WHERE scope_id=?",String.class,f.scope)).isEqualTo("UNCLASSIFIED");
        assertThat(count("secret_scope_origin_decisions")).isZero();assertThat(count("secret_scope_policy_bindings")).isZero();
        assertThat(jdbc.queryForObject("SELECT response_origin_set_by_user_id FROM secret_connection_scopes WHERE scope_id=?",Long.class,f.scope)).isNull();
    }
    @Test void legacyProductionAndTestNeedRealCollectionEvidenceButNoClassificationLedger() {
        for(String origin:List.of("PRODUCTION","TEST")) {
            var f=fixture("CONFIRMED","UNCLASSIFIED");
            jdbc.update("UPDATE secret_connection_scopes SET response_origin=?,response_origin_set_by_user_id=2,response_origin_set_at=now() WHERE scope_id=?",origin,f.scope);
            jdbc.update("UPDATE secret_run_scopes SET snapshot_origin=? WHERE scope_id=?",origin,f.scope);
            assertThat(service.context("security",f.occurrence).allowedDecisions()).contains("ABNORMAL").doesNotContain("NORMAL");
            var opened=service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","legacy-"+origin));
            assertThat(jdbc.queryForObject("SELECT case_origin FROM secret_response_cases WHERE case_id=?",String.class,opened.caseId())).isEqualTo(origin);
        }
        assertThat(count("secret_scope_origin_decisions")).isZero();assertThat(count("secret_scope_policy_bindings")).isZero();
    }
    @Test void unclassifiedCannotUseAnOldRevisionOrPausedSourceAsCurrentCollectionApproval() {
        var f=fixture("CONFIRMED","UNCLASSIFIED");
        jdbc.update("UPDATE secret_connections SET status='PAUSED' WHERE connection_id=?",f.connection);
        assertThat(service.context("security",f.occurrence).allowedDecisions()).doesNotContain("ABNORMAL","NORMAL");
        jdbc.update("UPDATE secret_connections SET status='ACTIVE' WHERE connection_id=?",f.connection);
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=?",f.scope);
        assertThat(service.context("security",f.occurrence).allowedDecisions()).doesNotContain("ABNORMAL","NORMAL");
    }
    @Test void oneDecisionCreatesReviewedCaseAndFourChecklistItemsAndReplayDoesNotDuplicate() {
        var f=fixture("CONFIRMED","PRODUCTION");var r=request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","one");
        var first=service.decide("security",f.occurrence,r);var replay=service.decide("security",f.occurrence,r);
        assertThat(first).isEqualTo(replay);assertThat(first.caseOperation()).isEqualTo("CREATED");
        assertThat(count("secret_exposure_assessments")).isEqualTo(1);assertThat(count("secret_response_cases")).isEqualTo(1);
        assertThat(count("secret_checklist_items")).isEqualTo(4);assertThat(count("secret_case_reviews")).isZero();
        assertThat(jdbc.queryForObject("SELECT opening_decision_id FROM secret_response_cases",Long.class)).isEqualTo(first.decisionId());
        assertThat(jdbc.queryForObject("SELECT review_status FROM secret_response_cases",String.class)).isEqualTo("REVIEWED");
        assertThat(countWhere("secret_audit_events","event_type='TRIAGE_DECIDED'")).isEqualTo(1);
        assertCode(ErrorCode.CONFLICT,()->service.decide("security",f.occurrence,new DecisionRequest("ABNORMAL","UNAPPROVED_SOURCE_LOCATION",
            r.findingId(),List.of("TICKET:SEC-999"),0L,1L,null,"one",null,null,null,null)));
    }
    @Test void secondLocationAttachesAndRevalidationStageReturnsToInProgress() {
        var f=fixture("CONFIRMED","PRODUCTION");var first=service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","first"));
        var other=location(f,"L2");jdbc.update("UPDATE secret_response_cases SET action_status='REVALIDATION_PENDING' WHERE case_id=?",first.caseId());
        var second=service.decide("security",other.occurrence,request(other,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","second"));
        assertThat(second.caseId()).isEqualTo(first.caseId());assertThat(second.caseOperation()).isEqualTo("ATTACHED");
        assertThat(count("secret_case_occurrences")).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases",String.class)).isEqualTo("IN_PROGRESS");
        assertThat(countWhere("secret_case_stage_history","reason_code='NEW_ABNORMAL_LOCATION'")).isEqualTo(1);
    }
    @Test void resolvedCaseIsPreservedAndNewExposureCreatesASuccessor() {
        var f=fixture("CONFIRMED","PRODUCTION");var first=service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","first"));
        jdbc.update("UPDATE secret_response_cases SET action_status='RESOLVED',resolved_at=now() WHERE case_id=?",first.caseId());
        var other=location(f,"L2");var second=service.decide("security",other.occurrence,request(other,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","new"));
        assertThat(second.caseId()).isNotEqualTo(first.caseId());assertThat(count("secret_response_cases")).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT previous_case_id FROM secret_response_cases WHERE is_current",Long.class)).isEqualTo(first.caseId());
    }
    @Test void candidateCannotOpenCaseAndOperationsAndAdminHaveNoDecisionAuthority() {
        var f=fixture("CANDIDATE","TEST");assertThat(service.context("security",f.occurrence).allowedDecisions()).doesNotContain("NORMAL","ABNORMAL");
        assertCode(ErrorCode.EVIDENCE_REQUIRED,()->service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","candidate")));
        assertCode(ErrorCode.NOT_FOUND,()->service.context("operator",f.occurrence));
        assertCode(ErrorCode.NOT_FOUND,()->service.decide("scoped",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","admin")));
        assertThat(count("secret_exposure_assessments")).isZero();
    }
    @Test void scopeFindingPresenceAndPolicyChangesRejectStaleDecisionsWithoutPartialWrites() {
        var f=fixture("CONFIRMED","PRODUCTION");var request=request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","stale");
        jdbc.update("UPDATE secret_connection_scopes SET response_origin_version=2 WHERE scope_id=?",f.scope);
        assertThatThrownBy(()->service.decide("security",f.occurrence,request)).isInstanceOfSatisfying(SecretReviewConflict.class,
            error->assertThat(error.changedFields()).contains("scope"));
        assertThat(count("secret_exposure_assessments")).isZero();assertThat(count("secret_command_idempotency")).isZero();
        assertThat(count("secret_response_cases")).isZero();
    }
    @Test void moreInfoRequiresAnOwnerAndDueDateCreatesOneTaskAndIsNotAnExposure() {
        var f=fixture("CANDIDATE","UNCLASSIFIED");var request=new DecisionRequest("NEEDS_MORE_INFO","INSUFFICIENT_EVIDENCE",null,List.of(),
            0L,0L,null,"investigate","POLICY_UNKNOWN",1L,OffsetDateTime.now().plusDays(1),"TICKET:SEC-123");
        var first=service.decide("security",f.occurrence,request);assertThat(first.investigationTaskId()).isNotNull();
        assertThat(first.exposureStatus()).isEqualTo("UNKNOWN");assertThat(first.caseId()).isNull();
        assertThat(service.decide("security",f.occurrence,request)).isEqualTo(first);
        assertThat(count("secret_investigation_tasks")).isEqualTo(1);assertThat(count("secret_response_cases")).isZero();
        assertThat(jdbc.queryForObject("SELECT finding_id FROM secret_exposure_assessments",Long.class)).isNull();
    }
    @Test void findingCorrectionDoesNotCreateNormalAndIndependentFindingStillNeedsReview() {
        var f=fixture("CONFIRMED","PRODUCTION");finding(f,"second-rule","2");
        var first=service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","fp"));
        assertThat(first.exposureStatus()).isEqualTo("UNKNOWN");assertThat(first.correctionId()).isNotNull();
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isEqualTo(1);
        long second=jdbc.queryForObject("SELECT finding_id FROM secret_current_valid_findings WHERE occurrence_id=?",Long.class,f.occurrence);
        service.decide("security",f.occurrence,new DecisionRequest("FALSE_POSITIVE","NOT_A_CREDENTIAL",second,List.of("TICKET:SEC-123"),1L,1L,null,"fp2",null,null,null,null));
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isZero();
        assertThat(service.queue("security","NORMAL_INVENTORY","PRODUCTION",0,20).total()).isZero();
    }
    @Test void authenticatedProviderProofCannotBeSuppressedAsFalsePositive() {
        var f=fixture("CONFIRMED","TEST");realProof(f);
        assertThat(service.context("security",f.occurrence).allowedDecisions()).doesNotContain("FALSE_POSITIVE");
        assertCode(ErrorCode.EVIDENCE_REQUIRED,()->service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","DOCUMENTED_PLACEHOLDER","real-fp")));
    }
    @Test void exactUnchangedEvidenceReusesOriginalApprovalButChangedObjectVersionDoesNot() {
        var f=fixture("CONFIRMED","PRODUCTION");var first=service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","DOCUMENTED_PLACEHOLDER","fp"));
        repeat(f,"commit-1");applyDefaults();assertThat(count("secret_finding_dispositions")).isEqualTo(2);
        assertThat(countWhere("secret_finding_dispositions","decision_source='EXACT_EVIDENCE_REUSE'")).isEqualTo(1);
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isZero();
        repeat(f,"commit-2");applyDefaults();assertThat(count("secret_finding_dispositions")).isEqualTo(2);
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT reused_from_disposition_id FROM secret_finding_dispositions WHERE decision_source='EXACT_EVIDENCE_REUSE'",Long.class)).isEqualTo(first.correctionId());
    }
    @Test void explicitAllowAutomaticallyRecordsPolicyNormalButDenyNeverOpensACase() {
        var f=fixture("CONFIRMED","PRODUCTION");bind(f,"ALLOW");applyDefaults();applyDefaults();
        assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences",String.class)).isEqualTo("NORMAL");
        assertThat(count("secret_exposure_assessments")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT decision_source FROM secret_exposure_assessments",String.class)).isEqualTo("POLICY");
        assertThat(jdbc.queryForObject("SELECT actor_user_id FROM secret_exposure_assessments",Long.class)).isNull();
        jdbc.update("UPDATE secret_storage_policies SET valid_until=now()-interval '1 second'");
        var context=service.context("security",f.occurrence);assertThat(context.storagePolicy().result()).isEqualTo("UNKNOWN");
        assertThat(context.storagePolicy().requiresReassessment()).isTrue();
        assertThat(service.queue("security","NORMAL_INVENTORY","PRODUCTION",0,20).total()).isZero();
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isEqualTo(1);
        var denied=fixture("CONFIRMED","TEST");bind(denied,"DENY");applyDefaults();assertThat(count("secret_response_cases")).isZero();
        assertThat(service.context("security",denied.occurrence).allowedReasonCodes().get("ABNORMAL")).containsExactly("POLICY_PROHIBITED_LOCATION");
    }
    @Test void concurrentRequestsCannotOpenTwoCasesAndReplayStillChecksRevokedPermission() throws Exception {
        var f=fixture("CONFIRMED","PRODUCTION");var request=request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","concurrent");
        try(var executor=Executors.newFixedThreadPool(2)) {
            var a=executor.submit(()->service.decide("security",f.occurrence,request));
            var b=executor.submit(()->service.decide("security",f.occurrence,request));
            assertThat(a.get(10,TimeUnit.SECONDS)).isEqualTo(b.get(10,TimeUnit.SECONDS));
        }
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=1");
        assertCode(ErrorCode.NOT_FOUND,()->service.decide("security",f.occurrence,request));
        assertThat(count("secret_response_cases")).isEqualTo(1);
    }
    @Test void unsafeEvidenceNeverEntersTheDatabaseOrPublicContext() {
        var f=fixture("CONFIRMED","PRODUCTION");var request=request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","safe");
        assertCode(ErrorCode.INVALID_INPUT,()->service.decide("security",f.occurrence,new DecisionRequest(request.decision(),request.reasonCode(),
            request.findingId(),List.of("https://private/raw-key"),0L,1L,null,"unsafe",null,null,null,null)));
        String context=JsonMapper.builder().findAndAddModules().build().writeValueAsString(service.context("security",f.occurrence));
        assertThat(context).doesNotContain("https://private/raw-key","fingerprint","protected_evidence","github://","source_object_ref","approved_ref");
        assertThat(count("secret_exposure_assessments")).isZero();
    }
    @Test
    void reviewCoordinatesUseCurrentApprovedPathOnlyAfterOccurrenceReadAuthority() {
        var f = fixture("CONFIRMED", "PRODUCTION");
        var context = service.context("security", f.occurrence);
        assertThat(context.safeLocationLabel()).isEqualTo("Example/project/fixtures/private/raw-key");
        assertThat(context.sourceDetails())
                .containsEntry("status", "AVAILABLE")
                .containsEntry("path", "fixtures/private/raw-key")
                .containsEntry("line", "L1");
        assertCode(ErrorCode.NOT_FOUND, () -> service.context("scoped", f.occurrence));
        jdbc.update(
                "UPDATE secret_connection_scopes SET approved_ref='github://Example/project/main/other/'"
                        + " WHERE scope_id=?",
                f.scope);
        var changed = service.context("security", f.occurrence);
        assertThat(changed.sourceDetails()).containsEntry("status", "UNAVAILABLE");
        assertThat(changed.safeLocationLabel()).isEqualTo("위치 #" + f.occurrence);
        assertThat(JsonMapper.builder().build().writeValueAsString(changed))
                .doesNotContain("private/raw-key", "github://", "source_object_ref", "approved_ref");
    }

    @Test void revokedFalsePositiveApprovalOrRealProofImmediatelyRestoresValidFinding() {
        var f=fixture("CONFIRMED","PRODUCTION");var corrected=service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","fp"));
        assertThat(count("secret_current_valid_findings")).isZero();
        jdbc.update("UPDATE secret_finding_dispositions SET revoked_at=now() WHERE disposition_id=?",corrected.correctionId());
        assertThat(count("secret_current_valid_findings")).isEqualTo(1);
        assertThat(service.context("security",f.occurrence).corrections().getFirst().recheckReason()).isEqualTo("APPROVAL_REVOKED");
        service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","new-fp"));
        assertThat(count("secret_current_valid_findings")).isZero();realProof(f);
        assertThat(count("secret_current_valid_findings")).isEqualTo(1);
    }
    @Test void independentNewFindingBlocksAutomaticReuseOfEvenTheUnchangedFinding() {
        var f=fixture("CONFIRMED","PRODUCTION");service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","fp"));
        repeat(f,"commit-1");long run=jdbc.queryForObject("SELECT last_seen_run_id FROM secret_occurrences WHERE occurrence_id=?",Long.class,f.occurrence);
        long rs=jdbc.queryForObject("SELECT run_scope_id FROM secret_run_scopes WHERE run_id=?",Long.class,run);
        long tool=jdbc.queryForObject("SELECT tool_run_id FROM secret_tool_runs WHERE run_scope_id=?",Long.class,rs);
        finding(new Fixture(f.connection,f.scope,f.key,f.occurrence,run,rs,tool),"independent-rule","2");applyDefaults();
        assertThat(count("secret_finding_dispositions")).isEqualTo(1);assertThat(count("secret_current_valid_findings")).isEqualTo(2);
    }
    @Test void nullObjectVersionOrExpiredApprovalNeverReusesFalsePositive() {
        var f=fixture("CONFIRMED","PRODUCTION");service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","fp"));
        repeat(f,null);applyDefaults();assertThat(count("secret_finding_dispositions")).isEqualTo(1);
        jdbc.update("UPDATE secret_finding_dispositions SET created_at=now()-interval '2 days',reuse_expires_at=now()-interval '1 day'");
        repeat(f,"commit-1");applyDefaults();assertThat(count("secret_finding_dispositions")).isEqualTo(1);
        assertThat(service.queue("security","NEEDS_DECISION","PRODUCTION",0,20).total()).isEqualTo(1);
    }
    @Test void automaticAllowCannotOverwriteHumanInvestigationOrRunOnALaterFailedScope() {
        var f=fixture("CONFIRMED","PRODUCTION");
        service.decide("security",f.occurrence,new DecisionRequest("NEEDS_MORE_INFO","INSUFFICIENT_EVIDENCE",null,List.of(),
            0L,1L,null,"more","POLICY_UNKNOWN",1L,OffsetDateTime.now().plusDays(1),"TICKET:SEC-123"));
        bind(f,"ALLOW");applyDefaults();assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,f.occurrence)).isEqualTo("UNKNOWN");
        var other=fixture("CONFIRMED","TEST");bind(other,"ALLOW");long failed=newRun(other.connection,other.scope);
        jdbc.update("UPDATE secret_jobs SET status='FAILED' WHERE job_id=(SELECT job_id FROM secret_scan_runs WHERE run_id=?)",failed);
        jdbc.update("UPDATE secret_run_scopes SET collection_status='FAILED' WHERE run_id=?",failed);applyDefaults();
        assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,other.occurrence)).isEqualTo("UNKNOWN");
    }
    @Test void integrityRepairUsesOriginalDecisionAndDoesNotCreateASecondAssessment() {
        var f=fixture("CONFIRMED","PRODUCTION");var first=service.decide("security",f.occurrence,request(f,"ABNORMAL","UNAPPROVED_SOURCE_LOCATION","open"));
        // Reproduce an old unlinked decision before any location-owned work exists.
        jdbc.update("DELETE FROM secret_checklist_items WHERE case_id=?",first.caseId());
        jdbc.update("DELETE FROM secret_case_occurrences WHERE case_id=?",first.caseId());
        var repaired=service.link("security",f.occurrence,new LinkRequest(first.decisionId(),1L,1L,1L,"repair"));
        assertThat(repaired.caseId()).isEqualTo(first.caseId());assertThat(count("secret_exposure_assessments")).isEqualTo(1);
        assertThat(count("secret_case_occurrences")).isEqualTo(1);
        assertThatThrownBy(()->service.link("security",f.occurrence,new LinkRequest(first.decisionId(),1L,1L,1L,"already"))).isInstanceOf(SecretReviewConflict.class);
    }
    @Test void scopeAclFiltersBeforeQueueCountsAndCannotLeakOtherLocations() {
        var first=fixture("CONFIRMED","PRODUCTION");fixture("CONFIRMED","PRODUCTION");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(4,'SECURITY',?,1,'MANUAL')",first.connection);
        var queue=service.queue("scoped","NEEDS_DECISION","PRODUCTION",0,20);
        assertThat(queue.total()).isEqualTo(1);assertThat(queue.items()).extracting(QueueItem::occurrenceId).containsExactly(first.occurrence);
        assertThat(queue.restrictedCoverage()).isTrue();assertThat(queue.partialCoverage()).isFalse();
    }
    @Test void falsePositiveSnapshotExpiresBeforeItsApprovalAndInvalidAssigneeRollsBackEverything() {
        var f=fixture("CONFIRMED","PRODUCTION");
        var bad=new DecisionRequest("NEEDS_MORE_INFO","INSUFFICIENT_EVIDENCE",null,List.of(),0L,1L,null,"bad-owner",
            "OWNER_UNKNOWN",3L,OffsetDateTime.now().plusDays(1),"TICKET:SEC-123");
        assertCode(ErrorCode.INVALID_INPUT,()->service.decide("security",f.occurrence,bad));
        assertThat(count("secret_exposure_assessments")).isZero();assertThat(count("secret_command_idempotency")).isZero();
        service.decide("security",f.occurrence,request(f,"FALSE_POSITIVE","NOT_A_CREDENTIAL","fp"));
        jdbc.update("UPDATE secret_finding_dispositions SET reuse_expires_at=now()+interval '30 seconds'");
        var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().findAndAddModules().build());
        var header=new org.springframework.transaction.support.TransactionTemplate(manager).execute(status->snapshots.create(
            1,"INVENTORY",Map.of("origin","PRODUCTION"),snapshots.authorizationRevision(1),false,
            List.of(new SecretReadSnapshots.Subject("CredentialSet",f.key,f.key,Map.of("workBucket","EXCLUDED_HISTORY"),List.of(f.occurrence)))));
        assertThat(Duration.between(header.asOf(),header.expiresAt())).isLessThan(Duration.ofMinutes(1));
    }

    record Fixture(long connection,long scope,long key,long occurrence,long run,long runScope,long tool) { }
    Fixture fixture(String state,String origin) {
        long key=jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,candidate_locator,fingerprint_key_version,
                masked_label,first_seen_at,last_seen_at)
            VALUES('AWS','AWS_ACCESS_KEY_PAIR',?,CASE WHEN ?='CONFIRMED' THEN ?::bytea END,
                CASE WHEN ?='CANDIDATE' THEN ?::bytea END,CASE WHEN ?='METADATA_ONLY' THEN NULL ELSE 'test-v1' END,
                'AWS ••••1234',now(),now()) RETURNING credential_set_id
            """,Long.class,state,state,identity(),state,identity(),state);
        long connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Safe connection','protected','ACTIVE',1) RETURNING connection_id",Long.class);
        long scope=jdbc.queryForObject("""
            INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled,
                response_origin,response_origin_version,response_origin_set_by_user_id,response_origin_set_at)
            VALUES(?,gen_random_uuid()::text,1,'GITHUB_REPOSITORY_FILES','github://Example/project/main/fixtures/','CURRENT_COMMIT_ONLY',true,
                ?,?,CASE WHEN ?='UNCLASSIFIED' THEN NULL ELSE 2 END,CASE WHEN ?='UNCLASSIFIED' THEN NULL ELSE now() END) RETURNING scope_id
            """,Long.class,connection,origin,origin.equals("UNCLASSIFIED")?0:1,origin,origin);
        if(!origin.equals("UNCLASSIFIED")) {
            long proposal=jdbc.queryForObject("""
                INSERT INTO secret_scope_classification_proposals(scope_id,expected_scope_version,scope_revision,scope_fingerprint,
                    proposed_origin,reason_code,evidence_ref,proposed_by_user_id,status)
                SELECT scope_id,0,revision,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),?,
                    'POLICY_PENDING','TICKET:SEC-123',3,'APPROVED' FROM secret_connection_scopes WHERE scope_id=? RETURNING proposal_id
                """,Long.class,origin,scope);
            jdbc.update("INSERT INTO secret_scope_origin_decisions(scope_id,from_origin,to_origin,reason_code,actor_user_id,version,proposal_id,evidence_ref,decision) VALUES(?,'UNCLASSIFIED',?,'SOURCE_CLASSIFICATION',2,1,?,'TICKET:SEC-123','APPROVED')",scope,origin,proposal);
        }
        long run=newRun(connection,scope),rs=jdbc.queryForObject("SELECT run_scope_id FROM secret_run_scopes WHERE run_id=?",Long.class,run);
        long tool=jdbc.queryForObject("SELECT tool_run_id FROM secret_tool_runs WHERE run_scope_id=?",Long.class,rs);
        long occurrence=jdbc.queryForObject("""
            INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,latest_object_version,
                environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id)
            VALUES(?,?,?,'Example/project/fixtures/private/raw-key','L1','commit-1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),clock_timestamp(),?) RETURNING occurrence_id
            """,Long.class,key,connection,scope,run);
        var f=new Fixture(connection,scope,key,occurrence,run,rs,tool);finding(f,"aws-access-token","1");return f;
    }
    Fixture location(Fixture f,String location) {
        long o=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,latest_object_version,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id) VALUES(?,?,?,'Example/project/fixtures/private/raw-key',?,'commit-1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),clock_timestamp(),?) RETURNING occurrence_id",Long.class,f.key,f.connection,f.scope,location,f.run);
        var other=new Fixture(f.connection,f.scope,f.key,o,f.run,f.runScope,f.tool);finding(other,"aws-access-token","1");return other;
    }
    long newRun(long c,long s) {
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',?,clock_timestamp(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class,c);
        long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,?,'MANUAL',1,now(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',clock_timestamp()) RETURNING run_id",Long.class,job,c);
        long rs=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at,detection_stage_status,validation_stage_status,validation_required) VALUES(?,?,'SUCCEEDED',1,clock_timestamp(),'SUCCEEDED','SKIPPED',false) RETURNING run_scope_id",Long.class,run,s);
        jdbc.update("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at) VALUES(?,'GITLEAKS','8.30.1','test-config','SUCCEEDED',1,now())",rs);return run;
    }
    void finding(Fixture f,String rule,String version) {jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,gen_random_uuid()::text,?,?,clock_timestamp())",f.occurrence,f.run,f.tool,rule,version);}
    void repeat(Fixture f,String version) {
        long run=newRun(f.connection,f.scope),rs=jdbc.queryForObject("SELECT run_scope_id FROM secret_run_scopes WHERE run_id=?",Long.class,run);
        long tool=jdbc.queryForObject("SELECT tool_run_id FROM secret_tool_runs WHERE run_scope_id=?",Long.class,rs);
        jdbc.update("UPDATE secret_occurrences SET last_seen_run_id=?,latest_object_version=?,last_seen_at=clock_timestamp() WHERE occurrence_id=?",run,version,f.occurrence);
        finding(new Fixture(f.connection,f.scope,f.key,f.occurrence,run,rs,tool),"aws-access-token","1");
    }
    void bind(Fixture f,String effect) {
        long policy=jdbc.queryForObject("INSERT INTO secret_storage_policies(version,status,reason_code,evidence_ref,created_by_user_id,approved_by_user_id,valid_from,valid_until,approved_at) VALUES(1,'ACTIVE','STANDARD','POLICY:SECRET-12',1,2,now()-interval '1 day',now()+interval '30 days',now()) RETURNING policy_id",Long.class);
        jdbc.update("INSERT INTO secret_storage_policy_rules(policy_id,policy_version,effect,connection_id,scope_id,scope_revision,scope_fingerprint,content_type,path_match) SELECT ?,1,?,connection_id,scope_id,revision,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),content_type,'SCOPE' FROM secret_connection_scopes WHERE scope_id=?",policy,effect,f.scope);
        jdbc.update("INSERT INTO secret_scope_policy_bindings(scope_id,scope_revision,scope_origin_version,scope_fingerprint,policy_id,policy_version,classification_decision_id) SELECT scope_id,revision,response_origin_version,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),?,1,(SELECT decision_id FROM secret_scope_origin_decisions WHERE scope_id=?) FROM secret_connection_scopes WHERE scope_id=?",policy,f.scope,f.scope);
    }
    void realProof(Fixture f) {jdbc.update("INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code) SELECT ?,?,job_id,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),'VALID','AUTHENTICATED' FROM secret_scan_runs WHERE run_id=?",f.key,f.run,f.run);}
    DecisionRequest request(Fixture f,String decision,String reason,String idempotency) {
        var context=service.context("security",f.occurrence);
        return new DecisionRequest(decision,reason,context.findings().stream().filter(Finding::valid).findFirst().map(Finding::findingId).orElse(null),
            List.of("TICKET:SEC-123"),context.versions().occurrence(),context.versions().scope(),context.versions().policy(),idempotency,null,null,null,null);
    }
    void applyDefaults() {jdbc.queryForObject("SELECT secret_apply_storage_policy_defaults(NULL::bigint)",Long.class);}
    static byte[] identity() {var value=new byte[32];new java.security.SecureRandom().nextBytes(value);return value;}
    static long count(String table) {return jdbc.queryForObject("SELECT count(*) FROM "+table,Long.class);}
    static long countWhere(String table,String where) {return jdbc.queryForObject("SELECT count(*) FROM "+table+" WHERE "+where,Long.class);}
    static void assertCode(ErrorCode code,Runnable action) {assertThatThrownBy(action::run).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.errorCode()).isEqualTo(code));}
}
