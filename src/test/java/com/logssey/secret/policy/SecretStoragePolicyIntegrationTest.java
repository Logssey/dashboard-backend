package com.logssey.secret.policy;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.policy.SecretPolicyContracts.*;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"spring.config.import=","logssey.admin.login-id=policy-admin",
        "logssey.admin.password=policy-test-password","logssey.admin.display-name=Policy Admin",
        "logssey.secret.bootstrap-security-login-id=","logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team=","logssey.secret.bootstrap-operations-login-id=",
        "logssey.secret.guide.groq.enabled=false"})
class SecretStoragePolicyIntegrationTest {
    private static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");
    static { POSTGRES.start(); }
    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url",POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username",POSTGRES::getUsername);
        properties.add("spring.datasource.password",POSTGRES::getPassword);
    }
    @AfterAll static void stop() { POSTGRES.stop(); }
    @Autowired JdbcTemplate jdbc;
    @Autowired SecretStoragePolicyService service;
    @Autowired SecretScopeChangeService changes;
    @Autowired WebApplicationContext context;
    @Autowired com.logssey.secret.query.SecretLocationService locations;
    @Autowired com.logssey.secret.decision.SecretDecisionService decisions;
    @Autowired com.logssey.secret.investigation.SecretInvestigationService investigations;
    long creator,reviewer,operator,connection,scope,occurrence;

    @Test void springProxyDecisionAndInvestigationCommandsUseWritableAtomicTransactions() {
        var result=decisions.decide("policy-creator",occurrence,new com.logssey.secret.decision.SecretDecisionContracts.DecisionRequest(
            "NEEDS_MORE_INFO","INSUFFICIENT_EVIDENCE",null,List.of(),0L,0L,null,"proxy-decision",
            "POLICY_UNKNOWN",creator,OffsetDateTime.now().plusDays(1),"TICKET:SEC-123"));
        long task=result.investigationTaskId();
        investigations.evidence("policy-creator",task,new com.logssey.secret.investigation.SecretInvestigationRequests.Evidence(
            "POLICY:SECRET-12","POLICY_REFERENCE",OffsetDateTime.now(),0L,"proxy-evidence"));
        investigations.assign("policy-creator",task,new com.logssey.secret.investigation.SecretInvestigationRequests.Assignment(
            reviewer,OffsetDateTime.now().plusDays(2),"OWNERSHIP_CHANGE",1L,"proxy-assignment"));
        assertCode(ErrorCode.EVIDENCE_REQUIRED,()->investigations.close("policy-creator",task,
            new com.logssey.secret.investigation.SecretInvestigationRequests.Close(2L,result.decisionId(),null,"proxy-close")));
        assertThat(investigations.detail("policy-creator",task).get("version")).isEqualTo(2L);
    }

    @BeforeEach void fixture() {
        jdbc.execute("TRUNCATE secret_connections,secret_storage_policies RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE secret_audit_events,secret_command_idempotency RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE secret_role_grants,secret_team_memberships RESTART IDENTITY");
        creator=userId("policy-creator"); reviewer=userId("policy-reviewer"); operator=userId("policy-operator");
        grant(creator,"SECURITY",null); grant(reviewer,"SECURITY",null); grant(operator,"OPERATIONS",null);
        connection=jdbc.queryForObject("""
                INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
                VALUES ('GITHUB','Safe connection','opaque-ref','ACTIVE',1) RETURNING connection_id
                """,Long.class);
        scope=jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled)
                VALUES (?,'private-source',1,'GITHUB_REPOSITORY_FILES',
                    'github://Example/project/main/fixtures/','CURRENT_COMMIT_ONLY',true) RETURNING scope_id
                """,Long.class,connection);
        long credential=jdbc.queryForObject("""
                INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,
                    masked_label,first_seen_at,last_seen_at)
                VALUES ('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(md5(random()::text),'hex'),'test','AWS masked',now(),now())
                RETURNING credential_set_id
                """,Long.class);
        occurrence=jdbc.queryForObject("""
                INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,
                    environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
                VALUES (?,?,?,'Example/project/fixtures/private/key.txt','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())
                RETURNING occurrence_id
                """,Long.class,credential,connection,scope);
    }

    @Test void independentPolicyAndSourceApprovalsProduceExplicitAllowWithoutInventingNormal() {
        var draft=service.draft(draft("ALLOW"),"policy-creator");
        assertThat(draft.status()).isEqualTo("DRAFT");
        assertThat(draft.capabilities().canApprove()).isFalse();
        assertCode(ErrorCode.FORBIDDEN,()->service.approvePolicy(draft.policyId(),1,new VersionRequest(1L),"policy-creator"));
        var active=service.approvePolicy(draft.policyId(),1,new VersionRequest(1L),"policy-reviewer");
        assertThat(active.usableNow()).isTrue();
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",active.policyId(),1L,
                "SOURCE_CLASSIFICATION","TICKET:SEC-123",0L),"policy-operator");
        assertThat(proposal.origin()).isEqualTo("UNCLASSIFIED");
        assertThat(proposal.pendingProposal().status()).isEqualTo("PENDING_APPROVAL");
        var approved=service.approveProposal(scope,proposal.pendingProposal().proposalId(),
                new ApproveProposalRequest(0L,1L),"policy-reviewer");
        assertThat(approved.origin()).isEqualTo("PRODUCTION");
        assertThat(approved.originVersion()).isEqualTo(1);
        assertThat(approved.approvalStatus()).isEqualTo("APPROVED");
        var result=service.evaluateOccurrence(occurrence,"policy-creator");
        assertThat(result.policyResult()).isEqualTo("ALLOWED");
        assertThat(result.reasonCode()).isEqualTo("EXPLICIT_ALLOW");
        assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,occurrence))
                .isEqualTo("UNKNOWN");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases",Long.class)).isZero();
    }

    @Test void noPolicyStaysUnknownAndSelfClassificationApprovalIsForbidden() {
        grant(creator,"OPERATIONS",connection);
        var proposed=service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","CHANGE:OPS-1",0L),"policy-creator");
        assertCode(ErrorCode.FORBIDDEN,()->service.approveProposal(scope,proposed.pendingProposal().proposalId(),
                new ApproveProposalRequest(0L,1L),"policy-creator"));
        service.approveProposal(scope,proposed.pendingProposal().proposalId(),new ApproveProposalRequest(0L,1L),"policy-reviewer");
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
        assertThat(service.classification(scope,"policy-operator").origin()).isEqualTo("TEST");
        assertThat(service.classification(scope,"policy-operator").storagePolicy()).isNull();
    }

    @Test void policyExpiryRetirementAndScopeMutationInvalidateAllowAndRequireRecheck() {
        var policy=activate("ALLOW"); bind(policy);
        var evaluation=service.evaluateOccurrence(occurrence,"policy-creator");
        jdbc.update("""
                UPDATE secret_occurrences SET exposure_status='NORMAL',policy_assessed_binding_id=?,
                    policy_assessed_origin_version=1,policy_recheck_required=false WHERE occurrence_id=?
                """,evaluation.bindingId(),occurrence);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").requiresReassessment()).isFalse();
        // Model elapsed validity without running a scheduler; the view must not reuse a cached ALLOW.
        jdbc.update("UPDATE secret_storage_policies SET valid_until=now()-interval '1 second' WHERE policy_id=?",policy.policyId());
        var expired=service.evaluateOccurrence(occurrence,"policy-creator");
        assertThat(expired.policyResult()).isEqualTo("UNKNOWN");
        assertThat(expired.reasonCode()).isEqualTo("POLICY_EXPIRED");
        assertThat(expired.requiresReassessment()).isTrue();
        jdbc.update("UPDATE secret_storage_policies SET valid_until=NULL WHERE policy_id=?",policy.policyId());
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Example/project/other/fixtures/' WHERE scope_id=?",scope);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").reasonCode()).isEqualTo("SCOPE_CHANGED");
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Example/project/main/fixtures/' WHERE scope_id=?",scope);
        service.retire(policy.policyId(),new RetireRequest(1L,"POLICY_WITHDRAWN","POLICY:SECRET-12"),"policy-reviewer");
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").reasonCode()).isEqualTo("POLICY_RETIRED");
        assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,occurrence)).isEqualTo("NORMAL");
    }

    @Test void denialAndRuleNonmatchAreDifferentAndConflictingActivationRollsBack() {
        var deny=activate("DENY"); bind(deny);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("DENIED");
        var allowDraft=service.draft(draft("ALLOW"),"policy-creator");
        assertCode(ErrorCode.CONFLICT,()->service.approvePolicy(allowDraft.policyId(),1,new VersionRequest(1L),"policy-reviewer"));
        assertThat(service.policy(allowDraft.policyId(),1,"policy-creator").status()).isEqualTo("DRAFT");
        assertThat(service.policy(deny.policyId(),1,"policy-creator").status()).isEqualTo("ACTIVE");
        jdbc.update("UPDATE secret_occurrences SET source_object_ref='Example/another/fixtures/key.txt' WHERE occurrence_id=?",occurrence);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").reasonCode()).isEqualTo("NO_MATCHING_RULE");
    }

    @Test void newPolicyVersionRetainsOldDefinitionAndRequiresExplicitRebinding() {
        var first=activate("ALLOW"); bind(first);
        var next=new DraftRequest(first.policyId(),1L,"POLICY_UPDATE","POLICY:SECRET-12",now().minusHours(1),null,
                List.of(new RuleRequest(connection,scope,"GITHUB_REPOSITORY_FILES","DENY","SCOPE",null,null)));
        var second=service.draft(next,"policy-creator");
        assertThat(second.version()).isEqualTo(2);
        service.approvePolicy(first.policyId(),2,new VersionRequest(2L),"policy-reviewer");
        assertThat(service.policy(first.policyId(),1,"policy-creator").rules()).extracting(SafeRule::effect).containsExactly("ALLOW");
        assertThat(service.policy(first.policyId(),1,"policy-creator").status()).isEqualTo("RETIRED");
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",first.policyId(),2L,"SOURCE_CORRECTION","CHANGE:OPS-2",1L),"policy-operator");
        service.approveProposal(scope,proposal.pendingProposal().proposalId(),new ApproveProposalRequest(1L,1L),"policy-reviewer");
        awaitCurrentBinding();
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("DENIED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_policy_bindings WHERE scope_id=?",Long.class,scope)).isEqualTo(2);
    }

    @Test void rebindingUsesOneMonotonicBoundaryWhenTheDatabaseClockMovesBackwards() {
        var first=activate("ALLOW");bind(first);
        var floor=now().plusMinutes(1);
        jdbc.update("UPDATE secret_scope_policy_bindings SET effective_from=? WHERE scope_id=? AND effective_until IS NULL",floor,scope);
        var second=service.draft(new DraftRequest(first.policyId(),1L,"POLICY_UPDATE","POLICY:SECRET-12",now().minusHours(1),null,
            List.of(new RuleRequest(connection,scope,"GITHUB_REPOSITORY_FILES","DENY","SCOPE",null,null))),"policy-creator");
        service.approvePolicy(first.policyId(),second.version(),new VersionRequest(second.version()),"policy-reviewer");
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",first.policyId(),second.version(),"SOURCE_CORRECTION","CHANGE:OPS-2",1L),"policy-operator");
        service.approveProposal(scope,proposal.pendingProposal().proposalId(),new ApproveProposalRequest(1L,1L),"policy-reviewer");
        var bindings=jdbc.queryForList("SELECT effective_from,effective_until FROM secret_scope_policy_bindings WHERE scope_id=? ORDER BY binding_id",scope);
        assertThat(bindings).hasSize(2);
        assertThat(((java.sql.Timestamp)bindings.getFirst().get("effective_until")).toInstant()).isEqualTo(floor.toInstant());
        assertThat(bindings.get(1).get("effective_from")).isEqualTo(bindings.getFirst().get("effective_until"));
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
    }

    @Test void metadataSourceCanBeClassifiedButNeverReceivesAValueStorageAllow() {
        jdbc.update("UPDATE secret_connections SET provider='AWS' WHERE connection_id=?",connection);
        jdbc.update("""
                UPDATE secret_connection_scopes SET content_type='IAM_ACCESS_KEY_METADATA',
                    approved_ref='aws://123456789012/global/iam/access-keys',history_limit='CURRENT_STATE_ONLY'
                WHERE scope_id=?
                """,scope);
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",null,null,"POLICY_PENDING","TICKET:SEC-123",0L),"policy-operator");
        var approved=service.approveProposal(scope,proposal.pendingProposal().proposalId(),new ApproveProposalRequest(0L,1L),"policy-reviewer");
        assertThat(approved.policyStatus()).isEqualTo("NOT_APPLICABLE");
        assertThat(approved.capabilities().canDraftPolicy()).isFalse();
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
    }

    @Test void snapshotsExpireAtPolicyDeadlineAndPolicyChangesInvalidateVisibleLocations() {
        var until=now().plusMinutes(5);
        var draft=service.draft(new DraftRequest(null,null,"AUTHORIZED_STORAGE","TICKET:SEC-123",now().minusHours(1),until,draft("ALLOW").rules()),"policy-creator");
        var active=service.approvePolicy(draft.policyId(),1,new VersionRequest(1L),"policy-reviewer"); bind(active);
        var filters=new com.logssey.secret.query.SecretInventoryFilters("PRODUCTION","ALL","ALL","ALL","VALUE_FINDINGS","ALL","ALL","ALL","ALL");
        var inventory=locations.inventory("policy-creator",filters,0,20,null);
        assertThat(inventory.get("expiresAt")).isEqualTo(until);
        String snapshot=inventory.get("snapshotId").toString();
        // Explicit invalidation must not wait for database and application wall clocks to agree.
        jdbc.update("UPDATE secret_query_snapshots SET created_at=clock_timestamp()+interval '1 minute' WHERE snapshot_id=?::uuid",snapshot);
        long secret=jdbc.queryForObject("SELECT credential_set_id FROM secret_occurrences WHERE occurrence_id=?",Long.class,occurrence);
        var detail=locations.locations("policy-creator",secret,filters,0,20,"ALL","ALL","ALL",null);
        String version=(String)detail.get("detailVersion");
        service.retire(active.policyId(),new RetireRequest(1L,"POLICY_WITHDRAWN","TICKET:SEC-123"),"policy-reviewer");
        assertCode(ErrorCode.CONFLICT,()->locations.inventory("policy-creator",filters,0,20,snapshot));
        assertCode(ErrorCode.CONFLICT,()->locations.locations("policy-creator",secret,filters,0,20,"ALL","ALL","ALL",version));
    }

    @Test void auditFailureRollsBackClassificationBindingProposalAndImpactsTogether() {
        var policy=activate("ALLOW");
        var proposed=service.propose(scope,new ProposalRequest("PRODUCTION",policy.policyId(),1L,"SOURCE_CLASSIFICATION","TICKET:SEC-123",0L),"policy-operator");
        jdbc.execute("""
                CREATE FUNCTION reject_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.event_type='CLASSIFICATION_APPROVED' THEN RAISE EXCEPTION 'injected policy audit failure'; END IF;
                RETURN NEW; END; $$
                """);
        jdbc.execute("CREATE TRIGGER reject_policy_audit BEFORE INSERT ON secret_audit_events FOR EACH ROW EXECUTE FUNCTION reject_policy_audit()");
        try {
            assertThatThrownBy(()->service.approveProposal(scope,proposed.pendingProposal().proposalId(),
                    new ApproveProposalRequest(0L,1L),"policy-reviewer"))
                    .isInstanceOf(org.springframework.dao.DataAccessException.class);
            var current=service.classification(scope,"policy-reviewer");
            assertThat(current.origin()).isEqualTo("UNCLASSIFIED");
            assertThat(current.originVersion()).isZero();
            assertThat(current.pendingProposal().status()).isEqualTo("PENDING_APPROVAL");
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_policy_bindings",Long.class)).isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_classification_impacts",Long.class)).isZero();
        } finally {
            jdbc.execute("DROP TRIGGER reject_policy_audit ON secret_audit_events");
            jdbc.execute("DROP FUNCTION reject_policy_audit()");
        }
    }

    @Test void protectedPolicyConditionsStayPrivateWhileOperatorsCanIdentifyApprovedTargets() throws Exception {
        grant(creator,"OPERATIONS",connection);
        var request=new DraftRequest(null,null,"AUTHORIZED_STORAGE","TICKET:SEC-123",now().minusHours(1),null,
                List.of(new RuleRequest(connection,scope,"GITHUB_REPOSITORY_FILES","ALLOW","PREFIX","main","fixtures/private/")));
        var draft=service.draft(request,"policy-creator");
        var active=service.approvePolicy(draft.policyId(),1,new VersionRequest(1L),"policy-reviewer"); bind(active);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("ALLOWED");
        jdbc.update("UPDATE secret_occurrences SET source_object_ref='Example/project/fixtures/private-other/key.txt' WHERE occurrence_id=?",occurrence);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
        String json=mvc().perform(get("/api/v1/secrets/scopes/"+scope+"/classification").with(user("policy-operator")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json).doesNotContain("github://","fixtures/private/","protectedPathCondition","branchCondition","private-source");
        assertThat(json).contains("PREFIX","Example/project");
    }

    @Test void correctionsAndRejectionsPreservePriorCaseOriginAndRecordImpacts() {
        var initial=service.propose(scope,new ProposalRequest("PRODUCTION",null,null,"POLICY_PENDING","TICKET:SEC-123",0L),"policy-operator");
        service.approveProposal(scope,initial.pendingProposal().proposalId(),new ApproveProposalRequest(0L,1L),"policy-reviewer");
        jdbc.update("UPDATE secret_occurrences SET exposure_status='ABNORMAL' WHERE occurrence_id=?",occurrence);
        long caseId=jdbc.queryForObject("""
                INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin)
                SELECT credential_set_id,occurrence_id,?,'ASSESSED_EXPOSURE','PRODUCTION'
                FROM secret_occurrences WHERE occurrence_id=? RETURNING case_id
                """,Long.class,creator,occurrence);
        jdbc.update("""
                INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id)
                SELECT ?,occurrence_id,credential_set_id FROM secret_occurrences WHERE occurrence_id=?
                """,caseId,occurrence);
        var rejected=service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","CHANGE:OPS-1",1L),"policy-operator");
        var afterReject=service.rejectProposal(scope,rejected.pendingProposal().proposalId(),
                new RejectProposalRequest("INSUFFICIENT_EVIDENCE",1L),"policy-reviewer");
        assertThat(afterReject.originVersion()).isEqualTo(1);
        assertThat(afterReject.origin()).isEqualTo("PRODUCTION");
        var proposed=service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","CHANGE:OPS-2",1L),"policy-operator");
        var corrected=service.approveProposal(scope,proposed.pendingProposal().proposalId(),new ApproveProposalRequest(1L,1L),"policy-reviewer");
        assertThat(corrected.originVersion()).isEqualTo(3);
        assertThat(corrected.history()).hasSize(3);
        assertThat(jdbc.queryForObject("SELECT case_origin FROM secret_response_cases WHERE case_id=?",String.class,caseId)).isEqualTo("PRODUCTION");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_classification_impacts WHERE case_id=?",Long.class,caseId)).isEqualTo(1);
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").requiresReassessment()).isTrue();
    }

    @Test void staleProposalScopeAndDuplicateRequestsCannotOverwriteClassification() throws Exception {
        var proposed=service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","TICKET:SEC-123",0L),"policy-operator");
        assertCode(ErrorCode.CONFLICT,()->service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","TICKET:SEC-123",0L),"policy-operator"));
        long id=proposed.pendingProposal().proposalId();
        try (var executor=Executors.newFixedThreadPool(2)) {
            var first=executor.submit(()->attemptApprove(id));
            var second=executor.submit(()->attemptApprove(id));
            assertThat(List.of(first.get(20,TimeUnit.SECONDS),second.get(20,TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder("APPROVED","CONFLICT");
        }
        assertThat(service.classification(scope,"policy-reviewer").history()).hasSize(1);
        var next=service.propose(scope,new ProposalRequest("PRODUCTION",null,null,"POLICY_PENDING","TICKET:SEC-123",1L),"policy-operator");
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",scope);
        assertCode(ErrorCode.CONFLICT,()->service.approveProposal(scope,next.pendingProposal().proposalId(),
                new ApproveProposalRequest(1L,1L),"policy-reviewer"));
        assertThat(service.classification(scope,"policy-reviewer").origin()).isEqualTo("TEST");
    }

    @Test void permissionsCsrfAndLegacyWriteBypassAreEnforcedByRealFilters() throws Exception {
        mvc().perform(get("/api/v1/secrets/scopes")).andExpect(status().isUnauthorized());
        mvc().perform(get("/api/v1/secrets/scopes").with(user("policy-admin"))).andExpect(status().isForbidden());
        String request="{\"origin\":\"TEST\",\"storagePolicyId\":null,\"storagePolicyVersion\":null,\"reasonCode\":\"POLICY_PENDING\",\"evidenceRef\":\"TICKET:SEC-123\",\"expectedScopeVersion\":0}";
        mvc().perform(post("/api/v1/secrets/scopes/"+scope+"/classification-proposals")
                .with(user("policy-operator")).contentType(MediaType.APPLICATION_JSON).content(request)).andExpect(status().isForbidden());
        mvc().perform(post("/api/v1/secrets/scopes/"+scope+"/classification-proposals")
                .with(user("policy-operator")).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.pendingProposal.status").value("PENDING_APPROVAL"));
        mvc().perform(patch("/api/v1/secrets/scopes/"+scope+"/response-origin").with(user("policy-reviewer")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("{\"origin\":\"TEST\",\"reasonCode\":\"APPROVED_TEST_FIXTURE\",\"expectedVersion\":0}"))
                .andExpect(status().isConflict());
        assertThat(service.classification(scope,"policy-reviewer").origin()).isEqualTo("UNCLASSIFIED");
    }

    @Test void invalidEvidenceAndMetadataScopesDoNotBecomeStoragePolicies() {
        var invalid=new DraftRequest(null,null,"AUTHORIZED_STORAGE","https://external.invalid/secret",now().minusHours(1),null,draft("ALLOW").rules());
        assertCode(ErrorCode.INVALID_INPUT,()->service.draft(invalid,"policy-creator"));
        assertCode(ErrorCode.INVALID_INPUT,()->service.draft(new DraftRequest(null,null,null,"TICKET:SEC-123",now(),null,draft("ALLOW").rules()),"policy-creator"));
        jdbc.update("UPDATE secret_connection_scopes SET content_type='IAM_ACCESS_KEY_METADATA' WHERE scope_id=?",scope);
        assertCode(ErrorCode.INVALID_INPUT,()->service.draft(draft("ALLOW"),"policy-creator"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_storage_policies",Long.class)).isZero();
    }

    @Test void legacyClassificationIsPreservedWithoutInventingIndependentApproval() {
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='PRODUCTION',response_origin_version=1,response_origin_set_by_user_id=?,response_origin_set_at=now() WHERE scope_id=?",creator,scope);
        jdbc.update("""
                INSERT INTO secret_scope_origin_decisions(scope_id,from_origin,to_origin,reason_code,actor_user_id,version)
                VALUES (?,'UNCLASSIFIED','PRODUCTION','APPROVED_PRODUCTION_SOURCE',?,1)
                """,scope,creator);
        var legacy=service.classification(scope,"policy-reviewer");
        assertThat(legacy.origin()).isEqualTo("PRODUCTION");
        assertThat(legacy.approvalStatus()).isEqualTo("LEGACY_REVIEW_REQUIRED");
        assertThat(legacy.history()).singleElement().satisfies(decision->assertThat(decision.decision()).isEqualTo("LEGACY"));
        assertThat(legacy.approvedByUserId()).isNull();
        var proposed=service.propose(scope,new ProposalRequest("TEST",null,null,"POLICY_PENDING","TICKET:SEC-123",1L),"policy-operator");
        var corrected=service.approveProposal(scope,proposed.pendingProposal().proposalId(),new ApproveProposalRequest(1L,1L),"policy-reviewer");
        assertThat(corrected.originVersion()).isEqualTo(2);
        assertThat(corrected.history()).hasSize(2);
        assertThat(corrected.history().get(1).decision()).isEqualTo("LEGACY");
    }

    private String attemptApprove(long id) {
        try { service.approveProposal(scope,id,new ApproveProposalRequest(0L,1L),"policy-reviewer"); return "APPROVED"; }
        catch (ApiException e) { return e.errorCode().name(); }
    }
    @Test void sourcePreviewIsReadOnlyAndSecurityCanSaveProductionWithoutAnotherAccount() {
        var preview=changes.preview(scope,new PreviewRequest("PRODUCTION",null,null,0L),"policy-creator");
        assertThat(preview.approvalMode()).isEqualTo("DIRECT");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_classification_proposals",Long.class)).isZero();
        var result=changes.propose(scope,change("PRODUCTION","DIRECT",0L,"direct-source"),"policy-creator");
        assertThat(result.origin()).isEqualTo("PRODUCTION");
        assertThat(result.approvalStatus()).isEqualTo("APPROVED");
        assertThat(result.pendingProposal()).isNull();
        assertThat(result.setupReasonCodes()).containsExactly("POLICY_MISSING");
        assertThat(result.changeResult().effect()).isEqualTo("APPLIED");
        assertThat(result.requiresSnapshotRefresh()).isTrue();
        assertThat(result.history().getFirst().approvalMode()).isEqualTo("DIRECT");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases",Long.class)).isZero();
    }

    @Test void sourceLabelCanBeSavedWithoutTicketsOrAnotherReviewerButCannotGrantStorage() {
        var result=changes.classifySource(scope,new SourceClassificationRequest("TEST",0L,"simple-source"),"policy-creator");
        assertThat(result.origin()).isEqualTo("TEST");
        assertThat(result.pendingProposal()).isNull();
        assertThat(result.storagePolicyId()).isNull();
        assertThat(result.changeResult().effect()).isEqualTo("APPLIED");
        assertThat(result.history().getFirst().evidenceRef()).startsWith("CHANGE:SOURCE-");
        assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences WHERE occurrence_id=?",String.class,occurrence)).isEqualTo("UNKNOWN");
        assertCode(ErrorCode.FORBIDDEN,()->changes.classifySource(scope,new SourceClassificationRequest("PRODUCTION",1L,"operator-source"),"policy-operator"));
        assertCode(ErrorCode.CONFLICT,()->changes.classifySource(scope,new SourceClassificationRequest("PRODUCTION",0L,"stale-source"),"policy-creator"));
    }

    @Test void operationsCannotClaimDirectAuthorityAndTestSourceStillNeedsIndependentReview() {
        assertThat(changes.preview(scope,new PreviewRequest("PRODUCTION",null,null,0L),"policy-operator").approvalMode()).isEqualTo("INDEPENDENT_REVIEW");
        assertCode(ErrorCode.CONFLICT,()->changes.propose(scope,change("PRODUCTION","DIRECT",0L,"operator-spoof"),"policy-operator"));
        var preview=changes.preview(scope,new PreviewRequest("TEST",null,null,0L),"policy-creator");
        assertThat(preview.approvalReasonCodes()).contains("TEST_CLASSIFICATION_REQUIRES_REVIEW");
        assertCode(ErrorCode.CONFLICT,()->changes.propose(scope,change("TEST","DIRECT",0L,"test-spoof"),"policy-creator"));
        var proposal=changes.propose(scope,change("TEST","INDEPENDENT_REVIEW",0L,"test-source"),"policy-creator");
        assertThat(proposal.origin()).isEqualTo("UNCLASSIFIED");
        assertThat(proposal.pendingProposal().capabilities().canApprove()).isFalse();
        assertCode(ErrorCode.FORBIDDEN,()->changes.approve(scope,proposal.pendingProposal().proposalId(),
            new ApproveProposalRequest(0L,1L,"self-approval"),"policy-creator"));
    }

    @Test void assignedReviewerIsLiveIndependentAndVersioned() {
        var result=changes.propose(scope,change("TEST","INDEPENDENT_REVIEW",0L,"review-assignment"),"policy-operator");
        long id=result.pendingProposal().proposalId();
        assertCode(ErrorCode.INVALID_INPUT,()->changes.assign(scope,id,new ReviewAssignmentRequest(operator,1L,"assign-self"),"policy-operator"));
        changes.assign(scope,id,new ReviewAssignmentRequest(reviewer,1L,"assign-reviewer"),"policy-operator");
        assertCode(ErrorCode.FORBIDDEN,()->changes.approve(scope,id,new ApproveProposalRequest(0L,2L,"wrong-reviewer"),"policy-creator"));
        var approved=changes.approve(scope,id,new ApproveProposalRequest(0L,2L,"right-reviewer"),"policy-reviewer");
        assertThat(approved.origin()).isEqualTo("TEST");
        assertThat(approved.pendingProposal()).isNull();
        assertThat(approved.history().getFirst().actorUserId()).isEqualTo(reviewer);
    }

    @Test void policyBindingChangeCannotUseDirectSourceShortcut() {
        var policy=activate("ALLOW");
        var preview=changes.preview(scope,new PreviewRequest("PRODUCTION",policy.policyId(),policy.version(),0L),"policy-creator");
        assertThat(preview.approvalMode()).isEqualTo("INDEPENDENT_REVIEW");
        assertThat(preview.approvalReasonCodes()).contains("POLICY_BINDING_CHANGE");
        assertCode(ErrorCode.CONFLICT,()->changes.propose(scope,new ProposalRequest("PRODUCTION",policy.policyId(),policy.version(),
            "SOURCE_CLASSIFICATION","TICKET:SEC-123",0L,"DIRECT",null,"policy-spoof"),"policy-creator"));
    }

    @Test void directCommandRetryAndNoopPreserveOneDecisionAndRecheckLiveAuthority() {
        var request=change("PRODUCTION","DIRECT",0L,"direct-retry");
        var first=changes.propose(scope,request,"policy-creator");
        var replay=changes.propose(scope,request,"policy-creator");
        assertThat(replay.changeResult().decisionId()).isEqualTo(first.changeResult().decisionId());
        assertCode(ErrorCode.CONFLICT,()->changes.propose(scope,change("TEST","INDEPENDENT_REVIEW",0L,"direct-retry"),"policy-creator"));
        var noop=changes.propose(scope,change("PRODUCTION","DIRECT",1L,"new-key-same-decision"),"policy-creator");
        assertThat(noop.changeResult().effect()).isEqualTo("UNCHANGED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_origin_decisions",Long.class)).isEqualTo(1);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",creator);
        assertCode(ErrorCode.NOT_FOUND,()->changes.propose(scope,request,"policy-creator"));
    }

    @Test void legacyProductionWithoutFormalEvidenceIsNotTreatedAsNoop() {
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='PRODUCTION',response_origin_version=1,response_origin_set_by_user_id=?,response_origin_set_at=now() WHERE scope_id=?",creator,scope);
        jdbc.update("INSERT INTO secret_scope_origin_decisions(scope_id,from_origin,to_origin,reason_code,actor_user_id,version) VALUES (?,'UNCLASSIFIED','PRODUCTION','APPROVED_PRODUCTION_SOURCE',?,1)",scope,creator);
        assertThat(service.classification(scope,"policy-creator").setupReasonCodes()).contains("CLASSIFICATION_EVIDENCE_REQUIRED");
        var result=changes.propose(scope,change("PRODUCTION","DIRECT",1L,"legacy-source"),"policy-creator");
        assertThat(result.changeResult().effect()).isEqualTo("APPLIED");
        assertThat(result.setupReasonCodes()).doesNotContain("CLASSIFICATION_EVIDENCE_REQUIRED");
    }

    @Test void previewAndWriteRejectStaleOrProtectedInputsWithoutMutation() {
        assertCode(ErrorCode.CONFLICT,()->changes.preview(scope,new PreviewRequest("PRODUCTION",null,null,1L),"policy-creator"));
        assertCode(ErrorCode.INVALID_INPUT,()->changes.propose(scope,new ProposalRequest("PRODUCTION",null,null,"POLICY_PENDING",
            "https://untrusted.invalid/reference",0L,"DIRECT",null,"bad-reference"),"policy-creator"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_classification_proposals",Long.class)).isZero();
    }

    private ProposalRequest change(String origin,String mode,long version,String key) {
        return new ProposalRequest(origin,null,null,"POLICY_PENDING","TICKET:SEC-123",version,mode,null,key);
    }

    @Test void sourceEvidenceCanBeRefreshedWhileTheRetiredPolicyRemainsUnresolved() {
        var policy=activate("ALLOW");bind(policy);
        service.retire(policy.policyId(),new RetireRequest(policy.version(),"POLICY_WITHDRAWN","TICKET:SEC-321"),"policy-reviewer");
        var preview=changes.preview(scope,new PreviewRequest("PRODUCTION",policy.policyId(),policy.version(),1L),"policy-creator");
        assertThat(preview.approvalMode()).isEqualTo("DIRECT");
        assertThat(preview.remainingReasonCodes()).contains("POLICY_RETIRED");
        var result=changes.propose(scope,new ProposalRequest("PRODUCTION",policy.policyId(),policy.version(),"SOURCE_CORRECTION","TICKET:SEC-456",1L,"DIRECT",null,"retain-retired-policy"),"policy-creator");
        assertThat(result.changeResult().effect()).isEqualTo("APPLIED");
        assertThat(result.setupReasonCodes()).contains("POLICY_RETIRED");
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("UNKNOWN");
        assertThat(service.policy(policy.policyId(),policy.version(),"policy-creator").status()).isEqualTo("RETIRED");
    }

    @Test void independentlyReviewedSourceChangeCannotReactivateARetainedRetiredPolicy() {
        var policy=activate("DENY");bind(policy);
        service.retire(policy.policyId(),new RetireRequest(policy.version(),"POLICY_WITHDRAWN","TICKET:SEC-321"),"policy-reviewer");
        var pending=changes.propose(scope,new ProposalRequest("TEST",policy.policyId(),policy.version(),"SOURCE_CORRECTION","TICKET:SEC-457",1L,"INDEPENDENT_REVIEW",reviewer,"retain-policy-review"),"policy-creator");
        var result=changes.approve(scope,pending.pendingProposal().proposalId(),new ApproveProposalRequest(1L,1L,"review-retained-policy"),"policy-reviewer");
        assertThat(result.origin()).isEqualTo("TEST");
        assertThat(result.setupReasonCodes()).contains("POLICY_RETIRED");
        assertThat(service.policy(policy.policyId(),policy.version(),"policy-creator").status()).isEqualTo("RETIRED");
    }

    @Test void scopeHandoffClosesOnlyWithTheCurrentFormalSourceDecision() {
        var requested=investigations.request("policy-operator",new com.logssey.secret.investigation.SecretInvestigationRequests.Request(
            "SCOPE",scope,"SOURCE_CLASSIFICATION",null,null,null,0L,"source-handoff"));
        long task=(Long)requested.get("taskId");
        var result=changes.propose(scope,change("PRODUCTION","DIRECT",0L,"source-for-handoff"),"policy-creator");
        var wrong=new com.logssey.secret.investigation.SecretInvestigationRequests.Close(0L,null,null,"wrong-source-proof",result.changeResult().decisionId()+100,null,null);
        assertCode(ErrorCode.EVIDENCE_REQUIRED,()->investigations.close("policy-operator",task,wrong));
        investigations.close("policy-operator",task,new com.logssey.secret.investigation.SecretInvestigationRequests.Close(
            0L,null,null,"close-source-handoff",result.changeResult().decisionId(),null,null));
        assertThat(investigations.detail("policy-operator",task).get("status")).isEqualTo("CLOSED");
        assertThat(service.classification(scope,"policy-operator").setupReasonCodes()).contains("POLICY_MISSING");
    }

    private PolicySummary activate(String effect) {
        var draft=service.draft(draft(effect),"policy-creator");
        return service.approvePolicy(draft.policyId(),draft.version(),new VersionRequest(draft.version()),"policy-reviewer");
    }
    private void bind(PolicySummary policy) {
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",policy.policyId(),policy.version(),"SOURCE_CLASSIFICATION","TICKET:SEC-123",0L),"policy-operator");
        service.approveProposal(scope,proposal.pendingProposal().proposalId(),new ApproveProposalRequest(0L,1L),"policy-reviewer");
        awaitCurrentBinding();
    }
    private void awaitCurrentBinding() {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT COALESCE(bool_and(effective_from<=clock_timestamp()),false) FROM secret_scope_policy_bindings WHERE scope_id=? AND effective_until IS NULL",Boolean.class,scope))) {
            if(System.nanoTime()>=deadline) throw new AssertionError("The fixture binding did not reach its effective boundary within three seconds");
            try { Thread.sleep(10); }
            catch(InterruptedException interrupted) { Thread.currentThread().interrupt();throw new AssertionError("Interrupted while awaiting the fixture binding",interrupted); }
        }
    }
    private DraftRequest draft(String effect) {
        return new DraftRequest(null,null,"AUTHORIZED_STORAGE","TICKET:SEC-123",now().minusHours(1),null,
                List.of(new RuleRequest(connection,scope,"GITHUB_REPOSITORY_FILES",effect,"SCOPE",null,null)));
    }
    private long userId(String login) {
        return jdbc.queryForObject("""
                INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES (?,'hash',?,'ADMIN')
                ON CONFLICT(login_id) DO UPDATE SET display_name=excluded.display_name RETURNING user_id
                """,Long.class,login,login);
    }
    private void grant(long user,String role,Long connection) {
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES (?,?,?,?,'MANUAL')",
                user,role,connection,user);
    }
    private OffsetDateTime now() { return jdbc.queryForObject("SELECT now()",OffsetDateTime.class); }
    private MockMvc mvc() { return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build(); }
    private void assertCode(ErrorCode code,Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(ApiException.class,error->assertThat(error.errorCode()).isEqualTo(code));
    }
}
