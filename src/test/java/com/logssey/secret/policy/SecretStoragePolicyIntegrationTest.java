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
    @Autowired WebApplicationContext context;
    long creator,reviewer,operator,connection,scope,occurrence;

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
        assertThat(service.evaluateOccurrence(occurrence,"policy-creator").policyResult()).isEqualTo("DENIED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_scope_policy_bindings WHERE scope_id=?",Long.class,scope)).isEqualTo(2);
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

    @Test void protectedRulesAreBoundToExactBranchAndPrefixAndNeverReturnedInResponses() throws Exception {
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
        assertThat(json).doesNotContain("github://","Example","fixtures/private/","protectedPathCondition","branchCondition","private-source");
        assertThat(json).contains("PREFIX");
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

    private String attemptApprove(long id) {
        try { service.approveProposal(scope,id,new ApproveProposalRequest(0L,1L),"policy-reviewer"); return "APPROVED"; }
        catch (ApiException e) { return e.errorCode().name(); }
    }
    private PolicySummary activate(String effect) {
        var draft=service.draft(draft(effect),"policy-creator");
        return service.approvePolicy(draft.policyId(),draft.version(),new VersionRequest(draft.version()),"policy-reviewer");
    }
    private void bind(PolicySummary policy) {
        var proposal=service.propose(scope,new ProposalRequest("PRODUCTION",policy.policyId(),policy.version(),"SOURCE_CLASSIFICATION","TICKET:SEC-123",0L),"policy-operator");
        service.approveProposal(scope,proposal.pendingProposal().proposalId(),new ApproveProposalRequest(0L,1L),"policy-reviewer");
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
