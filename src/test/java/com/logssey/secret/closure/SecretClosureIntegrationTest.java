package com.logssey.secret.closure;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.snapshot.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import static com.logssey.secret.closure.SecretClosureContracts.*;
import static org.assertj.core.api.Assertions.*;

class SecretClosureIntegrationTest {
    static final PostgreSQLContainer DB=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;static DataSourceTransactionManager manager;
    SecretClosureService service;SecretGovernanceService governance;
    long key,caseId;LocationFixture first;
    record LocationFixture(long connection,long scope,long occurrence,long baselineRun,long baselineTool,long revalidation) { }
    @BeforeAll static void start() {
        DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);manager=new DataSourceTransactionManager(ds);
    }
    @AfterAll static void stop() {DB.stop();}
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE dashboard_users,secret_connections,secret_storage_policies,secret_lifecycle_provider_writers,secret_lifecycle_provider_capabilities RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','unused','Security','ADMIN'),('reviewer','unused','Reviewer','ADMIN'),('scoped','unused','Scoped','ADMIN')");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,'MANUAL'),(2,'SECURITY',1,'MANUAL')");
        var access=new SecretAccessService(jdbc);var json=JsonMapper.builder().findAndAddModules().build();
        var repository=new SecretClosureRepository(jdbc,access);var evaluator=new SecretClosureEvaluator(repository,json);
        service=new SecretClosureService(repository,evaluator,access,new SecretCommandExecutor(jdbc,manager),new SecretReadSnapshots(jdbc,json),json);
        governance=new SecretGovernanceService(service,repository);
        key=jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
            VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',?,'test-v1','AWS ••••1234',now()-interval '1 hour',now()-interval '1 hour') RETURNING credential_set_id
            """,Long.class,new byte[32]);
        first=location("PRODUCTION",false);
        caseId=jdbc.queryForObject("""
            INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,
                action_status,review_status,version,opened_at)
            VALUES(?,?,1,'ASSESSED_EXPOSURE','PRODUCTION','REVALIDATION_PENDING','REVIEWED',1,now()-interval '50 minutes') RETURNING case_id
            """,Long.class,key,first.occurrence);
        link(first);first=missing(first);
    }
    @Test void comparableMissingAndIndependentlyApprovedRetirementPermitOnlyLimited() {
        long evidence=manual("REVOKED");var checks=service.checks("security",caseId);
        assertThat(checks.allowedCoverageLevels()).containsExactly("LIMITED");
        assertThat(checks.requiredResponseLocations().items()).hasSize(1).allMatch(item->item.status().equals("PASSED"));
        var request=resolution(checks,"LIMITED","resolve");var result=service.resolve("security",caseId,request);
        assertThat(result.coverageLevel()).isEqualTo("LIMITED");assertThat(result.resolutionId()).isNotNull();
        assertThat(service.resolve("security",caseId,request)).isEqualTo(result);
        assertThat(jdbc.queryForObject("SELECT is_current FROM secret_response_cases WHERE case_id=?",Boolean.class,caseId)).isTrue();
        assertThat(count("secret_case_resolutions")).isEqualTo(1);assertThat(count("secret_case_resolution_checks")).isEqualTo(1);
        var after=service.checks("security",caseId);assertThat(after.lastResolution().coverageLevel()).isEqualTo("LIMITED");
        assertThat(after.lastResolution().evidenceIds()).contains(evidence);assertThat(after.allowedCoverageLevels()).isEmpty();
        assertThat(after.lastResolution().limitations()).contains("PROVIDER_RETIREMENT_NOT_VERIFIED");
        assertThatThrownBy(()->jdbc.update("UPDATE secret_case_resolutions SET coverage_level='FULL' WHERE case_id=?",caseId))
            .isInstanceOf(org.springframework.dao.DataAccessException.class);
    }
    @Test void trustedProviderEvidenceCanPermitFullButManualCannotForgeIt() {
        manual("REVOKED");var checks=service.checks("security",caseId);
        var forged=resolution(checks,"FULL","fake-full");
        assertThatThrownBy(()->service.resolve("security",caseId,forged)).isInstanceOf(SecretClosureConflict.class);
        provider();checks=service.checks("security",caseId);assertThat(checks.allowedCoverageLevels()).contains("FULL");
        var result=service.resolve("security",caseId,resolution(checks,"FULL","trusted-full"));assertThat(result.coverageLevel()).isEqualTo("FULL");
    }
    @Test void missingAloneAndUncheckedOrInvalidCredentialsCannotClaimRetirement() {
        assertThat(service.checks("security",caseId).allowedCoverageLevels()).isEmpty();
        jdbc.update("""
            INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,
                requested_at,completed_at,provider_checked_at,result,reason_code)
            SELECT ?,run_id,job_id,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),'INVALID','INVALID_ACCESS_KEY'
            FROM secret_scan_runs WHERE run_id=?
            """,key,first.baselineRun);
        assertThat(service.checks("security",caseId).closureChecks()).anyMatch(check->check.reasonCode().equals("CURRENT_LIFECYCLE_EVIDENCE_REQUIRED"));
        assertThat(count("secret_case_resolutions")).isZero();
    }
    @Test void aSecondPresentUnknownOrUnlinkedAbnormalLocationBlocksLimitedWithoutPartialWrites() {
        manual("REVOKED");var second=location("PRODUCTION",false);
        var checks=service.checks("security",caseId);assertThat(checks.unlinkedAbnormalLocations().visibleCount()).isEqualTo(1);
        assertThat(checks.allowedCoverageLevels()).isEmpty();
        var blocked=new ResolutionRequest("RESOLVE",checks.caseVersion(),checks.closureCheckVersion(),List.of(),"LIMITED","blocked");
        assertThatThrownBy(()->service.resolve("security",caseId,blocked))
            .isInstanceOf(SecretClosureConflict.class);
        jdbc.update("UPDATE secret_occurrences SET exposure_status='UNKNOWN' WHERE occurrence_id=?",second.occurrence);
        checks=service.checks("security",caseId);assertThat(checks.unassessedCurrentLocations().visibleCount()).isEqualTo(1);
        assertThat(count("secret_case_resolutions")).isZero();assertThat(count("secret_command_idempotency")).isZero();
    }
    @Test void sourceRevisionFailureOrChangedActionInvalidatesEarlierMissingProof() {
        manual("REVOKED");assertThat(service.checks("security",caseId).canResolve()).isTrue();
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",first.scope);
        assertThat(service.checks("security",caseId).allowedCoverageLevels()).isEmpty();
        jdbc.update("UPDATE secret_connection_scopes SET revision=1 WHERE scope_id=?",first.scope);
        jdbc.update("UPDATE secret_case_occurrences SET last_material_action_at=clock_timestamp() WHERE case_id=?",caseId);
        assertThat(service.checks("security",caseId).allowedCoverageLevels()).isEmpty();
    }
    @Test void snapshotVersionRejectsNewFactsAndReplayRechecksRevokedAuthority() {
        manual("REVOKED");var before=service.checks("security",caseId);var request=resolution(before,"LIMITED","once");
        jdbc.update("UPDATE secret_case_occurrences SET version=version+1 WHERE case_id=?",caseId);
        assertThatThrownBy(()->service.resolve("security",caseId,request)).isInstanceOf(SecretClosureConflict.class);
        jdbc.update("UPDATE secret_case_occurrences SET version=version-1 WHERE case_id=?",caseId);
        var now=service.checks("security",caseId);var valid=resolution(now,"LIMITED","once-valid");service.resolve("security",caseId,valid);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=1");
        code(ErrorCode.NOT_FOUND,()->service.resolve("security",caseId,valid));
    }
    @Test void limitedReaderGetsOnlyVisibleLocationChecksAndCannotResolveOrApproveAnException() {
        manual("REVOKED");var second=location("PRODUCTION",true);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(3,'SECURITY',?,1,'MANUAL')",first.connection);
        var checks=service.checks("scoped",caseId);assertThat(checks.closureCheckVersion()).isNull();assertThat(checks.caseVersion()).isNull();
        assertThat(checks.requiredResponseLocations().items()).extracting(Location::occurrenceId).containsExactly(first.occurrence);
        assertThat(checks.allowedCoverageLevels()).isEmpty();assertThat(checks.capabilities().canApproveException()).isFalse();
        assertThat(checks.closureChecks()).noneMatch(check->Objects.equals(check.occurrenceId(),second.occurrence));
        code(ErrorCode.FORBIDDEN,()->governance.approveException("scoped",caseId,new ExceptionRequest(List.of(first.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-1",OffsetDateTime.now().plusDays(1),1L,"limited")));
    }
    @Test void otherOriginUncertaintyIsSeparateAndCannotChangeThisClosureVersion() {
        manual("REVOKED");var before=service.checks("security",caseId);var other=location("TEST",false);
        jdbc.update("UPDATE secret_occurrences SET exposure_status='UNKNOWN',presence_status='UNKNOWN' WHERE occurrence_id=?",other.occurrence);
        var after=service.checks("security",caseId);assertThat(after.closureCheckVersion()).isEqualTo(before.closureCheckVersion());
        assertThat(after.allowedCoverageLevels()).containsExactly("LIMITED");
    }
    @Test void riskAcceptanceHasAnExplicitScopeAndNewLocationIsNotAutomaticallyCovered() {
        var accepted=governance.approveException("security",caseId,new ExceptionRequest(List.of(first.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-1",OffsetDateTime.now().plusDays(1),version(),"risk"));
        assertThat(service.isFullyRiskAccepted(caseId)).isTrue();assertThat(service.riskAcceptanceDeadline(caseId)).isNotNull();
        var second=location("PRODUCTION",false);assertThat(service.isFullyRiskAccepted(caseId)).isFalse();
        assertThat(governance.exceptions("security",caseId).items().getFirst().occurrenceIds()).containsExactly(first.occurrence);
        governance.revoke("security",caseId,new RevokeRequest(accepted.exceptionId(),"APPROVAL_WITHDRAWN",version(),"revoke"));
        assertThat(service.isFullyRiskAccepted(caseId)).isFalse();
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases WHERE case_id=?",String.class,caseId)).isEqualTo("REVALIDATION_PENDING");
    }
    @Test void overlappingAndExpiredOrChangedScopeAcceptancesCannotHideRemainingRisk() {
        var request=new ExceptionRequest(List.of(first.occurrence),"COMPENSATING_CONTROL","TICKET:SEC-1",OffsetDateTime.now().plusDays(1),version(),"risk");
        var accepted=governance.approveException("security",caseId,request);assertThat(governance.approveException("security",caseId,request)).isEqualTo(accepted);
        code(ErrorCode.CONFLICT,()->governance.approveException("security",caseId,new ExceptionRequest(List.of(first.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-2",OffsetDateTime.now().plusDays(1),version(),"overlap")));
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",first.scope);assertThat(service.isFullyRiskAccepted(caseId)).isFalse();
        assertThat(governance.exceptions("security",caseId).items().getFirst().status()).isEqualTo("SCOPE_CHANGED");
        jdbc.update("UPDATE secret_connection_scopes SET revision=1 WHERE scope_id=?",first.scope);
        jdbc.update("UPDATE secret_exceptions SET approved_at=now()-interval '2 days',expires_at=now()-interval '1 day'");
        assertThat(service.isFullyRiskAccepted(caseId)).isFalse();assertThat(governance.exceptions("security",caseId).items().getFirst().status()).isEqualTo("EXPIRED");
    }
    @Test void approvedTransferCannotDismissAnActualRemainingExposureAndRequiresIndependentReview() {
        var transfer=governance.transfer("security",caseId,new TransferRequest(List.of(first.occurrence),"OWNER_TRANSFER","TICKET:SEC-1","CHANGE:SEC-2",version(),"transfer"));
        code(ErrorCode.FORBIDDEN,()->governance.reviewTransfer("security",caseId,transfer.evidenceId(),new TransferReview("APPROVE","TRANSFER_AND_ACCEPTANCE_CONFIRMED",1L,version(),"self")));
        governance.reviewTransfer("reviewer",caseId,transfer.evidenceId(),new TransferReview("APPROVE","TRANSFER_AND_ACCEPTANCE_CONFIRMED",1L,version(),"independent"));
        var checks=service.checks("security",caseId);assertThat(checks.allowedDismissalReasonCodes()).doesNotContain("OUT_OF_SCOPE");
        code(ErrorCode.EVIDENCE_REQUIRED,()->service.dismiss("security",caseId,new DismissalRequest("OUT_OF_SCOPE",List.of(transfer.evidenceId()),version(),"no-lifecycle")));
        manual("REVOKED");checks=service.checks("security",caseId);assertThat(checks.allowedDismissalReasonCodes()).contains("OUT_OF_SCOPE");
        var dismissed=service.dismiss("security",caseId,new DismissalRequest("OUT_OF_SCOPE",List.of(transfer.evidenceId()),version(),"proper-transfer"));
        assertThat(dismissed.status()).isEqualTo("CLOSED");assertThat(jdbc.queryForObject("SELECT is_current FROM secret_response_cases",Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases",String.class)).isNotEqualTo("RESOLVED");
        assertThat(service.checks("security",caseId).lastDismissal().reasonCode()).isEqualTo("OUT_OF_SCOPE");
    }
    @Test void changedScopeMakesAnExistingTransferUnavailableForReview() {
        var transfer=governance.transfer("security",caseId,new TransferRequest(List.of(first.occurrence),"OWNER_TRANSFER","TICKET:SEC-1","CHANGE:SEC-2",version(),"transfer"));
        assertThat(governance.transfers("reviewer",caseId).items().getFirst().canReview()).isTrue();
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",first.scope);
        assertThat(governance.transfers("reviewer",caseId).items().getFirst().canReview()).isFalse();
        code(ErrorCode.CONFLICT,()->governance.reviewTransfer("reviewer",caseId,transfer.evidenceId(),new TransferReview("APPROVE","TRANSFER_AND_ACCEPTANCE_CONFIRMED",1L,version(),"stale-transfer")));
    }
    @Test void verifiedSyntheticTestCanCloseOnlyAsSimulationAndUnknownTestCannot() {
        asTest();syntheticProof();manual("FIXTURE_RETIRED");var checks=service.checks("security",caseId);
        assertThat(checks.allowedCoverageLevels()).containsExactly("SIMULATION");
        var result=service.resolve("security",caseId,resolution(checks,"SIMULATION","simulation"));
        assertThat(result.coverageLevel()).isEqualTo("SIMULATION");
        assertThat(service.checks("security",caseId).lastResolution().limitations()).contains("PROVIDER_RETIREMENT_NOT_CLAIMED");
    }
    @Test void suspectedRealTestAlertNeedsAReviewedRetirementAndExplicitClosure() {
        asTest();long life=manual("REVOKED");
        long alert=jdbc.queryForObject("""
            INSERT INTO secret_cross_environment_alerts(credential_set_id,status,test_case_id,first_observed_at,last_observed_at)
            VALUES(?,'SUSPECTED_REAL',?,now()-interval '1 hour',now()) RETURNING alert_id
            """,Long.class,key,caseId);
        jdbc.update("INSERT INTO secret_cross_environment_alert_locations(alert_id,occurrence_id,last_observed_at) VALUES(?,?,now())",alert,first.occurrence);
        var blocked=service.checks("security",caseId);assertThat(blocked.allowedCoverageLevels()).isEmpty();
        assertThat(blocked.closureChecks()).anyMatch(check->check.reasonCode().equals("CROSS_ENVIRONMENT_ALERT_OPEN"));
        var access=new SecretAccessService(jdbc);
        var alerts=new com.logssey.secret.alert.SecretCrossEnvironmentAlertService(jdbc,access,new SecretCommandExecutor(jdbc,manager));
        alerts.close("security",alert,new com.logssey.secret.alert.SecretCrossEnvironmentAlertRequests.Close(0L,"CREDENTIAL_RETIRED",List.of(),List.of(),List.of(life),caseId,null,"retired-alert"));
        var checks=service.checks("security",caseId);assertThat(checks.allowedCoverageLevels()).containsExactly("LIMITED");
        var impossible=resolution(checks,"SIMULATION","not-synthetic");
        assertThatThrownBy(()->service.resolve("security",caseId,impossible)).isInstanceOf(SecretClosureConflict.class);
    }
    @Test void falsePositiveDismissalIsNotResolutionAndAnIndependentFindingPreventsIt() {
        correction(first);var checks=service.checks("security",caseId);
        assertThat(checks.allowedDismissalReasonCodes()).containsExactly("FALSE_POSITIVE");
        var proof=checks.eligibleDismissalEvidenceByReason().get("FALSE_POSITIVE").stream().map(EvidenceReference::evidenceId).toList();
        service.dismiss("security",caseId,new DismissalRequest("FALSE_POSITIVE",proof,version(),"fp-close"));
        assertThat(count("secret_case_resolutions")).isZero();assertThat(count("secret_case_dismissals")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT is_current FROM secret_response_cases",Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases",String.class)).isNotEqualTo("RESOLVED");
        assertThat(service.checks("security",caseId).lastDismissal().reasonCode()).isEqualTo("FALSE_POSITIVE");
    }
    @Test void oneUncorrectedFindingOrAuthenticatedRealKeyBlocksFalsePositiveDismissal() {
        correction(first);
        jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,'independent','other-rule','1',now()-interval '55 minutes')",first.occurrence,first.baselineRun,first.baselineTool);
        assertThat(service.checks("security",caseId).allowedDismissalReasonCodes()).doesNotContain("FALSE_POSITIVE");
    }
    @Test void aCorrectionCannotDismissAfterTheApprovedSourceRevisionChanges() {
        correction(first);assertThat(service.checks("security",caseId).allowedDismissalReasonCodes()).contains("FALSE_POSITIVE");
        var proof=service.checks("security",caseId).eligibleDismissalEvidenceIds();
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",first.scope);
        assertThat(service.checks("security",caseId).allowedDismissalReasonCodes()).doesNotContain("FALSE_POSITIVE");
        code(ErrorCode.EVIDENCE_REQUIRED,()->service.dismiss("security",caseId,new DismissalRequest("FALSE_POSITIVE",proof,version(),"stale-fp")));
        assertThat(count("secret_case_dismissals")).isZero();
    }
    @Test void aCorrectionDoesNotBypassAnIncompleteLatestScopeOrUnknownPresence() {
        correction(first);long latest=run(first.connection,first.scope,"FULL_SCAN",2,1);
        jdbc.update("UPDATE secret_run_scopes SET collection_status='FAILED' WHERE run_id=?",latest);
        assertThat(service.checks("security",caseId).allowedDismissalReasonCodes()).doesNotContain("FALSE_POSITIVE");
        jdbc.update("UPDATE secret_run_scopes SET collection_status='SUCCEEDED' WHERE run_id=?",latest);
        jdbc.update("UPDATE secret_occurrences SET presence_status='UNKNOWN' WHERE occurrence_id=?",first.occurrence);
        assertThat(service.checks("security",caseId).allowedDismissalReasonCodes()).doesNotContain("FALSE_POSITIVE");
    }
    @Test void aPublicRiskDeadlineRequiresAuthorityAcrossAllRelatedLocations() {
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(3,'SECURITY',?,1,'MANUAL')",first.connection);
        governance.approveException("security",caseId,new ExceptionRequest(List.of(first.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-1",OffsetDateTime.now().plusDays(1),version(),"risk"));
        assertThat(service.riskAcceptanceDeadline(caseId,"scoped")).isNotNull();
        var hidden=location("PRODUCTION",false);
        governance.approveException("security",caseId,new ExceptionRequest(List.of(hidden.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-2",OffsetDateTime.now().plusDays(1),version(),"hidden-risk"));
        assertThat(service.riskAcceptanceDeadline(caseId,"security")).isNotNull();
        assertThat(service.riskAcceptanceDeadline(caseId,"scoped")).isNull();
    }
    @Test void aHiddenScopeChangeCannotAlterTheVisibleExceptionProjection() {
        var hidden=location("PRODUCTION",false);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(3,'SECURITY',?,1,'MANUAL')",first.connection);
        governance.approveException("security",caseId,new ExceptionRequest(List.of(first.occurrence,hidden.occurrence),"BUSINESS_CONTINUITY","TICKET:SEC-1",OffsetDateTime.now().plusDays(1),version(),"risk"));
        var before=governance.exceptions("scoped",caseId);
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",hidden.scope);
        var after=governance.exceptions("scoped",caseId);
        assertThat(after).isEqualTo(before);assertThat(after.items().getFirst().occurrenceIds()).containsExactly(first.occurrence);
        assertThat(governance.exceptions("security",caseId).items().getFirst().status()).isEqualTo("SCOPE_CHANGED");
    }
    @Test void normalApprovedStorageMayRemainPresentButExpiredPolicyMustBeReviewed() {
        manual("REVOKED");var normal=location("PRODUCTION",false);normalPolicy(normal);
        var checks=service.checks("security",caseId);assertThat(checks.authorizedStorageLocations().items()).extracting(Location::occurrenceId).contains(normal.occurrence);
        assertThat(checks.allowedCoverageLevels()).containsExactly("LIMITED");
        jdbc.update("UPDATE secret_storage_policies SET valid_until=now()-interval '1 second'");
        assertThat(service.checks("security",caseId).allowedCoverageLevels()).isEmpty();
    }
    @Test void historicalUnknownWithComparableMissingDoesNotRequireAnInventedCurrentDecision() {
        manual("REVOKED");long currentCase=caseId;var historical=location("PRODUCTION",false);
        long old=jdbc.queryForObject("""
            INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,is_current,closed_at,action_status)
            VALUES(?,?,1,'ASSESSED_EXPOSURE','PRODUCTION',false,now(),'RESOLVED') RETURNING case_id
            """,Long.class,key,historical.occurrence);
        caseId=old;link(historical);historical=missing(historical);caseId=currentCase;
        jdbc.update("UPDATE secret_occurrences SET exposure_status='UNKNOWN' WHERE occurrence_id=?",historical.occurrence);
        var checks=service.checks("security",caseId);assertThat(checks.historicalMissingLocations().items()).extracting(Location::occurrenceId).contains(historical.occurrence);
        assertThat(checks.unassessedCurrentLocations().visibleCount()).isZero();assertThat(checks.allowedCoverageLevels()).containsExactly("LIMITED");
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",historical.scope);
        assertThat(service.checks("security",caseId).unassessedCurrentLocations().visibleCount()).isEqualTo(1);
    }
    @Test void unrelatedScopeFailureDoesNotBlockTheRequiredScopes() {
        manual("REVOKED");long unrelated=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled) VALUES(?,gen_random_uuid()::text,1,'GITHUB_REPOSITORY_FILES','protected-unrelated',true) RETURNING scope_id",Long.class,first.connection);
        long failed=run(first.connection,unrelated,"FULL_SCAN",2,1);
        jdbc.update("UPDATE secret_run_scopes SET collection_status='FAILED' WHERE run_id=?",failed);
        jdbc.update("UPDATE secret_jobs SET status='FAILED' WHERE job_id=(SELECT job_id FROM secret_scan_runs WHERE run_id=?)",failed);
        assertThat(service.checks("security",caseId).allowedCoverageLevels()).containsExactly("LIMITED");
    }

    LocationFixture location(String origin,boolean linked) {
        long connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Safe connection','protected','ACTIVE',1) RETURNING connection_id",Long.class);
        long scope=jdbc.queryForObject("""
            INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled,
                response_origin,response_origin_version,response_origin_set_by_user_id,response_origin_set_at)
            VALUES(?,gen_random_uuid()::text,1,'GITHUB_REPOSITORY_FILES','github://Example/project/main/src/','CURRENT_COMMIT_ONLY',true,?,1,2,now()) RETURNING scope_id
            """,Long.class,connection,origin);
        long run=run(connection,scope,"FULL_SCAN",60,55),tool=jdbc.queryForObject("SELECT t.tool_run_id FROM secret_tool_runs t JOIN secret_run_scopes s USING(run_scope_id) WHERE s.run_id=?",Long.class,run);
        long occurrence=jdbc.queryForObject("""
            INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,latest_object_version,environment,
                exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at,last_seen_run_id,policy_assessed_origin_version)
            VALUES(?,?,?,'Example/project/src/private.txt','L4','commit-1','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',now()-interval '1 hour',now()-interval '55 minutes',?,1) RETURNING occurrence_id
            """,Long.class,key,connection,scope,run);
        jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,gen_random_uuid()::text,'aws-access-token','1',now()-interval '55 minutes')",occurrence,run,tool);
        var f=new LocationFixture(connection,scope,occurrence,run,tool,0);if(linked)link(f);return f;
    }
    void link(LocationFixture f) {
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,response_status,last_material_action_at,actions_completed_at) VALUES(?,?,?,'REVALIDATION_PENDING',now()-interval '20 minutes',now()-interval '15 minutes')",caseId,f.occurrence,key);
        jdbc.update("INSERT INTO secret_action_records(case_id,occurrence_id,action_type,performed_at,recorded_by_user_id,evidence_ref,case_version,action_cycle) SELECT ?,?,'REVOKED',last_material_action_at,1,'TICKET:SEC-1',(SELECT coalesce(max(case_version),0)+1 FROM secret_action_records WHERE case_id=?),1 FROM secret_case_occurrences WHERE case_id=? AND occurrence_id=?",caseId,f.occurrence,caseId,caseId,f.occurrence);
        jdbc.update("UPDATE secret_response_cases SET version=(SELECT max(case_version) FROM secret_action_records WHERE case_id=?) WHERE case_id=?",caseId,caseId);
    }
    LocationFixture missing(LocationFixture f) {
        long run=run(f.connection,f.scope,"REVALIDATE",10,5);
        long revalidation=jdbc.queryForObject("""
            INSERT INTO secret_case_revalidations(case_id,occurrence_id,action_id,connection_id,scope_id,job_id,run_id,requested_by_user_id,
                idempotency_digest,baseline_config_hash,baseline_engine_version,baseline_fingerprint_version,runtime_fingerprint_version,case_version,status,requested_at,finished_at,
                scope_revision,scope_origin_version,baseline_identity,action_cycle,occurrence_version,last_material_action_at,actions_completed_at)
            SELECT ?,?,a.action_id,?,?,r.job_id,r.run_id,1,gen_random_uuid()::text,'test-config','8.0.0','test-v1','test-v1',1,'MISSING',r.requested_at,r.finished_at,
                1,1,k.fingerprint,co.action_cycle,co.version,co.last_material_action_at,co.actions_completed_at
            FROM secret_scan_runs r JOIN secret_case_occurrences co ON co.case_id=? AND co.occurrence_id=?
            JOIN secret_action_records a ON a.case_id=co.case_id AND a.occurrence_id=co.occurrence_id
            JOIN secret_credential_sets k ON k.credential_set_id=co.credential_set_id WHERE r.run_id=? RETURNING revalidation_id
            """,Long.class,caseId,f.occurrence,f.connection,f.scope,caseId,f.occurrence,run);
        jdbc.update("UPDATE secret_occurrences SET presence_status='MISSING',last_complete_coverage_at=(SELECT finished_at FROM secret_scan_runs WHERE run_id=?) WHERE occurrence_id=?",run,f.occurrence);
        return new LocationFixture(f.connection,f.scope,f.occurrence,f.baselineRun,f.baselineTool,revalidation);
    }
    long run(long connection,long scope,String kind,int requestedMinutes,int finishedMinutes) {
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES(?,?,now()-(?*interval '1 minute'),now(),1,3,'SUCCEEDED',now()-(?*interval '1 minute')) RETURNING job_id",Long.class,kind,connection,requestedMinutes,finishedMinutes);
        long run=jdbc.queryForObject("""
            INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,started_at,
                collection_status,detection_status,validation_status,result_status,finished_at)
            VALUES(?,?,?,1,now()-(?*interval '1 minute'),now()-(?*interval '1 minute'),now()-(?*interval '1 minute'),
                'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',now()-(?*interval '1 minute')) RETURNING run_id
            """,Long.class,job,connection,"REVALIDATE".equals(kind)?"REVALIDATION":"MANUAL",requestedMinutes,requestedMinutes,requestedMinutes-1,finishedMinutes);
        long rs=jdbc.queryForObject("""
            INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,started_at,finished_at,detection_stage_status,validation_stage_status,validation_required)
            SELECT run_id,?,'SUCCEEDED',0,started_at,finished_at,'SUCCEEDED','SKIPPED',false FROM secret_scan_runs WHERE run_id=? RETURNING run_scope_id
            """,Long.class,scope,run);
        jdbc.update("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at) SELECT ?,'GITLEAKS','8.0.0','test-config','SUCCEEDED',0,finished_at FROM secret_scan_runs WHERE run_id=?",rs,run);return run;
    }
    long manual(String kind) {
        long evidence=jdbc.queryForObject("""
            INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,verification_method,
                verification_level,evidence_ref,performed_at,observed_at,submitted_by_user_id)
            SELECT case_id,credential_set_id,opening_occurrence_id,case_origin,?,'EXTERNAL_RECORD','PENDING','TICKET:SEC-1',now()-interval '20 minutes',now(),1
            FROM secret_response_cases WHERE case_id=? RETURNING evidence_id
            """,Long.class,kind,caseId);
        jdbc.update("INSERT INTO secret_lifecycle_evidence_reviews(evidence_id,decision,reason_code,expected_evidence_version,case_version,reviewed_by_user_id) VALUES(?,'APPROVE','EXTERNAL_RECORD_CONFIRMED',1,2,2)",evidence);
        jdbc.update("INSERT INTO secret_lifecycle_evidence_applications(evidence_id,case_id,credential_set_id,origin,reviewed_by_user_id) SELECT ?,case_id,credential_set_id,case_origin,2 FROM secret_response_cases WHERE case_id=?",evidence,caseId);return evidence;
    }
    long provider() {
        jdbc.update("INSERT INTO secret_lifecycle_provider_writers(database_role) SELECT current_user ON CONFLICT DO NOTHING");
        jdbc.update("INSERT INTO secret_lifecycle_provider_capabilities VALUES('TEST_TRUSTED_RETIREMENT','1','TEST_ONLY','REVOKED') ON CONFLICT DO NOTHING");
        return jdbc.queryForObject("""
            INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,verification_method,
                verification_level,provider_validator_id,validator_version,endpoint_class,reason_code,performed_at,observed_at)
            SELECT case_id,credential_set_id,opening_occurrence_id,case_origin,'REVOKED','PROVIDER','PROVIDER_VERIFIED',
                'TEST_TRUSTED_RETIREMENT','1','TEST_ONLY','CONFIRMED_KEY_RETIRED',now()-interval '20 minutes',now()
            FROM secret_response_cases WHERE case_id=? RETURNING evidence_id
            """,Long.class,caseId);
    }
    void asTest() {
        jdbc.update("UPDATE secret_response_cases SET case_origin='TEST' WHERE case_id=?",caseId);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='TEST' WHERE scope_id=?",first.scope);
        jdbc.update("UPDATE secret_run_scopes SET snapshot_origin='TEST' WHERE scope_id=?",first.scope);
    }
    void syntheticProof() {
        long manifest=jdbc.queryForObject("INSERT INTO secret_fixture_manifests(version,protected_manifest_ref,approval_status,valid_from,valid_until) VALUES(1,'TEST:EXACT_IDENTITY','DRAFT',now()-interval '1 day',now()+interval '1 day') RETURNING manifest_id",Long.class);
        jdbc.update("INSERT INTO secret_fixture_manifest_identities(manifest_id,manifest_version,scope_id,scope_revision,issuer,credential_type,fingerprint_key_version,protected_fingerprint) SELECT ?,1,?,1,issuer,credential_type,fingerprint_key_version,fingerprint FROM secret_credential_sets WHERE credential_set_id=?",manifest,first.scope,key);
        jdbc.update("UPDATE secret_fixture_manifests SET approval_status='APPROVED',approved_by_user_id=2 WHERE manifest_id=?",manifest);
        long match=jdbc.queryForObject("""
            INSERT INTO secret_fixture_match_evidence(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,run_scope_id,
                comparator_id,comparator_version,match_result,observed_at)
            SELECT ?,?,1,?,1,run_scope_id,'LOGSSEY_PROTECTED_IDENTITY','1','MATCH',now() FROM secret_run_scopes WHERE run_id=? RETURNING match_evidence_id
            """,Long.class,key,first.scope,manifest,first.baselineRun);
        jdbc.update("INSERT INTO secret_test_fixture_attestations(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,match_evidence_id,confirmed_by_user_id,confirmation_source,status,confirmed_at) VALUES(?,?,1,?,1,?,1,'HUMAN','ACTIVE',now())",key,first.scope,manifest,match);
    }
    void correction(LocationFixture f) {
        long decision=jdbc.queryForObject("""
            INSERT INTO secret_exposure_assessments(occurrence_id,finding_id,finding_rule_id,finding_run_id,finding_rule_version,
                from_status,decision,reason_code,scope_origin,actor_user_id,version,scope_version,scope_revision,evidence_refs)
            SELECT o.occurrence_id,f.finding_id,f.rule_id,f.run_id,f.rule_version,'ABNORMAL','FALSE_POSITIVE','NOT_A_CREDENTIAL',s.response_origin,
                1,1,1,1,'["TICKET:SEC-1"]'::jsonb FROM secret_occurrences o JOIN secret_connection_scopes s USING(scope_id)
            JOIN secret_findings f ON f.occurrence_id=o.occurrence_id AND f.run_id=o.last_seen_run_id WHERE o.occurrence_id=? RETURNING assessment_id
            """,Long.class,f.occurrence);
        jdbc.update("UPDATE secret_occurrences SET exposure_assessment_version=1 WHERE occurrence_id=?",f.occurrence);
        jdbc.update("""
            INSERT INTO secret_finding_dispositions(decision_id,finding_id,occurrence_id,scope_id,scope_revision,scope_origin_version,scope_fingerprint,
                source_object_digest,location_digest,object_version,rule_id,rule_version,engine,engine_version,config_hash,
                protected_evidence_identity,identity_key_version,issuer,credential_type,reason_code,decision_source,reviewed_by_user_id,reuse_expires_at)
            SELECT ?,f.finding_id,o.occurrence_id,o.scope_id,1,1,md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text),
                sha256(convert_to(o.source_object_ref,'UTF8')),sha256(convert_to(o.location_key,'UTF8')),o.latest_object_version,
                f.rule_id,f.rule_version,t.engine,t.engine_version,t.config_hash,k.fingerprint,k.fingerprint_key_version,k.issuer,k.credential_type,
                'NOT_A_CREDENTIAL','HUMAN',1,now()+interval '29 days' FROM secret_occurrences o JOIN secret_connection_scopes s USING(scope_id)
            JOIN secret_findings f ON f.occurrence_id=o.occurrence_id AND f.run_id=o.last_seen_run_id JOIN secret_tool_runs t ON t.tool_run_id=f.tool_run_id
            JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id WHERE o.occurrence_id=?
            """,decision,f.occurrence);
    }
    void normalPolicy(LocationFixture f) {
        long policy=jdbc.queryForObject("INSERT INTO secret_storage_policies(version,status,reason_code,evidence_ref,created_by_user_id,approved_by_user_id,valid_from,valid_until,approved_at) VALUES(1,'ACTIVE','STANDARD','POLICY:SECRET-1',1,2,now()-interval '1 day',now()+interval '1 day',now()) RETURNING policy_id",Long.class);
        jdbc.update("INSERT INTO secret_storage_policy_rules(policy_id,policy_version,effect,connection_id,scope_id,scope_revision,scope_fingerprint,content_type,path_match) SELECT ?,1,'ALLOW',connection_id,scope_id,revision,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),content_type,'SCOPE' FROM secret_connection_scopes WHERE scope_id=?",policy,f.scope);
        long decision=jdbc.queryForObject("INSERT INTO secret_scope_origin_decisions(scope_id,from_origin,to_origin,reason_code,actor_user_id,version) VALUES(?,'UNCLASSIFIED','PRODUCTION','APPROVED_PRODUCTION_SOURCE',2,1) RETURNING decision_id",Long.class,f.scope);
        long binding=jdbc.queryForObject("INSERT INTO secret_scope_policy_bindings(scope_id,scope_revision,scope_origin_version,scope_fingerprint,policy_id,policy_version,classification_decision_id) SELECT scope_id,revision,response_origin_version,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),?,1,? FROM secret_connection_scopes WHERE scope_id=? RETURNING binding_id",Long.class,policy,decision,f.scope);
        jdbc.update("UPDATE secret_occurrences SET exposure_status='NORMAL',policy_assessed_binding_id=?,policy_assessed_origin_version=1,policy_recheck_required=false WHERE occurrence_id=?",binding,f.occurrence);
    }
    ResolutionRequest resolution(ClosureChecks checks,String level,String key) {
        var proof=checks.coverageOptions().stream().filter(o->o.level().equals(level)).findFirst().map(CoverageOption::evidenceIds).orElse(List.of());
        return new ResolutionRequest("RESOLVE",checks.caseVersion(),checks.closureCheckVersion(),proof,level,key);
    }
    long version() {return jdbc.queryForObject("SELECT version FROM secret_response_cases WHERE case_id=?",Long.class,caseId);}
    static long count(String table) {return jdbc.queryForObject("SELECT count(*) FROM "+table,Long.class);}
    static void code(ErrorCode expected,Runnable action) {assertThatThrownBy(action::run).isInstanceOfSatisfying(ApiException.class,error->assertThat(error.errorCode()).isEqualTo(expected));}
}
