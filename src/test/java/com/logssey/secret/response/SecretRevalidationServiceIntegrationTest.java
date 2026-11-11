package com.logssey.secret.response;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.common.error.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.admin.login-id=revalidation-admin",
        "logssey.admin.password=revalidation-pass",
        "logssey.admin.display-name=Revalidation Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.guide.provider=groq",
        "logssey.secret.guide.groq.enabled=false",
        "logssey.secret.guide.claude.enabled=false"
})
class SecretRevalidationServiceIntegrationTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @Autowired private JdbcTemplate jdbc;
    @Autowired private SecretRevalidationService service;
    @Autowired private SecretLocationReadiness readiness;
    @Autowired private com.logssey.secret.lifecycle.SecretLifecycleService lifecycle;
    @Autowired private SecretGuideService guide;
    @Autowired private SecretGuideRepository guideRepository;
    @Autowired private SecretCaseRepository caseRepository;
    @Autowired private com.logssey.secret.fixture.SecretFixtureService fixtureService;
    @Autowired private SecretLocationWorkflow workflow;
    @Autowired private com.logssey.secret.query.SecretLocationService locations;
    @Autowired private com.logssey.secret.alert.SecretCrossEnvironmentAlertService alerts;
    @Autowired private WebApplicationContext webContext;

    private long caseId;
    private long occurrenceId;

    @BeforeEach
    void fixture() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE secret_role_grants, secret_team_memberships RESTART IDENTITY");
        long actor = jdbc.queryForObject("""
                SELECT user_id FROM dashboard_users WHERE login_id = 'revalidation-admin'
                """, Long.class);
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL'), (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actor, actor, actor, actor);
        long connection = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Synthetic', 'test-only', 'ACTIVE', 1)
                RETURNING connection_id
                """, Long.class);
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled, response_origin,
                     response_origin_set_by_user_id, response_origin_set_at)
                VALUES (?, 'fixture', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://Other/fixture/main/src/', 'CURRENT_COMMIT_ONLY', TRUE,
                        'TEST', ?, clock_timestamp()) RETURNING scope_id
                """, Long.class, connection, actor);
        long baselineJob = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at, attempt_no,
                     max_attempts, status, created_at, finished_at)
                VALUES ('FULL_SCAN', ?, clock_timestamp() - INTERVAL '1 hour',
                        clock_timestamp() - INTERVAL '1 hour', 1, 3, 'SUCCEEDED',
                        clock_timestamp() - INTERVAL '1 hour',
                        clock_timestamp() - INTERVAL '50 minutes') RETURNING job_id
                """, Long.class, connection);
        long baselineRun = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version,
                     scheduled_at, requested_at, collection_status, detection_status,
                     validation_status, result_status, finished_at)
                VALUES (?, ?, 'MANUAL', 1, clock_timestamp() - INTERVAL '1 hour',
                        clock_timestamp() - INTERVAL '1 hour', 'SUCCEEDED',
                        'SUCCEEDED', 'SKIPPED', 'SUCCEEDED',
                        clock_timestamp() - INTERVAL '50 minutes') RETURNING run_id
                """, Long.class, baselineJob, connection);
        long baselineRunScope = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes
                    (run_id, scope_id, collection_status, object_count, finished_at)
                VALUES (?, ?, 'SUCCEEDED', 1,
                        clock_timestamp() - INTERVAL '50 minutes') RETURNING run_scope_id
                """, Long.class, baselineRun, scope);
        long toolRun = jdbc.queryForObject("""
                INSERT INTO secret_tool_runs
                    (run_scope_id, engine, engine_version, config_hash, status,
                     finding_count, finished_at)
                VALUES (?, 'GITLEAKS', '8.0.0', repeat('a', 64), 'SUCCEEDED', 1,
                        clock_timestamp() - INTERVAL '50 minutes') RETURNING tool_run_id
                """, Long.class, baselineRunScope);
        long secret = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint,
                     fingerprint_key_version, masked_label, first_seen_at, last_seen_at)
                VALUES ('GITHUB', 'GITHUB_PAT', 'CONFIRMED', decode(md5(random()::text), 'hex'),
                        'test-v1', 'ghp_••••1234', clock_timestamp() - INTERVAL '1 hour',
                        clock_timestamp() - INTERVAL '50 minutes') RETURNING credential_set_id
                """, Long.class);
        occurrenceId = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref,
                     location_key, environment, exposure_status, exposure_range,
                     presence_status, first_seen_at, last_seen_at, last_seen_run_id)
                VALUES (?, ?, ?, 'Other/fixture/src/test.txt', 'L4', 'UNKNOWN',
                        'ABNORMAL', 'UNKNOWN', 'PRESENT',
                        clock_timestamp() - INTERVAL '1 hour',
                        clock_timestamp() - INTERVAL '50 minutes', ?)
                RETURNING occurrence_id
                """, Long.class, secret, connection, scope, baselineRun);
        jdbc.update("""
                INSERT INTO secret_findings
                    (occurrence_id, run_id, tool_run_id, finding_key,
                     rule_id, rule_version, detected_at)
                VALUES (?, ?, ?, 'baseline', 'github-pat', '8.0.0',
                        clock_timestamp() - INTERVAL '50 minutes')
                """, occurrenceId, baselineRun, toolRun);
        caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id,
                     opening_reason, case_origin, review_status, action_status,
                     assigned_user_id)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'TEST', 'REVIEWED',
                        'REVALIDATION_PENDING', ?) RETURNING case_id
                """, Long.class, secret, occurrenceId, actor, actor);
        jdbc.update("""
                INSERT INTO secret_case_occurrences
                    (case_id, occurrence_id, credential_set_id, response_status)
                VALUES (?, ?, ?, 'REVALIDATION_PENDING')
                """, caseId, occurrenceId, secret);
        jdbc.update("""
                INSERT INTO secret_action_records
                    (case_id, occurrence_id, action_type, performed_at,
                     recorded_by_user_id, evidence_ref, case_version)
                VALUES (?, ?, 'REVOKED', clock_timestamp() - INTERVAL '10 minutes',
                        ?, 'TICKET:SEC-123', 1)
                """, caseId, occurrenceId, actor);
        jdbc.update("""
          UPDATE secret_case_occurrences SET assigned_user_id=?,last_material_action_at=(SELECT max(performed_at) FROM secret_action_records WHERE case_id=?),actions_completed_at=clock_timestamp()-INTERVAL '1 minute'
          WHERE case_id=? AND occurrence_id=?
          """,actor,caseId,caseId,occurrenceId);
    }

    @Test
    void databaseOnlyAssessmentDoesNotBlockAnExternalLocationRecheck() {
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE kind='ASSESS' AND status='PENDING'", Long.class))
                .isPositive();
        var accepted = service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, 0L, "assessment-does-not-block"),
                "revalidation-admin");
        assertThat(accepted.jobStatus()).isEqualTo("PENDING");
        // The newly queued external recheck still excludes a second external request.
        assertThatThrownBy(() -> service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 1L, 1L, "external-still-exclusive"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
    }

    @Test
    void exactAwsValueLocationsCanRequestTheSameAuditedLocationRecheck() {
        String[][] scopes = {
                {"AWS_SECRETS_MANAGER_VALUE", "aws://123456789012/ap-northeast-2/secrets-manager/secret/arn%3Aaws%3Asecretsmanager%3Aap-northeast-2%3A123456789012%3Asecret%3Afixture"},
                {"AWS_SSM_PARAMETER_VALUE", "aws://123456789012/ap-northeast-2/ssm/parameter/arn%3Aaws%3Assm%3Aap-northeast-2%3A123456789012%3Aparameter%2Ffixture"},
                {"AWS_S3_OBJECT_CONTENT", "aws://123456789012/ap-northeast-2/s3/object/example-bucket/fixture.env"}
        };
        for (int i = 0; i < scopes.length; i++) {
            if (i > 0) fixture();
            jdbc.update("UPDATE secret_connections SET provider='AWS',auth_ref='aws-profile:test'");
            jdbc.update("UPDATE secret_connection_scopes SET content_type=?,history_limit='CURRENT_VALUE_ONLY',approved_ref=?",
                    scopes[i][0], scopes[i][1]);
            jdbc.update("UPDATE secret_occurrences SET source_object_ref='aws-content-scope:' || scope_id::text WHERE occurrence_id=?", occurrenceId);
            var accepted = service.request(caseId,
                    new SecretRevalidationRequest(occurrenceId, 0L, 0L, "exact-aws-location-" + i),
                    "revalidation-admin");
            assertThat(accepted.jobStatus()).isEqualTo("PENDING");
            assertThat(jdbc.queryForMap("SELECT j.kind,j.purpose,s.snapshot_content_type FROM secret_scan_runs r JOIN secret_jobs j USING(job_id) JOIN secret_run_scopes s USING(run_id) WHERE r.run_id=?", accepted.runId()))
                    .containsEntry("kind", "REVALIDATE")
                    .containsEntry("purpose", "LOCATION_RECHECK")
                    .containsEntry("snapshot_content_type", scopes[i][0]);
        }
    }

    @Test
    void awsMetadataCannotBeRecheckedAsASecretLocation() {
        jdbc.update("UPDATE secret_connections SET provider='AWS',auth_ref='aws-profile:test'");
        jdbc.update("UPDATE secret_connection_scopes SET content_type='IAM_ACCESS_KEY_METADATA',history_limit='CURRENT_STATE_ONLY',approved_ref='aws://123456789012/global/iam/access-keys'");
        assertThatThrownBy(() -> service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, 0L, "metadata-is-not-a-value"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE purpose='LOCATION_RECHECK'", Long.class)).isZero();
    }

    @Test
    void laterSuccessfulFullScanInvalidatesTheSamePostActionAbsenceProjectionAsClosure() {
        var accepted = service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, 0L, "latest-absence"),
                "revalidation-admin");
        jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=clock_timestamp() WHERE job_id=(SELECT job_id FROM secret_scan_runs WHERE run_id=?)", accepted.runId());
        jdbc.update("UPDATE secret_scan_runs SET collection_status='SUCCEEDED',detection_status='SUCCEEDED',validation_status='SKIPPED',result_status='SUCCEEDED',finished_at=clock_timestamp() WHERE run_id=?", accepted.runId());
        jdbc.update("UPDATE secret_run_scopes SET collection_status='SUCCEEDED',object_count=1,started_at=clock_timestamp(),finished_at=clock_timestamp(),detection_stage_status='SUCCEEDED',validation_stage_status='SKIPPED',validation_required=false WHERE run_id=?", accepted.runId());
        jdbc.update("UPDATE secret_case_revalidations SET status='MISSING',finished_at=clock_timestamp() WHERE run_id=?", accepted.runId());
        jdbc.update("UPDATE secret_occurrences SET presence_status='MISSING' WHERE occurrence_id=?", occurrenceId);
        var principal = new com.logssey.secret.access.SecretPrincipal(actor());
        assertThat(((java.util.Map<?, ?>) readiness.capabilities(principal, caseId, occurrenceId).get("locationAbsenceCheck")).get("status"))
                .isEqualTo("PASSED");

        long connection = jdbc.queryForObject("SELECT connection_id FROM secret_occurrences WHERE occurrence_id=?", Long.class, occurrenceId);
        long scope = jdbc.queryForObject("SELECT scope_id FROM secret_occurrences WHERE occurrence_id=?", Long.class, occurrenceId);
        long job = jdbc.queryForObject("""
                INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,status,attempt_no,max_attempts,finished_at)
                VALUES('FULL_SCAN',?,clock_timestamp(),clock_timestamp(),'SUCCEEDED',1,3,clock_timestamp()) RETURNING job_id
                """, Long.class, connection);
        long run = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,
                    collection_status,detection_status,validation_status,result_status,finished_at)
                VALUES(?,?,'SCHEDULED',1,clock_timestamp(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',clock_timestamp()) RETURNING run_id
                """, Long.class, job, connection);
        jdbc.update("""
                INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,started_at,finished_at,
                    detection_stage_status,validation_stage_status,validation_required)
                VALUES(?,?,'SUCCEEDED',1,clock_timestamp(),clock_timestamp(),'SUCCEEDED','SKIPPED',false)
                """, run, scope);
        assertThat(((java.util.Map<?, ?>) readiness.capabilities(principal, caseId, occurrenceId).get("locationAbsenceCheck")).get("status"))
                .isEqualTo("UNKNOWN");
    }

    @Test
    void requestIsSingleScopeAndIdempotentButUnfinishedRunCannotResolve() {
        var request = new SecretRevalidationRequest(occurrenceId, 0L, 0L, "test-recheck-1");
        var accepted = service.request(caseId, request, "revalidation-admin");
        assertThat(accepted.jobStatus()).isEqualTo("PENDING");
        assertThat(accepted.result()).isEqualTo("PENDING");
        assertThat(service.request(caseId, request, "revalidation-admin").runId())
                .isEqualTo(accepted.runId());
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM secret_run_scopes WHERE run_id = ?
                """, Long.class, accepted.runId())).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT kind FROM secret_jobs WHERE job_id =
                    (SELECT job_id FROM secret_scan_runs WHERE run_id = ?)
                """, String.class, accepted.runId())).isEqualTo("REVALIDATE");
        assertThatThrownBy(() -> service.resolve(caseId,
                new SecretResolveRequest(1L, "POST_ACTION_REVALIDATION"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases WHERE case_id = ?",
                String.class, caseId)).isEqualTo("REVALIDATION_PENDING");
    }

    @Test
    void resolutionRequiresPostActionMissingEvidenceForEveryLocation() {
        var accepted = service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, 0L, "test-recheck-2"),
                "revalidation-admin");
        jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED',
                    detection_status = 'SUCCEEDED', result_status = 'SUCCEEDED',
                    finished_at = clock_timestamp() WHERE run_id = ?
                """, accepted.runId());
        jdbc.update("""
                UPDATE secret_case_revalidations SET status = 'MISSING',
                    finished_at = clock_timestamp() WHERE run_id = ?
                """, accepted.runId());
        jdbc.update("""
                UPDATE secret_occurrences SET presence_status = 'MISSING'
                WHERE occurrence_id = ?
                """, occurrenceId);
        long scopeId = jdbc.queryForObject("""
                SELECT scope_id FROM secret_occurrences WHERE occurrence_id = ?
                """, Long.class, occurrenceId);
        jdbc.update("UPDATE secret_connection_scopes SET enabled = FALSE WHERE scope_id = ?", scopeId);
        assertThatThrownBy(() -> service.resolve(caseId,
                new SecretResolveRequest(1L, "POST_ACTION_REVALIDATION"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_connection_scopes SET enabled = TRUE WHERE scope_id = ?", scopeId);
        assertThatThrownBy(()->service.resolve(caseId,new SecretResolveRequest(1L,"POST_ACTION_REVALIDATION"),"revalidation-admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases WHERE case_id=?",String.class,caseId)).isEqualTo("REVALIDATION_PENDING");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_case_resolutions WHERE case_id=?",Long.class,caseId)).isZero();
    }

    @Test
    void unknownOutcomeDoesNotClaimResolution() {
        var accepted = service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, 0L, "test-recheck-3"),
                "revalidation-admin");
        jdbc.update("""
                UPDATE secret_case_revalidations SET status = 'UNKNOWN',
                    failure_code = 'REVALIDATION_INCOMPLETE', finished_at = clock_timestamp()
                WHERE run_id = ?
                """, accepted.runId());
        assertThatThrownBy(() -> service.resolve(caseId,
                new SecretResolveRequest(1L, "POST_ACTION_REVALIDATION"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
    }

    @Test void coordinatorNeverInheritsLocationOrIncompleteActionRights(){
        jdbc.update("UPDATE secret_case_occurrences SET assigned_user_id=NULL WHERE case_id=?",caseId);
        assertThatThrownBy(()->service.request(caseId,new SecretRevalidationRequest(occurrenceId,0L,0L,"no-own"),"revalidation-admin")).isInstanceOf(ApiException.class);
        long actor=actor();jdbc.update("UPDATE secret_case_occurrences SET assigned_user_id=?,actions_completed_at=NULL WHERE case_id=?",actor,caseId);
        assertThatThrownBy(()->service.request(caseId,new SecretRevalidationRequest(occurrenceId,0L,0L,"incomplete"),"revalidation-admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_case_revalidations",Long.class)).isZero();
    }
    @Test void staleLocationAndRevokedReplayAreRejectedWithoutDuplicateJobs(){
        assertThatThrownBy(()->service.request(caseId,new SecretRevalidationRequest(occurrenceId,0L,2L,"stale"),"revalidation-admin")).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_response_cases SET review_status='UNREVIEWED' WHERE case_id=?",caseId);
        var r=new SecretRevalidationRequest(occurrenceId,0L,0L,"current");service.request(caseId,r,"revalidation-admin");
        jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE role='REMEDIATOR'");
        assertThatThrownBy(()->service.request(caseId,r,"revalidation-admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_case_revalidations",Long.class)).isEqualTo(1);
    }
    @Test void presentRevalidationStartsFreshActionCycleWithoutReusingOldCompletion(){
        var v=service.request(caseId,new SecretRevalidationRequest(occurrenceId,0L,0L,"present"),"revalidation-admin");
        jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=now() WHERE job_id=(SELECT job_id FROM secret_scan_runs WHERE run_id=?)",v.runId());
        jdbc.update("UPDATE secret_case_revalidations SET status='PRESENT',finished_at=now() WHERE run_id=?",v.runId());
        var r=new SecretResumeRequest(occurrenceId,1L,1L,"REVALIDATION_PRESENT","resume");
        service.resume(caseId,r,"revalidation-admin");service.resume(caseId,r,"revalidation-admin");
        var o=jdbc.queryForMap("SELECT * FROM secret_case_occurrences WHERE case_id=? AND occurrence_id=?",caseId,occurrenceId);
        assertThat(o).containsEntry("action_cycle",2L).containsEntry("response_status","IN_PROGRESS").containsEntry("last_material_action_at",null).containsEntry("actions_completed_at",null);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_case_resume_events",Long.class)).isEqualTo(1);
        assertThatThrownBy(()->service.request(caseId,new SecretRevalidationRequest(occurrenceId,2L,2L,"premature"),"revalidation-admin")).isInstanceOf(ApiException.class);
    }
    @Test void independentManualReviewPreservesOriginalAndNeverBecomesProviderProof(){
        long reviewer=reviewer();var submitted=lifecycle.submit(caseId,new com.logssey.secret.lifecycle.SecretLifecycleService.Submission("REVOKED",java.time.OffsetDateTime.now().minusMinutes(2),"CHANGE:SEC-12",0L,"submit"),"revalidation-admin");
        long id=((Number)submitted.get("evidenceId")).longValue();
        var r=new com.logssey.secret.lifecycle.SecretLifecycleService.Review("APPROVE","EXTERNAL_RECORD_CONFIRMED",1L,1L,"approve");
        assertThatThrownBy(()->lifecycle.review(caseId,id,r,"revalidation-admin")).isInstanceOf(ApiException.class);
        lifecycle.review(caseId,id,r,"independent");lifecycle.review(caseId,id,r,"independent");
        assertThat(jdbc.queryForMap("SELECT verification_level,verification_method,version FROM secret_credential_lifecycle_evidence WHERE evidence_id=?",id))
            .containsEntry("verification_level","PENDING").containsEntry("verification_method","EXTERNAL_RECORD").containsEntry("version",1L);
        assertThat(jdbc.queryForObject("SELECT verification_level FROM secret_current_lifecycle_evidence WHERE evidence_id=?",String.class,id)).isEqualTo("APPROVED_MANUAL");
        var json=lifecycle.list(caseId,"revalidation-admin").toString();assertThat(json).contains("LIMITED","APPROVED_MANUAL","PROVIDER_RETIREMENT_NOT_VERIFIED").doesNotContain("auth_ref","fingerprint","source_object_ref");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_lifecycle_evidence_reviews",Long.class)).isEqualTo(1);
        assertThatThrownBy(()->jdbc.update("UPDATE secret_credential_lifecycle_evidence SET kind='ROTATED' WHERE evidence_id=?",id)).isInstanceOf(org.springframework.dao.DataAccessException.class);
        lifecycle.review(caseId,id,new com.logssey.secret.lifecycle.SecretLifecycleService.Review("REJECT","CONTRADICTORY_EVIDENCE",2L,2L,"reject"),"independent");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_current_lifecycle_evidence",Long.class)).isZero();
    }
    @Test void arbitraryProviderEvidenceIsRejectedAtDatabaseBoundary(){
        assertThatThrownBy(()->jdbc.update("""
         INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,verification_method,verification_level,
          provider_validator_id,validator_version,endpoint_class,reason_code,performed_at,observed_at)
         SELECT case_id,credential_set_id,opening_occurrence_id,case_origin,'REVOKED','PROVIDER','PROVIDER_VERIFIED','FAKE','1','AWS_STS',
          'CONFIRMED_KEY_RETIRED',now(),now() FROM secret_response_cases WHERE case_id=?
         """,caseId)).isInstanceOf(org.springframework.dao.DataAccessException.class).hasMessageContaining("TRUSTED_LIFECYCLE_WRITER_REQUIRED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_lifecycle_evidence",Long.class)).isZero();
    }
    @Test void repositoryNameAndTestLabelNeverProveSyntheticFixture(){
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Logssey/test-find-key/develop/fixtures/'");
        var response = guide.guide(caseId, "revalidation-admin");
        assertThat(response.source()).isEqualTo("DEFAULT");
        assertThat(response.readiness().reasonCode()).isEqualTo("SYNTHETIC_FIXTURE_REQUIRED");
        assertThat(response.readiness().providerCalled()).isFalse();
        assertThatThrownBy(()->lifecycle.submit(caseId,new com.logssey.secret.lifecycle.SecretLifecycleService.Submission("FIXTURE_RETIRED",java.time.OffsetDateTime.now().minusMinutes(1),"CHANGE:SEC-2",0L,"fake-fixture"),"revalidation-admin")).isInstanceOf(ApiException.class);
    }
    @Test void onlyExactApprovedFixtureCanSelectExternalGuideAndRealProofImmediatelyDisablesIt(){
        long key=jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id=?",Long.class,caseId);
        long scope=jdbc.queryForObject("SELECT scope_id FROM secret_occurrences WHERE occurrence_id=?",Long.class,occurrenceId);
        jdbc.update("UPDATE secret_credential_sets SET fingerprint=decode(repeat('ab',32),'hex') WHERE credential_set_id=?",key);
        long manifest=jdbc.queryForObject("INSERT INTO secret_fixture_manifests(version,protected_manifest_ref,approval_status,valid_from,valid_until) VALUES(1,'FIXTURE:SAFE','DRAFT',now()-INTERVAL '1 day',now()+INTERVAL '1 day') RETURNING manifest_id",Long.class);
        jdbc.update("INSERT INTO secret_fixture_manifest_identities(manifest_id,manifest_version,scope_id,scope_revision,issuer,credential_type,fingerprint_key_version,protected_fingerprint) SELECT ?,1,?,1,issuer,credential_type,fingerprint_key_version,fingerprint FROM secret_credential_sets WHERE credential_set_id=?",manifest,scope,key);
        jdbc.update("UPDATE secret_fixture_manifests SET approval_status='APPROVED',approved_by_user_id=? WHERE manifest_id=?",actor(),manifest);
        long rs=jdbc.queryForObject("SELECT rs.run_scope_id FROM secret_run_scopes rs JOIN secret_occurrences o ON o.last_seen_run_id=rs.run_id WHERE o.occurrence_id=?",Long.class,occurrenceId);
        long match=jdbc.queryForObject("INSERT INTO secret_fixture_match_evidence(credential_set_id,scope_id,scope_revision,manifest_id,manifest_version,run_scope_id,comparator_id,comparator_version,match_result,observed_at) VALUES(?,?,1,?,1,?,'LOGSSEY_PROTECTED_IDENTITY','1','MATCH',now()) RETURNING match_evidence_id",Long.class,key,scope,manifest,rs);
        fixtureService.attest("revalidation-admin",key,new com.logssey.secret.fixture.SecretFixtureService.Attest(scope,1L,manifest,1L,match,"exact"));
        var calls=new java.util.concurrent.atomic.AtomicInteger();
        var localGuide=new SecretGuideService(caseRepository,guideRepository,context->{calls.incrementAndGet();return java.util.Optional.of(java.util.List.of("VERIFY_EXPOSURE","EXTERNAL_ROTATION","RECORD_ACTION","REVALIDATE"));});
        assertThat(localGuide.guide(caseId,"revalidation-admin").source()).isEqualTo("GROQ");assertThat(calls.get()).isEqualTo(1);
        long reviewer=reviewer();var submitted=lifecycle.submit(caseId,new com.logssey.secret.lifecycle.SecretLifecycleService.Submission("FIXTURE_RETIRED",java.time.OffsetDateTime.now().minusSeconds(2),"CHANGE:SEC-14",0L,"fixture-retired"),"revalidation-admin");
        long evidence=((Number)submitted.get("evidenceId")).longValue();
        lifecycle.review(caseId,evidence,new com.logssey.secret.lifecycle.SecretLifecycleService.Review("APPROVE","EXTERNAL_RECORD_CONFIRMED",1L,1L,"fixture-review"),"independent");
        assertThat(lifecycle.locationCheck(new com.logssey.secret.access.SecretPrincipal(actor()),occurrenceId).get("coverageLimit")).isEqualTo("SIMULATION");
        jdbc.update("INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code) SELECT ?,run_id,job_id,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),'VALID','AUTHENTICATED' FROM secret_scan_runs WHERE run_id=(SELECT last_seen_run_id FROM secret_occurrences WHERE occurrence_id=?)",key,occurrenceId);
        assertThat(localGuide.guide(caseId,"revalidation-admin").source()).isEqualTo("DEFAULT");assertThat(calls.get()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_current_lifecycle_evidence WHERE evidence_id=?",Long.class,evidence)).isZero();
    }
    @Test void laterProviderAuthenticationContradictsManualRetirementAndAnApprovalCannotOverrideIt(){
        reviewer();var submitted=lifecycle.submit(caseId,new com.logssey.secret.lifecycle.SecretLifecycleService.Submission("RETIRED",java.time.OffsetDateTime.now().minusMinutes(2),"CHANGE:SEC-15",0L,"retired"),"revalidation-admin");
        long evidence=((Number)submitted.get("evidenceId")).longValue();
        jdbc.update("INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code) SELECT credential_set_id,last_seen_run_id,(SELECT job_id FROM secret_scan_runs WHERE run_id=o.last_seen_run_id),'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),'VALID','AUTHENTICATED' FROM secret_occurrences o WHERE occurrence_id=?",occurrenceId);
        assertThatThrownBy(()->lifecycle.review(caseId,evidence,new com.logssey.secret.lifecycle.SecretLifecycleService.Review("APPROVE","EXTERNAL_RECORD_CONFIRMED",1L,1L,"contradiction"),"independent")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_lifecycle_evidence_reviews",Long.class)).isZero();
    }

    @Test void validationBeforeMaterialActionIsHistoryUntilAFreshProviderObservationArrives(){
        long key=jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id=?",Long.class,caseId);
        var beforeAction=jdbc.queryForObject("SELECT clock_timestamp()-interval '30 minutes'",java.time.OffsetDateTime.class);
        long previous=validation(beforeAction);
        var filter=new com.logssey.secret.query.SecretInventoryFilters("TEST","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var before=locations.locations("revalidation-admin",key,filter,0,20,"ALL","ALL","ALL",null);
        var item=(java.util.Map<?,?>)((java.util.List<?>)before.get("items")).getFirst();var validity=(java.util.Map<?,?>)item.get("validity");
        assertThat(validity.get("result")).isEqualTo("UNCHECKED");assertThat(validity.get("reasonCode")).isEqualTo("POST_ACTION_VALIDATION_REQUIRED");
        assertThat(((java.util.Map<?,?>)validity.get("lastObservation")).get("result")).isEqualTo("VALID");assertThat(validity.get("observedAt")).isNull();
        assertThat(item.get("lastMaterialActionAt")).isNotNull();assertThat(item.get("fixtureStatus")).isEqualTo("NOT_APPLICABLE");
        validation(jdbc.queryForObject("SELECT clock_timestamp()",java.time.OffsetDateTime.class));
        var after=locations.locations("revalidation-admin",key,filter,0,20,"ALL","ALL","ALL",null);
        assertThat(((java.util.Map<?,?>)((java.util.Map<?,?>)((java.util.List<?>)after.get("items")).getFirst()).get("validity")).get("result")).isEqualTo("VALID");
        assertThat(jdbc.queryForObject("SELECT provider_checked_at FROM secret_validation_attempts WHERE attempt_id=?",java.time.OffsetDateTime.class,previous)).isEqualTo(beforeAction);
    }

    private long validation(java.time.OffsetDateTime observed){
        var source=jdbc.queryForMap("SELECT r.job_id,r.run_id FROM secret_occurrences o JOIN secret_scan_runs r ON r.run_id=o.last_seen_run_id WHERE o.occurrence_id=?",occurrenceId);
        return com.logssey.secret.validation.SecretValidationTestFixtures.completed(jdbc,occurrenceId,((Number)source.get("job_id")).longValue(),((Number)source.get("run_id")).longValue(),"VALID","AUTHENTICATED",observed.minusSeconds(1),observed.plusSeconds(1),observed);
    }

    @Test void evidencedAlertClosureDoesNotReopenUntilAContradictoryProviderObservation(){
        reviewer();jdbc.update("UPDATE secret_run_scopes SET detection_stage_status='SUCCEEDED',validation_stage_status='SKIPPED',validation_required=false");
        jdbc.update("""
         INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code)
         SELECT credential_set_id,last_seen_run_id,(SELECT job_id FROM secret_scan_runs WHERE run_id=o.last_seen_run_id),'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',
          now()-INTERVAL '3 minutes',now()-INTERVAL '3 minutes',now()-INTERVAL '3 minutes','VALID','AUTHENTICATED'
         FROM secret_occurrences o WHERE occurrence_id=?
         """,occurrenceId);
        jdbc.queryForObject("SELECT secret_reconcile_test_alerts(NULL)",Long.class);
        long alert=jdbc.queryForObject("SELECT alert_id FROM secret_cross_environment_alerts",Long.class);
        var submitted=lifecycle.submit(caseId,new com.logssey.secret.lifecycle.SecretLifecycleService.Submission("REVOKED",java.time.OffsetDateTime.now().minusMinutes(1),"CHANGE:SEC-16",0L,"retirement-for-alert"),"revalidation-admin");
        long evidence=((Number)submitted.get("evidenceId")).longValue();
        lifecycle.review(caseId,evidence,new com.logssey.secret.lifecycle.SecretLifecycleService.Review("APPROVE","EXTERNAL_RECORD_CONFIRMED",1L,1L,"alert-review"),"independent");
        alerts.close("revalidation-admin",alert,new com.logssey.secret.alert.SecretCrossEnvironmentAlertRequests.Close(0L,"CREDENTIAL_RETIRED",null,null,java.util.List.of(evidence),caseId,null,"close-real-alert"));
        assertThat(jdbc.queryForObject("SELECT secret_reconcile_test_alerts(NULL)",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_cross_environment_alerts",Long.class)).isEqualTo(1);
        jdbc.update("UPDATE secret_validation_attempts SET provider_checked_at=statement_timestamp(),completed_at=statement_timestamp()");
        jdbc.queryForObject("SELECT secret_reconcile_test_alerts(NULL)",Long.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_cross_environment_alerts",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT previous_alert_id FROM secret_cross_environment_alerts WHERE closed_at IS NULL",Long.class)).isEqualTo(alert);
    }

    private long actor(){return jdbc.queryForObject("SELECT user_id FROM dashboard_users WHERE login_id='revalidation-admin'",Long.class);}
    private long reviewer(){
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name) VALUES('independent','unused','Reviewer') ON CONFLICT(login_id) DO NOTHING");
        long id=jdbc.queryForObject("SELECT user_id FROM dashboard_users WHERE login_id='independent'",Long.class);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(?,'SECURITY',?,'MANUAL')",id,actor());return id;
    }

    @Test
    void revalidationEndpointNeedsSessionAndCsrf() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(webContext).apply(springSecurity()).build();
        String body = "{\"occurrenceId\":" + occurrenceId
                + ",\"expectedCaseVersion\":0,\"expectedOccurrenceVersion\":0,\"idempotencyKey\":\"browser-recheck\"}";
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/revalidations", caseId)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"revalidation-admin\",\"password\":\"revalidation-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(session).isNotNull();
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/revalidations", caseId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/revalidations", caseId)
                        .session(session).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.jobStatus").value("PENDING"));
    }
}
