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
        "logssey.admin.login-id=revalidation-admin",
        "logssey.admin.password=revalidation-pass",
        "logssey.admin.display-name=Revalidation Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-remediator-login-id="
})
class SecretRevalidationServiceIntegrationTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");

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
    }

    @Test
    void requestIsSingleScopeAndIdempotentButUnfinishedRunCannotResolve() {
        var request = new SecretRevalidationRequest(occurrenceId, 0L, "test-recheck-1");
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
                new SecretRevalidationRequest(occurrenceId, 0L, "test-recheck-2"),
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
        var resolved = service.resolve(caseId,
                new SecretResolveRequest(1L, "POST_ACTION_REVALIDATION"),
                "revalidation-admin");
        assertThat(resolved.stage()).isEqualTo("RESOLVED");
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM secret_case_resolution_locations WHERE case_id = ?
                """, Long.class, caseId)).isEqualTo(1);
        assertThatThrownBy(() -> service.resolve(caseId,
                new SecretResolveRequest(2L, "POST_ACTION_REVALIDATION"),
                "revalidation-admin")).isInstanceOf(ApiException.class);
    }

    @Test
    void unknownOutcomeDoesNotClaimResolution() {
        var accepted = service.request(caseId,
                new SecretRevalidationRequest(occurrenceId, 0L, "test-recheck-3"),
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

    @Test
    void revalidationEndpointNeedsSessionAndCsrf() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(webContext).apply(springSecurity()).build();
        String body = "{\"occurrenceId\":" + occurrenceId
                + ",\"expectedVersion\":0,\"idempotencyKey\":\"browser-recheck\"}";
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
