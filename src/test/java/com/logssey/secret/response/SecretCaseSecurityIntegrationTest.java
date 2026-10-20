package com.logssey.secret.response;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.admin.login-id=case-admin",
        "logssey.admin.password=case-pass",
        "logssey.admin.display-name=Case Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team="
})
class SecretCaseSecurityIntegrationTest {
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

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private SecretCaseService service;

    @Autowired
    private WebApplicationContext context;

    private long actorId;
    private long caseId;

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE secret_role_grants, secret_team_memberships RESTART IDENTITY");
        actorId = jdbc.queryForObject("SELECT user_id FROM dashboard_users WHERE login_id = 'case-admin'",
                Long.class);
        long connection = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Test', 'test-ref', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class);
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, enabled,
                     history_limit, response_origin, response_origin_set_by_user_id,
                     response_origin_set_at)
                VALUES (?, 'fixture', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://Other/fixture/main/src/', TRUE, 'CURRENT_COMMIT_ONLY',
                        'TEST', ?, now())
                RETURNING scope_id
                """, Long.class, connection, actorId);
        long secret = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, fingerprint_key_version,
                     masked_label, first_seen_at, last_seen_at)
                VALUES ('AWS', 'AWS_ACCESS_KEY_PAIR', 'CONFIRMED', decode(md5(random()::text), 'hex'),
                        'test', 'AWS ••••1234', now(), now()) RETURNING credential_set_id
                """, Long.class);
        long occurrence = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, 'repo/test.txt', 'L1', 'UNKNOWN', 'ABNORMAL', 'UNKNOWN',
                        'PRESENT', now(), now()) RETURNING occurrence_id
                """, Long.class, secret, connection, scope);
        caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id,
                     opening_reason, case_origin)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'TEST') RETURNING case_id
                """, Long.class, secret, occurrence, actorId);
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, occurrence, secret);
    }

    @Test
    void operationsBootstrapRequiresExplicitExistingAccountAndPreservesRevocation() {
        jdbc.update("""
                INSERT INTO dashboard_users(login_id,password_hash,display_name,role)
                VALUES ('operations-bootstrap','hash','Operations','ADMIN')
                ON CONFLICT (login_id) DO NOTHING
                """);
        var bootstrap = new SecretRoleBootstrap(jdbc, "case-admin", "", "", "operations-bootstrap");
        bootstrap.grantConfiguredRoles();
        bootstrap.grantConfiguredRoles();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM secret_role_grants g
                JOIN dashboard_users u ON u.user_id=g.user_id
                WHERE u.login_id='operations-bootstrap' AND g.role='OPERATIONS' AND g.revoked_at IS NULL
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM secret_role_grants g
                JOIN dashboard_users u ON u.user_id=g.user_id
                WHERE u.login_id='operations-bootstrap' AND g.role IN ('SECURITY','REMEDIATOR')
                """, Long.class)).isZero();
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE role='OPERATIONS'");
        bootstrap.grantConfiguredRoles();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_role_grants WHERE role='OPERATIONS' AND revoked_at IS NULL",
                Long.class)).isZero();
    }

    @Test
    void invalidOperationsBootstrapDoesNotPartiallyGrantRoles() {
        assertThatThrownBy(() -> new SecretRoleBootstrap(jdbc, "case-admin", "", "", "missing-account")
                .grantConfiguredRoles()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SecretRoleBootstrap(jdbc, "", "", "", "case-admin")
                .grantConfiguredRoles()).isInstanceOf(IllegalStateException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_role_grants", Long.class)).isZero();
    }

    @Test
    void sessionCsrfAndSecretRoleAreEnforcedByRealSecurityFilter() throws Exception {
        MockMvc mvc = mvc();
        mvc.perform(get("/api/v1/secrets/cases?origin=TEST"))
                .andExpect(status().isUnauthorized());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"case-admin\",\"password\":\"case-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(session).isNotNull();
        mvc.perform(get("/api/v1/secrets/cases?origin=TEST").session(session))
                .andExpect(status().isForbidden());

        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL'), (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actorId, actorId, actorId, actorId);
        mvc.perform(get("/api/v1/secrets/cases?origin=TEST").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].caseOrigin").value("TEST"));
        String body = "{\"team\":null,\"assigneeUserId\":" + actorId
                + ",\"reasonCode\":\"INITIAL_ASSIGNMENT\",\"expectedVersion\":0}";
        mvc.perform(patch("/api/v1/secrets/cases/{caseId}/assignment", caseId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(patch("/api/v1/secrets/cases/{caseId}/assignment", caseId)
                        .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1))
                .andExpect(jsonPath("$.assigneeUserId").value(actorId));
    }

    @Test
    void triageMutationsRequireSessionCsrfAndSecurityGrant() throws Exception {
        long scopeId = jdbc.queryForObject("SELECT scope_id FROM secret_connection_scopes", Long.class);
        long occurrenceId = jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences", Long.class);
        MockMvc mvc = mvc();
        mvc.perform(get("/api/v1/secrets/scopes/{scopeId}/response-origin", scopeId))
                .andExpect(status().isUnauthorized());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"case-admin\",\"password\":\"case-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        String classify = "{\"origin\":\"TEST\",\"reasonCode\":\"APPROVED_TEST_FIXTURE\",\"expectedVersion\":0}";
        String assess = "{\"decision\":\"ABNORMAL\",\"reasonCode\":\"SIMULATED_EXPOSURE\",\"findingId\":1,\"expectedVersion\":0}";
        mvc.perform(get("/api/v1/secrets/triage-candidates").session(session))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/secrets/scopes/{scopeId}/response-origin", scopeId)
                        .session(session))
                .andExpect(status().isForbidden());
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL')
                """, actorId, actorId);
        mvc.perform(get("/api/v1/secrets/triage-candidates").session(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(1));
        mvc.perform(get("/api/v1/secrets/occurrences/{occurrenceId}/triage", occurrenceId)
                        .session(session))
                .andExpect(status().isOk());
        mvc.perform(patch("/api/v1/secrets/scopes/{scopeId}/response-origin", scopeId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(classify))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/secrets/occurrences/{occurrenceId}/assessments", occurrenceId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(assess))
                .andExpect(status().isForbidden());
        mvc.perform(patch("/api/v1/secrets/scopes/{scopeId}/response-origin", scopeId)
                        .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content(classify))
                .andExpect(status().isConflict());
    }

    @Test
    void auditInsertFailureRollsBackAssignmentAndVersionThroughSpringTransaction() {
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL'), (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actorId, actorId, actorId, actorId);
        jdbc.execute("""
                CREATE OR REPLACE FUNCTION test_reject_assignment_audit() RETURNS trigger AS $$
                BEGIN
                    IF NEW.event_type = 'ASSIGNMENT_CHANGED' THEN
                        RAISE EXCEPTION 'injected audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """);
        jdbc.execute("""
                CREATE TRIGGER test_reject_assignment_audit
                BEFORE INSERT ON secret_audit_events
                FOR EACH ROW EXECUTE FUNCTION test_reject_assignment_audit()
                """);
        try {
            assertThatThrownBy(() -> service.assign(caseId,
                    new SecretAssignmentRequest(null, actorId, "INITIAL_ASSIGNMENT", 0L),
                    "case-admin")).isInstanceOf(DataAccessException.class);
            assertThat(jdbc.queryForObject(
                    "SELECT version FROM secret_response_cases WHERE case_id = ?", Long.class, caseId))
                    .isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_assignment_history", Long.class))
                    .isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events", Long.class))
                    .isZero();
        } finally {
            jdbc.execute("DROP TRIGGER IF EXISTS test_reject_assignment_audit ON secret_audit_events");
            jdbc.execute("DROP FUNCTION IF EXISTS test_reject_assignment_audit()");
        }
    }

    @Test
    void legacyReviewIsBlockedAndLocationActionRequiresCsrfWithoutSecondApproval() throws Exception {
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL'), (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actorId, actorId, actorId, actorId);
        service.assign(caseId,
                new SecretAssignmentRequest(null, actorId, "INITIAL_ASSIGNMENT", 0L),
                "case-admin");
        MockMvc mvc = mvc();
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"case-admin\",\"password\":\"case-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        String review = "{\"decision\":\"CONFIRMED\",\"reasonCode\":\"EVIDENCE_CONFIRMED\",\"expectedVersion\":1}";
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/review", caseId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(review))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/review", caseId)
                        .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(review))
                .andExpect(status().isConflict());
        long occurrenceId = jdbc.queryForObject(
                "SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        String assignment="{\"team\":null,\"assigneeUserId\":"+actorId+",\"reasonCode\":\"INITIAL_ASSIGNMENT\",\"expectedCaseVersion\":1,\"expectedOccurrenceVersion\":0}";
        mvc.perform(patch("/api/v1/secrets/cases/{caseId}/occurrences/{occurrenceId}/assignment",caseId,occurrenceId)
                .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(assignment))
                .andExpect(status().isOk());
        String action = "{\"actionType\":\"ROTATED\",\"occurrenceId\":" + occurrenceId
                + ",\"performedAt\":\"" + OffsetDateTime.now(ZoneOffset.UTC)
                + "\",\"evidenceRef\":\"TICKET:SEC-123\",\"expectedCaseVersion\":2,\"expectedOccurrenceVersion\":1,\"idempotencyKey\":\"http-action\"}";
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/actions", caseId)
                        .session(session).contentType(MediaType.APPLICATION_JSON).content(action))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/actions", caseId)
                        .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(action))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.requiresSnapshotRefresh").value(true));
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/actions", caseId)
                        .session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(action))
                .andExpect(status().isOk());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_action_records",Long.class)).isEqualTo(1);
    }

    @Test
    void failedActionAuditRollsBackCaseLocationAndActionRecord() {
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, 'MANUAL'), (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actorId, actorId, actorId, actorId);
        service.assign(caseId,
                new SecretAssignmentRequest(null, actorId, "INITIAL_ASSIGNMENT", 0L),
                "case-admin");
        service.review(caseId,
                new SecretCaseReviewRequest("CONFIRMED", "EVIDENCE_CONFIRMED", 1L),
                "case-admin");
        jdbc.execute("""
                CREATE OR REPLACE FUNCTION test_reject_action_audit() RETURNS trigger AS $$
                BEGIN
                    IF NEW.event_type = 'ACTION_RECORDED' THEN
                        RAISE EXCEPTION 'injected audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """);
        jdbc.execute("""
                CREATE TRIGGER test_reject_action_audit
                BEFORE INSERT ON secret_audit_events
                FOR EACH ROW EXECUTE FUNCTION test_reject_action_audit()
                """);
        try {
            long occurrenceId = jdbc.queryForObject(
                    "SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id = ?",
                    Long.class, caseId);
            assertThatThrownBy(() -> service.action(caseId,
                    new SecretActionRequest("ROTATED", occurrenceId,
                            OffsetDateTime.now(ZoneOffset.UTC), "TICKET:SEC-123", 2L),
                    "case-admin")).isInstanceOf(DataAccessException.class);
            assertThat(jdbc.queryForObject(
                    "SELECT version FROM secret_response_cases WHERE case_id = ?", Long.class, caseId))
                    .isEqualTo(2);
            assertThat(jdbc.queryForObject(
                    "SELECT action_status FROM secret_response_cases WHERE case_id = ?",
                    String.class, caseId)).isEqualTo("OPEN");
            assertThat(jdbc.queryForObject(
                    "SELECT response_status FROM secret_case_occurrences WHERE case_id = ?",
                    String.class, caseId)).isEqualTo("OPEN");
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_action_records", Long.class))
                    .isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_case_stage_history", Long.class))
                    .isZero();
        } finally {
            jdbc.execute("DROP TRIGGER IF EXISTS test_reject_action_audit ON secret_audit_events");
            jdbc.execute("DROP FUNCTION IF EXISTS test_reject_action_audit()");
        }
    }

    private MockMvc mvc() {
        return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }
}
