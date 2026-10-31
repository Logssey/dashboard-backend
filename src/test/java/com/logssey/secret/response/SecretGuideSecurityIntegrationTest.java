package com.logssey.secret.response;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.admin.login-id=guide-admin",
        "logssey.admin.password=guide-pass",
        "logssey.admin.display-name=Guide Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team=",
        "logssey.secret.guide.groq.enabled=false"
})
class SecretGuideSecurityIntegrationTest {
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
    @Autowired private SecretGuideRepository guideRepository;
    @Autowired private WebApplicationContext context;

    private long actorId;
    private long caseId;

    @BeforeEach
    void seedCase() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE secret_role_grants, secret_team_memberships RESTART IDENTITY");
        actorId = jdbc.queryForObject("SELECT user_id FROM dashboard_users WHERE login_id = 'guide-admin'",
                Long.class);
        long connectionId = jdbc.queryForObject("""
                INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Test', 'test-ref', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class);
        long scopeId = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, enabled,
                     history_limit, response_origin, response_origin_set_by_user_id,
                     response_origin_set_at)
                VALUES (?, 'fixture', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://Other/fixture/main/src/', TRUE, 'CURRENT_COMMIT_ONLY',
                        'TEST', ?, now()) RETURNING scope_id
                """, Long.class, connectionId, actorId);
        long secretId = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, fingerprint_key_version,
                     masked_label, first_seen_at, last_seen_at)
                VALUES ('AWS', 'AWS_ACCESS_KEY_PAIR', 'CONFIRMED', decode(md5(random()::text), 'hex'),
                        'test', 'AWS ••••1234', now(), now()) RETURNING credential_set_id
                """, Long.class);
        long occurrenceId = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, 'repo/test.txt', 'L1', 'UNKNOWN', 'ABNORMAL', 'UNKNOWN',
                        'PRESENT', now(), now()) RETURNING occurrence_id
                """, Long.class, secretId, connectionId, scopeId);
        caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id,
                     opening_reason, case_origin)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'TEST') RETURNING case_id
                """, Long.class, secretId, occurrenceId, actorId);
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, occurrenceId, secretId);
    }

    @Test
    void sessionCsrfAndCaseRoleProtectReadOnlyGuide() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", caseId).with(csrf()))
                .andExpect(status().isUnauthorized());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"guide-admin\",\"password\":\"guide-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", caseId).session(session))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", caseId)
                        .session(session).with(csrf()))
                .andExpect(status().isForbidden());

        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                VALUES (?, 'REMEDIATOR', ?, 'MANUAL')
                """, actorId, actorId);
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", caseId)
                        .session(session).with(csrf()))
                .andExpect(status().isForbidden());

        jdbc.update("UPDATE secret_case_occurrences SET assigned_user_id = ? WHERE case_id = ?",
                actorId, caseId);
        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", caseId)
                        .session(session).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.source").value("DEFAULT"))
                .andExpect(jsonPath("$.steps[0].code").value("VERIFY_EXPOSURE"));
        assertThat(guideRepository.currentCase(caseId).orElseThrow().syntheticFixture()).isFalse();
        jdbc.update("""
                UPDATE secret_connection_scopes
                SET approved_ref = 'github://Logssey/test-find-key/develop/fixtures/'
                WHERE scope_key = 'fixture'
                """);
        assertThat(guideRepository.currentCase(caseId).orElseThrow().syntheticFixture()).isFalse();
        assertThat(jdbc.queryForObject("SELECT version FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events WHERE case_id = ?",
                Long.class, caseId)).isZero();
    }
}
