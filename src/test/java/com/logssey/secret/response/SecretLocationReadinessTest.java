package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.access.SecretRole;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class SecretLocationReadinessTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final SecretAccessService access = mock(SecretAccessService.class);
    private final SecretPrincipal actor = new SecretPrincipal(7);
    private final Map<String, Object> row = new HashMap<>();

    @BeforeEach
    void fixture() {
        var actionAt = OffsetDateTime.parse("2026-11-06T01:00:00Z");
        row.putAll(
                Map.of(
                        "connection_id",
                        9L,
                        "assigned_user_id",
                        7L,
                        "is_current",
                        true,
                        "disposition",
                        "IN_SCOPE",
                        "action_status",
                        "IN_PROGRESS",
                        "response_status",
                        "REVALIDATION_PENDING",
                        "component_state",
                        "CONFIRMED",
                        "fingerprint_key_version",
                        "v1",
                        "provider",
                        "NOTION"));
        row.putAll(
                Map.of(
                        "auth_ref",
                        "notion-internal:default",
                        "enabled",
                        true,
                        "connection_status",
                        "ACTIVE",
                        "content_type",
                        "NOTION_PAGE_CONTENT",
                        "history_limit",
                        "CURRENT_VERSION_ONLY",
                        "approved_ref",
                        "notion://pages/11111111-2222-3333-4444-555555555555",
                        "case_origin",
                        "PRODUCTION",
                        "response_origin",
                        "PRODUCTION"));
        row.put("actions_completed_at", actionAt);
        row.put("last_material_action_at", actionAt);
        row.put("source_context_current", true);
        row.put("revalidation_context_current", true);
        when(jdbc.queryForList(anyString(), eq(31L), eq(12L))).thenReturn(List.of(row));
        when(access.hasConnectionRole(actor, 9L, SecretRole.REMEDIATOR)).thenReturn(true);
    }

    @Test
    void disabledNotionCollectionCannotQueueALocationRecheck() {
        var result = new SecretLocationReadiness(jdbc, access).capabilities(actor, 31, 12);
        assertThat(result)
                .containsEntry("canRequestRevalidation", false)
                .containsEntry("revalidationBlockReasonCode", "SOURCE_REVALIDATION_UNSUPPORTED");
    }

    @Test
    void enabledNotionCollectionStillRequiresTheConfiguredCredentialReference() {
        row.put("auth_ref", "notion-internal:other");
        var result = new SecretLocationReadiness(jdbc, access, true).capabilities(actor, 31, 12);
        assertThat(result)
                .containsEntry("canRequestRevalidation", false)
                .containsEntry("revalidationBlockReasonCode", "SCOPE_UNAVAILABLE");
    }

    @Test
    void enabledApprovedNotionConnectionCanQueueALocationRecheck() {
        var result = new SecretLocationReadiness(jdbc, access, true).capabilities(actor, 31, 12);
        assertThat(result)
                .containsEntry("canRequestRevalidation", true)
                .containsEntry("revalidationBlockReasonCode", null);
    }

    @Test
    void githubRechecksRetainTheirExistingEligibilityWithNotionDisabled() {
        row.put("provider", "GITHUB");
        row.put("content_type", "GITHUB_REPOSITORY_FILES");
        row.put("history_limit", "CURRENT_COMMIT_ONLY");
        row.put("approved_ref", "github://acme/repo/main/config/");
        row.put("auth_ref", "existing-github-reference");
        assertThat(new SecretLocationReadiness(jdbc, access).capabilities(actor, 31, 12))
                .containsEntry("canRequestRevalidation", true);
    }

    @Test
    void legacyNotionMissingResultsDoNotProveLocationAbsence() {
        row.putAll(
                Map.of(
                        "revalidation_status",
                        "MISSING",
                        "presence_status",
                        "MISSING",
                        "same_identity",
                        true,
                        "scope_version",
                        1L,
                        "revalidation_connection_version",
                        1L,
                        "latest_scope_run_id",
                        2L,
                        "revalidation_run_id",
                        2L,
                        "action_cycle",
                        1L,
                        "revalidation_cycle",
                        1L));
        row.putAll(
                Map.of(
                        "revision",
                        1L,
                        "revalidation_revision",
                        1L,
                        "response_origin_version",
                        1L,
                        "revalidation_origin_version",
                        1L,
                        "location_version",
                        1L,
                        "revalidation_occurrence_version",
                        1L));
        row.put("revalidation_completed_at", row.get("actions_completed_at"));
        row.put("revalidation_action_at", row.get("last_material_action_at"));
        var result = new SecretLocationReadiness(jdbc, access, true).capabilities(actor, 31, 12);
        assertThat(((Map<?, ?>) result.get("locationAbsenceCheck")).get("status"))
                .isEqualTo("UNKNOWN");
        row.put("provider", "GITHUB");
        assertThat(
                        ((Map<?, ?>)
                                        new SecretLocationReadiness(jdbc, access)
                                                .capabilities(actor, 31, 12)
                                                .get("locationAbsenceCheck"))
                                .get("status"))
                .isEqualTo("PASSED");
    }
}
