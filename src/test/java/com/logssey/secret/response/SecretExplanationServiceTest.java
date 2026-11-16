package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.logssey.secret.run.SecretRunCoverageResponse;
import com.logssey.secret.run.SecretRunQueryService;
import com.logssey.secret.run.SecretRunScopeResultResponse;
import com.logssey.secret.run.SecretRunService;
import com.logssey.secret.run.SecretRunStatusResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

class SecretExplanationServiceTest {
    private final SecretLocationWorkflow cases = mock(SecretLocationWorkflow.class);
    private final SecretCaseRepository repository = mock(SecretCaseRepository.class);
    private final SecretGuideRepository guides = mock(SecretGuideRepository.class);
    private final SecretRunService runs = mock(SecretRunService.class);
    private final SecretRunQueryService runQueries = mock(SecretRunQueryService.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final ClaudeSecretGuideProvider provider = mock(ClaudeSecretGuideProvider.class);
    private final ObjectProvider<ClaudeSecretGuideProvider> providers = mock(ObjectProvider.class);
    private final SecretExplanationService service = new SecretExplanationService(runs,
            runQueries, cases, repository, guides, jdbc, providers);

    @Test void readinessAndPartialLocationAccessDoNotDispatchAnExternalRequest() {
        prepare(false);
        var result = service.responseCase(12, "security", true);
        assertThat(result.source()).isEqualTo("DEFAULT");
        assertThat(result.readiness().reasonCode()).isEqualTo("ALL_LOCATIONS_ACCESS_REQUIRED");
        verify(provider, never()).explain(any());

        prepare(true);
        assertThat(service.responseCase(12, "security", false).readiness().status()).isEqualTo("READY");
        verify(provider, never()).explain(any());
    }

    @Test void checksTheCurrentVersionAfterTheModelResponds() {
        var detail = prepare(true);
        var changed = new LinkedHashMap<>(detail);
        changed.put("version", 2L);
        when(cases.detail(12, "security")).thenReturn(detail, changed);
        generated("RECORD_ACTION");
        var result = service.responseCase(12, "security", true);
        assertThat(result.source()).isEqualTo("DEFAULT");
        assertThat(result.readiness().reasonCode()).isEqualTo("CONTEXT_CHANGED");
        assertThat(result.readiness().providerCalled()).isTrue();
    }

    @Test void keepsIdentifiersLocalAndUsesTheRealCaseActionAnchor() {
        prepare(true);
        generated("RECORD_ACTION");
        var result = service.responseCase(12, "security", true);
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::href)
                .containsExactly("/secrets/cases/12?tab=work#case-action-form");
        var argument = org.mockito.ArgumentCaptor.forClass(SecretExplanationContext.class);
        verify(provider).explain(argument.capture());
        assertThat(argument.getValue().externalFields()).doesNotContainKeys("caseId", "name", "path", "href", "login");
        assertThat(result.documents()).extracting(SecretExplanationResponse.Document::id).containsExactly("GITHUB_PAT");
    }

    @Test void anAssignedCoordinatorStillNeedsToAssignUnownedResponseLocations() {
        var detail = prepare(true);
        var location = location(null, null, false, false);
        location.put("canAssign", true);
        detail.put("occurrences", List.of(location));
        detail.put("taskGuidance", guidance("ASSIGN_LOCATION", true));
        var result = service.responseCase(12, "security", false);
        assertThat(result.facts()).extracting(SecretExplanationResponse.Fact::code).contains("ASSIGNEE_REQUIRED");
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::code).containsExactly("ASSIGN_SELF");
        assertThat(result.actions().getFirst().href()).isEqualTo("/secrets/cases/12?tab=work#case-assignment");
    }

    @Test void locationAssignmentsAndCapabilitiesOverrideCoarseCaseFlags() {
        var detail = prepare(true);
        detail.put("assigneeUserId", null);
        detail.put("capabilities", Map.of("canReview", true, "canRecordAction", true, "canRequestRevalidation", true));
        detail.put("occurrences", List.of(location(null, "responders", false, false)));
        detail.put("taskGuidance", guidance("REQUEST_REVALIDATION", false));
        var result = service.responseCase(12, "security", false);
        assertThat(result.facts()).extracting(SecretExplanationResponse.Fact::code).doesNotContain("ASSIGNEE_REQUIRED");
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::code).containsExactly("OPEN_CASE");
    }

    @Test void locationRecheckUsesTheRealAnchorAndClosureWaitsForItsActualNextStep() {
        var detail = prepare(true);
        detail.put("occurrences", List.of(location(7L, null, false, true)));
        detail.put("taskGuidance", guidance("REQUEST_REVALIDATION", true));
        var result = service.responseCase(12, "security", false);
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::code).containsExactly("REVALIDATE");
        assertThat(result.actions().getFirst().href())
                .isEqualTo("/secrets/cases/12?tab=verification&check=locations#case-verification-title");
        detail.put("taskGuidance", guidance("REVIEW_CLOSURE", true));
        assertThat(service.responseCase(12, "security", false).actions()).extracting(SecretExplanationResponse.Action::code)
                .containsExactly("REVIEW_CLOSURE");
    }

    @Test void aWaitingTaskDoesNotRecommendAnotherRequestFromStaleCapabilities() {
        var detail = prepare(true);
        detail.put("occurrences", List.of(location(7L, null, true, true)));
        detail.put("taskGuidance", guidance("WAIT_FOR_REVALIDATION", false));
        assertThat(service.responseCase(12, "security", false).actions()).extracting(SecretExplanationResponse.Action::code)
                .containsExactly("OPEN_CASE");
    }

    @Test void aChangedTaskBasisInvalidatesTheModelResponseEvenWithoutACaseVersionChange() {
        var detail = prepare(true);
        var changed = new LinkedHashMap<>(detail);
        var nextGuidance = guidance("RECORD_LOCATION_ACTION", true);
        nextGuidance.put("blockedReasonCode", "EVIDENCE_CHANGED");
        changed.put("taskGuidance", nextGuidance);
        when(cases.detail(12, "security")).thenReturn(detail, changed);
        generated("RECORD_ACTION");
        assertThat(service.responseCase(12, "security", true).readiness().reasonCode()).isEqualTo("CONTEXT_CHANGED");
    }

    @Test void simpleMetadataStatusDoesNotCallClaudeOrOfferContentFindings() {
        prepare(true);
        var run = mock(SecretRunStatusResponse.class);
        var coverage = mock(SecretRunCoverageResponse.class);
        when(coverage.coverageComplete()).thenReturn(true);
        when(run.coverage()).thenReturn(coverage);
        when(run.scopeResults()).thenReturn(List.of(new SecretRunScopeResultResponse(
                2, "IAM_ACCESS_KEY_METADATA", "global", "SUCCEEDED", 0L, null)));
        when(run.status()).thenReturn("SUCCEEDED");
        when(run.provider()).thenReturn("AWS");
        when(runs.status(18, "security")).thenReturn(run);
        when(runQueries.status("security", 18)).thenReturn(Map.of("capabilities", Map.of("canViewFindings", true)));
        var result = service.run(18, "security", true);
        assertThat(result.readiness().reasonCode()).isEqualTo("BASIC_CONTEXT");
        assertThat(result.readiness().aiAvailable()).isFalse();
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::code).containsExactly("CHECK_STATUS");
        verify(provider, never()).explain(any());
    }

    @Test void recordedActionsAreReadOnlyForTheVisibleLocationIds() {
        prepare(true);
        when(jdbc.queryForObject(any(String.class), eq(Boolean.class), any(Object[].class))).thenReturn(true);
        var result = service.responseCase(12, "security", false);
        assertThat(result.facts()).extracting(SecretExplanationResponse.Fact::code).contains("ACTION_RECORDED");
        verify(jdbc).queryForObject("SELECT EXISTS(SELECT 1 FROM secret_action_records WHERE case_id=? AND occurrence_id IN (?))",
                Boolean.class, new Object[]{12L, 14L});
    }

    private Map<String, Object> prepare(boolean allReadable) {
        var detail = new LinkedHashMap<String, Object>();
        detail.put("stage", "IN_PROGRESS");
        detail.put("issuer", "GITHUB");
        detail.put("credentialType", "GITHUB_CLASSIC_PAT");
        detail.put("assigneeUserId", 7L);
        detail.put("occurrences", List.of(location(7L, null, true, false)));
        detail.put("taskGuidance", guidance("RECORD_LOCATION_ACTION", true));
        detail.put("version", 1L);
        when(cases.detail(12, "security")).thenReturn(detail);
        when(repository.actorId("security")).thenReturn(Optional.of(7L));
        when(guides.allLocationsReadable(7, 12)).thenReturn(allReadable);
        when(guides.currentCase(12)).thenReturn(Optional.empty());
        when(providers.getIfAvailable()).thenReturn(provider);
        when(provider.configurationReason()).thenReturn("READY");
        when(provider.modelId()).thenReturn(ClaudeSecretGuideProvider.MODEL);
        return detail;
    }

    private static Map<String, Object> location(Long assignee, String team, boolean record, boolean recheck) {
        var location = new LinkedHashMap<String, Object>();
        location.put("occurrenceId", 14L);
        location.put("assignedUserId", assignee);
        location.put("assignedTeam", team);
        location.put("requiredRemediation", true);
        location.put("canAssign", false);
        location.put("canRecordAction", record);
        location.put("canRequestRevalidation", recheck);
        return location;
    }

    private static Map<String, Object> guidance(String action, boolean executable) {
        var guidance = new LinkedHashMap<String, Object>();
        guidance.put("nextActionCode", action);
        guidance.put("canExecute", executable);
        return guidance;
    }

    private void generated(String action) {
        when(provider.explain(any())).thenReturn(new ClaudeSecretGuideProvider.Explanation(
                "현재 대응 위치의 작업과 다음 확인을 검토하세요.", List.of(action),
                "CLAUDE_GENERATED", true, false, Instant.now()));
    }
}
