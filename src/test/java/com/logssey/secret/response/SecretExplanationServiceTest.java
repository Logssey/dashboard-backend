package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.logssey.secret.run.SecretRunQueryService;
import com.logssey.secret.run.SecretRunService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

class SecretExplanationServiceTest {
    private final SecretCaseService cases = mock(SecretCaseService.class);
    private final SecretCaseRepository repository = mock(SecretCaseRepository.class);
    private final SecretGuideRepository guides = mock(SecretGuideRepository.class);
    private final ClaudeSecretGuideProvider provider = mock(ClaudeSecretGuideProvider.class);
    private final ObjectProvider<ClaudeSecretGuideProvider> providers = mock(ObjectProvider.class);
    private final SecretExplanationService service = new SecretExplanationService(mock(SecretRunService.class),
            mock(SecretRunQueryService.class), cases, repository, guides, mock(JdbcTemplate.class), providers);

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
        when(detail.version()).thenReturn(1L, 2L);
        when(provider.explain(any())).thenReturn(new ClaudeSecretGuideProvider.Explanation(
                "기록된 조치와 다음 확인을 검토하세요.", List.of("OPEN_CASE"), "CLAUDE_GENERATED", true, false, Instant.now()));
        var result = service.responseCase(12, "security", true);
        assertThat(result.source()).isEqualTo("DEFAULT");
        assertThat(result.readiness().reasonCode()).isEqualTo("CONTEXT_CHANGED");
        assertThat(result.readiness().providerCalled()).isTrue();
    }

    @Test void keepsIdentifiersLocalAndUsesTheRealCaseTabs() {
        prepare(true);
        when(provider.explain(any())).thenReturn(new ClaudeSecretGuideProvider.Explanation(
                "아직 조치 기록이 없어요. 현재 작업에서 담당 범위의 조치를 기록하세요.",
                List.of("RECORD_ACTION"), "CLAUDE_GENERATED", true, false, Instant.now()));
        var result = service.responseCase(12, "security", true);
        assertThat(result.actions()).extracting(SecretExplanationResponse.Action::href)
                .containsExactly("/secrets/cases/12?tab=work");
        var argument = org.mockito.ArgumentCaptor.forClass(SecretExplanationContext.class);
        verify(provider).explain(argument.capture());
        assertThat(argument.getValue().externalFields()).doesNotContainKeys("caseId", "name", "path", "href", "login");
        assertThat(result.documents()).extracting(SecretExplanationResponse.Document::id).containsExactly("GITHUB_PAT");
    }

    private SecretCaseDetail prepare(boolean allReadable) {
        var detail = mock(SecretCaseDetail.class);
        when(cases.detail(12, "security")).thenReturn(detail);
        when(repository.actorId("security")).thenReturn(Optional.of(7L));
        when(guides.allLocationsReadable(7, 12)).thenReturn(allReadable);
        when(guides.currentCase(12)).thenReturn(Optional.empty());
        when(detail.stage()).thenReturn("IN_PROGRESS");
        when(detail.issuer()).thenReturn("GITHUB");
        when(detail.credentialType()).thenReturn("GITHUB_CLASSIC_PAT");
        when(detail.actions()).thenReturn(List.of());
        when(detail.occurrences()).thenReturn(List.of(new SecretCaseOccurrence(14, "IN_PROGRESS")));
        when(detail.assigneeUserId()).thenReturn(7L);
        when(detail.capabilities()).thenReturn(new SecretCaseCapabilities(true, false, true, true, true, false, false));
        when(detail.version()).thenReturn(1L);
        when(providers.getIfAvailable()).thenReturn(provider);
        when(provider.configurationReason()).thenReturn("READY");
        when(provider.modelId()).thenReturn(ClaudeSecretGuideProvider.MODEL);
        return detail;
    }
}
