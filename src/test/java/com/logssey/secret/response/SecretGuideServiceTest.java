package com.logssey.secret.response;

import java.util.List;
import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SecretGuideServiceTest {
    private final SecretCaseRepository cases = mock(SecretCaseRepository.class);
    private final SecretGuideRepository guides = mock(SecretGuideRepository.class);
    private final SecretGuideProvider provider = mock(SecretGuideProvider.class);
    private final SecretGuideService service = new SecretGuideService(cases, guides, provider);

    @Test
    void productionCaseUsesVersionedFallbackWithoutExternalCall() {
        prepare("PRODUCTION", null);
        var response = service.guide(17, "security");

        assertThat(response.version()).isEqualTo("secret-response-guide-v1");
        assertThat(response.source()).isEqualTo("DEFAULT");
        assertThat(response.steps()).extracting(SecretGuideResponse.Step::code)
                .contains("EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE");
        verifyNoInteractions(provider);
    }

    @Test
    void otherTestSourcesNeverLeaveTheServer() {
        when(cases.actorId("security")).thenReturn(Optional.of(7L));
        when(guides.canRead(7,17)).thenReturn(true);
        when(guides.allLocationsReadable(7,17)).thenReturn(true);
        when(guides.currentCase(17)).thenReturn(Optional.of(new SecretGuideRepository.GuideCase(
                "TEST", "OPEN", null, "AWS", "AWS_ACCESS_KEY_PAIR", "CONFIRMED",
                "UNCHECKED", false)));
        assertThat(service.guide(17, "security").source()).isEqualTo("DEFAULT");
        verifyNoInteractions(provider);
    }

    @Test
    void testCaseSendsOnlyWhitelistedEnumsAndAcceptsValidSelection() {
        prepare("TEST", null);
        when(provider.selectSteps(any())).thenReturn(Optional.of(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE")));

        var response = service.guide(17, "security");

        assertThat(response.source()).isEqualTo("GROQ");
        assertThat(response.steps()).extracting(SecretGuideResponse.Step::code)
                .containsExactly("VERIFY_EXPOSURE", "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE");
        var context = org.mockito.ArgumentCaptor.forClass(SecretGuideContext.class);
        verify(provider).selectSteps(context.capture());
        assertThat(context.getValue().externalFields()).containsEntry("issuer", "AWS")
                .containsEntry("credentialType", "AWS_ACCESS_KEY_PAIR")
                .containsEntry("validationStatus", "UNCHECKED")
                .doesNotContainKeys("maskedLabel", "sourceObjectRef", "path", "freeText");
    }

    @Test
    void unknownAndMalformedProviderResultsAreSafeFallbacks() {
        prepare("TEST", null);
        when(provider.selectSteps(any())).thenReturn(Optional.of(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "REVALIDATE")));
        assertThat(service.guide(17, "security").source()).isEqualTo("DEFAULT");

        when(provider.selectSteps(any())).thenThrow(new IllegalStateException("provider body or secret"));
        assertThat(service.guide(17, "security").source()).isEqualTo("DEFAULT");
    }

    @Test
    void onlySecurityOrAssignedRemediatorMayRequestGuide() {
        when(cases.actorId("remediator")).thenReturn(Optional.of(7L));
        when(guides.currentCase(17)).thenReturn(Optional.of(guideCase("TEST", 8L)));
        when(cases.hasCaseRole(7, 17, "REMEDIATOR")).thenReturn(true);
        assertCode(ErrorCode.FORBIDDEN, () -> service.guide(17, "remediator"));
        verifyNoInteractions(provider);

        when(guides.currentCase(17)).thenReturn(Optional.of(guideCase("TEST", 7L)));
        when(guides.canRead(7,17)).thenReturn(true);
        when(provider.selectSteps(any())).thenReturn(Optional.empty());
        assertThat(service.guide(17, "remediator").source()).isEqualTo("DEFAULT");
        verify(cases, never()).updateAssignment(anyLong(), anyLong(),
                any(), any());
    }

    @Test
    void missingCaseAndUnknownActorFailBeforeProviderCall() {
        when(cases.actorId("security")).thenReturn(Optional.of(7L));
        when(guides.currentCase(17)).thenReturn(Optional.empty());
        assertCode(ErrorCode.NOT_FOUND, () -> service.guide(17, "security"));
        assertCode(ErrorCode.UNAUTHENTICATED, () -> service.guide(17, "unknown"));
        verifyNoInteractions(provider);
    }

    private void prepare(String origin, Long assignee) {
        when(cases.actorId("security")).thenReturn(Optional.of(7L));
        when(guides.currentCase(17)).thenReturn(Optional.of(guideCase(origin, assignee)));
        when(guides.canRead(7,17)).thenReturn(true);
        when(guides.allLocationsReadable(7,17)).thenReturn(true);
    }

    private static SecretGuideRepository.GuideCase guideCase(String origin, Long assignee) {
        return new SecretGuideRepository.GuideCase(origin, "OPEN", assignee, "AWS",
                "AWS_ACCESS_KEY_PAIR", "CONFIRMED", "UNCHECKED", true);
    }

    private static void assertCode(ErrorCode expected, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
                .satisfies(error -> assertThat(((ApiException) error).errorCode()).isEqualTo(expected));
    }
}
