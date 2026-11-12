package com.logssey.secret.response;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecretGuideControllerTest {
    @Test
    void getServesDefaultAndReadinessWithoutInvokingPostGuide() throws Exception {
        var service = mock(SecretGuideService.class);
        when(service.readiness(17, "security")).thenReturn(SecretGuideCatalog.fallback()
                .withReadiness(new SecretGuideReadiness("UNAVAILABLE", "KEY_MISSING", false, false, false, false)));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretGuideController(service)).build();
        mvc.perform(get("/api/v1/secrets/cases/{caseId}/guide", 17)
                        .principal(new UsernamePasswordAuthenticationToken("security", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.source").value("DEFAULT"))
                .andExpect(jsonPath("$.readiness.reasonCode").value("KEY_MISSING"))
                .andExpect(jsonPath("$.readiness.aiRequested").value(false))
                .andExpect(jsonPath("$.readiness.providerCalled").value(false))
                .andExpect(jsonPath("$.readiness.apiKey").doesNotExist());
        verify(service, never()).guide(anyLong(), any());
    }

    @Test
    void servesVersionedGuidanceWithoutEvidenceFields() throws Exception {
        var service = mock(SecretGuideService.class);
        when(service.guide(17, "security")).thenReturn(SecretGuideCatalog.fallback());
        var mvc = MockMvcBuilders.standaloneSetup(new SecretGuideController(service)).build();

        mvc.perform(post("/api/v1/secrets/cases/{caseId}/guide", 17)
                        .principal(new UsernamePasswordAuthenticationToken("security", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("secret-response-guide-v3"))
                .andExpect(jsonPath("$.source").value("DEFAULT"))
                .andExpect(jsonPath("$.steps[0].code").value("VERIFY_EXPOSURE"))
                .andExpect(jsonPath("$.maskedLabel").doesNotExist())
                .andExpect(jsonPath("$.sourceObjectRef").doesNotExist());
    }
}
