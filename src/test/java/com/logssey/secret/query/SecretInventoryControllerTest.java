package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecretInventoryControllerTest {
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-10-14T00:00:00Z");

    @Test
    void exposesPagedInventoryAndDistinctLocationsWithoutInternalIdentityColumns() throws Exception {
        var service = mock(SecretInventoryService.class);
        var summary = new SecretSummaryResponse(42, "AWS", "AWS_ACCESS_KEY_PAIR",
                "CONFIRMED", "AWS AKIA••••1234", "UNASSESSED", "VALID",
                "AUTHENTICATED", NOW, NOW, 2, NOW, NOW);
        when(service.list(0, 20, "ALL", "ALL", "admin"))
                .thenReturn(new SecretListResponse(List.of(summary), 1, 0, 20));
        when(service.detail(42, "admin")).thenReturn(new SecretDetailResponse(
                42, "AWS", "AWS_ACCESS_KEY_PAIR", "CONFIRMED", "AWS AKIA••••1234",
                "UNASSESSED", "VALID", "AUTHENTICATED", NOW, NOW, 2, NOW, NOW,
                "UNKNOWN", null, "UNKNOWN",
                List.of(new SecretOccurrenceResponse(1, 7, "repo/a.txt", "L1", "UNKNOWN",
                                "UNKNOWN", "UNKNOWN", "PRESENT", NOW, NOW),
                        new SecretOccurrenceResponse(2, 7, "repo/b.java", "L9", "UNKNOWN",
                                "UNKNOWN", "UNKNOWN", "PRESENT", NOW, NOW)), null));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretInventoryController(service)).build();
        var admin = new UsernamePasswordAuthenticationToken("admin", "n/a");

        mvc.perform(get("/api/v1/secrets").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].occurrenceCount").value(2))
                .andExpect(jsonPath("$.items[0].severity").value("UNASSESSED"))
                .andExpect(jsonPath("$.items[0].validationStatus").value("VALID"))
                .andExpect(jsonPath("$.items[0].validationReasonCode").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.items[0].fingerprint").doesNotExist())
                .andExpect(jsonPath("$.items[0].candidateLocator").doesNotExist());
        mvc.perform(get("/api/v1/secrets/42").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.occurrences[0].sourceObjectRef").value("repo/a.txt"))
                .andExpect(jsonPath("$.occurrences[1].sourceObjectRef").value("repo/b.java"))
                .andExpect(jsonPath("$.occurrences[0].environment").value("UNKNOWN"))
                .andExpect(jsonPath("$.externalKeyRef").doesNotExist())
                .andExpect(jsonPath("$.authRef").doesNotExist());
    }

    @Test
    void exposesIamMetadataOnlyWithoutInternalKeyReference() throws Exception {
        var service = mock(SecretInventoryService.class);
        when(service.detail(7, "admin")).thenReturn(new SecretDetailResponse(
                7, "AWS", "AWS_IAM_ACCESS_KEY", "METADATA_ONLY",
                "AWS IAM access key ····CDEF", "UNASSESSED", "UNCHECKED",
                null, null, null, 1, NOW, NOW, "UNKNOWN", null, "UNKNOWN",
                List.of(), new AwsIamMetadataResponse("ACTIVE", NOW, NOW,
                "Amazon S3", "ap-northeast-1", NOW)));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretInventoryController(service)).build();
        var admin = new UsernamePasswordAuthenticationToken("admin", "n/a");
        mvc.perform(get("/api/v1/secrets/7").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.componentState").value("METADATA_ONLY"))
                .andExpect(jsonPath("$.validationStatus").value("UNCHECKED"))
                .andExpect(jsonPath("$.severity").value("UNASSESSED"))
                .andExpect(jsonPath("$.iamMetadata.keyStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.iamMetadata.lastUsedService").value("Amazon S3"))
                .andExpect(jsonPath("$.externalKeyRef").doesNotExist())
                .andExpect(jsonPath("$.accessKeyId").doesNotExist());
    }

    @Test
    void connectionPickerReturnsOnlyTheSafeFields() throws Exception {
        var service = mock(SecretInventoryService.class);
        when(service.connections("admin")).thenReturn(new SecretConnectionListResponse(
                List.of(new SecretConnectionResponse(7, "GITHUB", "Fixture GitHub", "ACTIVE", 1))));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretInventoryController(service)).build();

        mvc.perform(get("/api/v1/secrets/connections")
                        .principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].connectionId").value(7))
                .andExpect(jsonPath("$.items[0].approvedScopeCount").value(1))
                .andExpect(jsonPath("$.items[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$.items[0].authRef").doesNotExist())
                .andExpect(jsonPath("$.items[0].approvedRef").doesNotExist());
    }
}
