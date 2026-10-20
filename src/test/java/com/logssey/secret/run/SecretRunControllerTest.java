package com.logssey.secret.run;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecretRunControllerTest {

    @Test
    void listsPaginatedRunSummariesWithoutSourceOrCredentialReferences() throws Exception {
        var service = mock(SecretRunService.class);
        var queries=mock(SecretRunQueryService.class);
        when(queries.list("admin","ALL","ALL",null,null,null,1,10,null)).thenReturn(java.util.Map.of(
            "items",java.util.List.of(java.util.Map.of("runId",42,"status","PARTIAL","incompleteScopeCount",1,"collectedObjectCount",3,"failureCode","AWS_ACCESS_DENIED")),"total",12,"page",1,"size",10));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretRunController(service,queries)).build();
        mvc.perform(get("/api/v1/secrets/runs?page=1&size=10")
                        .principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(12))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(10))
                .andExpect(jsonPath("$.items[0].runId").value(42))
                .andExpect(jsonPath("$.items[0].status").value("PARTIAL"))
                .andExpect(jsonPath("$.items[0].incompleteScopeCount").value(1))
                .andExpect(jsonPath("$.items[0].collectedObjectCount").value(3))
                .andExpect(jsonPath("$.items[0].failureCode").value("AWS_ACCESS_DENIED"))
                .andExpect(jsonPath("$.items[0].approvedRef").doesNotExist())
                .andExpect(jsonPath("$.items[0].authRef").doesNotExist())
                .andExpect(jsonPath("$.items[0].scopeResults").doesNotExist());
    }

    @Test
    void acceptsAsyncRegistrationAndPublishesStatusLocation() throws Exception {
        var service = mock(SecretRunService.class);
        when(service.register(any(SecretRunRequest.class), eq("admin")))
                .thenReturn(new SecretRunAcceptedResponse(42, "PENDING"));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretRunController(service)).build();

        mvc.perform(post("/api/v1/secrets/runs")
                        .principal(new UsernamePasswordAuthenticationToken("admin", "n/a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"connectionId\":7,\"idempotencyKey\":\"request-123\"}"))
                .andExpect(status().isAccepted())
                .andExpect(header().string("Location", "/api/v1/secrets/runs/42"))
                .andExpect(jsonPath("$.runId").value(42))
                .andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    void exposesOnlySafeRunStatusFields() throws Exception {
        var service = mock(SecretRunService.class);
        when(service.status(42, "admin")).thenReturn(new SecretRunStatusResponse(
                42, 7, "MANUAL", "PARTIAL", "PARTIAL", "SUCCEEDED", "SKIPPED",
                2, 2, 1, 3, 1, 3, null, null, null, null, "SOURCE_UNAVAILABLE",
                java.util.List.of(new SecretRunScopeResultResponse(8,
                        "AWS_SECRETS_MANAGER_METADATA", "ap-northeast-2", "PARTIAL",
                        3L, "AWS_ACCESS_DENIED"))));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretRunController(service)).build();

        mvc.perform(get("/api/v1/secrets/runs/42")
                        .principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PARTIAL"))
                .andExpect(jsonPath("$.incompleteScopeCount").value(1))
                .andExpect(jsonPath("$.failureCode").value("SOURCE_UNAVAILABLE"))
                .andExpect(jsonPath("$.scopeResults[0].contentType")
                        .value("AWS_SECRETS_MANAGER_METADATA"))
                .andExpect(jsonPath("$.scopeResults[0].region").value("ap-northeast-2"))
                .andExpect(jsonPath("$.scopeResults[0].objectCount").value(3))
                .andExpect(jsonPath("$.scopeResults[0].gapCode").value("AWS_ACCESS_DENIED"))
                .andExpect(jsonPath("$.approvedRef").doesNotExist())
                .andExpect(jsonPath("$.authRef").doesNotExist())
                .andExpect(jsonPath("$.scopeResults[0].approvedRef").doesNotExist());
    }
}
