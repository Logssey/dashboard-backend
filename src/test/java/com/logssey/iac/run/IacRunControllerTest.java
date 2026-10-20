package com.logssey.iac.run;

import com.logssey.common.error.GlobalExceptionHandler;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class IacRunControllerTest {

    private static final String BODY = """
            {"repo":"Logssey/infrastructure","prNumber":58,"headSha":"%s",
             "gate":{"status":"PASSED","findings":[]}}
            """;
    private final IacRunService service = mock(IacRunService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new IacRunController(service))
            .setControllerAdvice(new GlobalExceptionHandler()).build();
    private final UsernamePasswordAuthenticationToken admin = new UsernamePasswordAuthenticationToken("admin", "n/a");

    @Test
    void registersARunAndPointsAtItsStatus() throws Exception {
        when(service.register(any(IacRunRequest.class), eq("admin"))).thenReturn(new IacRunCreatedResponse(7, "PLANNING"));
        mvc.perform(post("/api/v1/iac/runs").principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content(BODY.formatted("a".repeat(40))))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "/api/v1/iac/runs/7"))
                .andExpect(jsonPath("$.runId").value(7))
                .andExpect(jsonPath("$.status").value("PLANNING"));
    }

    @Test
    void readsTheTriggerAndDefaultsToPullRequest() throws Exception {
        var captor = org.mockito.ArgumentCaptor.forClass(IacRunRequest.class);
        when(service.register(captor.capture(), eq("admin"))).thenReturn(new IacRunCreatedResponse(8, "PLANNING"));
        mvc.perform(post("/api/v1/iac/runs").principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"repo":"Logssey/infrastructure","headSha":"%s","trigger":"PUSH",
                                 "gate":{"status":"PASSED","findings":[]}}
                                """.formatted("b".repeat(40))))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/v1/iac/runs").principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content(BODY.formatted("a".repeat(40))))
                .andExpect(status().isCreated());
        assertThat(captor.getAllValues()).extracting(IacRunRequest::isPush).containsExactly(true, false);
        assertThat(captor.getAllValues().getFirst().prNumber()).isNull();
    }

    @Test
    void rejectsMalformedRunRequests() throws Exception {
        mvc.perform(post("/api/v1/iac/runs").principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content(BODY.formatted("not-a-sha")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_INPUT"));
        verify(service, never()).register(any(), any());
    }

    @Test
    void acceptsAPlanUpload() throws Exception {
        when(service.uploadPlan(eq(7L), any(byte[].class), eq("admin"))).thenReturn(new IacPlanAcceptedResponse(7, "ANALYZING"));
        mvc.perform(put("/api/v1/iac/runs/7/plan").principal(admin).contentType("application/gzip")
                        .content(IacPlanFixtures.gzipResource("plan-scrubbed.json")))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("ANALYZING"));
    }

    @Test
    void refusesAnOversizedPlanBeforeReadingIt() throws Exception {
        mvc.perform(put("/api/v1/iac/runs/7/plan").principal(admin).contentType("application/gzip")
                        .content(new byte[IacPlanInspector.MAX_COMPRESSED_BYTES + 1]))
                .andExpect(status().isContentTooLarge())
                .andExpect(jsonPath("$.code").value("PAYLOAD_TOO_LARGE"));
        verify(service, never()).uploadPlan(anyLong(), any(), any());
    }
}
