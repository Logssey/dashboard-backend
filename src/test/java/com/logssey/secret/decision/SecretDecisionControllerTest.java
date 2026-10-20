package com.logssey.secret.decision;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class SecretDecisionControllerTest {
    @Test void staleReviewReturnsOnlySafeChangedFieldCodes() throws Exception {
        var service=mock(SecretDecisionService.class);
        when(service.context("security",12)).thenThrow(new SecretReviewConflict("policy","finding"));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretDecisionController(service))
            .setControllerAdvice(new SecretDecisionErrors()).build();
        mvc.perform(get("/api/v1/secrets/occurrences/12/review-context").principal(()->"security"))
            .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("CONFLICT"))
            .andExpect(jsonPath("$.details.reasonCode").value("STALE_REVIEW_CONTEXT"))
            .andExpect(jsonPath("$.details.changedFields[0]").value("policy"))
            .andExpect(jsonPath("$.details.changedFields[1]").value("finding"));
    }
    @Test void independentRoutesKeepTheSelectedOccurrenceAndAuthenticatedActor() throws Exception {
        var service=mock(SecretDecisionService.class);
        when(service.decide(eq("security"),eq(12L),any())).thenReturn(new SecretDecisionContracts.DecisionResult(
            23,12,"ABNORMAL",17L,"CREATED",0L,null,null,"ACTION_REQUIRED",true));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretDecisionController(service)).build();
        mvc.perform(post("/api/v1/secrets/occurrences/12/decisions").principal(()->"security")
                .contentType(MediaType.APPLICATION_JSON).content("""
                {"decision":"ABNORMAL","reasonCode":"POLICY_PROHIBITED_LOCATION","findingId":123,
                 "evidenceRefs":["TICKET:SEC-123"],"expectedOccurrenceVersion":4,"expectedScopeVersion":2,
                 "expectedPolicyVersion":1,"idempotencyKey":"decision-once"}
                """))
            .andExpect(status().isOk()).andExpect(jsonPath("$.decisionId").value(23))
            .andExpect(jsonPath("$.caseId").value(17)).andExpect(jsonPath("$.caseOperation").value("CREATED"));
        verify(service).decide(eq("security"),eq(12L),argThat(r->r.expectedOccurrenceVersion()==4L&&r.findingId()==123L));
    }
}
