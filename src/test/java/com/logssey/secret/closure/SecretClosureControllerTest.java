package com.logssey.secret.closure;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static com.logssey.secret.closure.SecretClosureContracts.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class SecretClosureControllerTest {
    @Test void disabledAcceptanceReturnsItsOwnReasonWithoutClaimingAnApproval() throws Exception {
        var closure=mock(SecretClosureService.class);var governance=mock(SecretGovernanceService.class);
        when(governance.approveException(eq("security"),eq(12L),any())).thenThrow(
            new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.RISK_ACCEPTANCE_DISABLED));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretClosureController(closure,governance))
            .setControllerAdvice(new com.logssey.common.error.GlobalExceptionHandler()).build();
        mvc.perform(post("/api/v1/secrets/cases/12/exceptions").principal(()->"security")
            .contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.code").value("RISK_ACCEPTANCE_DISABLED"));
    }
    @Test void blockedResolutionReturnsSafeTypedChecksForTheSelectedCase() throws Exception {
        var closure=mock(SecretClosureService.class);var governance=mock(SecretGovernanceService.class);
        when(closure.resolve(eq("security"),eq(12L),any())).thenThrow(new SecretClosureConflict(List.of(
            new Check("POSITION_REQUIRED","UNKNOWN","POST_ACTION_COMPARISON_REQUIRED",42L,List.of()))));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretClosureController(closure,governance))
            .setControllerAdvice(new SecretClosureErrors()).build();
        mvc.perform(post("/api/v1/secrets/cases/12/resolution-decisions").principal(()->"security")
                .contentType(MediaType.APPLICATION_JSON).content("""
                {"decision":"RESOLVE","expectedCaseVersion":4,"closureCheckVersion":"context",
                 "evidenceIds":[7],"coverageLevel":"LIMITED","idempotencyKey":"closure"}
                """))
            .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("CONFLICT"))
            .andExpect(jsonPath("$.details.reasonCode").value("CLOSURE_BLOCKED"))
            .andExpect(jsonPath("$.details.closureChecks[0].occurrenceId").value(42))
            .andExpect(jsonPath("$.details.closureChecks[0].reasonCode").value("POST_ACTION_COMPARISON_REQUIRED"));
        verify(closure).resolve(eq("security"),eq(12L),argThat(r->r.expectedCaseVersion()==4&&r.evidenceIds().equals(List.of(7L))));
    }
}
