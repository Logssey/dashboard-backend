package com.logssey.secret.connection;

import java.time.OffsetDateTime;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class SecretConnectionTestControllerTest {
    @Test
    void postReturnsOnlyFixedStatusAndSafeReason() throws Exception {
        var service = mock(SecretConnectionTestService.class);
        when(service.test(3, "admin")).thenReturn(new SecretConnectionTestResponse(
                3, "AWS", "FAILED", "AWS_ACCOUNT_MISMATCH",
                OffsetDateTime.parse("2026-10-14T01:02:03Z")));
        var mvc = MockMvcBuilders.standaloneSetup(new SecretConnectionTestController(service)).build();

        mvc.perform(post("/api/v1/secrets/connections/3/test")
                        .principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.connectionId").value(3))
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.reasonCode").value("AWS_ACCOUNT_MISMATCH"))
                .andExpect(jsonPath("$.checkedAt").exists())
                .andExpect(jsonPath("$.authRef").doesNotExist())
                .andExpect(jsonPath("$.approvedRef").doesNotExist())
                .andExpect(jsonPath("$.accountId").doesNotExist());
    }
}
