package com.logssey.secret.query;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.logssey.common.error.GlobalExceptionHandler;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class SecretInventoryControllerTest {
    @Test
    void pagedInventoryForwardsNormalizedFiltersAndTheSameSnapshot() throws Exception {
        var legacy=mock(SecretInventoryService.class);
        var queries=mock(SecretLocationService.class);
        var filters=new SecretInventoryFilters("TEST","GITHUB","AWS","DEV","VALUE_FINDINGS","ALL","ALL","ALL","ALL");
        when(queries.inventory("admin",filters,1,20,"snapshot-1")).thenReturn(Map.of(
            "items",List.of(Map.of("id",42,"maskedLabel","AWS ••••1234")),"total",21,
            "scope","inventory","unit","CredentialSet","snapshotId","snapshot-1"));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretInventoryController(legacy,queries))
            .setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(get("/api/v1/secrets?origin=TEST&source=GITHUB&issuer=AWS&environment=DEV&page=1&snapshotId=snapshot-1")
            .principal(new UsernamePasswordAuthenticationToken("admin","n/a")))
            .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(21))
            .andExpect(jsonPath("$.scope").value("inventory")).andExpect(jsonPath("$.unit").value("CredentialSet"))
            .andExpect(jsonPath("$.snapshotId").value("snapshot-1"))
            .andExpect(jsonPath("$.items[0].fingerprint").doesNotExist());
        verify(queries).inventory("admin",filters,1,20,"snapshot-1");
        verifyNoInteractions(legacy);
    }

    @Test
    void conflictingIssuerAliasesAreRejectedInsteadOfSilentlyChangingFilters() throws Exception {
        var legacy=mock(SecretInventoryService.class); var queries=mock(SecretLocationService.class);
        var mvc=MockMvcBuilders.standaloneSetup(new SecretInventoryController(legacy,queries))
            .setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(get("/api/v1/secrets?issuer=AWS&provider=GITHUB"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_INPUT"));
        verifyNoInteractions(queries);
    }

    @Test
    void keyDetailKeepsOriginAndOnlyExposesSafeProjection() throws Exception {
        var legacy=mock(SecretInventoryService.class); var queries=mock(SecretLocationService.class);
        when(queries.detail("admin",7,"TEST")).thenReturn(Map.of("id",7,"occurrences",List.of(
            Map.of("occurrenceId",12,"safeLocationLabel","위치 #12","presence","UNKNOWN"))));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretInventoryController(legacy,queries)).build();
        mvc.perform(get("/api/v1/secrets/7?origin=TEST").principal(new UsernamePasswordAuthenticationToken("admin","n/a")))
            .andExpect(status().isOk()).andExpect(jsonPath("$.occurrences[0].safeLocationLabel").value("위치 #12"))
            .andExpect(jsonPath("$.occurrences[0].sourceObjectRef").doesNotExist())
            .andExpect(jsonPath("$.externalKeyRef").doesNotExist());
        verify(queries).detail("admin",7,"TEST");
    }

    @Test
    void connectionPickerKeepsItsSeparateExecutionPermissionBoundary() throws Exception {
        var legacy=mock(SecretInventoryService.class); var queries=mock(SecretLocationService.class);
        when(legacy.connections("admin")).thenReturn(new SecretConnectionListResponse(List.of(
            new SecretConnectionResponse(7,"GITHUB","연결 #7","ACTIVE",1))));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretInventoryController(legacy,queries)).build();
        mvc.perform(get("/api/v1/secrets/connections").principal(new UsernamePasswordAuthenticationToken("admin","n/a")))
            .andExpect(status().isOk()).andExpect(jsonPath("$.items[0].connectionId").value(7))
            .andExpect(jsonPath("$.items[0].authRef").doesNotExist());
        verifyNoInteractions(queries);
    }
}
