package com.logssey.secret.query;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.logssey.secret.decision.SecretDecisionController;
import com.logssey.secret.decision.SecretDecisionService;
import com.logssey.secret.response.SecretCaseController;
import com.logssey.secret.response.SecretCaseService;
import com.logssey.secret.response.SecretLocationWorkflow;

class SecretMatrixControllerTest {
    @Test void matrixAndBothCaseRoutesKeepTheSnapshotAndSelectedCell() throws Exception {
        var workbench=mock(SecretWorkbenchService.class);
        var filters=new SecretWorkbenchService.Filters("TEST","GITHUB","AWS","DEV",7L,null);
        String snapshot="12345678-1111-2222-3333-123456789abc";
        when(workbench.matrix("security",filters,snapshot)).thenReturn(Map.of("snapshotId",snapshot,"total",2));
        when(workbench.queue("security",filters,"CURRENT_CASES",null,0,20,snapshot,"UNASSESSED","UNCHECKED"))
                .thenReturn(Map.of("snapshotId",snapshot,"total",2,"items",List.of()));
        var mvc=MockMvcBuilders.standaloneSetup(new SecretWorkbenchController(workbench),
                new SecretDecisionController(mock(SecretDecisionService.class),workbench),
                new SecretCaseController(mock(SecretCaseService.class),mock(SecretLocationWorkflow.class),workbench)).build();
        String base="?origin=TEST&source=GITHUB&provider=AWS&environment=DEV&connectionId=7&snapshotId="+snapshot;
        var actor=new UsernamePasswordAuthenticationToken("security","unused");
        mvc.perform(get("/api/v1/secrets/matrix"+base).principal(actor)).andExpect(status().isOk())
                .andExpect(jsonPath("$.snapshotId").value(snapshot)).andExpect(jsonPath("$.total").value(2));
        mvc.perform(get("/api/v1/secrets/review-queue"+base+"&bucket=CURRENT_CASES&severity=UNASSESSED&validity=UNCHECKED").principal(actor))
                .andExpect(status().isOk()).andExpect(jsonPath("$.snapshotId").value(snapshot));
        mvc.perform(get("/api/v1/secrets/cases"+base+"&severity=UNASSESSED&validity=UNCHECKED").principal(actor))
                .andExpect(status().isOk()).andExpect(jsonPath("$.snapshotId").value(snapshot));
        verify(workbench,times(2)).queue("security",filters,"CURRENT_CASES",null,0,20,snapshot,"UNASSESSED","UNCHECKED");
    }
}
