package com.logssey.secret.run.progress;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets/runs")
public class SecretRunProgressController {
    private final SecretRunProgressService service;
    public SecretRunProgressController(SecretRunProgressService service) { this.service = service; }

    @GetMapping("/{runId}/progress")
    public SecretRunProgress progress(@PathVariable long runId,
            @RequestParam(defaultValue = "0") long afterEventId,
            @RequestParam(defaultValue = "100") int size,
            @RequestParam Map<String, String> params, Authentication authentication) {
        if (!Set.of("afterEventId", "size").containsAll(params.keySet())) throw new ApiException(ErrorCode.INVALID_INPUT);
        return service.progress(authentication == null ? null : authentication.getName(), runId, afterEventId, size);
    }
}
