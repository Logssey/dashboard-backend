package com.logssey.iac.run;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.iac.auth.IacCiSecurityConfig;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/iac/runs")
public class IacRunController {

    private final IacRunService service;

    public IacRunController(IacRunService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<IacRunCreatedResponse> register(@Valid @RequestBody IacRunRequest request,
                                                          Authentication authentication) {
        // infrastructure 의 iac-report 워크플로(GitHub OIDC)면 토큰의 레포로, 아니면 관리자 세션으로
        var ci = IacCiSecurityConfig.ciCaller(authentication);
        var created = ci.isPresent() ? service.registerByCi(request, ci.get())
                : service.register(request, name(authentication));
        return ResponseEntity.created(URI.create("/api/v1/iac/runs/" + created.runId())).body(created);
    }

    /** 본문은 민감값을 지운 plan JSON 의 gzip. 20MB 를 넘으면 끝까지 읽지 않고 413. */
    @PutMapping("/{runId}/plan")
    public ResponseEntity<IacPlanAcceptedResponse> uploadPlan(@PathVariable long runId, HttpServletRequest request,
                                                              Authentication authentication) throws IOException {
        if (request.getContentLengthLong() > IacPlanInspector.MAX_COMPRESSED_BYTES) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        }
        byte[] body;
        try (InputStream in = request.getInputStream()) {
            body = in.readNBytes(IacPlanInspector.MAX_COMPRESSED_BYTES + 1);
        }
        var ci = IacCiSecurityConfig.ciCaller(authentication);
        return ResponseEntity.accepted().body(ci.isPresent() ? service.uploadPlanByCi(runId, body, ci.get())
                : service.uploadPlan(runId, body, name(authentication)));
    }

    @GetMapping("/{runId}")
    public IacRunStatusResponse status(@PathVariable long runId, Authentication authentication) {
        var ci = IacCiSecurityConfig.ciCaller(authentication);
        return ci.isPresent() ? service.statusByCi(runId, ci.get()) : service.status(runId, name(authentication));
    }

    private static String name(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
