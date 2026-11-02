package com.logssey.reach.ci;

import java.net.URI;
import java.security.Principal;

import com.logssey.reach.ci.dto.ReachCiCheckCreatedResponse;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach/ci/checks")
public class ReachCiCheckController {
    private final ReachCiCheckService service;

    public ReachCiCheckController(ReachCiCheckService service) {
        this.service = service;
    }

    /**
     * API-12 실행. 202와 Location을 준다. 같은 멱등 키로 다시 보내면 Idempotent-Replayed: true (명세 2-7).
     * 헤더는 required = false로 받아 Service가 400(INVALID_INPUT 본문)을 준다. 스프링 기본 400은 본문이 비어 있다
     */
    @PostMapping
    public ResponseEntity<ReachCiCheckCreatedResponse> create(
            Principal principal,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody ReachCiCheckRequest request) {
        var created = service.create(principal == null ? null : principal.getName(), idempotencyKey, request);
        var response = ResponseEntity.accepted().location(URI.create("/api/v1/reach/ci/checks/" + created.check().id()));
        if (created.replayed()) response.header("Idempotent-Replayed", "true");
        return response.body(created.check());
    }

    /** API-12 결과 조회 */
    @GetMapping("/{checkId}")
    public ReachCiCheckResponse check(Principal principal, @PathVariable long checkId) {
        return service.check(principal == null ? null : principal.getName(), checkId);
    }
}
