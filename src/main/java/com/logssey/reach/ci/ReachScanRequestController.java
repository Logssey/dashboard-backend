package com.logssey.reach.ci;

import java.net.URI;
import java.security.Principal;

import com.logssey.reach.scan.ReachScanService;
import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** API-01. 같은 경로의 조회(API-02·03)는 ReachScanController에 있다. 만드는 일은 CI 검사와 같아 이 패키지에 둔다 */
@RestController
@RequestMapping("/api/v1/reach")
public class ReachScanRequestController {
    private final ReachCiCheckService checks;
    private final ReachScanService scans;

    public ReachScanRequestController(ReachCiCheckService checks, ReachScanService scans) {
        this.checks = checks;
        this.scans = scans;
    }

    /** 202와 Location. 응답은 API-03과 같은 Scan이다. 같은 멱등 키로 다시 보내면 Idempotent-Replayed: true (명세 2-7) */
    @PostMapping("/scans")
    public ResponseEntity<ReachScanResponse> create(
            Principal principal,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody ReachScanRequest request) {
        String loginId = principal == null ? null : principal.getName();
        var created = checks.createScan(loginId, idempotencyKey, request);
        long scanId = created.check().scanId();
        var response = ResponseEntity.accepted().location(URI.create("/api/v1/reach/scans/" + scanId));
        if (created.replayed()) response.header("Idempotent-Replayed", "true");
        return response.body(scans.scan(loginId, scanId));
    }
}
