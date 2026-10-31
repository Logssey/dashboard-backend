package com.logssey.reach.scan;

import java.security.Principal;
import java.time.Instant;
import java.util.List;

import com.logssey.reach.scan.dto.ReachScanPageResponse;
import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachScanController {
    private final ReachScanService service;

    public ReachScanController(ReachScanService service) {
        this.service = service;
    }

    /** API-02. 쉼표로 준 값은 Spring이 목록으로 나눈다(scanStatus=RUNNING,FAILED). from·to는 ISO 8601(2026-10-31T00:00:00Z) */
    @GetMapping("/scans")
    public ReachScanPageResponse scans(
            Principal principal,
            @RequestParam(required = false) Long target,
            @RequestParam(required = false) List<String> scanStatus,
            @RequestParam(required = false) List<String> trigger,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String include) {
        var filter = new ReachScanFilter(target, scanStatus, trigger, from, to, sort);
        return service.scans(principal == null ? null : principal.getName(), filter, size, cursor, include);
    }

    /** API-03 */
    @GetMapping("/scans/{scanId}")
    public ReachScanResponse scan(Principal principal, @PathVariable long scanId) {
        return service.scan(principal == null ? null : principal.getName(), scanId);
    }
}
