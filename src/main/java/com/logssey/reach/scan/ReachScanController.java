package com.logssey.reach.scan;

import java.security.Principal;

import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachScanController {
    private final ReachScanService service;

    public ReachScanController(ReachScanService service) {
        this.service = service;
    }

    /** API-03 */
    @GetMapping("/scans/{scanId}")
    public ReachScanResponse scan(Principal principal, @PathVariable long scanId) {
        return service.scan(principal == null ? null : principal.getName(), scanId);
    }
}
