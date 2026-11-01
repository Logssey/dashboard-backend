package com.logssey.reach.export;

import java.security.Principal;
import java.util.List;

import com.logssey.reach.export.dto.ReachOcsfPageResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachExportController {
    private final ReachExportService service;

    public ReachExportController(ReachExportService service) {
        this.service = service;
    }

    /**
     * API-11. scanId는 필수지만 required = false로 받아 Service가 400을 준다(스프링 기본 400은 본문이 비어서).
     * 쉼표로 준 status는 Spring이 목록으로 나눈다(status=REACHABLE,UNKNOWN)
     */
    @GetMapping("/exports/ocsf")
    public ReachOcsfPageResponse ocsf(Principal principal,
                                      @RequestParam(required = false) Long scanId,
                                      @RequestParam(required = false) List<String> status,
                                      @RequestParam(required = false) Integer size,
                                      @RequestParam(required = false) String cursor) {
        return service.ocsf(principal == null ? null : principal.getName(), scanId, status, size, cursor);
    }
}
