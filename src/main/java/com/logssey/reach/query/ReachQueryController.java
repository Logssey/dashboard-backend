package com.logssey.reach.query;

import java.security.Principal;
import com.logssey.reach.query.dto.ReachFindingPageResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachQueryController {
    private final ReachQueryService service;

    public ReachQueryController(ReachQueryService service) {
        this.service = service;
    }

    @GetMapping("/findings")
    public ReachFindingPageResponse findings(Principal principal){
        return service.findings(principal == null ? null : principal.getName());
    }
}