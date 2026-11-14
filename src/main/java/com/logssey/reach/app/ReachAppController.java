package com.logssey.reach.app;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logssey.reach.app.dto.ReachAppListResponse;

/** 감시 대상 앱 조회 (API-14). 값은 설정 logssey.reach.apps다 */
@RestController
@RequestMapping("/api/v1/reach")
public class ReachAppController {
    private final ReachAppService service;

    public ReachAppController(ReachAppService service) {
        this.service = service;
    }

    @GetMapping("/apps")
    public ReachAppListResponse apps(Principal principal) {
        return service.apps(principal == null ? null : principal.getName());
    }
}
