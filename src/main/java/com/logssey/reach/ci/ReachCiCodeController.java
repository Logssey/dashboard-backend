package com.logssey.reach.ci;

import java.security.Principal;

import com.logssey.reach.ci.auth.ReachCiCaller;
import com.logssey.reach.ci.dto.ReachCiCodeResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReachCiCodeController {
    private final ReachCiCodeService service;

    public ReachCiCodeController(ReachCiCodeService service) {
        this.service = service;
    }

    /** 러너가 받을 Reach 코드의 커밋 (API-12 보조). 모르면 404 */
    @GetMapping("/api/v1/reach/ci/code")
    public ReachCiCodeResponse code(Principal principal) {
        var ci = ReachCiCaller.from(principal);
        return ci.isPresent() ? service.codeForCi(ci.get()) : service.code(principal == null ? null : principal.getName());
    }
}
