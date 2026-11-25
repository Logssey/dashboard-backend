package com.logssey.overview.score;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 통합 현황 보안 점수 (dashboard-design-docs ADR-D012). 운영 환경만 계산한다.
 * Secret만은 지금 보는 사람의 Secret 권한 범위로 읽는다(기존 통합 현황과 같은 투영을 쓰므로). 나머지 기능은 사람과 관계없이 같다
 */
@RestController
@RequestMapping("/api/v1/overview")
public class SecurityScoreController {

    private final SecurityScoreService service;

    public SecurityScoreController(SecurityScoreService service) {
        this.service = service;
    }

    @GetMapping("/score")
    public SecurityScoreResponse score(Principal principal) {
        return service.score(principal == null ? null : principal.getName());
    }
}
