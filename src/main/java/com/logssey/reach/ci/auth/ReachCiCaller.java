package com.logssey.reach.ci.auth;

import java.security.Principal;
import java.util.Optional;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * GitHub OIDC 토큰으로 들어온 CI 호출 주체. 클레임은 ReachTokenSecurityConfig가 검사한 뒤라 비어 있지 않다.
 * repository는 소유자를 붙인 이름(Logssey/service-backend), subject는 sub, ref는 이벤트의 ref(refs/pull/1/merge, refs/heads/main)
 */
public record ReachCiCaller(String repository, String subject, String eventName, String ref) {

    /** CI 토큰이면 호출 주체, 대시보드 세션이면 빈 값 */
    public static Optional<ReachCiCaller> from(Principal principal) {
        if (!(principal instanceof JwtAuthenticationToken token)) {
            return Optional.empty();
        }
        var jwt = token.getToken();
        return Optional.of(new ReachCiCaller(jwt.getClaimAsString("repository"), jwt.getSubject(),
                jwt.getClaimAsString("event_name"), jwt.getClaimAsString("ref")));
    }

    /** 멱등 키 범위이자 검사를 만든 주체 표시 (V37 idempotency_scope) */
    public String scope() {
        return "CI:" + repository;
    }

    /** 소유자를 뗀 레포 이름 */
    public String repositoryName() {
        return repository.substring(repository.indexOf('/') + 1);
    }

    String repositoryOwner() {
        int slash = repository.indexOf('/');
        return slash < 0 ? "" : repository.substring(0, slash);
    }
}
