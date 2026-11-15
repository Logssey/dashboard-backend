package com.logssey.reach.ci.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Reach CI 인증 설정 (GitHub OIDC, API 명세 2-2).
 * repositoryOwner가 비어 있으면 CI 토큰은 모두 403이다(설치 설정을 넣기 전에는 닫혀 있다).
 * 허용 레포는 repositoryOwner + 감시 대상 앱의 레포(logssey.reach.apps[*].repo)다
 */
@ConfigurationProperties("logssey.reach.ci")
public record ReachCiProperties(String repositoryOwner, @DefaultValue("main") String defaultBranch,
                                @DefaultValue Oidc oidc) {

    static final String GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

    public ReachCiProperties {
        defaultBranch = defaultBranch == null || defaultBranch.isBlank() ? "main" : defaultBranch;
        oidc = oidc == null ? new Oidc(null, null, null) : oidc;
    }

    /** 설정이 없을 때(CI 토큰은 모두 거부) */
    public static ReachCiProperties closed() {
        return new ReachCiProperties(null, null, null);
    }

    public boolean open() {
        return repositoryOwner != null && !repositoryOwner.isBlank();
    }

    /** 토큰 발급자·서명 키 주소·aud. 테스트만 바꾼다 */
    public record Oidc(@DefaultValue(GITHUB_ISSUER) String issuer,
                       @DefaultValue(GITHUB_ISSUER + "/.well-known/jwks") String jwkSetUri,
                       @DefaultValue("logssey-reach") String audience) {

        public Oidc {
            issuer = issuer == null || issuer.isBlank() ? GITHUB_ISSUER : issuer;
            jwkSetUri = jwkSetUri == null || jwkSetUri.isBlank() ? GITHUB_ISSUER + "/.well-known/jwks" : jwkSetUri;
            audience = audience == null || audience.isBlank() ? "logssey-reach" : audience;
        }
    }
}
