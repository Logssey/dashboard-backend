package com.logssey.iac.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * IaC CI 인증 설정 (GitHub Actions OIDC, IaC 보안 ADR-13).
 * subject 는 토큰의 sub 와 정확히 같아야 한다. infrastructure 의 iac-report 는 main 만 쓰는 environment(iac-app)에서
 * 돌아 sub 가 repo:Logssey/infrastructure:environment:iac-app 이다. PR 코드(iac-gate)는 이 sub 를 받을 수 없다.
 * 설정이 없으면 그 sub 를 쓴다(공용 application.properties 를 건드리지 않으려고 여기 둔다).
 * 빈 값으로 설정하면 CI 토큰은 모두 401 (CI 를 끌 때). 나머지 값은 테스트만 바꾼다.
 */
@ConfigurationProperties("logssey.iac.ci")
public record IacCiProperties(String subject, String audience, String issuer, String jwkSetUri) {

    static final String GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
    static final String REPORT_WORKFLOW_SUBJECT = "repo:Logssey/infrastructure:environment:iac-app";

    public IacCiProperties {
        subject = subject == null ? REPORT_WORKFLOW_SUBJECT : subject.strip();
        audience = blank(audience) ? "logssey-iac" : audience;
        issuer = blank(issuer) ? GITHUB_ISSUER : issuer;
        jwkSetUri = blank(jwkSetUri) ? GITHUB_ISSUER + "/.well-known/jwks" : jwkSetUri;
    }

    public boolean open() {
        return !subject.isEmpty();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
