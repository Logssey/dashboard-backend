package com.logssey.iac.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * IaC CI 인증 설정 (GitHub Actions OIDC, IaC 보안 ADR-13).
 * 토큰의 sub 가 아래 둘 중 하나와 정확히 같아야 한다. 둘 다 infrastructure 의 main 만 쓰는 environment 다.
 *   - reportSubject: iac-report (environment iac-app) → PR 실행만 등록
 *   - driftSubject: iac-drift (environment iac-drift) → main 매일 점검(PUSH)만 등록
 * infrastructure 레포는 2026-07-15 뒤에 만들어져 sub 에 조직·레포 ID 가 붙는다 (immutable subject).
 * ID 는 이름을 바꾸거나 같은 이름으로 다시 만들어도 바뀌지 않아 이름보다 안전하다.
 * PR 코드(iac-gate)는 이 sub 를 받을 수 없다. 설정이 없으면 아래 값을 쓰고(공용 application.properties 를
 * 건드리지 않으려고 여기 둔다), 빈 값으로 설정하면 그 호출은 401 (끌 때). 나머지 값은 테스트만 바꾼다.
 */
@ConfigurationProperties("logssey.iac.ci")
public record IacCiProperties(String reportSubject, String driftSubject, String audience, String issuer,
                              String jwkSetUri) {

    static final String GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
    static final String INFRASTRUCTURE = "repo:Logssey@329835088/infrastructure@1372604168";
    static final String REPORT_SUBJECT = INFRASTRUCTURE + ":environment:iac-app";
    static final String DRIFT_SUBJECT = INFRASTRUCTURE + ":environment:iac-drift";

    public IacCiProperties {
        reportSubject = reportSubject == null ? REPORT_SUBJECT : reportSubject.strip();
        driftSubject = driftSubject == null ? DRIFT_SUBJECT : driftSubject.strip();
        audience = blank(audience) ? "logssey-iac" : audience;
        issuer = blank(issuer) ? GITHUB_ISSUER : issuer;
        jwkSetUri = blank(jwkSetUri) ? GITHUB_ISSUER + "/.well-known/jwks" : jwkSetUri;
    }

    /** 토큰의 sub 로 할 수 있는 실행 종류 (PR·PUSH). 모르는 sub 면 null */
    String triggerOf(String subject) {
        if (subject == null || subject.isEmpty()) return null;
        if (subject.equals(reportSubject)) return "PR";
        if (subject.equals(driftSubject)) return "PUSH";
        return null;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
