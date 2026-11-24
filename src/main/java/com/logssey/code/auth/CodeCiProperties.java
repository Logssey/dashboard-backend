package com.logssey.code.auth;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 코드 취약점 결과 업로드 인증 설정 (GitHub Actions OIDC).
 * 토큰은 아래 레포의 .github/workflows/code-scan.yml 이 기본 브랜치(develop)에서 받은 것이어야 한다.
 * 설정이 없으면 아래 값을 쓴다 (공용 application.properties 를 건드리지 않으려고 여기 둔다).
 * repositories 를 빈 값으로 설정하면 업로드는 모두 401 (끌 때). 나머지 값은 테스트만 바꾼다.
 */
@ConfigurationProperties("logssey.code.ci")
public record CodeCiProperties(List<String> repositories, String branch, String audience, String issuer,
                               String jwkSetUri) {

    static final String GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
    static final String WORKFLOW_PATH = ".github/workflows/code-scan.yml";

    public CodeCiProperties {
        repositories = repositories == null ? List.of("Logssey/service-backend", "Logssey/service-frontend")
                : repositories.stream().map(String::strip).filter(value -> !value.isEmpty()).toList();
        branch = blank(branch) ? "develop" : branch.strip();
        audience = blank(audience) ? "logssey-code" : audience;
        issuer = blank(issuer) ? GITHUB_ISSUER : issuer;
        jwkSetUri = blank(jwkSetUri) ? GITHUB_ISSUER + "/.well-known/jwks" : jwkSetUri;
    }

    /** 허용한 레포의 code-scan 워크플로가 기본 브랜치에서 push·수동 실행으로 받은 토큰인가 (PR 실행은 못 올린다) */
    boolean accepts(String repository, String ref, String eventName, String workflowRef) {
        if (repository == null || ref == null || eventName == null || workflowRef == null) return false;
        String branchRef = "refs/heads/" + branch;
        return repositories.stream().anyMatch(repository::equalsIgnoreCase)
                && branchRef.equals(ref)
                && ("push".equals(eventName) || "workflow_dispatch".equals(eventName))
                && workflowRef.equalsIgnoreCase(repository + "/" + WORKFLOW_PATH + "@" + branchRef);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
