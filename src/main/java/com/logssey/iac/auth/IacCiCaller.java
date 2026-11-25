package com.logssey.iac.auth;

/**
 * GitHub OIDC 로 인증된 infrastructure 워크플로. trigger 는 이 호출이 다룰 수 있는 실행 종류다
 * (iac-report → PR, iac-drift → PUSH). 레포와 종류가 맞지 않는 실행은 등록·조회할 수 없다.
 */
public record IacCiCaller(String repository, String trigger) {
}
