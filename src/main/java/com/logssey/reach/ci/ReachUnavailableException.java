package com.logssey.reach.ci;

/**
 * 의존 서비스를 잠시 쓸 수 없음 → 503 UNAVAILABLE (API 명세 2-6, details.dependency).
 * 공통 ErrorCode에 503이 없어 Reach CI 패키지 안에서만 쓴다(ReachUnavailableAdvice)
 */
class ReachUnavailableException extends RuntimeException {

    private final String dependency;

    ReachUnavailableException(String dependency, String reason) {
        super(dependency + ": " + reason);
        this.dependency = dependency;
    }

    String dependency() {
        return dependency;
    }
}
