package com.logssey.credential.risk;

/**
 * 키 목록에서 찾는 위험 종류와 심각도 (테스트 시나리오 1.2).
 * CRITICAL은 실제로 유출된 키에만 쓰므로 여기서는 쓰지 않는다.
 */
public enum RiskType {
    /** 만료일 없이 발급됨. 유출되면 계속 쓸 수 있다 */
    NO_EXPIRY(Severity.HIGH),
    /** 45일 이상 사용하지 않음 */
    UNUSED(Severity.MEDIUM),
    /** 만료까지 7일 이내 */
    EXPIRING_SOON(Severity.LOW),
    /** 이미 만료됨. 정리 권고 */
    EXPIRED(Severity.LOW);

    private final Severity severity;

    RiskType(Severity severity) {
        this.severity = severity;
    }

    public Severity severity() {
        return severity;
    }
}
