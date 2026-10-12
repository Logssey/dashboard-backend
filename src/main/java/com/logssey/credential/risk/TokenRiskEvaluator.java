package com.logssey.credential.risk;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.ExpiryPolicy;

/**
 * 수집한 키의 위험을 판단한다.
 * 기준값은 06-test/notion-admin-mock-scenarios.md 1장을 따르며, 나중에 바꿀 수 있다.
 * 한 키가 여러 경우에 해당하면 경우마다 한 건씩 만든다.
 */
public class TokenRiskEvaluator {

    /** 만료 임박: 만료까지 7일 이내 */
    public static final Duration EXPIRING_SOON_WINDOW = Duration.ofDays(7);

    /** 미사용: 마지막 사용 후 45일 이상. 한 번도 안 썼으면 발급일 기준 */
    public static final Duration UNUSED_THRESHOLD = Duration.ofDays(45);

    private final Clock clock;

    public TokenRiskEvaluator(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public List<TokenRiskFinding> evaluate(CollectedCredential credential) {
        Instant now = clock.instant();
        List<TokenRiskFinding> findings = new ArrayList<>();

        switch (credential.status()) {
            case REVOKED -> {
                // 이미 조치된 키다. 상태만 갱신하고 탐지는 만들지 않는다
                return findings;
            }
            case EXPIRED -> {
                findings.add(finding(credential, RiskType.EXPIRED));
                return findings;
            }
            default -> {
                // 아래에서 판단한다
            }
        }

        if (credential.expiryPolicy() == ExpiryPolicy.NEVER) {
            findings.add(finding(credential, RiskType.NO_EXPIRY));
        } else if (credential.expiresAt() != null) {
            if (!credential.expiresAt().isAfter(now)) {
                findings.add(finding(credential, RiskType.EXPIRED));
            } else if (!credential.expiresAt().isAfter(now.plus(EXPIRING_SOON_WINDOW))) {
                findings.add(finding(credential, RiskType.EXPIRING_SOON));
            }
        }

        Instant lastActivity = credential.lastUsedAt() != null ? credential.lastUsedAt() : credential.issuedAt();
        if (lastActivity != null && !lastActivity.isAfter(now.minus(UNUSED_THRESHOLD))) {
            findings.add(finding(credential, RiskType.UNUSED));
        }
        return findings;
    }

    private static TokenRiskFinding finding(CollectedCredential credential, RiskType type) {
        return new TokenRiskFinding(credential.issuer(), credential.externalId(), type, type.severity());
    }
}
