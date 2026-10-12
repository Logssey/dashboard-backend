package com.logssey.credential.event;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.risk.RiskType;
import com.logssey.credential.risk.TokenRiskEvaluator;
import com.logssey.credential.risk.TokenRiskFinding;

/**
 * 위험 판단 결과 한 건을 탐지 이벤트 한 건으로 바꾼다.
 *
 * - 영역은 SECRETS
 * - 환경: 연결 자산의 환경 → 키의 환경 → 둘 다 모르면 PROD (ERD 초안 4.2)
 * - 담당 팀을 모르면 "미지정"
 * - 근거(evidence)에는 키 원문을 넣지 않는다 (ADR-D009)
 * - 같은 키 + 같은 제목이면 같은 탐지로 본다. 그래서 제목은 위험 종류마다 고정이다
 */
public final class CredentialRiskEventFactory {

    static final String DOMAIN = "SECRETS";
    static final String DEFAULT_ENVIRONMENT = "PROD";
    static final String UNASSIGNED_TEAM = "미지정";

    private CredentialRiskEventFactory() {
    }

    public static NewDetectionEvent create(StoredCredential stored, TokenRiskFinding finding,
                                           Instant now, String displayId) {
        CollectedCredential credential = stored.credential();
        String environment = environmentOf(stored);
        boolean environmentAssumed = stored.assetEnvironment() == null && stored.environment() == null;

        return new NewDetectionEvent(
                stored.assetId(),
                stored.credentialId(),
                displayId,
                finding.severity().name(),
                title(credential.issuer(), finding.type()),
                environment,
                stored.ownerTeam() != null && !stored.ownerTeam().isBlank() ? stored.ownerTeam() : UNASSIGNED_TEAM,
                now,
                DOMAIN,
                evidence(credential, finding.type(), now, environmentAssumed),
                recommendation(finding.type()));
    }

    /** 위험 종류마다 고정된 제목. 중복 판단에 쓰이므로 바꾸면 기존 탐지와 다른 탐지로 취급된다 */
    public static String title(String issuer, RiskType type) {
        String subject = issuerLabel(issuer) + " " + ("AWS".equals(issuer) ? "키" : "토큰");
        return switch (type) {
            case NO_EXPIRY -> "만료일 없이 발급된 " + subject;
            case UNUSED -> TokenRiskEvaluator.UNUSED_THRESHOLD.toDays() + "일 이상 사용하지 않은 " + subject;
            case EXPIRING_SOON -> "만료가 임박한 " + subject;
            case EXPIRED -> "만료된 " + subject;
        };
    }

    static String environmentOf(StoredCredential stored) {
        if (stored.assetEnvironment() != null) {
            return stored.assetEnvironment();
        }
        if (stored.environment() != null) {
            return stored.environment();
        }
        return DEFAULT_ENVIRONMENT;
    }

    private static String evidence(CollectedCredential credential, RiskType type, Instant now,
                                   boolean environmentAssumed) {
        List<String> lines = new ArrayList<>();
        String name = credential.displayName() != null ? credential.displayName() : "이름 없음";
        lines.add("토큰: " + name + " (" + credential.externalId() + ")");
        switch (type) {
            case NO_EXPIRY -> {
                lines.add("만료 방식: 만료 없음");
                lines.add("판단 기준: 만료일 없이 발급된 키");
            }
            case EXPIRING_SOON -> {
                lines.add("만료까지: " + daysCeil(now, credential.expiresAt()) + "일");
                lines.add("판단 기준: 만료까지 " + TokenRiskEvaluator.EXPIRING_SOON_WINDOW.toDays() + "일 이내");
            }
            case UNUSED -> {
                if (credential.lastUsedAt() != null) {
                    lines.add("마지막 사용: " + daysFloor(credential.lastUsedAt(), now) + "일 전");
                } else if (credential.issuedAt() != null) {
                    lines.add("사용 기록: 없음 (발급 " + daysFloor(credential.issuedAt(), now) + "일 전)");
                } else {
                    lines.add("사용 기록: 없음");
                }
                lines.add("판단 기준: 마지막 사용 후 " + TokenRiskEvaluator.UNUSED_THRESHOLD.toDays() + "일 이상");
            }
            case EXPIRED -> {
                if (credential.expiresAt() != null && !credential.expiresAt().isAfter(now)) {
                    lines.add("만료: " + daysFloor(credential.expiresAt(), now) + "일 전");
                } else {
                    lines.add("상태: 만료됨");
                }
                lines.add("판단 기준: 만료된 키");
            }
        }
        if (environmentAssumed) {
            lines.add("환경: 미확인이라 운영으로 간주");
        }
        return String.join("\n", lines);
    }

    private static String recommendation(RiskType type) {
        return switch (type) {
            case NO_EXPIRY -> "토큰 용도를 확인한 뒤 만료일을 지정해 다시 발급하고, 기존 토큰을 폐기합니다.";
            case UNUSED -> "사용처가 남아 있는지 확인하고, 없으면 토큰을 폐기합니다.";
            case EXPIRING_SOON -> "연동이 멈추기 전에 새 토큰을 발급해 교체합니다.";
            case EXPIRED -> "저장 위치에 남아 있는 만료된 토큰을 정리합니다.";
        };
    }

    private static String issuerLabel(String issuer) {
        if (issuer == null) {
            return "";
        }
        return switch (issuer) {
            case "NOTION" -> "Notion";
            case "GITHUB" -> "GitHub";
            case "AWS" -> "AWS";
            default -> issuer;
        };
    }

    /** 과거 시각부터 지금까지 지난 날수 (내림) */
    private static long daysFloor(Instant past, Instant now) {
        return Duration.between(past, now).toDays();
    }

    /** 지금부터 미래 시각까지 남은 날수 (올림) */
    private static long daysCeil(Instant now, Instant future) {
        long seconds = Duration.between(now, future).getSeconds();
        return Math.max(0, (seconds + 86_399) / 86_400);
    }
}
