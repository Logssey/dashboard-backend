package com.logssey.credential.query;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.event.CredentialRiskRepository;
import com.logssey.credential.event.CredentialRiskRepository.LinkedEvent;
import com.logssey.credential.event.StoredCredential;
import com.logssey.credential.query.dto.response.CredentialListResponse;
import com.logssey.credential.query.dto.response.CredentialListResponse.CredentialItem;
import com.logssey.credential.query.dto.response.CredentialListResponse.RiskRef;
import com.logssey.credential.query.dto.response.CredentialListResponse.Summary;
import com.logssey.credential.risk.RiskType;
import com.logssey.credential.risk.TokenRiskEvaluator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 시크릿 보안 탭의 키 목록과 요약 숫자 (API 명세: 키 목록 조회).
 *
 * - 요약 숫자는 필터와 관계없이 전체 키 기준
 * - 만료 임박 판단은 탐지 등록과 같은 판단 코드(TokenRiskEvaluator)를 쓴다
 * - 정렬: 가장 높은 위험의 심각도 순 → 위험 없는 키 → displayName 가나다순
 */
@Service
@Transactional(readOnly = true)
public class CredentialListService {

    private static final Set<String> ISSUERS = Set.of("ALL", "AWS", "GITHUB", "NOTION");
    private static final int NO_RISK_RANK = 5;

    private final CredentialRiskRepository repository;
    private final Clock clock;

    @Autowired
    public CredentialListService(CredentialRiskRepository repository) {
        this(repository, Clock.systemUTC());
    }

    CredentialListService(CredentialRiskRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    public CredentialListResponse getCredentials(String issuer, String status, boolean riskOnly) {
        validateIssuer(issuer);
        validateStatus(status);

        List<StoredCredential> credentials = repository.findAllCredentials();
        Map<Long, List<RiskRef>> risksByCredential = groupRisks(repository.findLinkedEvents());
        TokenRiskEvaluator evaluator = new TokenRiskEvaluator(clock);

        long atRisk = 0;
        long expiringSoon = 0;
        List<CredentialItem> items = new ArrayList<>();
        for (StoredCredential stored : credentials) {
            CollectedCredential credential = stored.credential();
            List<RiskRef> risks = risksByCredential.getOrDefault(stored.credentialId(), List.of());
            if (!risks.isEmpty()) {
                atRisk++;
            }
            if (credential.status() == CredentialStatus.ACTIVE && evaluator.evaluate(credential).stream()
                    .anyMatch(finding -> finding.type() == RiskType.EXPIRING_SOON)) {
                expiringSoon++;
            }
            if (matches(credential, risks, issuer, status, riskOnly)) {
                items.add(toItem(stored, risks));
            }
        }

        items.sort(Comparator
                .comparingInt(CredentialListService::topRiskRank)
                .thenComparing(CredentialItem::displayName, Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparingLong(CredentialItem::credentialId));

        return new CredentialListResponse(new Summary(credentials.size(), atRisk, expiringSoon), items);
    }

    private static boolean matches(CollectedCredential credential, List<RiskRef> risks,
                                   String issuer, String status, boolean riskOnly) {
        if (!"ALL".equals(issuer) && !issuer.equals(credential.issuer())) {
            return false;
        }
        if (!"ALL".equals(status) && !status.equals(credential.status().name())) {
            return false;
        }
        return !riskOnly || !risks.isEmpty();
    }

    private static Map<Long, List<RiskRef>> groupRisks(List<LinkedEvent> events) {
        Map<Long, List<RiskRef>> grouped = new HashMap<>();
        for (LinkedEvent event : events) {
            grouped.computeIfAbsent(event.credentialId(), id -> new ArrayList<>())
                    .add(new RiskRef(event.eventId(), event.displayId(), event.severity(), event.title(),
                            event.reviewStatus()));
        }
        Comparator<RiskRef> bySeverity = Comparator.comparingInt((RiskRef risk) -> severityRank(risk.severity()))
                .thenComparingLong(RiskRef::eventId);
        grouped.values().forEach(list -> list.sort(bySeverity));
        return grouped;
    }

    private static CredentialItem toItem(StoredCredential stored, List<RiskRef> risks) {
        CollectedCredential credential = stored.credential();
        return new CredentialItem(
                stored.credentialId(),
                credential.displayName(),
                credential.externalId(),
                credential.issuer(),
                credential.credentialType(),
                credential.status().name(),
                credential.expiryPolicy().name(),
                format(credential.expiresAt()),
                format(credential.lastUsedAt()),
                credential.owner(),
                stored.ownerTeam(),
                List.copyOf(risks));
    }

    private static int topRiskRank(CredentialItem item) {
        return item.risks().isEmpty() ? NO_RISK_RANK : severityRank(item.risks().get(0).severity());
    }

    private static int severityRank(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 1;
            case "HIGH" -> 2;
            case "MEDIUM" -> 3;
            case "LOW" -> 4;
            default -> NO_RISK_RANK;
        };
    }

    private static String format(Instant instant) {
        return instant != null ? instant.truncatedTo(ChronoUnit.SECONDS).toString() : null;
    }

    private static void validateIssuer(String issuer) {
        if (issuer == null || !ISSUERS.contains(issuer)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "issuer는 ALL, AWS, GITHUB, NOTION 중 하나여야 합니다.");
        }
    }

    private static void validateStatus(String status) {
        if ("ALL".equals(status)) {
            return;
        }
        try {
            CredentialStatus.valueOf(status);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ApiException(ErrorCode.INVALID_INPUT,
                    "status는 ALL, ACTIVE, INACTIVE, EXPIRED, REVOKED, UNKNOWN 중 하나여야 합니다.");
        }
    }
}
