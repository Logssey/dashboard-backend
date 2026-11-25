package com.logssey.credential.query;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.query.dto.response.CredentialListResponse;
import com.logssey.credential.query.dto.response.CredentialListResponse.CredentialItem;
import com.logssey.credential.query.dto.response.CredentialListResponse.Summary;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 시크릿 보안 탭의 키 목록과 요약 숫자 (API 명세: 키 목록 조회).
 *
 * Secret 기준 문서(security-solution-docs/secret-management)에 맞춘 규칙:
 * - 문서에서 문자열만 찾은 키는 유효성·권한·노출 범위를 확인하기 전이므로 등급 대신 미평가(UNASSESSED)
 * - AWS는 Access Key ID와 Secret Access Key가 함께 보여야 CONFIRMED. 하나만 보이면 CANDIDATE
 * - 발급처 목록(Notion Admin API)으로만 아는 키는 등급을 매기지 않는다. 만료·미사용은 위험이 아니라 목록 정보
 * - 환경을 모르면 UNKNOWN. PROD로 가정하지 않는다
 * - 정렬: 문서에서 발견한 키(CONFIRMED → CANDIDATE) → 목록 정보만 있는 키, 각각 이름순
 */
@Service
@Transactional(readOnly = true)
public class CredentialListService {

    static final String SOURCE_SCAN = "SCAN";
    static final String CONFIRMED = "CONFIRMED";
    static final String CANDIDATE = "CANDIDATE";
    static final String METADATA_ONLY = "METADATA_ONLY";
    static final String UNASSESSED = "UNASSESSED";
    static final String CREDENTIAL_UNCONFIRMED = "CREDENTIAL_UNCONFIRMED";
    static final String EXPOSURE_UNKNOWN = "EXPOSURE_UNKNOWN";

    private static final Set<String> ISSUERS = Set.of("ALL", "AWS", "GITHUB", "NOTION", "CUSTOM");

    private final CredentialQueryRepository repository;

    public CredentialListService(CredentialQueryRepository repository) {
        this.repository = repository;
    }

    public CredentialListResponse getCredentials(String issuer, String status, boolean foundOnly) {
        validateIssuer(issuer);
        validateStatus(status);

        List<StoredCredential> credentials = repository.findAllCredentials();
        long found = 0;
        long candidates = 0;
        List<CredentialItem> items = new ArrayList<>();
        for (StoredCredential stored : credentials) {
            CredentialItem item = toItem(stored);
            if (SOURCE_SCAN.equals(item.source())) {
                found++;
                if (CANDIDATE.equals(item.componentState())) {
                    candidates++;
                }
            }
            if (matches(item, issuer, status, foundOnly)) {
                items.add(item);
            }
        }

        items.sort(Comparator
                .comparingInt(CredentialListService::rank)
                .thenComparing(CredentialItem::displayName, Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparingLong(CredentialItem::credentialId));

        long inventory = credentials.size() - found;
        return new CredentialListResponse(new Summary(credentials.size(), found, candidates, inventory), items);
    }

    /** 구성요소 완전성. 문서에서 발견한 키만 CONFIRMED/CANDIDATE, 나머지는 목록 정보 */
    static String componentState(StoredCredential stored) {
        if (!SOURCE_SCAN.equals(stored.source())) {
            return METADATA_ONLY;
        }
        if ("AWS".equals(stored.credential().issuer())) {
            // AWS 키는 ID와 비밀값 두 조각이 모두 보여야 완전하다
            return stored.credential().externalId() != null && stored.secretSeen() ? CONFIRMED : CANDIDATE;
        }
        return stored.secretSeen() ? CONFIRMED : CANDIDATE;
    }

    private static CredentialItem toItem(StoredCredential stored) {
        CollectedCredential credential = stored.credential();
        String componentState = componentState(stored);
        boolean found = SOURCE_SCAN.equals(stored.source());
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
                stored.source(),
                found ? stored.storageLocation() : null,
                stored.environment() != null ? stored.environment() : "UNKNOWN",
                componentState,
                found ? UNASSESSED : null,
                found ? (CONFIRMED.equals(componentState) ? EXPOSURE_UNKNOWN : CREDENTIAL_UNCONFIRMED) : null);
    }

    private static boolean matches(CredentialItem item, String issuer, String status, boolean foundOnly) {
        if (!"ALL".equals(issuer) && !issuer.equals(item.issuer())) {
            return false;
        }
        if (!"ALL".equals(status) && !status.equals(item.status())) {
            return false;
        }
        return !foundOnly || SOURCE_SCAN.equals(item.source());
    }

    private static int rank(CredentialItem item) {
        return switch (item.componentState()) {
            case CONFIRMED -> 1;
            case CANDIDATE -> 2;
            default -> 3;
        };
    }

    private static String format(Instant instant) {
        return instant != null ? instant.truncatedTo(ChronoUnit.SECONDS).toString() : null;
    }

    private static void validateIssuer(String issuer) {
        if (issuer == null || !ISSUERS.contains(issuer)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "issuer는 ALL, AWS, GITHUB, NOTION, CUSTOM 중 하나여야 합니다.");
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
