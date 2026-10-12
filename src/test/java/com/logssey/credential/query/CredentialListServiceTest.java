package com.logssey.credential.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;
import com.logssey.credential.event.CredentialRiskRepository;
import com.logssey.credential.event.StoredCredential;
import com.logssey.credential.query.dto.response.CredentialListResponse;
import com.logssey.credential.query.dto.response.CredentialListResponse.CredentialItem;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 키 목록 조회 (API 명세: 키 목록 조회). 로컬 샘플과 같은 키 5개로 확인한다 */
class CredentialListServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private FakeRepository repository;
    private CredentialListService service;

    @BeforeEach
    void setUp() {
        repository = new FakeRepository();
        repository.credentials.addAll(List.of(
                stored(1, "deploy-bot", ExpiryPolicy.FIXED, later(90), ago(1), CredentialStatus.ACTIVE),
                stored(2, "notion-sync", ExpiryPolicy.FIXED, later(5), ago(1), CredentialStatus.ACTIVE),
                stored(3, "old-script", ExpiryPolicy.FIXED, later(90), ago(60), CredentialStatus.ACTIVE),
                stored(4, "legacy-export", ExpiryPolicy.NEVER, null, ago(1), CredentialStatus.ACTIVE),
                stored(5, "revoked-tool", ExpiryPolicy.FIXED, later(30), ago(40), CredentialStatus.REVOKED)));
        repository.events.addAll(List.of(
                new CredentialRiskRepository.LinkedEvent(9, 2, "SEC-002", "LOW", "만료가 임박한 Notion 토큰", "UNREVIEWED"),
                new CredentialRiskRepository.LinkedEvent(10, 3, "SEC-003", "MEDIUM", "45일 이상 사용하지 않은 Notion 토큰", "UNREVIEWED"),
                new CredentialRiskRepository.LinkedEvent(11, 4, "SEC-004", "HIGH", "만료일 없이 발급된 Notion 토큰", "UNREVIEWED")));
        service = new CredentialListService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("요약 숫자: 전체 5, 위험 있는 키 3, 만료 임박 1")
    void summary() {
        CredentialListResponse response = service.getCredentials("ALL", "ALL", false);

        assertThat(response.summary().totalCount()).isEqualTo(5);
        assertThat(response.summary().atRiskCount()).isEqualTo(3);
        assertThat(response.summary().expiringSoonCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("정렬: 위험 높은 키(HIGH → MEDIUM → LOW) → 위험 없는 키는 이름순")
    void sortedByRiskThenName() {
        CredentialListResponse response = service.getCredentials("ALL", "ALL", false);

        assertThat(response.items()).extracting(CredentialItem::displayName)
                .containsExactly("legacy-export", "old-script", "notion-sync", "deploy-bot", "revoked-tool");
    }

    @Test
    @DisplayName("필터: 발급자·상태·위험만. 요약 숫자는 필터와 관계없이 그대로")
    void filters() {
        assertThat(service.getCredentials("NOTION", "ALL", false).items()).hasSize(5);
        assertThat(service.getCredentials("AWS", "ALL", false).items()).isEmpty();
        assertThat(service.getCredentials("ALL", "REVOKED", false).items())
                .extracting(CredentialItem::displayName).containsExactly("revoked-tool");

        CredentialListResponse riskOnly = service.getCredentials("ALL", "ALL", true);
        assertThat(riskOnly.items()).hasSize(3);
        assertThat(riskOnly.summary().totalCount()).isEqualTo(5);
    }

    @Test
    @DisplayName("한 키에 위험이 여러 개면 심각도 높은 것이 먼저 온다")
    void risksSortedBySeverity() {
        repository.events.add(new CredentialRiskRepository.LinkedEvent(12, 4, "SEC-005", "MEDIUM",
                "45일 이상 사용하지 않은 Notion 토큰", "UNREVIEWED"));

        CredentialItem legacy = service.getCredentials("ALL", "ALL", false).items().get(0);

        assertThat(legacy.risks()).extracting(CredentialListResponse.RiskRef::severity).containsExactly("HIGH", "MEDIUM");
    }

    @Test
    @DisplayName("키 값 표시: 만료 없음은 expiresAt null, 시각은 초 단위 ISO 8601 UTC")
    void itemValues() {
        CredentialItem legacy = service.getCredentials("ALL", "ALL", false).items().get(0);

        assertThat(legacy.issuer()).isEqualTo("NOTION");
        assertThat(legacy.status()).isEqualTo("ACTIVE");
        assertThat(legacy.expiryPolicy()).isEqualTo("NEVER");
        assertThat(legacy.expiresAt()).isNull();
        assertThat(legacy.lastUsedAt()).isEqualTo("2026-10-07T00:00:00Z");
        assertThat(legacy.ownerTeam()).isEqualTo("Platform");
    }

    @Test
    @DisplayName("허용값이 아닌 issuer·status는 INVALID_INPUT")
    void invalidInput() {
        assertThatThrownBy(() -> service.getCredentials("SLACK", "ALL", false))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.getCredentials("ALL", "active", false))
                .isInstanceOf(ApiException.class);
    }

    // ---------------------------------------------------------------- 도우미

    private static Instant ago(long days) {
        return NOW.minus(Duration.ofDays(days));
    }

    private static Instant later(long days) {
        return NOW.plus(Duration.ofDays(days));
    }

    private static StoredCredential stored(long id, String name, ExpiryPolicy expiryPolicy, Instant expiresAt,
                                           Instant lastUsedAt, CredentialStatus status) {
        CollectedCredential credential = new CollectedCredential("NOTION", "NOTION_PAT", "sample-pat-" + id, name,
                "Team Member A", ago(120), expiryPolicy, expiresAt, lastUsedAt, status, null, null);
        return new StoredCredential(id, credential, "Platform", null, null, null);
    }

    private static final class FakeRepository extends CredentialRiskRepository {

        private final List<StoredCredential> credentials = new ArrayList<>();
        private final List<LinkedEvent> events = new ArrayList<>();

        FakeRepository() {
            super(null);
        }

        @Override
        public List<StoredCredential> findAllCredentials() {
            return credentials;
        }

        @Override
        public List<LinkedEvent> findLinkedEvents() {
            return events;
        }
    }
}
