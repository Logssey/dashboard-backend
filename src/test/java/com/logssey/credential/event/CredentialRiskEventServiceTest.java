package com.logssey.credential.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 키 위험 판단 → 탐지 이벤트 자동 등록.
 * DB 없이, 저장소를 가짜로 바꿔 끼워 확인한다. SQL 자체는 로컬 서버 실행으로 확인한다.
 */
class CredentialRiskEventServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private FakeRepository repository;
    private CredentialRiskEventService service;

    @BeforeEach
    void setUp() {
        repository = new FakeRepository();
        service = new CredentialRiskEventService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("샘플 키 5개 → 탐지 3건 (만료 임박 LOW, 미사용 MEDIUM, 만료일 없음 HIGH). 정상·폐기는 없음")
    void createsEventsFromRules() {
        repository.credentials.addAll(List.of(
                stored(1, "deploy-bot", ago(120), ExpiryPolicy.FIXED, later(90), ago(1), CredentialStatus.ACTIVE),
                stored(2, "notion-sync", ago(360), ExpiryPolicy.FIXED, later(5), ago(1), CredentialStatus.ACTIVE),
                stored(3, "old-script", ago(200), ExpiryPolicy.FIXED, later(90), ago(60), CredentialStatus.ACTIVE),
                stored(4, "legacy-export", ago(30), ExpiryPolicy.NEVER, null, ago(1), CredentialStatus.ACTIVE),
                stored(5, "revoked-tool", ago(150), ExpiryPolicy.FIXED, later(30), ago(40), CredentialStatus.REVOKED)));

        int created = service.createRiskEvents();

        assertThat(created).isEqualTo(3);
        assertThat(repository.inserted)
                .extracting(NewDetectionEvent::credentialId, NewDetectionEvent::severity, NewDetectionEvent::title)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(2L, "LOW", "만료가 임박한 Notion 토큰"),
                        org.assertj.core.groups.Tuple.tuple(3L, "MEDIUM", "45일 이상 사용하지 않은 Notion 토큰"),
                        org.assertj.core.groups.Tuple.tuple(4L, "HIGH", "만료일 없이 발급된 Notion 토큰"));
        assertThat(repository.inserted)
                .allSatisfy(event -> {
                    assertThat(event.domain()).isEqualTo("SECRETS");
                    assertThat(event.detectedAt()).isEqualTo(NOW);
                });
    }

    @Test
    @DisplayName("화면 ID는 지금까지 쓴 가장 큰 SEC 번호 다음부터 매긴다")
    void displayIdContinuesFromMaxNumber() {
        repository.maxSecretsNumber = 1;
        repository.credentials.add(stored(2, "notion-sync", ago(360), ExpiryPolicy.FIXED, later(5), ago(1), CredentialStatus.ACTIVE));
        repository.credentials.add(stored(4, "legacy-export", ago(30), ExpiryPolicy.NEVER, null, ago(1), CredentialStatus.ACTIVE));

        service.createRiskEvents();

        assertThat(repository.inserted).extracting(NewDetectionEvent::displayId).containsExactly("SEC-002", "SEC-003");
    }

    @Test
    @DisplayName("두 번 돌려도 같은 키 + 같은 제목의 탐지는 다시 만들지 않는다")
    void doesNotDuplicate() {
        repository.credentials.add(stored(4, "legacy-export", ago(30), ExpiryPolicy.NEVER, null, ago(1), CredentialStatus.ACTIVE));

        int first = service.createRiskEvents();
        int second = service.createRiskEvents();

        assertThat(first).isEqualTo(1);
        assertThat(second).isZero();
        assertThat(repository.inserted).hasSize(1);
    }

    @Test
    @DisplayName("한 키가 두 경우에 해당하면 두 건을 만든다 (만료일 없음 + 미사용)")
    void oneCredentialTwoRisks() {
        repository.credentials.add(stored(10, "required-only", ago(280), ExpiryPolicy.NEVER, null, null, CredentialStatus.ACTIVE));

        service.createRiskEvents();

        assertThat(repository.inserted).extracting(NewDetectionEvent::severity).containsExactly("HIGH", "MEDIUM");
    }

    @Test
    @DisplayName("환경: 자산 환경 → 키 환경 → 둘 다 모르면 PROD. 담당 팀을 모르면 미지정")
    void environmentAndOwnerTeamRules() {
        repository.credentials.add(new StoredCredential(1, credential("from-asset", ExpiryPolicy.NEVER, null),
                "Backend", "PROD", 7L, "DEV"));
        repository.credentials.add(new StoredCredential(2, credential("from-credential", ExpiryPolicy.NEVER, null),
                "Backend", "DEV", null, null));
        repository.credentials.add(new StoredCredential(3, credential("unknown", ExpiryPolicy.NEVER, null),
                null, null, null, null));

        service.createRiskEvents();

        assertThat(repository.inserted).extracting(NewDetectionEvent::environment).containsExactly("DEV", "DEV", "PROD");
        assertThat(repository.inserted.get(0).assetId()).isEqualTo(7L);
        assertThat(repository.inserted.get(2).ownerTeam()).isEqualTo("미지정");
        assertThat(repository.inserted.get(2).evidence()).contains("환경: 미확인이라 운영으로 간주");
        assertThat(repository.inserted.get(0).evidence()).doesNotContain("운영으로 간주");
    }

    @Test
    @DisplayName("근거에 판단 기준과 날수가 들어간다")
    void evidenceShowsRuleAndDays() {
        repository.credentials.add(stored(2, "notion-sync", ago(360), ExpiryPolicy.FIXED, later(5), ago(1), CredentialStatus.ACTIVE));
        repository.credentials.add(stored(3, "old-script", ago(200), ExpiryPolicy.FIXED, later(90), ago(60), CredentialStatus.ACTIVE));

        service.createRiskEvents();

        assertThat(repository.inserted.get(0).evidence())
                .contains("토큰: notion-sync (pat-2)", "만료까지: 5일", "판단 기준: 만료까지 7일 이내");
        assertThat(repository.inserted.get(1).evidence())
                .contains("마지막 사용: 60일 전", "판단 기준: 마지막 사용 후 45일 이상");
    }

    // ---------------------------------------------------------------- 도우미

    private static Instant ago(long days) {
        return NOW.minus(Duration.ofDays(days));
    }

    private static Instant later(long days) {
        return NOW.plus(Duration.ofDays(days));
    }

    private static StoredCredential stored(long id, String name, Instant issuedAt, ExpiryPolicy expiryPolicy,
                                           Instant expiresAt, Instant lastUsedAt, CredentialStatus status) {
        CollectedCredential credential = new CollectedCredential("NOTION", "NOTION_PAT", "pat-" + id, name,
                "Team Member A", issuedAt, expiryPolicy, expiresAt, lastUsedAt, status, null, null);
        return new StoredCredential(id, credential, "Platform", null, null, null);
    }

    private static CollectedCredential credential(String name, ExpiryPolicy expiryPolicy, Instant expiresAt) {
        return new CollectedCredential("NOTION", "NOTION_PAT", "pat-" + name, name, null,
                ago(10), expiryPolicy, expiresAt, ago(1), CredentialStatus.ACTIVE, null, null);
    }

    /** DB 대신 메모리에 담는 가짜 저장소 */
    private static final class FakeRepository extends CredentialRiskRepository {

        private final List<StoredCredential> credentials = new ArrayList<>();
        private final List<NewDetectionEvent> inserted = new ArrayList<>();
        private int maxSecretsNumber;

        FakeRepository() {
            super(null);
        }

        @Override
        public List<StoredCredential> findAllCredentials() {
            return credentials;
        }

        @Override
        public Set<EventKey> findExistingEventKeys() {
            Set<EventKey> keys = new HashSet<>();
            for (NewDetectionEvent event : inserted) {
                keys.add(new EventKey(event.credentialId(), event.title()));
            }
            return keys;
        }

        @Override
        public int findMaxSecretsNumber() {
            return maxSecretsNumber;
        }

        @Override
        public void insertEvent(NewDetectionEvent event) {
            inserted.add(event);
        }
    }
}
