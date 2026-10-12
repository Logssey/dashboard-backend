package com.logssey.credential.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 스캔으로 발견한 키(source = SCAN)의 유출 탐지 */
class CredentialLeakEventTest {

    private static final Instant NOW = Instant.parse("2026-10-12T00:00:00Z");
    private static final String LOCATION = "Notion 페이지: Logssey 탐지 테스트 (page-1)";

    @Test
    @DisplayName("비밀값이 보인 키는 CRITICAL '원문 노출', 식별자만 보인 AWS 키는 HIGH 'ID 노출'")
    void leakSeverity() {
        FakeRepository repository = new FakeRepository();
        repository.credentials.add(scanned(1, "AWS", "AKIAIOSFODNN7EXAMPLE", "AKIA****MPLE", true));
        repository.credentials.add(scanned(2, "AWS", "AKIAI44QH8DHBEXAMPLE", "AKIA****MPLE", false));
        repository.credentials.add(scanned(3, "NOTION", null, "ntn_****g7H8", true));

        new CredentialRiskEventService(repository, Clock.fixed(NOW, ZoneOffset.UTC)).createRiskEvents();

        assertThat(repository.inserted)
                .extracting(NewDetectionEvent::severity, NewDetectionEvent::title)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("CRITICAL", "AWS 키 원문 노출"),
                        org.assertj.core.groups.Tuple.tuple("HIGH", "AWS 키 ID 노출"),
                        org.assertj.core.groups.Tuple.tuple("CRITICAL", "Notion 토큰 원문 노출"));
    }

    @Test
    @DisplayName("근거에 발견 위치와 마스킹 값만 있고, 환경을 모르면 운영으로 간주한다")
    void leakEvidence() {
        FakeRepository repository = new FakeRepository();
        repository.credentials.add(scanned(1, "AWS", "AKIAIOSFODNN7EXAMPLE", "AKIA****MPLE", true));

        new CredentialRiskEventService(repository, Clock.fixed(NOW, ZoneOffset.UTC)).createRiskEvents();

        NewDetectionEvent event = repository.inserted.get(0);
        assertThat(event.evidence())
                .contains("발견 위치: " + LOCATION, "노출 값: AKIA****MPLE", "Secret Access Key: 함께 노출됨",
                        "환경: 미확인이라 운영으로 간주")
                .doesNotContain("AKIAIOSFODNN7EXAMPLE");
        assertThat(event.ownerTeam()).isEqualTo("미지정");
        assertThat(event.domain()).isEqualTo("SECRETS");
    }

    private static StoredCredential scanned(long id, String issuer, String externalId, String masked, boolean secretExposed) {
        String type = "AWS".equals(issuer) ? "AWS_ACCESS_KEY" : "NOTION_TOKEN";
        CollectedCredential credential = new CollectedCredential(issuer, type, externalId, issuer + " key " + masked,
                null, null, ExpiryPolicy.UNKNOWN, null, null, CredentialStatus.UNKNOWN, null, null);
        return new StoredCredential(id, credential, null, null, null, null, "SCAN", masked, LOCATION, secretExposed);
    }

    private static final class FakeRepository extends CredentialRiskRepository {

        private final List<StoredCredential> credentials = new ArrayList<>();
        private final List<NewDetectionEvent> inserted = new ArrayList<>();

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
            inserted.forEach(event -> keys.add(new EventKey(event.credentialId(), event.title())));
            return keys;
        }

        @Override
        public int findMaxSecretsNumber() {
            return 0;
        }

        @Override
        public void insertEvent(NewDetectionEvent event) {
            inserted.add(event);
        }
    }
}
