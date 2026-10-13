package com.logssey.credential.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;
import com.logssey.credential.query.dto.response.CredentialListResponse;
import com.logssey.credential.query.dto.response.CredentialListResponse.CredentialItem;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 키 목록 조회 (API 명세: 키 목록 조회).
 * 로컬 샘플과 같은 목록 키 5개 + 문서에서 발견한 키 4개로 Secret 기준 문서의 규칙을 확인한다.
 */
class CredentialListServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private FakeRepository repository;
    private CredentialListService service;

    @BeforeEach
    void setUp() {
        repository = new FakeRepository();
        repository.credentials.addAll(List.of(
                inventory(1, "deploy-bot", ExpiryPolicy.FIXED, later(90), ago(1), CredentialStatus.ACTIVE),
                inventory(2, "notion-sync", ExpiryPolicy.FIXED, later(5), ago(1), CredentialStatus.ACTIVE),
                inventory(3, "old-script", ExpiryPolicy.FIXED, later(90), ago(60), CredentialStatus.ACTIVE),
                inventory(4, "legacy-export", ExpiryPolicy.NEVER, null, ago(1), CredentialStatus.ACTIVE),
                inventory(5, "revoked-tool", ExpiryPolicy.FIXED, later(30), ago(40), CredentialStatus.REVOKED),
                // AWS ID + Secret 둘 다 보임
                found(6, "AWS", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", "AWS 키 AKIA****MPLE", true),
                // AWS ID만 보임
                found(7, "AWS", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPL2", "AWS 키 AKIA****MPL2", false),
                // AWS Secret만 보임
                found(8, "AWS", "AWS_ACCESS_KEY", null, "AWS Secret Key wJal****EKEY", true),
                // Notion 토큰
                found(9, "NOTION", "NOTION_TOKEN", null, "Notion 토큰 ntn_****abcd", true)));
        service = new CredentialListService(repository);
    }

    @Test
    @DisplayName("요약 숫자: 전체 9, 문서에서 발견 4, 그중 후보 2, 목록 정보만 5")
    void summary() {
        CredentialListResponse.Summary summary = service.getCredentials("ALL", "ALL", false).summary();

        assertThat(summary.totalCount()).isEqualTo(9);
        assertThat(summary.foundCount()).isEqualTo(4);
        assertThat(summary.candidateCount()).isEqualTo(2);
        assertThat(summary.inventoryCount()).isEqualTo(5);
    }

    @Test
    @DisplayName("구성요소: AWS는 ID와 Secret이 함께 보여야 CONFIRMED, 하나만 보이면 CANDIDATE. 목록 키는 METADATA_ONLY")
    void componentState() {
        assertThat(item(6).componentState()).isEqualTo("CONFIRMED");
        assertThat(item(7).componentState()).isEqualTo("CANDIDATE");
        assertThat(item(8).componentState()).isEqualTo("CANDIDATE");
        assertThat(item(9).componentState()).isEqualTo("CONFIRMED");
        assertThat(item(1).componentState()).isEqualTo("METADATA_ONLY");
    }

    @Test
    @DisplayName("등급: 문서에서 발견한 키는 미평가(UNASSESSED)와 사유. CRITICAL·HIGH를 바로 붙이지 않는다")
    void foundKeysAreUnassessed() {
        assertThat(item(6).severity()).isEqualTo("UNASSESSED");
        assertThat(item(6).missingReason()).isEqualTo("EXPOSURE_UNKNOWN");
        assertThat(item(7).severity()).isEqualTo("UNASSESSED");
        assertThat(item(7).missingReason()).isEqualTo("CREDENTIAL_UNCONFIRMED");
    }

    @Test
    @DisplayName("목록 정보만 있는 키는 만료 임박·만료 없음·미사용이어도 등급이 없다")
    void inventoryHasNoSeverity() {
        // 2: 5일 뒤 만료, 3: 60일 미사용, 4: 만료 없음, 5: 폐기
        for (long id : new long[] {1, 2, 3, 4, 5}) {
            assertThat(item(id).severity()).as("credential %d", id).isNull();
            assertThat(item(id).missingReason()).as("credential %d", id).isNull();
            assertThat(item(id).location()).as("credential %d", id).isNull();
        }
    }

    @Test
    @DisplayName("환경을 모르면 UNKNOWN. PROD로 가정하지 않는다")
    void unknownEnvironment() {
        assertThat(item(6).environment()).isEqualTo("UNKNOWN");
        assertThat(item(1).environment()).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("정렬: 발견한 키(CONFIRMED → CANDIDATE) → 목록 키, 각각 이름순")
    void sorted() {
        assertThat(service.getCredentials("ALL", "ALL", false).items()).extracting(CredentialItem::credentialId)
                .containsExactly(6L, 9L, 8L, 7L, 1L, 4L, 2L, 3L, 5L);
    }

    @Test
    @DisplayName("필터: 발급자·상태·발견한 키만. 요약 숫자는 필터와 관계없이 그대로")
    void filters() {
        assertThat(service.getCredentials("NOTION", "ALL", false).items()).hasSize(6);
        assertThat(service.getCredentials("AWS", "ALL", false).items()).hasSize(3);
        assertThat(service.getCredentials("ALL", "REVOKED", false).items())
                .extracting(CredentialItem::displayName).containsExactly("revoked-tool");

        CredentialListResponse foundOnly = service.getCredentials("ALL", "ALL", true);
        assertThat(foundOnly.items()).extracting(CredentialItem::source).containsOnly("SCAN");
        assertThat(foundOnly.items()).hasSize(4);
        assertThat(foundOnly.summary().totalCount()).isEqualTo(9);
    }

    @Test
    @DisplayName("키 값 표시: 발견 위치, 만료 없음은 expiresAt null, 시각은 초 단위 ISO 8601 UTC")
    void itemValues() {
        assertThat(item(6).location()).isEqualTo("Notion 페이지: 테스트 (page-1)");
        CredentialItem legacy = item(4);
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

    private CredentialItem item(long id) {
        return service.getCredentials("ALL", "ALL", false).items().stream()
                .filter(item -> item.credentialId() == id)
                .findFirst()
                .orElseThrow();
    }

    private static Instant ago(long days) {
        return NOW.minus(Duration.ofDays(days));
    }

    private static Instant later(long days) {
        return NOW.plus(Duration.ofDays(days));
    }

    private static StoredCredential inventory(long id, String name, ExpiryPolicy expiryPolicy, Instant expiresAt,
                                              Instant lastUsedAt, CredentialStatus status) {
        CollectedCredential credential = new CollectedCredential("NOTION", "NOTION_PAT", "sample-pat-" + id, name,
                "Team Member A", ago(120), expiryPolicy, expiresAt, lastUsedAt, status, null, null);
        return new StoredCredential(id, credential, "Platform", null, "API", null, null, false);
    }

    private static StoredCredential found(long id, String issuer, String type, String externalId, String name,
                                          boolean secretSeen) {
        CollectedCredential credential = new CollectedCredential(issuer, type, externalId, name, null, null,
                ExpiryPolicy.UNKNOWN, null, null, CredentialStatus.UNKNOWN, null, null);
        return new StoredCredential(id, credential, null, null, "SCAN", "****",
                "Notion 페이지: 테스트 (page-1)", secretSeen);
    }

    private static final class FakeRepository extends CredentialQueryRepository {

        private final List<StoredCredential> credentials = new ArrayList<>();

        FakeRepository() {
            super(null);
        }

        @Override
        public List<StoredCredential> findAllCredentials() {
            return credentials;
        }
    }
}
