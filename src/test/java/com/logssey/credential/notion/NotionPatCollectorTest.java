package com.logssey.credential.notion;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.LoggerFactory;

/**
 * Notion Admin API Mock 테스트 (06-test/notion-admin-mock-scenarios.md).
 * WireMock이 Notion인 척하고, 수집기가 시나리오별 응답을 맞게 처리하는지 확인한다.
 * DB와 Spring 컨텍스트 없이 돈다.
 */
class NotionPatCollectorTest {

    private static final String TOKEN = "test-org-bot-token-must-not-be-logged";
    private static final String SPACE_ID = "00000000-0000-0000-0000-000000000001";
    private static final String PATH = "/admin/v1/spaces/" + SPACE_ID + "/personal_access_tokens";

    // 테스트용 현재 시각과 시각 값 (시나리오 문서 5장)
    private static final long JAN_1 = 1767225600000L;
    private static final long IN_90_DAYS = 1799193600000L;
    private static final long IN_5_DAYS = 1791849600000L;
    private static final long YESTERDAY = 1791331200000L;
    private static final long DAYS_AGO_2 = 1791244800000L;
    private static final long DAYS_AGO_3 = 1791158400000L;
    private static final long DAYS_AGO_10 = 1790553600000L;
    private static final long DAYS_AGO_60 = 1786233600000L;

    /** retry-after 헤더가 없을 때 기다릴 시간 (이번 단계 기준 1초) */
    private static final Duration TEST_RETRY_AFTER_FALLBACK = NotionAdminSettings.DEFAULT_RETRY_AFTER_FALLBACK;

    @RegisterExtension
    static WireMockExtension notion = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    private RecordingSleeper sleeper;
    private NotionPatCollector collector;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        sleeper = new RecordingSleeper();
        NotionAdminSettings settings = NotionAdminSettings.withDefaults(notion.baseUrl() + "/admin", TOKEN);
        collector = new NotionPatCollector(settings, sleeper);

        logs = new ListAppender<>();
        logs.start();
        collectorLogger().addAppender(logs);
    }

    /** 공통 확인: 어떤 시나리오에서도 연동 토큰이 로그에 남지 않는다 (ADR-D009) */
    @AfterEach
    void tokenIsNeverLogged() {
        collectorLogger().detachAppender(logs);
        assertThat(logs.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .noneMatch(message -> message.contains(TOKEN));
    }

    // ---------------------------------------------------------------- 토큰 상태

    @Test
    @DisplayName("N-01 정상: 2개 수집, 헤더·시각 변환 확인")
    void normal() {
        stubOk(page(false, null,
                pat("pat-0001", JAN_1, IN_90_DAYS, YESTERDAY, "active"),
                pat("pat-0002", JAN_1, IN_90_DAYS, YESTERDAY, "active")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isTrue();
        assertThat(result.credentials()).hasSize(2);

        CollectedCredential first = result.credentials().get(0);
        assertThat(first.issuer()).isEqualTo("NOTION");
        assertThat(first.credentialType()).isEqualTo("NOTION_PAT");
        assertThat(first.externalId()).isEqualTo("pat-0001");
        assertThat(first.owner()).isEqualTo("Team Member A");
        assertThat(first.status()).isEqualTo(CredentialStatus.ACTIVE);
        assertThat(first.expiryPolicy()).isEqualTo(ExpiryPolicy.FIXED);
        assertThat(first.issuedAt()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));
        assertThat(first.expiresAt()).isEqualTo(Instant.parse("2027-01-06T00:00:00Z"));
        assertThat(first.lastUsedAt()).isEqualTo(Instant.parse("2026-10-07T00:00:00Z"));

        notion.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("Authorization", equalTo("Bearer " + TOKEN))
                .withHeader("Notion-Version", equalTo("2026-06-01"))
                .withQueryParam("page_size", equalTo("100"))
                .withQueryParam("cursor", absent()));
    }

    @Test
    @DisplayName("N-02 만료 시각 수집: 5일 뒤 만료 → 만료 방식 FIXED와 만료 시각만 기록 (등급 없음)")
    void expiresAtCollected() {
        stubOk(page(false, null, pat("pat-0002", JAN_1, IN_5_DAYS, YESTERDAY, "active")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        CollectedCredential token = result.credentials().get(0);
        assertThat(token.expiryPolicy()).isEqualTo(ExpiryPolicy.FIXED);
        assertThat(token.expiresAt()).isEqualTo(Instant.parse("2026-10-13T00:00:00Z"));
    }

    @Test
    @DisplayName("N-04 이미 만료: 상태 EXPIRED로 기록")
    void expired() {
        stubOk(page(false, null, pat("pat-0004", JAN_1, DAYS_AGO_3, DAYS_AGO_10, "expired")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.credentials().get(0).status()).isEqualTo(CredentialStatus.EXPIRED);
    }

    @Test
    @DisplayName("N-05 폐기: 상태 REVOKED, 폐기 정보 수집")
    void revoked() {
        stubOk(page(false, null, """
                {
                  "id": "pat-0005",
                  "name": "old-script",
                  "creator": { "id": "user-0001" },
                  "created_at": %d,
                  "expires_at": %d,
                  "status": "revoked",
                  "revoked_at": %d,
                  "revoked_by": { "type": "user", "id": "user-0009" }
                }
                """.formatted(JAN_1, IN_90_DAYS, DAYS_AGO_2)));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        CollectedCredential token = result.credentials().get(0);
        assertThat(token.status()).isEqualTo(CredentialStatus.REVOKED);
        assertThat(token.revokedAt()).isEqualTo(Instant.parse("2026-10-06T00:00:00Z"));
        assertThat(token.revokedBy()).isEqualTo("user:user-0009");
    }

    @Test
    @DisplayName("N-06 마지막 사용 시각 수집: 60일 전 사용 → 시각만 기록 (미사용 경고 없음)")
    void lastUsedAtCollected() {
        stubOk(page(false, null, pat("pat-0006", JAN_1, IN_90_DAYS, DAYS_AGO_60, "active")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.credentials().get(0).lastUsedAt()).isEqualTo(Instant.parse("2026-08-09T00:00:00Z"));
    }

    @Test
    @DisplayName("N-08 한 번도 안 씀: 마지막 사용 시각 없음으로 기록")
    void neverUsed() {
        stubOk(page(false, null, pat("pat-old", JAN_1, IN_90_DAYS, null, "active")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.credentials().get(0).lastUsedAt()).isNull();
    }

    @Test
    @DisplayName("N-09 만료일 없음: 만료 방식 NEVER, 만료 시각 없음")
    void noExpiry() {
        stubOk(page(false, null, pat("pat-0009", JAN_1, null, YESTERDAY, "active")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        CollectedCredential token = result.credentials().get(0);
        assertThat(token.expiryPolicy()).isEqualTo(ExpiryPolicy.NEVER);
        assertThat(token.expiresAt()).isNull();
    }

    // ---------------------------------------------------------------- 응답 모양

    @Test
    @DisplayName("N-10 필수 필드만: 오류 없이 수집. 만료 없음, 사용 기록 없음으로 기록")
    void requiredFieldsOnly() {
        stubOk(page(false, null, """
                { "id": "pat-0010", "creator": { "id": "user-0003" }, "created_at": %d, "status": "active" }
                """.formatted(JAN_1)));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isTrue();
        CollectedCredential token = result.credentials().get(0);
        assertThat(token.displayName()).isNull();
        assertThat(token.lastUsedAt()).isNull();
        assertThat(token.owner()).isEqualTo("user-0003");
        assertThat(token.expiryPolicy()).isEqualTo(ExpiryPolicy.NEVER);
    }

    @Test
    @DisplayName("N-11 페이지 나눔: next_cursor로 두 번째 페이지까지 101개 수집")
    void pagination() {
        String[] firstPageTokens = IntStream.rangeClosed(1, 100)
                .mapToObj(i -> pat("pat-p1-" + i, JAN_1, IN_90_DAYS, YESTERDAY, "active"))
                .toArray(String[]::new);
        notion.stubFor(get(urlPathEqualTo(PATH)).withQueryParam("cursor", absent())
                .willReturn(okJson(page(true, "page-2", firstPageTokens))));
        notion.stubFor(get(urlPathEqualTo(PATH)).withQueryParam("cursor", equalTo("page-2"))
                .willReturn(okJson(page(false, null, pat("pat-p2-1", JAN_1, IN_90_DAYS, YESTERDAY, "active")))));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isTrue();
        assertThat(result.credentials()).hasSize(101);
        notion.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        notion.verify(1, getRequestedFor(urlPathEqualTo(PATH)).withQueryParam("cursor", equalTo("page-2")));
    }

    // ---------------------------------------------------------------- 오류

    @Test
    @DisplayName("N-12 인증 오류 401: 다시 시도 없이 실패, 토큰 재등록 안내")
    void unauthorized() {
        stubError(401, "unauthorized");

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertFailedWithoutRetry(result, CollectionFailure.UNAUTHORIZED);
        assertThat(result.failure().userMessage()).isEqualTo("Notion 연동 토큰이 유효하지 않습니다. 다시 등록해 주세요");
    }

    @Test
    @DisplayName("N-13 권한 부족 403 missing_scope: 다시 시도 없이 실패, 권한 안내")
    void missingScope() {
        stubError(403, "missing_scope");

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertFailedWithoutRetry(result, CollectionFailure.MISSING_SCOPE);
        assertThat(result.failure().userMessage()).isEqualTo("연동 토큰에 personal-access-token:read 권한이 필요합니다");
    }

    @Test
    @DisplayName("N-14 접근 불가 403 forbidden: 다시 시도 없이 실패, 조직 소유자 확인 안내")
    void forbidden() {
        stubError(403, "forbidden");

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertFailedWithoutRetry(result, CollectionFailure.FORBIDDEN);
        assertThat(result.failure().userMessage()).isEqualTo("이 워크스페이스에 접근할 수 없습니다. 조직 소유자에게 확인하세요");
    }

    @Test
    @DisplayName("N-15 호출 제한 후 성공: retry-after 2초 기다린 뒤 다시 요청해 성공")
    void rateLimitedThenRecovered() {
        notion.stubFor(get(urlPathEqualTo(PATH)).inScenario("rate-limit")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(rateLimited("2"))
                .willSetStateTo("recovered"));
        notion.stubFor(get(urlPathEqualTo(PATH)).inScenario("rate-limit")
                .whenScenarioStateIs("recovered")
                .willReturn(okJson(page(false, null, pat("pat-0015", JAN_1, IN_90_DAYS, YESTERDAY, "active")))));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isTrue();
        assertThat(result.credentials()).hasSize(1);
        assertThat(sleeper.waits).containsExactly(Duration.ofSeconds(2));
        notion.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    @DisplayName("N-16 호출 제한 계속: 첫 요청 + 다시 시도 3번 = 4번 요청 후 수집 실패")
    void rateLimitedUntilGiveUp() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(rateLimited("2")));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isFalse();
        assertThat(result.failure()).isEqualTo(CollectionFailure.RATE_LIMITED);
        assertThat(result.credentials()).isEmpty();
        assertThat(sleeper.waits).containsExactly(
                Duration.ofSeconds(2), Duration.ofSeconds(2), Duration.ofSeconds(2));
        notion.verify(4, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    @DisplayName("429에 retry-after가 없으면 설정의 기본 대기 시간을 쓴다")
    void rateLimitedWithoutRetryAfterUsesFallback() {
        notion.stubFor(get(urlPathEqualTo(PATH)).inScenario("no-retry-after")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(rateLimited(null))
                .willSetStateTo("recovered"));
        notion.stubFor(get(urlPathEqualTo(PATH)).inScenario("no-retry-after")
                .whenScenarioStateIs("recovered")
                .willReturn(okJson(page(false, null))));

        NotionCollectionResult result = collector.collect(SPACE_ID);

        assertThat(result.success()).isTrue();
        assertThat(sleeper.waits).containsExactly(TEST_RETRY_AFTER_FALLBACK);
    }

    @Test
    @DisplayName("설정의 toString에 토큰이 나오지 않는다")
    void settingsToStringMasksToken() {
        NotionAdminSettings settings = new NotionAdminSettings(
                NotionAdminSettings.REAL_BASE_URL, TOKEN, 100, 3, TEST_RETRY_AFTER_FALLBACK);

        assertThat(settings.toString()).doesNotContain(TOKEN).contains("token=****");
    }

    // ---------------------------------------------------------------- 도우미

    private void assertFailedWithoutRetry(NotionCollectionResult result, CollectionFailure expected) {
        assertThat(result.success()).isFalse();
        assertThat(result.failure()).isEqualTo(expected);
        assertThat(result.credentials()).isEmpty();
        assertThat(sleeper.waits).isEmpty();
        notion.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    private static void stubOk(String body) {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(body)));
    }

    private static void stubError(int status, String code) {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse()
                .withStatus(status)
                .withHeader("Content-Type", "application/json")
                .withBody(errorBody(status, code))));
    }

    private static ResponseDefinitionBuilder rateLimited(String retryAfterSeconds) {
        ResponseDefinitionBuilder response = aResponse()
                .withStatus(429)
                .withHeader("Content-Type", "application/json")
                .withBody(errorBody(429, "rate_limited"));
        return retryAfterSeconds != null ? response.withHeader("Retry-After", retryAfterSeconds) : response;
    }

    private static String errorBody(int status, String code) {
        return """
                { "object": "error", "status": %d, "code": "%s", "message": "example message" }
                """.formatted(status, code);
    }

    private static String page(boolean hasMore, String nextCursor, String... tokens) {
        String cursorPart = nextCursor != null ? ", \"next_cursor\": \"" + nextCursor + "\"" : "";
        return "{ \"results\": [" + String.join(",", tokens) + "], \"has_more\": " + hasMore + cursorPart + " }";
    }

    /** 이름·만든 사람(이메일 포함)을 갖춘 토큰. null인 시각 값은 칸째로 뺀다 */
    private static String pat(String id, Long createdAt, Long expiresAt, Long lastUsedAt, String status) {
        List<String> fields = new ArrayList<>();
        fields.add("\"id\": \"" + id + "\"");
        fields.add("\"name\": \"" + id + "-name\"");
        fields.add("\"creator\": { \"id\": \"user-0001\", \"name\": \"Team Member A\", \"email\": \"a@example.com\" }");
        fields.add("\"status\": \"" + status + "\"");
        if (createdAt != null) {
            fields.add("\"created_at\": " + createdAt);
        }
        if (expiresAt != null) {
            fields.add("\"expires_at\": " + expiresAt);
        }
        if (lastUsedAt != null) {
            fields.add("\"last_used_at\": " + lastUsedAt);
        }
        return fields.stream().collect(Collectors.joining(", ", "{ ", " }"));
    }

    private static Logger collectorLogger() {
        return (Logger) LoggerFactory.getLogger(NotionPatCollector.class);
    }

    /** 실제로 기다리지 않고, 몇 초를 기다리려 했는지만 기록한다 */
    private static final class RecordingSleeper implements Sleeper {

        private final List<Duration> waits = new ArrayList<>();

        @Override
        public void sleep(Duration duration) {
            waits.add(duration);
        }
    }
}
