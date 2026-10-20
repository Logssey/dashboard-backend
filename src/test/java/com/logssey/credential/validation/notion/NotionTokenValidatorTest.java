package com.logssey.credential.validation.notion;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.logssey.credential.validation.ValidationOutcome;
import com.logssey.credential.validation.ValidationReason;
import com.logssey.credential.validation.ValidationResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.LoggerFactory;

/**
 * Notion 토큰 검증 (GET /v1/users/me). WireMock이 Notion인 척하고, 응답별로 결과와 이유가 맞게 나오는지 확인한다.
 * 토큰 값은 가짜다.
 */
class NotionTokenValidatorTest {

    private static final String TOKEN = "ntn_TestOnlyFakeToken000000000000000000000000000000";
    private static final Instant NOW = Instant.parse("2026-10-13T00:00:00Z");
    private static final String PATH = "/v1/users/me";

    @RegisterExtension
    static WireMockExtension notion = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    private NotionTokenValidator validator;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        validator = new NotionTokenValidator(notion.baseUrl(), Duration.ofSeconds(2), Duration.ofMillis(500),
                Clock.fixed(NOW, ZoneOffset.UTC));
        logs = new ListAppender<>();
        logs.start();
        validatorLogger().addAppender(logs);
    }

    /** 공통 확인: 어떤 경우에도 토큰이 로그에 남지 않는다 */
    @AfterEach
    void tokenIsNeverLogged() {
        validatorLogger().detachAppender(logs);
        assertThat(logs.list).extracting(ILoggingEvent::getFormattedMessage)
                .noneMatch(message -> message.contains(TOKEN));
    }

    @Test
    @DisplayName("200: VALID. 주체 종류·워크스페이스 이름만 기록하고, 요청 헤더가 맞다")
    void valid() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("""
                { "object": "user", "id": "bot-0001", "name": "Logssey", "type": "bot",
                  "avatar_url": null,
                  "bot": { "owner": { "type": "workspace", "workspace": true }, "workspace_name": "테스트 워크스페이스" } }
                """)));

        ValidationOutcome outcome = validator.validate(TOKEN);

        assertThat(outcome.result()).isEqualTo(ValidationResult.VALID);
        assertThat(outcome.reason()).isEqualTo(ValidationReason.IDENTITY_CONFIRMED);
        assertThat(outcome.httpStatus()).isEqualTo(200);
        assertThat(outcome.safeFacts()).containsEntry("principalId", "bot-0001")
                .containsEntry("principalType", "bot")
                .containsEntry("ownerType", "workspace")
                .containsEntry("workspaceName", "테스트 워크스페이스")
                .doesNotContainKey("name");
        assertThat(outcome.validatorId()).isEqualTo("notion-self");
        assertThat(outcome.endpointClass()).isEqualTo("IDENTITY_SELF");
        assertThat(outcome.checkedAt()).isEqualTo(NOW);
        notion.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("Authorization", equalTo("Bearer " + TOKEN))
                .withHeader("Notion-Version", equalTo(NotionTokenValidator.NOTION_VERSION)));
    }

    @Test
    @DisplayName("401: INVALID. 만료·폐기라고 추측하지 않는다 (INVALID_UNSPECIFIED)")
    void invalid() {
        stubError(401, "unauthorized");

        ValidationOutcome outcome = validator.validate(TOKEN);

        assertThat(outcome.result()).isEqualTo(ValidationResult.INVALID);
        assertThat(outcome.reason()).isEqualTo(ValidationReason.INVALID_UNSPECIFIED);
        assertThat(outcome.httpStatus()).isEqualTo(401);
        assertThat(outcome.safeFacts()).isEmpty();
    }

    @Test
    @DisplayName("403: 무효로 단정하지 않고 UNKNOWN / PERMISSION_LIMITED")
    void forbidden() {
        stubError(403, "restricted_resource");

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.PERMISSION_LIMITED);
    }

    @Test
    @DisplayName("429: UNKNOWN / RATE_LIMITED, 기다릴 시간 기록, 여기서 다시 시도하지 않음")
    void rateLimited() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(429)
                .withHeader("Retry-After", "30")
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"object\": \"error\", \"status\": 429, \"code\": \"rate_limited\" }")));

        ValidationOutcome outcome = validator.validate(TOKEN);

        assertResult(outcome, ValidationResult.UNKNOWN, ValidationReason.RATE_LIMITED);
        assertThat(outcome.retryAfter()).isEqualTo(Duration.ofSeconds(30));
        notion.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    @DisplayName("400: 우리 요청이 잘못된 것 (예: 낡은 Notion-Version). UNKNOWN / VALIDATOR_AUTH_ERROR")
    void badRequest() {
        stubError(400, "missing_version");

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.VALIDATOR_AUTH_ERROR);
    }

    @Test
    @DisplayName("500·503: UNKNOWN / PROVIDER_ERROR")
    void providerError() {
        stubError(503, "service_unavailable");

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.PROVIDER_ERROR);
    }

    @Test
    @DisplayName("200인데 사용자 정보가 아님: VALID로 치지 않고 UNKNOWN / PROVIDER_ERROR")
    void unexpectedBody() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("{ \"object\": \"list\" }")));

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.PROVIDER_ERROR);
    }

    @Test
    @DisplayName("연결이 끊김: UNKNOWN / NETWORK_ERROR")
    void connectionReset() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.NETWORK_ERROR);
    }

    @Test
    @DisplayName("응답이 너무 늦음(시간 초과): UNKNOWN / NETWORK_ERROR")
    void timeout() {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("{}").withFixedDelay(2000)));

        assertResult(validator.validate(TOKEN), ValidationResult.UNKNOWN, ValidationReason.NETWORK_ERROR);
    }

    @Test
    @DisplayName("빈 값: 요청하지 않고 UNCHECKED / INCOMPLETE_CREDENTIAL")
    void blankToken() {
        assertResult(validator.validate(" "), ValidationResult.UNCHECKED, ValidationReason.INCOMPLETE_CREDENTIAL);
        assertResult(validator.validate(null), ValidationResult.UNCHECKED, ValidationReason.INCOMPLETE_CREDENTIAL);
        notion.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    @DisplayName("Notion 형식이 아니거나 이상한 문자가 섞임: 요청하지 않고 UNCHECKED / UNSUPPORTED_TYPE")
    void unsupportedFormat() {
        assertResult(validator.validate("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
                ValidationResult.UNCHECKED, ValidationReason.UNSUPPORTED_TYPE);
        assertResult(validator.validate("ntn_abcdefghijklmnopqrstuvwxyz\r\nX-Injected: 1"),
                ValidationResult.UNCHECKED, ValidationReason.UNSUPPORTED_TYPE);
        notion.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    @DisplayName("결과와 검증기 toString에 토큰이 나오지 않는다")
    void resultNeverContainsToken() {
        stubError(401, "unauthorized");

        ValidationOutcome outcome = validator.validate(TOKEN);

        assertThat(outcome.toString()).doesNotContain(TOKEN);
        assertThat(validator.toString()).doesNotContain(TOKEN);
    }

    private static void assertResult(ValidationOutcome outcome, ValidationResult result, ValidationReason reason) {
        assertThat(outcome.result()).isEqualTo(result);
        assertThat(outcome.reason()).isEqualTo(reason);
    }

    private static void stubError(int status, String code) {
        notion.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(status)
                .withHeader("Content-Type", "application/json")
                .withBody("{ \"object\": \"error\", \"status\": %d, \"code\": \"%s\", \"message\": \"test\" }"
                        .formatted(status, code))));
    }

    private static Logger validatorLogger() {
        return (Logger) LoggerFactory.getLogger(NotionTokenValidator.class);
    }
}
