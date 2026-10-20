package com.logssey.credential.validation.notion;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import com.logssey.credential.validation.ValidationOutcome;
import com.logssey.credential.validation.ValidationReason;
import com.logssey.credential.validation.ValidationResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse;

/**
 * 발견한 Notion 토큰이 지금 살아 있는지 Notion에 물어본다 (Secret 기준 문서: 검증기 등록 계약, Notion 연결 토큰).
 *
 * - 호출: GET {baseUrl}/v1/users/me, 검사할 토큰을 Bearer로. 페이지나 데이터는 읽지 않고 "이 토큰 주인이 누구냐"만 묻는다
 * - 호출 대상은 설정한 baseUrl 하나뿐이다. 발견한 문서에 적힌 주소로는 요청하지 않는다
 * - 형식이 맞지 않으면 요청하지 않는다 (UNCHECKED). 이상한 문자가 헤더에 들어가는 것도 막는다
 * - 응답 해석 (05-research/verification-and-risk 3장):
 *     200 → VALID / IDENTITY_CONFIRMED (주체 종류, 워크스페이스 이름만 기록)
 *     401 → INVALID / INVALID_UNSPECIFIED (만료·폐기라고 추측하지 않음)
 *     403 → UNKNOWN / PERMISSION_LIMITED (무효로 단정하지 않음)
 *     429 → UNKNOWN / RATE_LIMITED (기다릴 시간 기록. 여기서 다시 시도하지 않고 다음 검사 일정에 맡긴다)
 *     400 → UNKNOWN / VALIDATOR_AUTH_ERROR (우리 요청이 잘못됨. 예: Notion-Version이 낡음)
 *     그 밖의 응답, 5xx, 이해할 수 없는 본문 → UNKNOWN / PROVIDER_ERROR
 *     연결 실패, 시간 초과 → UNKNOWN / NETWORK_ERROR
 * - 토큰과 응답 본문은 로그·결과에 넣지 않는다
 *
 * 아직 Spring 빈으로 등록하지 않는다. 결과를 저장할 secret_validation_attempts가 생기면 연결한다.
 */
public class NotionTokenValidator {

    public static final String VALIDATOR_ID = "notion-self";
    public static final String VALIDATOR_VERSION = "1";
    public static final String ENDPOINT_CLASS = "IDENTITY_SELF";
    public static final String NOTION_VERSION = "2026-03-11";
    static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(15);
    static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(20);

    /** ntn_ (현재 형식), secret_ (예전 내부 연결 형식). 영문·숫자 외 문자는 받지 않는다 */
    private static final Pattern SUPPORTED_TOKEN = Pattern.compile("^(?:ntn_|secret_)[A-Za-z0-9]{20,200}$");

    private static final Logger log = LoggerFactory.getLogger(NotionTokenValidator.class);

    private final RestClient restClient;
    private final Clock clock;

    public NotionTokenValidator(String baseUrl) {
        this(baseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, Clock.systemUTC());
    }

    NotionTokenValidator(String baseUrl, Duration connectTimeout, Duration readTimeout, Clock clock) {
        Objects.requireNonNull(baseUrl, "baseUrl");
        this.clock = Objects.requireNonNull(clock, "clock");
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(readTimeout);
        this.restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .baseUrl(baseUrl)
                .defaultHeader("Notion-Version", NOTION_VERSION)
                .build();
    }

    public ValidationOutcome validate(String token) {
        if (token == null || token.isBlank()) {
            return outcome(ValidationResult.UNCHECKED, ValidationReason.INCOMPLETE_CREDENTIAL, null, null, Map.of());
        }
        if (!SUPPORTED_TOKEN.matcher(token).matches()) {
            return outcome(ValidationResult.UNCHECKED, ValidationReason.UNSUPPORTED_TYPE, null, null, Map.of());
        }

        ValidationOutcome result;
        try {
            result = restClient.get()
                    .uri("/v1/users/me")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange((request, response) -> interpret(response));
        } catch (ResourceAccessException e) {
            // 예외 메시지에는 요청 정보가 섞일 수 있어 예외 종류(클래스 이름)만 남긴다
            log.warn("Notion token validation could not reach Notion. causes={}", causeChain(e));
            result = outcome(ValidationResult.UNKNOWN, ValidationReason.NETWORK_ERROR, null, null, Map.of());
        } catch (RuntimeException e) {
            // 본문을 읽지 못한 경우 등. 예외 메시지에 응답 내용이 섞일 수 있어 종류만 남긴다
            log.warn("Notion token validation failed. causes={}", causeChain(e));
            result = outcome(ValidationResult.UNKNOWN, ValidationReason.PROVIDER_ERROR, null, null, Map.of());
        }
        log.info("Notion token validation finished. result={}, reason={}, httpStatus={}",
                result.result(), result.reason(), result.httpStatus());
        return result;
    }

    private ValidationOutcome interpret(ConvertibleClientHttpResponse response) throws java.io.IOException {
        int status = response.getStatusCode().value();
        return switch (status) {
            case 200 -> identityConfirmed(response.bodyTo(NotionSelfResponse.class));
            case 401 -> outcome(ValidationResult.INVALID, ValidationReason.INVALID_UNSPECIFIED, status, null, Map.of());
            case 403 -> outcome(ValidationResult.UNKNOWN, ValidationReason.PERMISSION_LIMITED, status, null, Map.of());
            case 429 -> outcome(ValidationResult.UNKNOWN, ValidationReason.RATE_LIMITED, status,
                    retryAfter(response.getHeaders().getFirst("Retry-After")), Map.of());
            case 400 -> {
                log.warn("Notion token validation request was rejected (400). Check validator settings such as Notion-Version.");
                yield outcome(ValidationResult.UNKNOWN, ValidationReason.VALIDATOR_AUTH_ERROR, status, null, Map.of());
            }
            default -> outcome(ValidationResult.UNKNOWN, ValidationReason.PROVIDER_ERROR, status, null, Map.of());
        };
    }

    private ValidationOutcome identityConfirmed(NotionSelfResponse self) {
        if (self == null || !"user".equals(self.object()) || self.id() == null) {
            return outcome(ValidationResult.UNKNOWN, ValidationReason.PROVIDER_ERROR, 200, null, Map.of());
        }
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("principalId", self.id());
        if (self.type() != null) {
            facts.put("principalType", self.type());
        }
        if (self.bot() != null) {
            if (self.bot().owner() != null && self.bot().owner().type() != null) {
                facts.put("ownerType", self.bot().owner().type());
            }
            if (self.bot().workspaceName() != null) {
                facts.put("workspaceName", self.bot().workspaceName());
            }
        }
        return outcome(ValidationResult.VALID, ValidationReason.IDENTITY_CONFIRMED, 200, null, facts);
    }

    private ValidationOutcome outcome(ValidationResult result, ValidationReason reason, Integer httpStatus,
                                      Duration retryAfter, Map<String, String> facts) {
        return new ValidationOutcome(result, reason, httpStatus, retryAfter, facts,
                VALIDATOR_ID, VALIDATOR_VERSION, ENDPOINT_CLASS, clock.instant());
    }

    /** 예외와 그 원인들의 클래스 이름만 (메시지는 넣지 않음). 예: ResourceAccessException <- HttpTimeoutException */
    private static String causeChain(Throwable e) {
        StringBuilder chain = new StringBuilder();
        Throwable current = e;
        for (int depth = 0; current != null && depth < 6; depth++) {
            if (chain.length() > 0) {
                chain.append(" <- ");
            }
            chain.append(current.getClass().getName());
            current = current.getCause() == current ? null : current.getCause();
        }
        return chain.toString();
    }

    private static Duration retryAfter(String headerValue) {
        if (headerValue == null) {
            return null;
        }
        try {
            long seconds = Long.parseLong(headerValue.trim());
            return seconds >= 0 ? Duration.ofSeconds(seconds) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public String toString() {
        return "NotionTokenValidator[" + VALIDATOR_ID + " v" + VALIDATOR_VERSION + "]";
    }
}
