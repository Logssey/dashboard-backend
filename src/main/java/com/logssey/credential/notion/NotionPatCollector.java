package com.logssey.credential.notion;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.CredentialStatus;
import com.logssey.credential.ExpiryPolicy;
import com.logssey.credential.notion.dto.NotionErrorBody;
import com.logssey.credential.notion.dto.NotionPat;
import com.logssey.credential.notion.dto.NotionPatPage;
import com.logssey.credential.notion.dto.NotionPerson;
import com.logssey.credential.notion.dto.NotionRevoker;
import com.logssey.credential.risk.TokenRiskEvaluator;
import com.logssey.credential.risk.TokenRiskFinding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse;

/**
 * Notion Enterprise 워크스페이스의 PAT 목록을 수집한다 (ADR-D010 ① 목록 수집).
 *
 * - 요청: GET {baseUrl}/v1/spaces/{space_id}/personal_access_tokens
 * - 페이지 나눔: has_more가 true면 next_cursor로 다음 페이지를 끝까지 받는다
 * - 429: retry-after만큼 기다렸다가 다시 요청. 횟수는 페이지(요청)마다 센다
 * - 401·403·그 밖의 오류: 다시 시도하지 않고 바로 실패
 * - expires_at이 없으면 "만료 없음"(NEVER)으로 본다 (테스트 시나리오 1.2)
 * - 연동 토큰은 로그에 남기지 않는다 (ADR-D009)
 *
 * 아직 Spring 빈으로 등록하지 않는다. 호출하는 곳(수집 일정, DB 저장)이 정해지면 연결한다.
 */
public class NotionPatCollector {

    private static final Logger log = LoggerFactory.getLogger(NotionPatCollector.class);

    static final String ISSUER = "NOTION";
    static final String CREDENTIAL_TYPE = "NOTION_PAT";
    private static final String PATH = "/v1/spaces/{spaceId}/personal_access_tokens";

    private final RestClient restClient;
    private final NotionAdminSettings settings;
    private final TokenRiskEvaluator riskEvaluator;
    private final Sleeper sleeper;

    public NotionPatCollector(NotionAdminSettings settings, TokenRiskEvaluator riskEvaluator, Sleeper sleeper) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.riskEvaluator = Objects.requireNonNull(riskEvaluator, "riskEvaluator");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
        this.restClient = RestClient.builder()
                .baseUrl(settings.baseUrl())
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + settings.token())
                .defaultHeader("Notion-Version", NotionAdminSettings.NOTION_VERSION)
                .build();
    }

    public NotionCollectionResult collect(String spaceId) {
        List<CollectedCredential> credentials = new ArrayList<>();
        String cursor = null;
        do {
            PageOutcome outcome = fetchWithRetry(spaceId, cursor);
            if (outcome.failure() != null) {
                log.warn("Notion PAT collection failed. failure={}, httpStatus={}",
                        outcome.failure(), outcome.httpStatus());
                return NotionCollectionResult.failed(outcome.failure());
            }
            NotionPatPage page = outcome.page();
            if (page.results() != null) {
                for (NotionPat pat : page.results()) {
                    credentials.add(toCredential(pat));
                }
            }
            if (page.hasMore() && (page.nextCursor() == null || page.nextCursor().isBlank())) {
                log.warn("Notion PAT collection failed. has_more is true but next_cursor is missing");
                return NotionCollectionResult.failed(CollectionFailure.UNEXPECTED_RESPONSE);
            }
            cursor = page.hasMore() ? page.nextCursor() : null;
        } while (cursor != null);

        List<TokenRiskFinding> findings = credentials.stream()
                .flatMap(credential -> riskEvaluator.evaluate(credential).stream())
                .toList();
        log.info("Notion PAT collection succeeded. tokens={}, findings={}", credentials.size(), findings.size());
        return NotionCollectionResult.succeeded(credentials, findings);
    }

    private PageOutcome fetchWithRetry(String spaceId, String cursor) {
        int retries = 0;
        while (true) {
            HttpResult result;
            try {
                result = fetchPage(spaceId, cursor);
            } catch (RuntimeException e) {
                // 예외 메시지에 요청 정보가 섞일 수 있으므로 종류만 남긴다
                log.warn("Notion PAT request failed. reason={}", e.getClass().getSimpleName());
                return PageOutcome.failed(CollectionFailure.UNEXPECTED_RESPONSE, 0);
            }

            if (result.status() == 200) {
                return result.page() != null
                        ? PageOutcome.ok(result.page())
                        : PageOutcome.failed(CollectionFailure.UNEXPECTED_RESPONSE, 200);
            }
            if (result.status() == 429) {
                if (retries >= settings.maxRetries()) {
                    return PageOutcome.failed(CollectionFailure.RATE_LIMITED, 429);
                }
                Duration wait = retryAfter(result.retryAfter());
                retries++;
                log.info("Notion rate limited. Waiting {} seconds before retry {}/{}",
                        wait.toSeconds(), retries, settings.maxRetries());
                sleeper.sleep(wait);
                continue;
            }
            return PageOutcome.failed(CollectionFailure.fromError(result.status(), result.errorCode()), result.status());
        }
    }

    private HttpResult fetchPage(String spaceId, String cursor) {
        return restClient.get()
                .uri(builder -> {
                    builder.path(PATH).queryParam("page_size", settings.pageSize());
                    if (cursor != null) {
                        builder.queryParam("cursor", cursor);
                    }
                    return builder.build(spaceId);
                })
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    if (status == 200) {
                        return new HttpResult(status, response.bodyTo(NotionPatPage.class), null, null);
                    }
                    return new HttpResult(status, null, readErrorCode(response),
                            response.getHeaders().getFirst("Retry-After"));
                });
    }

    private static String readErrorCode(ConvertibleClientHttpResponse response) {
        try {
            NotionErrorBody body = response.bodyTo(NotionErrorBody.class);
            return body != null ? body.code() : null;
        } catch (RuntimeException e) {
            // 본문이 없거나 형식이 다르면 상태 코드로만 판단한다
            return null;
        }
    }

    private Duration retryAfter(String headerValue) {
        if (headerValue != null) {
            try {
                long seconds = Long.parseLong(headerValue.trim());
                if (seconds >= 0) {
                    return Duration.ofSeconds(seconds);
                }
            } catch (NumberFormatException ignored) {
                // 숫자가 아니면 기본값을 쓴다
            }
        }
        return settings.retryAfterFallback();
    }

    private static CollectedCredential toCredential(NotionPat pat) {
        Instant expiresAt = toInstant(pat.expiresAt());
        return new CollectedCredential(
                ISSUER,
                CREDENTIAL_TYPE,
                pat.id(),
                pat.name(),
                owner(pat.creator()),
                toInstant(pat.createdAt()),
                expiresAt != null ? ExpiryPolicy.FIXED : ExpiryPolicy.NEVER,
                expiresAt,
                toInstant(pat.lastUsedAt()),
                toStatus(pat.status()),
                toInstant(pat.revokedAt()),
                revokedBy(pat.revokedBy()));
    }

    private static Instant toInstant(Long epochMillis) {
        return epochMillis != null ? Instant.ofEpochMilli(epochMillis) : null;
    }

    private static String owner(NotionPerson creator) {
        if (creator == null) {
            return null;
        }
        return creator.name() != null && !creator.name().isBlank() ? creator.name() : creator.id();
    }

    private static String revokedBy(NotionRevoker revoker) {
        return revoker != null ? revoker.type() + ":" + revoker.id() : null;
    }

    private static CredentialStatus toStatus(String status) {
        if (status == null) {
            return CredentialStatus.UNKNOWN;
        }
        return switch (status) {
            case "active" -> CredentialStatus.ACTIVE;
            case "expired" -> CredentialStatus.EXPIRED;
            case "revoked" -> CredentialStatus.REVOKED;
            default -> CredentialStatus.UNKNOWN;
        };
    }

    private record HttpResult(int status, NotionPatPage page, String errorCode, String retryAfter) {
    }

    private record PageOutcome(NotionPatPage page, CollectionFailure failure, int httpStatus) {

        static PageOutcome ok(NotionPatPage page) {
            return new PageOutcome(page, null, 200);
        }

        static PageOutcome failed(CollectionFailure failure, int httpStatus) {
            return new PageOutcome(null, failure, httpStatus);
        }
    }
}
