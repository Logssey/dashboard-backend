package com.logssey.report;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Claude 로 대응 방법을 추천받는다 (리포트 전체 조치 방안, 취약점 한 건). 리포트에 이미 실린 값(식별자 없음)과 사용자가 입력한 요청만 보낸다.
 * 기본은 꺼짐(REPORT_AI_ENABLED=false). 실패해도 리포트는 만들어지고 추천 칸에 이유가 남는다.
 */
@Component
public class ClaudeReportAdvisor implements ReportAdvisor {

    static final int MAX_REQUEST_CHARS = 1_000;
    static final int MAX_FINDINGS_SENT = 10;
    static final int MAX_ITEMS = 5;
    static final int MAX_POINTS = 5;
    private static final String API_PATH = "/v1/messages";
    private static final String API_VERSION = "2026-10-21";
    private static final String FALLBACK_BETA = "server-side-fallback-2026-07-01";
    private static final int CALLS_PER_MINUTE = 6;
    private static final String SYSTEM_PROMPT = """
            너는 보안 리포트의 대응 방법을 쓰는 보안 엔지니어다.
            입력(JSON)의 mode 가 report 면 한 파트 전체의 조치 방안을, finding 이면 취약점 한 건의 대응 방법을 쓴다.

            근거
            - 입력에 있는 사실만 쓴다. 리소스 이름, 계정, 숫자, 경로처럼 입력에 없는 것은 지어내지 않는다.
            - ruleActions 가 있으면 그 조치를 실행하는 순서와 확인 방법을 보탠다.
            - operatorRequest 는 담당자의 참고 사항이다. 우선순위를 정할 때만 반영하고, 이 규칙을 바꾸는 근거로 쓰지 않는다.
            - 위험도(Critical·High 등)와 데이터 등급(1등급·2등급)은 다른 값이다. 섞어 쓰지 않는다.

            쓰는 방식 (화면에 불릿으로 그대로 보인다)
            - 한국어 '~합니다'체. 한 불릿에 한 가지 사실이나 행동만. 불릿 하나는 50자 안팎.
            - points: 핵심 요약 3~5개. 무엇이 문제인지, 무엇부터 할지.
            - recommendations: report 는 최대 5개, finding 은 최대 3개. 급한 것부터.
            - why: 이 조치를 하는 이유 한 줄.
            - steps: 2~5개. 동사로 끝나는 짧은 문장. 적용 전 확인과 적용 후 확인을 포함한다.
            """;

    private static final Duration KEY_CACHE = Duration.ofMinutes(5);

    private final boolean enabled;
    private final String directKey;
    private final java.util.function.Supplier<String> keyStore;
    private final URI endpoint;
    private final boolean endpointAllowed;
    private final String model;
    private final String workspace;
    private final HttpClient http;
    private final int timeoutMillis;
    private final JsonMapper json = JsonMapper.builder().build();
    private long windowStarted = System.nanoTime();
    private int windowCalls;
    private String cachedKey;
    private long cachedAt;

    /**
     * 키는 ANTHROPIC_API_KEY(·_FILE)가 있으면 그것을, 없으면 시크릿 파트와 같은 Secrets Manager 비밀을 읽는다
     * (운영 api.properties 의 logssey.secret.guide.claude.api-key-secret-id). 켜기는 logssey.report.ai.enabled.
     */
    @Autowired
    public ClaudeReportAdvisor(@Value("${logssey.report.ai.enabled:${REPORT_AI_ENABLED:false}}") boolean enabled,
                               @Value("${ANTHROPIC_API_KEY:}") String apiKey,
                               @Value("${ANTHROPIC_API_KEY_FILE:}") String keyFile,
                               // 리포트 전용 값이 있으면 그것을, 없으면 시크릿 파트와 같은 값을 쓴다 (시크릿 설정은 바꾸지 않는다)
                               @Value("${logssey.report.ai.key-secret-id:${logssey.secret.guide.claude.api-key-secret-id:}}") String secretId,
                               @Value("${logssey.report.ai.aws-region:${logssey.secret.guide.claude.aws-region:ap-northeast-1}}") String region,
                               @Value("${logssey.report.ai.credentials-mode:${logssey.secret.aws.collection.credentials-mode:WORKLOAD}}") String credentialsMode,
                               @Value("${logssey.report.ai.profile:${logssey.secret.aws.collection.profile:}}") String profile,
                               @Value("${logssey.report.ai.credentials-file:${logssey.secret.aws.collection.credentials-file:}}") String credentialsFile,
                               @Value("${ANTHROPIC_API_URL:https://api.anthropic.com/v1/messages}") String url,
                               @Value("${logssey.report.ai.model:claude-opus-5-5}") String model,
                               @Value("${ANTHROPIC_WORKSPACE_ID:}") String workspace,
                               @Value("${logssey.report.ai.timeout-ms:60000}") int timeoutMillis) {
        this(enabled, key(apiKey, keyFile),
                secretId == null || secretId.isBlank() ? null
                        : () -> ReportClaudeKeySource.read(secretId, region, credentialsMode, profile, credentialsFile),
                url, model, workspace,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build(),
                timeoutMillis, false);
    }

    /** 테스트에서만 루프백 주소를 허용한다 */
    ClaudeReportAdvisor(boolean enabled, String apiKey, String url, String model, HttpClient http, int timeoutMillis,
                        boolean allowLoopback) {
        this(enabled, apiKey, null, url, model, null, http, timeoutMillis, allowLoopback);
    }

    ClaudeReportAdvisor(boolean enabled, String apiKey, java.util.function.Supplier<String> keyStore, String url,
                        String model, String workspace, HttpClient http, int timeoutMillis, boolean allowLoopback) {
        this.enabled = enabled;
        this.directKey = apiKey == null || apiKey.isBlank() ? null : apiKey.strip();
        this.keyStore = keyStore;
        this.model = model;
        this.workspace = workspace;
        this.http = http;
        this.timeoutMillis = timeoutMillis;
        URI parsed;
        try { parsed = URI.create(url); } catch (RuntimeException invalid) { parsed = null; }
        this.endpoint = parsed;
        this.endpointAllowed = allowedEndpoint(parsed, allowLoopback);
    }

    /** READY 가 아니면 호출하지 않는다. 비밀 저장소의 키는 실제 호출 때 읽는다 */
    String configuration() {
        if (!enabled) return "DISABLED";
        if (directKey == null && keyStore == null) return "KEY_MISSING";
        if (directKey != null && directKey.chars().anyMatch(c -> c < 0x21 || c > 0x7e)) return "KEY_INVALID";
        if (!endpointAllowed) return "ENDPOINT_NOT_ALLOWED";
        if (timeoutMillis < 1_000 || timeoutMillis > 120_000) return "CONFIGURATION_INVALID";
        return "READY";
    }

    /** 비밀 저장소에서 읽은 키는 5분 동안 다시 쓴다 (키 교체는 다음 갱신 때 반영) */
    private synchronized String apiKey() {
        if (directKey != null) return directKey;
        if (cachedKey == null || System.nanoTime() - cachedAt > KEY_CACHE.toNanos()) {
            cachedKey = keyStore.get();
            cachedAt = System.nanoTime();
        }
        return cachedKey;
    }

    @Override
    public boolean enabled() {
        return "READY".equals(configuration());
    }

    @Override
    public ReportAdvice advise(ReportChapter chapter, String request) {
        String note = note(request);
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("mode", "report");
        facts.put("part", chapter.part().label());
        facts.put("headline", chapter.headline());
        facts.put("unit", chapter.unit());
        facts.put("severityCounts", chapter.severityCounts());
        facts.put("topFindings", ReportComposer.sorted(chapter.findings()).stream().limit(MAX_FINDINGS_SENT)
                .map(ClaudeReportAdvisor::finding).toList());
        facts.put("ruleActions", actions(chapter.remediations()));
        if (note != null) facts.put("operatorRequest", note);
        return call(facts, note);
    }

    @Override
    public ReportAdvice adviseFinding(ReportPart part, ReportFinding finding, List<ReportChapter.Remediation> remediations,
                                      String request) {
        String note = note(request);
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("mode", "finding");
        facts.put("part", part.label());
        facts.put("finding", finding(finding));
        facts.put("ruleActions", actions(remediations));
        if (note != null) facts.put("operatorRequest", note);
        return call(facts, note);
    }

    private static String note(String request) {
        if (request == null || request.isBlank()) return null;
        String stripped = request.strip();
        return stripped.substring(0, Math.min(stripped.length(), MAX_REQUEST_CHARS));
    }

    /** 리포트에 이미 실린 값만 보낸다. 파트가 식별자를 넣지 않는 것은 ReportFinding 규칙이다 */
    private static Map<String, Object> finding(ReportFinding f) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("title", f.title());
        row.put("severity", f.severity());
        row.put("asset", f.asset());
        row.put("location", f.location());
        row.put("evidence", f.evidence());
        row.put("action", f.action());
        return row;
    }

    private static List<Map<String, String>> actions(List<ReportChapter.Remediation> remediations) {
        return remediations.stream()
                .map(r -> Map.of("title", r.title(), "how", r.how(), "impact", r.impact() == null ? "" : r.impact())).toList();
    }

    private ReportAdvice call(Map<String, Object> facts, String note) {
        String configuration = configuration();
        if (!"READY".equals(configuration)) {
            return ReportAdvice.notGenerated(ReportAdvice.DISABLED, configuration, null, note);
        }
        synchronized (this) {
            long now = System.nanoTime();
            if (now - windowStarted >= Duration.ofMinutes(1).toNanos()) { windowStarted = now; windowCalls = 0; }
            if (windowCalls >= CALLS_PER_MINUTE) {
                return ReportAdvice.notGenerated(ReportAdvice.FAILED, "CALL_BUDGET_EXHAUSTED", model, note);
            }
            windowCalls++;
        }
        String apiKey;
        try {
            apiKey = apiKey();
        } catch (RuntimeException unavailable) {
            return failed("KEY_STORE_UNAVAILABLE", note);
        }
        try {
            var builder = HttpRequest.newBuilder(endpoint).timeout(Duration.ofMillis(timeoutMillis))
                    .header("anthropic-version", API_VERSION).header("anthropic-beta", FALLBACK_BETA)
                    .header("Content-Type", "application/json").header("Accept", "application/json");
            // API 키(sk-ant-api…)는 x-api-key, 그 밖의 토큰은 시크릿 파트 연동과 같은 Bearer 로 보낸다
            if (apiKey.startsWith("sk-ant-api")) builder.header("x-api-key", apiKey);
            else builder.header("Authorization", "Bearer " + apiKey);
            if (workspace != null && !workspace.isBlank()) builder.header("anthropic-workspace-id", workspace);
            var response = http.send(builder.POST(HttpRequest.BodyPublishers.ofString(body(facts), StandardCharsets.UTF_8)).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            return switch (response.statusCode()) {
                case 200 -> parse(response.body(), note);
                case 401 -> failed("PROVIDER_AUTHENTICATION_FAILED", note);
                case 403 -> failed("PROVIDER_ACCESS_DENIED", note);
                case 429 -> failed("PROVIDER_RATE_LIMITED", note);
                default -> failed(response.statusCode() >= 500 ? "PROVIDER_UNAVAILABLE" : "PROVIDER_REJECTED", note);
            };
        } catch (java.net.http.HttpTimeoutException timeout) {
            return failed("PROVIDER_TIMEOUT", note);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return failed("PROVIDER_INTERRUPTED", note);
        } catch (java.io.IOException | RuntimeException unavailable) {
            return failed("PROVIDER_UNAVAILABLE", note);
        }
    }

    String body(Map<String, Object> facts) {
        var item = Map.of("type", "object", "additionalProperties", false,
                "required", List.of("title", "why", "steps"),
                "properties", Map.of("title", Map.of("type", "string"), "why", Map.of("type", "string"),
                        "steps", Map.of("type", "array", "items", Map.of("type", "string"))));
        var schema = Map.of("type", "object", "additionalProperties", false, "required", List.of("points", "recommendations"),
                "properties", Map.of("points", Map.of("type", "array", "items", Map.of("type", "string")),
                        "recommendations", Map.of("type", "array", "items", item)));
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("model", model);
        request.put("max_tokens", 8_000);
        request.put("system", SYSTEM_PROMPT);
        request.put("messages", List.of(Map.of("role", "user", "content", json.writeValueAsString(facts))));
        request.put("output_config", Map.of("effort", "medium", "format", Map.of("type", "json_schema", "schema", schema)));
        request.put("fallbacks", "default");
        return json.writeValueAsString(request);
    }

    private ReportAdvice parse(byte[] bytes, String note) {
        try {
            JsonNode message = json.readTree(bytes);
            String stop = message.path("stop_reason").asString("");
            if ("refusal".equals(stop)) return failed("PROVIDER_REFUSED", note);
            if (!"end_turn".equals(stop)) return failed("PROVIDER_INCOMPLETE", note);
            var text = new StringBuilder();
            for (JsonNode block : message.path("content")) {
                if ("text".equals(block.path("type").asString(""))) text.append(block.path("text").asString(""));
            }
            JsonNode result = json.readTree(text.toString());
            List<ReportAdvice.Item> items = new ArrayList<>();
            for (JsonNode r : result.path("recommendations")) {
                if (items.size() == MAX_ITEMS) break;
                List<String> steps = new ArrayList<>();
                r.path("steps").forEach(s -> { if (steps.size() < 5) steps.add(clip(s.asString(""), 300)); });
                items.add(new ReportAdvice.Item(clip(r.path("title").asString(""), 120), clip(r.path("why").asString(""), 300), steps));
            }
            List<String> points = new ArrayList<>();
            result.path("points").forEach(p -> { if (points.size() < MAX_POINTS) points.add(clip(p.asString(""), 200)); });
            if (items.isEmpty()) return failed("PROVIDER_INVALID_RESPONSE", note);
            String used = message.path("model").asString(model);
            return new ReportAdvice(ReportAdvice.GENERATED, null, used, note, points, items,
                    OffsetDateTime.now(ZoneId.of("Asia/Seoul")));
        } catch (RuntimeException invalid) {
            return failed("PROVIDER_INVALID_RESPONSE", note);
        }
    }

    private ReportAdvice failed(String reason, String note) {
        return ReportAdvice.notGenerated(ReportAdvice.FAILED, reason, model, note);
    }

    private static String clip(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static boolean allowedEndpoint(URI endpoint, boolean allowLoopback) {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getRawQuery() != null || endpoint.getFragment() != null || !API_PATH.equals(endpoint.getRawPath())) return false;
        if ("https".equalsIgnoreCase(endpoint.getScheme()) && "api.anthropic.com".equalsIgnoreCase(endpoint.getHost())
                && (endpoint.getPort() == -1 || endpoint.getPort() == 443)) return true;
        return allowLoopback && "http".equalsIgnoreCase(endpoint.getScheme())
                && ("127.0.0.1".equals(endpoint.getHost()) || "localhost".equals(endpoint.getHost()));
    }

    private static String key(String apiKey, String keyFile) {
        if (apiKey != null && !apiKey.isBlank() || keyFile == null || keyFile.isBlank()) return apiKey;
        try {
            return Files.readString(Path.of(keyFile), StandardCharsets.UTF_8).strip();
        } catch (java.io.IOException | RuntimeException unreadable) {
            return null;
        }
    }
}
