package com.logssey.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

class ClaudeReportAdvisorTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private HttpServer server;
    private final AtomicReference<String> body = new AtomicReference<>();
    private final AtomicReference<com.sun.net.httpserver.Headers> headers = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String reply = "";

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/messages", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            headers.set(exchange.getRequestHeaders());
            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
            if (out.length > 0) exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private ClaudeReportAdvisor advisor(boolean enabled, String url) {
        return new ClaudeReportAdvisor(enabled, "sk-ant-api03-test", url, "claude-opus-5-5",
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), 5_000, true);
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages";
    }

    private static ReportChapter chapter() {
        var finding = new ReportFinding("IAC-P1", "인터넷에서 시크릿까지 열린 공격 경로", "CRITICAL", "미조치", "시크릿, 1등급",
                "인터넷 → EC2 → 역할 → 시크릿", "EC2가 IMDSv1을 허용", OffsetDateTime.now(), null, false, "미지정",
                "끊을 지점: EC2 메타데이터를 IMDSv2로만 받기", "/iac");
        return new ReportChapter(ReportPart.IAC, OffsetDateTime.now(), "1등급 데이터까지 열린 경로 1개", "열린 경로",
                null, List.of(), Map.of("CRITICAL", 1L), List.of(finding),
                List.of(new ReportChapter.Remediation("EC2 메타데이터를 IMDSv2로만 받기", "imds_tokens 를 required 로", "열린 경로 1개 닫힘", "/iac")),
                List.of(), List.of(), null, null, null);
    }

    private static String message(String stopReason, String text) {
        return JSON.writeValueAsString(Map.of("type", "message", "role", "assistant", "model", "claude-opus-5-5",
                "stop_reason", stopReason,
                "content", List.of(Map.of("type", "thinking", "thinking", ""), Map.of("type", "text", "text", text))));
    }

    @Test
    void 꺼져_있으면_호출하지_않고_이유를_남긴다() {
        var advice = advisor(false, url()).advise(chapter(), "  다음 주 배포 전 끝내야 함  ");

        assertThat(advice.status()).isEqualTo(ReportAdvice.DISABLED);
        assertThat(advice.reason()).isEqualTo("DISABLED");
        assertThat(advice.request()).isEqualTo("다음 주 배포 전 끝내야 함");
        assertThat(body.get()).isNull();
    }

    @Test
    void 추천을_받아_항목으로_나누고_요청에는_리포트에_실린_값만_보낸다() throws Exception {
        reply = message("end_turn", JSON.writeValueAsString(Map.of("points", List.of("원인은 두 가지", "IMDSv2 강제부터"),
                "recommendations", List.of(Map.of("title", "IMDSv2 강제", "why", "자격 증명 탈취를 막는다",
                        "steps", List.of("변수 변경", "plan 확인", "apply 후 경로 재계산"))))));

        var advice = advisor(true, url()).advise(chapter(), "운영 중단 없이");

        assertThat(advice.status()).isEqualTo(ReportAdvice.GENERATED);
        assertThat(advice.points()).containsExactly("원인은 두 가지", "IMDSv2 강제부터");
        assertThat(advice.items()).singleElement().satisfies(item -> {
            assertThat(item.title()).isEqualTo("IMDSv2 강제");
            assertThat(item.steps()).hasSize(3);
        });
        var sent = JSON.readTree(body.get());
        assertThat(sent.path("model").asString("")).isEqualTo("claude-opus-5-5");
        assertThat(sent.path("fallbacks").asString("")).isEqualTo("default");
        assertThat(sent.path("output_config").path("format").path("type").asString("")).isEqualTo("json_schema");
        assertThat(sent.has("thinking")).as("Opus 5.5 는 thinking 을 보내지 않는다").isFalse();
        var facts = JSON.readTree(sent.path("messages").get(0).path("content").asString(""));
        assertThat(facts.path("mode").asString("")).isEqualTo("report");
        assertThat(facts.path("operatorRequest").asString("")).isEqualTo("운영 중단 없이");
        assertThat(facts.path("topFindings").get(0).path("location").asString("")).isEqualTo("인터넷 → EC2 → 역할 → 시크릿");
        assertThat(headers.get().getFirst("x-api-key")).isEqualTo("sk-ant-api03-test");
        assertThat(headers.get().getFirst("anthropic-beta")).isEqualTo("server-side-fallback-2026-07-01");
    }

    @Test
    void 거절과_서버_오류는_실패로_남긴다() {
        reply = message("refusal", "");
        assertThat(advisor(true, url()).advise(chapter(), null).reason()).isEqualTo("PROVIDER_REFUSED");

        status = 500;
        reply = "{}";
        var failed = advisor(true, url()).advise(chapter(), null);
        assertThat(failed.status()).isEqualTo(ReportAdvice.FAILED);
        assertThat(failed.reason()).isEqualTo("PROVIDER_UNAVAILABLE");
    }

    @Test
    void 형식이_맞지_않는_응답은_실패로_남긴다() {
        reply = message("end_turn", "그냥 문장");
        assertThat(advisor(true, url()).advise(chapter(), null).reason()).isEqualTo("PROVIDER_INVALID_RESPONSE");
    }

    @Test
    void 허용하지_않은_주소로는_보내지_않는다() {
        var advice = new ClaudeReportAdvisor(true, "sk-ant-api03-test", "https://example.com/v1/messages",
                "claude-opus-5-5", HttpClient.newHttpClient(), 5_000, false).advise(chapter(), null);

        assertThat(advice.status()).isEqualTo(ReportAdvice.DISABLED);
        assertThat(advice.reason()).isEqualTo("ENDPOINT_NOT_ALLOWED");
    }

    @Test
    void 환경_변수_키가_없으면_비밀_저장소에서_읽은_키를_쓴다() {
        reply = message("end_turn", JSON.writeValueAsString(Map.of("points", List.of("p"),
                "recommendations", List.of(Map.of("title", "t", "why", "r", "steps", List.of("a", "b"))))));
        var fromStore = new ClaudeReportAdvisor(true, null, () -> "sk-ant-oat01-from-store", url(), "claude-opus-5-5",
                null, HttpClient.newHttpClient(), 5_000, true);

        assertThat(fromStore.enabled()).isTrue();
        assertThat(fromStore.advise(chapter(), null).status()).isEqualTo(ReportAdvice.GENERATED);
        assertThat(headers.get().getFirst("Authorization")).isEqualTo("Bearer sk-ant-oat01-from-store");
    }

    @Test
    void 비밀_저장소를_읽지_못하면_실패로_남기고_보내지_않는다() {
        var broken = new ClaudeReportAdvisor(true, null, () -> { throw new IllegalStateException("x"); }, url(),
                "claude-opus-5-5", null, HttpClient.newHttpClient(), 5_000, true);

        var advice = broken.advise(chapter(), null);

        assertThat(advice.status()).isEqualTo(ReportAdvice.FAILED);
        assertThat(advice.reason()).isEqualTo("KEY_STORE_UNAVAILABLE");
        assertThat(body.get()).isNull();
    }

    @Test
    void 취약점_한_건은_그_건과_규칙_조치만_보낸다() throws Exception {
        reply = message("end_turn", JSON.writeValueAsString(Map.of("points", List.of("EC2가 IMDSv1 허용"),
                "recommendations", List.of(Map.of("title", "IMDSv2 강제", "why", "자격 증명 탈취 차단", "steps", List.of("a", "b"))))));
        var ch = chapter();

        var advice = advisor(true, url()).adviseFinding(ReportPart.IAC, ch.findings().getFirst(), ch.remediations(), null);

        assertThat(advice.status()).isEqualTo(ReportAdvice.GENERATED);
        var facts = JSON.readTree(JSON.readTree(body.get()).path("messages").get(0).path("content").asString(""));
        assertThat(facts.path("mode").asString("")).isEqualTo("finding");
        assertThat(facts.path("finding").path("title").asString("")).isEqualTo("인터넷에서 시크릿까지 열린 공격 경로");
        assertThat(facts.has("topFindings")).isFalse();
    }

    @Test
    void 요청_내용은_1000자로_자른다() {
        var advice = advisor(false, url()).advise(chapter(), "가".repeat(1_500));
        assertThat(advice.request()).hasSize(ClaudeReportAdvisor.MAX_REQUEST_CHARS);
    }
}
