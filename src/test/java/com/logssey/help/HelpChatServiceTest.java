package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.logssey.help.HelpChatDtos.ChatRequest;
import com.logssey.help.HelpChatService.HelpChatException;

/** Full chat flow against a fake Messages API on loopback. No real API key and no Docker are needed. */
class HelpChatServiceTest {

    private static final List<Captured> REQUESTS = new CopyOnWriteArrayList<>();
    private static final AtomicReference<String> NEXT_RESPONSE = new AtomicReference<>();
    private static final AtomicReference<Integer> NEXT_STATUS = new AtomicReference<>(200);
    private static final String FAKE_KEY = "test-" + HelpTestKeys.random("abcdef0123456789", 24);
    private static HttpServer server;
    private static String endpoint;

    record Captured(String apiKey, String version, String body) {
    }

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/messages", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            REQUESTS.add(new Captured(exchange.getRequestHeaders().getFirst("x-api-key"),
                    exchange.getRequestHeaders().getFirst("anthropic-version"), body));
            byte[] reply = NEXT_RESPONSE.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("content-type", "application/json");
            exchange.sendResponseHeaders(NEXT_STATUS.get(), reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        server.start();
        endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages";
    }

    @AfterAll
    static void stop() {
        if (server != null) server.stop(0);
    }

    @BeforeEach
    void reset() {
        REQUESTS.clear();
        NEXT_STATUS.set(200);
    }

    private static ClaudeHelpProvider provider(boolean enabled) {
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        return new ClaudeHelpProvider(enabled, enabled ? FAKE_KEY : "", "", endpoint, 5_000, http, true);
    }

    private static HelpChatService service(HelpCallBudget.Limits limits) {
        var clock = new HelpCallBudgetTest.MutableClock(Instant.parse("2026-11-19T01:00:00Z"), ZoneId.of("Asia/Seoul"));
        return new HelpChatService(new HelpDocumentLibrary(), provider(true), new HelpCallBudget(limits, clock));
    }

    private static HelpChatService service() {
        return service(new HelpCallBudget.Limits(5, 40, 20, 300));
    }

    private static String grounded(String text) {
        return HelpAnswerFilterTest.message("end_turn", "[" + HelpAnswerFilterTest.citedText(text, 0, 0) + "]");
    }

    private static String code(Throwable e) {
        return ((HelpChatException) e).code();
    }

    @Test
    void answersFromGuidesWithSources() {
        NEXT_RESPONSE.set(grounded("상단 오른쪽 로그아웃 버튼을 누르세요."));
        var response = service().chat("admin", new ChatRequest("로그아웃은 어떻게 해요?", "통합 현황", List.of()));

        assertThat(response.grounded()).isTrue();
        assertThat(response.answer()).contains("로그아웃");
        assertThat(response.sources()).isNotEmpty();
        assertThat(response.remainingToday()).isEqualTo(39);

        assertThat(REQUESTS).hasSize(1);
        var sent = REQUESTS.get(0);
        assertThat(sent.apiKey()).isEqualTo(FAKE_KEY);
        assertThat(sent.version()).isEqualTo(ClaudeHelpProvider.API_VERSION);
        assertThat(sent.body()).doesNotContain("\"tools\"", FAKE_KEY);
        assertThat(sent.body()).contains("\"type\":\"document\"", "로그아웃은 어떻게 해요?", "현재 화면: 통합 현황");
    }

    @Test
    void ungroundedAnswerBecomesFixedNotFoundMessage() {
        NEXT_RESPONSE.set(HelpAnswerFilterTest.message("end_turn", "[{\"type\":\"text\",\"text\":\"모르겠어요\"}]"));
        var response = service().chat("admin", new ChatRequest("오늘 점심 메뉴 추천해 줘", "", List.of()));

        assertThat(response.grounded()).isFalse();
        assertThat(response.answer()).isEqualTo(HelpChatService.NOT_FOUND_ANSWER);
        assertThat(response.sources()).isEmpty();
    }

    @Test
    void secretLikeQuestionIsRejectedWithoutAnyCall() {
        NEXT_RESPONSE.set(grounded("x"));
        var chat = service();
        assertThatThrownBy(() -> chat.chat("admin",
                new ChatRequest("이 키 유효해요? " + HelpTestKeys.anthropicLike(), "", List.of())))
                .isInstanceOf(HelpChatException.class)
                .satisfies(e -> assertThat(code(e)).isEqualTo("QUESTION_REJECTED"));
        assertThatThrownBy(() -> chat.chat("admin", new ChatRequest("다음 질문", "", List.of(
                new HelpTurn("user", "토큰 " + HelpTestKeys.githubLike()), new HelpTurn("assistant", "답")))))
                .satisfies(e -> assertThat(code(e)).isEqualTo("QUESTION_REJECTED"));

        assertThat(REQUESTS).isEmpty();
        // Rejected questions do not use up the quota.
        NEXT_RESPONSE.set(grounded("답"));
        assertThat(chat.chat("admin", new ChatRequest("정상 질문", "", List.of())).remainingToday()).isEqualTo(39);
    }

    @Test
    void enforcesPerUserMinuteLimitAndChargesFailedCalls() {
        var chat = service(new HelpCallBudget.Limits(2, 40, 20, 300));
        NEXT_STATUS.set(500);
        NEXT_RESPONSE.set("{}");
        assertThatThrownBy(() -> chat.chat("admin", new ChatRequest("질문 1", "", List.of())))
                .satisfies(e -> assertThat(code(e)).isEqualTo("PROVIDER_UNAVAILABLE"));

        NEXT_STATUS.set(200);
        NEXT_RESPONSE.set(grounded("답"));
        chat.chat("admin", new ChatRequest("질문 2", "", List.of()));
        assertThatThrownBy(() -> chat.chat("admin", new ChatRequest("질문 3", "", List.of())))
                .satisfies(e -> {
                    assertThat(code(e)).isEqualTo("RATE_LIMITED");
                    assertThat(((HelpChatException) e).retryAfterSeconds()).isBetween(1, 61);
                });
        chat.chat("viewer", new ChatRequest("질문 4", "", List.of()));
        assertThat(REQUESTS).hasSize(3);
    }

    @Test
    void repeatedQuestionIsServedFromCacheWithoutCharge() {
        var chat = service();
        NEXT_RESPONSE.set(grounded("답"));
        chat.chat("admin", new ChatRequest("로그인은 어떻게 해요?", "통합 현황", List.of()));
        var second = chat.chat("admin", new ChatRequest("  로그인은   어떻게 해요? ", "통합 현황", List.of()));

        assertThat(second.cached()).isTrue();
        assertThat(REQUESTS).hasSize(1);
    }

    @Test
    void historyIsSentAsAlternatingTurns() {
        NEXT_RESPONSE.set(grounded("답"));
        service().chat("admin", new ChatRequest("그다음은요?", "", List.of(
                new HelpTurn("user", "스캔은 어디서 해요?"), new HelpTurn("assistant", "스캔 이력 화면이에요."))));
        String body = REQUESTS.get(0).body();
        assertThat(body.indexOf("스캔은 어디서 해요?")).isLessThan(body.indexOf("스캔 이력 화면이에요."));
        assertThat(body.indexOf("스캔 이력 화면이에요.")).isLessThan(body.indexOf("그다음은요?"));
    }

    @Test
    void malformedHistoryAndPageAreDropped() {
        assertThat(HelpChatService.cleanHistory(List.of(new HelpTurn("system", "x"), new HelpTurn("assistant", "y"))))
                .isEmpty();
        assertThat(HelpChatService.cleanHistory(List.of(new HelpTurn("user", "a")))).isEmpty();
        assertThat(HelpChatService.cleanPage("키·노출 위치")).isEqualTo("키·노출 위치");
        assertThat(HelpChatService.cleanPage("<script>")).isEmpty();
    }

    @Test
    void missingKeyReportsNotConfiguredWithoutCalling() {
        var chat = new HelpChatService(new HelpDocumentLibrary(), provider(false),
                new HelpCallBudget(new HelpCallBudget.Limits(5, 40, 20, 300), java.time.Clock.systemUTC()));

        assertThat(chat.status().ready()).isFalse();
        assertThat(chat.status().reasonCode()).isEqualTo("DISABLED");
        assertThatThrownBy(() -> chat.chat("admin", new ChatRequest("질문", "", List.of())))
                .satisfies(e -> assertThat(code(e)).isEqualTo("NOT_CONFIGURED"));
        assertThat(REQUESTS).isEmpty();
    }
}
