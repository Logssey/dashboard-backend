package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

/** Design doc 12.3: only a fully valid card JSON becomes cards; everything else falls back to playbook text. */
class HelpChecklistTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    static HelpDocument playbook() {
        return new HelpDocumentLibrary().documents().stream()
                .filter(doc -> doc.file().equals(HelpChecklist.PLAYBOOK_FILE)).findFirst().orElseThrow();
    }

    static Map<String, Object> card(String screen, String focus, Integer... checks) {
        var card = new LinkedHashMap<String, Object>();
        card.put("checks", List.of(checks));
        card.put("screen", screen);
        card.put("focus", focus);
        return card;
    }

    /** A valid ten-check answer: nine cards, checks 9 and 10 merged on the same screen. */
    static List<Map<String, Object>> validCards() {
        return new ArrayList<>(List.of(
                card("VULN_FINDINGS", "CVE 검색 칸에 44228을 넣어 Log4j가 나오는지 봅니다.", 1),
                card("VULN_SUMMARY", "상태 × 심각도 표에서 영향 받는 Finding을 봅니다.", 2),
                card("VULN_WORKLOADS", "스캔 없음 · 불일치 카드가 있으면 스캔 요청을 누릅니다.", 3),
                card("IAC", "지금 열린 공격 경로로 바깥에서 닿는지 봅니다.", 4),
                card("RUNTIME", "탐지 결과에서 사고 이후 이상 탐지를 봅니다.", 5),
                card("OUTSIDE", "보안 그룹이나 방화벽으로 막고 서버를 격리합니다.", 6),
                card("SECRET_FINDINGS", "그 서버가 쓰던 키를 찾아 대응 건으로 교체합니다.", 7),
                card("COMPLIANCE", "새 점검 결과에서 새로 실패한 항목을 봅니다.", 8),
                card("VULN_FINDINGS", "수정 버전으로 올린 뒤 새 스캔하고 검토 저장에 남깁니다.", 9, 10)));
    }

    static String modelReply(Object payload) {
        String text = payload instanceof String raw ? raw : JSON.writeValueAsString(payload);
        String block = JSON.writeValueAsString(Map.of("type", "text", "text", text));
        return HelpAnswerFilterTest.message("end_turn", "[" + block + "]");
    }

    static Map<String, Object> answer(List<Map<String, Object>> cards) {
        return Map.of("cards", cards, "closing", "화면에서 직접 확인해 주세요. 저는 실제 탐지 결과를 볼 수 없어요.");
    }

    private static HelpChecklist.Result parse(String reply) {
        return HelpChecklist.parse(reply.getBytes(StandardCharsets.UTF_8), playbook());
    }

    private static HelpChecklist.Result parseWith(Consumer<List<Map<String, Object>>> change) {
        var cards = validCards();
        change.accept(cards);
        return parse(modelReply(answer(cards)));
    }

    private static void assertFallback(HelpChecklist.Result result) {
        assertThat(result.fallback()).as(String.valueOf(result.reasonCode())).isTrue();
        assertThat(result.cards()).isNull();
        assertThat(result.text()).startsWith(HelpChecklist.FALLBACK_INTRO).endsWith(HelpChecklist.CLOSING);
        for (int i = 1; i <= 10; i++) assertThat(result.text()).contains("\n" + i + ". ");
        assertThat(result.sources()).hasSize(10);
    }

    @Test
    void validJsonBecomesCardsWithServerTitlesAndSources() {
        var result = parse(modelReply(answer(validCards())));

        assertThat(result.fallback()).isFalse();
        assertThat(result.cards()).hasSize(9);
        var first = result.cards().get(0);
        assertThat(first.checks()).containsExactly(1);
        assertThat(first.titles()).containsExactly("1. 무엇이 터졌나");
        assertThat(first.screen()).isEqualTo("VULN_FINDINGS");
        assertThat(result.cards().get(8).titles()).containsExactly("9. 고치고 다시 확인", "10. 기록·보고");
        assertThat(result.text()).contains("1. 무엇이 터졌나 (취약점 관리 > Finding 목록)", "Logssey 밖", "볼 수 없어요");
        assertThat(result.sources()).hasSize(10)
                .allSatisfy(source -> assertThat(source.doc()).isEqualTo(HelpChecklist.PLAYBOOK_FILE));
    }

    @Test
    void malformedJsonFallsBack() {
        assertFallback(parse(modelReply("{\"cards\": [ {\"checks\": [1], \"screen\": ")));
        assertFallback(parse(modelReply("체크리스트입니다: 1. CVE 검색")));
        assertFallback(parse(modelReply(Map.of("cards", validCards()))));                       // closing missing
        assertFallback(parseWith(cards -> cards.get(0).put("extra", "x")));                     // unknown field
        assertFallback(parseWith(cards -> cards.get(0).put("checks", List.of("1"))));           // not a number
        assertFallback(parse(HelpAnswerFilterTest.message("max_tokens", "[]")));               // cut off
    }

    @Test
    void screenKeyOutsideTheAllowListFallsBack() {
        assertFallback(parseWith(cards -> cards.get(0).put("screen", "ADMIN_SETTINGS")));
        assertFallback(parseWith(cards -> cards.get(0).put("screen", "/vulnerabilities/findings")));
        // A known key on a check it does not serve (RUNTIME is only for check 5).
        assertFallback(parseWith(cards -> cards.get(0).put("screen", "RUNTIME")));
    }

    @Test
    void missingOrReorderedChecksFallBack() {
        assertFallback(parseWith(cards -> cards.remove(7)));                                     // check 8 dropped
        assertFallback(parseWith(cards -> cards.set(8, card("VULN_FINDINGS", "수정 버전을 봅니다.", 9))));  // 10 dropped
        assertFallback(parseWith(cards -> {                                                      // 2 before 1
            var first = cards.remove(0);
            cards.add(1, first);
        }));
        assertFallback(parseWith(cards -> cards.add(card("VULN_FINDINGS", "한 번 더", 10))));     // 10 repeated
    }

    @Test
    void linksHtmlKeysAndLongTextFallBack() {
        assertFallback(parseWith(cards -> cards.get(0).put("focus", "https://example.invalid 에서 확인하세요.")));
        assertFallback(parseWith(cards -> cards.get(0).put("focus", "www.example.invalid 를 엽니다.")));
        assertFallback(parseWith(cards -> cards.get(0).put("focus", "<a href=x>여기</a>를 누릅니다.")));
        assertFallback(parseWith(cards -> cards.get(0).put("focus", "키 " + HelpTestKeys.githubLike())));
        assertFallback(parseWith(cards -> cards.get(0).put("focus", "가".repeat(HelpChecklist.MAX_FOCUS_CHARS + 1))));
        assertFallback(parse(modelReply(Map.of("cards", validCards(), "closing", "https://example.invalid"))));
    }

    @Test
    void fallbackUsesOnlyPlaybookLines() {
        var result = HelpChecklist.fallback(playbook(), "TEST", HelpAnswerFilter.Usage.EMPTY);
        String playbookText = playbook().text();
        for (String line : result.text().split("\n")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.equals(HelpChecklist.FALLBACK_INTRO) || trimmed.equals(HelpChecklist.CLOSING)) continue;
            assertThat(playbookText).as(trimmed).contains(trimmed);
        }
    }

    @Test
    void cardModeOnlyForTheButtonOrACveNumber() {
        assertThat(HelpChecklist.wanted("checklist", "Log4Shell 터졌어 뭐부터 봐?")).isTrue();
        assertThat(HelpChecklist.wanted(null, "CVE-2021-44228 터졌어")).isTrue();
        assertThat(HelpChecklist.wanted(null, "cve-2024-4577 대응은?")).isTrue();
        assertThat(HelpChecklist.wanted(null, "Log4Shell 터졌어 뭐부터 봐?")).isFalse();
        assertThat(HelpChecklist.wanted(null, "우리 서버 뚫렸어?")).isFalse();
        assertThat(HelpChecklist.wanted("text", "CVE 검색은 어떻게 해요?")).isFalse();
    }

    @Test
    void screenKeysMatchTheSchemaAndTheFrontendTable() {
        // Same list as HELP_SCREEN_ROUTES in the frontend (tests/helpChat.test.mjs checks the other side).
        var expected = List.of("COMPLIANCE", "IAC", "OUTSIDE", "RUNTIME", "SECRET_CASES", "SECRET_FINDINGS",
                "VULN_FINDINGS", "VULN_SCANS", "VULN_SUMMARY", "VULN_WORKLOADS");
        assertThat(HelpChecklist.SCREENS.keySet()).containsExactlyInAnyOrderElementsOf(expected);
        String schema = JSON.writeValueAsString(HelpChecklist.schema());
        expected.forEach(key -> assertThat(schema).contains("\"" + key + "\""));
        assertThat(schema).contains("\"additionalProperties\":false");
    }
}
