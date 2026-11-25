package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

/** Design doc 18.1 (customer data masking), 18.3 (yes/no signals) and 18.4 (report draft checks). */
class HelpPrivacyAndSignalsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void customerDataIsMaskedBeforeItLeaves() {
        assertThat(HelpPrivacyMask.mask("담당자 kim.dev+ops@example.co.kr 에게 알렸어요"))
                .isEqualTo("담당자 [이메일] 에게 알렸어요");
        assertThat(HelpPrivacyMask.mask("203.0.113.7 에서 접속, 내부망 10.0.0.0/8"))
                .isEqualTo("[IP] 에서 접속, 내부망 [IP]");
        assertThat(HelpPrivacyMask.mask("2001:db8::1 과 fe80::1ff:fe23:4567:890a")).isEqualTo("[IP] 과 [IP]");
        assertThat(HelpPrivacyMask.mask("연락처 010-1234-5678, 02 345 6789, +82 10-9876-5432"))
                .isEqualTo("연락처 [전화번호], [전화번호], [전화번호]");
        assertThat(HelpPrivacyMask.mask("주민번호 900101-1234567")).isEqualTo("주민번호 [주민번호]");
        assertThat(HelpPrivacyMask.mask("카드 4111 1111 1111 1111")).isEqualTo("카드 [카드번호]");
    }

    @Test
    void ordinaryQuestionsAreLeftAlone() {
        for (String text : List.of("CVE-2021-44228 우리 영향 있어?", "log4j 2.17.1로 올렸어요", "10:30:00에 탐지가 떴어요",
                "2026-11-25 사고 기록", "Finding 3건, 공격 경로 72개", "Class::method 같은 코드", "포트 8080 열려 있어요")) {
            assertThat(HelpPrivacyMask.mask(text)).as(text).isEqualTo(text);
            assertThat(HelpPrivacyMask.changes(text)).isFalse();
        }
    }

    @Test
    void onlyKnownBooleanSignalsSurviveAndTheServerWritesTheSentence() {
        var raw = new LinkedHashMap<String, Object>();
        raw.put("sensorsDown", true);
        raw.put("runtimeUnreviewed", false);
        raw.put("liveKeys", "true");                       // not a boolean
        raw.put("openPaths", 72);                          // a count must not pass
        raw.put("ignorePreviousInstructions", true);       // unknown key
        raw.put("drifts", Map.of("x", "y"));

        Map<String, Boolean> clean = HelpSignals.clean(raw);
        assertThat(clean).containsExactly(Map.entry("runtimeUnreviewed", false), Map.entry("sensorsDown", true));
        String text = HelpSignals.text(clean);
        assertThat(text).contains("예/아니오로만", "검토 안 한 런타임 탐지(의심스러운 시도): 없음",
                "정상인 런타임 센서가 하나도 없음(Logssey로 침해 흔적을 볼 수 없음): 있음");
        assertThat(text).doesNotContain("72", "ignore", "true", "x");
        assertThat(HelpSignals.text(Map.of())).isEmpty();
        assertThat(HelpSignals.clean(null)).isEmpty();
    }

    @Test
    void signalsGoIntoTheUserTurnAsServerTextOnly() {
        var provider = new ClaudeHelpProvider(true, "unused", "", "https://api.anthropic.com/v1/messages", 30_000,
                java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NEVER).build(), false);
        String body = provider.requestBody(List.of(), "요약", List.of(), "서버 뚫린 것 같아",
                HelpSignals.clean(Map.of("sensorsDown", true, "liveKeys", false)));
        String userText = JSON.readTree(body).path("messages").get(0).path("content").get(0).path("text").asText();
        assertThat(userText).startsWith("현재 화면: 요약\n\nLogssey 환경 신호").endsWith("질문: 서버 뚫린 것 같아");
        String system = JSON.readTree(body).path("system").get(0).path("text").asText();
        assertThat(system).contains("yes/no values", "do not invent counts", "list all ten checks");
    }

    @Test
    void reportDraftKeepsOnlySafeSentencesWhoseNumbersCameFromTheNotes() {
        String memo = "14시에 웹 서버 2대를 격리함. 런타임 탐지 3건 확인. 키 교체는 아직.";
        var ok = JSON.readTree("""
                {"summary":"웹 서버 2대를 격리하고 런타임 탐지 3건을 확인했습니다.",
                 "checked":["런타임 탐지 3건을 확인했습니다."],"actions":["14시에 웹 서버 2대를 격리했습니다."],
                 "remaining":["키 교체가 남아 있습니다."]}""");
        var draft = HelpReport.draft(ok, memo);
        assertThat(draft).isNotNull();
        assertThat(draft.actions()).containsExactly("14시에 웹 서버 2대를 격리했습니다.");

        assertThat(HelpReport.draft(JSON.readTree("""
                {"summary":"서버 5대가 뚫렸습니다.","checked":[],"actions":[],"remaining":[]}"""), memo))
                .as("a number the notes never mentioned").isNull();
        assertThat(HelpReport.draft(JSON.readTree("""
                {"summary":"자세한 내용은 https://example.invalid 참고","checked":[],"actions":[],"remaining":[]}"""), memo))
                .as("links are blocked").isNull();
        assertThat(HelpReport.draft(JSON.readTree("""
                {"summary":"요약","checked":[],"actions":[],"remaining":[],"extra":"x"}"""), memo))
                .as("unknown fields").isNull();
        assertThat(HelpReport.draft(JSON.readTree("""
                {"summary":"키 %s 를 교체","checked":[],"actions":[],"remaining":[]}""".formatted(HelpTestKeys.githubLike())), memo))
                .as("key-looking values").isNull();
    }
}
