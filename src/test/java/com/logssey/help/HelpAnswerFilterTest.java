package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

class HelpAnswerFilterTest {

    private static final List<HelpDocument> DOCS = List.of(
            new HelpDocument("a.md", "로그인 가이드", "# 로그인 가이드\n\n## 로그인하기\n아이디로 로그인한다.\n"),
            new HelpDocument("b.md", "시크릿 가이드", "# 시크릿 가이드\n\n## 개요\n소개\n\n## 대응 건 만들기\n버튼을 누른다.\n"));

    static String message(String stopReason, String contentJson) {
        return """
                {"id":"msg_test","type":"message","role":"assistant","model":"claude-sonnet-5-5",
                 "stop_reason":"%s","content":%s,
                 "usage":{"input_tokens":120,"cache_read_input_tokens":3000,"cache_creation_input_tokens":0,"output_tokens":80}}
                """.formatted(stopReason, contentJson);
    }

    static String citedText(String text, int documentIndex, int start) {
        return """
                {"type":"text","text":"%s","citations":[{"type":"char_location","cited_text":"x",
                 "document_index":%d,"document_title":"t","start_char_index":%d,"end_char_index":%d}]}
                """.formatted(text, documentIndex, start, start + 5);
    }

    private static HelpAnswerFilter.Result parse(String json) {
        return HelpAnswerFilter.parse(json.getBytes(StandardCharsets.UTF_8), DOCS);
    }

    @Test
    void keepsCitedAnswerAndResolvesSection() {
        int start = DOCS.get(1).text().indexOf("버튼");
        var result = parse(message("end_turn", "[" + citedText("대응 관리에서 버튼을 누르세요.", 1, start) + "]"));

        assertThat(result.ok()).isTrue();
        assertThat(result.answer()).isEqualTo("대응 관리에서 버튼을 누르세요.");
        assertThat(result.sources()).containsExactly(new HelpAnswerFilter.Source("b.md", "시크릿 가이드", "대응 건 만들기"));
        assertThat(result.usage().cacheRead()).isEqualTo(3000);
    }

    @Test
    void answerWithoutCitationIsNotGrounded() {
        var result = parse(message("end_turn", "[{\"type\":\"text\",\"text\":\"문서에 없는 내용이에요.\"}]"));
        assertThat(result.reasonCode()).isEqualTo("NO_GROUNDED_ANSWER");
        assertThat(result.answer()).isNull();
    }

    @Test
    void rejectsRefusalTruncationUrlsAndKeys() {
        assertThat(parse(message("refusal", "[]")).reasonCode()).isEqualTo("PROVIDER_REFUSED");
        assertThat(parse(message("max_tokens", "[" + citedText("잘린 답", 0, 0) + "]")).reasonCode())
                .isEqualTo("PROVIDER_INVALID_RESPONSE");
        assertThat(parse(message("end_turn", "[" + citedText("https://example.invalid 로 가세요", 0, 0) + "]")).reasonCode())
                .isEqualTo("ANSWER_BLOCKED");
        assertThat(parse(message("end_turn", "[" + citedText("키는 " + HelpTestKeys.githubLike(), 0, 0) + "]")).reasonCode())
                .isEqualTo("ANSWER_BLOCKED");
        assertThat(parse(message("end_turn", "[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"x\",\"input\":{}}]")).reasonCode())
                .isEqualTo("PROVIDER_INVALID_RESPONSE");
        assertThat(parse("not json").reasonCode()).isEqualTo("PROVIDER_INVALID_RESPONSE");
    }

    @Test
    void ignoresCitationsToUnknownDocuments() {
        var result = parse(message("end_turn", "[" + citedText("답", 9, 0) + "]"));
        assertThat(result.reasonCode()).isEqualTo("NO_GROUNDED_ANSWER");
    }
}
