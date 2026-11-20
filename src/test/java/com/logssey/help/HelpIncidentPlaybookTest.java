package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Design section 11: incident guidance comes only from the playbook guide and keeps every check. */
class HelpIncidentPlaybookTest {

    private static final String PLAYBOOK = "09-incident-playbook.md";
    private static final Pattern NUMBERED_SECTION = Pattern.compile("(?m)^## (\\d+)\\. ");

    private static HelpDocument playbook() {
        return new HelpDocumentLibrary().documents().stream()
                .filter(doc -> doc.file().equals(PLAYBOOK)).findFirst().orElseThrow();
    }

    @Test
    void playbookListsTenChecksInOrderAndLeavesReportingToTheTeam() {
        HelpDocument doc = playbook();

        List<Integer> numbers = NUMBERED_SECTION.matcher(doc.text()).results()
                .map(result -> Integer.parseInt(result.group(1))).toList();
        assertThat(numbers).containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        assertThat(doc.text()).contains("빼지 말고", "Logssey 밖", "담당 부서와 확인", "볼 수 없어서");
        assertThat(doc.text()).doesNotContain("24시간", "72시간", "http://", "https://");
        assertThat(HelpAnswerFilter.safe(doc.text().substring(0, 1_000))).isTrue();
    }

    @Test
    void requestCarriesIncidentRulesAndRoomForTheChecklist() {
        var provider = new ClaudeHelpProvider(true, "unused", "", "https://api.anthropic.com/v1/messages", 30_000,
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), false);
        JsonNode body = JsonMapper.builder().build().readTree(
                provider.requestBody(List.of(playbook()), "Finding 목록", List.of(), "Log4Shell 터졌어 뭐부터 봐?"));

        assertThat(body.path("max_tokens").asInt()).isEqualTo(ClaudeHelpProvider.MAX_TOKENS).isEqualTo(3_000);
        String system = body.path("system").get(0).path("text").asText();
        assertThat(system).contains("never drop one", "cannot see", "Never conclude", "responsible team",
                "3 to 5 sentences", "ground every answer in the documents again", "plain text only");
        assertThat(body.has("tools")).isFalse();
    }

    @Test
    void tenLineChecklistSurvivesTheRepeatFilter() {
        var lines = new ArrayList<>(List.of(
                "1번: 취약점 관리 > Finding 목록의 CVE 검색 칸에 44228을 넣어 Log4j 패키지가 나오는지 봅니다.",
                "2번: Finding 목록의 배포 상태 필터에서 실행 중을 골라 실행 중인 곳에 있는지 봅니다. 결과가 없어도 안전하다는 뜻은 아닙니다.",
                "3번: 워크로드의 스캔 없음 · 불일치 카드가 있으면 그 줄의 스캔 요청으로 먼저 스캔합니다.",
                "4번: Finding 상세 근거에서 판정이 도달 가능인지, IaC 보안의 지금 열린 공격 경로로 바깥에서 닿는지 봅니다.",
                "5번: 런타임 보안 탐지 결과에서 사고 이후 이상 탐지를 봅니다. 센서가 없으면 Logssey 밖에서 접근 로그를 봅니다.",
                "6번: 서버 격리와 차단은 Logssey 밖에서 하고, 지금 점검으로 공격 경로가 닫혔는지 다시 봅니다.",
                "7번: 그 서버가 쓰던 키는 시크릿 키·노출 위치에서 찾아 대응 건으로 교체합니다.",
                "8번: 컴플라이언스 새 점검과 IaC 실제 드리프트로 계정·권한·설정이 바뀌지 않았는지 봅니다.",
                "9번: 수정 버전으로 올린 뒤 새 스캔으로 Finding이 사라졌는지 확인합니다.",
                "10번: 검토 저장에 판정과 메모를 남기고, 외부 신고가 필요한지는 담당 부서와 확인합니다."));
        String intro = "이 순서로 확인해 보세요. 취약점 관리, 런타임 보안, IaC 보안, 시크릿, 컴플라이언스 화면을 차례로 봅니다. "
                + "Finding 상세의 근거와 판정 상태, 공격 경로, 탐지 결과, 키 교체, 드리프트, 검토 저장까지 모두 확인합니다.";
        String answer = intro + "\n\n" + String.join("\n\n", lines);

        String kept = HelpAnswerFilter.withoutRepeatedParagraphs(answer);
        for (int i = 1; i <= 10; i++) assertThat(kept).contains(i + "번:");
    }

    @Test
    void checklistLengthLimit() {
        int start = playbook().text().indexOf("## 1.");
        var docs = List.of(playbook());
        String within = "가".repeat(HelpAnswerFilter.MAX_ANSWER_CHARS);
        String over = within + "가";

        assertThat(parse(docs, within, start).ok()).isTrue();
        assertThat(parse(docs, over, start).reasonCode()).isEqualTo("ANSWER_BLOCKED");
    }

    private static HelpAnswerFilter.Result parse(List<HelpDocument> docs, String text, int start) {
        String json = HelpAnswerFilterTest.message("end_turn", "[" + HelpAnswerFilterTest.citedText(text, 0, start) + "]");
        return HelpAnswerFilter.parse(json.getBytes(StandardCharsets.UTF_8), docs);
    }
}
