package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Design doc 19: the ISMS-P evidence guide matches the compliance catalogue and never claims an item is met. */
class HelpIsmsEvidenceTest {

    private static final String GUIDE = "10-isms-p-evidence.md";
    /** "2.11.2 취약점 점검 및 조치": an item number followed by its name, up to a comma, bracket, colon or line end. */
    private static final Pattern ITEM = Pattern.compile("(?<![\\d.])([123]\\.\\d{1,2}\\.\\d{1,2}) ([^,(:\\n\"]+)");
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]+)\"");

    private static List<HelpDocument> docs() {
        return new HelpDocumentLibrary().documents();
    }

    private static String guide() {
        return docs().stream().filter(doc -> doc.file().equals(GUIDE)).findFirst().orElseThrow().text();
    }

    /** ISMS-P 2023 controls from the compliance catalogue: id -> [title, evaluationMode]. */
    private static Map<String, String[]> catalogue() throws IOException {
        try (InputStream in = HelpIsmsEvidenceTest.class.getClassLoader().getResourceAsStream("compliance/catalog.json")) {
            JsonNode root = JsonMapper.builder().build().readTree(in);
            var controls = new LinkedHashMap<String, String[]>();
            for (JsonNode framework : root.path("frameworks")) {
                if (!framework.path("id").asText().equals("isms")) continue;
                for (JsonNode control : framework.path("controls")) {
                    controls.put(control.path("id").asText().strip(),
                            new String[] {control.path("title").asText().strip(), control.path("evaluationMode").asText()});
                }
            }
            return controls;
        }
    }

    @Test
    void guideIsApprovedAndSafeToSend() {
        assertThat(HelpDocumentLibrary.manifestEntries(getClass().getClassLoader())).contains(GUIDE);
        String text = guide();
        // safe() also caps an answer at 4,000 characters, so check the guide line by line.
        assertThat(text.lines().toList()).allSatisfy(line -> assertThat(HelpAnswerFilter.safe(line)).as(line).isTrue());
        assertThat(text).doesNotContain("http://", "https://");
    }

    @Test
    void everyItemNumberAndNameMatchesTheCatalogue() throws IOException {
        var catalogue = catalogue();
        assertThat(catalogue).hasSize(101);
        String text = guide();

        var mentioned = ITEM.matcher(text).results().collect(Collectors.toList());
        assertThat(mentioned).isNotEmpty();
        for (var item : mentioned) {
            String id = item.group(1);
            assertThat(catalogue).as("unknown ISMS-P item %s", id).containsKey(id);
            assertThat(item.group(2).strip()).as("name of %s", id).isEqualTo(catalogue.get(id)[0]);
        }
        // Every one of the 101 items is placed somewhere: with Logssey evidence, report only, or outside Logssey.
        var ids = mentioned.stream().map(m -> m.group(1)).collect(Collectors.toSet());
        assertThat(ids).containsAll(catalogue.keySet());
    }

    @Test
    void automatedSectionListsExactlyTheReportsAutomatedItems() throws IOException {
        var catalogue = catalogue();
        String text = guide();
        int start = text.indexOf("## 컴플라이언스 ISMS-P 보고서가 자동으로 점검하는 항목");
        assertThat(start).isPositive();
        String section = text.substring(start, text.indexOf("\n## ", start + 1));
        var listed = ITEM.matcher(section).results().map(m -> m.group(1)).collect(Collectors.toSet());
        var automated = catalogue.entrySet().stream().filter(e -> e.getValue()[1].equals("AUTOMATED"))
                .map(Map.Entry::getKey).collect(Collectors.toSet());
        assertThat(automated).hasSize(27);
        assertThat(listed).isEqualTo(automated);

        // Nothing automated is filed under "outside Logssey".
        int outside = text.indexOf("## Logssey 밖에서 증명하는 항목");
        String outsideSection = text.substring(outside, text.indexOf("\n## ", outside + 1));
        var outsideIds = ITEM.matcher(outsideSection).results().map(m -> m.group(1)).toList();
        assertThat(outsideIds).isNotEmpty().noneMatch(automated::contains);
    }

    @Test
    void guideNeverClaimsAnItemIsMetAndPointsToAuditors() {
        String text = guide();
        assertThat(text).doesNotContain("충족합니다", "충족한다", "충족됩니다", "인증받을 수 있", "인증을 받을 수 있",
                "준수합니다", "통과할 수 있습니다");
        assertThat(text).contains("심사원", "Logssey 밖", "볼 수 없습니다");
    }

    @Test
    void screenNamesInTheGuideExistInTheOtherGuides() {
        String others = docs().stream().filter(doc -> !doc.file().equals(GUIDE)).map(HelpDocument::text)
                .collect(Collectors.joining("\n"));
        String text = guide();
        var names = text.lines().filter(line -> line.startsWith("- Logssey에서 볼 곳:"))
                .flatMap(line -> QUOTED.matcher(line).results().map(m -> m.group(1))).distinct().toList();
        assertThat(names).isNotEmpty();
        assertThat(names).allSatisfy(name -> assertThat(others).as("screen name %s", name).contains("\"" + name + "\""));
    }

    @Test
    void systemPromptKeepsIsmsAnswersToEvidenceOnly() {
        var provider = new ClaudeHelpProvider(true, "unused", "", "https://api.anthropic.com/v1/messages", 30_000,
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), false);
        String body = provider.requestBody(docs(), "컴플라이언스", List.of(), "ISMS-P 2.11.2는 어디서 증적을 봐요?");
        assertThat(body).contains("ISMS-P or certification questions", "Never say that an item is met", "auditors decide",
                "ISMS-P 항목별로 Logssey에서 증적을 보는 곳");
    }
}
