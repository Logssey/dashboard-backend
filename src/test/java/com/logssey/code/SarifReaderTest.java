package com.logssey.code;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 실제 도구 출력(service-backend 를 검사한 SARIF 를 줄인 것)으로 읽기를 확인한다 */
class SarifReaderTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static final String WORKSPACE = "/home/runner/work/service-backend/service-backend";

    @Test
    void spotbugsPathsBecomeRepositoryRelativeAndCweComesFromTheRelationship() throws IOException {
        var result = SarifReader.read(fixture("spotbugs.sarif"), WORKSPACE);

        assertThat(result.total()).isEqualTo(2);
        var first = result.findings().getFirst();
        assertThat(first.ruleId()).isEqualTo("SQL_INJECTION_SPRING_JDBC");
        assertThat(first.severity()).isEqualTo("MEDIUM");
        assertThat(first.cwe()).isEqualTo("CWE-89");
        assertThat(first.path()).isEqualTo("src/main/java/com/reused/chat/ChatRepository.java");
        assertThat(first.line()).isEqualTo(20);
        assertThat(first.helpUri()).startsWith("https://find-sec-bugs.github.io/");
    }

    @Test
    void semgrepLevelFallsBackToTheRuleAndCweComesFromTheTag() throws IOException {
        var result = SarifReader.read(fixture("semgrep.sarif"), WORKSPACE);

        assertThat(result.findings()).extracting(SarifReader.Finding::severity).containsExactly("MEDIUM", "HIGH");
        var injection = result.findings().get(1);
        assertThat(injection.path()).isEqualTo(".github/workflows/ci.yml");
        assertThat(injection.line()).isEqualTo(240);
        assertThat(injection.cwe()).isEqualTo("CWE-78");
    }

    @Test
    void storesAtMostTheLimitButCountsEverything() {
        StringBuilder results = new StringBuilder();
        for (int i = 0; i < SarifReader.MAX_FINDINGS + 5; i++) {
            results.append(i == 0 ? "" : ",").append("{\"ruleId\":\"r\",\"level\":\"note\",\"message\":{\"text\":\"m\"}}");
        }
        var result = SarifReader.read(MAPPER.readTree("{\"runs\":[{\"results\":[" + results + "]}]}"), null);

        assertThat(result.total()).isEqualTo(SarifReader.MAX_FINDINGS + 5);
        assertThat(result.findings()).hasSize(SarifReader.MAX_FINDINGS);
        assertThat(result.findings().getFirst().severity()).isEqualTo("LOW");
        assertThat(result.findings().getFirst().path()).isEqualTo("(unknown)");
    }

    @Test
    void onlyHttpsHelpLinksAreKept() {
        var result = SarifReader.read(MAPPER.readTree("""
                {"runs":[{"tool":{"driver":{"rules":[{"id":"r","helpUri":"javascript:alert(1)"}]}},
                  "results":[{"ruleId":"r","message":{"text":"m"}}]}]}
                """), null);

        assertThat(result.findings().getFirst().helpUri()).isNull();
    }

    @Test
    void rejectsSomethingThatIsNotSarif() {
        assertThatThrownBy(() -> SarifReader.read(MAPPER.readTree("{\"version\":\"2.1.0\"}"), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static JsonNode fixture(String name) throws IOException {
        try (InputStream in = SarifReaderTest.class.getResourceAsStream("/code/" + name)) {
            return MAPPER.readTree(in);
        }
    }
}
