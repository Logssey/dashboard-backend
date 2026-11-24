package com.logssey.reach.ci;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

class ReachL3InputTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static final String WEBSOCKET = "org.apache.tomcat.embed:tomcat-embed-websocket";
    private static final String CORE = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.24";

    @Test
    void aResultIsMatchedByCveAndCoordinates() {
        var input = parse(cve("CVE-2026-73180", WEBSOCKET, "REGION"));
        String websocket = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@11.0.24";
        assertThat(input.result("CVE-2026-73180", websocket, true)).map(ReachL3Input.Result::reached).contains("REGION");
        assertThat(input.result("CVE-2026-1", websocket, true)).isEmpty();
    }

    @Test
    void anotherJarOfTheSameGroupGetsTheResultOnlyWhenTheBundleJudgedIt() {
        // Grype puts this Tomcat WebSocket CVE on tomcat-embed-core; bundle.py gives that match the websocket verdict
        var input = parse(cve("CVE-2026-73180", WEBSOCKET, "NONE"));
        assertThat(input.result("CVE-2026-73180", CORE, true)).map(ReachL3Input.Result::reached).contains("NONE");
        // bundle.py left it an unanalysed copy (another version than the analysed jar, …): no L3 either
        assertThat(input.result("CVE-2026-73180", CORE, false)).isEmpty();
        // another groupId is other code (Jackson 2 for data on Jackson 3)
        var jackson = parse(cve("CVE-2026-1", "tools.jackson.core:jackson-core", "REGION"));
        assertThat(jackson.result("CVE-2026-1", "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.21.5", true)).isEmpty();
        // only maven: npm coordinates have no groupId to compare
        assertThat(jackson.result("CVE-2026-1", "pkg:npm/%40tools/jackson-core@1.0.0", true)).isEmpty();
    }

    @Test
    void twoResultsOfTheSameGroupAreNotGuessedBetween() {
        var input = parse(cve("CVE-2026-1", "org.example:a", "REGION"), cve("CVE-2026-1", "org.example:b", "NONE"));
        assertThat(input.result("CVE-2026-1", "pkg:maven/org.example/a@1", true)).map(ReachL3Input.Result::reached).contains("REGION");
        assertThat(input.result("CVE-2026-1", "pkg:maven/org.example/c@1", true)).isEmpty();
    }

    @Test
    void aCveIdThatStartsAnotherDoesNotMatchIt() {
        var input = parse(cve("CVE-2026-11", "org.example:a", "REGION"));
        assertThat(input.result("CVE-2026-1", "pkg:maven/org.example/b@1", true)).isEmpty();
    }

    @Test
    void theGroupIsEverythingBeforeTheLastColon() {
        assertThat(ReachL3Input.group("org.apache.tomcat.embed:tomcat-embed-core")).isEqualTo("org.apache.tomcat.embed");
        assertThat(ReachL3Input.group("left-pad")).isEmpty();
        assertThat(ReachL3Input.group("")).isEmpty();
    }

    private static ReachL3Input parse(Map<?, ?>... cves) {
        var l3 = Map.of("tool", "l3.py", "counts", Map.of(),
                "run", Map.of("scenario", "reused-api", "observedAt", "2026-11-24T00:00:00Z"),
                "cves", List.of(cves));
        var input = ReachL3Input.parse(MAPPER.valueToTree(l3), null, MAPPER);
        assertThat(input.run().status()).isEqualTo("SUCCEEDED");
        return input;
    }

    private static Map<String, Object> cve(String id, String coordinates, String reached) {
        return Map.of("cve", id, "coordinates", coordinates, "reached", reached);
    }
}
