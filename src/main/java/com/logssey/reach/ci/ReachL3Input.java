package com.logssey.reach.ci;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import com.logssey.reach.ReachCodes;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * 결과 묶음의 l3 (PRD FR-14): 러너가 앱을 띄워 본 L3 능동 관측. 검사해 저장할 모양으로 바꾼다.
 * 모양은 러너 verdict/l3.py 출력({tool, scope, segments, counts, cves[]})에 run(l3-run.sh의 근거 항목)을 더한 것,
 * 또는 실행이 실패했을 때 {"error": "…"}다.
 * L3는 판정 옆의 근거라서 잘못된 l3가 스캔을 실패시키지 않는다. 그때는 FAILED 실행 하나로 남기고 결과는 넣지 않는다.
 * 아는 칸만 골라 담는다(러너가 칸을 더해도 DB에 그대로 쌓이지 않게).
 */
final class ReachL3Input {

    /** reach_l3_runs 한 행. counts·detail은 JSON 문자열 */
    record Run(String status, String error, String scenario, String observationMethod, OffsetDateTime observedAt,
               String counts, String detail) {}

    /** reach_l3_results 한 행. detail은 JSON 문자열 */
    record Result(String reached, boolean regionsChecked, boolean startupOnly, String detail) {}

    static final String INVALID = "invalid L3 result in the bundle";
    private static final List<String> METHODS = List.of("COVERAGE", "MAPS", "UPROBE");
    /** run에서 detail로 옮기는 칸 (FR-14 수용 기준 3의 근거 항목과 실행 정보) */
    private static final List<String> RUN_DETAIL = List.of("build", "configKeys", "invocations", "requests", "scope",
            "javaRelease", "jacoco", "appStartSeconds", "durationSeconds");
    /** CVE 결과에서 detail로 옮기는 칸 */
    private static final List<String> RESULT_DETAIL = List.of("during", "functions", "regions", "paths", "note",
            "installedVersions", "regionVersion", "functionsUnchecked");
    /** Finding 하나의 근거 크기 한도. L2 경로가 많은 CVE도 수십 KB다 */
    private static final int RESULT_MAX = 256 * 1024;
    private static final int RUN_MAX = 512 * 1024;

    private final Run run;
    private final Map<String, Result> results;

    private ReachL3Input(Run run, Map<String, Result> results) {
        this.run = run;
        this.results = results;
    }

    /** l3가 없으면 null (앱을 띄우지 않은 스캔: PR, 재대조, 시나리오 없는 레포) */
    static ReachL3Input parse(JsonNode l3, JsonMapper mapper) {
        if (l3 == null || l3.isNull() || l3.isMissingNode()) return null;
        try {
            return read(l3, mapper);
        } catch (IllegalArgumentException e) {
            return failed(INVALID);
        }
    }

    Run run() {
        return run;
    }

    /** 이 Finding의 L3 결과. CVE와 패키지 좌표(group:artifact)로 잇는다. 같은 좌표의 여러 버전은 같은 결과를 받는다 */
    Optional<Result> result(String vulnerabilityId, String purl) {
        return Optional.ofNullable(results.get(key(vulnerabilityId, coordinates(purl))));
    }

    private static ReachL3Input failed(String error) {
        return new ReachL3Input(new Run("FAILED", cut(error, 500), null, null, null, "{}", "{}"), Map.of());
    }

    private static ReachL3Input read(JsonNode l3, JsonMapper mapper) {
        if (!l3.isObject()) throw new IllegalArgumentException();
        if (l3.has("error")) {
            String error = text(l3.get("error"));
            return failed(error == null || error.isBlank() ? "L3 run failed" : error);
        }
        var runNode = l3.get("run");
        if (runNode == null || !runNode.isObject()) throw new IllegalArgumentException();
        String scenario = text(runNode.get("scenario"));
        if (scenario == null || scenario.isBlank() || scenario.length() > 64) throw new IllegalArgumentException();
        String method = runNode.has("observationMethod") ? text(runNode.get("observationMethod")) : "COVERAGE";
        method = method == null ? null : method.toUpperCase(Locale.ROOT);
        if (!METHODS.contains(method)) throw new IllegalArgumentException();
        OffsetDateTime observedAt;
        try {
            observedAt = OffsetDateTime.parse(String.valueOf(text(runNode.get("observedAt"))));
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException();
        }

        ObjectNode detail = pick(runNode, RUN_DETAIL, mapper);
        for (String name : List.of("tool", "segments")) {
            if (l3.has(name)) detail.set(name, l3.get(name));
        }
        var counts = l3.get("counts");
        if (counts != null && !counts.isObject()) throw new IllegalArgumentException();
        String detailJson = mapper.writeValueAsString(detail);
        if (detailJson.length() > RUN_MAX) throw new IllegalArgumentException();

        var results = new HashMap<String, Result>();
        var cves = l3.get("cves");
        if (cves == null || !cves.isArray()) throw new IllegalArgumentException();
        for (JsonNode cve : cves) {
            if (!cve.isObject()) throw new IllegalArgumentException();
            String id = text(cve.get("cve"));
            String coordinates = text(cve.get("coordinates"));
            String reached = text(cve.get("reached"));
            if (id == null || id.isBlank() || coordinates == null || coordinates.isBlank() || reached == null) {
                throw new IllegalArgumentException();
            }
            reached = reached.toUpperCase(Locale.ROOT);
            if (!ReachCodes.L3_LEVELS.contains(reached)) throw new IllegalArgumentException();
            ObjectNode resultDetail = pick(cve, RESULT_DETAIL, mapper);
            String json = mapper.writeValueAsString(resultDetail);
            if (json.length() > RESULT_MAX) {
                // 경로가 아주 많은 CVE: 도달 수준과 함수·구간 근거는 남기고 경로만 뺀다
                resultDetail.remove("paths");
                resultDetail.put("pathsOmitted", true);
                json = mapper.writeValueAsString(resultDetail);
                if (json.length() > RESULT_MAX) throw new IllegalArgumentException();
            }
            var result = new Result(reached, bool(cve.get("regionsChecked")), bool(cve.get("startupOnly")), json);
            if (results.put(key(id, coordinates), result) != null) throw new IllegalArgumentException();
        }
        var run = new Run("SUCCEEDED", null, scenario, method, observedAt,
                counts == null ? "{}" : mapper.writeValueAsString(counts), detailJson);
        return new ReachL3Input(run, results);
    }

    /** 아는 칸만. 배열·객체·값은 그대로 둔다(안쪽 이름은 러너 출력과 같다) */
    private static ObjectNode pick(JsonNode node, List<String> names, JsonMapper mapper) {
        ObjectNode out = mapper.createObjectNode();
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && !value.isNull()) out.set(name, value instanceof ArrayNode a ? a.deepCopy() : value);
        }
        return out;
    }

    /** pkg:maven/org.example/lib@1.0 → org.example:lib (러너 bundle.py coordinates와 같다) */
    static String coordinates(String purl) {
        if (purl == null || !purl.startsWith("pkg:")) return "";
        String body = purl.substring(4);
        for (char end : new char[] {'#', '?'}) {
            int at = body.indexOf(end);
            if (at >= 0) body = body.substring(0, at);
        }
        int version = body.indexOf('@');
        if (version >= 0) body = body.substring(0, version);
        String[] parts = body.split("/");
        if (parts.length < 2) return "";
        var namespace = new StringBuilder();
        for (int i = 1; i < parts.length - 1; i++) {
            if (namespace.length() > 0) namespace.append('/');
            namespace.append(decode(parts[i]));
        }
        String name = decode(parts[parts.length - 1]);
        return namespace.length() == 0 ? name : namespace + ":" + name;
    }

    private static String decode(String value) {
        // purl은 %로만 인코딩한다. URLDecoder가 +를 공백으로 바꾸지 않게 먼저 지킨다
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static String key(String vulnerabilityId, String coordinates) {
        return vulnerabilityId + "\n" + coordinates;
    }

    private static String text(JsonNode node) {
        return node == null || !node.isString() ? null : node.asString();
    }

    private static boolean bool(JsonNode node) {
        return node != null && node.isBoolean() && node.asBoolean();
    }

    private static String cut(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max - 1) + "…";
    }
}
