package com.logssey.code;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.MissingNode;

/**
 * SARIF 2.1.0(Semgrep·SpotBugs 출력)에서 화면에 필요한 값만 꺼낸다. 코드 조각(snippet)은 저장하지 않는다.
 * - 심각도: result.level, 없으면 규칙의 defaultConfiguration.level. error → HIGH, warning → MEDIUM, 그 밖 → LOW
 * - CWE: 규칙 태그("CWE-89: ...", Semgrep) 또는 CWE 도구와의 관계(SpotBugs)
 * - 경로: uriBaseId 가 가리키는 절대 경로(SpotBugs 의 소스 폴더)를 붙인 뒤 워크스페이스 앞부분을 떼어 레포 기준으로 만든다
 */
final class SarifReader {

    static final int MAX_FINDINGS = 1000;
    private static final Pattern CWE = Pattern.compile("^CWE-(\\d+)");

    record Finding(String ruleId, String severity, String cwe, String message, String path, Integer line,
                   String helpUri) {
    }

    /** findings 는 앞에서부터 MAX_FINDINGS 건까지, total 은 전체 건수 */
    record Result(List<Finding> findings, int total) {
    }

    private SarifReader() {
    }

    static Result read(JsonNode root, String workspace) {
        JsonNode runs = root.path("runs");
        if (!runs.isArray()) throw new IllegalArgumentException("Not a SARIF log");
        List<Finding> findings = new ArrayList<>();
        int total = 0;
        for (JsonNode run : runs) {
            Map<String, JsonNode> rules = new HashMap<>();
            for (JsonNode rule : run.path("tool").path("driver").path("rules")) {
                rules.put(rule.path("id").asText(), rule);
            }
            JsonNode bases = run.path("originalUriBaseIds");
            for (JsonNode result : run.path("results")) {
                total++;
                if (findings.size() < MAX_FINDINGS) findings.add(finding(result, rules, bases, workspace));
            }
        }
        return new Result(findings, total);
    }

    private static Finding finding(JsonNode result, Map<String, JsonNode> rules, JsonNode bases, String workspace) {
        String ruleId = result.path("ruleId").asText("");
        JsonNode rule = rules.getOrDefault(ruleId, MissingNode.getInstance());
        String level = result.path("level").asText(rule.path("defaultConfiguration").path("level").asText("warning"));
        String message = result.path("message").path("text").asText("");
        if (message.isBlank()) message = rule.path("shortDescription").path("text").asText("");
        JsonNode location = result.path("locations").path(0).path("physicalLocation");
        int line = location.path("region").path("startLine").asInt(0);
        String helpUri = rule.path("helpUri").asText("");
        return new Finding(cut(ruleId.isEmpty() ? "unknown" : ruleId, 300), severity(level), cwe(rule),
                cut(message.strip(), 1000), cut(path(location.path("artifactLocation"), bases, workspace), 500),
                line > 0 ? line : null, helpUri.startsWith("https://") ? cut(helpUri, 500) : null);
    }

    private static String severity(String level) {
        return switch (level) {
            case "error" -> "HIGH";
            case "warning" -> "MEDIUM";
            default -> "LOW";
        };
    }

    private static String cwe(JsonNode rule) {
        for (JsonNode tag : rule.path("properties").path("tags")) {
            Matcher matcher = CWE.matcher(tag.asText(""));
            if (matcher.find()) return "CWE-" + matcher.group(1);
        }
        for (JsonNode relation : rule.path("relationships")) {
            JsonNode target = relation.path("target");
            String id = target.path("id").asText("");
            if ("CWE".equals(target.path("toolComponent").path("name").asText()) && id.matches("\\d{1,6}")) {
                return "CWE-" + id;
            }
        }
        return null;
    }

    private static String path(JsonNode artifact, JsonNode bases, String workspace) {
        String uri = artifact.path("uri").asText("");
        String base = bases.path(artifact.path("uriBaseId").asText("")).path("uri").asText("");
        String path = base.startsWith("file:") ? base + uri : uri;
        path = path.replaceFirst("^file://", "").replaceFirst("^file:", "");
        if (workspace != null && !workspace.isBlank()) {
            String prefix = workspace.endsWith("/") ? workspace : workspace + "/";
            if (path.startsWith(prefix)) path = path.substring(prefix.length());
        }
        path = path.replaceFirst("^\\./", "");
        return path.isEmpty() ? "(unknown)" : path;
    }

    private static String cut(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max - 1) + "…";
    }
}
