package com.logssey.secret.export;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * SARIF 2.1.0. GitHub 파일은 physicalLocations, 노션·AWS 같은 파일이 아닌 위치는 logicalLocations로 표현한다.
 * DefectDojo SARIF 파서는 kind가 fail인 결과만 읽고 physicalLocation이 없으면 파일 칸을 비워 두므로,
 * 파일이 아닌 위치는 메시지 문구에도 논리 경로를 함께 적는다.
 */
public final class SarifExportWriter {
    static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    static final String GITHUB_NOTICE = "GitHub 코드 스캐닝은 저장소 하나 단위로 업로드됩니다. "
            + "여러 저장소나 노션 위치가 섞인 파일은 일부 결과만 표시될 수 있어요.";

    private SarifExportWriter() { }

    public static Map<String, Object> write(SecretExportDocument document) {
        var rules = new TreeMap<String, Map<String, Object>>();
        var results = new ArrayList<Map<String, Object>>();
        for (var record : document.records()) {
            rules.computeIfAbsent(record.ruleId(), SarifExportWriter::rule);
            results.add(result(record));
        }
        var driver = map("name", "Logssey", "informationUri", "https://github.com/Logssey",
                "semanticVersion", "1.0.0", "rules", new ArrayList<>(rules.values()));
        var run = map("tool", map("driver", driver), "results", results,
                "columnKind", "utf16CodeUnits",
                "properties", map("logssey", LogsseyJsonExportWriter.meta(document), "notice", GITHUB_NOTICE));
        return map("$schema", SCHEMA, "version", "2.1.0", "runs", List.of(run));
    }

    private static Map<String, Object> rule(String ruleId) {
        return map("id", ruleId, "name", ruleId,
                "shortDescription", map("text", "노출된 인증 정보 (" + ruleId + ")"),
                "defaultConfiguration", map("level", "error"),
                "properties", map("tags", List.of("security", "secret", "external/cwe/cwe-798")));
    }

    private static Map<String, Object> result(SecretExportRecord record) {
        var location = record.location();
        var where = location.logicalName(record.occurrenceId());
        var message = record.maskedLabel() + " (" + record.issuer() + " · " + record.credentialType() + ") 키가 "
                + where + (location.startLine() == null ? "" : ":" + location.startLine()) + "에서 발견됐어요.";
        var sarifLocation = new LinkedHashMap<String, Object>();
        if (location.isFile()) {
            var region = new LinkedHashMap<String, Object>();
            if (location.startLine() != null) {
                region.put("startLine", location.startLine());
                if (location.endLine() != null) region.put("endLine", location.endLine());
            }
            var physical = new LinkedHashMap<String, Object>();
            physical.put("artifactLocation", map("uri", location.path(), "uriBaseId", "SRCROOT"));
            if (!region.isEmpty()) physical.put("region", region);
            sarifLocation.put("physicalLocation", physical);
            sarifLocation.put("logicalLocations", List.of(map("kind", "module", "name", location.repository(),
                    "fullyQualifiedName", location.repository() + "@" + location.branch())));
        } else {
            sarifLocation.put("logicalLocations", logical(record));
        }
        sarifLocation.put("message", map("text", location.label()));
        return map("ruleId", record.ruleId(), "kind", "fail", "level", level(record.severity()),
                "message", map("text", message),
                "locations", List.of(sarifLocation),
                "partialFingerprints", map("logsseyOccurrence/v1", Long.toString(record.occurrenceId())),
                "properties", properties(record));
    }

    private static List<Map<String, Object>> logical(SecretExportRecord record) {
        var location = record.location();
        return switch (location.kind()) {
            case "NOTION_PAGE" -> List.of(
                    map("kind", "resource", "name", location.blockId() == null ? "title" : location.blockId(),
                            "fullyQualifiedName", location.logicalName(record.occurrenceId())),
                    map("kind", "resource", "name", location.pageId(),
                            "fullyQualifiedName", "notion/pages/" + location.pageId()));
            case "AWS_RESOURCE" -> List.of(map("kind", "resource", "name", location.resource(),
                    "fullyQualifiedName", location.logicalName(record.occurrenceId())));
            default -> List.of(map("kind", "resource", "name", "location-" + record.occurrenceId(),
                    "fullyQualifiedName", location.logicalName(record.occurrenceId())));
        };
    }

    private static Map<String, Object> properties(SecretExportRecord record) {
        var tags = new ArrayList<String>(List.of("secret", "source:" + lower(record.source())));
        if (record.exposureRange() != null) tags.add("exposure-range:" + lower(record.exposureRange()));
        return map("logsseyCredentialSetId", record.credentialSetId(), "logsseyOccurrenceId", record.occurrenceId(),
                "maskedLabel", record.maskedLabel(), "issuer", record.issuer(), "credentialType", record.credentialType(),
                "severity", record.severity(), "validationStatus", record.validationStatus(),
                "source", record.source(), "environment", record.environment(), "origin", record.origin(),
                "exposure", record.exposure(), "exposureRange", record.exposureRange(),
                "presence", record.presence(), "actionStatus", record.actionStatus(),
                "firstSeenAt", text(record.firstSeenAt()), "lastSeenAt", text(record.lastSeenAt()),
                "detectedAt", text(record.detectedAt()), "tags", tags);
    }

    static String level(String severity) {
        if (severity == null) return "warning";
        return switch (severity) {
            case "CRITICAL", "HIGH" -> "error";
            case "LOW" -> "note";
            default -> "warning";
        };
    }

    private static String lower(String value) { return value == null ? "unknown" : value.toLowerCase(java.util.Locale.ROOT); }

    static String text(Object value) { return value == null ? null : value.toString(); }

    /** null 값은 넣지 않는다(SARIF 검증기가 null을 허용하지 않는 칸이 있다). */
    static Map<String, Object> map(Object... pairs) {
        var result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < pairs.length; i += 2) if (pairs[i + 1] != null) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }
}
