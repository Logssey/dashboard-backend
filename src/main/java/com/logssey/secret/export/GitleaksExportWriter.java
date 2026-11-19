package com.logssey.secret.export;

import static com.logssey.secret.export.SarifExportWriter.text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gitleaks v8 보고서 모양의 JSON 목록.
 * DefectDojo Gitleaks 파서(dojo/tools/gitleaks/parser.py)는 Description이 있는 항목을 현재 형식으로 읽고,
 * 중복 판단에 Description·File·Secret·StartLine을 쓴다. Secret과 Match에는 원문 대신 마스킹 라벨을 넣는다.
 * Fingerprint는 gitleaks 관례(파일:규칙:줄)를 따르며 HMAC 지문을 쓰지 않는다.
 */
public final class GitleaksExportWriter {
    private GitleaksExportWriter() { }

    public static List<Map<String, Object>> write(SecretExportDocument document) {
        return document.records().stream().map(GitleaksExportWriter::item).toList();
    }

    private static Map<String, Object> item(SecretExportRecord record) {
        var location = record.location();
        String file = location.logicalName(record.occurrenceId());
        int start = location.startLine() == null ? 0 : location.startLine();
        int end = location.endLine() == null ? start : location.endLine();
        var tags = new ArrayList<String>();
        tags.add("logssey");
        tags.add("source:" + record.source());
        tags.add("severity:" + record.severity());
        tags.add("exposure:" + record.exposure());
        tags.add("exposure-range:" + record.exposureRange());
        tags.add("presence:" + record.presence());
        tags.add("status:" + record.actionStatus());
        tags.add("validation:" + record.validationStatus());

        var item = new LinkedHashMap<String, Object>();
        item.put("Description", record.issuer() + " " + record.credentialType() + " (" + record.ruleId() + ")");
        item.put("StartLine", start);
        item.put("EndLine", end);
        item.put("StartColumn", 0);
        item.put("EndColumn", 0);
        item.put("Match", record.maskedLabel());
        item.put("Secret", record.maskedLabel());
        item.put("File", file);
        item.put("SymlinkFile", "");
        item.put("Commit", "");
        item.put("Entropy", 0);
        item.put("Author", "");
        item.put("Email", "");
        item.put("Date", text(record.detectedAt() != null ? record.detectedAt() : record.lastSeenAt()));
        item.put("Message", location.label());
        item.put("Tags", tags);
        item.put("RuleID", record.ruleId());
        item.put("Fingerprint", file + ":" + record.ruleId() + ":" + start);
        return item;
    }
}
