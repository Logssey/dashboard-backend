package com.logssey.secret.export;

import static com.logssey.secret.export.SarifExportWriter.text;

import java.util.LinkedHashMap;
import java.util.Map;

/** Logssey 기본 JSON. 필드 설명은 docs/secret-export-format.md. */
public final class LogsseyJsonExportWriter {
    static final String SCHEMA = "logssey.secret-export";
    static final String SCHEMA_VERSION = "1.0";

    private LogsseyJsonExportWriter() { }

    public static Map<String, Object> write(SecretExportDocument document) {
        var result = meta(document);
        result.put("items", document.records().stream().map(LogsseyJsonExportWriter::item).toList());
        return result;
    }

    static Map<String, Object> meta(SecretExportDocument document) {
        var meta = new LinkedHashMap<String, Object>();
        meta.put("schema", SCHEMA);
        meta.put("schemaVersion", SCHEMA_VERSION);
        meta.put("generatedAt", text(document.generatedAt()));
        meta.put("asOf", text(document.asOf()));
        meta.put("restrictedCoverage", document.restrictedCoverage());
        meta.put("filters", document.filters());
        meta.put("keyCount", document.keyCount());
        meta.put("locationCount", document.records().size());
        return meta;
    }

    private static Map<String, Object> item(SecretExportRecord record) {
        var location = record.location();
        var where = new LinkedHashMap<String, Object>();
        where.put("kind", location.kind());
        where.put("label", location.label());
        where.put("logicalName", location.logicalName(record.occurrenceId()));
        where.put("repository", location.repository());
        where.put("branch", location.branch());
        where.put("path", location.path());
        where.put("startLine", location.startLine());
        where.put("endLine", location.endLine());
        where.put("notionPageId", location.pageId());
        where.put("notionBlockId", location.blockId());
        where.put("awsRegion", location.region());
        where.put("awsResource", location.resource());

        var item = new LinkedHashMap<String, Object>();
        item.put("credentialSetId", record.credentialSetId());
        item.put("occurrenceId", record.occurrenceId());
        item.put("maskedLabel", record.maskedLabel());
        item.put("issuer", record.issuer());
        item.put("credentialType", record.credentialType());
        item.put("ruleId", record.ruleId());
        item.put("severity", record.severity());
        item.put("validationStatus", record.validationStatus());
        item.put("source", record.source());
        item.put("environment", record.environment());
        item.put("origin", record.origin());
        item.put("location", where);
        item.put("exposure", record.exposure());
        item.put("exposureRange", record.exposureRange());
        item.put("presence", record.presence());
        item.put("actionStatus", record.actionStatus());
        item.put("firstSeenAt", text(record.firstSeenAt()));
        item.put("lastSeenAt", text(record.lastSeenAt()));
        item.put("detectedAt", text(record.detectedAt()));
        return item;
    }
}
