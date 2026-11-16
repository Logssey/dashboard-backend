package com.logssey.compliance;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Prowler JSON-OCSF를 화면과 평가 엔진이 공통으로 쓰는 안전한 형태로 바꾼다. */
@Component
public class ProwlerOcsfNormalizer {

    static final int MAX_RESULTS = 20_000;
    private static final Pattern ARN_ACCOUNT = Pattern.compile("(arn:[^:]+:[^:]*:[^:]*:)(\\d{4})\\d{4}(\\d{4})(:)");
    private static final Pattern ACCOUNT = Pattern.compile("\\b(\\d{4})\\d{4}(\\d{4})\\b");
    private final JsonMapper mapper = JsonMapper.builder().build();
    private final Clock clock;

    public ProwlerOcsfNormalizer() {
        this(Clock.systemUTC());
    }

    ProwlerOcsfNormalizer(Clock clock) {
        this.clock = clock;
    }

    public NormalizedImport normalize(byte[] bytes, String fallbackEnvironment) {
        final JsonNode root;
        try {
            root = mapper.readTree(bytes);
        } catch (RuntimeException e) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "Prowler JSON 파일을 읽을 수 없습니다.");
        }
        JsonNode records = records(root);
        if (records.size() > MAX_RESULTS) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE,
                    "한 번에 가져올 수 있는 결과는 " + MAX_RESULTS + "건입니다.");
        }

        var unique = new LinkedHashMap<String, NormalizedResult>();
        int warnings = 0;
        for (int index = 0; index < records.size(); index++) {
            var normalized = normalizeRecord(records.get(index), fallbackEnvironment);
            if (normalized == null) {
                warnings++;
            } else {
                unique.put(normalized.fingerprint(), normalized);
            }
        }
        if (unique.isEmpty()) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "가져올 수 있는 Prowler 결과가 없습니다.");
        }

        JsonNode first = records.get(0);
        JsonNode product = first.path("metadata").path("product");
        int duplicates = records.size() - unique.size() - warnings;
        return new NormalizedImport(
                Map.copyOf(unique), records.size(), Math.max(duplicates, 0), warnings,
                bounded(text(product.path("name"), "Prowler"), 100),
                bounded(text(product.path("version"), "unknown"), 50));
    }

    private JsonNode records(JsonNode root) {
        if (root.isArray()) return root;
        if (root.path("findings").isArray()) return root.path("findings");
        if (root.path("items").isArray()) return root.path("items");
        throw new ApiException(ErrorCode.UNPROCESSABLE,
                "최상위 배열 또는 findings/items 배열이 필요합니다.");
    }

    private NormalizedResult normalizeRecord(JsonNode record, String fallbackEnvironment) {
        String checkId = firstText(record.path("metadata").path("event_code"), record.path("unmapped").path("check_id"));
        String rawStatus = firstText(record.path("status_code"), record.path("status")).toUpperCase(Locale.ROOT);
        if (checkId.isBlank() || rawStatus.isBlank()) return null;

        JsonNode resource = record.path("resources").isArray() && !record.path("resources").isEmpty()
                ? record.path("resources").get(0) : mapper.createObjectNode();
        String provider = firstText(record.path("cloud").path("provider"), resource.path("cloud_partition"),
                record.path("metadata").path("provider"));
        if (provider.isBlank()) provider = "aws";
        provider = bounded(provider.toLowerCase(Locale.ROOT), 30);

        String asset = firstText(resource.path("name"), record.path("cloud").path("account").path("name"));
        if (asset.isBlank()) asset = provider.equals("kubernetes") ? "cluster-wide" : "AWS Account";
        String fingerprint = firstText(record.path("finding_info").path("uid"));
        if (fingerprint.isBlank()) {
            fingerprint = provider + ":" + checkId + ":" + firstText(resource.path("uid"), resource.path("name"));
        }

        return new NormalizedResult(
                bounded(checkId, 180),
                bounded(text(record.path("finding_info").path("title"), checkId), 500),
                provider,
                normalizedStatus(rawStatus),
                bounded(mask(asset), 500),
                mask(firstText(record.path("status_detail"), record.path("message"), record.path("status_code"))),
                mask(firstTextOr(record.path("remediation").path("desc"),
                        record.path("finding_info").path("desc"), "Prowler 점검 기준 충족")),
                observedAt(record),
                bounded(firstTextOr(resource.path("region"), record.path("cloud").path("region"), "global"), 100),
                bounded(text(record.path("severity"), "Unknown"), 30),
                sha256(fingerprint),
                bounded(mask(text(resource.path("uid"), "")), 700),
                bounded(firstTextOr(resource.path("type"), resource.path("type_name"), ""), 180),
                environment(record, fallbackEnvironment));
    }

    private static String normalizedStatus(String raw) {
        return switch (raw) {
            case "PASS" -> "PASS";
            case "FAIL" -> "FAIL";
            case "MUTED", "MANUAL" -> "NEEDS_REVIEW";
            default -> "ERROR";
        };
    }

    private OffsetDateTime observedAt(JsonNode record) {
        String iso = firstText(record.path("time_dt"), record.path("finding_info").path("created_time_dt"));
        if (!iso.isBlank()) {
            try {
                return OffsetDateTime.parse(iso);
            } catch (DateTimeParseException ignored) {
                try {
                    return Instant.parse(iso).atOffset(ZoneOffset.UTC);
                } catch (DateTimeParseException ignoredAgain) {
                    // 아래 epoch 또는 현재 시각을 사용한다.
                }
            }
        }
        JsonNode epoch = !record.path("time").isMissingNode() ? record.path("time")
                : record.path("finding_info").path("created_time");
        if (epoch.isNumber()) return Instant.ofEpochSecond(epoch.asLong()).atOffset(ZoneOffset.UTC);
        return OffsetDateTime.now(clock);
    }

    private static String environment(JsonNode record, String fallback) {
        JsonNode labels = record.path("resources").isArray() && !record.path("resources").isEmpty()
                ? record.path("resources").get(0).path("labels") : null;
        if (labels != null && labels.isArray()) {
            for (JsonNode labelNode : labels) {
                String label = labelNode.asText("");
                int separator = label.indexOf(':');
                if (separator < 0) continue;
                String key = label.substring(0, separator);
                if (!key.equalsIgnoreCase("environment") && !key.equalsIgnoreCase("env")) continue;
                String value = label.substring(separator + 1).toLowerCase(Locale.ROOT);
                if (value.equals("prod") || value.equals("production") || value.equals("운영")) return "prod";
                if (value.equals("dev") || value.equals("development") || value.equals("staging") || value.equals("개발")) return "dev";
            }
        }
        return fallback;
    }

    private static String firstText(JsonNode... nodes) {
        for (JsonNode node : nodes) {
            if (node != null && node.isValueNode() && !node.asText("").isBlank()) return node.asText();
        }
        return "";
    }

    private static String firstTextOr(JsonNode first, JsonNode second, String fallback) {
        String value = firstText(first, second);
        return value.isBlank() ? fallback : value;
    }

    private static String text(JsonNode node, String fallback) {
        return node != null && node.isValueNode() && !node.asText("").isBlank() ? node.asText() : fallback;
    }

    private static String mask(String value) {
        String safe = value == null ? "" : value.replace("\u0000", "");
        String arnMasked = ARN_ACCOUNT.matcher(safe).replaceAll("$1$2****$3$4");
        return ACCOUNT.matcher(arnMasked).replaceAll("$1****$2");
    }

    private static String bounded(String value, int max) {
        if (value == null) return "";
        String safe = value.replace("\u0000", "");
        return safe.length() <= max ? safe : safe.substring(0, max);
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", e);
        }
    }

    public record NormalizedImport(Map<String, NormalizedResult> results, int inputCount, int duplicateCount,
                                   int warningCount, String product, String version) {}

    public record NormalizedResult(String checkId, String title, String provider, String result, String asset,
                                   String currentValue, String expectedValue, OffsetDateTime observedAt,
                                   String region, String severity, String fingerprint, String assetUid,
                                   String assetType, String environment) {
        String checkKey() { return provider + ":" + checkId; }
    }
}
