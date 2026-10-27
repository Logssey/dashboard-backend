package com.logssey.runtime.ingest;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;

import org.springframework.stereotype.Component;

/** Converts allow-listed Falco rules into the dashboard's stable runtime event contract. */
@Component
public class FalcoRuntimeEventNormalizer {

    static final String MISSING_SOURCE_RULE = "MISSING_SOURCE_RULE";
    static final String UNSUPPORTED_SOURCE_RULE = "UNSUPPORTED_SOURCE_RULE";
    static final String RULE_VALIDATION_FAILED = "RULE_VALIDATION_FAILED";

    private static final Set<String> SHELLS = Set.of("bash", "sh", "ash", "dash", "zsh");
    private static final Set<String> PACKAGE_MANAGERS = Set.of(
            "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "pacman", "microdnf", "zypper");
    private static final List<String> SENSITIVE_PATH_PREFIXES = List.of(
            "/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/");
    private static final String SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/";
    private static final Pattern DEPLOYMENT_POD = Pattern.compile("^(.+)-[a-f0-9]{8,10}-[a-z0-9]{5}$");

    private final FalcoRuleRegistry ruleRegistry;

    public FalcoRuntimeEventNormalizer(FalcoRuleRegistry ruleRegistry) {
        this.ruleRegistry = ruleRegistry;
    }

    public RuntimeNormalizationResult normalize(String clusterId, JsonNode event, Instant receivedAt) {
        String sourceRule = text(event, "rule");
        if (sourceRule == null) {
            return RuntimeNormalizationResult.ignored(MISSING_SOURCE_RULE);
        }
        RuntimeRuleDefinition definition = ruleRegistry.find(sourceRule).orElse(null);
        if (definition == null) {
            return RuntimeNormalizationResult.ignored(UNSUPPORTED_SOURCE_RULE);
        }

        JsonNode fields = event.path("output_fields");
        String containerId = text(fields, "container.id");
        String processName = baseName(text(fields, "proc.name", "proc.exepath", "proc.exe"));
        String targetPath = text(fields, "fd.name", "fs.path.name", "evt.arg.path", "evt.arg.filename", "fd.directory");
        if (!valid(definition.validationProfile(), processName, containerId, targetPath)) {
            return RuntimeNormalizationResult.ignored(RULE_VALIDATION_FAILED);
        }

        String executable = text(fields, "proc.exepath", "proc.exe", "proc.name");
        String namespace = text(fields, "k8s.ns.name", "k8s.namespace.name");
        String podName = text(fields, "k8s.pod.name");
        String sourceEventId = text(event, "uuid", "event_id", "id");
        if (sourceEventId == null) {
            sourceEventId = RuntimeHashing.sha256(event.toString());
        }

        List<String> missing = new ArrayList<>();
        required(missing, "asset.namespace", namespace);
        required(missing, "asset.podName", podName);
        required(missing, "asset.containerId", containerId);
        required(missing, "process.executable", executable);
        String targetName = "FILE".equals(definition.targetType()) ? targetPath : executable;
        required(missing, "target.name", targetName);

        String cmdline = text(fields, "proc.cmdline", "proc.args");
        List<String> arguments = cmdline == null || cmdline.isBlank()
                ? List.of()
                : Arrays.stream(cmdline.trim().split("\\s+", 32)).toList();

        NormalizedRuntimeEvent.AssetSnapshot asset = new NormalizedRuntimeEvent.AssetSnapshot(
                clusterId,
                namespace,
                "Deployment",
                workloadName(text(fields, "k8s.deployment.name"), podName),
                text(fields, "k8s.pod.uid"),
                podName,
                containerId,
                text(fields, "k8s.pod.container.name", "container.name"),
                image(fields),
                text(fields, "container.image.digest"),
                text(fields, "k8s.node.name", "evt.hostname"),
                text(fields, "k8s.sa.name", "k8s.serviceaccount.name"));

        NormalizedRuntimeEvent.ProcessSnapshot process = new NormalizedRuntimeEvent.ProcessSnapshot(
                longValue(fields, "proc.pid"),
                longValue(fields, "proc.ppid"),
                executable,
                arguments,
                text(fields, "proc.pexepath", "proc.pname"),
                text(fields, "user.uid", "user.name"));

        NormalizedRuntimeEvent.TargetSnapshot target = new NormalizedRuntimeEvent.TargetSnapshot(
                definition.targetType(), targetName, operation(definition.validationProfile()));

        return RuntimeNormalizationResult.normalized(new NormalizedRuntimeEvent(
                sourceEventId,
                instant(text(event, "time", "timestamp"), receivedAt),
                definition.ruleKey(),
                definition.title(),
                definition.version(),
                priority(text(event, "priority")),
                definition.eventType(),
                asset,
                process,
                target,
                missing.isEmpty() ? "COMPLETE" : "PARTIAL",
                List.copyOf(missing)));
    }

    private static boolean valid(RuntimeRuleDefinition.ValidationProfile profile, String processName,
                                 String containerId, String targetPath) {
        if (containerId == null || "host".equals(containerId)) {
            return false;
        }
        return switch (profile) {
            case CONTAINER_SHELL -> SHELLS.contains(processName);
            case PACKAGE_MANAGER_EXECUTION -> PACKAGE_MANAGERS.contains(processName);
            case SERVICE_ACCOUNT_TOKEN_ACCESS -> targetPath != null
                    && targetPath.startsWith(SERVICE_ACCOUNT_TOKEN_PATH);
            case SENSITIVE_PATH_WRITE -> targetPath != null
                    && SENSITIVE_PATH_PREFIXES.stream().anyMatch(targetPath::startsWith);
        };
    }

    private static String operation(RuntimeRuleDefinition.ValidationProfile profile) {
        return switch (profile) {
            case CONTAINER_SHELL, PACKAGE_MANAGER_EXECUTION -> "EXEC";
            case SERVICE_ACCOUNT_TOKEN_ACCESS -> "OPEN";
            case SENSITIVE_PATH_WRITE -> "WRITE";
        };
    }

    private static String image(JsonNode fields) {
        String repository = text(fields, "container.image.repository");
        String tag = text(fields, "container.image.tag");
        if (repository == null) {
            return text(fields, "container.image");
        }
        return tag == null ? repository : repository + ":" + tag;
    }

    private static String workloadName(String explicit, String podName) {
        if (explicit != null) {
            return explicit;
        }
        if (podName == null) {
            return null;
        }
        Matcher matcher = DEPLOYMENT_POD.matcher(podName);
        return matcher.matches() ? matcher.group(1) : podName;
    }

    private static String priority(String value) {
        if (value == null) {
            return "WARNING";
        }
        return switch (value.toUpperCase(Locale.ROOT)) {
            case "EMERGENCY", "ALERT", "CRITICAL", "ERROR" -> "CRITICAL";
            case "WARNING", "WARN" -> "WARNING";
            case "NOTICE" -> "NOTICE";
            default -> "INFORMATIONAL";
        };
    }

    private static Instant instant(String value, Instant fallback) {
        if (value == null) {
            return fallback;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            return fallback;
        }
    }

    private static void required(List<String> missing, String field, String value) {
        if (value == null) {
            missing.add(field);
        }
    }

    private static Long longValue(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.canConvertToLong()) {
            return value.longValue();
        }
        try {
            return Long.valueOf(value.asText());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static String text(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && !value.isNull()) {
                String result = value.asText().trim();
                if (!result.isEmpty()) {
                    return result;
                }
            }
        }
        return null;
    }

    private static String baseName(String path) {
        if (path == null) {
            return null;
        }
        int slash = path.lastIndexOf('/');
        return (slash >= 0 ? path.substring(slash + 1) : path).toLowerCase(Locale.ROOT);
    }
}
