package com.logssey.runtime.ingest;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.logssey.runtime.ingest.RuntimeRuleDefinition.Maturity;
import com.logssey.runtime.ingest.RuntimeRuleDefinition.Mode;
import com.logssey.runtime.ingest.RuntimeRuleDefinition.ValidationProfile;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/** Loads and validates the versioned runtime rule contract shipped with the application. */
@Component
public final class RuntimeRulePack {

    static final String RESOURCE = "runtime/rules/runtime-rule-pack-v1.yaml";
    static final String SCHEMA_VERSION = "runtime-rule-pack/v1";

    private final String packVersion;
    private final List<RuntimeRuleDefinition> rules;
    private final Map<SourceRuleKey, RuntimeRuleDefinition> sourceIndex;

    public RuntimeRulePack() {
        this(loadDocument());
    }

    RuntimeRulePack(Map<String, Object> document) {
        require(SCHEMA_VERSION.equals(string(document, "schemaVersion")), "Unsupported rule pack schema");
        this.packVersion = requiredString(document, "packVersion");
        this.rules = parseRules(list(document, "rules"));
        this.sourceIndex = buildIndex(rules);
    }

    public String packVersion() {
        return packVersion;
    }

    public List<RuntimeRuleDefinition> rules() {
        return rules;
    }

    public Optional<RuntimeRuleDefinition> find(String sensor, String sourceRule) {
        if (sensor == null || sourceRule == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sourceIndex.get(new SourceRuleKey(sensor, sourceRule)));
    }

    private static Map<String, Object> loadDocument() {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        Yaml yaml = new Yaml(new SafeConstructor(options));
        try (InputStream input = new ClassPathResource(RESOURCE).getInputStream()) {
            Object loaded = yaml.load(input);
            if (!(loaded instanceof Map<?, ?> map)) {
                throw new IllegalStateException("Runtime rule pack root must be a mapping");
            }
            return stringMap(map, "rule pack");
        } catch (IOException e) {
            throw new IllegalStateException("Runtime rule pack could not be loaded", e);
        }
    }

    private static List<RuntimeRuleDefinition> parseRules(List<?> values) {
        require(!values.isEmpty(), "Runtime rule pack must contain rules");
        List<RuntimeRuleDefinition> parsed = new ArrayList<>(values.size());
        Set<String> keys = new LinkedHashSet<>();
        for (Object value : values) {
            if (!(value instanceof Map<?, ?> map)) {
                throw new IllegalStateException("Each runtime rule must be a mapping");
            }
            Map<String, Object> rule = stringMap(map, "rule");
            String key = requiredString(rule, "key");
            require(keys.add(key), "Duplicate runtime rule key: " + key);
            Mode mode = enumValue(Mode.class, requiredString(rule, "mode"), key + ".mode");
            Map<String, List<String>> sourceRules = stringListMap(rule.get("sourceRules"), key + ".sourceRules");
            require(mode == Mode.DRAFT || !sourceRules.isEmpty(), key + " active rule requires a source mapping");
            require(mode != Mode.DRAFT || sourceRules.isEmpty(), key + " draft rule cannot expose a source mapping");
            int noiseBudget = integer(rule, "noiseBudgetPerMinute");
            require(noiseBudget > 0, key + ".noiseBudgetPerMinute must be positive");
            RuntimeRuleDefinition definition = new RuntimeRuleDefinition(
                    key,
                    requiredString(rule, "title"),
                    requiredString(rule, "version"),
                    requiredString(rule, "eventType"),
                    requiredString(rule, "targetType"),
                    requiredString(rule, "operation"),
                    mode,
                    enumValue(Maturity.class, requiredString(rule, "maturity"), key + ".maturity"),
                    enumValue(ValidationProfile.class, requiredString(rule, "validationProfile"),
                            key + ".validationProfile"),
                    stringList(rule.get("sensors"), key + ".sensors"),
                    stringList(rule.get("mitre"), key + ".mitre"),
                    noiseBudget,
                    requiredString(rule, "owner"),
                    sourceRules);
            require(definition.sensors().containsAll(sourceRules.keySet()),
                    key + " source mapping references an undeclared sensor");
            parsed.add(definition);
        }
        return List.copyOf(parsed);
    }

    private static Map<SourceRuleKey, RuntimeRuleDefinition> buildIndex(List<RuntimeRuleDefinition> rules) {
        Map<SourceRuleKey, RuntimeRuleDefinition> index = new LinkedHashMap<>();
        for (RuntimeRuleDefinition definition : rules) {
            definition.sourceRules().forEach((sensor, sourceRules) -> sourceRules.forEach(sourceRule -> {
                SourceRuleKey key = new SourceRuleKey(sensor, sourceRule);
                RuntimeRuleDefinition previous = index.putIfAbsent(key, definition);
                require(previous == null, "Duplicate sensor source mapping: " + sensor + "/" + sourceRule);
            }));
        }
        return Map.copyOf(index);
    }

    private static Map<String, Object> stringMap(Map<?, ?> value, String path) {
        Map<String, Object> result = new LinkedHashMap<>();
        value.forEach((key, item) -> {
            if (!(key instanceof String stringKey)) {
                throw new IllegalStateException(path + " keys must be strings");
            }
            result.put(stringKey, item);
        });
        return result;
    }

    private static Map<String, List<String>> stringListMap(Object value, String path) {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalStateException(path + " must be a mapping");
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        stringMap(map, path).forEach((key, item) -> result.put(key, stringList(item, path + "." + key)));
        return Map.copyOf(result);
    }

    private static List<?> list(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof List<?> list)) {
            throw new IllegalStateException(key + " must be a list");
        }
        return list;
    }

    private static List<String> stringList(Object value, String path) {
        if (!(value instanceof List<?> list)) {
            throw new IllegalStateException(path + " must be a list");
        }
        List<String> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank()) {
                throw new IllegalStateException(path + " values must be non-blank strings");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static int integer(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Number number)) {
            throw new IllegalStateException(key + " must be an integer");
        }
        return number.intValue();
    }

    private static String requiredString(Map<String, Object> map, String key) {
        String value = string(map, key);
        require(value != null && !value.isBlank(), key + " is required");
        return value;
    }

    private static String string(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value instanceof String text ? text : null;
    }

    private static <T extends Enum<T>> T enumValue(Class<T> type, String value, String path) {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(path + " has an unsupported value: " + value, e);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private record SourceRuleKey(String sensor, String sourceRule) {
    }
}
