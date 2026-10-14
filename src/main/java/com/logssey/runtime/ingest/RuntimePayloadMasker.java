package com.logssey.runtime.ingest;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

import org.springframework.stereotype.Component;

/** Masks known secret-bearing keys and common credential fragments before a raw event is persisted. */
@Component
public class RuntimePayloadMasker {

    private static final String REDACTED = "[REDACTED]";
    private static final Pattern KEY_VALUE_SECRET = Pattern.compile(
            "(?i)(password|passwd|pwd|token|secret|authorization|api[_-]?key)=([^\\s]+)");
    private static final Pattern BEARER = Pattern.compile("(?i)bearer\\s+[a-z0-9._~+/-]+=*");

    public MaskedPayload mask(JsonNode source) {
        List<String> maskedFields = new ArrayList<>();
        JsonNode copy = maskNode(source.deepCopy(), "$", maskedFields);
        return new MaskedPayload(copy, List.copyOf(maskedFields));
    }

    private JsonNode maskNode(JsonNode node, String path, List<String> maskedFields) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = object.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPath = path + "." + field.getKey();
                if (isSensitiveKey(field.getKey())) {
                    object.put(field.getKey(), REDACTED);
                    maskedFields.add(childPath);
                } else {
                    object.set(field.getKey(), maskNode(field.getValue(), childPath, maskedFields));
                }
            }
            return object;
        }
        if (node.isArray()) {
            ArrayNode array = (ArrayNode) node;
            for (int i = 0; i < array.size(); i++) {
                array.set(i, maskNode(array.get(i), path + "[" + i + "]", maskedFields));
            }
            return array;
        }
        if (node.isTextual()) {
            String original = node.textValue();
            String masked = KEY_VALUE_SECRET.matcher(original).replaceAll("$1=" + REDACTED);
            masked = BEARER.matcher(masked).replaceAll("Bearer " + REDACTED);
            if (!original.equals(masked)) {
                maskedFields.add(path);
                return StringNode.valueOf(masked);
            }
        }
        return node;
    }

    private static boolean isSensitiveKey(String key) {
        String normalized = key.toLowerCase(Locale.ROOT).replace('-', '_');
        return normalized.equals("authorization")
                || normalized.equals("cookie")
                || normalized.equals("password")
                || normalized.equals("passwd")
                || normalized.equals("secret")
                || normalized.equals("token")
                || normalized.equals("api_key")
                || normalized.equals("access_token")
                || normalized.equals("refresh_token")
                || normalized.equals("environment_variables")
                || normalized.equals("env");
    }

    public record MaskedPayload(JsonNode payload, List<String> maskedFields) {
    }
}
