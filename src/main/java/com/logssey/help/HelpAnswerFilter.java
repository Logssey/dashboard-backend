package com.logssey.help;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Parses a Messages API response and keeps only a grounded, plain-text answer.
 * An answer with no citation into the approved guides is never shown.
 */
final class HelpAnswerFilter {

    static final int MAX_ANSWER_CHARS = 1_500;
    private static final Pattern FORBIDDEN = Pattern.compile(
            "(?i)https?://|www\\.|<\\s*/?\\s*(script|iframe|img|a|svg)\\b|javascript:|-----BEGIN");
    private static final JsonMapper JSON = new JsonMapper();

    private HelpAnswerFilter() {
    }

    static Result parse(byte[] body, List<HelpDocument> documents) {
        Usage usage = Usage.EMPTY;
        try {
            JsonNode message = JSON.readTree(body);
            usage = usage(message.path("usage"));
            if (!"message".equals(message.path("type").asText())
                    || !"assistant".equals(message.path("role").asText())) {
                return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
            }
            String stop = message.path("stop_reason").asText();
            if ("refusal".equals(stop)) return Result.failed("PROVIDER_REFUSED", usage);
            if (!"end_turn".equals(stop)) return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
            JsonNode content = message.path("content");
            if (!content.isArray()) return Result.failed("PROVIDER_INVALID_RESPONSE", usage);

            var text = new StringBuilder();
            var sources = new LinkedHashSet<Source>();
            int citations = 0;
            for (JsonNode block : content) {
                String type = block.path("type").asText();
                if ("thinking".equals(type) || "redacted_thinking".equals(type)) continue;
                if (!"text".equals(type) || !block.path("text").isTextual()) {
                    return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
                }
                text.append(block.path("text").asText());
                for (JsonNode citation : block.path("citations")) {
                    int index = citation.path("document_index").asInt(-1);
                    if (index < 0 || index >= documents.size()) continue;
                    citations++;
                    HelpDocument doc = documents.get(index);
                    sources.add(new Source(doc.file(), doc.title(),
                            doc.sectionAt(citation.path("start_char_index").asInt(0))));
                }
            }
            String answer = text.toString().strip();
            if (answer.isEmpty()) return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
            if (citations == 0) return Result.ungrounded(usage);
            if (!safe(answer)) return Result.failed("ANSWER_BLOCKED", usage);
            return new Result(answer, List.copyOf(new ArrayList<>(sources)), true, null, usage);
        } catch (RuntimeException invalid) {
            return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
        }
    }

    static boolean safe(String answer) {
        if (answer.length() > MAX_ANSWER_CHARS) return false;
        if (answer.chars().anyMatch(c -> c < 0x20 && c != '\n')) return false;
        if (FORBIDDEN.matcher(answer).find()) return false;
        return !HelpQuestionGuard.containsSecretLikeValue(answer);
    }

    private static Usage usage(JsonNode node) {
        if (!node.isObject()) return Usage.EMPTY;
        return new Usage(node.path("input_tokens").asInt(0),
                node.path("cache_read_input_tokens").asInt(0),
                node.path("cache_creation_input_tokens").asInt(0),
                node.path("output_tokens").asInt(0));
    }

    record Source(String doc, String title, String section) {
    }

    record Usage(int input, int cacheRead, int cacheWrite, int output) {
        static final Usage EMPTY = new Usage(0, 0, 0, 0);
    }

    record Result(String answer, List<Source> sources, boolean grounded, String reasonCode, Usage usage) {
        static Result failed(String reasonCode, Usage usage) {
            return new Result(null, List.of(), false, reasonCode, usage);
        }

        static Result ungrounded(Usage usage) {
            return new Result(null, List.of(), false, "NO_GROUNDED_ANSWER", usage);
        }

        boolean ok() {
            return reasonCode == null;
        }
    }
}
