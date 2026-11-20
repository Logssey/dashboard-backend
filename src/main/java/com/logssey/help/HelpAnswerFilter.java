package com.logssey.help;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
    private static final Pattern PARAGRAPH_BREAK = Pattern.compile("\\n\\s*\\n");
    private static final double REPEAT_OVERLAP = 0.6;
    private static final int MIN_PAIRS_FOR_REPEAT = 15;

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
            String answer = withoutRepeatedParagraphs(text.toString().strip());
            if (answer.isEmpty()) return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
            if (citations == 0) return Result.ungrounded(usage);
            if (!safe(answer)) return Result.failed("ANSWER_BLOCKED", usage);
            return new Result(answer, List.copyOf(new ArrayList<>(sources)), true, null, usage);
        } catch (RuntimeException invalid) {
            return Result.failed("PROVIDER_INVALID_RESPONSE", usage);
        }
    }

    /**
     * Drops a paragraph that repeats an earlier one, even when reworded slightly
     * (character-pair overlap of 60% or more). Short paragraphs are always kept.
     */
    static String withoutRepeatedParagraphs(String answer) {
        String[] paragraphs = PARAGRAPH_BREAK.split(answer);
        if (paragraphs.length < 2) return answer;
        var kept = new ArrayList<String>();
        var keptPairs = new ArrayList<Set<String>>();
        for (String paragraph : paragraphs) {
            String trimmed = paragraph.strip();
            if (trimmed.isEmpty()) continue;
            Set<String> pairs = characterPairs(trimmed);
            boolean repeated = pairs.size() >= MIN_PAIRS_FOR_REPEAT
                    && keptPairs.stream().anyMatch(earlier -> overlap(earlier, pairs) >= REPEAT_OVERLAP);
            if (repeated) continue;
            kept.add(trimmed);
            keptPairs.add(pairs);
        }
        return String.join("\n\n", kept);
    }

    private static Set<String> characterPairs(String paragraph) {
        String letters = paragraph.replaceAll("[\\s\\p{Punct}“”‘’·…]", "");
        var pairs = new HashSet<String>();
        for (int i = 0; i + 1 < letters.length(); i++) pairs.add(letters.substring(i, i + 2));
        return pairs;
    }

    private static double overlap(Set<String> a, Set<String> b) {
        if (a.isEmpty() || b.isEmpty()) return 0;
        int common = 0;
        for (String pair : b) if (a.contains(pair)) common++;
        return (double) common / Math.min(a.size(), b.size());
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
