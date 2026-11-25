package com.logssey.secret.response;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** External requests contain only the published vocabulary of statuses and actions. */
record SecretExplanationContext(String topic, String sourceProvider, String issuer, String credentialType, List<String> facts,
                                List<String> actions, List<String> documents) {
    SecretExplanationContext(String topic, String issuer, List<String> facts, List<String> actions, List<String> documents) {
        this(topic, "OTHER", issuer, "OTHER", facts, actions, documents);
    }

    SecretExplanationContext {
        if (!Set.of("SCAN", "CASE").contains(topic)) throw new IllegalArgumentException("EXPLANATION_TOPIC");
        sourceProvider = Set.of("AWS", "GITHUB", "NOTION").contains(sourceProvider == null ? "" : sourceProvider) ? sourceProvider : "OTHER";
        issuer = Set.of("AWS", "GITHUB", "NOTION", "MIXED").contains(issuer == null ? "" : issuer) ? issuer : "OTHER";
        credentialType = Set.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS", "AWS_IAM_ACCESS_KEY",
                "GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT", "NOTION_CONNECTION_TOKEN", "MIXED")
                .contains(credentialType == null ? "" : credentialType) ? credentialType : "OTHER";
        facts = bounded(facts, SecretExplanationCatalog.factCodes(), 24);
        actions = bounded(actions, SecretExplanationCatalog.actionCodes(), 8);
        documents = bounded(documents, Set.of("GITHUB_PAT", "AWS_ACCESS_KEYS", "AWS_TEMPORARY", "NOTION_AUTH"), 3);
    }

    Map<String, Object> externalFields() {
        return Map.of("topic", topic, "sourceProvider", sourceProvider, "issuer", issuer,
                "credentialType", credentialType, "facts", facts,
                "allowedActions", actions, "referenceDocumentCodes", documents,
                "contractVersion", SecretExplanationCatalog.VERSION);
    }

    private static List<String> bounded(List<String> values, Set<String> allowed, int maximum) {
        if (values == null || values.size() > maximum || !allowed.containsAll(values)) {
            throw new IllegalArgumentException("EXPLANATION_VOCABULARY");
        }
        return values.stream().distinct().sorted().toList();
    }
}
