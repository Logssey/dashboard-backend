package com.logssey.secret.response;

import java.util.List;

public record SecretExplanationResponse(String version, String topic, String source, String summary,
        List<Fact> facts, List<Action> actions, List<Document> documents, SecretGuideReadiness readiness) {
    public record Fact(String code, String label) { }
    public record Action(String code, String label, String href) { }
    public record Document(String id, String title, String url, String reviewedAt) { }
}
