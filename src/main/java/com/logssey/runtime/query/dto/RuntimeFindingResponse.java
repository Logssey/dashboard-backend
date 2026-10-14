package com.logssey.runtime.query.dto;

import java.util.List;

public record RuntimeFindingResponse(
        long findingId,
        String displayId,
        Rule rule,
        String reviewStatus,
        String actionStatus,
        String disposition,
        String sourcePriority,
        String evaluationStatus,
        String finalSeverity,
        String firstSeenAt,
        String lastSeenAt,
        long occurrenceCount,
        List<String> sensors,
        AssetSummary asset,
        ProcessSummary process,
        Long assigneeUserId,
        String assigneeDisplayName,
        String note,
        long version) {

    public record Rule(String key, String title, String version) {
    }

    public record AssetSummary(
            String clusterId,
            String namespace,
            String workloadKind,
            String workloadName,
            String podUid,
            String podName,
            String containerName,
            String image,
            String imageDigest,
            String nodeName,
            String serviceAccountName,
            boolean deleted) {
    }

    public record ProcessSummary(String executable, String parentExecutable, String userId) {
    }
}
