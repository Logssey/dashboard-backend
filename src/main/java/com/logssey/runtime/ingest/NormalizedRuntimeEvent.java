package com.logssey.runtime.ingest;

import java.time.Instant;
import java.util.List;

public record NormalizedRuntimeEvent(
        String sourceEventId,
        Instant occurredAt,
        String ruleKey,
        String ruleTitle,
        String ruleVersion,
        String sourcePriority,
        String eventType,
        AssetSnapshot asset,
        ProcessSnapshot process,
        String normalizationStatus,
        List<String> missingFields) {

    public record AssetSnapshot(
            String clusterId,
            String namespace,
            String workloadKind,
            String workloadName,
            String podUid,
            String podName,
            String containerId,
            String containerName,
            String image,
            String imageDigest,
            String nodeName,
            String serviceAccountName) {

        public boolean resolvable() {
            return namespace != null && podName != null && containerId != null;
        }
    }

    public record ProcessSnapshot(
            Long processId,
            Long parentProcessId,
            String executable,
            List<String> arguments,
            String parentExecutable,
            String userId) {
    }
}
