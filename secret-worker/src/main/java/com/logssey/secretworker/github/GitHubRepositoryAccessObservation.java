package com.logssey.secretworker.github;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;

/** Safe provider metadata only. No repository URL, response body or authentication material. */
public record GitHubRepositoryAccessObservation(
        long runScopeId,
        List<Long> occurrenceIds,
        boolean publicRepository,
        boolean metadataComplete,
        OffsetDateTime observedAt,
        String reasonCode) {
    public GitHubRepositoryAccessObservation {
        occurrenceIds = List.copyOf(occurrenceIds);
        if (runScopeId <= 0
                || observedAt == null
                || !Set.of(
                                "PUBLIC_CONFIRMED",
                                "REPOSITORY_NON_PUBLIC",
                                "METADATA_UNAVAILABLE",
                                "METADATA_INCOMPLETE",
                                "METADATA_CONFLICT")
                        .contains(reasonCode)
                || publicRepository
                        && (!metadataComplete || !"PUBLIC_CONFIRMED".equals(reasonCode)))
            throw new IllegalArgumentException("INVALID_ACCESS_OBSERVATION");
    }
}
