package com.logssey.secretworker.notion;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;

/**
 * Safe page metadata only: whether the page is published to the web. No URL, title or content.
 * Published proves BROAD (anyone with the link, no sign-in). Not published proves nothing about
 * who can read it inside the workspace, so it is recorded as an unknown audience.
 */
public record NotionPageAccessObservation(
        long runScopeId,
        List<Long> occurrenceIds,
        boolean publishedToWeb,
        OffsetDateTime observedAt,
        String reasonCode) {
    public NotionPageAccessObservation {
        occurrenceIds = List.copyOf(occurrenceIds);
        if (runScopeId <= 0
                || observedAt == null
                || !Set.of("PUBLISHED_TO_WEB", "NOT_PUBLISHED").contains(reasonCode)
                || publishedToWeb != "PUBLISHED_TO_WEB".equals(reasonCode))
            throw new IllegalArgumentException("INVALID_ACCESS_OBSERVATION");
    }
}
