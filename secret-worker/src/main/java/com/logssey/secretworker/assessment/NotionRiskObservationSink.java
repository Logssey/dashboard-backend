package com.logssey.secretworker.assessment;

import com.logssey.secret.risk.core.SecretRiskObservationWriter;
import com.logssey.secretworker.notion.NotionPageAccessObservation;
import com.logssey.secretworker.notion.NotionPageAccessSink;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Persists Notion web-publication observations in the scope's existing, fenced transaction. */
@Component
public final class NotionRiskObservationSink implements NotionPageAccessSink {
    private final SecretRiskObservationWriter observations;

    public NotionRiskObservationSink(JdbcTemplate jdbc) {
        observations = new SecretRiskObservationWriter(jdbc);
    }

    @Override
    public void observe(NotionPageAccessObservation observation) {
        for (long occurrenceId : observation.occurrenceIds().stream().distinct().sorted().toList()) {
            observations.notionPageAccess(
                    occurrenceId,
                    observation.runScopeId(),
                    observation.publishedToWeb(),
                    observation.observedAt());
        }
    }
}
