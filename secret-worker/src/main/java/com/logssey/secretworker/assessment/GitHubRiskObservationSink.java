package com.logssey.secretworker.assessment;

import com.logssey.secret.risk.core.SecretRiskObservationWriter;
import com.logssey.secretworker.github.GitHubRepositoryAccessObservation;
import com.logssey.secretworker.github.GitHubRepositoryAccessSink;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Persists access observations in the collector's existing, fenced scope transaction. */
@Component
public final class GitHubRiskObservationSink implements GitHubRepositoryAccessSink {
    private final SecretRiskObservationWriter observations;

    public GitHubRiskObservationSink(JdbcTemplate jdbc) {
        observations = new SecretRiskObservationWriter(jdbc);
    }

    @Override
    public void observe(GitHubRepositoryAccessObservation observation) {
        // The source IDs come from the completed run scope. The writer checks every parent,
        // current source revision and ingestion key again before adding immutable evidence.
        for (long occurrenceId : observation.occurrenceIds().stream().distinct().sorted().toList()) {
            observations.githubRepositoryAccess(
                    occurrenceId,
                    observation.runScopeId(),
                    observation.publicRepository(),
                    observation.metadataComplete(),
                    observation.observedAt());
        }
    }
}
