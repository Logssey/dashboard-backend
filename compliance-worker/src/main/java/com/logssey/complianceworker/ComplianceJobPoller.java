package com.logssey.complianceworker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.compliance-worker.enabled", havingValue = "true")
public class ComplianceJobPoller {

    private static final Logger log = LoggerFactory.getLogger(ComplianceJobPoller.class);

    private final ComplianceWorkerProperties properties;
    private final ComplianceWorkerApiClient api;
    private final ProwlerExecutionService execution;

    public ComplianceJobPoller(ComplianceWorkerProperties properties, ComplianceWorkerApiClient api,
                               ProwlerExecutionService execution) {
        this.properties = properties;
        this.api = api;
        this.execution = execution;
    }

    @Scheduled(fixedDelayString = "${logssey.compliance-worker.poll-delay}")
    public void poll() {
        if (properties.token() == null || properties.token().length() < 24) {
            log.error("Compliance Worker token is missing or too short; polling is disabled");
            return;
        }
        try {
            api.claim().ifPresent(execution::execute);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Compliance job polling failed ({}); retrying on next poll", e.getClass().getSimpleName());
        }
    }
}
