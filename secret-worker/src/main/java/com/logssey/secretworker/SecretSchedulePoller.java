package com.logssey.secretworker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.secret.scheduler.enabled", havingValue = "true")
public class SecretSchedulePoller {

    private static final Logger log = LoggerFactory.getLogger(SecretSchedulePoller.class);
    private final SecretScheduleService service;
    private final com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat;

    public SecretSchedulePoller(SecretScheduleService service, com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat) {
        this.service = service;
        this.heartbeat = heartbeat;
    }

    @Scheduled(fixedDelayString = "${logssey.secret.scheduler.poll-delay}")
    public void poll() {
        heartbeat.begin("SCHEDULER");
        try {
            int count = service.reserveDueJobs();
            if (count > 0) {
                log.info("Reserved {} Secret scan job(s); collection has not started", count);
            }
            heartbeat.success("SCHEDULER");
        } catch (RuntimeException error) {
            heartbeat.failure("SCHEDULER","SCHEDULER_POLL_FAILED");
            // Avoid logging database values, authentication references or whole exception messages.
            log.error("Secret schedule reservation failed ({}); retry on next poll", error.getClass().getSimpleName());
        }
    }
}
