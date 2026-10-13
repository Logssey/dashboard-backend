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

    public SecretSchedulePoller(SecretScheduleService service) {
        this.service = service;
    }

    @Scheduled(fixedDelayString = "${logssey.secret.scheduler.poll-delay}")
    public void poll() {
        try {
            int count = service.reserveDueJobs();
            if (count > 0) {
                log.info("Reserved {} Secret scan job(s); collection has not started", count);
            }
        } catch (RuntimeException error) {
            // Avoid logging database values, authentication references or whole exception messages.
            log.error("Secret schedule reservation failed ({}); retry on next poll", error.getClass().getSimpleName());
        }
    }
}
