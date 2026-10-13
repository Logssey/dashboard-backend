package com.logssey.secretworker;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("logssey.secret.scheduler")
public record SecretSchedulerProperties(
        boolean enabled, Duration pollDelay, Duration scanInterval, int batchSize, int maxAttempts) {

    public SecretSchedulerProperties {
        if (pollDelay == null || pollDelay.compareTo(Duration.ofMillis(1)) < 0) {
            throw new IllegalArgumentException("Scheduler poll delay must be at least 1ms");
        }
        if (scanInterval == null || scanInterval.compareTo(Duration.ofSeconds(1)) < 0
                || scanInterval.compareTo(Duration.ofDays(365)) > 0 || scanInterval.getNano() != 0) {
            throw new IllegalArgumentException("Scan interval must be whole seconds between 1s and 365d");
        }
        if (batchSize < 1 || batchSize > 1000) {
            throw new IllegalArgumentException("Scheduler batch size must be between 1 and 1000");
        }
        if (maxAttempts < 1 || maxAttempts > 20) {
            throw new IllegalArgumentException("Job max attempts must be between 1 and 20");
        }
    }
}
