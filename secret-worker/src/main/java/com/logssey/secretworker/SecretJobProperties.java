package com.logssey.secretworker;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("logssey.secret.executor")
public record SecretJobProperties(boolean enabled, Duration pollDelay, Duration leaseDuration,
                                  int batchSize, Duration retryInitialDelay, Duration retryMaxDelay) {

    public SecretJobProperties {
        if (pollDelay == null || pollDelay.compareTo(Duration.ofMillis(100)) < 0) {
            throw new IllegalArgumentException("Executor poll delay must be at least 100ms");
        }
        if (leaseDuration == null || leaseDuration.compareTo(Duration.ofSeconds(1)) < 0
                || leaseDuration.compareTo(Duration.ofDays(1)) > 0) {
            throw new IllegalArgumentException("Job lease duration must be between 1s and 1d");
        }
        if (batchSize < 1 || batchSize > 1000) {
            throw new IllegalArgumentException("Executor batch size must be between 1 and 1000");
        }
        if (retryInitialDelay == null || retryInitialDelay.compareTo(Duration.ofSeconds(1)) < 0
                || retryInitialDelay.compareTo(Duration.ofDays(1)) > 0
                || retryMaxDelay == null || retryMaxDelay.compareTo(retryInitialDelay) < 0
                || retryMaxDelay.compareTo(Duration.ofDays(1)) > 0) {
            throw new IllegalArgumentException("Retry delays must be between 1s and 1d, with max >= initial");
        }
    }

    public Duration retryDelay(int completedAttempts) {
        long multiplier = 1L << Math.min(Math.max(completedAttempts - 1, 0), 19);
        Duration delay = retryInitialDelay.multipliedBy(multiplier);
        return delay.compareTo(retryMaxDelay) > 0 ? retryMaxDelay : delay;
    }
}
