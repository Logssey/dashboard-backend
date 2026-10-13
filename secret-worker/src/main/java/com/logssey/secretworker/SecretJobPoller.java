package com.logssey.secretworker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.secret.executor.enabled", havingValue = "true")
public class SecretJobPoller {

    private static final Logger log = LoggerFactory.getLogger(SecretJobPoller.class);

    private final SecretJobExecutionService execution;
    private final SecretJobProperties properties;
    private final ObjectProvider<SecretJobProcessor> processorProvider;

    public SecretJobPoller(SecretJobExecutionService execution, SecretJobProperties properties,
                           ObjectProvider<SecretJobProcessor> processorProvider) {
        this.execution = execution;
        this.properties = properties;
        this.processorProvider = processorProvider;
    }

    @Scheduled(fixedDelayString = "${logssey.secret.executor.poll-delay}")
    public void poll() {
        // Enabling the property alone must not consume jobs before a collector is integrated.
        SecretJobProcessor processor = processorProvider.getIfAvailable();
        if (processor == null) {
            return;
        }
        try {
            execution.recoverExpiredJobs();
            // Claim immediately before processing so a queued local job does not lose its lease.
            for (int i = 0; i < properties.batchSize(); i++) {
                var job = execution.claimNextJob();
                if (job.isEmpty()) {
                    break;
                }
                processOne(processor, job.get());
            }
        } catch (RuntimeException error) {
            log.error("Secret job polling failed ({}); retry on next poll", error.getClass().getSimpleName());
        }
    }

    private void processOne(SecretJobProcessor processor, ClaimedSecretJob job) {
        try {
            processor.process(job, execution);
            if (!execution.complete(job.jobId(), job.leaseToken())) {
                execution.fail(job.jobId(), job.leaseToken(), SecretJobFailureCode.INCOMPLETE_RUN, true);
            }
        } catch (SecretJobFailure failure) {
            execution.fail(job.jobId(), job.leaseToken(), failure.code(), failure.retryable());
        } catch (RuntimeException error) {
            // Exception messages and provider response bodies may contain secrets.
            log.error("Secret job {} failed ({}); recording a generic code", job.jobId(),
                    error.getClass().getSimpleName());
            execution.fail(job.jobId(), job.leaseToken(), SecretJobFailureCode.PROCESSOR_FAILURE, true);
        }
    }
}
