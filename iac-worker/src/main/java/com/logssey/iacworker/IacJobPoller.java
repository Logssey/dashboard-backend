package com.logssey.iacworker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.iac.executor.enabled", havingValue = "true")
public class IacJobPoller {

    private static final Logger log = LoggerFactory.getLogger(IacJobPoller.class);

    private final IacJobExecutionService execution;
    private final IacJobProperties properties;
    private final ObjectProvider<IacJobProcessor> processorProvider;

    public IacJobPoller(IacJobExecutionService execution, IacJobProperties properties,
                        ObjectProvider<IacJobProcessor> processorProvider) {
        this.execution = execution;
        this.properties = properties;
        this.processorProvider = processorProvider;
    }

    @Scheduled(fixedDelayString = "${logssey.iac.executor.poll-delay}")
    public void poll() {
        // Each processor claims only its own kind. No processor means no claims.
        var processors = processorProvider.orderedStream().toList();
        if (processors.isEmpty()) {
            return;
        }
        try {
            execution.recoverExpiredJobs();
            for (IacJobProcessor processor : processors) {
                // Claim immediately before processing so a queued job does not lose its lease.
                for (int i = 0; i < properties.batchSize(); i++) {
                    var job = execution.claimNextJob(processor.kind());
                    if (job.isEmpty()) break;
                    processOne(processor, job.get());
                }
            }
        } catch (RuntimeException error) {
            log.error("IaC job polling failed ({}); retry on next poll", error.getClass().getSimpleName());
        }
    }

    @Scheduled(fixedDelayString = "${logssey.iac.executor.plan-cleanup-delay}")
    public void deleteExpiredPlans() {
        try {
            int deleted = execution.deleteExpiredPlans();
            if (deleted > 0) {
                log.info("Deleted {} expired plan payloads", deleted);
            }
        } catch (RuntimeException error) {
            log.error("Plan cleanup failed ({}); retry on next run", error.getClass().getSimpleName());
        }
    }

    void processOne(IacJobProcessor processor, ClaimedIacJob job) {
        try {
            processor.process(job, execution);
            if (!execution.complete(job.jobId(), job.leaseToken())) {
                log.warn("IaC job {} lost its lease before completion", job.jobId());
            }
        } catch (IacJobFailure failure) {
            execution.fail(job.jobId(), job.leaseToken(), failure.code(), failure.retryable());
        } catch (RuntimeException error) {
            // Exception messages may contain plan or provider content.
            log.error("IaC job {} failed ({}); recording a generic code", job.jobId(),
                    error.getClass().getSimpleName());
            execution.fail(job.jobId(), job.leaseToken(), IacJobFailureCode.PROCESSOR_FAILURE, true);
        }
    }
}
