package com.logssey.secretworker;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.secret.executor.enabled", havingValue = "true")
public class SecretJobPoller implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(SecretJobPoller.class);

    private final SecretJobExecutionService execution;
    private final SecretJobProperties properties;
    private final ObjectProvider<SecretJobProcessor> processorProvider;
    private final com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat;
    private final Set<String> runningProviders = ConcurrentHashMap.newKeySet();
    private final ExecutorService providerExecutor =
            Executors.newFixedThreadPool(3,
                    Thread.ofPlatform().daemon(true).name("secret-provider-", 0).factory());
    private volatile boolean stopped;

    public SecretJobPoller(SecretJobExecutionService execution, SecretJobProperties properties,
                           ObjectProvider<SecretJobProcessor> processorProvider) {
        this(execution,properties,processorProvider,null);
    }
    @org.springframework.beans.factory.annotation.Autowired
    public SecretJobPoller(SecretJobExecutionService execution, SecretJobProperties properties,
                           ObjectProvider<SecretJobProcessor> processorProvider,
                           com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat) {
        this.execution = execution;
        this.properties = properties;
        this.processorProvider = processorProvider;
        this.heartbeat = heartbeat;
    }

    @Scheduled(fixedDelayString = "${logssey.secret.executor.poll-delay}")
    public void poll() {
        // Each opt-in provider claims only its own jobs. No collector means no claims.
        var processors = processorProvider.orderedStream().toList();
        if (processors.isEmpty() || stopped) {
            return;
        }
        if(heartbeat!=null)heartbeat.begin("EXECUTOR");
        try {
            execution.recoverExpiredJobs();
            for (SecretJobProcessor processor : processors) {
                String provider = processor.provider() == null ? "ALL" : processor.provider();
                if (runningProviders.add(provider)) {
                    try {
                        providerExecutor.execute(() -> processBatch(processor, provider));
                    } catch (RejectedExecutionException rejected) {
                        runningProviders.remove(provider);
                        if (!stopped) throw rejected;
                    }
                }
            }
            if(heartbeat!=null)heartbeat.success("EXECUTOR");
        } catch (RuntimeException error) {
            if(heartbeat!=null)heartbeat.failure("EXECUTOR","EXECUTOR_POLL_FAILED");
            log.error("Secret job polling failed ({}); retry on next poll", error.getClass().getSimpleName());
        }
    }

    private void processBatch(SecretJobProcessor processor, String provider) {
        try {
            for (int i = 0; i < properties.batchSize() && !stopped; i++) {
                // Claim inside the provider's execution slot, immediately before processing.
                var job = execution.claimNextJob(processor.provider());
                if (job.isEmpty()) break;
                processOne(processor, job.get());
            }
            if (heartbeat != null) heartbeat.success("EXECUTOR");
        } catch (RuntimeException error) {
            if (heartbeat != null) heartbeat.failure("EXECUTOR", "EXECUTOR_POLL_FAILED");
            log.error("Secret provider polling failed ({}); retry on next poll",
                    error.getClass().getSimpleName());
        } finally {
            runningProviders.remove(provider);
        }
    }

    private void processOne(SecretJobProcessor processor, ClaimedSecretJob job) {
        if(heartbeat!=null)heartbeat.activeJob("EXECUTOR",job.jobId());
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
        } finally {
            if(heartbeat!=null)heartbeat.clearJob("EXECUTOR", job.jobId());
        }
    }

    @Override
    public void destroy() {
        stopped = true;
        providerExecutor.shutdown();
        try {
            if (!providerExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                providerExecutor.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            providerExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
