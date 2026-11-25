package com.logssey.complianceworker;

import static com.logssey.complianceworker.WorkerDtos.ClaimedJob;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ProwlerExecutionService {

    private static final Logger log = LoggerFactory.getLogger(ProwlerExecutionService.class);

    private final ComplianceWorkerProperties properties;
    private final ComplianceWorkerApiClient api;
    private final AwsTargetIdentityService identities;

    public ProwlerExecutionService(ComplianceWorkerProperties properties, ComplianceWorkerApiClient api,
                                   AwsTargetIdentityService identities) {
        this.properties = properties;
        this.api = api;
        this.identities = identities;
    }

    void execute(ClaimedJob job) {
        Path work = null;
        try {
            var identity = identities.verify(job);
            if (!job.target().awsAccountId().equals(identity.accountId())) {
                api.fail(job, "TARGET_ACCOUNT_MISMATCH", false);
                return;
            }
            if ("CONNECTION_TEST".equals(job.jobKind())) {
                api.completeConnection(job, identity);
                return;
            }
            if (!"ASSESSMENT".equals(job.jobKind())) {
                api.fail(job, "UNSUPPORTED_JOB_KIND", false);
                return;
            }
            work = Files.createTempDirectory("logssey-compliance-" + job.jobId() + "-");
            Process process = new ProcessBuilder(ProwlerCommand.build(properties.prowlerExecutable(), job, work))
                    .redirectOutput(work.resolve("prowler.stdout.log").toFile())
                    .redirectError(work.resolve("prowler.stderr.log").toFile())
                    .start();
            var leaseLost = new AtomicBoolean(false);
            try (var heartbeats = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "compliance-heartbeat-" + job.jobId());
                thread.setDaemon(true);
                return thread;
            })) {
                long delay = Math.max(10, properties.heartbeatDelay().toSeconds());
                heartbeats.scheduleWithFixedDelay(() -> heartbeat(job, process, leaseLost), delay, delay,
                        TimeUnit.SECONDS);
                boolean finished = process.waitFor(properties.scanTimeout().toMillis(), TimeUnit.MILLISECONDS);
                if (!finished) {
                    process.destroyForcibly();
                    api.fail(job, "PROWLER_TIMEOUT", true);
                    return;
                }
            }
            if (leaseLost.get()) return;
            if (process.exitValue() != 0) {
                api.fail(job, "PROWLER_EXIT_FAILURE", true);
                return;
            }
            Path result = findResult(work);
            api.submit(job, result);
        } catch (AwsTargetIdentityService.TargetIdentityException e) {
            bestEffortFailure(job, e.code(), e.retryable());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            bestEffortFailure(job, "WORKER_INTERRUPTED", true);
        } catch (IOException | RuntimeException e) {
            log.error("Compliance job {} failed ({}); details are not returned to the API",
                    job.jobId(), e.getClass().getSimpleName());
            bestEffortFailure(job, "WORKER_EXECUTION_FAILURE", true);
        } finally {
            deleteTemporaryDirectory(work);
        }
    }

    private void heartbeat(ClaimedJob job, Process process, AtomicBoolean leaseLost) {
        try {
            if (!api.heartbeat(job)) {
                leaseLost.set(true);
                process.destroyForcibly();
            }
        } catch (IOException e) {
            log.warn("Compliance job {} heartbeat failed; the next heartbeat will retry", job.jobId());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Path findResult(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            var matches = files.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".ocsf.json"))
                    .toList();
            if (matches.size() != 1) throw new IOException("Expected exactly one Prowler OCSF result");
            return matches.getFirst();
        }
    }

    private void bestEffortFailure(ClaimedJob job, String code, boolean retryable) {
        try {
            api.fail(job, code, retryable);
        } catch (IOException | InterruptedException ignored) {
            if (ignored instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    private static void deleteTemporaryDirectory(Path directory) {
        if (directory == null) return;
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException ignored) {
            // The OS temp cleaner is the final fallback. Never expose output contents in logs.
        }
    }
}
