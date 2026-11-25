package com.logssey.secretworker;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class SecretJobPollerTest {
    @Test
    void slowGitHubJobDoesNotBlockAwsOrAllowAnotherGitHubBatch() throws Exception {
        var execution = mock(SecretJobExecutionService.class);
        var github = new ClaimedSecretJob(1, 1, 1, 1, "github-lease", OffsetDateTime.now().plusMinutes(5));
        var aws = new ClaimedSecretJob(2, 2, 2, 1, "aws-lease", OffsetDateTime.now().plusMinutes(5));
        when(execution.claimNextJob("GITHUB")).thenReturn(Optional.of(github), Optional.empty());
        when(execution.claimNextJob("AWS")).thenReturn(Optional.of(aws), Optional.empty());
        when(execution.complete(anyLong(), anyString())).thenReturn(true);
        var githubStarted = new CountDownLatch(1);
        var releaseGithub = new CountDownLatch(1);
        var awsProcessed = new CountDownLatch(1);
        var factory = new StaticListableBeanFactory();
        factory.addBean("github", processor("GITHUB", (job, service) -> {
            githubStarted.countDown();
            try {
                if (!releaseGithub.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Fixture timed out");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Fixture interrupted");
            }
        }));
        factory.addBean("aws", processor("AWS", (job, service) -> awsProcessed.countDown()));
        var properties = new SecretJobProperties(true, Duration.ofSeconds(30), Duration.ofMinutes(5),
                10, Duration.ofSeconds(1), Duration.ofMinutes(1));
        var poller = new SecretJobPoller(execution, properties,
                factory.getBeanProvider(SecretJobProcessor.class));
        try {
            poller.poll();
            assertThat(githubStarted.await(2, TimeUnit.SECONDS)).isTrue();
            poller.poll();
            assertThat(awsProcessed.await(2, TimeUnit.SECONDS)).isTrue();
            verify(execution, times(1)).claimNextJob("GITHUB");
            verify(execution, never()).complete(github.jobId(), github.leaseToken());
        } finally {
            releaseGithub.countDown();
            poller.destroy();
        }
        verify(execution).complete(aws.jobId(), aws.leaseToken());
        verify(execution).complete(github.jobId(), github.leaseToken());
    }

    private SecretJobProcessor processor(String provider,
            BiConsumer<ClaimedSecretJob, SecretJobExecutionService> action) {
        return new SecretJobProcessor() {
            @Override public String provider() { return provider; }
            @Override public void process(ClaimedSecretJob job, SecretJobExecutionService execution) {
                action.accept(job, execution);
            }
        };
    }
}
