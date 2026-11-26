package com.logssey.secretworker.assessment;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import com.logssey.secretworker.operations.SecretOperationsHeartbeat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class SecretAssessmentPollerTest {
  final SecretAssessmentExecutor executor = mock(SecretAssessmentExecutor.class);
  final SecretOperationsHeartbeat heartbeat = mock(SecretOperationsHeartbeat.class);
  final ApplicationContextRunner runner = new ApplicationContextRunner()
      .withBean(SecretAssessmentExecutor.class, () -> executor)
      .withBean(SecretOperationsHeartbeat.class, () -> heartbeat)
      .withUserConfiguration(SecretAssessmentPoller.class);

  @Test void databaseAssessmentRunsWhileExternalCollectionIsDisabled() {
    runner.withPropertyValues("logssey.secret.executor.enabled=false").run(context -> {
      assertThat(context).hasSingleBean(SecretAssessmentPoller.class);
      var lease = new SecretAssessmentExecutor.Lease(1, 2, 3, 4, UUID.randomUUID(), 1);
      when(executor.claim()).thenReturn(Optional.of(lease), Optional.empty());
      when(executor.execute(lease)).thenReturn(true);
      context.getBean(SecretAssessmentPoller.class).poll();
      verify(executor).execute(lease);
      verify(heartbeat).success("ASSESSMENT");
    });
  }

  @Test void assessmentCanBeExplicitlyDisabledWithoutDisablingCollection() {
    runner.withPropertyValues("logssey.secret.executor.enabled=true", "logssey.secret.assessment.enabled=false")
        .run(context -> assertThat(context).doesNotHaveBean(SecretAssessmentPoller.class));
  }

  @Test void failedJobCannotReportSuccessfulAssessmentHeartbeat() {
    var lease = new SecretAssessmentExecutor.Lease(1, 2, 3, 4, UUID.randomUUID(), 1);
    when(executor.claim()).thenReturn(Optional.of(lease));
    when(executor.execute(lease)).thenReturn(false);
    new SecretAssessmentPoller(executor, heartbeat).poll();
    verify(heartbeat).failure("ASSESSMENT", "ASSESSMENT_JOB_INCOMPLETE");
    verify(heartbeat, never()).success("ASSESSMENT");
  }
}
