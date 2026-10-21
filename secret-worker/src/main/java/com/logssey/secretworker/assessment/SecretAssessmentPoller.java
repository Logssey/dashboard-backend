package com.logssey.secretworker.assessment;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.secret.executor.enabled", havingValue = "true")
public class SecretAssessmentPoller {
  private final SecretAssessmentExecutor executor;

  public SecretAssessmentPoller(SecretAssessmentExecutor executor) {
    this.executor = executor;
  }

  @Scheduled(fixedDelay = 30000)
  public void poll() {
    executor.queueExpired();
    for (int i = 0; i < 20; i++) {
      var job = executor.claim();
      if (job.isEmpty()) return;
      executor.execute(job.get());
    }
  }
}
