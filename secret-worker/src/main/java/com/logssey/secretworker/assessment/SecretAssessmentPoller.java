package com.logssey.secretworker.assessment;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "logssey.secret.assessment.enabled", havingValue = "true", matchIfMissing = true)
public class SecretAssessmentPoller {
  private final SecretAssessmentExecutor executor;
  private final com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat;

  public SecretAssessmentPoller(SecretAssessmentExecutor executor,com.logssey.secretworker.operations.SecretOperationsHeartbeat heartbeat) {
    this.executor = executor;
    this.heartbeat=heartbeat;
  }

  @Scheduled(fixedDelay = 30000)
  public void poll() {
    heartbeat.begin("ASSESSMENT");
    try{
      executor.queueExpired();
      for (int i = 0; i < 20; i++) {
        var job = executor.claim();
        if (job.isEmpty()) break;
        heartbeat.activeJob("ASSESSMENT",job.get().jobId());
        if (!executor.execute(job.get())) {
          heartbeat.failure("ASSESSMENT", "ASSESSMENT_JOB_INCOMPLETE");
          return;
        }
        heartbeat.clearJob("ASSESSMENT");
      }
      heartbeat.success("ASSESSMENT");
    }catch(RuntimeException failure){
      heartbeat.failure("ASSESSMENT","ASSESSMENT_POLL_FAILED");
    }
  }
}
