package com.logssey.secretworker.usage;
import com.logssey.secretworker.operations.SecretOperationsHeartbeat;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
@Component
@ConditionalOnProperty(name="logssey.secret.usage.cloudtrail-enabled",havingValue="true")
public class UsageObservationPoller {
    private final UsageObservationExecutor executor;private final UsageObservationScheduler scheduler;private final SecretOperationsHeartbeat heartbeat;
    public UsageObservationPoller(UsageObservationExecutor executor,UsageObservationScheduler scheduler,SecretOperationsHeartbeat heartbeat){this.executor=executor;this.scheduler=scheduler;this.heartbeat=heartbeat;}
    @Scheduled(fixedDelayString="${logssey.secret.usage.poll-delay:30s}")
    public void poll(){heartbeat.begin("USAGE");try{scheduler.reserveDue();for(int i=0;i<10;i++){var lease=executor.claim();if(lease.isEmpty())break;heartbeat.begin("USAGE");heartbeat.activeJob("USAGE",lease.get().jobId());if(!executor.execute(lease.get())){heartbeat.failure("USAGE","USAGE_JOB_INCOMPLETE");return;}heartbeat.success("USAGE");}heartbeat.success("USAGE");}catch(RuntimeException unavailable){heartbeat.failure("USAGE","USAGE_POLL_FAILED");}}
}
