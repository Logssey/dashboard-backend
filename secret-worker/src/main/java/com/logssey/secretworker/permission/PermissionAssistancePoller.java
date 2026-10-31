package com.logssey.secretworker.permission;
import com.logssey.secretworker.operations.SecretOperationsHeartbeat;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
@Component
@ConditionalOnProperty(name="logssey.secret.permissions.enabled",havingValue="true")
public class PermissionAssistancePoller {
    private final PermissionAssistanceExecutor executor;private final SecretOperationsHeartbeat heartbeat;
    public PermissionAssistancePoller(PermissionAssistanceExecutor executor,SecretOperationsHeartbeat heartbeat){this.executor=executor;this.heartbeat=heartbeat;}
    @Scheduled(fixedDelayString="${logssey.secret.permissions.poll-delay:30s}")
    public void poll(){heartbeat.begin("PERMISSIONS");try{for(int i=0;i<10;i++){var job=executor.claim();if(job.isEmpty())break;heartbeat.begin("PERMISSIONS");heartbeat.activeJob("PERMISSIONS",job.get().jobId());if(!executor.execute(job.get())){heartbeat.failure("PERMISSIONS","PERMISSION_JOB_INCOMPLETE");return;}heartbeat.success("PERMISSIONS");}heartbeat.success("PERMISSIONS");}catch(RuntimeException error){heartbeat.failure("PERMISSIONS","PERMISSION_POLL_FAILED");}}
}
