package com.logssey.secretworker.operations;

import com.logssey.secret.operations.SecretOperationsStore;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;

/** Independent heartbeat thread: a blocked scheduler pool cannot pretend to have progressed. */
@Component
public class SecretOperationsHeartbeat implements InitializingBean, DisposableBean {
    private static final Logger LOG=LoggerFactory.getLogger(SecretOperationsHeartbeat.class);
    private final UUID instance=UUID.randomUUID();
    private final String deployment;
    private final boolean enabled,cleanupEnabled;
    private final Duration interval,cleanupInterval;
    private final SecretOperationsStore store;
    private final Map<String,State> states=new ConcurrentHashMap<>();
    private ScheduledExecutorService thread;
    private Instant lastCleanup=Instant.EPOCH;
    public SecretOperationsHeartbeat(JdbcTemplate jdbc,PlatformTransactionManager manager,Environment env,
            @Value("${logssey.secret.operations.enabled:true}") boolean enabled,
            @Value("${logssey.secret.operations.deployment-key:secret-worker}") String deployment,
            @Value("${logssey.secret.operations.heartbeat-interval:30s}") Duration interval,
            @Value("${logssey.secret.operations.snapshot-cleanup.enabled:true}") boolean cleanupEnabled,
            @Value("${logssey.secret.operations.snapshot-cleanup.interval:15m}") Duration cleanupInterval,
            @Value("${logssey.secret.operations.heartbeat-grace:2m}") Duration grace,
            @Value("${logssey.secret.operations.queue-grace:2m}") Duration queueGrace,
            @Value("${logssey.secret.operations.expected-instances:1}") int expected){
        if(deployment==null||!deployment.matches("[A-Za-z0-9._-]{1,100}"))throw new IllegalArgumentException("OPERATIONS_DEPLOYMENT_KEY_INVALID");
        if(interval.toMillis()<1000||cleanupInterval.toMillis()<1000)throw new IllegalArgumentException("OPERATIONS_INTERVAL_INVALID");
        this.store=new SecretOperationsStore(jdbc,manager,grace,queueGrace,expected,deployment);this.enabled=enabled;this.deployment=deployment;
        this.interval=interval;this.cleanupEnabled=cleanupEnabled;this.cleanupInterval=cleanupInterval;
        boolean executor=env.getProperty("logssey.secret.executor.enabled",Boolean.class,false);
        boolean sources=env.getProperty("logssey.secret.github.enabled",Boolean.class,false)
            ||env.getProperty("logssey.secret.aws.collection.enabled",Boolean.class,false)
            ||env.getProperty("logssey.secret.notion.collection.enabled",Boolean.class,false);
        register("SCHEDULER",env.getProperty("logssey.secret.scheduler.enabled",Boolean.class,false),pollMs(env,"logssey.secret.scheduler.poll-delay"));
        register("EXECUTOR",executor&&sources,pollMs(env,"logssey.secret.executor.poll-delay"));
        register("ASSESSMENT",executor,30_000);
        register("PERMISSIONS",env.getProperty("logssey.secret.permissions.enabled",Boolean.class,false),pollMs(env,"logssey.secret.permissions.poll-delay"));
        register("MAINTENANCE",cleanupEnabled,cleanupInterval.toMillis());
    }
    private void register(String component,boolean on,long pollMs){states.put(component,new State(on,pollMs));}
    private static long pollMs(Environment env,String key){return org.springframework.boot.convert.DurationStyle.detectAndParse(env.getProperty(key,"30s")).toMillis();}
    public void begin(String component){State s=state(component);synchronized(s){s.state="RUNNING";s.pollStarted=now();s.error=null;}}
    public void success(String component){State s=state(component);synchronized(s){s.state="IDLE";s.finished=now();s.success=s.finished;s.job=null;s.error=null;}}
    public void failure(String component,String safeCode){State s=state(component);synchronized(s){s.state="FAILED";s.finished=now();s.job=null;s.error=safeCode;}}
    public void activeJob(String component,long id){State s=state(component);synchronized(s){s.job=id;}}
    public void clearJob(String component){State s=state(component);synchronized(s){s.job=null;}}
    private State state(String component){var s=states.get(component);if(s==null)throw new IllegalArgumentException("OPERATIONS_COMPONENT_INVALID");return s;}
    private static OffsetDateTime now(){return OffsetDateTime.now(ZoneOffset.UTC);}
    @Override public void afterPropertiesSet(){if(!enabled)return;thread=Executors.newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon(true).name("secret-operations-heartbeat").factory());thread.scheduleWithFixedDelay(this::tick,0,interval.toMillis(),TimeUnit.MILLISECONDS);}
    void tick(){
        try{
            for(var e:states.entrySet()){State s=e.getValue();synchronized(s){store.heartbeat(new SecretOperationsStore.Beat(instance,deployment,e.getKey(),s.enabled,s.state,s.interval,s.pollStarted,s.finished,s.success,s.job,s.error));}}
            store.monitor();
            if(cleanupEnabled&&lastCleanup.plus(cleanupInterval).isBefore(Instant.now())){
                begin("MAINTENANCE");store.cleanupExpiredSnapshots(500);success("MAINTENANCE");lastCleanup=Instant.now();
            }
        }catch(RuntimeException failure){LOG.error("Secret operations persistence unavailable ({})",failure.getClass().getSimpleName());}
    }
    @Override public void destroy(){if(thread!=null)thread.shutdownNow();}
    private static final class State{
        final boolean enabled;final long interval;String state="IDLE",error;OffsetDateTime pollStarted,finished,success;Long job;
        State(boolean enabled,long interval){this.enabled=enabled;this.interval=interval;}
    }
}
