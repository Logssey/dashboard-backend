package com.logssey.secret.operations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Independent from the worker: a dead worker cannot raise its own stale alert. */
@Component
@ConditionalOnProperty(name="logssey.secret.operations.monitor-enabled",havingValue="true",matchIfMissing=true)
public class SecretOperationsApiMonitor {
    private static final Logger LOG=LoggerFactory.getLogger(SecretOperationsApiMonitor.class);
    private final SecretOperationsService service;
    public SecretOperationsApiMonitor(SecretOperationsService service){this.service=service;}
    @Scheduled(fixedDelayString="${logssey.secret.operations.monitor-interval:30s}")
    public void poll(){
        try{service.monitor();}
        catch(RuntimeException failure){LOG.error("Secret operations monitor unavailable ({})",failure.getClass().getSimpleName());}
    }
}
