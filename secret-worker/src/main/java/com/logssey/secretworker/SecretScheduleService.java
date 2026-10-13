package com.logssey.secretworker;

import java.util.Objects;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class SecretScheduleService {

    private final SecretScheduleRepository repository;
    private final SecretSchedulerProperties properties;
    private final TransactionTemplate transaction;

    public SecretScheduleService(SecretScheduleRepository repository, SecretSchedulerProperties properties,
                                 PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.properties = properties;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public int reserveDueJobs() {
        if (!properties.enabled()) {
            return 0;
        }
        return Objects.requireNonNull(transaction.execute(status -> {
            var now = repository.databaseNow();
            var connections = repository.lockDueConnections(now, properties.batchSize());
            for (var connection : connections) {
                repository.reserve(connection, now, properties);
            }
            return connections.size();
        }));
    }
}
