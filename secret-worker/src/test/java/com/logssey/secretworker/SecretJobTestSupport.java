package com.logssey.secretworker;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/** Test-only access to the package-private job repository. */
public final class SecretJobTestSupport {
    private SecretJobTestSupport() { }

    public static SecretJobExecutionService execution(JdbcTemplate jdbc, SecretJobProperties properties,
                                                      PlatformTransactionManager transactions) {
        return new SecretJobExecutionService(new SecretJobRepository(jdbc), properties, transactions);
    }
}
