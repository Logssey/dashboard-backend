package com.logssey.iacworker;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/** Test-only access to the package-private job repository. */
public final class IacJobTestSupport {
    private IacJobTestSupport() { }

    public static IacJobExecutionService execution(JdbcTemplate jdbc, IacJobProperties properties,
                                                   PlatformTransactionManager transactions) {
        return new IacJobExecutionService(new IacJobRepository(jdbc), properties, transactions);
    }
}
