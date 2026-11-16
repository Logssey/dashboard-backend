package com.logssey.complianceworker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(ComplianceWorkerProperties.class)
public class ComplianceWorkerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ComplianceWorkerApplication.class, args);
    }
}
