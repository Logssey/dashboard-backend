package com.logssey.secretworker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({SecretSchedulerProperties.class, SecretJobProperties.class})
public class SecretWorkerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecretWorkerApplication.class, args);
    }
}
