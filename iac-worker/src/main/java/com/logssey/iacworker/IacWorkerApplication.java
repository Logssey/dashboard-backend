package com.logssey.iacworker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(IacJobProperties.class)
public class IacWorkerApplication {

    public static void main(String[] args) {
        SpringApplication.run(IacWorkerApplication.class, args);
    }
}
