package com.logssey.runtime.operations;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class RuntimeMaintenanceJob {

    private final RuntimeOperationsService service;

    public RuntimeMaintenanceJob(RuntimeOperationsService service) {
        this.service = service;
    }

    @Scheduled(cron = "${logssey.runtime.maintenance-cron:0 15 3 * * *}", zone = "UTC")
    public void run() {
        service.runScheduled();
    }
}
