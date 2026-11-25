package com.logssey.complianceworker;

import java.net.URI;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("logssey.compliance-worker")
public record ComplianceWorkerProperties(boolean enabled, URI apiBaseUrl, String token, String workerId,
                                         Duration pollDelay, Duration heartbeatDelay, Duration scanTimeout,
                                         String prowlerExecutable, String awsRegion, String stsEndpoint) {
}
