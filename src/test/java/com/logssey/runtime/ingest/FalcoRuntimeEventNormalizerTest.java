package com.logssey.runtime.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

class FalcoRuntimeEventNormalizerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final FalcoRuntimeEventNormalizer normalizer = new FalcoRuntimeEventNormalizer();

    @Test
    void normalizesContainerShellExecution() throws Exception {
        JsonNode event = objectMapper.readTree("""
                {
                  "uuid": "falco-event-1",
                  "time": "2026-10-14T01:02:03Z",
                  "priority": "Warning",
                  "output_fields": {
                    "proc.name": "bash",
                    "proc.exepath": "/usr/bin/bash",
                    "proc.cmdline": "bash -c whoami",
                    "proc.pid": 121,
                    "proc.ppid": 87,
                    "proc.pexepath": "/usr/bin/containerd-shim-runc-v2",
                    "user.uid": "1000",
                    "container.id": "7fd32a",
                    "container.image.repository": "example/reused-api",
                    "container.image.tag": "demo",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p",
                    "k8s.pod.uid": "pod-uid-1",
                    "k8s.pod.container.name": "api",
                    "evt.hostname": "worker-a",
                    "k8s.sa.name": "reused-api"
                  }
                }
                """);

        NormalizedRuntimeEvent result = normalizer
                .normalize("logssey-prod", event, Instant.EPOCH)
                .orElseThrow();

        assertThat(result.ruleKey()).isEqualTo("RUN-001");
        assertThat(result.occurredAt()).isEqualTo(Instant.parse("2026-10-14T01:02:03Z"));
        assertThat(result.asset().workloadName()).isEqualTo("reused-api");
        assertThat(result.asset().nodeName()).isEqualTo("worker-a");
        assertThat(result.asset().resolvable()).isTrue();
        assertThat(result.process().arguments()).containsExactly("bash", "-c", "whoami");
        assertThat(result.normalizationStatus()).isEqualTo("COMPLETE");
    }

    @Test
    void ignoresHostAndNonShellEvents() throws Exception {
        JsonNode hostShell = objectMapper.readTree("""
                {"output_fields":{"proc.name":"bash","container.id":"host"}}
                """);
        JsonNode containerCurl = objectMapper.readTree("""
                {"output_fields":{"proc.name":"curl","container.id":"container-1"}}
                """);

        assertThat(normalizer.normalize("logssey-prod", hostShell, Instant.EPOCH)).isEmpty();
        assertThat(normalizer.normalize("logssey-prod", containerCurl, Instant.EPOCH)).isEmpty();
    }
}
