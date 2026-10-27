package com.logssey.runtime.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

class FalcoRuntimeEventNormalizerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RuntimeRulePack rulePack = new RuntimeRulePack();
    private final FalcoRuntimeEventNormalizer normalizer =
            new FalcoRuntimeEventNormalizer(new FalcoRuleRegistry(rulePack));

    @Test
    void normalizesContainerShellExecution() throws Exception {
        NormalizedRuntimeEvent result = normalized("""
                {
                  "rule": "Logssey RUN-001 Container Shell",
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

        assertThat(result.ruleKey()).isEqualTo("RUN-001");
        assertThat(result.occurredAt()).isEqualTo(Instant.parse("2026-10-14T01:02:03Z"));
        assertThat(result.asset().workloadName()).isEqualTo("reused-api");
        assertThat(result.asset().nodeName()).isEqualTo("worker-a");
        assertThat(result.asset().resolvable()).isTrue();
        assertThat(result.process().arguments()).containsExactly("bash", "-c", "whoami");
        assertThat(result.target()).isEqualTo(
                new NormalizedRuntimeEvent.TargetSnapshot("PROCESS", "/usr/bin/bash", "EXEC"));
        assertThat(result.normalizationStatus()).isEqualTo("COMPLETE");
    }

    @Test
    void normalizesServiceAccountTokenAccessWithoutTokenContents() throws Exception {
        NormalizedRuntimeEvent result = normalized(fileEvent(
                "Logssey RUN-003 ServiceAccount Token Access",
                "/var/run/secrets/kubernetes.io/serviceaccount/token"));

        assertThat(result.ruleKey()).isEqualTo("RUN-003");
        assertThat(result.eventType()).isEqualTo("FILE_ACCESS");
        assertThat(result.target()).isEqualTo(new NormalizedRuntimeEvent.TargetSnapshot(
                "FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token", "OPEN"));
    }

    @Test
    void normalizesPackageManagerExecution() throws Exception {
        NormalizedRuntimeEvent result = normalized("""
                {
                  "rule": "Logssey RUN-004 Package Manager Execution",
                  "output_fields": {
                    "proc.name": "apt-get",
                    "proc.exepath": "/usr/bin/apt-get",
                    "proc.cmdline": "apt-get install curl",
                    "container.id": "container-1",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p"
                  }
                }
                """);

        assertThat(result.ruleKey()).isEqualTo("RUN-004");
        assertThat(result.target()).isEqualTo(
                new NormalizedRuntimeEvent.TargetSnapshot("PROCESS", "/usr/bin/apt-get", "EXEC"));
    }

    @Test
    void normalizesSensitivePathWrite() throws Exception {
        NormalizedRuntimeEvent result = normalized(
                fileEvent("Logssey RUN-007 Sensitive Path Write", "/etc/cron.d/persistence"));

        assertThat(result.ruleKey()).isEqualTo("RUN-007");
        assertThat(result.eventType()).isEqualTo("FILE_WRITE");
        assertThat(result.target()).isEqualTo(
                new NormalizedRuntimeEvent.TargetSnapshot("FILE", "/etc/cron.d/persistence", "WRITE"));
    }

    @Test
    void separatesGeneralAndServiceProcessShells() throws Exception {
        NormalizedRuntimeEvent serviceShell = normalized("""
                {
                  "rule": "Logssey RUN-002 Service Process Shell",
                  "output_fields": {
                    "proc.name": "sh",
                    "proc.exepath": "/bin/sh",
                    "proc.pexepath": "/usr/bin/java",
                    "container.id": "container-1",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p"
                  }
                }
                """);
        RuntimeNormalizationResult incorrectlyClassified = normalize("""
                {
                  "rule": "Logssey RUN-001 Container Shell",
                  "output_fields": {
                    "proc.name": "sh",
                    "proc.exepath": "/bin/sh",
                    "proc.pexepath": "/usr/bin/java",
                    "container.id": "container-1"
                  }
                }
                """);

        assertThat(serviceShell.ruleKey()).isEqualTo("RUN-002");
        assertThat(serviceShell.ruleMode()).isEqualTo(RuntimeRuleDefinition.Mode.DETECT);
        assertThat(incorrectlyClassified.ignoredReason())
                .isEqualTo(FalcoRuntimeEventNormalizer.RULE_VALIDATION_FAILED);
    }

    @Test
    void normalizesObserveOnlyWritablePathExecution() throws Exception {
        NormalizedRuntimeEvent result = normalized("""
                {
                  "rule": "Logssey RUN-015 Writable Path Execution",
                  "output_fields": {
                    "proc.name": "payload",
                    "proc.exepath": "/dev/shm/payload",
                    "container.id": "container-1",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p"
                  }
                }
                """);

        assertThat(result.ruleKey()).isEqualTo("RUN-015");
        assertThat(result.ruleMode()).isEqualTo(RuntimeRuleDefinition.Mode.OBSERVE);
        assertThat(result.noiseBudgetPerMinute()).isEqualTo(100);
    }

    @Test
    void normalizesOfficialFalcoRuleAliases() throws Exception {
        NormalizedRuntimeEvent ptrace = normalized("""
                {
                  "rule": "PTRACE attached to process",
                  "output_fields": {
                    "proc.name": "gdb",
                    "proc.exepath": "/usr/bin/gdb",
                    "evt.arg.pid": "2481",
                    "container.id": "container-1",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p"
                  }
                }
                """);
        NormalizedRuntimeEvent logClear = normalized(
                fileEvent("Clear Log Activities", "/var/log/application.log"));

        assertThat(ptrace.ruleKey()).isEqualTo("RUN-006");
        assertThat(ptrace.target()).isEqualTo(
                new NormalizedRuntimeEvent.TargetSnapshot("PROCESS", "2481", "ACCESS"));
        assertThat(logClear.ruleKey()).isEqualTo("RUN-023");
        assertThat(logClear.target().operation()).isEqualTo("DELETE");
    }

    @Test
    void rejectsUnknownAndMissingSourceRulesWithExplicitReasons() throws Exception {
        RuntimeNormalizationResult missing = normalize("""
                {"output_fields":{"proc.name":"bash","container.id":"container-1"}}
                """);
        RuntimeNormalizationResult unknown = normalize("""
                {"rule":"Third-party rule","output_fields":{"proc.name":"bash","container.id":"container-1"}}
                """);

        assertThat(missing.ignoredReason()).isEqualTo(FalcoRuntimeEventNormalizer.MISSING_SOURCE_RULE);
        assertThat(unknown.ignoredReason()).isEqualTo(FalcoRuntimeEventNormalizer.UNSUPPORTED_SOURCE_RULE);
    }

    @Test
    void rejectsHostEventsAndRuleNameSpoofing() throws Exception {
        RuntimeNormalizationResult host = normalize("""
                {
                  "rule":"Logssey RUN-001 Container Shell",
                  "output_fields":{"proc.name":"bash","container.id":"host"}
                }
                """);
        RuntimeNormalizationResult spoofedPackageRule = normalize("""
                {
                  "rule":"Logssey RUN-004 Package Manager Execution",
                  "output_fields":{"proc.name":"curl","container.id":"container-1"}
                }
                """);
        RuntimeNormalizationResult spoofedFileRule = normalize(
                fileEvent("Logssey RUN-007 Sensitive Path Write", "/tmp/harmless"));

        assertThat(host.ignoredReason()).isEqualTo(FalcoRuntimeEventNormalizer.RULE_VALIDATION_FAILED);
        assertThat(spoofedPackageRule.ignoredReason()).isEqualTo(FalcoRuntimeEventNormalizer.RULE_VALIDATION_FAILED);
        assertThat(spoofedFileRule.ignoredReason()).isEqualTo(FalcoRuntimeEventNormalizer.RULE_VALIDATION_FAILED);
    }

    private NormalizedRuntimeEvent normalized(String json) throws Exception {
        return normalize(json).normalizedEvent().orElseThrow();
    }

    private RuntimeNormalizationResult normalize(String json) throws Exception {
        JsonNode event = objectMapper.readTree(json);
        return normalizer.normalize("logssey-prod", event, Instant.EPOCH);
    }

    private static String fileEvent(String rule, String path) {
        return """
                {
                  "rule": "%s",
                  "priority": "Warning",
                  "output_fields": {
                    "evt.type": "openat",
                    "fd.name": "%s",
                    "proc.name": "reused-api",
                    "proc.exepath": "/app/reused-api",
                    "proc.pid": 4242,
                    "user.uid": "1000",
                    "container.id": "container-1",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p"
                  }
                }
                """.formatted(rule, path);
    }
}
