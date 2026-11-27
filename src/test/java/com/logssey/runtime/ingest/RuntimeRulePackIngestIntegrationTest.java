package com.logssey.runtime.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import com.logssey.runtime.ingest.dto.FalcoEventEnvelope;
import com.logssey.runtime.operations.RuntimeOperationsRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

class RuntimeRulePackIngestIntegrationTest {

    private static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:16");
    private static JdbcTemplate jdbc;
    private static RuntimeIngestService service;
    private static RuntimeOperationsRepository operationsRepository;

    @BeforeAll
    static void startDatabase() {
        DB.start();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                DB.getJdbcUrl(), DB.getUsername(), DB.getPassword());
        Flyway.configure().dataSource(dataSource).load().migrate();
        jdbc = new JdbcTemplate(dataSource);

        RuntimeRulePack rulePack = new RuntimeRulePack();
        RuntimeIngestRepository repository = new RuntimeIngestRepository(JdbcClient.create(dataSource));
        operationsRepository = new RuntimeOperationsRepository(JdbcClient.create(dataSource));
        service = new RuntimeIngestService(
                new RuntimePayloadMasker(),
                new FalcoRuntimeEventNormalizer(new FalcoRuleRegistry(rulePack)),
                repository,
                JsonMapper.builder().build(),
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)),
                262_144,
                300,
                java.time.Duration.ofDays(30));
    }

    @AfterAll
    static void stopDatabase() {
        DB.stop();
    }

    @Test
    void detectCreatesFindingWhileObserveKeepsEvidenceOnly() throws Exception {
        var mapper = JsonMapper.builder().build();
        var detected = service.ingestFalco(new FalcoEventEnvelope(
                "logssey-prod", null, "falco-json-0.1", mapper.readTree(event(
                        "detect-1", "Logssey RUN-002 Service Process Shell", "/bin/sh", "sh", "/usr/bin/java"))), null);
        var observed = service.ingestFalco(new FalcoEventEnvelope(
                "logssey-prod", null, "falco-json-0.1", mapper.readTree(event(
                        "observe-1", "Logssey RUN-015 Writable Path Execution",
                        "/dev/shm/payload", "payload", "/bin/sh"))), null);

        assertThat(detected.processingStatus()).isEqualTo("GROUPED");
        assertThat(detected.findingId()).isNotNull();
        assertThat(observed.processingStatus()).isEqualTo("OBSERVED");
        assertThat(observed.findingId()).isNull();
        assertThat(jdbc.queryForObject("""
                SELECT count(*)
                FROM runtime_events e
                JOIN runtime_raw_events r ON r.raw_event_id = e.raw_event_id
                WHERE r.cluster_id = 'logssey-prod'
                """, Long.class)).isEqualTo(2L);
        assertThat(jdbc.queryForObject("""
                SELECT count(DISTINCT fe.finding_id)
                FROM runtime_finding_events fe
                JOIN runtime_events e ON e.runtime_event_id = fe.runtime_event_id
                JOIN runtime_raw_events r ON r.raw_event_id = e.raw_event_id
                WHERE r.cluster_id = 'logssey-prod'
                """, Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForList(
                """
                SELECT e.rule_mode
                FROM runtime_events e
                JOIN runtime_raw_events r ON r.raw_event_id = e.raw_event_id
                WHERE r.cluster_id = 'logssey-prod'
                ORDER BY e.runtime_event_id
                """, String.class))
                .containsExactly("DETECT", "OBSERVE");
    }

    @Test
    void rateLimitedEventsAreAggregatedWithoutRawPayloadRows() throws Exception {
        var mapper = JsonMapper.builder().build();
        com.logssey.runtime.ingest.dto.RuntimeIngestResponse last = null;
        for (int index = 0; index < 21; index++) {
            last = service.ingestFalco(new FalcoEventEnvelope(
                    "rate-limit-cluster", null, "falco-json-0.1", mapper.readTree(event(
                    "rate-limit-" + index, "Logssey RUN-002 Service Process Shell",
                    "/bin/sh", "sh", "/usr/bin/java").replace(
                    "\"evt.hostname\": \"worker-a\"", "\"evt.hostname\": \"worker-rate\""))), null);
        }

        assertThat(last).isNotNull();
        assertThat(last.processingStatus()).isEqualTo("RATE_LIMITED");
        assertThat(last.rawEventId()).isNull();
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM runtime_raw_events WHERE cluster_id = 'rate-limit-cluster'", Long.class))
                .isEqualTo(20L);
        assertThat(jdbc.queryForObject(
                "SELECT rate_limited_count FROM runtime_ingest_rate_windows "
                        + "WHERE cluster_id = 'rate-limit-cluster' AND node_name = 'worker-rate' "
                        + "AND rule_key = 'RUN-002'", Long.class))
                .isEqualTo(1L);
        var counts = operationsRepository.countsSince(Instant.now().minusSeconds(60));
        assertThat(counts.rateLimited()).isGreaterThanOrEqualTo(1L);
        assertThat(counts.received()).isGreaterThanOrEqualTo(21L);
    }

    private static String event(String id, String rule, String executable,
                                String processName, String parentExecutable) {
        return """
                {
                  "uuid": "%s",
                  "time": "2026-10-27T10:00:00Z",
                  "priority": "Warning",
                  "rule": "%s",
                  "output_fields": {
                    "proc.name": "%s",
                    "proc.exepath": "%s",
                    "proc.pexepath": "%s",
                    "proc.cmdline": "%s -c id",
                    "proc.pid": 100,
                    "proc.ppid": 10,
                    "user.uid": "1000",
                    "container.id": "container-1",
                    "container.name": "api",
                    "container.image.repository": "logssey/reused-api",
                    "container.image.tag": "demo",
                    "k8s.ns.name": "reused",
                    "k8s.pod.name": "reused-api-7d9df64b9f-k2j9p",
                    "k8s.pod.uid": "pod-1",
                    "evt.hostname": "worker-a"
                  }
                }
                """.formatted(id, rule, processName, executable, parentExecutable, processName);
    }
}
