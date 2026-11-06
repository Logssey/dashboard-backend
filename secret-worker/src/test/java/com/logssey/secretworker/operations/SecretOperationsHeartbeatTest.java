package com.logssey.secretworker.operations;
import java.time.*;
import java.util.List;
import com.logssey.secret.operations.SecretOperationsHealth;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.assertThat;

class SecretOperationsHeartbeatTest {
    static final com.logssey.secret.testing.SecretTestPostgres PG=new com.logssey.secret.testing.SecretTestPostgres();
    static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
    @BeforeAll static void start(){PG.start();var ds=new DriverManagerDataSource(PG.getJdbcUrl(),PG.getUsername(),PG.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);}
    @AfterAll static void stop(){PG.stop();}
    @BeforeEach void clear(){jdbc.execute("TRUNCATE secret_worker_heartbeats,secret_operations_alerts CASCADE");}
    SecretOperationsHeartbeat heartbeat(MockEnvironment env){return new SecretOperationsHeartbeat(jdbc,tm,env,false,"heartbeat-fixture",Duration.ofSeconds(30),false,Duration.ofMinutes(15),Duration.ofMinutes(2),Duration.ofMinutes(2),1);}
    @Test void firstIdleDisabledTickPersistsStableProcessStartWithoutInventingPollSuccess(){
        var heartbeat=heartbeat(new MockEnvironment());heartbeat.tick();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_worker_heartbeats WHERE started_at IS NOT NULL AND last_poll_started_at IS NULL AND last_success_at IS NULL AND NOT enabled",Long.class)).isEqualTo(5);
        var started=jdbc.queryForObject("SELECT min(started_at) FROM secret_worker_heartbeats",OffsetDateTime.class);heartbeat.tick();
        assertThat(jdbc.queryForObject("SELECT min(started_at) FROM secret_worker_heartbeats",OffsetDateTime.class)).isEqualTo(started);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_operations_alerts",Long.class)).isZero();
    }
    @Test void configuredSlowPollingIntervalIsRecordedAndProcessHeartbeatIsIndependent(){
        var env=new MockEnvironment().withProperty("logssey.secret.scheduler.enabled","true").withProperty("logssey.secret.scheduler.poll-delay","10m");
        var heartbeat=heartbeat(env);heartbeat.begin("SCHEDULER");heartbeat.success("SCHEDULER");heartbeat.tick();
        assertThat(jdbc.queryForObject("SELECT poll_interval_ms FROM secret_worker_heartbeats WHERE component='SCHEDULER'",Long.class)).isEqualTo(600000);
        assertThat(jdbc.queryForObject("SELECT last_success_at IS NOT NULL FROM secret_worker_heartbeats WHERE component='SCHEDULER'",Boolean.class)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "logssey.secret.github.enabled",
        "logssey.secret.aws.collection.enabled",
        "logssey.secret.notion.collection.enabled"
    })
    void eachConfiguredCollectionPipelineReportsAHealthyExecutorAfterPolling(String sourceProperty) {
        var env = new MockEnvironment()
                .withProperty("logssey.secret.executor.enabled", "true")
                .withProperty("logssey.secret.github.enabled", "false")
                .withProperty("logssey.secret.aws.collection.enabled", "false")
                .withProperty("logssey.secret.notion.collection.enabled", "false")
                .withProperty(sourceProperty, "true");
        var heartbeat = heartbeat(env);
        heartbeat.begin("EXECUTOR");
        heartbeat.success("EXECUTOR");
        heartbeat.tick();

        var row = jdbc.queryForMap("SELECT * FROM secret_worker_heartbeats WHERE component='EXECUTOR'");
        assertThat(row).containsEntry("enabled", true);
        assertThat(row.get("last_poll_started_at")).isNotNull();
        assertThat(row.get("last_success_at")).isNotNull();
        assertThat(SecretOperationsHealth.component("EXECUTOR", List.of(row),
                OffsetDateTime.now(ZoneOffset.UTC), 1, Duration.ofMinutes(2)))
                .containsEntry("status", "HEALTHY").containsEntry("liveInstances", 1);
    }

    @Test
    void aConfiguredNotionSourceDoesNotEnableADisabledExecutor() {
        var env = new MockEnvironment()
                .withProperty("logssey.secret.executor.enabled", "false")
                .withProperty("logssey.secret.notion.collection.enabled", "true");
        heartbeat(env).tick();

        assertThat(jdbc.queryForObject(
                "SELECT enabled FROM secret_worker_heartbeats WHERE component='EXECUTOR'", Boolean.class))
                .isFalse();
    }

    @Test
    void anEnabledExecutorWithoutACollectionSourceStaysDisabled() {
        var env = new MockEnvironment().withProperty("logssey.secret.executor.enabled", "true");
        heartbeat(env).tick();

        assertThat(jdbc.queryForObject(
                "SELECT enabled FROM secret_worker_heartbeats WHERE component='EXECUTOR'", Boolean.class))
                .isFalse();
    }
}
