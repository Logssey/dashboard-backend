package com.logssey.secretworker.operations;
import java.time.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
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
}
