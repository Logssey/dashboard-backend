package com.logssey.reach.app;

import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.ReachTestProperties;
import com.logssey.reach.app.dto.ReachAppListResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachAppServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();   // 버전 번호를 적지 않는다
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE reach_targets, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
    }

    @Test
    void listsConfiguredAppsInConfigurationOrder() {
        var items = service(ReachTestProperties.REUSED).apps("admin").items();
        assertThat(items).extracting(ReachAppListResponse.Item::code).containsExactly("API", "WEB", "CHAT");
        assertThat(items.get(2)).isEqualTo(
                new ReachAppListResponse.Item("CHAT", "service-backend", "chat-server", "logssey/reused-chat"));
        assertThat(service(new ReachProperties(null, null)).apps("admin").items()).isEmpty();
    }

    @Test
    void requiresAdmin() {
        var service = service(ReachTestProperties.REUSED);
        assertError(() -> service.apps(null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.apps("nobody"), ErrorCode.FORBIDDEN);
    }

    /** V47: 앱 코드는 형식만 DB가 본다. Re:Used 세 앱이 아니어도 들어가고, 형식이 틀리면 거절한다 */
    @Test
    void databaseAcceptsAnyWellFormedAppCode() {
        for (String app : List.of("API", "ORDER", "BATCH_2", "A")) {
            insertTarget(app);
        }
        for (String app : List.of("order", "1API", "ORDER-API", "")) {
            assertThatThrownBy(() -> insertTarget(app)).isInstanceOf(DataIntegrityViolationException.class);
        }
    }

    private static void insertTarget(String app) {
        jdbc.update("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', ?, 'org/' || ?, 'sha256:' || md5(?) || md5(?), 'x')
                """, app, app, app, app + "2");
    }

    private static ReachAppService service(ReachProperties properties) {
        return new ReachAppService(properties, new ReachAppRepository(JdbcClient.create(jdbc)));
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }
}
