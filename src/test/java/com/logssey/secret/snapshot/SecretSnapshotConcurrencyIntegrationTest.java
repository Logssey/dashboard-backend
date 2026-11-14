package com.logssey.secret.snapshot;

import static org.assertj.core.api.Assertions.*;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.query.SecretLocationRepository;
import com.logssey.secret.query.SecretReadConflict;
import com.logssey.secret.query.SecretReadConflictAdvice;
import com.logssey.secret.query.SecretWorkbenchService;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.testing.SecretTestPostgres;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

class SecretSnapshotConcurrencyIntegrationTest {
    static final SecretTestPostgres DB = new SecretTestPostgres();
    static JdbcTemplate jdbc;
    static DataSourceTransactionManager manager;
    long user;
    SecretReadSnapshots snapshots;
    final SecretWorkbenchService.Filters all = new SecretWorkbenchService.Filters("ALL","ALL","ALL","ALL",null,null);

    @BeforeAll static void database() {
        DB.start();
        var ds = new DriverManagerDataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        jdbc = new JdbcTemplate(ds);
        manager = new DataSourceTransactionManager(ds);
    }
    @AfterAll static void stop() { DB.stop(); }
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        user = jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('reader','hash','reader','ADMIN') RETURNING user_id", Long.class);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(?,'SECURITY',?,'MANUAL')", user,user);
        jdbc.update("INSERT INTO secret_snapshot_owner_locks(user_id,epoch) VALUES (?,0)", user);
        snapshots = new SecretReadSnapshots(jdbc,JsonMapper.builder().build(),manager);
    }

    @Test void concurrentSummaryRequestsRestartWholeReadsAndNeverExceedFiveSnapshots() throws Exception {
        var initial = service(new SecretAccessService(jdbc));
        for (int i=0;i<5;i++) initial.summary("reader",all,null);
        var barrier = new CyclicBarrier(2);
        var first = ThreadLocal.withInitial(() -> true);
        var transactions = ConcurrentHashMap.<Long>newKeySet();
        var access = new SecretAccessService(jdbc) {
            @Override public SecretPrincipal requirePrincipal(String login) {
                var actor = super.requirePrincipal(login);
                transactions.add(jdbc.queryForObject("SELECT txid_current()",Long.class));
                assertThat(jdbc.queryForObject("SHOW transaction_isolation",String.class)).isEqualTo("repeatable read");
                if (first.get()) {
                    first.set(false);
                    try { barrier.await(15,TimeUnit.SECONDS); }
                    catch (Exception e) { throw new IllegalStateException(e); }
                }
                return actor;
            }
        };
        var service = service(access);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var one = workers.submit(() -> service.summary("reader",all,null));
            var two = workers.submit(() -> service.summary("reader",all,null));
            var a = one.get(30,TimeUnit.SECONDS);
            var b = two.get(30,TimeUnit.SECONDS);
            assertThat(a).containsEntry("origin","ALL");
            assertThat(b).containsEntry("origin","ALL");
            assertThat(a.get("snapshotId")).isNotEqualTo(b.get("snapshotId"));
            assertThat(transactions).hasSize(3);
            assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots WHERE owner_user_id=?",Long.class,user)).isEqualTo(5);
            for (var response : List.of(a,b)) {
                var frozen = initial.summary("reader",all,response.get("snapshotId").toString());
                assertThat(frozen.get("metrics")).isEqualTo(response.get("metrics"));
            }
        }
    }

    @Test void serializationRetryRechecksRevokedAuthorizationInsteadOfReusingTheOldProjection() {
        var first = new AtomicBoolean(true);
        var transactions = new java.util.HashSet<Long>();
        var access = new SecretAccessService(jdbc) {
            @Override public SecretPrincipal requirePrincipal(String login) {
                transactions.add(jdbc.queryForObject("SELECT txid_current()",Long.class));
                return super.requirePrincipal(login);
            }
            @Override public void requireAnyRole(SecretPrincipal actor) {
                super.requireAnyRole(actor);
                if (first.getAndSet(false)) outsideTransaction(() -> {
                    jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE user_id=?",user);
                    jdbc.update("UPDATE secret_snapshot_owner_locks SET epoch=epoch+1 WHERE user_id=?",user);
                });
            }
        };
        assertThatThrownBy(() -> service(access).summary("reader",all,null))
            .isInstanceOfSatisfying(ApiException.class,e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        assertThat(transactions).hasSize(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots",Long.class)).isZero();
    }

    @Test void aFailedAttemptRollsBackAllItsWritesBeforeReadingTheNewRevision() {
        var attempts = new AtomicInteger();
        var transactions = new java.util.HashSet<Long>();
        var result = snapshots.readConsistently(() -> {
            int attempt = attempts.incrementAndGet();
            transactions.add(jdbc.queryForObject("SELECT txid_current()",Long.class));
            long revision = jdbc.queryForObject("SELECT epoch FROM secret_snapshot_owner_locks WHERE user_id=?",Long.class,user);
            jdbc.update("INSERT INTO secret_snapshot_retirements(snapshot_id,owner_user_id) VALUES (?,?)",UUID.randomUUID(),user);
            if(attempt==1) outsideTransaction(() -> jdbc.update("UPDATE secret_snapshot_owner_locks SET epoch=epoch+1 WHERE user_id=?",user));
            return snapshots.create(user,"INVENTORY",Map.of("origin","ALL"),"revision-"+revision,false,List.of());
        });
        assertThat(attempts).hasValue(2);
        assertThat(transactions).hasSize(2);
        assertThat(jdbc.queryForObject("SELECT authorization_revision FROM secret_query_snapshots WHERE snapshot_id=?",String.class,result.snapshotId())).isEqualTo("revision-1");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_snapshot_retirements",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots",Long.class)).isEqualTo(1);
    }

    @Test void serializationContentionHasABoundedSafeConflictButOtherSqlErrorsAreNotRetried() {
        var attempts = new AtomicInteger();
        var transactions = new java.util.HashSet<Long>();
        assertThatThrownBy(() -> snapshots.readConsistently(() -> {
            attempts.incrementAndGet();transactions.add(jdbc.queryForObject("SELECT txid_current()",Long.class));
            jdbc.execute("DO $$ BEGIN RAISE EXCEPTION 'controlled concurrency fixture' USING ERRCODE='40001'; END $$");
            return true;
        })).isInstanceOfSatisfying(SecretReadConflict.class,e -> {
            assertThat(e.reason()).isEqualTo(SecretReadConflict.Reason.SNAPSHOT_RETRY);
            var response = new SecretReadConflictAdvice().changed(e);
            assertThat(response.getStatusCode().value()).isEqualTo(409);
            assertThat(response.getBody()).containsEntry("retryable",true).containsEntry("details",Map.of("reasonCode","SNAPSHOT_RETRY"));
        });
        assertThat(attempts).hasValue(3);
        assertThat(transactions).hasSize(3);
        attempts.set(0);
        assertThatThrownBy(() -> snapshots.readConsistently(() -> {
            attempts.incrementAndGet();
            jdbc.execute("DO $$ BEGIN RAISE EXCEPTION 'controlled integrity fixture' USING ERRCODE='23505'; END $$");
            return true;
        })).isInstanceOf(DataAccessException.class);
        assertThat(attempts).hasValue(1);
    }

    @Test void anExistingTransactionIsNeverSuspendedOrPartiallyRetried() {
        var outer = new TransactionTemplate(manager);
        outer.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        var attempts = new AtomicInteger();
        assertThatThrownBy(() -> outer.execute(status -> {
            long original = jdbc.queryForObject("SELECT txid_current()",Long.class);
            return snapshots.readConsistently(() -> {
                attempts.incrementAndGet();
                assertThat(jdbc.queryForObject("SELECT txid_current()",Long.class)).isEqualTo(original);
                jdbc.execute("DO $$ BEGIN RAISE EXCEPTION 'controlled concurrency fixture' USING ERRCODE='40001'; END $$");
                return true;
            });
        })).isInstanceOfSatisfying(SecretReadConflict.class,e -> assertThat(e.reason()).isEqualTo(SecretReadConflict.Reason.SNAPSHOT_RETRY));
        assertThat(attempts).hasValue(1);
    }

    private SecretWorkbenchService service(SecretAccessService access) {
        var json = JsonMapper.builder().build();
        return new SecretWorkbenchService(jdbc,access,new SecretLocationRepository(jdbc),
            new SecretLocationWorkflow(jdbc,access,new SecretCommandExecutor(jdbc,manager),snapshots),
            new SecretCoverageService(jdbc,access),snapshots,json);
    }
    private void outsideTransaction(Runnable work) {
        var separate = new TransactionTemplate(manager);
        separate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        separate.executeWithoutResult(status -> work.run());
    }
}
