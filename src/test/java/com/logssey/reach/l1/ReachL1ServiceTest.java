package com.logssey.reach.l1;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.l1.ReachInventoryRequest.Container;
import com.logssey.reach.l1.ReachInventoryRequest.Workload;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachL1ServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String A = digest('a');
    private static final String B = digest('b');
    private static JdbcTemplate jdbc;
    private ReachL1Service service;
    private OffsetDateTime now;

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
        jdbc.execute("TRUNCATE reach_workloads, reach_workload_observations, reach_review_history, reach_reviews, "
                + "reach_evidence, reach_verdicts, reach_findings, reach_scans, reach_targets, dashboard_users "
                + "RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        service = service("reused-prod", List.of("reused"), "48 hours");
        now = OffsetDateTime.now(ZoneOffset.UTC).withNano(0);
    }

    @Test
    void requiresAdmin() {
        var request = upload(now, c(A, 1));
        assertError(() -> service.upload(null, request), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.upload("nobody", request), ErrorCode.FORBIDDEN);
    }

    @Test
    void replacesTheNamespaceAndLeavesOthersAlone() {
        jdbc.update("INSERT INTO reach_workload_observations (cluster, namespace, observed_at, source, reported_by) "
                + "VALUES ('reused-prod', 'other', now(), 'MANUAL', 'USER:9')");
        jdbc.update("INSERT INTO reach_workloads (cluster, namespace, kind, name, container, image, image_digest, ready_replicas) "
                + "VALUES ('reused-prod', 'other', 'Deployment', 'x', 'x', 'r/x:1', ?, 1)", A);

        service.upload("admin", upload(now.minusMinutes(1), c(A, 1)));
        var response = service.upload("admin", upload(now, c(B, 2)));

        assertThat(response.workloads()).isEqualTo(1);
        assertThat(digests("reused")).containsExactly(B);
        assertThat(digests("other")).containsExactly(A);
        assertThat(jdbc.queryForMap("SELECT source, reported_by FROM reach_workload_observations WHERE namespace = 'reused'"))
                .containsEntry("source", "MANUAL").containsEntry("reported_by", "USER:1");
    }

    @Test
    void rejectsBadInput() {
        var tooMany = new ArrayList<Container>();
        for (int i = 0; i <= ReachL1Service.MAX_CONTAINERS; i++) {
            tooMany.add(new Container("c" + i, "r/api:x", A, 1));
        }
        List<ReachInventoryRequest> bad = List.of(
                new ReachInventoryRequest("other-cluster", "reused", now, List.of()),
                new ReachInventoryRequest("reused-prod", "other", now, List.of()),
                new ReachInventoryRequest("reused-prod", null, now, List.of()),
                new ReachInventoryRequest("reused-prod", "reused", null, List.of()),
                new ReachInventoryRequest("reused-prod", "reused", now.plusMinutes(6), List.of()),
                new ReachInventoryRequest("reused-prod", "reused", now, null),
                upload(now, c("sha256:abc", 1)),
                upload(now, c(A.toUpperCase().replace("SHA256", "sha256"), 1)),
                upload(now, c(A, null)),
                upload(now, c(A, -1)),
                upload(now, c(A, 1), c(A, 2)),                                       // 같은 컨테이너·digest 두 번
                upload(now, new Container("api", "r/" + "x".repeat(511), A, 1)),     // image 513자
                upload(now, new Container(" ", "r/api:x", A, 1)),
                upload(now, tooMany.toArray(Container[]::new)),
                new ReachInventoryRequest("reused-prod", "reused", now,
                        List.of(new Workload("", "reused-api", List.of(c(A, 1))))),
                new ReachInventoryRequest("reused-prod", "reused", now,
                        List.of(new Workload("Deployment", "reused-api", null))));

        assertError(() -> service.upload("admin", null), ErrorCode.INVALID_INPUT);
        for (var request : bad) {
            assertError(() -> service.upload("admin", request), ErrorCode.INVALID_INPUT);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_workload_observations", Integer.class)).isZero();

        // 파드가 없는 네임스페이스, 5분 안의 미래는 받는다
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now.plusMinutes(4), List.of()));
        assertThat(digests("reused")).isEmpty();
    }

    @Test
    void recomputesDeployment() {
        long running = finding(target(A, now.minusDays(1)));
        long absent = finding(target(B, now.minusDays(1)));

        var response = service.upload("admin", upload(now, c(A, 2)));

        assertThat(response.findingsUpdated()).isEqualTo(2);
        assertThat(deployment(running)).isEqualTo("RUNNING");
        assertThat(deployment(absent)).isEqualTo("NOT_RUNNING");
    }

    @Test
    void staysUnknownWithoutAFreshObservationAfterTheTarget() {
        long newer = finding(target(B, now));   // 조회보다 나중에 생긴 대상
        service.upload("admin", upload(now.minusMinutes(1), c(A, 1)));
        assertThat(deployment(newer)).isEqualTo("UNKNOWN");

        reset();
        long stale = finding(target(A, now.minusDays(1)));
        long staleAbsent = finding(target(B, now.minusDays(1)));
        service("reused-prod", List.of("reused"), "1 second").upload("admin", upload(now.minusSeconds(30), c(A, 1)));
        assertThat(deployment(stale)).isEqualTo("UNKNOWN");         // 보였어도 오래된 조회는 믿지 않는다
        assertThat(deployment(staleAbsent)).isEqualTo("UNKNOWN");
    }

    @Test
    void partialFreshnessIsUnknown() {
        var twoNamespaces = service("reused-prod", List.of("reused", "other"), "48 hours");
        long id = finding(target(A, now.minusDays(1)));

        twoNamespaces.upload("admin", upload("reused", now, c(B, 1)));
        assertThat(deployment(id)).isEqualTo("UNKNOWN");

        twoNamespaces.upload("admin", upload("other", now, c(B, 1)));
        assertThat(deployment(id)).isEqualTo("NOT_RUNNING");
    }

    @Test
    void ignoresRepoTargets() {
        long repo = jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, repo_name, repo_commit, image_digest, display_name, created_at)
                VALUES ('REPO', 'API', 'Logssey/service-backend', 'abc', ?, 'repo', ?) RETURNING target_id
                """, Long.class, A, now.minusDays(1));
        long id = finding(repo);

        var response = service.upload("admin", upload(now, c(A, 1)));

        assertThat(response.findingsUpdated()).isZero();
        assertThat(deployment(id)).isEqualTo("UNKNOWN");
    }

    @Test
    void countsOnlyChangedFindings() {
        finding(target(A, now.minusDays(1)));

        assertThat(service.upload("admin", upload(now.minusMinutes(1), c(A, 1))).findingsUpdated()).isEqualTo(1);
        assertThat(service.upload("admin", upload(now, c(A, 1))).findingsUpdated()).isZero();
    }

    @Test
    void rejectsAnOlderObservationAndAcceptsTheSameTime() {
        long id = finding(target(A, now.minusDays(1)));
        service.upload("admin", upload(now, c(A, 1)));

        assertError(() -> service.upload("admin", upload(now.minusHours(1), c(B, 1))), ErrorCode.CONFLICT);
        assertThat(digests("reused")).containsExactly(A);
        assertThat(deployment(id)).isEqualTo("RUNNING");
        assertThat(jdbc.queryForObject("SELECT observed_at FROM reach_workload_observations", OffsetDateTime.class))
                .isEqualTo(now);

        service.upload("admin", upload(now, c(B, 1)));   // 같은 시각은 재시도로 받는다
        assertThat(digests("reused")).containsExactly(B);
        assertThat(deployment(id)).isEqualTo("NOT_RUNNING");
    }

    @Test
    void ignoresRowsOutsideTheAllowList() {
        long id = finding(target(A, now.minusDays(1)));
        // 예전 설정(다른 클러스터 이름)으로 올라와 남은 행
        service("old-cluster", List.of("reused"), "48 hours").upload("admin",
                new ReachInventoryRequest("old-cluster", "reused", now, List.of(workload(c(A, 1)))));

        service.upload("admin", upload(now, c(B, 1)));

        assertThat(deployment(id)).isEqualTo("NOT_RUNNING");
    }

    @Test
    void storesReadyReplicasPerDigest() {
        service.upload("admin", upload(now, c(A, 2), c(B, 0)));   // 롤아웃 중

        assertThat(jdbc.queryForList("SELECT image_digest, ready_replicas FROM reach_workloads ORDER BY image_digest"))
                .containsExactly(Map.of("image_digest", A, "ready_replicas", 2),
                        Map.of("image_digest", B, "ready_replicas", 0));
    }

    @Test
    void crashingWorkloadIsStillRunning() {
        long id = finding(target(A, now.minusDays(1)));

        service.upload("admin", upload(now, c(A, 0)));

        assertThat(deployment(id)).isEqualTo("RUNNING");   // 팀 결정 전 동작: 준비 0이어도 실행 중
    }

    @Test
    void recomputeWithoutUploadTurnsStaleObservationsUnknown() {
        long running = finding(target(A, now.minusDays(1)));
        long absent = finding(target(B, now.minusDays(1)));
        service.upload("admin", upload(now, c(A, 1)));
        assertThat(service.recompute(null)).isZero();   // 아직 신선하면 바뀌는 것이 없다

        jdbc.update("UPDATE reach_workload_observations SET observed_at = now() - interval '49 hours'");   // 수집이 끊김

        assertThat(service.recompute(null)).isEqualTo(2);
        assertThat(deployment(running)).isEqualTo("UNKNOWN");
        assertThat(deployment(absent)).isEqualTo("UNKNOWN");
    }

    @Test
    void recomputeCanTouchOneTarget() {
        long targetA = target(A, now.minusDays(1));
        long a = finding(targetA);
        long b = finding(target(B, now.minusDays(1)));
        service.upload("admin", upload(now, c(A, 1), c(B, 1)));
        jdbc.update("UPDATE reach_workload_observations SET observed_at = now() - interval '49 hours'");

        assertThat(service.recompute(targetA)).isEqualTo(1);
        assertThat(deployment(a)).isEqualTo("UNKNOWN");
        assertThat(deployment(b)).isEqualTo("RUNNING");
    }

    @Test
    void rejectsAnEmptyAllowList() {
        assertThatThrownBy(() -> service("reused-prod", List.of(), "48 hours"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static ReachL1Service service(String cluster, List<String> namespaces, String fresh) {
        return new ReachL1Service(new ReachL1Repository(JdbcClient.create(jdbc)), cluster, namespaces, fresh);
    }

    private static String digest(char c) {
        return "sha256:" + String.valueOf(c).repeat(64);
    }

    private static Container c(String digest, Integer ready) {
        return new Container("api", "r/api:x", digest, ready);
    }

    private static Workload workload(Container... containers) {
        return new Workload("Deployment", "reused-api", Arrays.asList(containers));
    }

    private static ReachInventoryRequest upload(OffsetDateTime observedAt, Container... containers) {
        return upload("reused", observedAt, containers);
    }

    private static ReachInventoryRequest upload(String namespace, OffsetDateTime observedAt, Container... containers) {
        return new ReachInventoryRequest("reused-prod", namespace, observedAt, List.of(workload(containers)));
    }

    private static List<String> digests(String namespace) {
        return jdbc.queryForList("SELECT image_digest FROM reach_workloads WHERE namespace = ? ORDER BY image_digest",
                String.class, namespace);
    }

    private static long target(String digest, OffsetDateTime createdAt) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name, created_at)
                VALUES ('IMAGE', 'API', 'reused-api', ?, 'api', ?) RETURNING target_id
                """, Long.class, digest, createdAt);
    }

    /** deployment 기본값(UNKNOWN)인 Finding. last_scan_id 때문에 성공한 스캔을 하나 만든다 */
    private static long finding(long targetId) {
        long scan = jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, finished_at)
                VALUES (?, 'SUCCEEDED', 'MANUAL', 'SYSTEM', now()) RETURNING scan_id
                """, Long.class, targetId);
        return jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, last_scan_id, first_seen_at, last_seen_at)
                VALUES (?, 'pkg:maven/test/lib@1', 'lib', '1', 'maven', 'CVE-2026-1', 'HIGH', ARRAY['TRIVY'], ?, now(), now())
                RETURNING finding_id
                """, Long.class, targetId, scan);
    }

    private static String deployment(long findingId) {
        return jdbc.queryForObject("SELECT deployment FROM reach_findings WHERE finding_id = ?", String.class, findingId);
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }
}
