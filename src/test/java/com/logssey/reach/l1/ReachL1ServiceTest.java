package com.logssey.reach.l1;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.l1.ReachInventoryRequest.Container;
import com.logssey.reach.l1.ReachInventoryRequest.Workload;
import com.logssey.reach.l1.dto.ReachWorkloadResponse;
import com.logssey.reach.ReachTestProperties;

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
import static org.assertj.core.api.Assertions.tuple;
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
    void collectorUploadNeedsNoAdminAndRecordsTheServiceAccount() {
        String subject = "system:serviceaccount:reach:reach-l1-collector";
        long running = finding(target(A, now.minusDays(1)));

        var response = service.uploadFromCollector(subject, upload(now, c(A, 2)));

        assertThat(response.findingsUpdated()).isEqualTo(1);
        assertThat(deployment(running)).isEqualTo("RUNNING");
        assertThat(jdbc.queryForMap("SELECT source, reported_by FROM reach_workload_observations WHERE namespace = 'reused'"))
                .containsEntry("source", "CLUSTER_READER").containsEntry("reported_by", subject);

        // 범위·검사·오래된 조회 거절은 수동 업로드와 같다
        assertError(() -> service.uploadFromCollector(subject, upload("other", now, c(A, 1))), ErrorCode.INVALID_INPUT);
        assertError(() -> service.uploadFromCollector(subject, upload(now.minusHours(1), c(A, 1))), ErrorCode.CONFLICT);
        assertError(() -> service.uploadFromCollector(null, upload(now, c(A, 1))), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.uploadFromCollector(" ", upload(now, c(A, 1))), ErrorCode.UNAUTHENTICATED);
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
    void withoutAnL1ScopeUploadsAreRejectedAndNothingIsRecomputed() {
        // 설정(logssey.reach.l1)이 없으면 L1이 꺼진다. 기동은 하고, 업로드는 400, 재계산은 0, 목록은 빈 결과 (PRD FR-15)
        long target = imageTarget("API", "logssey/reused-api", A);
        scan(target, "IMAGE_BUILD", "SUCCEEDED");
        for (var off : List.of(service("reused-prod", List.of(), "48 hours"), service(null, List.of("reused"), "48 hours"))) {
            assertError(() -> off.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of())),
                    ErrorCode.INVALID_INPUT);
            assertThat(off.recompute(null)).isZero();
            var page = off.workloads("admin", ALL, null, null, "total");
            assertThat(page.items()).isEmpty();
            assertThat(page.totalCount()).isZero();
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_workload_observations", Long.class)).isZero();
    }

    // ---- API-07 워크로드 목록 ----

    private static final String ECR = "794386801311.dkr.ecr.ap-northeast-1.amazonaws.com/";
    private static final ReachWorkloadFilter ALL = new ReachWorkloadFilter(null, null, null, null);

    @Test
    void workloadsRequireAdmin() {
        assertError(() -> service.workloads(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.workloads("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
    }

    @Test
    void noObservationIsAnEmptyPageNotAnError() {
        var page = service.workloads("admin", ALL, null, null, "total");

        assertThat(page.observations()).isEmpty();
        assertThat(page.items()).isEmpty();
        assertThat(page.hasNext()).isFalse();
        assertThat(page.nextCursor()).isNull();
        assertThat(page.totalCount()).isZero();
    }

    @Test
    void anObservedNamespaceWithoutPodsHasAnObservationButNoItems() {
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of()));

        var page = service.workloads("admin", ALL, null, null, null);

        assertThat(page.observations()).singleElement().satisfies(o -> {
            assertThat(o.cluster()).isEqualTo("reused-prod");
            assertThat(o.namespace()).isEqualTo("reused");
            assertThat(o.observedAt()).isEqualTo(now);
            assertThat(o.source()).isEqualTo("MANUAL");
            assertThat(o.fresh()).isTrue();
        });
        assertThat(page.items()).isEmpty();
    }

    @Test
    void freshObservationIsRunningAndStaleIsUnknown() {
        service.upload("admin", upload(now, c(A, 2)));
        var fresh = service.workloads("admin", ALL, null, null, null);
        assertThat(fresh.items()).singleElement().satisfies(w -> {
            assertThat(w.deployment()).isEqualTo("RUNNING");
            assertThat(w.replicas().ready()).isEqualTo(2);
            assertThat(w.observedAt()).isEqualTo(now);
            assertThat(w.source()).isEqualTo("MANUAL");
        });

        jdbc.update("UPDATE reach_workload_observations SET observed_at = now() - interval '49 hours'");
        var stale = service.workloads("admin", ALL, null, null, null);
        assertThat(stale.observations()).singleElement().satisfies(o -> assertThat(o.fresh()).isFalse());
        assertThat(stale.items()).singleElement().satisfies(w -> assertThat(w.deployment()).isEqualTo("UNKNOWN"));

        assertThat(service.workloads("admin", filter(null, null, null, List.of("UNKNOWN")), null, null, null).items()).hasSize(1);
        assertThat(service.workloads("admin", filter(null, null, null, List.of("RUNNING")), null, null, null).items()).isEmpty();
        assertThat(service.workloads("admin", filter(null, null, null, List.of("NOT_RUNNING")), null, null, null).items()).isEmpty();
    }

    @Test
    void matchesScansByDigestAndFallsBackToTheAppScan() {
        String c = digest('c');
        long api = imageTarget("API", "logssey/reused-api", A);
        long apiScan = scan(api, "MANUAL", "SUCCEEDED");
        long rebuilt = imageTarget("API", "logssey/reused-api", B);
        scan(rebuilt, "PR", "SUCCEEDED");           // PR 스캔은 MATCH로 치지 않는다
        scan(rebuilt, "MANUAL", "RUNNING");         // 끝나지 않은 스캔도
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of(
                new Workload("Deployment", "reused-api", List.of(
                        new Container("api", ECR + "logssey/reused-api:aaa", A, 1),
                        new Container("api", ECR + "logssey/reused-api:bbb", B, 1))),
                new Workload("Deployment", "reused-chat", List.of(
                        new Container("chat", ECR + "logssey/reused-chat:ccc", c, 2))))));

        var items = service.workloads("admin", ALL, null, null, null).items();

        assertThat(items).hasSize(3);
        assertThat(items.get(0).image().digest()).isEqualTo(A);
        assertThat(items.get(0).app()).isEqualTo("API");
        assertThat(items.get(0).scanMatch()).isEqualTo(new ReachWorkloadResponse.ScanMatch("MATCH", apiScan, "DIGEST"));
        assertThat(items.get(1).image().digest()).isEqualTo(B);
        assertThat(items.get(1).app()).isEqualTo("API");
        assertThat(items.get(1).scanMatch()).isEqualTo(new ReachWorkloadResponse.ScanMatch("MISMATCH", apiScan, null));
        assertThat(items.get(2).name()).isEqualTo("reused-chat");
        assertThat(items.get(2).app()).isEqualTo("CHAT");   // 스캔한 적이 없어도 설치 설정의 이미지로 앱을 안다
        assertThat(items.get(2).scanMatch()).isEqualTo(new ReachWorkloadResponse.ScanMatch("NO_SCAN", null, null));

        assertThat(service.workloads("admin", filter(null, List.of("API"), null, null), null, null, null).items()).hasSize(2);
        assertThat(service.workloads("admin", filter(null, List.of("CHAT"), null, null), null, null, null).items())
                .singleElement().satisfies(w -> assertThat(w.name()).isEqualTo("reused-chat"));
        assertThat(service.workloads("admin", filter(null, null, B, null), null, null, null).items())
                .singleElement().satisfies(w -> assertThat(w.image().digest()).isEqualTo(B));
    }

    @Test
    void appComesFromTheDigestTargetEvenIfTheRepositoryNameDiffers() {
        long target = imageTarget("WEB", "reused-web", A);   // 등록 이름이 파드 이미지 저장소와 다르다
        long scan = scan(target, "IMAGE_BUILD", "SUCCEEDED");
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of(
                new Workload("Deployment", "reused-web", List.of(new Container("web", ECR + "logssey/reused-web:1", A, 1))))));

        var item = service.workloads("admin", ALL, null, null, null).items().get(0);

        assertThat(item.app()).isEqualTo("WEB");
        assertThat(item.scanMatch()).isEqualTo(new ReachWorkloadResponse.ScanMatch("MATCH", scan, "DIGEST"));
    }

    @Test
    void appComesFromTheInstallationConfigWhenTheImageWasNeverScanned() {
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of(
                new Workload("Deployment", "reused-web", List.of(new Container("web", ECR + "logssey/reused-web:1", A, 1))),
                new Workload("Deployment", "sidecar", List.of(new Container("proxy", ECR + "vendor/proxy:2", B, 1))))));

        var page = service.workloads("admin", ALL, null, null, "total");

        assertThat(page.items()).extracting(ReachWorkloadResponse::name, ReachWorkloadResponse::app)
                .containsExactly(tuple("reused-web", "WEB"), tuple("sidecar", null));   // 설정에 없는 이미지는 그대로 모름
        assertThat(page.items()).allSatisfy(w ->
                assertThat(w.scanMatch()).isEqualTo(new ReachWorkloadResponse.ScanMatch("NO_SCAN", null, null)));
        assertThat(service.workloads("admin", filter(null, List.of("WEB"), null, null), null, null, "total").totalCount())
                .isEqualTo(1);   // 앱 필터와 개수도 같은 기준
    }

    @Test
    void aTargetOfTheSameDigestWinsOverTheInstallationConfig() {
        long target = imageTarget("API", "logssey/reused-web", A);   // 같은 digest의 대상이 다른 앱으로 등록됐으면 그것을 따른다
        scan(target, "MANUAL", "SUCCEEDED");
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, List.of(
                new Workload("Deployment", "reused-web", List.of(new Container("web", ECR + "logssey/reused-web:1", A, 1))))));

        assertThat(service.workloads("admin", ALL, null, null, null).items()).singleElement()
                .satisfies(w -> assertThat(w.app()).isEqualTo("API"));
    }

    @Test
    void splitsTheImageIntoRepositoryAndTag() {
        var images = List.of(
                ECR + "logssey/reused-api:bb4639b7e45c21d5ced03a5f541b1982093e0865",
                "nginx",
                "nginx:1.27",
                "localhost:5000/team/app:v1",
                "registry:5000/app",
                "ghcr.io/org/app@" + A,
                "org/app:v2@" + A);
        var workloads = new ArrayList<Workload>();
        for (int i = 0; i < images.size(); i++) {
            workloads.add(new Workload("Deployment", "w" + i, List.of(new Container("c", images.get(i), A, 1))));
        }
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, workloads));

        var items = service.workloads("admin", ALL, null, null, null).items();

        assertThat(items).extracting(w -> w.image().repository() + " " + w.image().revision()).containsExactly(
                "logssey/reused-api bb4639b7e45c21d5ced03a5f541b1982093e0865",
                "nginx null",
                "nginx 1.27",
                "team/app v1",
                "app null",
                "org/app null",
                "org/app v2");
    }

    @Test
    void rolloutGivesOneItemPerDigest() {
        service.upload("admin", upload(now, c(B, 0), c(A, 2)));

        var items = service.workloads("admin", ALL, null, null, null).items();

        assertThat(items).extracting(w -> w.image().digest() + " " + w.replicas().ready()).containsExactly(A + " 2", B + " 0");
        assertThat(items).allSatisfy(w -> assertThat(w.deployment()).isEqualTo("RUNNING"));
    }

    @Test
    void showsOnlyTheAllowList() {
        jdbc.update("INSERT INTO reach_workload_observations (cluster, namespace, observed_at, source, reported_by) "
                + "VALUES ('reused-prod', 'other', now(), 'MANUAL', 'USER:9'), ('old-cluster', 'reused', now(), 'MANUAL', 'USER:9')");
        jdbc.update("INSERT INTO reach_workloads (cluster, namespace, kind, name, container, image, image_digest, ready_replicas) "
                + "VALUES ('reused-prod', 'other', 'Deployment', 'x', 'x', 'r/x:1', ?, 1), "
                + "('old-cluster', 'reused', 'Deployment', 'y', 'y', 'r/y:1', ?, 1)", A, A);
        service.upload("admin", upload(now, c(B, 1)));

        var page = service.workloads("admin", ALL, null, null, "total");
        assertThat(page.observations()).extracting(o -> o.cluster() + "/" + o.namespace()).containsExactly("reused-prod/reused");
        assertThat(page.items()).extracting(w -> w.image().digest()).containsExactly(B);
        assertThat(page.totalCount()).isEqualTo(1);

        var outside = service.workloads("admin", filter(List.of("other"), null, null, null), null, null, "total");
        assertThat(outside.observations()).isEmpty();
        assertThat(outside.items()).isEmpty();
        assertThat(outside.totalCount()).isZero();
        assertThat(service.workloads("admin", filter(List.of("reused", "other"), null, null, null), null, null, null).items()).hasSize(1);
    }

    @Test
    void rejectsBadQueries() {
        // 앱 코드는 설정(logssey.reach.apps)과 대조한다. Re:Used 설정에 FOO는 없다
        assertError(() -> service.workloads("admin", filter(null, List.of("FOO"), null, null), null, null, null),
                ErrorCode.INVALID_INPUT);
        assertError(() -> filter(null, null, null, List.of("GONE")), ErrorCode.INVALID_INPUT);
        assertError(() -> filter(null, null, "sha256:ABC", null), ErrorCode.INVALID_INPUT);
        assertError(() -> filter(null, null, A.toUpperCase(), null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.workloads("admin", ALL, 0, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.workloads("admin", ALL, 101, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.workloads("admin", ALL, null, null, "pods"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.workloads("admin", ALL, null, "not-a-cursor", null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.workloads("admin", ALL, null, "a.b.c", null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void pagesWithACursorThatSurvivesAReupload() {
        var three = List.of(
                new Workload("Deployment", "reused-web", List.of(new Container("web", "r/web:1", digest('3'), 1))),
                new Workload("Deployment", "reused-api", List.of(new Container("api", "r/api:1", digest('1'), 1))),
                new Workload("Deployment", "reused-chat", List.of(new Container("chat", "r/chat:1", digest('2'), 1))));
        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now.minusMinutes(1), three));

        var first = service.workloads("admin", ALL, 2, null, "total");
        assertThat(first.items()).extracting(w -> w.name()).containsExactly("reused-api", "reused-chat");
        assertThat(first.hasNext()).isTrue();
        assertThat(first.totalCount()).isEqualTo(3);

        service.upload("admin", new ReachInventoryRequest("reused-prod", "reused", now, three));   // id가 바뀐다

        var second = service.workloads("admin", ALL, 2, first.nextCursor(), null);
        assertThat(second.items()).extracting(w -> w.name()).containsExactly("reused-web");
        assertThat(second.hasNext()).isFalse();
        assertThat(second.nextCursor()).isNull();
        assertThat(second.observations()).hasSize(1);   // 다음 페이지에도 준다

        assertError(() -> service.workloads("admin", filter(null, null, null, List.of("RUNNING")), 2, first.nextCursor(), null),
                ErrorCode.INVALID_INPUT);
    }

    private static ReachWorkloadFilter filter(List<String> namespace, List<String> app, String digest, List<String> deployment) {
        return new ReachWorkloadFilter(namespace, app, digest, deployment);
    }

    private static long imageTarget(String app, String repository, String digest) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', ?, ?, ?, ?) RETURNING target_id
                """, Long.class, app, repository, digest, repository);
    }

    private static long scan(long targetId, String trigger, String status) {
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, started_at, finished_at)
                VALUES (?, ?, ?, 'SYSTEM', now(), CASE WHEN ? = 'SUCCEEDED' THEN now() END) RETURNING scan_id
                """, Long.class, targetId, status, trigger, status);
    }

    private static ReachL1Service service(String cluster, List<String> namespaces, String fresh) {
        return new ReachL1Service(new ReachL1Repository(JdbcClient.create(jdbc)),
                ReachTestProperties.withL1(cluster, namespaces), fresh);
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
