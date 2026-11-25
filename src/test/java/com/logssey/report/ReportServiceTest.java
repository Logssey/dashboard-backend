package com.logssey.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.iac.query.IacQueryRepository;
import com.logssey.iac.query.IacQueryService;
import com.logssey.iac.report.IacReportChapterProvider;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

class ReportServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final LocalDate TODAY = LocalDate.now(ZoneId.of("Asia/Seoul"));
    private static final String HOPS = """
            [{"kind":"Internet","id":"internet","name":"internet"},
             {"kind":"AWSEC2Instance","id":"i-0abc123","name":"i-0abc123"},
             {"kind":"AWSRole","id":"arn:aws:iam::111122223333:role/node","name":"logssey-prod-role-node"},
             {"kind":"AWSSecretsManagerSecret","id":"arn:aws:secretsmanager:ap-northeast-1:111122223333:secret:prod/db","name":"prod/db"}]
            """;
    private static DriverManagerDataSource datasource;
    private static JdbcTemplate jdbc;
    private final AtomicReference<String> sentRequest = new AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicInteger findingCalls = new java.util.concurrent.atomic.AtomicInteger();

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE report_audit_events, report_finding_advice, report_snapshots, iac_run_path_changes, iac_attack_paths, iac_findings, "
                + "iac_jobs, iac_runs, iac_repos, iac_data_assets, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) VALUES ('admin', 'h', '관리자', 'ADMIN')");
        jdbc.update("INSERT INTO iac_data_assets (arn, kind, tier) VALUES ('arn:aws:secretsmanager:ap-northeast-1:111122223333:secret:prod/db', 'SECRET', 1)");
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, status, finished_at) VALUES ('COLLECT_GRAPH', 'SCHEDULED', 'SUCCEEDED', now() - interval '1 hour')");
        jdbc.update("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, status, first_seen_at, last_seen_at)
                VALUES ('p1', 'internet', 1, 1, 'CRITICAL', 'PROD', ?::jsonb, 3, 'OPEN', now() - interval '20 days', now())
                """, HOPS);
    }

    /** AI 는 받은 요청만 기록하고 고정된 추천을 돌려준다 */
    private ReportAdvisor fakeAdvisor() {
        return new ReportAdvisor() {
            public boolean enabled() {
                return true;
            }

            public ReportAdvice advise(ReportChapter chapter, String request) {
                sentRequest.set(request);
                return new ReportAdvice(ReportAdvice.GENERATED, null, "claude-opus-5-5", request, List.of("IMDSv2 강제부터"),
                        List.of(new ReportAdvice.Item("IMDSv2 강제", "자격 증명 탈취 차단", List.of("변수 변경", "plan 확인"))),
                        OffsetDateTime.now());
            }

            public ReportAdvice adviseFinding(ReportPart part, ReportFinding finding, List<ReportChapter.Remediation> actions,
                                              String request) {
                findingCalls.incrementAndGet();
                return new ReportAdvice(ReportAdvice.GENERATED, null, "claude-opus-5-5", request, List.of(finding.id() + " 대응"),
                        List.of(new ReportAdvice.Item("건별 조치", "이 경로를 끊는다", List.of("a", "b"))), OffsetDateTime.now());
            }
        };
    }

    private ReportService service(ReportChapterProvider... extra) {
        var providers = new ArrayList<ReportChapterProvider>(
                List.of(new IacReportChapterProvider(new IacQueryService(new IacQueryRepository(jdbc)))));
        providers.addAll(List.of(extra));
        return new ReportService(new ReportRepository(jdbc), providers, fakeAdvisor(), new DataSourceTransactionManager(datasource));
    }

    private static ReportDtos.CreateRequest request(String name, List<String> parts, String ai) {
        return new ReportDtos.CreateRequest(name, TODAY.minusDays(30), TODAY, parts, ai);
    }

    @Test
    void 파트_리포트는_4개_절로_만들고_이름에_파트명을_붙인다() {
        var service = service();

        long id = service.create(request(null, List.of("IAC"), "배포 전 끝내야 함"), "admin").reportIds().getFirst();
        var c = service.get(id, "admin").content();

        assertThat(c.name()).isEqualTo("[IaC 보안] 보안 리포트 " + TODAY.minusDays(30) + " ~ " + TODAY);
        assertThat(c.part()).isEqualTo(ReportPart.IAC);
        assertThat(c.overview().connected()).isTrue();
        // 1 발견된 취약점
        assertThat(c.vulnerabilities().findings()).singleElement().satisfies(f -> {
            assertThat(f.location()).isEqualTo("인터넷 → EC2 → 역할 → 시크릿");
            assertThat(f.dueDefault()).isTrue();
        });
        assertThat(c.vulnerabilities().overdue()).isEqualTo(1);
        // 2 조치 방안: 규칙 조치 + AI 추천 (입력창 내용이 그대로 전달됨)
        assertThat(c.remediation().actions()).extracting(ReportContent.Action::title)
                .contains("EC2 메타데이터를 IMDSv2로만 받기", "역할의 시크릿 읽기 범위 좁히기");
        assertThat(c.remediation().actions().getFirst().rank()).isEqualTo(1);
        assertThat(c.remediation().actions().getFirst().findingIds()).containsExactly("IAC-P1");
        assertThat(c.remediation().advice().status()).isEqualTo(ReportAdvice.GENERATED);
        assertThat(sentRequest.get()).isEqualTo("배포 전 끝내야 함");
        // 3 처리 우선순위
        assertThat(c.priorities()).singleElement().satisfies(p -> {
            assertThat(p.rank()).isEqualTo(1);
            assertThat(p.overdue()).isTrue();
        });
        // 4 부록
        assertThat(c.appendix().links()).extracting(ReportChapter.Link::url).contains("/iac");
        assertThat(service.list("admin")).singleElement().satisfies(item -> {
            assertThat(item.part()).isEqualTo(ReportPart.IAC);
            assertThat(item.critical()).isEqualTo(1);
        });
    }

    @Test
    void 파트를_여러_개_고르면_파트마다_리포트를_만든다() {
        ReportChapterProvider runtime = new ReportChapterProvider() {
            public ReportPart part() {
                return ReportPart.RUNTIME;
            }

            public ReportChapter chapter(OffsetDateTime from, OffsetDateTime to, String loginId) {
                return new ReportChapter(ReportPart.RUNTIME, OffsetDateTime.now(), "런타임", "Finding", null, List.of(),
                        java.util.Map.of(), List.of(), List.of(), List.of(), List.of(), null, null, null);
            }
        };
        var service = service(runtime);

        var ids = service.create(request("11월 점검", List.of("RUNTIME", "IAC"), null), "admin").reportIds();

        assertThat(ids).hasSize(2);
        assertThat(service.list("admin")).extracting(ReportDtos.ListItem::name)
                .containsExactlyInAnyOrder("[IaC 보안] 11월 점검", "[런타임 보안] 11월 점검");
    }

    @Test
    void 장을_아직_제공하지_않는_파트는_데이터_연결_전_리포트로_만들고_AI_에_보내지_않는다() {
        var service = service();

        long id = service.create(request(null, List.of("SECRET"), "참고"), "admin").reportIds().getFirst();
        var c = service.get(id, "admin").content();

        assertThat(c.name()).startsWith("[시크릿] 보안 리포트");
        assertThat(c.overview().connected()).isFalse();
        assertThat(c.overview().stale()).as("연결 전은 기준 시각 경고를 띄우지 않는다").isFalse();
        assertThat(service.list("admin")).singleElement().satisfies(item -> assertThat(item.connected()).isFalse());
        assertThat(new String(service.print(id, "admin").content(), StandardCharsets.UTF_8))
                .contains("처리 우선순위", "발견된 취약점", "공통 조치 방안", "데이터 연결 전이라 비어 있습니다")
                .doesNotContain("처리할 취약점이 없습니다");
        assertThat(c.vulnerabilities().findings()).isEmpty();
        assertThat(c.priorities()).isEmpty();
        assertThat(c.remediation().advice().reason()).isEqualTo("PART_NOT_CONNECTED");
        assertThat(sentRequest.get()).as("AI 호출 없음").isNull();
        assertThat(service.options("admin").connectedParts()).containsExactly(ReportPart.IAC);
    }

    @Test
    void 스냅샷은_이후_변경과_상관없이_같은_숫자를_보여준다() {
        var service = service();
        long id = service.create(request(null, List.of("IAC"), null), "admin").reportIds().getFirst();

        jdbc.update("UPDATE iac_attack_paths SET status = 'CLOSED'");

        assertThat(service.get(id, "admin").content().overview().keyMetric().value()).isEqualTo(1);
    }

    @Test
    void 인쇄용_HTML은_4개_절이고_식별자가_없다() {
        var service = service();
        long id = service.create(request(null, List.of("IAC"), null), "admin").reportIds().getFirst();

        var html = new String(service.print(id, "admin").content(), StandardCharsets.UTF_8);

        assertThat(html).contains("인터넷 → EC2 → 역할 → 시크릿", "IMDSv2 강제");
        assertThat(html.indexOf("처리 우선순위")).as("우선순위가 맨 앞").isLessThan(html.indexOf("발견된 취약점"));
        assertThat(html.indexOf("발견된 취약점")).isLessThan(html.indexOf("<h2>공통 조치 방안"));
        assertThat(html)
                .doesNotContain("111122223333", "i-0abc123", "prod/db", "logssey-prod-role-node", "arn:aws");
    }

    @Test
    void 건별_AI_대응_방법은_한_번_만들어_리포트에_붙고_인쇄본에도_실린다() {
        var service = service();
        long id = service.create(request(null, List.of("IAC"), "운영 중단 없이"), "admin").reportIds().getFirst();

        var first = service.adviseFinding(id, "IAC-P1", "admin");
        var again = service.adviseFinding(id, "IAC-P1", "admin");

        assertThat(first.points()).containsExactly("IAC-P1 대응");
        assertThat(first.request()).as("리포트를 만들 때 적은 요청을 함께 쓴다").isEqualTo("운영 중단 없이");
        assertThat(again.points()).isEqualTo(first.points());
        assertThat(findingCalls.get()).as("두 번째는 저장된 것을 돌려준다").isEqualTo(1);
        assertThat(service.get(id, "admin").findingAdvice()).containsOnlyKeys("IAC-P1");
        assertThat(new String(service.print(id, "admin").content(), StandardCharsets.UTF_8)).contains("건별 AI 대응 방법", "IAC-P1 대응");
        assertThatThrownBy(() -> service.adviseFinding(id, "IAC-P999", "admin"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.NOT_FOUND));

        service.delete(id, "admin");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM report_finding_advice", Integer.class)).isZero();
    }

    @Test
    void 건별_요청에는_그_건의_끊을_지점에_해당하는_조치만_보낸다() {
        var finding = new ReportFinding("IAC-P1", "t", "CRITICAL", null, null, null, null, null, null, false, null,
                "끊을 지점: EC2 메타데이터를 IMDSv2로만 받기 또는 역할의 시크릿 읽기 범위 좁히기", null);
        var actions = List.of(new ReportContent.Action(1, "EC2 메타데이터를 IMDSv2로만 받기", "h", null, null, List.of("IAC-P1")),
                new ReportContent.Action(2, "역할의 시크릿 읽기 범위 좁히기", "h", null, null, List.of("IAC-P1", "IAC-P2")),
                new ReportContent.Action(3, "State 버킷 읽기 주체 줄이기", "h", null, null, List.of()));

        assertThat(ReportService.relatedActions(finding, actions)).extracting(ReportChapter.Remediation::title)
                .containsExactly("EC2 메타데이터를 IMDSv2로만 받기", "역할의 시크릿 읽기 범위 좁히기");
    }

    @Test
    void 삭제하면_목록과_보기에서_사라지고_기록은_남는다() {
        var service = service();
        long id = service.create(request(null, List.of("IAC"), null), "admin").reportIds().getFirst();
        service.get(id, "admin");

        service.delete(id, "admin");

        assertThat(service.list("admin")).isEmpty();
        assertThatThrownBy(() -> service.get(id, "admin"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
        assertThatThrownBy(() -> service.delete(id, "admin")).isInstanceOf(ApiException.class);
        assertThat(jdbc.queryForObject("SELECT content::text FROM report_snapshots WHERE report_id = ?", String.class, id))
                .as("본문은 비운다").isEqualTo("{}");
        assertThat(jdbc.queryForList("SELECT event_type FROM report_audit_events ORDER BY event_id", String.class))
                .containsExactly("CREATED", "VIEWED", "DELETED");
    }

    @Test
    void 잘못된_요청과_관리자가_아닌_사용자를_막는다() {
        var service = service();

        assertThatThrownBy(() -> service.create(new ReportDtos.CreateRequest(null, TODAY, TODAY.plusDays(1), List.of("IAC"), null), "admin"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.create(request(null, List.of(), null), "admin")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.create(request(null, List.of("NETWORK"), null), "admin")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.list("nobody"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
    }
}
