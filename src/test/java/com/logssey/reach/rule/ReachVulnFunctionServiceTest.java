package com.logssey.reach.rule;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.rule.dto.ReachVulnFunctionResponse;

import java.util.ArrayList;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachVulnFunctionServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final ReachVulnFunctionData DATA = new ReachVulnFunctionData();   // 실제 동봉 파일
    private static final ReachVulnFunctionFilter ALL = new ReachVulnFunctionFilter(null, null, null);
    private static JdbcTemplate jdbc;
    private ReachVulnFunctionService service;

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
        jdbc.execute("TRUNCATE dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        service = new ReachVulnFunctionService(DATA, new ReachRuleRepository(JdbcClient.create(jdbc)));
    }

    // ---- 데이터 파일 ----

    @Test
    void loadsTheShippedDataFile() {
        assertThat(DATA.version()).isEqualTo("v0");
        assertThat(DATA.generated()).isEqualTo("2026-10-10");
        assertThat(DATA.items()).hasSize(49);
        assertThat(DATA.items().stream().map(ReachVulnFunctionResponse::cve).distinct()).hasSize(16);
        assertThat(DATA.items()).extracting(ReachVulnFunctionResponse::id)
                .containsExactlyElementsOf(java.util.stream.IntStream.rangeClosed(1, 49).boxed().toList());

        var lazy = DATA.items().stream()
                .filter(item -> item.cve().equals("CVE-2026-13506") && item.method().equals("force")).findFirst().orElseThrow();
        assertThat(lazy.packageUrl()).isEqualTo("pkg:maven/org.bouncycastle/bcprov-jdk18on");
        assertThat(lazy.className()).isEqualTo("org.bouncycastle.asn1.LazyEncodedSequence");
        assertThat(lazy.descriptor()).isEqualTo("()V");
        assertThat(lazy.fixedVersions()).containsExactly("1.85");
        assertThat(lazy.fixCommits()).containsExactly("bcgit/bc-java@77454da9");
        assertThat(lazy.confidence()).isEqualTo("high");
        assertThat(DATA.packages("CVE-2026-13506")).containsExactly("pkg:maven/org.bouncycastle/bcprov-jdk18on");

        // 수정 버전은 릴리스 줄마다 하나라 전부 준다. 버전 순서(문자 순서가 아니다)
        var tomcat = DATA.items().stream().filter(item -> item.cve().equals("CVE-2026-65182")).findFirst().orElseThrow();
        assertThat(tomcat.fixedVersions()).containsExactly("9.0.121", "10.1.59", "11.0.25");
    }

    @Test
    void refusesABrokenDataFile() {
        var mapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> new ReachVulnFunctionData(mapper.readTree("{\"schema\":\"other/v1\",\"cves\":[]}")))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("schema");
        assertThatThrownBy(() -> new ReachVulnFunctionData(mapper.readTree("{\"schema\":\"reach-spec/v0\",\"cves\":[]}")))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new ReachVulnFunctionData(mapper.readTree("""
                {"schema":"reach-spec/v0","cves":[{"cve":"CVE-1","package":{"coordinates":"a:b"},"sinks":[{"class":"C","method":"m"}]}]}
                """))).isInstanceOf(IllegalStateException.class).hasMessageContaining("CVE");
        assertThatThrownBy(() -> new ReachVulnFunctionData(mapper.readTree("""
                {"schema":"reach-spec/v0","cves":[{"cve":"CVE-2026-0001","package":{"coordinates":"a:b"},"sinks":[]}]}
                """))).isInstanceOf(IllegalStateException.class).hasMessageContaining("sinks");
        assertThatThrownBy(() -> new ReachVulnFunctionData(mapper.readTree("""
                {"schema":"reach-spec/v0","cves":[{"cve":"CVE-2026-0001","package":{"coordinates":"nocolon"},"sinks":[{"class":"C","method":"m"}]}]}
                """))).isInstanceOf(IllegalStateException.class).hasMessageContaining("coordinates");
    }

    @Test
    void comparesCveAndVersionsAsNumbers() {
        assertThat(ReachVulnFunctionData.compareCve("CVE-2026-8763", "CVE-2026-13506")).isNegative();
        assertThat(ReachVulnFunctionData.compareCve("CVE-2025-14813", "CVE-2026-0636")).isNegative();
        assertThat(ReachVulnFunctionData.compareVersions("1.81.1", "1.81")).isPositive();
        assertThat(ReachVulnFunctionData.compareVersions("9.0.121", "10.1.59")).isNegative();
    }

    // ---- API-10 ----

    @Test
    void requiresAdmin() {
        assertError(() -> service.vulnFunctions(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.vulnFunctions("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
    }

    @Test
    void listsByCveClassMethodWithTotalAndDataVersion() {
        var page = service.vulnFunctions("admin", ALL, 100, null, List.of("total"));

        assertThat(page.totalCount()).isEqualTo(49);
        assertThat(page.items()).hasSize(49);
        assertThat(page.hasNext()).isFalse();
        assertThat(page.version()).isEqualTo("v0");
        assertThat(page.generated()).isEqualTo("2026-10-10");
        assertThat(page.items().get(0).cve()).isEqualTo("CVE-2025-14813");   // 연도·번호 숫자 순
        var cves = page.items().stream().map(ReachVulnFunctionResponse::cve).distinct().toList();
        assertThat(cves).isSortedAccordingTo(ReachVulnFunctionData::compareCve);
        assertThat(service.vulnFunctions("admin", ALL, null, null, null).totalCount()).isNull();
    }

    @Test
    void filtersByCveAndPackagePrefix() {
        var bc = service.vulnFunctions("admin", new ReachVulnFunctionFilter(List.of("CVE-2026-13506"), null, null), null, null, null);
        assertThat(bc.items()).extracting(ReachVulnFunctionResponse::method)
                .containsExactlyInAnyOrder("force", "getObjects", "<init>");

        var tomcat = service.vulnFunctions("admin", new ReachVulnFunctionFilter(null, "pkg:maven/org.apache.tomcat", null), 100, null, List.of("total"));
        assertThat(tomcat.items()).isNotEmpty().allSatisfy(item -> assertThat(item.packageUrl()).startsWith("pkg:maven/org.apache.tomcat"));
        assertThat(tomcat.items()).extracting(ReachVulnFunctionResponse::cve).containsOnly("CVE-2026-65182", "CVE-2026-65905", "CVE-2026-68525", "CVE-2026-65637");

        var two = service.vulnFunctions("admin", new ReachVulnFunctionFilter(List.of("CVE-2026-13506", "CVE-2026-8763"), null, null), 100, null, null);
        assertThat(two.items()).extracting(ReachVulnFunctionResponse::cve).containsOnly("CVE-2026-13506", "CVE-2026-8763");
        assertThat(two.items().get(0).cve()).isEqualTo("CVE-2026-8763");

        assertThat(service.vulnFunctions("admin", new ReachVulnFunctionFilter(List.of("CVE-2020-0001"), null, null), null, null, null).items()).isEmpty();
    }

    @Test
    void sortsByTheChosenColumnFirst() {
        var byMethod = service.vulnFunctions("admin", new ReachVulnFunctionFilter(null, null, "method"), 100, null, null);
        assertThat(byMethod.items()).extracting(ReachVulnFunctionResponse::method).isSorted();
        var byClass = service.vulnFunctions("admin", new ReachVulnFunctionFilter(null, null, "class"), 100, null, null);
        assertThat(byClass.items()).extracting(ReachVulnFunctionResponse::className).isSorted();
    }

    @Test
    void pagesWithACursorTiedToTheFilter() {
        var seen = new ArrayList<Integer>();
        String cursor = null;
        int pages = 0;
        do {
            var page = service.vulnFunctions("admin", ALL, 20, cursor, null);
            page.items().forEach(item -> seen.add(item.id()));
            cursor = page.nextCursor();
            assertThat(page.hasNext()).isEqualTo(cursor != null);
            pages++;
        } while (cursor != null);
        assertThat(pages).isEqualTo(3);
        assertThat(seen).hasSize(49).doesNotHaveDuplicates();

        String first = service.vulnFunctions("admin", ALL, 20, null, null).nextCursor();
        assertError(() -> service.vulnFunctions("admin", new ReachVulnFunctionFilter(null, null, "method"), 20, first, null),
                ErrorCode.INVALID_INPUT);
    }

    @Test
    void rejectsBadQueries() {
        assertError(() -> new ReachVulnFunctionFilter(List.of("cve-2026-1"), null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> new ReachVulnFunctionFilter(null, null, "updatedAt"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.vulnFunctions("admin", ALL, 0, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.vulnFunctions("admin", ALL, 101, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.vulnFunctions("admin", ALL, null, null, List.of("definition")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.vulnFunctions("admin", ALL, null, "zz", null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.vulnFunctions("admin", ALL, null, ReachDataCursorTestSupport.encoded(0, 1), null), ErrorCode.INVALID_INPUT);
        // excluded는 받되 지금 데이터에는 뺀 메서드 기록이 없어 결과가 같다
        assertThat(service.vulnFunctions("admin", ALL, 100, null, List.of("excluded")).items()).hasSize(49);
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }

    /** 커서 형식을 직접 만들어 보는 테스트용 */
    private static final class ReachDataCursorTestSupport {
        static String encoded(int offset, int fingerprint) {
            return java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString((offset + "," + fingerprint).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
