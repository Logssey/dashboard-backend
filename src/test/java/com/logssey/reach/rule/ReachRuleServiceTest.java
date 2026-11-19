package com.logssey.reach.rule;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.rule.dto.ReachRuleResponse;

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

class ReachRuleServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final ReachVulnFunctionData FUNCTIONS = new ReachVulnFunctionData();
    private static final ReachRuleData DATA = new ReachRuleData(FUNCTIONS);   // 실제 동봉 파일
    private static final ReachRuleFilter ALL = new ReachRuleFilter(null, null, null, null);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static JdbcTemplate jdbc;
    private ReachRuleService service;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
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
        service = new ReachRuleService(DATA, new ReachRuleRepository(JdbcClient.create(jdbc)));
    }

    // ---- 데이터 파일 ----

    @Test
    void loadsTheShippedRules() {
        assertThat(DATA.version()).isEqualTo("v0");
        assertThat(DATA.rules()).hasSize(16);

        var tomcat = DATA.rule("RULE-CVE-2026-65182").orElseThrow();
        assertThat(tomcat.cve()).isEqualTo("CVE-2026-65182");
        assertThat(tomcat.method()).isEqualTo("RULE");
        assertThat(tomcat.packages()).containsExactly("pkg:maven/org.apache.tomcat.embed/tomcat-embed-core");
        // 조건 순서대로, 호출 그래프 결과(sink, sink_weak)는 빼고
        assertThat(tomcat.facts()).containsExactly("F-tomcat.addConstraint", "F-tomcat.securityCollection",
                "F-tomcat.servletSecurityAnn", "F-tomcat.setServletSecurity", "F-repo.webxml.securityConstraint",
                "F-jar.springBoot4");
        assertThat(tomcat.evaluationOrder()).containsExactly("REACHABLE", "UNREACHABLE", "UNKNOWN", "DEFAULT");
        assertThat(tomcat.defaultStatus()).isEqualTo("UNREACHABLE");
        assertThat(tomcat.reasons()).containsOnlyKeys("UNREACHABLE", "UNKNOWN");
        assertThat(tomcat.reasons().get("UNREACHABLE")).contains("보안 제약");
        assertThat(tomcat.vulnFunctionIds()).isNotEmpty().allSatisfy(id ->
                assertThat(FUNCTIONS.items().get(id - 1).cve()).isEqualTo("CVE-2026-65182"));

        var jackson = DATA.rule("RULE-CVE-2026-89407").orElseThrow();
        assertThat(jackson.infoFacts()).containsExactly("F-dto.floating.any");
        assertThat(jackson.facts()).contains("F-dto.floating.tokens")   // Finding 근거 factId와 같은 표기
                .noneMatch(id -> ReachRuleData.CALLGRAPH_FACTS.contains(id.substring(2)));
        assertThat(DATA.rules()).extracting(ReachRuleResponse::method).contains("RULE", "CALLGRAPH");
        // HTTP/2 SNI 검증 우회: 레포 설정 사실과 코드 사실을 함께 본다
        var http2 = DATA.rule("RULE-CVE-2026-65637").orElseThrow();
        assertThat(http2.method()).isEqualTo("RULE");
        assertThat(http2.facts()).containsExactly("F-repo.spring.http2Enabled", "F-repo.spring.serverSsl",
                "F-repo.spring.http2Yaml", "F-tomcat.http2ProtocolNew", "F-tomcat.addUpgradeProtocol",
                "F-spring.http2SetEnabled", "F-jar.springBoot4");
        assertThat(http2.reasons()).containsOnlyKeys("REACHABLE", "UNREACHABLE", "UNKNOWN");
        // 모든 규칙에 취약 함수와 패키지가 있다 (두 데이터 파일이 같은 CVE 16개)
        assertThat(DATA.rules()).allSatisfy(rule -> {
            assertThat(rule.packages()).isNotEmpty();
            assertThat(rule.vulnFunctionIds()).isNotEmpty();
        });
    }

    @Test
    void definitionHoldsTheRawConditionAndTheFactsItUses() {
        var rule = DATA.rule("RULE-CVE-2026-65182").orElseThrow();
        var definition = rule.definition();
        assertThat(definition.path("verdict").path("otherwise").asString()).isEqualTo("unreachable");
        assertThat(definition.path("verdict").path("unknown_if").toString()).contains("sink_weak");
        var factIds = new ArrayList<String>();
        definition.path("facts").forEach(fact -> factIds.add(fact.path("id").asString()));
        // 원문이라 F- 없이 rules.json 이름 그대로
        assertThat(factIds).containsExactlyElementsOf(rule.facts().stream().map(id -> id.substring(2)).toList());
        assertThat(definition.path("facts").get(0).path("type").isString()).isTrue();
    }

    @Test
    void refusesRulesThatUseUndefinedFacts() {
        String base = """
                {"schema":"reach-rules/v0","facts":[{"id":"a.fact","type":"class-ref"}],"repo_facts":[],
                 "verdicts":{"CVE-2026-65182":{"method":"rule","unknown_if":[[%s]],"otherwise":"unreachable"}}}""";
        assertThat(new ReachRuleData(MAPPER.readTree(base.formatted("\"!a.fact\", \"sink\"")), FUNCTIONS).rules()).hasSize(1);
        assertThatThrownBy(() -> new ReachRuleData(MAPPER.readTree(base.formatted("\"missing.fact\"")), FUNCTIONS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("missing.fact");
        assertThatThrownBy(() -> new ReachRuleData(MAPPER.readTree(base.replace("reach-rules/v0", "other/v1").formatted("\"a.fact\"")), FUNCTIONS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("schema");
        assertThatThrownBy(() -> new ReachRuleData(MAPPER.readTree(base.replace("\"rule\"", "\"magic\"").formatted("\"a.fact\"")), FUNCTIONS))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("method");
    }

    // ---- API-09 ----

    @Test
    void requiresAdmin() {
        assertError(() -> service.rules(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.rules("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.rule(null, "RULE-CVE-2026-65182", null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.rule("nobody", "RULE-CVE-2026-65182", null), ErrorCode.FORBIDDEN);
    }

    @Test
    void listsRulesInCveOrderWithoutDefinitionUnlessAsked() {
        var page = service.rules("admin", ALL, null, null, List.of("total"));
        assertThat(page.totalCount()).isEqualTo(16);
        assertThat(page.items()).hasSize(16);
        assertThat(page.version()).isEqualTo("v0");
        assertThat(page.items()).extracting(ReachRuleResponse::cve).isSortedAccordingTo(ReachVulnFunctionData::compareCve);
        assertThat(page.items()).allSatisfy(rule -> assertThat(rule.definition()).isNull());

        var withDefinition = service.rules("admin", ALL, null, null, List.of("definition"));
        assertThat(withDefinition.items()).allSatisfy(rule -> assertThat(rule.definition()).isNotNull());
        assertThat(withDefinition.totalCount()).isNull();
    }

    @Test
    void filtersByCvePackageAndFact() {
        var databind = service.rules("admin", new ReachRuleFilter(null, "pkg:maven/tools.jackson.core/jackson-databind", null, null), null, null, null);
        assertThat(databind.items()).isNotEmpty().allSatisfy(rule ->
                assertThat(rule.packages()).anyMatch(p -> p.startsWith("pkg:maven/tools.jackson.core/jackson-databind")));

        var byFact = service.rules("admin", new ReachRuleFilter(null, null, "F-tomcat.addConstraint", null), null, null, null);
        assertThat(byFact.items()).extracting(ReachRuleResponse::cve).contains("CVE-2026-65182")
                .allSatisfy(cve -> assertThat(DATA.rule("RULE-" + cve).orElseThrow().facts()).contains("F-tomcat.addConstraint"));

        var two = service.rules("admin", new ReachRuleFilter(List.of("CVE-2026-89407", "CVE-2026-65182"), null, null, null), null, null, null);
        assertThat(two.items()).extracting(ReachRuleResponse::cve).containsExactly("CVE-2026-65182", "CVE-2026-89407");

        assertThat(service.rules("admin", new ReachRuleFilter(null, null, "no.such.fact", null), null, null, null).items()).isEmpty();
        // 접두사 없는 이름은 다른 값이다
        assertThat(service.rules("admin", new ReachRuleFilter(null, null, "tomcat.addConstraint", null), null, null, null).items()).isEmpty();
    }

    @Test
    void returnsOneRuleOrNotFound() {
        assertThat(service.rule("admin", "RULE-CVE-2026-89407", null).definition()).isNull();
        assertThat(service.rule("admin", "RULE-CVE-2026-89407", List.of("definition")).definition()).isNotNull();
        assertError(() -> service.rule("admin", "RULE-CVE-2020-0001", null), ErrorCode.NOT_FOUND);
        assertError(() -> service.rule("admin", "CVE-2026-89407", null), ErrorCode.NOT_FOUND);
        assertError(() -> service.rule("admin", "RULE-CVE-2026-89407", List.of("total")), ErrorCode.INVALID_INPUT);
    }

    @Test
    void pagesWithACursorTiedToTheFilter() {
        // 규칙 16개를 6개씩: 6, 6, 4
        var first = service.rules("admin", ALL, 6, null, null);
        var second = service.rules("admin", ALL, 6, first.nextCursor(), null);
        var third = service.rules("admin", ALL, 6, second.nextCursor(), null);
        assertThat(first.hasNext()).isTrue();
        assertThat(third.hasNext()).isFalse();
        assertThat(third.nextCursor()).isNull();
        var all = new ArrayList<String>();
        for (var page : List.of(first, second, third)) page.items().forEach(rule -> all.add(rule.id()));
        assertThat(all).hasSize(16).doesNotHaveDuplicates();
        assertError(() -> service.rules("admin", new ReachRuleFilter(null, null, "F-tomcat.addConstraint", null), 5, first.nextCursor(), null),
                ErrorCode.INVALID_INPUT);
    }

    @Test
    void rejectsBadQueries() {
        assertError(() -> new ReachRuleFilter(List.of("CVE-26-1"), null, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> new ReachRuleFilter(null, null, null, "updatedAt"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.rules("admin", ALL, 0, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.rules("admin", ALL, null, null, List.of("excluded")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.rules("admin", ALL, null, "zz", null), ErrorCode.INVALID_INPUT);
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }
}
