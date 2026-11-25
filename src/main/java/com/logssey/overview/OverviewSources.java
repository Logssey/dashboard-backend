package com.logssey.overview;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.report.ReportChapter;
import com.logssey.report.ReportChapterProvider;
import com.logssey.report.ReportFinding;
import com.logssey.report.ReportPart;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * 시크릿을 뺀 보안 기능의 "지금 열린" 위험을 읽는다. 각 기능의 코드는 바꾸지 않고 읽기만 한다.
 * - IaC·취약점 관리: 리포트 장(ReportChapterProvider)과 같은 기준 (리포트와 숫자가 같다)
 * - 런타임: 조치 상태가 열림·진행 중이고 '정상 동작'으로 분류하지 않은 Finding
 * - 컴플라이언스: 대상·환경별 최신 점검의 FAIL 결과
 * - 코드 취약점: 레포·도구별 최신 검사 결과
 * 한 기능을 읽다가 실패해도 다른 기능은 그대로 보여 준다 (그 기능만 ERROR).
 */
@Component
public class OverviewSources {

    private static final Logger log = LoggerFactory.getLogger(OverviewSources.class);

    /** status: CONNECTED · NO_DATA(아직 결과 없음) · NOT_AUTHORIZED · ERROR */
    public record PartData(OverviewPart part, String status, List<OverviewItem> items, Instant dataAsOf) {
        static PartData of(OverviewPart part, List<OverviewItem> items, Instant dataAsOf) {
            return new PartData(part, items.isEmpty() && dataAsOf == null ? "NO_DATA" : "CONNECTED", items, dataAsOf);
        }
    }

    private final JdbcClient jdbc;
    private final List<ReportChapterProvider> chapters;

    public OverviewSources(JdbcClient jdbc, List<ReportChapterProvider> chapters) {
        this.jdbc = jdbc;
        this.chapters = chapters;
    }

    public List<PartData> read(String login) {
        return List.of(
                guarded(OverviewPart.IAC, () -> fromChapter(OverviewPart.IAC, ReportPart.IAC, login)),
                guarded(OverviewPart.VULNERABILITY, () -> fromChapter(OverviewPart.VULNERABILITY, ReportPart.VULNERABILITY, login)),
                guarded(OverviewPart.RUNTIME, this::runtime),
                guarded(OverviewPart.COMPLIANCE, this::compliance),
                guarded(OverviewPart.CODE, this::code));
    }

    private static PartData guarded(OverviewPart part, Supplier<PartData> reader) {
        try {
            return reader.get();
        } catch (ApiException e) {
            if (e.errorCode() == ErrorCode.FORBIDDEN) return new PartData(part, "NOT_AUTHORIZED", List.of(), null);
            log.warn("overview: {} read failed: {}", part, e.errorCode());
            return new PartData(part, "ERROR", List.of(), null);
        } catch (RuntimeException e) {
            log.warn("overview: {} read failed", part, e);
            return new PartData(part, "ERROR", List.of(), null);
        }
    }

    /** IaC 경로는 목표 데이터 자산(제목)마다, 드리프트는 자원마다. 취약점은 CVE·패키지마다 (버전·이미지가 달라도 한 건) */
    private PartData fromChapter(OverviewPart part, ReportPart reportPart, String login) {
        var provider = chapters.stream().filter(p -> p.part() == reportPart).findFirst().orElse(null);
        if (provider == null) return new PartData(part, "NO_DATA", List.of(), null);
        OffsetDateTime now = OffsetDateTime.now();
        ReportChapter chapter = provider.chapter(now.minusDays(30), now, login);
        List<OverviewItem> items = new ArrayList<>();
        for (ReportFinding f : chapter.findings()) {
            items.add(new OverviewItem(part, groupKey(reportPart, f), OverviewItem.severity(f.severity()), f.title(), "PROD",
                    true, f.foundAt() == null ? null : f.foundAt().toInstant(), f.link() == null ? part.link() : f.link()));
        }
        return PartData.of(part, items, chapter.dataAsOf() == null ? null : chapter.dataAsOf().toInstant());
    }

    static String groupKey(ReportPart part, ReportFinding f) {
        if (part == ReportPart.IAC) return f.id().startsWith("IAC-P") ? "path:" + f.title() : f.id();
        // 제목 "CVE-… · 패키지 버전 …", 위치 "패키지@버전 (경로)"
        String cve = f.title().split(" · ", 2)[0];
        String component = f.location() == null ? f.id() : f.location().split("@", 2)[0];
        return cve + "|" + component;
    }

    /** 같은 규칙은 워크로드가 달라도 한 건. 평가 전이면 미평가 */
    private PartData runtime() {
        List<OverviewItem> items = jdbc.sql("""
                SELECT rule_key, rule_title, final_severity, evaluation_status, review_status, first_seen_at
                FROM runtime_findings
                WHERE action_status IN ('OPEN', 'IN_PROGRESS') AND disposition <> 'EXPECTED'
                """).query((rs, n) -> new OverviewItem(OverviewPart.RUNTIME, rs.getString("rule_key"),
                "EVALUATED".equals(rs.getString("evaluation_status")) ? OverviewItem.severity(rs.getString("final_severity")) : "UNASSESSED",
                rs.getString("rule_title"), "PROD", true, instant(rs.getObject("first_seen_at", OffsetDateTime.class)),
                OverviewPart.RUNTIME.link())).list();
        Instant asOf = jdbc.sql("SELECT max(last_seen_at) FROM runtime_findings")
                .query((rs, n) -> instant(rs.getObject(1, OffsetDateTime.class))).list().getFirst();
        return PartData.of(OverviewPart.RUNTIME, items, asOf);
    }

    /** 같은 환경의 같은 점검 항목은 자원이 여러 개여도 한 건 */
    private PartData compliance() {
        String latest = """
                SELECT DISTINCT ON (target_key, environment) run_id, environment, coalesce(finished_at, created_at) AS at
                FROM compliance_runs ORDER BY target_key, environment, created_at DESC, run_id DESC
                """;
        List<OverviewItem> items = jdbc.sql("WITH latest AS (" + latest + ") "
                + "SELECT r.check_id, r.title, r.severity, upper(l.environment) AS env, r.observed_at "
                + "FROM compliance_results r JOIN latest l ON l.run_id = r.run_id WHERE r.result = 'FAIL'")
                .query((rs, n) -> new OverviewItem(OverviewPart.COMPLIANCE, rs.getString("env") + "|" + rs.getString("check_id"),
                        OverviewItem.severity(rs.getString("severity")), rs.getString("title"), rs.getString("env"), true,
                        instant(rs.getObject("observed_at", OffsetDateTime.class)), OverviewPart.COMPLIANCE.link())).list();
        Instant asOf = jdbc.sql("WITH latest AS (" + latest + ") SELECT max(at) FROM latest")
                .query((rs, n) -> instant(rs.getObject(1, OffsetDateTime.class))).list().getFirst();
        return PartData.of(OverviewPart.COMPLIANCE, items, asOf);
    }

    /** 같은 레포의 같은 규칙은 위치가 여러 개여도 한 건 */
    private PartData code() {
        List<OverviewItem> items = jdbc.sql("""
                SELECT s.repository, f.rule_id, f.severity, f.message, s.scanned_at
                FROM code_findings f JOIN code_scans s ON s.scan_id = f.scan_id
                """).query((rs, n) -> {
            String rule = rs.getString("rule_id");
            String repo = rs.getString("repository");
            return new OverviewItem(OverviewPart.CODE, repo + "|" + rule, OverviewItem.severity(rs.getString("severity")),
                    rule.substring(rule.lastIndexOf('.') + 1) + " · " + repo.substring(repo.indexOf('/') + 1), "PROD", true,
                    instant(rs.getObject("scanned_at", OffsetDateTime.class)), OverviewPart.CODE.link());
        }).list();
        Instant asOf = jdbc.sql("SELECT max(scanned_at) FROM code_scans")
                .query((rs, n) -> instant(rs.getObject(1, OffsetDateTime.class))).list().getFirst();
        return PartData.of(OverviewPart.CODE, items, asOf);
    }

    private static Instant instant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }
}
