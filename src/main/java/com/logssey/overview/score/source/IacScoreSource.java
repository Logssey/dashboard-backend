package com.logssey.overview.score.source;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import com.logssey.overview.OverviewItem;
import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * IaC의 열린 위험 (ADR-D011 결정 1과 같은 범위: 열린 공격 경로 + 드리프트). IaC 테이블을 읽기만 한다.
 * 공격 경로는 경로 끝 데이터 자산의 ARN으로 붙고, 드리프트는 자산을 몰라 IaC 미분류로 간다.
 * 마지막 성공 검사는 그래프 수집·분석·드리프트 작업 중 가장 최근에 성공한 것이다
 */
@Component
public class IacScoreSource implements ScoreSource {

    private final JdbcClient jdbc;

    public IacScoreSource(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public OverviewPart part() {
        return OverviewPart.IAC;
    }

    @Override
    public Result read(String login) {
        List<Finding> findings = new ArrayList<>(jdbc.sql("""
                SELECT p.path_id, p.entry, p.severity, p.first_seen_at, a.arn, a.kind
                FROM iac_attack_paths p JOIN iac_data_assets a ON a.data_asset_id = p.target_data_asset_id
                WHERE p.status = 'OPEN' AND p.environment = 'PROD'
                """).query((rs, n) -> new Finding("path:" + rs.getLong("path_id"),
                rs.getString("entry") + " → " + rs.getString("kind"), OverviewItem.severity(rs.getString("severity")), null,
                Hint.arn(rs.getString("arn")), instant(rs.getObject("first_seen_at", OffsetDateTime.class)))).list());
        findings.addAll(jdbc.sql("""
                SELECT finding_id, rule_id, severity, resource_address, first_seen_at
                FROM iac_findings
                WHERE source = 'DRIFT' AND status IN ('OPEN', 'ACCEPTED') AND environment = 'PROD'
                """).query((rs, n) -> new Finding("drift:" + rs.getLong("finding_id"),
                rs.getString("rule_id") + " · " + rs.getString("resource_address"),
                OverviewItem.severity(rs.getString("severity")), null, Hint.NONE,
                instant(rs.getObject("first_seen_at", OffsetDateTime.class)))).list());
        Instant last = jdbc.sql("""
                SELECT max(finished_at) FROM iac_jobs
                WHERE status = 'SUCCEEDED' AND kind IN ('COLLECT_GRAPH', 'ENRICH_GRAPH', 'CHECK_DRIFT')
                """).query((rs, n) -> instant(rs.getObject(1, OffsetDateTime.class))).list().getFirst();
        String status = findings.isEmpty() && last == null ? "NO_DATA" : "CONNECTED";
        return new Result(part(), status, findings, last == null ? List.of() : List.of(Coverage.all(last)), null);
    }

    static Instant instant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }
}
