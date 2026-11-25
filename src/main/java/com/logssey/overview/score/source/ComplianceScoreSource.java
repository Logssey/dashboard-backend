package com.logssey.overview.score.source;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.overview.OverviewItem;
import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * 컴플라이언스의 열린 위험 (ADR-D011 결정 1: 대상·환경별 최신 점검의 FAIL, 운영만). 컴플라이언스 테이블을 읽기만 한다.
 * 등급은 Prowler 점검 심각도(ADR-D011 결정 2). 실패한 자원 ARN(asset_uid)으로 자산에 붙는다(ADR-D012 결정 4).
 * 처음 발견은 같은 결과 지문이 처음 FAIL로 나온 점검 시각이다. 점검은 손으로 돌리므로 평가 기준이 30일이다
 */
@Component
public class ComplianceScoreSource implements ScoreSource {

    private static final String LATEST = """
            SELECT DISTINCT ON (target_key, environment) run_id, finished_at
            FROM compliance_runs WHERE environment = 'prod'
            ORDER BY target_key, environment, finished_at DESC, run_id DESC
            """;

    private final JdbcClient jdbc;

    public ComplianceScoreSource(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public OverviewPart part() {
        return OverviewPart.COMPLIANCE;
    }

    @Override
    public Result read(String login) {
        List<Finding> findings = jdbc.sql("WITH latest AS (" + LATEST + """
                )
                SELECT r.result_id, r.check_id, r.title, r.severity, r.asset_uid, r.fingerprint,
                       (SELECT min(r2.observed_at) FROM compliance_results r2
                        JOIN compliance_runs u2 ON u2.run_id = r2.run_id
                        WHERE r2.fingerprint = r.fingerprint AND r2.result = 'FAIL' AND u2.environment = 'prod') AS first_seen
                FROM compliance_results r JOIN latest l ON l.run_id = r.run_id
                WHERE r.result = 'FAIL'
                """).query((rs, n) -> new Finding("result:" + rs.getLong("result_id"),
                rs.getString("check_id") + " · " + rs.getString("title"), OverviewItem.severity(rs.getString("severity")),
                null, Hint.arn(rs.getString("asset_uid")),
                IacScoreSource.instant(rs.getObject("first_seen", OffsetDateTime.class)))).list();
        Instant last = jdbc.sql("WITH latest AS (" + LATEST + ") SELECT max(finished_at) FROM latest")
                .query((rs, n) -> IacScoreSource.instant(rs.getObject(1, OffsetDateTime.class))).list().getFirst();
        String status = findings.isEmpty() && last == null ? "NO_DATA" : "CONNECTED";
        return new Result(part(), status, findings, last == null ? List.of() : List.of(Coverage.all(last)), null);
    }
}
