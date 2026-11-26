package com.logssey.overview.score.source;

import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.overview.OverviewItem;
import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * 코드 취약점의 열린 위험 (ADR-D011 결정 1: 레포·도구별 최신 검사). 코드 테이블을 읽기만 한다.
 * 레포와 파일 경로로 자산에 붙는다(.github/ 아래는 배포 경로). 처음 발견 시각이 저장되지 않아 null이다(기한 지표에서 빠진다).
 * 검사 범위는 레포마다이고, 마지막 성공은 그 레포의 가장 최근 검사다
 */
@Component
public class CodeScoreSource implements ScoreSource {

    private final JdbcClient jdbc;

    public CodeScoreSource(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public OverviewPart part() {
        return OverviewPart.CODE;
    }

    @Override
    public Result read(String login) {
        List<Finding> findings = jdbc.sql("""
                SELECT s.repository, s.tool, f.seq, f.rule_id, f.severity, f.path, f.line
                FROM code_findings f JOIN code_scans s ON s.scan_id = f.scan_id
                """).query((rs, n) -> {
            String rule = rs.getString("rule_id");
            return new Finding(rs.getString("repository") + "|" + rs.getString("tool") + "|" + rs.getInt("seq"),
                    rule.substring(rule.lastIndexOf('.') + 1) + " · " + rs.getString("path"),
                    OverviewItem.severity(rs.getString("severity")), null,
                    Hint.repo(rs.getString("repository"), rs.getString("path")), null);
        }).list();
        List<Coverage> coverage = jdbc.sql("SELECT repository, max(scanned_at) AS last FROM code_scans GROUP BY repository")
                .query((rs, n) -> new Coverage(Hint.repo(rs.getString("repository"), null),
                        IacScoreSource.instant(rs.getObject("last", OffsetDateTime.class)))).list();
        return new Result(part(), coverage.isEmpty() ? "NO_DATA" : "CONNECTED", findings, coverage, null);
    }
}
