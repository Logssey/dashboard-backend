package com.logssey.reach.query;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource;

import org.springframework.stereotype.Component;

/**
 * 이미지 취약점(Reach)을 통합 현황 보안 점수에 넘긴다 (dashboard-design-docs ADR-D012 결정 1 "이미지 등급").
 * 실행 중 이미지(L1 조회가 신선할 때)의 PR이 아닌 최신 성공 스캔 Finding이고, 등급·감점은 {@link ReachRiskGrade}다
 * (도달 × 실행 × 스캐너 심각도, 구간 안은 CVSS). 앱으로 워크로드 자산에 붙는다.
 * 평가 시각은 L1 조회 시각이다(48시간 기준). L1이 끊기면 마지막 범위를 그대로 넘기고 계산기가 평가 끊김으로 본다.
 * L1이 꺼진 설치는 스캔 시각을 쓴다
 */
@Component
public class ReachScoreSource implements ScoreSource {

    private final ReachQueryService query;

    public ReachScoreSource(ReachQueryService query) {
        this.query = query;
    }

    @Override
    public OverviewPart part() {
        return OverviewPart.VULNERABILITY;
    }

    @Override
    public Result read(String login) {
        var scope = query.scoreScope();
        List<Finding> findings = new ArrayList<>();
        for (var row : scope.rows()) {
            var risk = ReachRiskGrade.of(row.severity(), row.status(), row.deployment(), row.cvssScore());
            findings.add(new Finding("finding:" + row.findingId(), row.vulnerabilityId() + " · " + row.componentName(),
                    risk.grade(), risk.deduction(), Hint.app(row.app()), instant(row.firstFoundAt())));
        }
        List<Coverage> coverage = new ArrayList<>();
        scope.scannedApps().forEach((app, scannedAt) -> coverage.add(new Coverage(Hint.app(app),
                instant(scope.observedAt() != null ? scope.observedAt() : scannedAt))));
        String status = coverage.isEmpty() ? "NO_DATA" : "CONNECTED";
        return new Result(part(), status, findings, coverage, null);
    }

    private static Instant instant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }
}
