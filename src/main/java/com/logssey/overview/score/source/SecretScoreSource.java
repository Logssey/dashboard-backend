package com.logssey.overview.score.source;

import java.util.List;

import com.logssey.overview.OverviewItem;
import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource;
import com.logssey.secret.query.SecretOverviewProjection;

import org.springframework.stereotype.Component;

/**
 * Secret의 열린 대응 건. 기존 통합 현황과 같은 투영(SecretOverviewProjection)을 쓰므로 보는 사람의 Secret 권한 범위다.
 * 대응 건에서 노출 위치의 자산 연결을 아직 받지 않아 모두 Secret 미분류로 간다(ADR-D012 결정 4, 받아들인 위험).
 * 위험 수용: CRITICAL은 수용해도 점수에 남기고, 그 밖의 수용은 점수에서 빼고 건수로 센다(결정 5)
 */
@Component
public class SecretScoreSource implements ScoreSource {

    private final SecretOverviewProjection projection;

    public SecretScoreSource(SecretOverviewProjection projection) {
        this.projection = projection;
    }

    @Override
    public OverviewPart part() {
        return OverviewPart.SECRET;
    }

    @Override
    public Result read(String login) {
        var secret = projection.read(login, "PROD");
        if (!"AVAILABLE".equals(secret.status())) return Result.failed(part(), secret.status());
        long accepted = 0;
        var findings = new java.util.ArrayList<Finding>();
        for (var c : secret.cases()) {
            if ("NOT_APPLICABLE".equals(c.assessmentStatus())) continue;
            String grade = c.severity() == null || "UNASSESSED".equals(c.severity()) ? "UNASSESSED"
                    : OverviewItem.severity(c.severity());
            boolean acceptedCase = "RISK_ACCEPTED".equals(c.stage());
            if (acceptedCase && !"CRITICAL".equals(grade)) {
                accepted++;
                continue;
            }
            if (!c.needsAction() && !acceptedCase) continue;
            findings.add(new Finding("case:" + c.id(), c.maskedLabel(), grade, null, Hint.NONE, c.openedAt()));
        }
        var coverage = secret.lastObservedAt() == null ? List.<Coverage>of() : List.of(Coverage.all(secret.lastObservedAt()));
        String status = findings.isEmpty() && coverage.isEmpty() ? "NO_DATA" : "CONNECTED";
        return new Result(part(), status, findings, coverage, accepted);
    }
}
