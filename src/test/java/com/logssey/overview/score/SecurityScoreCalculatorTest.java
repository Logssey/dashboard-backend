package com.logssey.overview.score;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.logssey.overview.OverviewPart;
import com.logssey.overview.score.ScoreSource.Coverage;
import com.logssey.overview.score.ScoreSource.Finding;
import com.logssey.overview.score.ScoreSource.Hint;
import com.logssey.overview.score.ScoreSource.Result;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** ADR-D012의 예와 규칙을 고정 사례로 둔다. 자산은 실제 설정(score-assets.json, Σ가중치 24, Node Role 3) */
class SecurityScoreCalculatorTest {

    static final Instant NOW = Instant.parse("2026-11-26T03:00:00Z");
    static final Instant FRESH = NOW.minus(Duration.ofHours(1));
    static final String RDS_ARN = "arn:aws:rds:ap-northeast-1:794386801311:db:reused";
    static final String NODE_ROLE = "arn:aws:iam::794386801311:role/logssey-prod-role-node";
    static final Map<String, String> ARN_KINDS = Map.of(RDS_ARN, "RDS");
    static final ScoreAssets ASSETS = ScoreAssets.load();

    /** IaC 그래프와 두 레포의 코드 검사가 방금 성공한 상태. 컴플라이언스는 아직 안 돌려 Node Role만 평가 안 됨 (Σ가중치 21) */
    static List<Result> base(List<Finding> iac, List<Finding> code) {
        List<Result> results = new ArrayList<>();
        results.add(new Result(OverviewPart.IAC, "CONNECTED", iac, List.of(Coverage.all(FRESH)), null));
        results.add(new Result(OverviewPart.CODE, "CONNECTED", code, List.of(
                new Coverage(Hint.repo("Logssey/service-backend", null), FRESH),
                new Coverage(Hint.repo("Logssey/service-frontend", null), FRESH)), null));
        return results;
    }

    static Finding code(String grade, String repo, String path) {
        return new Finding(path, path, grade, null, Hint.repo(repo, path), null);
    }

    static SecurityScoreResponse calc(List<Result> results) {
        return SecurityScoreCalculator.calculate(ASSETS, ARN_KINDS, results, NOW);
    }

    @Test
    void adrExampleHighMediumHighIs72() {
        var r = calc(base(List.of(), List.of(
                code("HIGH", "Logssey/service-backend", "src/main/java/App.java"),          // API
                code("MEDIUM", "Logssey/service-backend", "chat-server/src/index.ts"),      // CHAT
                code("HIGH", "Logssey/service-backend", ".github/workflows/ci.yml"))));     // 배포 경로
        // 100 − (3×73 + 3×47 + 3×73) ÷ 21
        assertThat(r.score()).isEqualTo(72);
        assertThat(r.coverage()).isEqualTo(88);   // 21 ÷ 24
        assertThat(asset(r, "node-role").status()).isEqualTo("NOT_EVALUATED");
        assertThat(asset(r, "deploy-path").deduction()).isEqualTo(73);
        assertThat(asset(r, "chat").deduction()).isEqualTo(47);
        assertThat(r.scoreRule()).isEqualTo("ADR-D012");
    }

    @Test
    void oneCriticalOnATier1AssetIs86() {
        var path = new Finding("p1", "internet → RDS", "CRITICAL", null, Hint.arn(RDS_ARN), NOW.minus(Duration.ofDays(1)));
        var r = calc(base(List.of(path), List.of()));
        assertThat(r.score()).isEqualTo(86);   // 100 − 3×99 ÷ 21
        assertThat(asset(r, "rds").worst().grade()).isEqualTo("CRITICAL");
        assertThat(r.indicators().openCritical()).isEqualTo(1);
    }

    @Test
    void deductionsDoNotAccumulateOnOneAsset() {
        var many = new ArrayList<Finding>();
        for (int i = 0; i < 10; i++) many.add(code("HIGH", "Logssey/service-backend", "src/A" + i + ".java"));
        var one = calc(base(List.of(), List.of(code("HIGH", "Logssey/service-backend", "src/A.java"))));
        assertThat(calc(base(List.of(), many)).score()).isEqualTo(one.score());
    }

    @Test
    void lowIsNotInTheScoreButIsInTheDistribution() {
        var r = calc(base(List.of(), List.of(code("LOW", "Logssey/service-backend", "src/A.java"))));
        assertThat(r.score()).isEqualTo(100);
        assertThat(r.indicators().gradeDistribution()).containsEntry("LOW", 1L);
    }

    @Test
    void nothingEvaluatedShowsNoScore() {
        var r = calc(List.of());
        assertThat(r.score()).isNull();
        assertThat(r.coverage()).isZero();
        assertThat(r.areas()).allSatisfy(a -> assertThat(a.score()).isNull());
    }

    @Test
    void aStoppedScanKeepsTheAssetAtLeastHigh() {
        var results = new ArrayList<>(base(List.of(), List.of()));
        results.set(0, new Result(OverviewPart.IAC, "CONNECTED", List.of(),
                List.of(Coverage.all(NOW.minus(Duration.ofDays(8)))), null));
        var r = calc(results);
        // RDS·tfstate·시크릿(각 3)과 S3(2)가 평가 끊김 → 73. 100 − 73×11 ÷ 21
        assertThat(r.score()).isEqualTo(62);
        assertThat(asset(r, "rds").status()).isEqualTo("STALE");
        assertThat(r.indicators().staleAssets()).contains("회원·거래 DB(RDS)", "S3(이미지, loki-chunks, loki-ruler)");
        assertThat(r.coverage()).isEqualTo(88);   // 끊김도 평가 범위에 든다
    }

    @Test
    void unclassifiedCountsOnlyWithAScoringFinding() {
        var results = new ArrayList<>(base(List.of(), List.of()));
        results.add(new Result(OverviewPart.SECRET, "CONNECTED",
                List.of(new Finding("case:1", "AKIA****", "LOW", null, Hint.NONE, FRESH)), List.of(Coverage.all(FRESH)), 2L));
        assertThat(calc(results).score()).isEqualTo(100);   // LOW만 있는 미분류는 분모에 안 든다

        results.set(2, new Result(OverviewPart.SECRET, "CONNECTED",
                List.of(new Finding("case:1", "AKIA****", "HIGH", null, Hint.NONE, FRESH)), List.of(Coverage.all(FRESH)), 2L));
        var r = calc(results);
        assertThat(r.score()).isEqualTo(91);   // 100 − 3×73 ÷ 24
        assertThat(asset(r, "unclassified-secret").weight()).isEqualTo(3);
        assertThat(r.indicators().unclassified()).isEqualTo(1);
        assertThat(r.indicators().riskAccepted()).isEqualTo(2L);
    }

    @Test
    void unassessedCountsAsHigh() {
        var r = calc(base(List.of(), List.of(code("UNASSESSED", "Logssey/service-frontend", "src/App.tsx"))));
        assertThat(asset(r, "web").deduction()).isEqualTo(73);
        assertThat(r.indicators().unassessed()).isEqualTo(1);
    }

    @Test
    void reachDeductionInsideTheBandIsUsed() {
        var results = new ArrayList<>(base(List.of(), List.of()));
        results.add(new Result(OverviewPart.VULNERABILITY, "CONNECTED",
                List.of(new Finding("f1", "CVE-2026-1 · lib", "CRITICAL", 97, Hint.app("API"), FRESH)),
                List.of(new Coverage(Hint.app("API"), FRESH)), null));
        var r = calc(results);
        assertThat(asset(r, "api").deduction()).isEqualTo(97);
        assertThat(r.score()).isEqualTo(86);   // 100 − 3×97 ÷ 21 = 86.1
    }

    @Test
    void complianceFailOnTheNodeRoleEvaluatesIt() {
        var results = new ArrayList<>(base(List.of(), List.of()));
        results.add(new Result(OverviewPart.COMPLIANCE, "CONNECTED",
                List.of(new Finding("r1", "iam_role_admin", "HIGH", null, Hint.arn(NODE_ROLE), FRESH),
                        new Finding("r2", "cloudtrail_enabled", "MEDIUM", null, Hint.arn("arn:aws:iam::794386801311:root"), FRESH)),
                List.of(Coverage.all(NOW.minus(Duration.ofDays(20)))), null));
        var r = calc(results);
        assertThat(asset(r, "node-role").status()).isEqualTo("EVALUATED");   // 컴플라이언스는 30일 기준
        assertThat(asset(r, "node-role").deduction()).isEqualTo(73);
        assertThat(asset(r, "unclassified-compliance").deduction()).isEqualTo(47);   // 계정 단위 점검
        assertThat(r.coverage()).isEqualTo(100);
    }

    @Test
    void overdueUsesTheGradeDeadline() {
        var late = new Finding("p1", "x", "HIGH", null, Hint.arn(RDS_ARN), NOW.minus(Duration.ofDays(8)));
        var inTime = new Finding("p2", "y", "MEDIUM", null, Hint.arn(RDS_ARN), NOW.minus(Duration.ofDays(8)));
        var r = calc(base(List.of(late, inTime), List.of()));
        assertThat(r.indicators().overdue()).isEqualTo(1);
    }

    @Test
    void areasAndPartPenalty() {
        var r = calc(base(List.of(), List.of(code("HIGH", "Logssey/service-backend", ".github/workflows/ci.yml"))));
        assertThat(r.areas()).filteredOn(a -> a.area().equals("DEPLOY")).singleElement()
                .satisfies(a -> assertThat(a.score()).isEqualTo(27));
        assertThat(r.areas()).filteredOn(a -> a.area().equals("DATA")).singleElement()
                .satisfies(a -> assertThat(a.score()).isEqualTo(100));
        assertThat(r.parts()).filteredOn(p -> p.part().equals("CODE")).singleElement()
                .satisfies(p -> assertThat(p.penalty()).isEqualTo(10));   // 3×73 ÷ 21 ≈ 10.4
    }

    @Test
    void anUnreadablePartLeavesItsOnlyAssetsUnevaluated() {
        var results = new ArrayList<>(base(List.of(), List.of()));
        results.add(Result.failed(OverviewPart.COMPLIANCE, "ERROR"));
        var r = calc(results);
        assertThat(asset(r, "node-role").status()).isEqualTo("NOT_EVALUATED");
        assertThat(r.parts()).filteredOn(p -> p.part().equals("COMPLIANCE")).singleElement()
                .satisfies(p -> assertThat(p.status()).isEqualTo("ERROR"));
    }

    @Test
    void repoPathPicksTheLongestPrefix() {
        assertThat(SecurityScoreCalculator.resolve(ASSETS, ARN_KINDS, Hint.repo("Logssey/service-backend", "chat-server/a.ts")).id())
                .isEqualTo("chat");
        assertThat(SecurityScoreCalculator.resolve(ASSETS, ARN_KINDS, Hint.repo("Logssey/service-frontend", ".github/x.yml")).id())
                .isEqualTo("deploy-path");
        assertThat(SecurityScoreCalculator.resolve(ASSETS, ARN_KINDS, Hint.repo("Logssey/other", "src/a.java"))).isNull();
    }

    static SecurityScoreResponse.AssetScore asset(SecurityScoreResponse r, String id) {
        return r.assets().stream().filter(a -> a.id().equals(id)).findFirst().orElseThrow();
    }
}
