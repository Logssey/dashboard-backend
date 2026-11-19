package com.logssey.iac.query;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.iac.auth.IacCiCaller;

import org.springframework.stereotype.Service;

/** 대시보드 조회 API (S-01·S-02). 모두 ADMIN 세션. */
@Service
public class IacQueryService {

    static final Duration GRAPH_STALE_AFTER = Duration.ofHours(24);
    private static final int MAX_LIMIT = 100;

    private final IacQueryRepository repository;

    public IacQueryService(IacQueryRepository repository) {
        this.repository = repository;
    }

    public IacSummaryResponse summary(String loginId) {
        requireAdmin(loginId);
        var graphAsOf = repository.lastSucceeded("COLLECT_GRAPH").orElse(null);
        boolean stale = graphAsOf == null || graphAsOf.isBefore(OffsetDateTime.now().minus(GRAPH_STALE_AFTER));
        return new IacSummaryResponse(
                new IacSummaryResponse.Metrics(repository.openPaths(1), repository.openPaths(null),
                        repository.openDrifts(), null, mainGateViolations()),
                repository.severityCounts(), repository.lastSucceeded("ENRICH_GRAPH").orElse(null), graphAsOf, stale);
    }

    /** main 매일 점검(iac-drift)의 열린 plan 전 검사 발견 건 수. 레포가 하나가 아니거나 main 점검 기록이 없으면 null(—) */
    private Long mainGateViolations() {
        var repos = repository.enabledRepoIds(null);
        if (repos.size() != 1 || repository.latestMainRunAt(repos.getFirst()).isEmpty()) {
            return null;
        }
        return repository.mainGateFindings(repos.getFirst()).values().stream().mapToLong(Long::longValue).sum();
    }

    public IacPathListResponse paths(String status, Integer tier, Long cursor, int limit, String loginId) {
        requireAdmin(loginId);
        if (!("OPEN".equals(status) || "CLOSED".equals(status)) || (tier != null && (tier < 1 || tier > 3))
                || limit < 1 || limit > MAX_LIMIT || (cursor != null && cursor < 0)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var items = repository.paths(status, tier, cursor == null ? 0 : cursor, limit + 1);
        Long next = items.size() > limit ? items.get(limit - 1).pathId() : null;
        return new IacPathListResponse(items.subList(0, Math.min(limit, items.size())), next);
    }

    public IacPullRequestResponse pullRequest(int number, String repo, String loginId) {
        requireAdmin(loginId);
        if (number <= 0) {
            throw new ApiException(ErrorCode.NOT_FOUND);
        }
        var repos = repository.enabledRepoIds(repo);
        if (repos.size() != 1) {
            // 레포가 여럿이면 ?repo= 로 고르게 한다
            throw new ApiException(repos.isEmpty() ? ErrorCode.NOT_FOUND : ErrorCode.INVALID_INPUT);
        }
        var run = repository.latestRun(repos.getFirst(), number).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return result(number, run);
    }

    /** run 하나의 결과 (PR 상세와 같은 모양). 관리자 세션용 */
    public IacPullRequestResponse runResult(long runId, String loginId) {
        requireAdmin(loginId);
        var run = repository.run(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return result(run.prNumber() == null ? 0 : run.prNumber(), run.run());
    }

    /** CI: 토큰의 레포·실행 종류에 맞는 run 만. 아니면 없는 것처럼 404 */
    public IacPullRequestResponse runResultByCi(long runId, IacCiCaller caller) {
        var run = repository.run(runId).filter(r -> r.repo().equals(caller.repository())
                        && (r.prNumber() == null ? "PUSH" : "PR").equals(caller.trigger()))
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return result(run.prNumber() == null ? 0 : run.prNumber(), run.run());
    }

    private IacPullRequestResponse result(int number, IacQueryRepository.RunRow run) {
        var gate = new IacPullRequestResponse.Gate("GATE_FAILED".equals(run.status()) ? "BLOCK" : "PASS",
                repository.gateFindings(run.runId()));
        return new IacPullRequestResponse(number, run.title(), run.runId(), run.headSha(), run.status(), run.verdict(),
                run.highestSeverity(), run.checkedAt(), gate, repository.pathChanges(run.runId()),
                repository.resourceFindings(run.runId()),
                repository.analysisStats(run.runId(), "resources"), repository.analysisStats(run.runId(), "state"));
    }

    public List<IacDriftResponse> drifts(String status, String loginId) {
        requireAdmin(loginId);
        if (!List.of("OPEN", "FIXED", "ACCEPTED").contains(status)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return repository.drifts(status);
    }

    /** S-01 D. PR 별 최신 판정 (최근 run 순, 최대 50). */
    public List<IacPullRequestSummaryResponse> pullRequests(String repo, String loginId) {
        requireAdmin(loginId);
        var repoId = singleRepo(repo);
        if (repoId.isEmpty()) {
            return List.of();
        }
        return repository.latestPullRequestRuns(repoId.getAsLong(), 50).stream().map(row -> {
            var stats = row.stats();
            var paths = stats == null ? null : stats.path("paths");
            var state = stats == null ? null : stats.path("state");
            return new IacPullRequestSummaryResponse(row.number(), row.title(), row.runId(), row.headSha(), row.status(),
                    row.verdict(), row.highestSeverity(), row.checkedAt(),
                    paths == null ? 0 : paths.path("added").asInt(0), paths == null ? 0 : paths.path("removed").asInt(0),
                    paths == null ? 0 : paths.path("removedRoutes").asInt(0),
                    state != null && "state.reader_increase".equals(state.path("ruleId").asString(null)),
                    repository.leadingRule(row.runId()).orElse(null));
        }).toList();
    }

    public IacPathDetailResponse path(long pathId, String loginId) {
        requireAdmin(loginId);
        var path = repository.path(pathId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return new IacPathDetailResponse(path, cutPoints(path));
    }

    /** 경로에서 끊을 수 있는 관계와 그 조치 (API 계약 action 값). */
    static List<IacPathDetailResponse.CutPoint> cutPoints(IacPathResponse path) {
        List<IacPathDetailResponse.CutPoint> cuts = new java.util.ArrayList<>();
        var hops = path.hops();
        for (int i = 0; i + 1 < hops.size(); i++) {
            String from = hops.get(i).path("kind").asString("");
            String to = hops.get(i + 1).path("kind").asString("");
            String action = null;
            if (from.equals("AWSEC2Instance") && to.equals("AWSRole")) action = "IMDSV2_REQUIRED";
            else if (from.equals("AWSRole") && to.equals("AWSSecretsManagerSecret")) action = "SECRETS_READ_SCOPE";
            else if (from.equals("AWSRole") && i + 1 == hops.size() - 1 && "TFSTATE".equals(path.target().kind())) {
                action = "TFSTATE_BUCKET_POLICY";
            }
            if (action != null) cuts.add(new IacPathDetailResponse.CutPoint(i, i + 1, action, action.toLowerCase()));
        }
        return cuts;
    }

    /** S-01 G. 열린 경로를 끊는 조치(PATH)와 State 읽기 주체를 줄이는 조치(STATE). */
    public List<IacRemediationResponse> remediations(String loginId) {
        requireAdmin(loginId);
        Map<String, long[]> byAction = new java.util.LinkedHashMap<>();
        for (var path : repository.openPaths()) {
            cutPoints(path).stream().map(IacPathDetailResponse.CutPoint::action).distinct().forEach(action -> {
                long[] counts = byAction.computeIfAbsent(action, a -> new long[2]);
                counts[0]++;
                if (path.tier() == 1) counts[1]++;
            });
        }
        List<IacRemediationResponse> result = new java.util.ArrayList<>();
        byAction.forEach((action, counts) -> result.add(
                new IacRemediationResponse(action, "PATH", counts[0], counts[1], action.toLowerCase())));
        boolean tfstateReaders = repository.latestJob("CHECK_STATE")
                .map(job -> job.stats().path("readerCount").asLong(0) > 0).orElse(false);
        if (tfstateReaders && !byAction.containsKey("TFSTATE_BUCKET_POLICY")) {
            result.add(new IacRemediationResponse("TFSTATE_BUCKET_POLICY", "STATE", 0, 0, "tfstate_bucket_policy"));
        }
        result.sort((a, b) -> Long.compare(b.tier1PathsCut() * 1000 + b.pathsCut(), a.tier1PathsCut() * 1000 + a.pathsCut()));
        return result;
    }

    /** policy/gate.sh 의 관문 순서와 규칙. */
    private static final List<IacGatesResponse.Stage> STAGES = List.of(
            new IacGatesResponse.Stage("0-1", "변경 감지", List.of("gate.backend_changed", "gate.workflow_changed", "gate.lock_changed"), 0, 0),
            new IacGatesResponse.Stage("2", "정적 검사", List.of("gate.exec_data_source", "gate.provisioner", "gate.lambda_invocation",
                    "gate.provider_not_allowed", "gate.provider_unpinned", "gate.module_unpinned", "gate.unscanned_file"), 0, 0),
            new IacGatesResponse.Stage("2b", "원격 모듈 재검사", List.of("gate.module_content_changed"), 0, 0),
            new IacGatesResponse.Stage("3", "init (lock 고정)", List.of("gate.lock_mismatch"), 0, 0),
            new IacGatesResponse.Stage("4", "plan", List.of("gate.plan_failed"), 0, 0));

    /** S-01 E. */
    public IacGatesResponse gates(String repo, String loginId) {
        requireAdmin(loginId);
        var registered = singleRepo(repo);
        if (registered.isEmpty()) {
            // 레포 등록 전: 검사 기록 없음 (화면은 "main 브랜치 검사 기록이 아직 없어요")
            return new IacGatesResponse(null, STAGES, new IacGatesResponse.SupplyChain(0, 0, 0, 0));
        }
        long repoId = registered.getAsLong();
        var main = repository.mainGateFindings(repoId);
        var blocks = repository.recentPullRequestGateBlocks(repoId);
        var stages = STAGES.stream().map(s -> new IacGatesResponse.Stage(s.stage(), s.name(), s.ruleIds(),
                s.ruleIds().stream().mapToLong(r -> main.getOrDefault(r, 0L)).sum(),
                s.ruleIds().stream().mapToLong(r -> blocks.getOrDefault(r, 0L)).sum())).toList();
        return new IacGatesResponse(repository.latestMainRunAt(repoId).orElse(null), stages,
                new IacGatesResponse.SupplyChain(main.getOrDefault("gate.provider_unpinned", 0L),
                        main.getOrDefault("gate.module_unpinned", 0L), main.getOrDefault("gate.module_content_changed", 0L),
                        main.getOrDefault("gate.lock_changed", 0L)));
    }

    /** S-01 H. 주기는 대시보드 호스트 타이머·CI 워크플로가 정한다. */
    public List<IacJobStatusResponse> jobs(String loginId) {
        requireAdmin(loginId);
        return List.of(
                job("COLLECT_GRAPH", "매일 03:00 KST (대시보드 호스트)", "AWS (Cartography, 읽기 전용 수집 역할)"),
                job("ENRICH_GRAPH", "수집 뒤", "자산 그래프"),
                job("CHECK_STATE", "수집 뒤", "자산 그래프의 tfstate 읽기 권한"),
                job("CHECK_DRIFT", "매일 main plan (CI)", "refresh plan 의 resource_drift"),
                job("ANALYZE_RUN", "PR 마다", "PR plan (민감값 제거)"));
    }

    private IacJobStatusResponse job(String kind, String schedule, String input) {
        var row = repository.jobStatus(kind);
        return new IacJobStatusResponse(kind, schedule, input, row.finishedAt(), row.status(), row.lastErrorCode(),
                row.pending());
    }

    /** 검사 대상 레포. 레포를 지정하지 않았고 등록된 레포가 없으면 비어 있다 (지정한 레포가 없으면 404). */
    private OptionalLong singleRepo(String repo) {
        var repos = repository.enabledRepoIds(repo);
        if (repos.isEmpty() && repo == null) {
            return OptionalLong.empty();
        }
        if (repos.size() != 1) {
            throw new ApiException(repos.isEmpty() ? ErrorCode.NOT_FOUND : ErrorCode.INVALID_INPUT);
        }
        return OptionalLong.of(repos.getFirst());
    }

    /** S-01 F 의 State 부분. 버킷 정책·State 속 민감값은 아직 확인하지 않아 null. */
    public IacStateSummaryResponse stateSummary(String loginId) {
        requireAdmin(loginId);
        return repository.latestJob("CHECK_STATE")
                .map(job -> new IacStateSummaryResponse(job.finishedAt(), job.stats().path("readerCount").asLong(0),
                        job.stats().path("tfstate"), null, null, null))
                .orElseGet(() -> new IacStateSummaryResponse(null, 0, null, null, null, null));
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        if (!repository.isAdmin(loginId)) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }
}
