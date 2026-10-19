package com.logssey.iac.query;

import java.time.Duration;
import java.time.OffsetDateTime;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

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
                new IacSummaryResponse.Metrics(repository.openPaths(1), repository.openPaths(null), null, null, null),
                repository.severityCounts(), repository.lastSucceeded("ENRICH_GRAPH").orElse(null), graphAsOf, stale);
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
        var gate = new IacPullRequestResponse.Gate("GATE_FAILED".equals(run.status()) ? "BLOCK" : "PASS",
                repository.gateFindings(run.runId()));
        return new IacPullRequestResponse(number, null, run.runId(), run.headSha(), run.status(), run.verdict(),
                run.highestSeverity(), run.checkedAt(), gate, repository.pathChanges(run.runId()),
                repository.analysisResources(run.runId()), null);
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
