package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;
import com.logssey.reach.query.dto.ReachFindingPageResponse;
import com.logssey.reach.query.dto.ReachSummaryResponse;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 대시보드 조회 API (API-04·05·08). 권한은 ADMIN (Reach API 명세 2-2). */
@Service
@Transactional(readOnly = true)
public class ReachQueryService {

    /** 목록 한 번에 주는 개수. 기본 20, 최대 100 (Reach API 명세 2-4) */
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private final ReachQueryRepository repository;

    public ReachQueryService(ReachQueryRepository repository) {
        this.repository = repository;
    }

    public ReachFindingPageResponse findings(String loginId, ReachFindingFilter filter,
                                             Integer size, String cursor, String include) {
        requireAdmin(loginId);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (include != null && !include.equals("total")) throw new ApiException(ErrorCode.INVALID_INPUT);

        var after = cursor == null ? null : ReachFindingCursor.decode(cursor);
        if (after != null && after.filter() != filter.fingerprint()) throw new ApiException(ErrorCode.INVALID_INPUT);

        var rows = repository.findings(filter, after, limit + 1);    // 하나 더 가져와 다음 페이지 확인
        boolean hasNext = rows.size() > limit;
        var page = hasNext ? rows.subList(0, limit) : rows;

        String nextCursor = null;
        if (hasNext) {
            var last = page.get(page.size() - 1);
            nextCursor = new ReachFindingCursor(last.statusRank(), last.severityRank(), last.cveYear(),
                    last.cveNumber(), last.item().id(), filter.fingerprint()).encode();
        }
        Long totalCount = "total".equals(include) ? repository.countFindings(filter) : null;
        return new ReachFindingPageResponse(page.stream().map(ReachQueryRepository.Row::item).toList(),
                nextCursor, hasNext, totalCount);
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        if (!repository.isAdmin(loginId)) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    public ReachSummaryResponse summary(String loginId, List<String> deployment, List<String> include) {
        requireAdmin(loginId);
        var deployments = ReachCodes.checked(deployment, ReachCodes.DEPLOYMENTS);
        var includes = ReachCodes.checked(include, List.of("matrix"));

        // 명세: 모든 값을 0까지 준다. LinkedHashMap은 넣은 순서를 지킨다
        var byStatus = zeros(ReachCodes.STATUSES);
        var byReason = zeros(ReachCodes.NOT_ANALYZED_REASONS);
        var bySeverity = zeros(ReachCodes.SEVERITIES);
        var byMethod = zeros(ReachCodes.METHODS);
        var byReviewState = zeros(ReachCodes.REVIEW_STATES);
        var byDeployment = zeros(ReachCodes.DEPLOYMENTS);
        var matrix = new LinkedHashMap<String, Map<String, Long>>();   // 0인 칸은 넣지 않는다
        long total = 0;

        for (var row : repository.summaryRows(deployments)) {
            long n = row.count();
            total += n;
            byStatus.merge(row.status(), n, Long::sum);
            bySeverity.merge(row.severity(), n, Long::sum);
            byReviewState.merge(row.reviewState(), n, Long::sum);
            byDeployment.merge(row.deployment(), n, Long::sum);
            if (row.method() != null) byMethod.merge(row.method(), n, Long::sum);              // NOT_ANALYZED는 방식 없음
            if (row.notAnalyzedReason() != null) byReason.merge(row.notAnalyzedReason(), n, Long::sum);
            matrix.computeIfAbsent(row.severity(), k -> new LinkedHashMap<>()).merge(row.status(), n, Long::sum);
            }

        long unreachable = byStatus.get("UNREACHABLE");
        long judged = byStatus.get("REACHABLE") + unreachable + byStatus.get("UNKNOWN");   // NOT_ANALYZED 제외 (PRD M-01)
        return new ReachSummaryResponse(
                new ReachSummaryResponse.Scope(null, null),
                new ReachSummaryResponse.Totals(total),
                byStatus, byReason, bySeverity, byMethod, byReviewState, byDeployment,
                includes.contains("matrix") ? matrix : null,
                new ReachSummaryResponse.NoiseReduction(unreachable, judged, ratio(unreachable, judged)),
                new ReachSummaryResponse.Coverage(judged, total, ratio(judged, total)),
                OffsetDateTime.now());
    }

    private static Map<String, Long> zeros(List<String> keys) {
        var map = new LinkedHashMap<String, Long>();
        keys.forEach(key -> map.put(key, 0L));
        return map;
    }

    /** 소수 셋째 자리 반올림, 분모 0이면 null (명세 API-08) */
    private static Double ratio(long numerator, long denominator) {
        return denominator == 0 ? null : Math.round(numerator * 1000.0 / denominator) / 1000.0;
    }

    /** API-05. 없는 id면 404 */
    public ReachFindingDetailResponse finding(String loginId, long findingId) {
        requireAdmin(loginId);
        return repository.finding(findingId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }
}