package com.logssey.reach.scan;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.scan.dto.ReachScanPageResponse;
import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 스캔 조회 API (API-02 이력, API-03 상세). 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional(readOnly = true)
public class ReachScanService {

    /** 목록 한 번에 주는 개수. 기본 20, 최대 100 (Reach API 명세 2-4) */
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private final ReachScanRepository repository;

    public ReachScanService(ReachScanRepository repository) {
        this.repository = repository;
    }

    /** API-02. 항목은 상세(API-03)와 같은 모양이고, counts는 SUCCEEDED 항목에만 있다 */
    public ReachScanPageResponse scans(String loginId, ReachScanFilter filter, Integer size, String cursor,
                                       String include) {
        requireAdmin(loginId);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (include != null && !include.equals("total")) throw new ApiException(ErrorCode.INVALID_INPUT);

        var after = cursor == null ? null : ReachScanCursor.decode(cursor);
        if (after != null && after.filter() != filter.fingerprint()) throw new ApiException(ErrorCode.INVALID_INPUT);
        // 없는 대상을 지정하면 빈 목록이 아니라 404 (명세 2-6 NOT_FOUND: target을 지정한 조회)
        if (filter.target() != null && !repository.targetExists(filter.target())) {
            throw new ApiException(ErrorCode.NOT_FOUND);
        }

        var rows = repository.scans(filter, after, limit + 1);    // 하나 더 가져와 다음 페이지 확인
        boolean hasNext = rows.size() > limit;
        var page = hasNext ? rows.subList(0, limit) : rows;

        // 페이지의 SUCCEEDED 스캔을 쿼리 한 번으로 센다. 스캔마다 세면 페이지 크기만큼 쿼리가 더 나간다(N+1)
        var succeeded = page.stream().map(ReachScanRepository.Row::item)
                .filter(scan -> "SUCCEEDED".equals(scan.scanStatus()))
                .map(ReachScanResponse::id)
                .toList();
        var counts = counts(succeeded);
        var items = page.stream().map(ReachScanRepository.Row::item)
                .map(scan -> counts.containsKey(scan.id()) ? scan.withCounts(counts.get(scan.id())) : scan)
                .toList();

        String nextCursor = null;
        if (hasNext) {
            var last = page.get(page.size() - 1);
            nextCursor = new ReachScanCursor(last.sortKey(), last.item().id(), filter.fingerprint()).encode();
        }
        Long totalCount = "total".equals(include) ? repository.countScans(filter) : null;
        return new ReachScanPageResponse(items, nextCursor, hasNext, totalCount);
    }

    /** API-03. 없는 id면 404. 실행 중·실패한 스캔은 counts 없이 준다 (명세 3-1) */
    public ReachScanResponse scan(String loginId, long scanId) {
        requireAdmin(loginId);
        var scan = repository.scan(scanId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!"SUCCEEDED".equals(scan.scanStatus())) return scan;
        return scan.withCounts(counts(List.of(scanId)).get(scanId));
    }

    /** 스캔마다 개수를 0까지 채워 합친다. 판정이 0건인 스캔도 빈 값이 아니라 0으로 나온다 */
    private Map<Long, ReachScanResponse.Counts> counts(List<Long> scanIds) {
        var result = new LinkedHashMap<Long, ReachScanResponse.Counts>();
        for (long id : scanIds) {
            result.put(id, new ReachScanResponse.Counts(0, zeros(ReachCodes.SEVERITIES), zeros(ReachCodes.STATUSES),
                    zeros(ReachCodes.REVIEW_STATES)));
        }
        for (var row : repository.countRows(scanIds)) {
            var counts = result.get(row.scanId());
            counts.bySeverity().merge(row.severity(), row.count(), Long::sum);
            counts.byStatus().merge(row.status(), row.count(), Long::sum);
            counts.byReviewState().merge(row.reviewState(), row.count(), Long::sum);
        }
        // total은 상태별 개수의 합
        result.replaceAll((id, counts) -> new ReachScanResponse.Counts(
                counts.byStatus().values().stream().mapToLong(Long::longValue).sum(),
                counts.bySeverity(), counts.byStatus(), counts.byReviewState()));
        return result;
    }

    /** LinkedHashMap은 넣은 순서(화면·명세 순서)를 지킨다 */
    private static Map<String, Long> zeros(List<String> keys) {
        var map = new LinkedHashMap<String, Long>();
        keys.forEach(key -> map.put(key, 0L));
        return map;
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
