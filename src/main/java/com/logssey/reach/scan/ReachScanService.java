package com.logssey.reach.scan;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.scan.dto.ReachScanResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 스캔 조회 API (API-03). 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional(readOnly = true)
public class ReachScanService {

    private final ReachScanRepository repository;

    public ReachScanService(ReachScanRepository repository) {
        this.repository = repository;
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
