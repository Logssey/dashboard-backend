package com.logssey.reach.export;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.export.dto.ReachOcsfPageResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 공통 Finding(OCSF) 내보내기 (API-11). 권한은 ADMIN (Reach API 명세 2-2) */
@Service
@Transactional(readOnly = true)
public class ReachExportService {

    /** 한 번에 주는 개수. 기본 20, 최대 100 (Reach API 명세 2-4) */
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private final ReachExportRepository repository;

    public ReachExportService(ReachExportRepository repository) {
        this.repository = repository;
    }

    /** 스캔 하나의 Finding을 상태와 상관없이 모두 준다. status를 주면 그 스캔의 판정 상태로 거른다 */
    public ReachOcsfPageResponse ocsf(String loginId, Long scanId, List<String> status, Integer size, String cursor) {
        requireAdmin(loginId);
        if (scanId == null) throw new ApiException(ErrorCode.INVALID_INPUT);   // 명세: scanId는 필수
        var statuses = ReachCodes.checked(status, ReachCodes.STATUSES);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);

        // 커서는 처음 요청의 scanId·status와 묶인다. 바꾸면 400 (명세 2-4)
        int filter = (scanId + "," + statuses).hashCode();
        var after = cursor == null ? null : ReachExportCursor.decode(cursor);
        if (after != null && after.filter() != filter) throw new ApiException(ErrorCode.INVALID_INPUT);

        String scanStatus = repository.scanStatus(scanId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        // 명세는 409 SCAN_NOT_READY다. 공통 ErrorCode에 아직 없어 같은 409인 CONFLICT를 쓴다
        if (!"SUCCEEDED".equals(scanStatus)) throw new ApiException(ErrorCode.CONFLICT);

        var rows = repository.findings(scanId, statuses, after == null ? null : after.findingId(), limit + 1);
        boolean hasNext = rows.size() > limit;    // 하나 더 가져와 다음 페이지 확인
        var page = hasNext ? rows.subList(0, limit) : rows;
        String nextCursor = hasNext
                ? new ReachExportCursor(Long.parseLong(page.get(page.size() - 1).findingInfo().uid()), filter).encode()
                : null;
        return new ReachOcsfPageResponse(page, nextCursor, hasNext);
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
