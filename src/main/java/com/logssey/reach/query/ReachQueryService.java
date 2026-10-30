package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.query.dto.ReachFindingPageResponse;

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
}