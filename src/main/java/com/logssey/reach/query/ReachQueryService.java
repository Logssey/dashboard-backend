package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.query.dto.ReachFindingPageResponse;
import com.logssey.reach.query.dto.ReachFindingResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 대시보드 조회 API (API-04·05·08). 권한은 ADMIN (Reach API 명세 2-2). */
@Service
@Transactional(readOnly = true)
public class ReachQueryService {

    private final ReachQueryRepository repository;

    public ReachQueryService(ReachQueryRepository repository) {
        this.repository = repository;
    }

    public ReachFindingPageResponse findings(String loginId) {
        requireAdmin(loginId);
        var items = repository.findings();
        return new ReachFindingPageResponse(items, null, false, (long) items.size());
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