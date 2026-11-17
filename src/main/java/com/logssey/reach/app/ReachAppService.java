package com.logssey.reach.app;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.app.dto.ReachAppListResponse;

/** API-14 감시 대상 앱. 화면의 앱 선택지가 이 목록을 쓴다 (PRD FR-15) */
@Service
@Transactional(readOnly = true)
public class ReachAppService {

    private final ReachProperties properties;
    private final ReachAppRepository repository;

    public ReachAppService(ReachProperties properties, ReachAppRepository repository) {
        this.properties = properties;
        this.repository = repository;
    }

    public ReachAppListResponse apps(String loginId) {
        if (loginId == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        if (!repository.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
        return new ReachAppListResponse(properties.apps().stream()
                .map(app -> new ReachAppListResponse.Item(app.code(), app.repo(), app.path(), app.image(), app.ecosystem()))
                .toList());
    }
}
