package com.logssey.reach.ci;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;

/**
 * CI 검사 목록(API-12 목록) 필터. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다.
 * 한 칸 안의 값은 OR, 칸끼리는 AND. repository는 대소문자를 가리지 않고, 소유자 없이 이름만 줘도 된다(검사에는 러너가 보낸 값이 그대로 있다)
 */
record ReachCiCheckFilter(String repository, List<String> mode, List<String> scanStatus) {

    /** V37 reach_ci_checks.repository 길이 */
    private static final int REPOSITORY_MAX = 200;

    ReachCiCheckFilter {
        repository = repository == null || repository.isBlank() ? null : repository.trim();
        if (repository != null && repository.length() > REPOSITORY_MAX) throw new ApiException(ErrorCode.INVALID_INPUT);
        mode = ReachCodes.checked(mode, ReachCodes.TRIGGERS);
        scanStatus = ReachCodes.checked(scanStatus, ReachCodes.SCAN_STATUSES);
    }

    /** 소유자를 뗀 레포 이름 (Logssey/service-backend → service-backend) */
    String repositoryName() {
        return repository == null ? null : repository.substring(repository.lastIndexOf('/') + 1);
    }

    /** 커서가 이 필터로 만들어졌는지 확인하는 값. 커서와 함께 필터를 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}
