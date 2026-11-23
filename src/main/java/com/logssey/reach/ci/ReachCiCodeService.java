package com.logssey.reach.ci;

import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ci.auth.ReachCiAccess;
import com.logssey.reach.ci.auth.ReachCiCaller;
import com.logssey.reach.ci.dto.ReachCiCodeResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 러너가 받을 Reach 코드의 커밋 (API-12 보조). 대시보드가 지금 돌리는 dashboard-backend 커밋이다.
 * 서비스 레포의 reach.yml은 이 커밋의 분석기·판정 데이터·스크립트를 받아, 결과를 올릴 API와 늘 같은 버전으로 스캔한다.
 * 커밋은 이미지를 만들 때 넣은 LOGSSEY_BUILD_COMMIT(배포 워크플로가 머지 커밋을 준다)이고, 설정
 * logssey.reach.ci.code-commit으로 바꿀 수 있다. 모르면(로컬 실행) 404이고 러너는 저장소 변수 REACH_REF가 있어야 돈다
 */
@Service
public class ReachCiCodeService {

    private static final Pattern COMMIT = Pattern.compile("[0-9a-f]{40}");
    /** 설정이 먼저, 없으면 이미지의 환경 변수 LOGSSEY_BUILD_COMMIT(Dockerfile api 단계) */
    static final String COMMIT_SOURCE = "${logssey.reach.ci.code-commit:${LOGSSEY_BUILD_COMMIT:}}";

    private final ReachCiCheckRepository repository;
    private final ReachCiAccess access;
    private final String commit;

    public ReachCiCodeService(ReachCiCheckRepository repository, ReachCiAccess access,
                              @Value(COMMIT_SOURCE) String commit) {
        this.repository = repository;
        this.access = access;
        this.commit = commit == null ? "" : commit.trim();
    }

    /** 대시보드 세션 (ADMIN) */
    public ReachCiCodeResponse code(String loginId) {
        if (loginId == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
        return response();
    }

    /** CI 토큰. 허용된 레포의 Reach 워크플로만 */
    public ReachCiCodeResponse codeForCi(ReachCiCaller caller) {
        access.authorizeRead(caller);
        return response();
    }

    private ReachCiCodeResponse response() {
        if (!COMMIT.matcher(commit).matches()) throw new ApiException(ErrorCode.NOT_FOUND);
        return new ReachCiCodeResponse(commit);
    }
}
