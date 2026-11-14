package com.logssey.reach.l1;

import java.util.List;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;

/**
 * 워크로드 목록(API-07) 필터. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다.
 * 한 칸 안의 값은 OR, 칸끼리는 AND. enum·digest 형식이 틀리면 INVALID_INPUT(400). app은 Service가 설정과 대조한다.
 * namespace는 허용 목록 밖 값이어도 400이 아니라 빈 결과다(Service가 허용 목록과 겹치는 것만 남긴다)
 */
record ReachWorkloadFilter(
        List<String> namespace,
        List<String> app,
        String digest,
        List<String> deployment) {

    private static final Pattern DIGEST = Pattern.compile("^sha256:[0-9a-f]{64}$");

    ReachWorkloadFilter {
        namespace = namespace == null ? List.of() : List.copyOf(namespace);
        app = app == null ? List.of() : List.copyOf(app);   // 앱 코드는 설정에 있어 Service가 검사한다 (PRD FR-15)
        deployment = ReachCodes.checked(deployment, ReachCodes.DEPLOYMENTS);
        if (digest != null && !DIGEST.matcher(digest).matches()) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }

    /** 커서가 이 필터로 만들어졌는지 확인하는 값. 커서와 함께 필터를 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}
