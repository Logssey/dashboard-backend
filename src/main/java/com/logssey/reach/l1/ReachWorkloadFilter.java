package com.logssey.reach.l1;

import java.util.List;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;

/**
 * 워크로드 목록(API-07) 필터. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다.
 * 한 칸 안의 값은 OR, 칸끼리는 AND. enum·digest 형식이 틀리면 INVALID_INPUT(400).
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
        app = ReachCodes.checked(app, ReachCodes.APPS);
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
