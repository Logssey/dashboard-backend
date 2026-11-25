package com.logssey.reach.query;

import java.util.List;

import com.logssey.reach.ReachCodes;


/**
 * Finding 목록(API-04) 필터. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다 (Reach API 명세 2-5).
 * 한 칸 안의 값은 OR, 칸끼리는 AND. 허용 밖 값이면 만들 때 INVALID_INPUT(400)이다.
 * scanId·target은 기준 범위를 바꾼다. 있는지와 상태는 DB를 봐야 해서 Service가 검사한다.
 * basis는 둘 다 없을 때의 기본 범위 기준이다: RUNNING(기본, 실행 중 이미지 먼저) 또는 LATEST(최신 스캔).
 * l3는 L3 도달 수준(REGION 등)이다. L3 결과가 없는 Finding은 l3를 주면 빠진다
 */
record ReachFindingFilter(
        List<String> status,
        List<String> severity,
        List<String> reviewState,
        List<String> deployment,
        String cveContains,
        Long scanId,
        Long target,
        String basis,
        List<String> l3) {

    static final List<String> BASES = List.of("RUNNING", "LATEST");

    ReachFindingFilter {
        basis = checkedBasis(basis);
        status = ReachCodes.checked(status, ReachCodes.STATUSES);
        severity = ReachCodes.checked(severity, ReachCodes.SEVERITIES);
        reviewState = ReachCodes.checked(reviewState, ReachCodes.REVIEW_STATES);
        deployment = ReachCodes.checked(deployment, ReachCodes.DEPLOYMENTS);
        cveContains = (cveContains == null || cveContains.isBlank()) ? null : cveContains.trim();
        l3 = ReachCodes.checked(l3, ReachCodes.L3_LEVELS);
    }

    /** L3 필터 없이 */
    ReachFindingFilter(List<String> status, List<String> severity, List<String> reviewState,
                       List<String> deployment, String cveContains, Long scanId, Long target, String basis) {
        this(status, severity, reviewState, deployment, cveContains, scanId, target, basis, null);
    }

    /** 기준 범위를 지정하지 않는 필터 */
    ReachFindingFilter(List<String> status, List<String> severity, List<String> reviewState,
                       List<String> deployment, String cveContains) {
        this(status, severity, reviewState, deployment, cveContains, null, null, null);
    }

    /** basis 없이(RUNNING) */
    ReachFindingFilter(List<String> status, List<String> severity, List<String> reviewState,
                       List<String> deployment, String cveContains, Long scanId, Long target) {
        this(status, severity, reviewState, deployment, cveContains, scanId, target, null);
    }

    /** 없으면 RUNNING, 허용 밖 값이면 INVALID_INPUT(400) */
    static String checkedBasis(String basis) {
        if (basis == null || basis.isBlank()) return "RUNNING";
        return ReachCodes.checked(List.of(basis), BASES).get(0);
    }

    /** 커서가 이 필터로 만들어졌는지 확인하는 값. 커서와 함께 필터를 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}