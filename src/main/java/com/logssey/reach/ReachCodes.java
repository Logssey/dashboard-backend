package com.logssey.reach;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** Reach 열거값. V34 CHECK 제약과 같다. 순서는 화면·명세 순서. query·review 등 reach 하위 패키지가 같이 쓴다 */
public final class ReachCodes {
    public static final List<String> STATUSES = List.of("REACHABLE", "UNKNOWN", "UNREACHABLE", "NOT_ANALYZED");
    public static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN");
    public static final List<String> METHODS = List.of("CALLGRAPH", "RULE", "MANUAL");
    public static final List<String> REVIEW_STATES = List.of("UNREVIEWED", "PROVISIONAL", "CONFIRMED");
    public static final List<String> DEPLOYMENTS = List.of("RUNNING", "NOT_RUNNING", "UNKNOWN");

    /** 사람이 검토로 남길 수 있는 판정. NOT_ANALYZED는 사람 판정이 아니다 (API 명세 API-06) */
    public static final List<String> HUMAN_STATUSES = List.of("REACHABLE", "UNKNOWN", "UNREACHABLE");

    /** 스캔 상태와 실행 계기 (V34 reach_scans CHECK) */
    public static final List<String> SCAN_STATUSES = List.of("QUEUED", "RUNNING", "SUCCEEDED", "FAILED");
    public static final List<String> TRIGGERS = List.of("MANUAL", "PR", "IMAGE_BUILD", "SCHEDULE");

    /** 서비스 단위 (V34 reach_targets CHECK) */
    public static final List<String> APPS = List.of("API", "WEB", "CHAT");

    /** CI 검사 게이트 정책 (V37 reach_ci_checks CHECK). 검사 mode는 스캔 trigger와 값이 같아 TRIGGERS를 쓴다 */
    public static final List<String> POLICIES = List.of("REPORT_ONLY", "GATE");

    /** 스캔 이력(API-02) 정렬. 앞에 -가 붙으면 내림차순 */
    public static final List<String> SCAN_SORTS = List.of("-createdAt", "createdAt", "-finishedAt", "finishedAt");

    /** API 명세 3-11의 네 사유. ANALYSIS_TIMEOUT은 명세에 아직 없어 0으로 채우지 않는다 */
    public static final List<String> NOT_ANALYZED_REASONS =
        List.of("NO_VULN_FUNCTION_DATA", "OS_PACKAGE", "UNANALYZED_COPY", "UNSUPPORTED_ECOSYSTEM");

    /** null이면 빈 목록, 허용 밖 값이면 400 */
    public static List<String> checked(List<String> values, List<String> allowed) {
        if (values == null) return List.of();
        for (String value : values) {
            if (!allowed.contains(value)) throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return values;
    }

    private ReachCodes() {}
}