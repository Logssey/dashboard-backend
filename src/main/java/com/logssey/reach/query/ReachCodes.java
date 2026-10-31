package com.logssey.reach.query;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** Reach 열거값. V34 CHECK 제약과 같다. 순서는 화면·명세 순서 */
final class ReachCodes {
    static final List<String> STATUSES = List.of("REACHABLE", "UNKNOWN", "UNREACHABLE", "NOT_ANALYZED");
    static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN");
    static final List<String> METHODS = List.of("CALLGRAPH", "RULE", "MANUAL");
    static final List<String> REVIEW_STATES = List.of("UNREVIEWED", "PROVISIONAL", "CONFIRMED");
    static final List<String> DEPLOYMENTS = List.of("RUNNING", "NOT_RUNNING", "UNKNOWN");

    /** API 명세 3-11의 네 사유. ANALYSIS_TIMEOUT은 명세에 아직 없어 0으로 채우지 않는다 */
    static final List<String> NOT_ANALYZED_REASONS =
        List.of("NO_VULN_FUNCTION_DATA", "OS_PACKAGE", "UNANALYZED_COPY", "UNSUPPORTED_ECOSYSTEM");
    
    /** null이면 빈 목록, 허용 밖 값이면 400 */
    static List<String> checked(List<String> values, List<String> allowed) {
        if (values == null) return List.of();
        for (String value : values) {
            if (!allowed.contains(value)) throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return values;
    }
    
    private ReachCodes() {}
}