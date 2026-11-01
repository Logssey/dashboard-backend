package com.logssey.reach.ci;

import java.util.List;

/**
 * API-01 본문. target과 rescanOf 중 하나만 준다. 값 검사는 ReachCiCheckService가 한다.
 * options를 빼면 crossCheck = ["GRYPE"], l1 = l2 = true (명세 API-01)
 */
public record ReachScanRequest(ReachTargetRequest target, Long rescanOf, Options options) {

    public record Options(List<String> crossCheck, Boolean l1, Boolean l2) {}
}
