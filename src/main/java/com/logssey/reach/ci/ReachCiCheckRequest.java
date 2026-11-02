package com.logssey.reach.ci;

/**
 * API-12 실행 본문. 값 검사는 Service의 validate()가 한다.
 * target과 rescanOf 중 하나만 준다. baselineScanId가 없으면 기준 스캔 없이(모든 Finding을 새 것으로) 본다
 */
public record ReachCiCheckRequest(
        String mode,
        String repository,
        String headCommit,
        PullRequest pullRequest,
        ReachTargetRequest target,
        Long rescanOf,
        String policy,
        Long baselineScanId) {

    public record PullRequest(Integer number, String baseRef, String headRef) {}
}
