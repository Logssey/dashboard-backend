package com.logssey.reach.ci.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** API-12 결과 조회·목록 항목. gate·findingsUrl은 스캔이 SUCCEEDED일 때만 있다 (명세 6-3: FAILED면 gate가 없다) */
public record ReachCiCheckResponse(
        long id, String mode, String repository, String headCommit, PullRequest pullRequest,
        long scanId, String scanStatus, String policy, Long baselineScanId,
        Gate gate, String findingsUrl, OffsetDateTime createdAt, OffsetDateTime finishedAt) {

    public record PullRequest(int number, String baseRef, String headRef) {}

    /** result는 PASS / WARN / FAIL, exitCode는 FAIL이면 1 (명세 6-2) */
    public record Gate(String result, int exitCode, List<Reason> reasons, NewFindings newFindings) {}

    public record Reason(String condition, long count, String summary) {}

    /** 기준 스캔에 없던 purl × CVE. byStatus는 0까지 채운다 */
    public record NewFindings(long total, Map<String, Long> byStatus) {}
}
