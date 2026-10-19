package com.logssey.iac.job;

/** enrichJobId 는 이번 기록으로 새로 등록한 보강 작업. 이미 대기 중이면 그 작업. 실패면 null. */
public record CollectGraphRunResponse(long jobId, Long enrichJobId) {
}
