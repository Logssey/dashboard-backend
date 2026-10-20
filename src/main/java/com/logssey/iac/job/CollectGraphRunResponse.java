package com.logssey.iac.job;

/** 이번 기록으로 등록한 보강·State 점검 작업. 이미 대기 중이면 그 작업, 수집이 실패했으면 null. */
public record CollectGraphRunResponse(long jobId, Long enrichJobId, Long stateJobId) {
}
