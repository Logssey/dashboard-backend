package com.logssey.iac.job;

/** 등록한 작업. 같은 종류가 이미 대기 중이면 그 작업. */
public record JobTriggeredResponse(long jobId, String kind) {
}
