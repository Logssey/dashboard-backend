package com.logssey.reach.ci.dto;

/** API-13 응답 (202). id는 CI 검사 ID. 지금은 저장까지 끝낸 뒤라 scanStatus가 SUCCEEDED 또는 FAILED다 */
public record ReachResultUploadResponse(long id, long scanId, String scanStatus) {}
