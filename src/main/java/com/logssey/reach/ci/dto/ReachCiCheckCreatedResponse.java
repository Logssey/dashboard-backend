package com.logssey.reach.ci.dto;

import java.time.OffsetDateTime;

/** API-12 실행 응답 (202). 같은 멱등 키로 다시 보내면 같은 검사를 지금 상태로 다시 준다 */
public record ReachCiCheckCreatedResponse(long id, String mode, long scanId, String scanStatus, String policy,
                                          OffsetDateTime createdAt) {}
