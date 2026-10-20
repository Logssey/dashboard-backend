package com.logssey.iac.finding;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;

/**
 * 담당자·상태 변경 (API 계약 PATCH /findings/{id}). 비워 둔 값은 바꾸지 않는다.
 * status 는 OPEN·ACCEPTED(위험 수용)만. FIXED 는 다음 점검이 정한다.
 * version 은 읽었을 때의 값 (다른 사람이 먼저 바꿨으면 409).
 */
public record FindingUpdateRequest(Long assigneeUserId, Boolean unassign,
                                   @Pattern(regexp = "^(OPEN|ACCEPTED)$") String status,
                                   @NotNull @PositiveOrZero Long version) {
}
