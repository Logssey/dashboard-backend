package com.logssey.iac.query;

import java.time.OffsetDateTime;

/** S-01 H 검사 주기와 상태. schedule 은 사람이 읽는 주기 설명 (주기 변경은 gitops·CI 에서). */
public record IacJobStatusResponse(String job, String schedule, String input, OffsetDateTime lastFinishedAt,
                                   String lastStatus, String lastErrorCode, long pending) {
}
