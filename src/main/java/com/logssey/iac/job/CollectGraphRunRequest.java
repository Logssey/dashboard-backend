package com.logssey.iac.job;

import java.time.OffsetDateTime;
import java.util.Map;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Cartography CronJob 이 수집을 마치고 결과를 기록한다. 통계는 이름 → 개수만 받는다. */
public record CollectGraphRunRequest(
        @NotNull @Pattern(regexp = "^(SUCCEEDED|FAILED)$") String status,
        @NotNull OffsetDateTime startedAt,
        @NotNull OffsetDateTime finishedAt,
        @Size(max = 50) Map<@Pattern(regexp = "^[A-Za-z0-9_]{1,60}$") String, @NotNull Long> stats) {
}
