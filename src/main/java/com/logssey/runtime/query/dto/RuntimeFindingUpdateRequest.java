package com.logssey.runtime.query.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record RuntimeFindingUpdateRequest(
        @Min(1) long version,
        String reviewStatus,
        String actionStatus,
        String disposition,
        Long assigneeUserId,
        @Size(max = 4000) String note) {
}
