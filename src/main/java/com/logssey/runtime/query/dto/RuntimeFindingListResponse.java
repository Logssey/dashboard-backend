package com.logssey.runtime.query.dto;

import java.util.List;

public record RuntimeFindingListResponse(List<RuntimeFindingResponse> items, long totalCount) {
}
