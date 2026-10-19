package com.logssey.iac.query;

import java.util.List;

public record IacPathListResponse(List<IacPathResponse> items, Long nextCursor) {
}
