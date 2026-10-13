package com.logssey.secret.query;

import java.util.List;

public record SecretListResponse(List<SecretSummaryResponse> items, long total, int page, int size) {
}
