package com.logssey.secret.response;

import java.util.List;

public record SecretCaseListResponse(List<SecretCaseSummary> items, long total, int page, int size) {
}
