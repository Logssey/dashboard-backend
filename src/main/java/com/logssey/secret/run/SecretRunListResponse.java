package com.logssey.secret.run;

import java.util.List;

public record SecretRunListResponse(List<SecretRunListItemResponse> items, long total, int page, int size) {
}
