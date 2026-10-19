package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretChecklistItem(long itemId, String guideVersion, String itemCode,
                                  String status, String evidenceRef,
                                  OffsetDateTime completedAt, Long completedByUserId,
                                  OffsetDateTime updatedAt) {
}
