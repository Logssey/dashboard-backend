package com.logssey.secretworker.notion;

import java.time.Duration;

public record NotionCollectionLimits(
    int maxBlocks, int maxDepth, int maxRequests, int maxTextBytes, Duration totalTimeout) {
  public static final NotionCollectionLimits DEFAULT =
      new NotionCollectionLimits(1_000, 16, 100, 1_048_576, Duration.ofSeconds(60));

  public NotionCollectionLimits {
    if (maxBlocks < 1
        || maxBlocks > 10_000
        || maxDepth < 1
        || maxDepth > 32
        || maxRequests < 2
        || maxRequests > 1_000
        || maxTextBytes < 1
        || maxTextBytes > 1_048_576
        || totalTimeout == null
        || totalTimeout.isNegative()
        || totalTimeout.isZero()
        || totalTimeout.compareTo(Duration.ofMinutes(2)) > 0) {
      throw new IllegalArgumentException("INVALID_NOTION_COLLECTION_LIMITS");
    }
  }
}
