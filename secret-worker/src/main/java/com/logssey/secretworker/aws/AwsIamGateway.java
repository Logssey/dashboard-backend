package com.logssey.secretworker.aws;

import java.time.Instant;
import java.util.List;

/** Raw AWS identifiers exist only in the short-lived collection callback. */
public interface AwsIamGateway extends AutoCloseable {
    default AwsIamGateway observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) { return this; }

    String accountId();
    Page<String> users(String marker);
    Page<AccessKey> accessKeys(String userName, String marker);
    LastUsed lastUsed(String accessKeyId);
    int rootAccessKeyCount();

    @Override default void close() { }

    record Page<T>(List<T> items, String nextMarker) {
        @Override public String toString() {
            return "Page[count=" + (items == null ? 0 : items.size())
                    + ", hasNext=" + (nextMarker != null) + "]";
        }
    }
    record AccessKey(String id, String userName, String status, Instant createdAt) {
        @Override public String toString() { return "AccessKey[REDACTED]"; }
    }
    record LastUsed(Instant at, String service, String region) {
        @Override public String toString() { return "LastUsed[REDACTED]"; }
    }
}
