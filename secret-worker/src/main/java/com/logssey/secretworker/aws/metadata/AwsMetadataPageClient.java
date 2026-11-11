package com.logssey.secretworker.aws.metadata;

/** A narrow, count-only boundary around approved AWS metadata listing operations. */
public interface AwsMetadataPageClient {
    default AwsMetadataPageClient observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) { return this; }

    Page listSecrets(String region, String nextToken);

    Page describeParameters(String region, String nextToken);

    Page listBuckets(String nextToken);

    /** The continuation token is kept only in memory and deliberately redacted from diagnostics. */
    record Page(int itemCount, String nextToken) {
        public Page {
            if (itemCount < 0) throw new IllegalArgumentException("Invalid AWS metadata page count");
        }

        @Override public String toString() {
            return "Page[itemCount=" + itemCount + ", hasNext=" + (nextToken != null) + "]";
        }
    }

    /** Carries a fixed code only; provider messages can contain resource identifiers. */
    final class Failure extends RuntimeException {
        private final AwsMetadataCollector.GapCode code;

        public Failure(AwsMetadataCollector.GapCode code) {
            super(code.name());
            this.code = code;
        }

        public AwsMetadataCollector.GapCode code() {
            return code;
        }
    }
}
