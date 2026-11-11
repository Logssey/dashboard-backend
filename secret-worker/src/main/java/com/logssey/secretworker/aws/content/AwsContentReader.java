package com.logssey.secretworker.aws.content;

/** Implementations return an owned byte array. Callers must zero it after synchronous use. */
public interface AwsContentReader {
    default AwsContentReader observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) { return this; }

    byte[] read(AwsContentScope scope, int maxBytes);

    enum FailureCode { ACCESS_DENIED, NOT_FOUND, RATE_LIMITED, UNAVAILABLE, TOO_LARGE, NON_TEXT }

    /** Deliberately has no provider exception cause or message. */
    final class ReadFailure extends RuntimeException {
        private final FailureCode code;

        public ReadFailure(FailureCode code) {
            super(code.name());
            this.code = code;
        }

        public FailureCode code() { return code; }
    }
}
