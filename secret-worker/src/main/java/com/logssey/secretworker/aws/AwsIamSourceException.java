package com.logssey.secretworker.aws;

/** Never carries provider error text or account content. */
public final class AwsIamSourceException extends RuntimeException {
    public enum Code { ACCESS_DENIED, RATE_LIMITED, UNAVAILABLE, INVALID_RESPONSE }

    private final Code code;

    public AwsIamSourceException(Code code) {
        super(code.name());
        this.code = code;
    }

    public Code code() { return code; }
}
