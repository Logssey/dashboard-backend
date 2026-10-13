package com.logssey.secretworker.github;

import java.time.Duration;

/** Deliberately carries no response body, token, file content, or provider error message. */
public final class GitHubSourceException extends RuntimeException {
    public enum Code { ACCESS_DENIED, RATE_LIMITED, SOURCE_UNAVAILABLE, API_ERROR, RESPONSE_TOO_LARGE, MALFORMED_RESPONSE }

    private final Code code;
    private final int status;
    private final Duration retryAfter;

    public GitHubSourceException(Code code, int status, Duration retryAfter) {
        super(code.name());
        this.code = code;
        this.status = status;
        this.retryAfter = retryAfter;
    }

    public Code code() { return code; }
    public int status() { return status; }
    public Duration retryAfter() { return retryAfter; }
}
