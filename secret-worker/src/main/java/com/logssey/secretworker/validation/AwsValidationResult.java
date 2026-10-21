package com.logssey.secretworker.validation;

import java.time.Instant;

/** Safe metadata only: no access key, secret, session token, response body, or exception text. */
public record AwsValidationResult(Status status, Reason reason, Instant evaluatedAt, Instant checkedAt,
                                  String method, String version) {
    public enum Status { VALID, INVALID, UNKNOWN, UNCHECKED }

    public enum Reason {
        AUTHENTICATED,
        INVALID_ACCESS_KEY,
        SIGNATURE_AMBIGUOUS,
        EXPIRED_SESSION,
        DISABLED,
        SYNTHETIC_FIXTURE,
        SOURCE_GUARD_BLOCKED,
        INCOMPLETE_PAIR,
        MISSING_SESSION_TOKEN,
        ACCESS_AMBIGUOUS,
        RATE_LIMITED,
        PROVIDER_UNAVAILABLE,
        CLIENT_FAILURE,
        NOT_APPROVED,
        RATE_BUDGET_EXHAUSTED,
        APPROVAL_CHANGED,
        SOURCE_UNAVAILABLE,
        CREDENTIAL_MISMATCH
    }

    public static final String METHOD = "AWS_STS_GET_CALLER_IDENTITY";
    public static final String VERSION = "1";
}
