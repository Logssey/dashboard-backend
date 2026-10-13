package com.logssey.secretworker;

import java.util.Objects;

/** A safe failure code, never a provider response or source content. */
public class SecretJobFailure extends RuntimeException {

    private final SecretJobFailureCode code;
    private final boolean retryable;

    public SecretJobFailure(SecretJobFailureCode code, boolean retryable) {
        super("Secret job failed: " + Objects.requireNonNull(code, "code").name());
        this.code = code;
        this.retryable = retryable;
    }

    public SecretJobFailureCode code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
