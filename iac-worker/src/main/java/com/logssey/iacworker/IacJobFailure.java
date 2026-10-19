package com.logssey.iacworker;

import java.util.Objects;

/** A safe failure code, never a provider response or plan content. */
public class IacJobFailure extends RuntimeException {

    private final IacJobFailureCode code;
    private final boolean retryable;

    public IacJobFailure(IacJobFailureCode code, boolean retryable) {
        super("IaC job failed: " + Objects.requireNonNull(code, "code").name());
        this.code = code;
        this.retryable = retryable;
    }

    public IacJobFailureCode code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }
}
