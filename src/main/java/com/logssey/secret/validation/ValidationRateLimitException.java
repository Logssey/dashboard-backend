package com.logssey.secret.validation;

/** Controlled request budget; contains no target or provider material. */
public final class ValidationRateLimitException extends RuntimeException {
    public ValidationRateLimitException() {
        super("RATE_BUDGET_EXHAUSTED");
    }
}
