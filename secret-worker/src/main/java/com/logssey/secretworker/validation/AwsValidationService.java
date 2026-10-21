package com.logssey.secretworker.validation;

/** Validates temporary key material without retaining it after one call. */
@FunctionalInterface
public interface AwsValidationService {
    AwsValidationResult validate(AwsKeyMaterial key);

    default boolean enabled() {
        return true;
}
}
