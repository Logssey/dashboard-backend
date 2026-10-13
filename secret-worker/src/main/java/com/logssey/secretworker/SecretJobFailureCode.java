package com.logssey.secretworker;

/** Extend this list deliberately; never turn provider error text into a stored code. */
public enum SecretJobFailureCode {
    LEASE_EXPIRED,
    PROCESSOR_FAILURE,
    INCOMPLETE_RUN,
    SOURCE_UNAVAILABLE,
    SOURCE_ACCESS_DENIED,
    SOURCE_RATE_LIMITED,
    DETECTOR_TEMPORARY,
    VALIDATOR_TEMPORARY
}
