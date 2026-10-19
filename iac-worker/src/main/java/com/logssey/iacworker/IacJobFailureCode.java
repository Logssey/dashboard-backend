package com.logssey.iacworker;

/** Extend this list deliberately; never turn provider or tool error text into a stored code. */
public enum IacJobFailureCode {
    LEASE_EXPIRED,
    PROCESSOR_FAILURE,
    PLAN_MISSING,
    PLAN_INVALID,
    GRAPH_UNAVAILABLE,
    AWS_UNAVAILABLE,
    SIMULATOR_UNAVAILABLE
}
