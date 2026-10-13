package com.logssey.secretworker;

/** A future collector supplies this bean. It must finish its DB writes before returning. */
public interface SecretJobProcessor {
    void process(ClaimedSecretJob job, SecretJobExecutionService execution);

    /** Null keeps the executor's original all-provider behavior for composite processors. */
    default String provider() {
        return null;
    }
}
