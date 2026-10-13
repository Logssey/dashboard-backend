package com.logssey.secret.run;

/** Safe collection coverage for one approved scope; no account or resource identifier. */
public record SecretRunScopeResultResponse(
        long runScopeId,
        String contentType,
        String region,
        String collectionStatus,
        Long objectCount,
        String gapCode) {
}
