package com.logssey.secret.run;

import java.time.OffsetDateTime;

/** Safe snapshotted scope. Never exposes approved_ref, account, ARN, path or credentials. */
public record SecretRunScopeResultResponse(
        long runScopeId, String contentType, String region, String collectionStatus,
        Long objectCount, String gapCode, Long scopeId, Long scopeRevision,
        String safeDisplayAlias, String scopeOutcome, Stage collection, Stage detection,
        Stage validation, OffsetDateTime startedAt, OffsetDateTime finishedAt, boolean retryable,
        int excludedObjectCount) {
    public SecretRunScopeResultResponse(long runScopeId, String contentType, String region, String collectionStatus,
            Long objectCount, String gapCode, Long scopeId, Long scopeRevision, String safeDisplayAlias,
            String scopeOutcome, Stage collection, Stage detection, Stage validation,
            OffsetDateTime startedAt, OffsetDateTime finishedAt, boolean retryable) {
        this(runScopeId,contentType,region,collectionStatus,objectCount,gapCode,scopeId,scopeRevision,
                safeDisplayAlias,scopeOutcome,collection,detection,validation,startedAt,finishedAt,retryable,0);
    }
    public SecretRunScopeResultResponse(long runScopeId, String contentType, String region,
            String collectionStatus, Long objectCount, String gapCode) {
        this(runScopeId,contentType,region,collectionStatus,objectCount,gapCode,null,null,
            "범위 #"+runScopeId,"UNKNOWN",null,null,null,null,null,false);
    }
    public record Stage(String status, String reasonCode, boolean required, OffsetDateTime observedAt) { }
}
