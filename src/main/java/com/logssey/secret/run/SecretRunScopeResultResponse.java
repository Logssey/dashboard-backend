package com.logssey.secret.run;

import java.time.OffsetDateTime;

/** Safe snapshotted scope with authorized GitHub target coordinates and no raw approval URI. */
public record SecretRunScopeResultResponse(
        long runScopeId, String contentType, String region, String collectionStatus,
        Long objectCount, String gapCode, Long scopeId, Long scopeRevision,
        String safeDisplayAlias, String scopeOutcome, Stage collection, Stage detection,
        Stage validation, OffsetDateTime startedAt, OffsetDateTime finishedAt, boolean retryable,
        int excludedObjectCount, java.util.List<ExclusionReason> exclusionReasons,
        com.logssey.secret.query.SecretSourceDetails.GitHubTarget githubTarget) {
    public SecretRunScopeResultResponse(long runScopeId, String contentType, String region, String collectionStatus,
            Long objectCount, String gapCode, Long scopeId, Long scopeRevision, String safeDisplayAlias,
            String scopeOutcome, Stage collection, Stage detection, Stage validation,
            OffsetDateTime startedAt, OffsetDateTime finishedAt, boolean retryable, int excludedObjectCount,
            java.util.List<ExclusionReason> exclusionReasons) {
        this(runScopeId,contentType,region,collectionStatus,objectCount,gapCode,scopeId,scopeRevision,
                safeDisplayAlias,scopeOutcome,collection,detection,validation,startedAt,finishedAt,retryable,
                excludedObjectCount,exclusionReasons,null);
    }
    public SecretRunScopeResultResponse(long runScopeId, String contentType, String region, String collectionStatus,
            Long objectCount, String gapCode, Long scopeId, Long scopeRevision, String safeDisplayAlias,
            String scopeOutcome, Stage collection, Stage detection, Stage validation,
            OffsetDateTime startedAt, OffsetDateTime finishedAt, boolean retryable, int excludedObjectCount) {
        this(runScopeId,contentType,region,collectionStatus,objectCount,gapCode,scopeId,scopeRevision,
                safeDisplayAlias,scopeOutcome,collection,detection,validation,startedAt,finishedAt,retryable,
                excludedObjectCount,java.util.List.of());
    }
    public record ExclusionReason(String code,long count,boolean expected) { }

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
