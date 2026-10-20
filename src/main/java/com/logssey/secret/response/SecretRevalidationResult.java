package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretRevalidationResult(long revalidationId, long occurrenceId, long runId,
                                       String jobStatus, String result, String failureCode,
                                       OffsetDateTime requestedAt, OffsetDateTime finishedAt,boolean canViewRun) {
    public SecretRevalidationResult(long revalidationId,long occurrenceId,long runId,String jobStatus,String result,String failureCode,OffsetDateTime requestedAt,OffsetDateTime finishedAt){
        this(revalidationId,occurrenceId,runId,jobStatus,result,failureCode,requestedAt,finishedAt,false);
    }
    SecretRevalidationResult withRunAccess(boolean allowed){return new SecretRevalidationResult(revalidationId,occurrenceId,runId,jobStatus,result,failureCode,requestedAt,finishedAt,allowed);}
}
