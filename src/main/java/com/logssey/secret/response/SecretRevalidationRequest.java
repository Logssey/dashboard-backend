package com.logssey.secret.response;
public record SecretRevalidationRequest(Long occurrenceId,Long expectedCaseVersion,Long expectedOccurrenceVersion,String idempotencyKey) {
 public SecretRevalidationRequest(Long occurrenceId,Long expectedVersion,String key){this(occurrenceId,expectedVersion,null,key);}
}
