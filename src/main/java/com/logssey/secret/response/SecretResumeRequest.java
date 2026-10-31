package com.logssey.secret.response;
public record SecretResumeRequest(Long occurrenceId,Long expectedCaseVersion,Long expectedOccurrenceVersion,String reasonCode,String idempotencyKey) {
 public SecretResumeRequest(Long occurrenceId,Long expectedVersion,String reasonCode){this(occurrenceId,expectedVersion,null,reasonCode,null);}
}
