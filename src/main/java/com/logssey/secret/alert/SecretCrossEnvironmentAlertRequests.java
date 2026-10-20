package com.logssey.secret.alert;
import java.time.OffsetDateTime;
import java.util.List;
public final class SecretCrossEnvironmentAlertRequests {
 private SecretCrossEnvironmentAlertRequests(){}
 public record Assignment(Long assigneeUserId,OffsetDateTime dueAt,String reasonCode,Long expectedVersion,String idempotencyKey){}
 public record Acknowledge(String reasonCode,Long expectedVersion,String idempotencyKey){}
 public record Close(Long expectedVersion,String reasonCode,List<Long> fixtureAttestationIds,List<Long> correctionIds,List<Long> lifecycleEvidenceIds,Long caseId,Long investigationTaskId,String idempotencyKey){}
}
