package com.logssey.secret.investigation;
import java.time.OffsetDateTime;
public final class SecretInvestigationRequests {
 private SecretInvestigationRequests(){}
 public record Assignment(Long assigneeUserId,OffsetDateTime dueAt,String reasonCode,Long expectedVersion,String idempotencyKey){}
 public record Evidence(String evidenceRef,String evidenceKind,OffsetDateTime observedAt,Long expectedVersion,String idempotencyKey){}
 public record Request(String targetType,Long targetId,String missingReasonCode,Long assigneeUserId,OffsetDateTime dueAt,String evidenceRef,Long expectedTargetVersion,String idempotencyKey){}
 public record AcceptEvidence(Long historyId,Long expectedVersion,String idempotencyKey){}
 public record Close(Long expectedVersion,Long resolvingDecisionId,Long restoredRunScopeId,String idempotencyKey,
     Long scopeOriginDecisionId,Long policyBindingId,Long acceptedEvidenceHistoryId){
  public Close(Long version,Long decision,Long run,String key){this(version,decision,run,key,null,null,null);}
 }
}
