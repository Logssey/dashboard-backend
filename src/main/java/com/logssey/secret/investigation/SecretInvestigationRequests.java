package com.logssey.secret.investigation;
import java.time.OffsetDateTime;
public final class SecretInvestigationRequests {
 private SecretInvestigationRequests(){}
 public record Assignment(Long assigneeUserId,OffsetDateTime dueAt,String reasonCode,Long expectedVersion,String idempotencyKey){}
 public record Evidence(String evidenceRef,String evidenceKind,OffsetDateTime observedAt,Long expectedVersion,String idempotencyKey){}
 public record Close(Long expectedVersion,Long resolvingDecisionId,Long restoredRunScopeId,String idempotencyKey){}
}
