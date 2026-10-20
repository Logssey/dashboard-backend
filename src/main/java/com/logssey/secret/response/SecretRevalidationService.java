package com.logssey.secret.response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import static com.logssey.secret.command.SecretCommandExecutor.requireExpectedVersion;
@Service
public class SecretRevalidationService {
 private final SecretRevalidationRepository repository; private final SecretAccessService access;
 private final SecretLocationWorkflow workflow; private final SecretLocationReadiness readiness;
 private final SecretCommandExecutor commands; private final SecretReadSnapshots snapshots; private final JdbcTemplate jdbc;
 public SecretRevalidationService(SecretRevalidationRepository repository,SecretAccessService access,SecretLocationWorkflow workflow,
   SecretLocationReadiness readiness,SecretCommandExecutor commands,SecretReadSnapshots snapshots,JdbcTemplate jdbc){
  this.repository=repository;this.access=access;this.workflow=workflow;this.readiness=readiness;this.commands=commands;this.snapshots=snapshots;this.jdbc=jdbc;
 }
 public SecretRevalidationResult request(long caseId,SecretRevalidationRequest r,String login){
  var actor=access.requirePrincipal(login);if(r==null||r.occurrenceId()==null||r.occurrenceId()<=0||r.expectedCaseVersion()==null||r.expectedOccurrenceVersion()==null)invalid();
  long occurrence=r.occurrenceId();
  var result=commands.execute(actor,SecretCommandExecutor.Kind.LOCATION_REVALIDATE,r.idempotencyKey(),digest(caseId,r),
   ()->requireAssigned(actor,caseId,occurrence),()->{
    var t=repository.lockTarget(caseId,occurrence).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
    requireExpectedVersion(r.expectedCaseVersion(),t.version());requireExpectedVersion(r.expectedOccurrenceVersion(),t.occurrenceVersion());
    if(!Boolean.TRUE.equals(readiness.capabilities(actor,caseId,occurrence).get("canRequestRevalidation")))conflict();
    var action=repository.latestAction(caseId,occurrence).orElseThrow(()->new ApiException(ErrorCode.CONFLICT));
    var baseline=repository.baseline(occurrence).orElse(new SecretRevalidationRepository.Baseline(null,null));
    String key="R"+HexFormat.of().formatHex(digest(caseId,actor.userId(),r.idempotencyKey()));
    var v=repository.reserve(t,action,baseline,actor.userId(),key);snapshots.invalidateOccurrence(occurrence);
    activity(caseId,occurrence,"REVALIDATION_REQUESTED",actor.userId(),t.version()+1,t.occurrenceVersion()+1,v.revalidationId());
    return new SecretCommandResult(v.revalidationId(),t.version()+1,SecretCommandResult.Status.PENDING);
   });
  return repository.list(caseId).stream().filter(v->v.revalidationId()==result.targetId()).findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
 }
 @Transactional(readOnly=true)
 public List<SecretRevalidationResult> list(long caseId,String login){
  var actor=access.requirePrincipal(login);var allowed=workflow.visibleLocations(caseId,actor).stream().map(o->((Number)o.get("occurrence_id")).longValue()).collect(java.util.stream.Collectors.toSet());
  if(allowed.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
  return repository.list(caseId).stream().filter(v->allowed.contains(v.occurrenceId())).toList();
 }
 public SecretCaseDetail resolve(long caseId,SecretResolveRequest request,String login){workflow.rejectLegacy(caseId,login);throw new ApiException(ErrorCode.CONFLICT);}
 public Map<String,Object> resume(long caseId,SecretResumeRequest r,String login){
  var actor=access.requirePrincipal(login);if(r==null||r.occurrenceId()==null||!"REVALIDATION_PRESENT".equals(r.reasonCode())||r.expectedCaseVersion()==null||r.expectedOccurrenceVersion()==null)invalid();
  long occurrence=r.occurrenceId();
  commands.execute(actor,SecretCommandExecutor.Kind.LOCATION_RESUME,r.idempotencyKey(),digest(caseId,r),()->requireAssigned(actor,caseId,occurrence),()->{
   var t=repository.lockTarget(caseId,occurrence).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
   requireExpectedVersion(r.expectedCaseVersion(),t.version());requireExpectedVersion(r.expectedOccurrenceVersion(),t.occurrenceVersion());
   if(!Boolean.TRUE.equals(readiness.capabilities(actor,caseId,occurrence).get("canResume")))conflict();
   var v=repository.latestForResume(caseId,occurrence).orElseThrow(()->new ApiException(ErrorCode.CONFLICT));
   if(!"PRESENT".equals(v.status())||!Objects.equals(v.actionId(),v.latestActionId()))conflict();
   repository.resume(t,actor.userId(),v.revalidationId());snapshots.invalidateOccurrence(occurrence);
   activity(caseId,occurrence,"REVALIDATION_RESUMED",actor.userId(),t.version()+1,t.occurrenceVersion()+1,v.revalidationId());
   return new SecretCommandResult(caseId,t.version()+1,SecretCommandResult.Status.IN_PROGRESS);
  });return workflow.detail(caseId,login);
 }
 private void requireAssigned(SecretPrincipal actor,long c,long o){if(!workflow.assignedRemediator(actor,c,o))throw new ApiException(ErrorCode.FORBIDDEN);}
 private void activity(long c,long o,String type,long actor,long cv,long ov,long ref){jdbc.update("INSERT INTO secret_location_activities(case_id,occurrence_id,activity_type,actor_user_id,case_version,occurrence_version,reference_id) VALUES(?,?,?,?,?,?,?)",c,o,type,actor,cv,ov,ref);}
 private static byte[] digest(Object... values){try{return MessageDigest.getInstance("SHA-256").digest(Arrays.deepToString(values).getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new IllegalStateException(e);}}
 private static void invalid(){throw new ApiException(ErrorCode.INVALID_INPUT);}private static void conflict(){throw new ApiException(ErrorCode.CONFLICT);}
    static boolean sufficient(SecretRevalidationRepository.ResolutionEvidence e) {
        return "REVALIDATION_PENDING".equals(e.responseStatus())
                && "MISSING".equals(e.presence())
                && e.actionId() != null && e.performedAt() != null
                && e.revalidationId() != null && "MISSING".equals(e.revalidationStatus())
                && e.actionId().equals(e.revalidationActionId())
                && e.requestedAt() != null && e.requestedAt().isAfter(e.performedAt())
                && e.finishedAt() != null && e.finishedAt().isAfter(e.performedAt())
                && !e.lastSeenAt().isAfter(e.finishedAt())
                && "SUCCEEDED".equals(e.collectionStatus())
                && ("SUCCEEDED".equals(e.detectionStatus())
                    || "SKIPPED".equals(e.detectionStatus()))
                && e.runScopeVersion() != null
                && e.runScopeVersion() == e.currentScopeVersion()
                && "ACTIVE".equals(e.connectionStatus()) && e.scopeEnabled()
                && e.caseOrigin().equals(e.responseOrigin())
                && SecretGithubScopePolicy.approved(e.contentType(), e.historyLimit(),
                        e.approvedRef());
    }

}
