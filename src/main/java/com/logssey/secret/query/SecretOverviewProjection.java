package com.logssey.secret.query;

import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.closure.SecretClosureService;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.risk.SecretRiskQueryService;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Read-time composition only: Secret records never become detection_events. */
@Service
public class SecretOverviewProjection {
  public record Case(long id, String caseOrigin, String maskedLabel, String issuer, String environment, String stage,
      String severity, String assessmentStatus, String ownerTeam, Instant openedAt) {
    public boolean needsAction() { return Set.of("OPEN", "IN_PROGRESS", "REVALIDATION_PENDING").contains(stage); }
  }
  public record Result(String status, boolean restrictedCoverage, List<Case> cases, Instant lastObservedAt) {
    public long unassessedCount() { return cases.stream().filter(c -> "UNASSESSED".equals(c.assessmentStatus())).count(); }
    public long notApplicableCount() { return cases.stream().filter(c -> "NOT_APPLICABLE".equals(c.assessmentStatus())).count(); }
  }
  private final SecretAccessService access;
  private final SecretLocationRepository locations;
  private final SecretLocationWorkflow workflow;
  private final SecretRiskQueryService risk;
  private final SecretClosureService closure;

  public SecretOverviewProjection(SecretAccessService access, SecretLocationRepository locations,
      SecretLocationWorkflow workflow, SecretRiskQueryService risk, SecretClosureService closure) {
    this.access=access; this.locations=locations; this.workflow=workflow; this.risk=risk; this.closure=closure;
  }

  @Transactional(readOnly=true)
  public Result read(String login, String environment) {
    var actor=access.requirePrincipal(login);
    boolean restricted=!access.hasGlobalRole(actor,SecretRole.SECURITY);
    if(!access.hasAnyRole(actor,Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR)))
      return new Result("NOT_AUTHORIZED",true,List.of(),null);
    var rows=locations.visible(actor.userId(),null,
        new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL"));
    var selected=rows.stream().filter(r -> "ALL".equals(environment)||environment.equals(r.environment())).toList();
    var riskRows=new HashMap<Long,Map<String,Object>>();
    var ids=rows.stream().map(SecretLocationRepository.Row::occurrenceId).distinct().toList();
    for(int start=0;start<ids.size();start+=10000)
      riskRows.putAll(risk.occurrenceRisks(actor.userId(),ids.subList(start,Math.min(ids.size(),start+10000))));
    var cases=new ArrayList<Case>();
    for(Long id:selected.stream().map(SecretLocationRepository.Row::caseId).filter(Objects::nonNull).distinct().toList()) {
      var detail=workflow.detail(id,login);
      if(!Boolean.TRUE.equals(detail.get("isCurrent"))||!"IN_SCOPE".equals(detail.get("disposition"))
          ||!Set.of("PRODUCTION","TEST","UNCLASSIFIED").contains(detail.get("caseOrigin")))continue;
      var members=rows.stream().filter(r -> Objects.equals(r.caseId(),id)).toList();
      var evaluation=SecretRiskReadModel.summarize(members.stream().filter(r -> !"RESOLVED".equals(r.actionStatus()))
          .map(SecretLocationRepository.Row::occurrenceId).distinct().toList(),riskRows,false);
      String stage=closure.riskAcceptanceDeadline(id,login)==null?(String)detail.get("stage"):"RISK_ACCEPTED";
      var environments=selected.stream().filter(r -> Objects.equals(r.caseId(),id)).map(SecretLocationRepository.Row::environment).distinct().toList();
      String environmentLabel=environments.size()==1?environments.getFirst():"MIXED";
      Object opened=detail.get("createdAt");
      Instant openedAt=opened instanceof java.time.OffsetDateTime value?value.toInstant():((java.sql.Timestamp)opened).toInstant();
      cases.add(new Case(id,(String)detail.get("caseOrigin"),(String)detail.get("maskedLabel"),(String)detail.get("issuer"),environmentLabel,
          stage,(String)evaluation.get("severity"),(String)evaluation.get("assessmentStatus"),
          (String)detail.get("assigneeTeam"),openedAt));
    }
    Instant last=selected.stream().map(SecretLocationRepository.Row::lastSeenAt).filter(Objects::nonNull)
        .map(java.time.OffsetDateTime::toInstant).max(Comparator.naturalOrder()).orElse(null);
    return new Result("AVAILABLE",restricted,List.copyOf(cases),last);
  }
}
