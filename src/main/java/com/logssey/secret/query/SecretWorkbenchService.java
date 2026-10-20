package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.snapshot.SecretReadSnapshots.*;
import com.logssey.secret.query.SecretLocationRepository.Row;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import tools.jackson.databind.ObjectMapper;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** A permission-bound frozen set backs both work cards and their destination lists. */
@Service
public class SecretWorkbenchService {
    public record Filters(String origin,String source,String provider,String environment,Long connectionId,String assignee) {
        public Filters {
            SecretInventoryFilters.require(origin,"PRODUCTION","TEST");
            new SecretInventoryFilters(origin,source,provider,environment,"ALL","ALL","ALL","ALL","ALL");
            if(connectionId!=null&&connectionId<=0||assignee!=null&&!assignee.matches("ME|UNASSIGNED|[1-9][0-9]{0,17}"))throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        public Map<String,String> normalized(){var f=new TreeMap<String,String>();f.put("origin",origin);f.put("source",source);f.put("provider",provider);f.put("environment",environment);
            if(connectionId!=null)f.put("connectionId",connectionId.toString());if(assignee!=null)f.put("assignee",assignee);return f;}
    }
    private record Metric(String key,String unit,String type,boolean allowed,List<String> ignored) {}
    private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretLocationRepository locations;
    private final SecretLocationWorkflow cases;private final SecretCoverageService coverage;private final SecretReadSnapshots snapshots;private final ObjectMapper json;
    public SecretWorkbenchService(JdbcTemplate jdbc,SecretAccessService access,SecretLocationRepository locations,SecretLocationWorkflow cases,
            SecretCoverageService coverage,SecretReadSnapshots snapshots,ObjectMapper json) {
        this.jdbc=jdbc;this.access=access;this.locations=locations;this.cases=cases;this.coverage=coverage;this.snapshots=snapshots;this.json=json;
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> summary(String login,Filters f,String snapshotId) {
        var actor=access.requirePrincipal(login);access.requireAnyRole(actor);var h=header(login,actor,f,snapshotId);
        var metrics=jdbc.query("SELECT * FROM secret_snapshot_metrics WHERE snapshot_id=? ORDER BY metric_key",(rs,n)->{
            String key=rs.getString("metric_key");var filter=new LinkedHashMap<String,Object>(f.normalized());
            filter.put("snapshotId",h.snapshotId().toString());
            filter.putAll(switch(key){
                case "ongoingCases"->Map.of("bucket","ACTION_REQUIRED","stages","OPEN,IN_PROGRESS");
                case "revalidationPendingCases"->Map.of("bucket","ACTION_REQUIRED","stages","REVALIDATION_PENDING");
                case "needsDecisionLocations"->Map.of("bucket","NEEDS_DECISION");
                case "needsCaseLinkLocations"->Map.of("bucket","NEEDS_CASE_LINK");
                case "coverageGapScopes"->Map.of("gapOnly",true);
                default->Map.of("classificationStatus","NEEDS_REVIEW");});
            return facts("key",key,"scope",key.contains("Scopes")?"coverage":"reviewQueue","unit",rs.getString("unit"),
                "value",rs.getObject("value",Long.class),"status",rs.getString("status"),"reasonCode",rs.getString("reason_code"),
                "appliedFilters",json.readValue(rs.getString("applied_filters"),Map.class),"notApplicableFilters",json.readValue(rs.getString("not_applicable_filters"),List.class),"queueFilter",filter);
        },h.snapshotId());
        var allCases=snapshots.page(h,"ResponseCase",0,Integer.MAX_VALUE);
        var counts=new LinkedHashMap<String,Long>();for(String stage:List.of("OPEN","IN_PROGRESS","REVALIDATION_PENDING","RESOLVED","RISK_ACCEPTED"))counts.put(stage,0L);
        allCases.forEach(c->counts.merge((String)c.get("stage"),1L,Long::sum));
        boolean caseAccess=access.hasAnyRole(actor,Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR));
        boolean securityAccess=access.hasAnyRole(actor,Set.of(SecretRole.SECURITY));
        var gaps=metrics.stream().filter(m->m.get("key").equals("coverageGapScopes")).findFirst().orElseThrow();
        return facts("scope","workbench","unit","Mixed","total",null,"origin",f.origin(),"filters",f.normalized(),
            "snapshotId",h.snapshotId(),"asOf",h.asOf(),"expiresAt",h.expiresAt(),"restrictedCoverage",h.restrictedCoverage(),
            "accessScope",access.hasAnyRole(actor,Set.of(SecretRole.SECURITY))?"AUTHORIZED_LOCATIONS":"ASSIGNED_LOCATIONS",
            "metrics",metrics,"caseSummary",facts("scope","currentCases","unit","ResponseCase","total",caseAccess?allCases.size():null,
                "status",caseAccess?"AVAILABLE":"NOT_AUTHORIZED","actionCounts",caseAccess?counts:null,
                "severityCounts",caseAccess?Map.of("CRITICAL",0,"HIGH",0,"MEDIUM",0,"LOW",0,"UNASSESSED",allCases.size()):null,
                "severityStatus","LEGACY_UNAVAILABLE","severityReasonCode","SEVERITY_EVIDENCE_REQUIRED"),
            "normalInventory",facts("unit","CredentialSet","status",securityAccess?"AVAILABLE":"NOT_AUTHORIZED","value",securityAccess?snapshots.count(h,"NormalCredentialSet"):null),
            "crossEnvironmentAlerts",facts("unit","CrossEnvironmentAlert","status",securityAccess?"AVAILABLE":"NOT_AUTHORIZED","value",securityAccess?snapshots.count(h,"CrossEnvironmentAlert"):null,"items",securityAccess?snapshots.page(h,"CrossEnvironmentAlert",0,20):List.of()),
            "partialCoverage","AVAILABLE".equals(gaps.get("status"))?((Number)gaps.get("value")).longValue()>0:null,
            "coverageStatus",gaps.get("status"));
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> queue(String login,Filters f,String bucket,String stages,int page,int size,String snapshotId) {
        if(page<0||page>1_000_000||size<1||size>100)throw new ApiException(ErrorCode.INVALID_INPUT);
        SecretInventoryFilters.require(bucket,"ACTION_REQUIRED","CURRENT_CASES","NEEDS_DECISION","NEEDS_CASE_LINK","NORMAL_INVENTORY","COVERAGE_GAPS","UNCLASSIFIED");
        if(stages!=null&&!Set.of("OPEN,IN_PROGRESS","REVALIDATION_PENDING","OPEN","IN_PROGRESS","RESOLVED","RISK_ACCEPTED").contains(stages))throw new ApiException(ErrorCode.INVALID_INPUT);
        var actor=access.requirePrincipal(login);access.requireAnyRole(actor);
        var required=switch(bucket){case "ACTION_REQUIRED","CURRENT_CASES"->Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR);case "COVERAGE_GAPS","UNCLASSIFIED"->Set.of(SecretRole.SECURITY,SecretRole.OPERATIONS);default->Set.of(SecretRole.SECURITY);};
        if(!access.hasAnyRole(actor,required))throw new ApiException(ErrorCode.FORBIDDEN);
        var h=header(login,actor,f,snapshotId);String type=switch(bucket){case "ACTION_REQUIRED","CURRENT_CASES"->"ResponseCase";case "NEEDS_DECISION"->"DecisionOccurrence";case "NEEDS_CASE_LINK"->"LinkOccurrence";case "NORMAL_INVENTORY"->"NormalCredentialSet";case "COVERAGE_GAPS"->"GapScope";default->"UnclassifiedScope";};
        var allowed=snapshots.page(h,type,0,Integer.MAX_VALUE).stream()
            .filter(r->!bucket.equals("ACTION_REQUIRED")||!Set.of("RESOLVED","RISK_ACCEPTED").contains(r.get("stage")))
            .filter(r->!type.equals("ResponseCase")||stages==null||Arrays.asList(stages.split(",")).contains(r.get("stage"))).toList();
        String unit=switch(type){case "ResponseCase"->"ResponseCase";case "NormalCredentialSet"->"CredentialSet";case "GapScope","UnclassifiedScope"->"Scope";default->"Occurrence";};
        return facts("items",allowed.stream().skip((long)page*size).limit(size).toList(),"total",allowed.size(),"page",page,"size",size,
            "unit",unit,"scope","reviewQueue","snapshotId",h.snapshotId(),"asOf",h.asOf(),"expiresAt",h.expiresAt(),"restrictedCoverage",h.restrictedCoverage(),
            "partialCoverage",null,"filters",f.normalized());
    }
    private Header header(String login,SecretPrincipal actor,Filters f,String supplied) {
        if(f.connectionId()!=null&&!access.canReadConnectionFacts(actor,f.connectionId())&&!access.hasConnectionRole(actor,f.connectionId(),SecretRole.REMEDIATOR))throw new ApiException(ErrorCode.FORBIDDEN);
        String revision=snapshots.authorizationRevision(actor.userId());
        if(supplied!=null&&!supplied.isBlank())return snapshots.require(supplied,actor.userId(),"WORKBENCH",f.normalized(),revision);
        var rows=locations.visible(actor.userId(),null,new SecretInventoryFilters(f.origin(),f.source(),f.provider(),f.environment(),"ALL","ALL","ALL","ALL","ALL"))
            .stream().filter(r->f.connectionId()==null||r.connectionId()==f.connectionId()).toList();
        var subjects=new ArrayList<Subject>();
        Set<Long> valid=validOccurrences(rows);
        var byKey=rows.stream().collect(Collectors.groupingBy(Row::secretId,LinkedHashMap::new,Collectors.toList()));
        var caseIds=rows.stream().map(Row::caseId).filter(Objects::nonNull).distinct().toList();
        for(long id:caseIds) {
            var member=rows.stream().filter(r->Objects.equals(r.caseId(),id)).toList();
            if(f.assignee()!=null&&member.stream().noneMatch(r->f.assignee().equals("UNASSIGNED")?r.assignedUserId()==null:
                Objects.equals(r.assignedUserId(),f.assignee().equals("ME")?actor.userId():Long.valueOf(f.assignee()))))continue;
            var c=cases.detail(id,login);c.remove("checklist");c.remove("occurrences");c.remove("capabilities");
            c.put("credentialSetId",c.get("secretId"));c.put("whyHereCode","ACTIVE_RESPONSE");c.put("nextActionCode","OPEN_CASE");
            subjects.add(new Subject("ResponseCase",id,member.getFirst().secretId(),c,member.stream().map(Row::occurrenceId).toList()));
        }
        for(Row r:rows) {
            if(!access.hasConnectionRole(actor,r.connectionId(),SecretRole.SECURITY)||r.componentState().equals("METADATA_ONLY")||!valid.contains(r.occurrenceId()))continue;
            if(r.exposure().equals("UNKNOWN")||r.requiresReassessment())subjects.add(subject("DecisionOccurrence",r,"NEEDS_REVIEW","OPEN_REVIEW"));
            else if(r.exposure().equals("ABNORMAL")&&r.caseId()==null)subjects.add(subject("LinkOccurrence",r,"CASE_LINK_REQUIRED","OPEN_REVIEW"));
        }
        for(var entry:byKey.entrySet()) {
            var keyRows=entry.getValue();Row first=keyRows.getFirst();
            if(keyRows.stream().anyMatch(r->!access.hasConnectionRole(actor,r.connectionId(),SecretRole.SECURITY)))continue;
            boolean metadata=first.componentState().equals("METADATA_ONLY");
            boolean normal=first.componentState().equals("CONFIRMED")&&keyRows.stream().allMatch(r->r.caseId()==null&&!r.requiresReassessment()&&r.exposure().equals("NORMAL")&&r.storagePolicyResult().equals("ALLOWED")&&valid.contains(r.occurrenceId()));
            if(metadata||normal)subjects.add(new Subject("NormalCredentialSet",entry.getKey(),entry.getKey(),facts("credentialSetId",entry.getKey(),"secretId",entry.getKey(),"maskedLabel",first.maskedLabel(),
                "inventorySubtype",metadata?"METADATA_ONLY":"AUTHORIZED_STORAGE","whyHereCode",metadata?"ACCESS_KEY_METADATA":"APPROVED_STORAGE","nextActionCode","OPEN_KEY"),keyRows.stream().map(Row::occurrenceId).toList()));
        }
        boolean operations=access.hasAnyRole(actor,Set.of(SecretRole.OPERATIONS,SecretRole.SECURITY));
        if(operations) {
            for(var item:allPages(p->coverage.gaps(login,f.origin(),f.source(),f.connectionId(),null,p,100)))subjects.add(new Subject("GapScope",((Number)item.get("scopeId")).longValue(),null,item));
            for(var conn:jdbc.queryForList("SELECT connection_id,provider FROM secret_connections")) {
                long id=((Number)conn.get("connection_id")).longValue();if(!access.canReadConnectionFacts(actor,id)||f.connectionId()!=null&&f.connectionId()!=id||!f.source().equals("ALL")&&!f.source().equals(conn.get("provider")))continue;
                for(var item:allPages(p->coverage.scopes(login,id,"ALL","NEEDS_REVIEW",false,p,100)))subjects.add(new Subject("UnclassifiedScope",((Number)item.get("scopeId")).longValue(),null,item));
            }
        }
        if(access.hasAnyRole(actor,Set.of(SecretRole.SECURITY))) {
            // Alert source is TEST; it is intentionally independent of the selected production origin.
            for(var alert:jdbc.queryForList("SELECT alert_id,status,credential_set_id FROM secret_cross_environment_alerts WHERE closed_at IS NULL")) {
                long id=((Number)alert.get("alert_id")).longValue();
                var ids=jdbc.queryForList("SELECT l.occurrence_id,o.connection_id FROM secret_cross_environment_alert_locations l JOIN secret_occurrences o USING(occurrence_id) WHERE l.alert_id=?",id).stream()
                    .filter(l->access.hasConnectionRole(actor,((Number)l.get("connection_id")).longValue(),SecretRole.SECURITY))
                    .map(l->((Number)l.get("occurrence_id")).longValue()).toList();
                if(!ids.isEmpty())subjects.add(new Subject("CrossEnvironmentAlert",id,((Number)alert.get("credential_set_id")).longValue(),
                    facts("alertId",id,"status",alert.get("status"),"nextActionCode","OPEN_ALERT"),ids));
            }
        }
        Header h=snapshots.create(actor.userId(),"WORKBENCH",f.normalized(),revision,!access.hasGlobalRole(actor,SecretRole.SECURITY),subjects);
        boolean security=access.hasAnyRole(actor,Set.of(SecretRole.SECURITY)),response=security||access.hasAnyRole(actor,Set.of(SecretRole.REMEDIATOR));
        List<String> na=new ArrayList<>();if(!f.provider().equals("ALL"))na.add("provider");if(!f.environment().equals("ALL"))na.add("environment");if(f.assignee()!=null)na.add("assignee");
        for(var m:List.of(new Metric("ongoingCases","ResponseCase","ResponseCase",response,List.of()),new Metric("revalidationPendingCases","ResponseCase","ResponseCase",response,List.of()),
            new Metric("needsDecisionLocations","Occurrence","DecisionOccurrence",security,List.of()),new Metric("needsCaseLinkLocations","Occurrence","LinkOccurrence",security,List.of()),
            new Metric("coverageGapScopes","Scope","GapScope",operations,na),new Metric("unclassifiedScopes","Scope","UnclassifiedScope",operations,na))) {
            var members=subjects.stream().filter(s->s.type().equals(m.type())).filter(s->!m.key().equals("ongoingCases")||Set.of("OPEN","IN_PROGRESS").contains(s.facts().get("stage")))
                .filter(s->!m.key().equals("revalidationPendingCases")||s.facts().get("stage").equals("REVALIDATION_PENDING")).toList();
            var applied=new TreeMap<>(f.normalized());m.ignored().forEach(applied::remove);
            jdbc.update("INSERT INTO secret_snapshot_metrics(snapshot_id,metric_key,unit,status,value,reason_code,applied_filters,not_applicable_filters) VALUES (?,?,?,?,?,?,?::jsonb,?::jsonb)",
                h.snapshotId(),m.key(),m.unit(),m.allowed()?"AVAILABLE":"NOT_AUTHORIZED",m.allowed()?(long)members.size():null,m.allowed()?null:"ROLE_REQUIRED",json.writeValueAsString(applied),json.writeValueAsString(m.ignored()));
            for(var s:members)jdbc.update("INSERT INTO secret_snapshot_metric_memberships(snapshot_id,metric_key,subject_type,subject_id) VALUES(?,?,?,?)",h.snapshotId(),m.key(),s.type(),s.id());
        }
        return h;
    }
    private Subject subject(String type,Row r,String why,String next){return new Subject(type,r.occurrenceId(),r.secretId(),facts("credentialSetId",r.secretId(),"secretId",r.secretId(),"occurrenceId",r.occurrenceId(),
        "caseId",r.caseId(),"maskedLabel",r.maskedLabel(),"componentState",r.componentState(),"source",r.source(),"environment",r.environment(),"origin",r.origin(),
        "presence",r.presence(),"exposure",r.exposure(),"validationStatus",r.validity()==null?"UNCHECKED":r.validity(),"severity","UNASSESSED", "safeLocationLabel","위치 #"+r.occurrenceId(),
        "whyHereCode",why,"nextActionCode",next),List.of(r.occurrenceId()));}
    private Set<Long> validOccurrences(List<Row> rows) {
        if(rows.isEmpty())return Set.of();
        return new HashSet<>(new NamedParameterJdbcTemplate(jdbc).queryForList("SELECT DISTINCT occurrence_id FROM secret_current_valid_findings WHERE occurrence_id IN (:ids)",Map.of("ids",rows.stream().map(Row::occurrenceId).toList()),Long.class));
    }
    @SuppressWarnings("unchecked") private List<Map<String,Object>> allPages(java.util.function.IntFunction<Map<String,Object>> query) {
        var out=new ArrayList<Map<String,Object>>();for(int p=0;;p++){var result=query.apply(p);var items=(List<Map<String,Object>>)result.get("items");out.addAll(items);if(out.size()>=((Number)result.get("total")).longValue()||items.isEmpty())return out;}
    }
}
