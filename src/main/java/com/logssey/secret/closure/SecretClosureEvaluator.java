package com.logssey.secret.closure;

import java.time.OffsetDateTime;
import java.util.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.access.SecretPrincipal;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import static com.logssey.secret.closure.SecretClosureContracts.*;
import static com.logssey.secret.closure.SecretClosureRepository.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** Computes the same immutable proof set for GET and the locked decision transaction. */
@Component
class SecretClosureEvaluator {
    final SecretClosureRepository repository;
    private final ObjectMapper json;
    SecretClosureEvaluator(SecretClosureRepository repository,ObjectMapper json) {this.repository=repository;this.json=json;}
    record Inspection(Map<String,Object> caseRow,List<Map<String,Object>> rows,List<Check> checks,
        Map<String,List<Location>> groups,List<CoverageOption> options,Map<String,Object> targetSnapshot,String version,
        Map<String,List<EvidenceReference>> dismissalEvidence,List<Long> remainingRiskIds) { }

    Inspection inspect(long id) {return inspect(id,null);}
    Inspection inspect(long id,SecretPrincipal actor) {
        var c=repository.caseRow(id,false);var rows=repository.related(id);var checks=new ArrayList<Check>();
        var groups=new LinkedHashMap<String,List<Location>>();
        for(String group:List.of("required","unlinked","unassessed","authorized","historical"))groups.put(group,new ArrayList<>());
        var risk=new ArrayList<Long>();var revalidationIds=new ArrayList<Long>();var snapshotRows=new ArrayList<Map<String,Object>>();
        boolean positionsPassed=true;
        for(var row:rows) {
            normalizePolicyClock(row);
            long occurrence=number(row,"occurrence_id");String exposure=text(row,"exposure_status");
            boolean linked=row.get("linked_case_id")!=null;
            boolean corrected=yes(row,"all_corrected")&&coverageReason(row,c)==null
                &&("PRESENT".equals(row.get("presence_status"))||row.get("historical_missing_id")!=null);
            row.put("all_corrected",corrected);
            boolean normal="NORMAL".equals(exposure)&&"ALLOWED".equals(row.get("policy_result"))&&!yes(row,"requires_reassessment");
            boolean history=row.get("historical_missing_id")!=null;
            String group,reason,status;
            if("METADATA_ONLY".equals(row.get("component_state"))) {group="authorized";reason="METADATA_NOT_EXPOSURE";status="PASSED";}
            else if(corrected) {group="historical";reason="ALL_FINDINGS_CORRECTED";status="PASSED";}
            else if(normal) {group="authorized";reason="CURRENT_POLICY_ALLOWED_STORAGE";status="PASSED";}
            else if(!linked&&history) {group="historical";reason="COMPARABLE_HISTORICAL_MISSING";status="PASSED";}
            else if("ABNORMAL".equals(exposure)) {
                risk.add(occurrence);
                if(!linked) {group="unlinked";reason="UNLINKED_ABNORMAL";status="BLOCKED";}
                else {
                    group="required";
                    boolean missing=yes(row,"comparable_post_action_missing");
                    reason=missing?"COMPARABLE_POST_ACTION_MISSING":"PRESENT".equals(row.get("presence_status"))?
                        "LOCATION_STILL_PRESENT":"POST_ACTION_COMPARISON_REQUIRED";
                    status=missing?"PASSED":"PRESENT".equals(row.get("presence_status"))?"BLOCKED":"UNKNOWN";
                    if(missing)revalidationIds.add(number(row,"revalidation_id"));
                }
            } else if(history&&!yes(row,"requires_reassessment")) {group="historical";reason="COMPARABLE_HISTORICAL_MISSING";status="PASSED";}
            else {group="unassessed";reason="UNASSESSED_CURRENT_LOCATION";status="UNKNOWN";risk.add(occurrence);}
            groups.get(group).add(new Location(occurrence,"위치 #"+occurrence,status,reason));
            checks.add(new Check("POSITION_"+group.toUpperCase(Locale.ROOT),status,reason,occurrence,
                "COMPARABLE_POST_ACTION_MISSING".equals(reason)?List.of(number(row,"revalidation_id")):List.of()));
            if(!"PASSED".equals(status))positionsPassed=false;
            if(Set.of("required","unlinked","unassessed").contains(group)) {
                String gap=coverageReason(row,c);
                checks.add(new Check("REQUIRED_SCOPE",gap==null?"PASSED":"UNKNOWN",gap==null?"CURRENT_REQUIRED_SCOPE_CHECKED":gap,occurrence,List.of()));
                if(gap!=null)positionsPassed=false;
                if(yes(row,"requires_reassessment")) {
                    checks.add(new Check("ASSESSMENT_BASIS","UNKNOWN","POLICY_OR_SOURCE_REASSESSMENT_REQUIRED",occurrence,List.of()));positionsPassed=false;
                }
            }
            snapshotRows.add(facts("occurrenceId",occurrence,"scopeId",row.get("scope_id"),"scopeRevision",row.get("revision"),
                "scopeOriginVersion",row.get("response_origin_version"),"origin",row.get("response_origin"),
                "connectionVersion",row.get("connection_version"),"connectionStatus",row.get("connection_status"),"scopeEnabled",row.get("enabled"),
                "presence",row.get("presence_status"),"exposure",exposure,"assessmentVersion",row.get("exposure_assessment_version"),
                "policyBindingId",row.get("binding_id"),"policyVersion",row.get("policy_version"),"policyResult",row.get("policy_result"),
                "requiresReassessment",row.get("requires_reassessment"),"locationVersion",row.get("location_version"),
                "actionCycle",row.get("action_cycle"),"actionId",row.get("last_material_action_id"),
                "lastMaterialAt",row.get("last_material_action_at"),"actionsCompletedAt",row.get("actions_completed_at"),
                "revalidationId",row.get("revalidation_id"),"revalidationStatus",row.get("revalidation_status"),
                "revalidationFinishedAt",row.get("revalidation_finished_at"),"attemptRunId",row.get("attempt_run_id"),
                "attemptOutcome",row.get("scope_outcome"),"lastSeenAt",row.get("last_seen_at"),"allCorrected",corrected));
        }
        if(rows.isEmpty()){checks.add(new Check("REQUIRED_LOCATIONS","UNKNOWN","NO_LOCATION_EVIDENCE",null,List.of()));positionsPassed=false;}
        var lifecycle=repository.lifecycle(c).stream().filter(e->actor==null||repository.readable(actor,number(e,"source_occurrence_id"))).toList();
        Set<Long> relatedScopes=new HashSet<>(rows.stream().map(row->number(row,"scope_id")).toList());
        var currentFixtures=repository.jdbc().queryForList("""
            SELECT f.attestation_id,f.scope_id,f.scope_revision,f.manifest_id,f.manifest_version
            FROM secret_current_fixture_attestations f WHERE f.credential_set_id=? ORDER BY f.attestation_id
            """,c.get("credential_set_id")).stream().filter(f->relatedScopes.contains(number(f,"scope_id"))).toList();
        boolean synthetic="TEST".equals(c.get("case_origin"))&&!rows.isEmpty()&&rows.stream()
            .filter(row->row.get("linked_case_id")!=null).allMatch(row->currentFixtures.stream()
                .anyMatch(f->Objects.equals(f.get("scope_id"),row.get("scope_id"))&&Objects.equals(f.get("scope_revision"),row.get("revision"))));
        boolean real=Boolean.TRUE.equals(repository.jdbc().queryForObject("SELECT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials WHERE credential_set_id=?)",Boolean.class,c.get("credential_set_id")));
        synthetic=synthetic&&!real&&rows.stream().anyMatch(row->row.get("linked_case_id")!=null);
        var lifeIds=lifecycle.stream().filter(e->!"FIXTURE_RETIRED".equals(e.get("kind"))).map(e->number(e,"evidence_id")).toList();
        var providerIds=lifecycle.stream().filter(e->!"FIXTURE_RETIRED".equals(e.get("kind"))&&"PROVIDER_VERIFIED".equals(e.get("verification_level"))).map(e->number(e,"evidence_id")).toList();
        var manualIds=lifecycle.stream().filter(e->!"FIXTURE_RETIRED".equals(e.get("kind"))&&"APPROVED_MANUAL".equals(e.get("verification_level"))).map(e->number(e,"evidence_id")).toList();
        var fixtureRetireIds=lifecycle.stream().filter(e->"FIXTURE_RETIRED".equals(e.get("kind"))).map(e->number(e,"evidence_id")).toList();
        var alerts="TEST".equals(c.get("case_origin"))?repository.jdbc().queryForList("SELECT alert_id,status,version,closed_at FROM secret_cross_environment_alerts WHERE credential_set_id=? ORDER BY alert_id",c.get("credential_set_id")):List.<Map<String,Object>>of();
        boolean alertsClosed=alerts.stream().noneMatch(alert->alert.get("closed_at")==null);
        if("TEST".equals(c.get("case_origin")))checks.add(new Check("CROSS_ENVIRONMENT_ALERTS",alertsClosed?"PASSED":"BLOCKED",
            alertsClosed?"RELATED_ALERTS_REVIEWED":"CROSS_ENVIRONMENT_ALERT_OPEN",null,List.of()));
        boolean lifePassed=synthetic?!fixtureRetireIds.isEmpty():!lifeIds.isEmpty();
        checks.add(new Check("CREDENTIAL_LIFECYCLE",lifePassed?"PASSED":"UNKNOWN",lifePassed?synthetic?"SYNTHETIC_FIXTURE_RETIRED":
            !providerIds.isEmpty()?"PROVIDER_RETIREMENT_CONFIRMED":"EXTERNAL_RETIREMENT_INDEPENDENTLY_APPROVED":"CURRENT_LIFECYCLE_EVIDENCE_REQUIRED",
            null,synthetic?fixtureRetireIds:lifeIds));
        var options=new ArrayList<CoverageOption>();
        boolean active=yes(c,"is_current")&&"IN_SCOPE".equals(c.get("disposition"))&&!"RESOLVED".equals(c.get("action_status"));
        if(!active)checks.add(new Check("CASE_ACTIVE","BLOCKED","CASE_NOT_ACTIVE",null,List.of()));
        if(active&&positionsPassed&&lifePassed&&(!"TEST".equals(c.get("case_origin"))||alertsClosed)) {
            if(synthetic)options.add(new CoverageOption("SIMULATION",List.of("SYNTHETIC_TEST_ONLY","PROVIDER_RETIREMENT_NOT_CLAIMED"),union(revalidationIds,fixtureRetireIds)));
            else {
                if(!providerIds.isEmpty())options.add(new CoverageOption("FULL",List.of("APPROVED_SUPPORTED_SCOPES_ONLY","MISUSE_NOT_ASSESSED"),union(revalidationIds,providerIds)));
                if(!manualIds.isEmpty())options.add(new CoverageOption("LIMITED",List.of("PROVIDER_RETIREMENT_NOT_VERIFIED","APPROVED_SUPPORTED_SCOPES_ONLY","MISUSE_NOT_ASSESSED"),union(revalidationIds,manualIds)));
            }
        }
        var dispositions=repository.jdbc().queryForList("""
            SELECT d.disposition_id,d.occurrence_id,d.created_at FROM secret_current_finding_dispositions d
            JOIN secret_findings f ON f.finding_id=d.finding_id JOIN secret_occurrences o ON o.occurrence_id=d.occurrence_id
            WHERE o.credential_set_id=? AND f.run_id=o.last_seen_run_id ORDER BY d.disposition_id
            """,c.get("credential_set_id"));
        Set<Long> relatedIds=new HashSet<>(rows.stream().map(row->number(row,"occurrence_id")).toList());
        dispositions=dispositions.stream().filter(d->relatedIds.contains(number(d,"occurrence_id"))).toList();
        var fpEvidence=dispositions.stream().map(d->new EvidenceReference(number(d,"disposition_id"),
            "FALSE_POSITIVE","Finding 교정 근거 #"+number(d,"disposition_id"),time(d,"created_at"))).toList();
        boolean allFp=!rows.isEmpty()&&rows.stream().filter(row->!"METADATA_ONLY".equals(row.get("component_state"))).allMatch(row->yes(row,"all_corrected"));
        var dismissal=new LinkedHashMap<String,List<EvidenceReference>>();
        if(active&&allFp&&!fpEvidence.isEmpty())dismissal.put("FALSE_POSITIVE",fpEvidence);
        var transfers=eligibleTransfers(id,rows);
        if(active&&(allFp||positionsPassed&&lifePassed&&(!"TEST".equals(c.get("case_origin"))||alertsClosed))&&!transfers.isEmpty())dismissal.put("OUT_OF_SCOPE",transfers);
        var target=facts("caseId",id,"caseVersion",c.get("version"),"origin",c.get("case_origin"),"stage",c.get("action_status"),"current",c.get("is_current"),
            "rows",snapshotRows,"lifecycle",lifecycle,"fixtureProof",currentFixtures,"alerts",alerts,"findingDispositions",dispositions,
            "checks",checks,"coverageOptions",options,"transferEvidence",transfers);
        return new Inspection(c,rows,checks,groups,options,target,SecretReadSnapshots.digest(json.writeValueAsString(target)),dismissal,risk.stream().distinct().sorted().toList());
    }

    private List<EvidenceReference> eligibleTransfers(long id,List<Map<String,Object>> rows) {
        Set<Long> required=new HashSet<>(rows.stream().filter(row->row.get("linked_case_id")!=null).map(row->number(row,"occurrence_id")).toList());
        return repository.jdbc().queryForList("""
            SELECT e.evidence_id,e.submitted_at FROM secret_case_transfer_evidence e
            JOIN LATERAL(SELECT r.decision FROM secret_case_transfer_reviews r WHERE r.evidence_id=e.evidence_id ORDER BY r.review_id DESC LIMIT 1)review ON review.decision='APPROVE'
            WHERE e.case_id=? AND NOT EXISTS(SELECT 1 FROM secret_case_transfer_locations l
              JOIN secret_occurrences o ON o.occurrence_id=l.occurrence_id JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
              WHERE l.evidence_id=e.evidence_id AND (l.scope_revision<>s.revision OR l.scope_origin_version<>s.response_origin_version
                  OR l.assessment_version<>o.exposure_assessment_version)) ORDER BY e.evidence_id
            """,id).stream().filter(e->{
                var covered=new HashSet<>(repository.jdbc().query("SELECT occurrence_id FROM secret_case_transfer_locations WHERE evidence_id=?",(rs,n)->rs.getLong(1),e.get("evidence_id")));
                return !required.isEmpty()&&covered.containsAll(required);
            }).map(e->new EvidenceReference(number(e,"evidence_id"),"OUT_OF_SCOPE","승인된 이관 근거 #"+number(e,"evidence_id"),time(e,"submitted_at"))).toList();
    }
    private String coverageReason(Map<String,Object> row,Map<String,Object> c) {
        if(!Objects.equals(row.get("response_origin"),c.get("case_origin")))return "SOURCE_CLASSIFICATION_CHANGED";
        if(!yes(row,"enabled")||!"ACTIVE".equals(row.get("connection_status")))return "REQUIRED_SCOPE_UNAVAILABLE";
        if(!"SUCCEEDED".equals(row.get("scope_outcome")))return "REQUIRED_SCOPE_INCOMPLETE";
        var due=time(row,"next_due_at");if(due!=null&&due.isBefore(repository.now()))return "REQUIRED_SCOPE_OVERDUE";
        return null;
    }
    private void normalizePolicyClock(Map<String,Object> row) {
        if(!Set.of("ALLOWED","DENIED").contains(text(row,"policy_result")))return;
        boolean usable=Boolean.TRUE.equals(repository.jdbc().queryForObject("""
            SELECT status='ACTIVE' AND valid_from<=clock_timestamp() AND (valid_until IS NULL OR valid_until>clock_timestamp())
            FROM secret_storage_policies WHERE policy_id=? AND version=?
            """,Boolean.class,row.get("policy_id"),row.get("policy_version")));
        if(!usable){row.put("policy_result","UNKNOWN");if(!"UNKNOWN".equals(row.get("exposure_status")))row.put("requires_reassessment",true);}
    }
    static List<Long> union(List<Long> first,List<Long> second) {return java.util.stream.Stream.concat(first.stream(),second.stream()).distinct().sorted().toList();}
}
