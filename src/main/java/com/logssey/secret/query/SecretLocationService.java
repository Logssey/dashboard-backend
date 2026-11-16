package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.query.SecretLocationRepository.Row;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

@Service
public class SecretLocationService {
    private final SecretLocationRepository repository;
    private final SecretReadSnapshots snapshots;
    private final SecretAccessService access;
    private final SecretCoverageService coverageService;
    private final com.logssey.secret.response.SecretLocationReadiness readiness;
    private final com.logssey.secret.lifecycle.SecretLifecycleService lifecycle;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.logssey.secret.risk.SecretRiskQueryService riskQueries;
    private static final Set<String> SAFE_REASONS=Set.of("AUTHENTICATED","INVALID_ACCESS_KEY","SIGNATURE_AMBIGUOUS",
        "EXPIRED_SESSION","DISABLED","INCOMPLETE_PAIR","MISSING_SESSION_TOKEN","ACCESS_AMBIGUOUS",
        "POST_ACTION_VALIDATION_REQUIRED","RATE_LIMITED","PROVIDER_UNAVAILABLE","CLIENT_FAILURE","SYNTHETIC_FIXTURE","SOURCE_GUARD_BLOCKED","VALIDATOR_NOT_ALLOWED","SOURCE_UNAVAILABLE",
        "AUTHENTICATION_REJECTED","RESPONSE_UNEXPECTED","UNSUPPORTED_TYPE","INCOMPLETE_CREDENTIAL","NOT_APPROVED",
        "RATE_BUDGET_EXHAUSTED","SOURCE_VALUE_UNAVAILABLE","CREDENTIAL_MISMATCH","APPROVAL_CHANGED","PROFILE_UNCONFIGURED");

    public SecretLocationService(SecretLocationRepository repository,SecretReadSnapshots snapshots,SecretAccessService access,
            SecretCoverageService coverageService,com.logssey.secret.response.SecretLocationReadiness readiness,com.logssey.secret.lifecycle.SecretLifecycleService lifecycle) {
        this.repository=repository; this.snapshots=snapshots; this.access=access; this.coverageService=coverageService;this.readiness=readiness;this.lifecycle=lifecycle;
    }

    public Map<String,Object> inventory(String loginId,SecretInventoryFilters filters,int page,int size,String snapshotId) {
        return inventory(loginId,filters,page,size,snapshotId,null);
    }

    public Map<String,Object> inventory(String loginId,SecretInventoryFilters filters,int page,int size,String snapshotId,Long runId) {
        return snapshots.readConsistently(() -> inventoryWithinRead(loginId,filters,page,size,snapshotId,runId));
    }

    private Map<String,Object> inventoryWithinRead(String loginId,SecretInventoryFilters filters,int page,int size,String snapshotId,Long runId) {
        validatePage(page,size);
        if(runId!=null&&runId<=0)throw new ApiException(ErrorCode.INVALID_INPUT);
        var actor=reader(loginId);
        var normalized=new java.util.TreeMap<>(filters.normalized());if(runId!=null)normalized.put("runId",runId.toString());
        String revision=snapshots.authorizationRevision(actor.userId());
        boolean restricted=!globalSecurity(actor);
        SecretReadSnapshots.Header header;
        if(snapshotId!=null && !snapshotId.isBlank()) {
            header=snapshots.require(snapshotId,actor.userId(),"INVENTORY",normalized,revision);
        } else {
            var runOccurrences=runId==null?null:repository.runOccurrenceIds(actor.userId(),runId);
            var base=new SecretInventoryFilters(filters.origin(),"ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
            var allVisible=repository.visible(actor.userId(),null,base).stream().collect(Collectors.groupingBy(Row::secretId));
            var riskRows=risks(actor,allVisible.values().stream().flatMap(List::stream).toList());
            var grouped=repository.visible(actor.userId(),null,filters).stream().filter(r->runOccurrences==null||runOccurrences.contains(r.occurrenceId())).filter(r->repository.matchesSearch(r,filters.q())).collect(Collectors.groupingBy(
                Row::secretId,LinkedHashMap::new,Collectors.toList()));
            var subjects=new ArrayList<SecretReadSnapshots.Subject>();
            for(var entry:grouped.entrySet()) {
                var rows=entry.getValue();
                var keyRows=allVisible.get(entry.getKey());
                String subtype=inventorySubtype(keyRows);
                if("NORMAL_INVENTORY".equals(filters.workBucket()) ? subtype==null : !matchesWorkBucket(rows,filters.workBucket())) continue;
                var matched=Set.of("ALL","NORMAL_INVENTORY").contains(filters.workBucket())?rows:rows.stream()
                    .filter(row->bucket(row).equals(filters.workBucket())).toList();
                var item=withReadOrigin(inventoryItem(keyRows,actor,subtype,riskRows),filters.origin());
                item.put("matchedLocationCount",matched.size());
                if(!"ALL".equals(filters.validity()) && !filters.validity().equals(item.get("validationStatus"))) continue;
                if(!"ALL".equals(filters.severity()) && !Objects.equals(filters.severity(),item.get("severity"))) continue;
                subjects.add(new SecretReadSnapshots.Subject("CredentialSet",entry.getKey(),entry.getKey(),item,
                    keyRows.stream().map(Row::occurrenceId).distinct().toList()));
            }
            subjects.sort(Comparator.comparingInt((SecretReadSnapshots.Subject s)->SecretRemediationSummary.priority(s.facts())).thenComparingLong(SecretReadSnapshots.Subject::id));
            header=snapshots.create(actor.userId(),"INVENTORY",normalized,revision,restricted,subjects);
        }
        return facts("items",snapshots.page(header,"CredentialSet",page,size),"total",snapshots.count(header,"CredentialSet"),
            "page",page,"size",size,"filters",normalized,"scope","inventory","unit","CredentialSet",
            "asOf",header.asOf(),"snapshotId",header.snapshotId(),"expiresAt",header.expiresAt(),
            "restrictedCoverage",header.restrictedCoverage(),"partialCoverage",null,"coverageStatus","UNKNOWN");
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> detail(String loginId,long secretId,String origin) {
        var actor=reader(loginId);
        var filter=new SecretInventoryFilters(origin,"ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var rows=repository.visible(actor.userId(),secretId,filter);
        if(rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var riskRows=risks(actor,rows);
        var result=withReadOrigin(inventoryItem(rows,actor,inventorySubtype(rows),riskRows),origin);
        result.put("expiryPolicy","UNKNOWN"); result.put("expiresAt",null); result.put("lifecycleStatus","UNKNOWN");
        // Compatibility field contains safe public locations, not original paths or line context.
        result.put("occurrences",rows.stream().map(row-> {
            var value=location(row,actor,loginId,riskRows.getOrDefault(row.occurrenceId(),Map.of())); value.put("id",row.occurrenceId());
            value.put("sourceObjectRef","위치 #"+row.occurrenceId()); value.put("locationKey",null);
            value.put("presenceStatus",row.presence()); value.put("exposureStatus",row.exposure());
            return value;
        }).toList());
        result.put("iamMetadata","METADATA_ONLY".equals(rows.getFirst().componentState())?
            repository.iamMetadata(secretId,rows.stream().map(Row::scopeId).distinct().toList()):null);
        return result;
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> locations(String loginId,long secretId,SecretInventoryFilters filters,int page,int size,
            String presence,String exposure,String actionStatus,String expectedDetailVersion) {
        validatePage(page,size);
        SecretInventoryFilters.require(presence,"ALL","PRESENT","MISSING","UNKNOWN");
        SecretInventoryFilters.require(exposure,"ALL","ABNORMAL","NORMAL","UNKNOWN");
        SecretInventoryFilters.require(actionStatus,"ALL","OPEN","IN_PROGRESS","REVALIDATION_PENDING","RESOLVED","NO_CASE");
        if(secretId<=0) throw new ApiException(ErrorCode.NOT_FOUND);
        var actor=reader(loginId);
        var base=new SecretInventoryFilters(filters.origin(),"ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var visible=repository.visible(actor.userId(),secretId,base);
        // A nonexistent key and a key with no readable relationship produce the same response.
        if(visible.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var riskRows=risks(actor,visible);
        String detailVersion=SecretReadSnapshots.digest(visible.stream().map(row -> row.occurrenceId()+":"+
            row.occurrenceVersion()+":"+row.origin()+":"+repository.originVersion(row)+":"+row.scopeRevision()+":"+row.presence()+":"+row.lastSeenAt()+":"+
            row.caseId()+":"+row.actionStatus()+":"+row.assignedUserId()+":"+row.validationAt()+":"+
            row.storageBindingId()+":"+row.storagePolicyVersion()+":"+row.storagePolicyResult()+":"+
            row.storagePolicyReason()+":"+row.requiresReassessment()+":"+row.allCurrentFindingsCorrected()+":"+
            repository.operationalFacts(row.occurrenceId()).get("location_version")+":"+
            SecretRiskReadModel.revision(riskRows.getOrDefault(row.occurrenceId(),Map.of()))).collect(Collectors.joining("|")));
        if(expectedDetailVersion!=null && !expectedDetailVersion.equals(detailVersion))
            throw new ApiException(ErrorCode.CONFLICT,"위치 정보가 변경되었어요. 다시 확인해 주세요.");
        var filtered=visible.stream().filter(row -> ("ALL".equals(filters.source())||row.source().equals(filters.source()))
            &&("ALL".equals(filters.environment())||row.environment().equals(filters.environment()))
            &&("ALL".equals(presence)||row.presence().equals(presence))
            &&("ALL".equals(exposure)||row.exposure().equals(exposure))
            &&("ALL".equals(actionStatus)||Objects.equals(row.actionStatus()==null?"NO_CASE":row.actionStatus(),actionStatus))).toList();
        var items=filtered.stream().skip((long)page*size).limit(size).map(row -> location(row,actor,loginId,riskRows.getOrDefault(row.occurrenceId(),Map.of()))).toList();
        return facts("credentialSetId",secretId,"credential",withReadOrigin(inventoryItem(visible,actor,inventorySubtype(visible),riskRows),filters.origin()),"detailVersion",detailVersion,
            "items",items,"total",filtered.size(),"visibleLocationCount",filtered.size(),"page",page,"size",size,
            "origin",filters.origin(),"unit","Occurrence","restrictedCoverage",!globalSecurity(actor),
            "locationStateCounts",facts("presence",counts(filtered,Row::presence),"exposure",counts(filtered,Row::exposure)),
            "sourceGroups",filtered.stream().collect(Collectors.groupingBy(Row::source,java.util.TreeMap::new,Collectors.toList())).entrySet().stream()
                .map(entry->facts("source",entry.getKey(),"locationCount",entry.getValue().size(),"scopeCount",entry.getValue().stream().map(Row::scopeId).distinct().count(),
                    "presenceCounts",counts(entry.getValue(),Row::presence))).toList(),
            "filters",facts("source",filters.source(),"environment",filters.environment(),"presence",presence,
                "exposure",exposure,"actionStatus",actionStatus),"readAt",OffsetDateTime.now());
    }

    private SecretPrincipal reader(String loginId) {
        var actor=access.requirePrincipal(loginId);
        access.requireAnyRole(actor);
        // OPERATIONS alone must not gain credential inventory access.
        if(!hasReaderGrant(actor)) throw new ApiException(ErrorCode.FORBIDDEN);
        return actor;
    }

    private boolean hasReaderGrant(SecretPrincipal actor) {
        return access.hasAnyRole(actor,Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR));
    }

    private boolean globalSecurity(SecretPrincipal actor) {
        return access.hasGlobalRole(actor,SecretRole.SECURITY);
    }

    private Map<String,Object> inventoryItem(List<Row> rows,SecretPrincipal actor) {
        return inventoryItem(rows,actor,inventorySubtype(rows));
    }

    private String inventorySubtype(List<Row> rows) {
        return repository.normalInventorySubtype(rows);
    }

    private Map<String,Object> inventoryItem(List<Row> rows,SecretPrincipal actor,String subtype) {
        return inventoryItem(rows,actor,subtype,risks(actor,rows));
    }

    private Map<Long,Map<String,Object>> risks(SecretPrincipal actor,List<Row> rows) {
        return riskQueries==null?Map.of():riskQueries.occurrenceRisks(actor.userId(),rows.stream().map(Row::occurrenceId).distinct().toList());
    }

    private Map<String,Object> inventoryItem(List<Row> rows,SecretPrincipal actor,String subtype,Map<Long,Map<String,Object>> riskRows) {
        var first=rows.getFirst();
        var latest=rows.stream().filter(row->row.validationAt()!=null).max(Comparator.comparing(Row::validationAt)).orElse(first);
        var cases=rows.stream().filter(row->row.caseId()!=null).map(Row::caseId).distinct().toList();
        var priority=List.of("ACTION_REQUIRED","NEEDS_CASE_LINK","NEEDS_DECISION","NORMAL_INVENTORY","INVENTORY","EXCLUDED_HISTORY");
        var representative=rows.stream().min(Comparator.comparingInt(row->priority.indexOf(bucket(row)))).orElse(first);
        String bucket=subtype!=null?"NORMAL_INVENTORY":bucket(representative);
        if(subtype==null && "NORMAL_INVENTORY".equals(bucket)) bucket="NEEDS_DECISION";
        OffsetDateTime lastMaterial=rows.stream().map(row->repository.operationalFacts(row.occurrenceId()).get("validation_after_action_at"))
            .filter(Objects::nonNull).map(v->((java.sql.Timestamp)v).toInstant().atOffset(java.time.ZoneOffset.UTC)).max(Comparator.naturalOrder()).orElse(null);
        boolean needsPostAction=lastMaterial!=null&&(latest.validationCheckedAt()==null||!latest.validationCheckedAt().isAfter(lastMaterial));
        var summary=SecretRemediationSummary.summarize(rows.stream().map(row->summaryFacts(row,actor)).toList(),!globalSecurity(actor));
        if(rows.stream().map(Row::origin).distinct().count()>1)summary.put("comparisonScope","AUTHORIZED_ALL_ORIGINS");
        var result=facts("id",first.secretId(),"issuer",first.issuer(),"provider",first.issuer(),
            "credentialType",first.credentialType(),"componentState",first.componentState(),"maskedLabel",first.maskedLabel(),
            "severity","UNASSESSED","validationStatus",needsPostAction?"UNCHECKED":latest.validity()==null?"UNCHECKED":latest.validity(),
            "validationReasonCode",needsPostAction?"POST_ACTION_VALIDATION_REQUIRED":safeReason(latest.validationReason()),"validatedAt",needsPostAction?null:text(latest.validationAt()),
            "validationCheckedAt",needsPostAction?null:text(latest.validationCheckedAt()),"lastMaterialActionAt",text(lastMaterial),"evidenceOrigin",latest.origin(),
            "occurrenceCount",rows.size(),"visibleLocationCount",rows.size(),"matchedLocationCount",rows.size(),
            "firstSeenAt",text(rows.stream().map(Row::firstSeenAt).min(Comparator.naturalOrder()).orElse(null)),
            "lastSeenAt",text(rows.stream().map(Row::lastSeenAt).max(Comparator.naturalOrder()).orElse(null)),
            "origin",rows.stream().map(Row::origin).distinct().count()==1?first.origin():null,"origins",rows.stream().map(Row::origin).distinct().sorted().toList(),"contentKind","METADATA_ONLY".equals(first.componentState())?"METADATA":"VALUE_FINDINGS",
            "workBucket",bucket,"inventorySubtype",subtype,
            "whyHereCode","RETIRED_HISTORY".equals(subtype)?"PROVIDER_RETIREMENT_CONFIRMED":"MANAGED_LOCATIONS".equals(subtype)?"MANAGED_LOCATIONS_CONFIRMED":reason(representative),
            "nextActionCode",java.util.Arrays.asList("RETIRED_HISTORY","MANAGED_LOCATIONS").contains(subtype)?"VIEW_DETAIL":next(representative,actor),
            "requiresReassessment",rows.stream().anyMatch(Row::requiresReassessment),
            "safeLocationLabel",repository.safeLocationLabel(representative),"currentCaseId",cases.size()==1?cases.getFirst():null,
            "casesByOrigin",cases.stream().map(id->facts("origin",rows.stream().filter(r->Objects.equals(r.caseId(),id)).findFirst().orElseThrow().origin(),"caseId",id)).toList(),
            "remediationSummary",summary,"restrictedCoverage",!globalSecurity(actor));
        var priorities=new ArrayList<String>();
        if(((Number)summary.get("postActionRedetectedCount")).longValue()>0)priorities.add("POST_ACTION_REDETECTED");
        if(rows.stream().anyMatch(r->r.exposure().equals("ABNORMAL")))priorities.add("CONFIRMED_EXPOSURE");
        if(rows.stream().anyMatch(r->"VALID".equals(r.validity())&&"DENIED".equals(r.storagePolicyResult())))priorities.add("VALID_AND_POLICY_DENIED");
        result.put("taskGuidance",SecretTaskGuidance.build((String)result.get("whyHereCode"),(String)result.get("nextActionCode"),
            facts("type","OCCURRENCE","id",representative.occurrenceId(),"secretId",first.secretId(),"caseId",representative.caseId()),
            true,null,null,text(representative.lastSeenAt()),null,null,List.of(),priorities));
        var relevant=rows.stream().filter(row->row.caseId()!=null?!"RESOLVED".equals(row.actionStatus()):
            !"NORMAL".equals(row.exposure())||row.requiresReassessment()
                ||Boolean.TRUE.equals(riskRows.getOrDefault(row.occurrenceId(),Map.of()).get("unassessed"))).map(Row::occurrenceId).distinct().toList();
        boolean outside=rows.stream().allMatch(row->"METADATA_ONLY".equals(row.componentState()))||relevant.isEmpty();
        result.putAll(SecretRiskReadModel.summarize(relevant,riskRows,outside));
        return result;
    }

    private Map<String,Object> summaryFacts(Row row,SecretPrincipal actor) {
        var operational=repository.operationalFacts(row.occurrenceId());
        var coverage=coverageService.occurrenceCoverage(actor,row.occurrenceId());
        var ready=row.caseId()==null?Map.<String,Object>of():readiness.capabilities(actor,row.caseId(),row.occurrenceId());
        return summaryFacts(row,operational,coverage,ready);
    }
    private Map<String,Object> summaryFacts(Row row,Map<String,Object> operational,Map<String,Object> coverage,Map<String,Object> ready) {
        boolean required=row.caseId()!=null&&!"RESOLVED".equals(row.actionStatus())&&!"METADATA_ONLY".equals(row.componentState());
        return facts("requiredRemediation",required,"approvedStorage",!required&&"NORMAL".equals(row.exposure())&&"ALLOWED".equals(row.storagePolicyResult())&&!row.requiresReassessment(),
            "metadataOnly","METADATA_ONLY".equals(row.componentState()),"actionStatus",row.actionStatus(),"presence",row.presence(),
            "currentCoverage",coverage.get("lastSuccessfulScan")!=null&&((List<?>)coverage.get("gapReasonCodes")).isEmpty(),
            "locationAbsenceCheck",ready.getOrDefault("locationAbsenceCheck",Map.of()),
            "lastCheckedAt",coverage.get("lastSuccessfulScan")==null?null:((Map<?,?>)coverage.get("lastSuccessfulScan")).get("finishedAt"),
            "lastMaterialActionAt",operational.get("last_material_action_at"),"lastSeenAt",row.lastSeenAt());
    }

    private Map<String,Object> location(Row row,SecretPrincipal actor,String loginId,Map<String,Object> risk) {
        var operational=repository.operationalFacts(row.occurrenceId());
        boolean review=access.hasConnectionRole(actor,row.connectionId(),SecretRole.SECURITY);
        var coverage=coverageService.occurrenceCoverage(loginId,row.occurrenceId());
        var gapReasons=(java.util.Collection<?>)coverage.getOrDefault("gapReasonCodes",List.of());
        boolean complete=gapReasons.isEmpty()&&coverage.get("lastSuccessfulScan")!=null;
        var visibleFacts=new ArrayList<String>();
        visibleFacts.add(row.presence());
        if("ABNORMAL".equals(row.exposure())) visibleFacts.add("EXPOSURE_CONFIRMED");
        if("UNKNOWN".equals(row.presence())) visibleFacts.add("COVERAGE_UNKNOWN");
        var ready=row.caseId()==null?facts("canRequestRevalidation",false):readiness.capabilities(actor,row.caseId(),row.occurrenceId());
        String validity=row.validity()==null?"UNCHECKED":row.validity();
        var result=facts("credentialSetId",row.secretId(),"occurrenceId",row.occurrenceId(),"connectionId",row.connectionId(),"scopeId",row.scopeId(),
            "source",row.source(),"environment",row.environment(),"origin",row.origin(),"scopeRevision",row.scopeRevision(),
            "safeLocationLabel",repository.safeLocationLabel(row),"presence",row.presence(),"exposure",row.exposure(),
            "storagePolicy",facts("result",row.storagePolicyResult(),"reasonCode",row.storagePolicyReason(),
                "bindingId",row.storageBindingId(),"policyId",row.storagePolicyId(),"version",row.storagePolicyVersion()),
            "requiresReassessment",row.requiresReassessment(),"allCurrentFindingsCorrected",row.allCurrentFindingsCorrected(),
            "validity",facts("result",validity,"reasonCode",safeReason(row.validationReason()),"observedAt",text(row.validationAt()),
                "providerCheckedAt",text(row.validationCheckedAt()),"postActionAfterAt",operational.get("validation_after_action_at"),"lastObservation",operational.get("previous_validation_result")==null?null:
                 facts("result",operational.get("previous_validation_result"),"reasonCode",safeReason((String)operational.get("previous_validation_reason")),
                  "observedAt",operational.get("previous_validation_at"),"providerCheckedAt",operational.get("previous_provider_checked_at"))),
            "lastMaterialActionAt",operational.get("last_material_action_at"),"actionCycle",operational.get("action_cycle"),"actionsCompletedAt",operational.get("actions_completed_at"),
            "coverage",coverage,
            "fixtureStatus",operational.getOrDefault("fixture_status","NOT_APPLICABLE"),
            "fixtureReasonCode",operational.get("fixture_status")==null?"ATTESTATION_EVIDENCE_REQUIRED":null,
            "caseId",row.caseId(),"actionStatus",row.actionStatus(),"assignedUserId",row.assignedUserId(),
            "occurrenceVersion",row.occurrenceVersion(),"caseVersion",row.caseVersion(),"facts",visibleFacts,
            "caseLinkStatus",row.caseId()!=null?"LINKED":(row.requiresReassessment()?"NEEDS_DECISION":("ABNORMAL".equals(row.exposure())?"NEEDS_CASE_LINK":
                ("METADATA_ONLY".equals(row.componentState())?"NOT_REQUIRED":"NEEDS_DECISION"))),
            "whyHereCode",reason(row),"nextActionCode",next(row,actor),
            "recentRevalidation",ready.get("recentRevalidation"),"revalidationBlockReasonCode",ready.get("revalidationBlockReasonCode"),
            "locationAbsenceCheck",ready.getOrDefault("locationAbsenceCheck",facts("status","UNKNOWN","reasonCode","POST_ACTION_EVIDENCE_REQUIRED")),
            "credentialLifecycleCheck",lifecycle.locationCheck(actor,row.occurrenceId()),
            "coverageCheck",facts("status",complete?"PASSED":"UNKNOWN","reasonCode",complete?"CURRENT_SCOPE_OBSERVED":"CURRENT_SCOPE_CHECK_REQUIRED"),
            "firstSeenAt",text(row.firstSeenAt()),"lastSeenAt",text(row.lastSeenAt()),
            "capabilities",facts("canReview",review&&"CONFIRMED".equals(row.componentState()),"canViewCase",row.caseId()!=null,
                "canRecordAction",row.caseId()!=null && lifecycle.assignedActionable(actor,row.caseId(),row.occurrenceId()),"canRequestRevalidation",ready.get("canRequestRevalidation"),"canViewCoverage",access.canReadConnectionFacts(actor,row.connectionId()),
                "canRequestAssistance",true,"canOpenSafeSource",false));
        SecretRiskReadModel.applyLocation(result,risk,"METADATA_ONLY".equals(row.componentState()));
        result.put("taskGuidance",SecretTaskGuidance.location(result));
        result.put("sourceDetails",repository.sourceDetails(row));
        result.put("detectionEvidence",repository.detectionEvidence(row));
        var summary=summaryFacts(row,operational,coverage,ready);
        result.put("requiredRemediation",summary.get("requiredRemediation"));
        result.put("remediationPresence",SecretRemediationSummary.state(summary));
        result.put("postActionRedetected",SecretRemediationSummary.redetected(summary));
        return result;
    }

    private String next(Row row,SecretPrincipal actor) {
        if("METADATA_ONLY".equals(row.componentState())) return "VIEW_METADATA";
        if(row.allCurrentFindingsCorrected()&&row.caseId()==null) return "VIEW_DECISION_HISTORY";
        if(row.requiresReassessment() && access.hasConnectionRole(actor,row.connectionId(),SecretRole.SECURITY)) return "REVIEW_EVIDENCE";
        if(row.caseId()!=null) return "VIEW_CASE";
        if("CANDIDATE".equals(row.componentState()) || !"PRESENT".equals(row.presence())) return "VIEW_DETAIL";
        if(access.hasConnectionRole(actor,row.connectionId(),SecretRole.SECURITY))
            return "ABNORMAL".equals(row.exposure())?"LINK_CASE":"REVIEW_EVIDENCE";
        return "VIEW_DETAIL";
    }
    private static String reason(Row row) {
        if("METADATA_ONLY".equals(row.componentState())) return "ACCESS_KEY_METADATA";
        if(row.allCurrentFindingsCorrected()) return "ALL_FINDINGS_CORRECTED";
        if(row.requiresReassessment()) return "POLICY_REVIEW_REQUIRED";
        if("CANDIDATE".equals(row.componentState())) return "INCOMPLETE_CREDENTIAL";
        if("ABNORMAL".equals(row.exposure())) return row.caseId()==null?"CASE_LINK_REQUIRED":"EXPOSURE_CONFIRMED";
        if("UNKNOWN".equals(row.presence())) return "COVERAGE_GAP";
        return "ALLOWED".equals(row.storagePolicyResult())?"APPROVED_STORAGE":"STORAGE_POLICY_REQUIRED";
    }
    private static String bucket(Row row) {
        if("METADATA_ONLY".equals(row.componentState())) return "NORMAL_INVENTORY";
        if(row.caseId()!=null&&!"RESOLVED".equals(row.actionStatus())) return "ACTION_REQUIRED";
        if(row.allCurrentFindingsCorrected()) return "EXCLUDED_HISTORY";
        if("RESOLVED".equals(row.actionStatus())) return "INVENTORY";
        if(row.requiresReassessment()) return "NEEDS_DECISION";
        if("ABNORMAL".equals(row.exposure())) return row.caseId()==null?"NEEDS_CASE_LINK":"ACTION_REQUIRED";
        if("CANDIDATE".equals(row.componentState()) || !"PRESENT".equals(row.presence())) return "INVENTORY";
        if("NORMAL".equals(row.exposure())&&"ALLOWED".equals(row.storagePolicyResult())&&!row.requiresReassessment()) return "NORMAL_INVENTORY";
        return "NEEDS_DECISION";
    }
    private static boolean matchesWorkBucket(List<Row> rows,String filter) {
        return "ALL".equals(filter)||rows.stream().anyMatch(row->bucket(row).equals(filter));
    }
    private static Map<String,Long> counts(List<Row> rows,java.util.function.Function<Row,String> key) {
        return rows.stream().collect(Collectors.groupingBy(key,LinkedHashMap::new,Collectors.counting()));
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> withReadOrigin(Map<String,Object> value,String origin){
        value.put("readOrigin",origin);
        if("ALL".equals(origin)&&value.get("remediationSummary") instanceof Map<?,?> summary)
            ((Map<String,Object>)summary).put("comparisonScope","AUTHORIZED_ALL_ORIGINS");
        return value;
    }
    private static String text(OffsetDateTime value) { return value==null?null:value.toString(); }
    private static String safeReason(String value) { return value==null?"NO_VERIFICATION_ATTEMPT":SAFE_REASONS.contains(value)?value:"UNSPECIFIED_REASON"; }
    private static void validatePage(int page,int size) {
        if(page<0||page>1_000_000||size<1||size>100) throw new ApiException(ErrorCode.INVALID_INPUT);
    }
}
