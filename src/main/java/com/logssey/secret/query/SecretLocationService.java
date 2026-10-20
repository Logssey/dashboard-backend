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
    private static final Set<String> SAFE_REASONS=Set.of("AUTHENTICATED","INVALID_ACCESS_KEY","SIGNATURE_AMBIGUOUS",
        "EXPIRED_SESSION","DISABLED","INCOMPLETE_PAIR","MISSING_SESSION_TOKEN","ACCESS_AMBIGUOUS",
        "RATE_LIMITED","PROVIDER_UNAVAILABLE","CLIENT_FAILURE","SYNTHETIC_FIXTURE","SOURCE_UNAVAILABLE");

    public SecretLocationService(SecretLocationRepository repository,SecretReadSnapshots snapshots,SecretAccessService access,
            SecretCoverageService coverageService) {
        this.repository=repository; this.snapshots=snapshots; this.access=access; this.coverageService=coverageService;
    }

    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> inventory(String loginId,SecretInventoryFilters filters,int page,int size,String snapshotId) {
        validatePage(page,size);
        var actor=reader(loginId);
        String revision=snapshots.authorizationRevision(actor.userId());
        boolean restricted=!globalSecurity(actor);
        SecretReadSnapshots.Header header;
        if(snapshotId!=null && !snapshotId.isBlank()) {
            header=snapshots.require(snapshotId,actor.userId(),"INVENTORY",filters.normalized(),revision);
        } else {
            var grouped=repository.visible(actor.userId(),null,filters).stream().collect(Collectors.groupingBy(
                Row::secretId,LinkedHashMap::new,Collectors.toList()));
            var subjects=new ArrayList<SecretReadSnapshots.Subject>();
            for(var entry:grouped.entrySet()) {
                var rows=entry.getValue();
                if(!matchesWorkBucket(rows,filters.workBucket())) continue;
                var matched="ALL".equals(filters.workBucket())?rows:rows.stream()
                    .filter(row->bucket(row).equals(filters.workBucket())).toList();
                var item=inventoryItem(matched,actor);
                item.put("visibleLocationCount",rows.size());
                item.put("occurrenceCount",rows.size());
                if(!"ALL".equals(filters.validity()) && !filters.validity().equals(item.get("validationStatus"))) continue;
                if(!"ALL".equals(filters.severity()) && !"UNASSESSED".equals(filters.severity())) continue;
                subjects.add(new SecretReadSnapshots.Subject("CredentialSet",entry.getKey(),entry.getKey(),item,
                    rows.stream().map(Row::occurrenceId).distinct().toList()));
            }
            header=snapshots.create(actor.userId(),"INVENTORY",filters.normalized(),revision,restricted,subjects);
        }
        return facts("items",snapshots.page(header,"CredentialSet",page,size),"total",snapshots.count(header,"CredentialSet"),
            "page",page,"size",size,"filters",filters.normalized(),"scope","inventory","unit","CredentialSet",
            "asOf",header.asOf(),"snapshotId",header.snapshotId(),"expiresAt",header.expiresAt(),
            "restrictedCoverage",header.restrictedCoverage(),"partialCoverage",null,"coverageStatus","UNKNOWN");
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> detail(String loginId,long secretId,String origin) {
        var actor=reader(loginId);
        var filter=new SecretInventoryFilters(origin,"ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var rows=repository.visible(actor.userId(),secretId,filter);
        if(rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var result=inventoryItem(rows,actor);
        result.put("expiryPolicy","UNKNOWN"); result.put("expiresAt",null); result.put("lifecycleStatus","UNKNOWN");
        // Compatibility field contains safe public locations, not original paths or line context.
        result.put("occurrences",rows.stream().map(row-> {
            var value=location(row,actor,loginId); value.put("id",row.occurrenceId());
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
        String detailVersion=SecretReadSnapshots.digest(visible.stream().map(row -> row.occurrenceId()+":"+
            row.occurrenceVersion()+":"+row.scopeRevision()+":"+row.presence()+":"+row.lastSeenAt()+":"+
            row.caseId()+":"+row.actionStatus()+":"+row.assignedUserId()+":"+row.validationAt()).collect(Collectors.joining("|")));
        if(expectedDetailVersion!=null && !expectedDetailVersion.equals(detailVersion))
            throw new ApiException(ErrorCode.CONFLICT,"위치 정보가 변경되었어요. 다시 확인해 주세요.");
        var filtered=visible.stream().filter(row -> ("ALL".equals(filters.source())||row.source().equals(filters.source()))
            &&("ALL".equals(filters.environment())||row.environment().equals(filters.environment()))
            &&("ALL".equals(presence)||row.presence().equals(presence))
            &&("ALL".equals(exposure)||row.exposure().equals(exposure))
            &&("ALL".equals(actionStatus)||Objects.equals(row.actionStatus()==null?"NO_CASE":row.actionStatus(),actionStatus))).toList();
        var items=filtered.stream().skip((long)page*size).limit(size).map(row -> location(row,actor,loginId)).toList();
        return facts("credentialSetId",secretId,"credential",inventoryItem(visible,actor),"detailVersion",detailVersion,
            "items",items,"total",filtered.size(),"visibleLocationCount",filtered.size(),"page",page,"size",size,
            "origin",filters.origin(),"unit","Occurrence","restrictedCoverage",!globalSecurity(actor),
            "locationStateCounts",facts("presence",counts(filtered,Row::presence),"exposure",counts(filtered,Row::exposure)),
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
        var first=rows.getFirst();
        var latest=rows.stream().filter(row->row.validationAt()!=null).max(Comparator.comparing(Row::validationAt)).orElse(first);
        var cases=rows.stream().filter(row->row.caseId()!=null).map(Row::caseId).distinct().toList();
        var representative=rows.stream().filter(row->"ABNORMAL".equals(row.exposure())).findFirst().orElse(first);
        String bucket=bucket(representative);
        return facts("id",first.secretId(),"issuer",first.issuer(),"provider",first.issuer(),
            "credentialType",first.credentialType(),"componentState",first.componentState(),"maskedLabel",first.maskedLabel(),
            "severity","UNASSESSED","validationStatus",latest.validity()==null?"UNCHECKED":latest.validity(),
            "validationReasonCode",safeReason(latest.validationReason()),"validatedAt",text(latest.validationAt()),
            "validationCheckedAt",text(latest.validationCheckedAt()),"evidenceOrigin",latest.origin(),
            "occurrenceCount",rows.size(),"visibleLocationCount",rows.size(),"matchedLocationCount",rows.size(),
            "firstSeenAt",text(rows.stream().map(Row::firstSeenAt).min(Comparator.naturalOrder()).orElse(null)),
            "lastSeenAt",text(rows.stream().map(Row::lastSeenAt).max(Comparator.naturalOrder()).orElse(null)),
            "origin",first.origin(),"contentKind","METADATA_ONLY".equals(first.componentState())?"METADATA":"VALUE_FINDINGS",
            "workBucket",bucket,"whyHereCode",reason(representative),"nextActionCode",next(representative,actor),
            "safeLocationLabel","위치 #"+representative.occurrenceId(),"currentCaseId",representative.caseId(),
            "casesByOrigin",cases.stream().map(id->facts("origin",first.origin(),"caseId",id)).toList(),
            "restrictedCoverage",!globalSecurity(actor));
    }

    private Map<String,Object> location(Row row,SecretPrincipal actor,String loginId) {
        boolean review=access.hasConnectionRole(actor,row.connectionId(),SecretRole.SECURITY);
        var coverage=coverageService.occurrenceCoverage(loginId,row.occurrenceId());
        var gapReasons=(java.util.Collection<?>)coverage.getOrDefault("gapReasonCodes",List.of());
        boolean complete=gapReasons.isEmpty()&&coverage.get("lastSuccessfulScan")!=null;
        var visibleFacts=new ArrayList<String>();
        visibleFacts.add(row.presence());
        if("ABNORMAL".equals(row.exposure())) visibleFacts.add("EXPOSURE_CONFIRMED");
        if("UNKNOWN".equals(row.presence())) visibleFacts.add("COVERAGE_UNKNOWN");
        String validity=row.validity()==null?"UNCHECKED":row.validity();
        return facts("occurrenceId",row.occurrenceId(),"connectionId",row.connectionId(),"scopeId",row.scopeId(),
            "source",row.source(),"environment",row.environment(),"origin",row.origin(),"scopeRevision",row.scopeRevision(),
            "safeLocationLabel","위치 #"+row.occurrenceId(),"presence",row.presence(),"exposure",row.exposure(),
            "storagePolicy",facts("result",row.storagePolicyResult(),"reasonCode","POLICY_EVIDENCE_REQUIRED"),
            "validity",facts("result",validity,"reasonCode",safeReason(row.validationReason()),"observedAt",text(row.validationAt())),
            "coverage",coverage,
            "fixtureStatus","TEST".equals(row.origin())?null:"NOT_APPLICABLE",
            "fixtureReasonCode","ATTESTATION_EVIDENCE_REQUIRED",
            "caseId",row.caseId(),"actionStatus",row.actionStatus(),"assignedUserId",row.assignedUserId(),
            "occurrenceVersion",row.occurrenceVersion(),"caseVersion",row.caseVersion(),"facts",visibleFacts,
            "caseLinkStatus",row.caseId()!=null?"LINKED":("ABNORMAL".equals(row.exposure())?"NEEDS_CASE_LINK":
                ("METADATA_ONLY".equals(row.componentState())?"NOT_REQUIRED":"NEEDS_DECISION")),
            "whyHereCode",reason(row),"nextActionCode",next(row,actor),
            "locationAbsenceCheck",facts("status","UNKNOWN","reasonCode","POST_ACTION_EVIDENCE_REQUIRED"),
            "credentialLifecycleCheck",facts("status","UNKNOWN","reasonCode","LIFECYCLE_EVIDENCE_REQUIRED"),
            "coverageCheck",facts("status",complete?"PASSED":"UNKNOWN","reasonCode",complete?"CURRENT_SCOPE_OBSERVED":"CURRENT_SCOPE_CHECK_REQUIRED"),
            "firstSeenAt",text(row.firstSeenAt()),"lastSeenAt",text(row.lastSeenAt()),
            "capabilities",facts("canReview",review&&"CONFIRMED".equals(row.componentState()),"canViewCase",row.caseId()!=null,
                "canRecordAction",false,"canRequestRevalidation",false,"canViewCoverage",true,"canOpenSafeSource",false));
    }

    private String next(Row row,SecretPrincipal actor) {
        if("METADATA_ONLY".equals(row.componentState())) return "VIEW_METADATA";
        if(row.caseId()!=null) return "VIEW_CASE";
        if(access.hasConnectionRole(actor,row.connectionId(),SecretRole.SECURITY))
            return "ABNORMAL".equals(row.exposure())?"LINK_CASE":"REVIEW_EVIDENCE";
        return "VIEW_DETAIL";
    }
    private static String reason(Row row) {
        if("METADATA_ONLY".equals(row.componentState())) return "ACCESS_KEY_METADATA";
        if("CANDIDATE".equals(row.componentState())) return "INCOMPLETE_CREDENTIAL";
        if("ABNORMAL".equals(row.exposure())) return row.caseId()==null?"CASE_LINK_REQUIRED":"EXPOSURE_CONFIRMED";
        if("UNKNOWN".equals(row.presence())) return "COVERAGE_GAP";
        return "ALLOWED".equals(row.storagePolicyResult())?"APPROVED_STORAGE":"STORAGE_POLICY_REQUIRED";
    }
    private static String bucket(Row row) {
        if("METADATA_ONLY".equals(row.componentState())) return "INVENTORY";
        if("ABNORMAL".equals(row.exposure())) return row.caseId()==null?"NEEDS_CASE_LINK":"ACTION_REQUIRED";
        if("NORMAL".equals(row.exposure())&&"ALLOWED".equals(row.storagePolicyResult())) return "NORMAL_INVENTORY";
        return "NEEDS_DECISION";
    }
    private static boolean matchesWorkBucket(List<Row> rows,String filter) {
        return "ALL".equals(filter)||rows.stream().anyMatch(row->bucket(row).equals(filter));
    }
    private static Map<String,Long> counts(List<Row> rows,java.util.function.Function<Row,String> key) {
        return rows.stream().collect(Collectors.groupingBy(key,LinkedHashMap::new,Collectors.counting()));
    }
    private static String text(OffsetDateTime value) { return value==null?null:value.toString(); }
    private static String safeReason(String value) { return value==null?"NO_VERIFICATION_ATTEMPT":SAFE_REASONS.contains(value)?value:"UNSPECIFIED_REASON"; }
    private static void validatePage(int page,int size) {
        if(page<0||page>1_000_000||size<1||size>100) throw new ApiException(ErrorCode.INVALID_INPUT);
    }
}
