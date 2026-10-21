package com.logssey.secret.risk;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.evidence.SecretEvidenceRules;

/** Closed, bounded facts. Free text and provider payloads never reach persistence. */
public final class SecretRiskFacts {
    private SecretRiskFacts() {}
    public record Field(String name,String type,boolean required,List<String> options,Integer minimum,Integer maximum) {}
    public record Form(String evidenceType,String subject,List<Field> fields) {}
    static Field choice(String name,String... values){return new Field(name,"ENUM",true,List.of(values),null,null);}
    static Field flag(String name){return new Field(name,"BOOLEAN",true,List.of(),null,null);}
    public static final List<Form> FORMS=List.of(
        new Form("ACCESS_SCOPE","OCCURRENCE",List.of(choice("audienceClass","BROAD","BOUNDED","UNKNOWN"),choice("coverageStatus","COMPLETE","PARTIAL","UNKNOWN"),flag("publicAccessConfirmed"),new Field("boundedPrincipalCount","INTEGER",true,List.of(),0,10000))),
        new Form("PERMISSION_MAPPING","OCCURRENCE",List.of(choice("identityBindingStatus","MATCHED","UNRESOLVED","CONFLICT"),choice("support","SUPPORTED","PARTIAL","UNSUPPORTED"),coverage("permissionCoverage"),coverage("targetCoverage"),coverage("restrictionCoverage"),coverage("classificationCoverage"),choice("impact","ADMIN","IMPORTANT","LIMITED","MINIMAL","UNKNOWN"))),
        new Form("ASSET_CLASSIFICATION","OCCURRENCE",List.of(choice("environment","PROD","DEV","TEST","UNKNOWN"),flag("sensitive"),flag("important"),flag("testOnly"))),
        new Form("ABUSE_LINK","OCCURRENCE",List.of(flag("unauthorizedUseConfirmed"),flag("materialImpactConfirmed"),flag("credentialLinked"),flag("occurrenceLinked"))),
        new Form("ABUSE_COVERAGE","OCCURRENCE",List.of(choice("investigationStatus","NOT_STARTED","IN_PROGRESS","COMPLETED","UNAVAILABLE"),choice("coverageStatus","COMPLETE","PARTIAL","UNKNOWN"))));
    static Field coverage(String name){return choice(name,"COMPLETE","PARTIAL","UNKNOWN","NOT_APPLICABLE");}
    public static final Set<String> EVIDENCE_DECISIONS=Set.of("ACCEPT","REJECT","RETRACT");
    public static final Set<String> EVIDENCE_REASONS=Set.of("EVIDENCE_VERIFIED","EVIDENCE_INCOMPLETE","EVIDENCE_CONTRADICTED","EVIDENCE_RETRACTED");
    public static final Set<String> OVERRIDE_REASONS=Set.of("ADDITIONAL_IMPACT_EVIDENCE","PRIOR_EVIDENCE_DISPROVED","EXPOSURE_CORRECTED","INCIDENT_LINK_DISPROVED");
    public static final Set<String> REVIEW_REASONS=Set.of("EVIDENCE_VERIFIED","EVIDENCE_INCOMPLETE","STALE_BASELINE","PRIOR_EVIDENCE_DISPROVED","INCIDENT_LINK_DISPROVED");
    public static SortedMap<String,Object> validate(String kind,String subject,Map<String,Object> facts){
        Form form=FORMS.stream().filter(f->f.evidenceType().equals(kind)).findFirst().orElseThrow(SecretRiskFacts::invalid);
        if(!"OCCURRENCE".equals(subject)||facts==null||facts.size()!=form.fields().size())throw invalid();
        var result=new TreeMap<String,Object>();
        for(Field field:form.fields()){
            Object value=facts.get(field.name());
            if(value==null)throw invalid();
            switch(field.type()){
                case "ENUM"->{if(!(value instanceof String s)||!field.options().contains(s))throw invalid();}
                case "BOOLEAN"->{if(!(value instanceof Boolean))throw invalid();}
                case "INTEGER"->{if(!(value instanceof Number n)||n.doubleValue()!=n.intValue()||n.intValue()<field.minimum()||n.intValue()>field.maximum())throw invalid();value=numeric(value);}
                default->throw invalid();
            }
            result.put(field.name(),value);
        }
        if(kind.equals("ACCESS_SCOPE")){
            if("BROAD".equals(result.get("audienceClass"))&&!Boolean.TRUE.equals(result.get("publicAccessConfirmed"))&& !"COMPLETE".equals(result.get("coverageStatus")))throw invalid();
            if("BOUNDED".equals(result.get("audienceClass"))&&(!"COMPLETE".equals(result.get("coverageStatus"))||((Number)result.get("boundedPrincipalCount")).intValue()<1))throw invalid();
        }
        return result;
    }
    private static int numeric(Object value){return ((Number)value).intValue();}
    public static void window(String kind,OffsetDateTime observed,OffsetDateTime until,OffsetDateTime now){
        SecretEvidenceRules.observed(observed);
        if(observed.isBefore(now.minusYears(10)))throw invalid();
        if(until==null){if(!kind.equals("ABUSE_LINK"))throw invalid();return;}
        Duration maximum=kind.equals("ACCESS_SCOPE")?Duration.ofHours(6):Duration.ofHours(24);
        if(!until.isAfter(now)||!until.isAfter(observed)||until.isAfter(observed.plus(maximum)))throw invalid();
    }
    static ApiException invalid(){return new ApiException(ErrorCode.INVALID_INPUT);}
}
