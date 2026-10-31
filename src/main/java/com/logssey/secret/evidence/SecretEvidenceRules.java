package com.logssey.secret.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import com.logssey.common.error.*;

/** Closed-code requests only. No free text, raw values, paths or URLs enter evidence/audit. */
public final class SecretEvidenceRules {
    private SecretEvidenceRules(){}
    public static final Set<String> ASSIGNMENT_REASONS=Set.of("INITIAL_ASSIGNMENT","OWNERSHIP_CHANGE","DUE_DATE_CHANGE","UNASSIGNED");
    public static final Set<String> MISSING_REASONS=Set.of("OWNER_UNKNOWN","POLICY_UNKNOWN","SOURCE_PERMISSION","VALIDATION_UNSUPPORTED","FIXTURE_UNCONFIRMED","EVIDENCE_INCOMPLETE");
    public static final Set<String> EVIDENCE_KINDS=Set.of("OWNER_CONFIRMATION","POLICY_REFERENCE","SOURCE_ACCESS_RESTORED","PROVIDER_REFERENCE","FIXTURE_REFERENCE");
    public static void code(String code,Set<String> allowed){if(code==null||!allowed.contains(code))throw new ApiException(ErrorCode.INVALID_INPUT);}
    public static void reference(String value,boolean required){
        if(value==null&&!required)return;
        if(value==null||!value.matches("(TICKET|CHANGE|POLICY):[A-Z][A-Z0-9]{0,15}-[1-9][0-9]{0,12}"))throw new ApiException(ErrorCode.INVALID_INPUT);
    }
    public static void future(OffsetDateTime due,boolean required){
        if(due==null&&!required)return;
        var now=OffsetDateTime.now(ZoneOffset.UTC);
        if(due==null||!due.isAfter(now)||due.isAfter(now.plusDays(90)))throw new ApiException(ErrorCode.INVALID_INPUT);
    }
    public static void observed(OffsetDateTime at){
        if(at==null||at.isAfter(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(5)))throw new ApiException(ErrorCode.INVALID_INPUT);
    }
    public static void page(int page,int size){if(page<0||page>1_000_000||size<1||size>100)throw new ApiException(ErrorCode.INVALID_INPUT);}
    public static byte[] digest(Object... normalizedSafeFields){
        try{return MessageDigest.getInstance("SHA-256").digest(Arrays.deepToString(normalizedSafeFields).getBytes(StandardCharsets.UTF_8));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException("SHA_256_UNAVAILABLE");}
    }
    public static Map<String,Object> mutation(String idName,com.logssey.secret.command.SecretCommandResult result){
        return Map.of(idName,result.targetId(),"version",result.version(),"status",result.status().name(),"requiresSnapshotRefresh",true);
    }
    public static long number(Map<String,Object> row,String field){return ((Number)row.get(field)).longValue();}
    public static OffsetDateTime time(Map<String,Object> row,String field){Object value=row.get(field);return value instanceof OffsetDateTime at?at:value instanceof java.sql.Timestamp t?t.toInstant().atOffset(ZoneOffset.UTC):null;}
}
