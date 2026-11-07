package com.logssey.secret.usage;

import com.logssey.common.error.*;
import java.time.OffsetDateTime;
import java.util.*;
import tools.jackson.databind.json.JsonMapper;

public final class SecretUsageContracts {
    private SecretUsageContracts(){}
    public record Ref(String type,Long id){}
    public record Request(Long occurrenceId,Long serverRegisteredTargetId,OffsetDateTime windowStart,OffsetDateTime windowEnd,Long expectedCredentialRevision,Long expectedScopeRevision,String idempotencyKey){}
    public record Manual(Long occurrenceId,Long expectedCredentialRevision,Long expectedScopeRevision,Ref sourceRef,Ref targetRef,OffsetDateTime windowStart,OffsetDateTime windowEnd,OffsetDateTime eventAt,String actionCode,String actionResult,String actorAttribution,String idempotencyKey){}
    public record Decision(String decision,Long expectedObservationRevision,String reasonCode,String idempotencyKey){}
    private static final JsonMapper JSON=JsonMapper.builder().findAndAddModules().build();
    public static <T> T decode(Map<String,Object> body,Class<T> type){
        var permitted=new HashSet<String>();for(var field:type.getRecordComponents())permitted.add(field.getName());
        if(body==null||!permitted.containsAll(body.keySet()))throw invalid();
        for(String name:List.of("sourceRef","targetRef"))if(body.containsKey(name)&&(!(body.get(name) instanceof Map<?,?> ref)||!Set.of("type","id").containsAll(ref.keySet())))throw invalid();
        try{return JSON.convertValue(body,type);}catch(RuntimeException malformed){throw invalid();}
    }
    public static ApiException invalid(){return new ApiException(ErrorCode.INVALID_INPUT);}
}
