package com.logssey.secretworker.permission;
import java.util.*;
public record PermissionCandidate(String status,List<String> capabilities,Map<String,String> coverage,List<String> reasonCodes,int policyDocumentCount,List<String> policyDigests) {
    public static PermissionCandidate unavailable(String reason){return new PermissionCandidate("PARTIAL",List.of(),Map.of("permissionCoverage","UNKNOWN","targetCoverage","UNKNOWN","restrictionCoverage","UNKNOWN","classificationCoverage","UNKNOWN"),List.of(reason),0,List.of());}
    public static PermissionCandidate unsupported(String reason){var empty=unavailable(reason);return new PermissionCandidate("UNSUPPORTED",empty.capabilities(),empty.coverage(),empty.reasonCodes(),0,List.of());}
    public Map<String,Object> facts(){return Map.of("capabilities",capabilities,"coverage",coverage,"reasonCodes",reasonCodes,"policyDocumentCount",policyDocumentCount,"policyDigests",policyDigests,"assessmentEffect","NONE_UNTIL_HUMAN_CONFIRMATION");}
}
