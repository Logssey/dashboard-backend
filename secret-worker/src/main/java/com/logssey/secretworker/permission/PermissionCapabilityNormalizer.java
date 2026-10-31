package com.logssey.secretworker.permission;
import java.util.*;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import com.logssey.secret.permission.core.SecretPermissionContext;

/** Summarizes potential positive capabilities. It never proves effective permission or an impact. */
public final class PermissionCapabilityNormalizer {
    private final JsonMapper json=new JsonMapper();
    public PermissionCandidate aws(List<String> documents,boolean complete,boolean session){
        var capabilities=new TreeSet<String>();var reasons=new TreeSet<String>();var digests=new ArrayList<String>();
        reasons.add("EFFECTIVE_PERMISSION_NOT_PROVEN");reasons.add("ORGANIZATION_LIMITS_UNOBSERVED");reasons.add("RESOURCE_POLICY_UNOBSERVED");if(session)reasons.add("SESSION_POLICY_UNOBSERVED");
        for(String document:documents){
            if(document==null||document.length()>65536){complete=false;reasons.add("POLICY_DOCUMENT_LIMIT");continue;}
            try{var root=json.readTree(document);var statements=root.path("Statement");var nodes=statements.isArray()?statements:json.createArrayNode().add(statements);
                for(JsonNode statement:nodes){
                    if(!statement.isObject()){complete=false;continue;}
                    if(!statement.path("Condition").isMissingNode())reasons.add("POLICY_CONDITIONS_PRESENT");
                    if(!"Allow".equals(statement.path("Effect").asText("")))continue;
                    if(statement.has("NotAction")||statement.has("NotResource")){complete=false;reasons.add("POLICY_COMPLEMENT_UNSUPPORTED");continue;}
                    var actions=statement.path("Action");var actionNodes=actions.isArray()?actions:json.createArrayNode().add(actions);
                    for(JsonNode action:actionNodes)if(action.isTextual())mapAwsAction(action.asText().toLowerCase(Locale.ROOT),capabilities);
                }
                digests.add(SecretPermissionContext.digest(document));
            }catch(RuntimeException malformed){complete=false;reasons.add("POLICY_DOCUMENT_UNSUPPORTED");}
        }
        if(!complete)reasons.add("POLICY_COLLECTION_PARTIAL");
        return new PermissionCandidate("PARTIAL",List.copyOf(capabilities),Map.of("permissionCoverage",complete?"COMPLETE":"PARTIAL","targetCoverage","PARTIAL","restrictionCoverage","UNKNOWN","classificationCoverage","UNKNOWN"),List.copyOf(reasons),digests.size(),List.copyOf(digests));
    }
    private void mapAwsAction(String action,Set<String> c){
        if(action.equals("*")||action.equals("iam:*")||Set.of("iam:createuser","iam:attachuserpolicy","iam:putuserpolicy","iam:createrole","iam:attachrolepolicy","iam:putrolepolicy").contains(action))c.add("IDENTITY_ADMINISTRATION");
        if(action.equals("*")||Set.of("cloudtrail:stoplogging","cloudtrail:deletetrail","guardduty:deletedetector","securityhub:disablesecurityhub","kms:schedulekeydeletion").contains(action))c.add("SECURITY_SETTINGS_WRITE");
        if(action.equals("*")||Set.of("ec2:*","s3:*","rds:*","eks:*","ecs:*").contains(action))c.add("RESOURCE_ADMINISTRATION");
        if(Set.of("eks:*","ecs:*","codedeploy:*","lambda:updatefunctioncode").contains(action))c.add("PRODUCTION_DEPLOY");
        if(action.equals("*")||Set.of("s3:*","s3:putobject","dynamodb:putitem","rds-data:executestatement").contains(action))c.add("DATA_WRITE");
        if(action.equals("*")||Set.of("secretsmanager:*","secretsmanager:getsecretvalue","ssm:*","ssm:getparameter","ssm:getparameters").contains(action))c.add("SENSITIVE_DATA_READ");
        if(action.equals("*")||Set.of("s3:getobject","ec2:describeinstances","rds:describedbinstances","dynamodb:getitem").contains(action))c.add("RESOURCE_READ");
    }
    public PermissionCandidate github(Map<String,Object> claims){
        var capabilities=new TreeSet<String>();Object scopesValue=claims.get("scopes");var scopes=scopesValue instanceof List<?> values?values:List.of();
        if(scopes.contains("repo")||scopes.contains("public_repo")){capabilities.add("DATA_WRITE");capabilities.add("RESOURCE_READ");}
        if(scopes.contains("admin:org"))capabilities.add("IDENTITY_ADMINISTRATION");
        if(scopes.contains("workflow"))capabilities.add("PRODUCTION_DEPLOY");
        if(scopes.contains("delete_repo"))capabilities.add("RESOURCE_ADMINISTRATION");
        var reasons=new ArrayList<String>(List.of("TOKEN_OWNER_NOT_EFFECTIVE_PERMISSION","REPOSITORY_AUTHORIZATION_UNOBSERVED","ORGANIZATION_LIMITS_UNOBSERVED","HUMAN_CONFIRMATION_REQUIRED"));
        if(!Boolean.TRUE.equals(claims.get("scopesComplete")))reasons.add("TOKEN_PERMISSIONS_UNAVAILABLE");
        return new PermissionCandidate("PARTIAL",List.copyOf(capabilities),Map.of("permissionCoverage",Boolean.TRUE.equals(claims.get("scopesComplete"))?"PARTIAL":"UNKNOWN","targetCoverage","UNKNOWN","restrictionCoverage","UNKNOWN","classificationCoverage","UNKNOWN"),List.copyOf(reasons),0,List.of());
    }
}
