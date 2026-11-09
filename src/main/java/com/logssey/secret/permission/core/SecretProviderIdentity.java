package com.logssey.secret.permission.core;

import java.util.*;

/** Protected provider identity metadata, never a credential, body or raw header. */
public record SecretProviderIdentity(String provider,String principalType,String accountRef,
        String principalRef,String principalId,Map<String,Object> claims) {
    private static final Set<String> SCOPES=Set.of("repo","public_repo","repo:status","repo_deployment","repo:invite","security_events","admin:org","write:org","read:org","user","read:user","user:email","delete_repo","workflow","gist","notifications","admin:public_key","write:public_key","read:public_key","admin:repo_hook","write:repo_hook","read:repo_hook","admin:org_hook","admin:gpg_key","write:gpg_key","read:gpg_key","read:packages","write:packages","delete:packages","codespace","project","read:project");
    private static final String NOTION_UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final Set<String> NOTION_CLAIMS = Set.of("schemaVersion", "workspaceRef", "ownerType");
    public SecretProviderIdentity {
        if(provider==null||!Set.of("AWS","GITHUB","NOTION").contains(provider)||principalId==null||!principalId.matches("[A-Za-z0-9:+=,.@_/-]{1,128}")||claims==null)throw new IllegalArgumentException("INVALID_PROVIDER_IDENTITY");
        if("AWS".equals(provider)) {
            if(accountRef==null||!accountRef.matches("[0-9]{12}")||principalRef==null||!principalRef.matches("arn:aws(?:-[a-z]+)?:[a-z0-9-]+::"+accountRef+":[A-Za-z0-9+=,.@_/:~-]{1,400}")||!Set.of("IAM_USER","ASSUMED_ROLE","ROOT","UNKNOWN").contains(principalType)||!claims.isEmpty())throw new IllegalArgumentException("INVALID_AWS_IDENTITY");
        } else if ("GITHUB".equals(provider)) {
            if(accountRef!=null||!"GITHUB_USER".equals(principalType)||!principalId.matches("[1-9][0-9]{0,18}")||!("github-user:"+principalId).equals(principalRef)||!claims.keySet().equals(Set.of("tokenKind","scopes","scopesComplete"))||!Set.of("CLASSIC","FINE_GRAINED").contains(claims.get("tokenKind"))||!(claims.get("scopesComplete") instanceof Boolean)||!(claims.get("scopes") instanceof List<?> scopes)||scopes.size()>SCOPES.size()||!SCOPES.containsAll(scopes))throw new IllegalArgumentException("INVALID_GITHUB_IDENTITY");
        } else {
            if (accountRef != null || !"NOTION_BOT".equals(principalType)
                    || !principalId.matches(NOTION_UUID)
                    || !("notion-bot:" + principalId).equals(principalRef)
                    || !NOTION_CLAIMS.containsAll(claims.keySet())
                    || !Integer.valueOf(1).equals(claims.get("schemaVersion"))) {
                throw new IllegalArgumentException("INVALID_NOTION_IDENTITY");
            }
            if (claims.containsKey("workspaceRef")
                    && (!(claims.get("workspaceRef") instanceof String workspaceRef)
                            || !workspaceRef.matches(NOTION_UUID))) {
                throw new IllegalArgumentException("INVALID_NOTION_IDENTITY");
            }
            if (claims.containsKey("ownerType")
                    && !"user".equals(claims.get("ownerType"))
                    && !"workspace".equals(claims.get("ownerType"))) {
                throw new IllegalArgumentException("INVALID_NOTION_IDENTITY");
            }
        }
        claims=Map.copyOf(claims);
    }
    public static SecretProviderIdentity aws(String account,String arn,String userId) {
        String type=arn!=null&&arn.contains(":user/")?"IAM_USER":arn!=null&&arn.contains(":assumed-role/")?"ASSUMED_ROLE":arn!=null&&arn.endsWith(":root")?"ROOT":"UNKNOWN";
        return new SecretProviderIdentity("AWS",type,account,arn,userId,Map.of());
    }
    public static SecretProviderIdentity github(long userId,boolean classic,String scopesHeader) {
        var scopes=new TreeSet<String>();boolean complete=classic&&scopesHeader!=null&&scopesHeader.length()<=4096;
        if(complete)for(String scope:scopesHeader.split(",")){String normalized=scope.trim();if(normalized.isEmpty())continue;if(SCOPES.contains(normalized))scopes.add(normalized);else complete=false;}
        return new SecretProviderIdentity("GITHUB","GITHUB_USER",null,"github-user:"+userId,Long.toString(userId),Map.of("tokenKind",classic?"CLASSIC":"FINE_GRAINED","scopes",List.copyOf(scopes),"scopesComplete",complete));
    }

    public static SecretProviderIdentity notion(String botId, String workspaceRef, String ownerType) {
        String principalId = canonicalNotionUuid(botId);
        var claims = new LinkedHashMap<String, Object>();
        claims.put("schemaVersion", 1);
        if (workspaceRef != null) claims.put("workspaceRef", canonicalNotionUuid(workspaceRef));
        if (ownerType != null) claims.put("ownerType", ownerType);
        return new SecretProviderIdentity("NOTION", "NOTION_BOT", null,
                "notion-bot:" + principalId, principalId, claims);
    }

    private static String canonicalNotionUuid(String value) {
        if (value == null || !value.toLowerCase(Locale.ROOT).matches(NOTION_UUID)) {
            throw new IllegalArgumentException("INVALID_NOTION_IDENTITY");
        }
        return value.toLowerCase(Locale.ROOT);
    }
}
