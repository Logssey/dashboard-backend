package com.logssey.secret.permission.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** One shared baseline for API enqueue/confirm and the leased observer. Contains protected metadata. */
public final class SecretPermissionContext {
    private static final JsonMapper JSON=JsonMapper.builder().findAndAddModules().build();
    private final JdbcTemplate jdbc;
    public SecretPermissionContext(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public Map<String,Object> read(long occurrence) {
        var rows=jdbc.queryForList("""
SELECT o.*,k.issuer,k.credential_type,k.component_state,k.credential_revision,
 s.revision AS scope_revision,s.response_origin_version,s.enabled AS scope_enabled,s.response_origin,s.approved_ref,s.content_type,s.history_limit,
 c.provider AS source_provider,c.scope_version,c.status AS connection_status,c.validation_revision,c.auth_ref,
 s.validation_approval_revision,i.identity_id,i.validation_attempt_id,i.provider AS identity_provider,i.principal_type,i.account_ref,i.principal_ref,i.principal_id,i.safe_claims::text AS identity_claims,i.observed_at AS identity_observed_at,i.expires_at AS identity_expires_at
FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id)
JOIN secret_connection_scopes s USING(scope_id) JOIN secret_connections c ON c.connection_id=o.connection_id
LEFT JOIN LATERAL(SELECT i.* FROM secret_credential_identities i
 JOIN secret_current_validation_attempts a ON a.attempt_id=i.validation_attempt_id
 WHERE i.occurrence_id=o.occurrence_id AND i.credential_revision=k.credential_revision AND i.scope_revision=s.revision
 AND a.attempt_id=(SELECT latest.attempt_id FROM secret_current_validation_attempts latest WHERE latest.occurrence_id=o.occurrence_id ORDER BY latest.completed_at DESC,latest.attempt_id DESC LIMIT 1)
 AND a.result='VALID' AND i.expires_at>clock_timestamp() ORDER BY i.identity_id DESC LIMIT 1)i ON true
WHERE o.occurrence_id=?
""",occurrence);
        if(rows.isEmpty())throw new IllegalArgumentException("OCCURRENCE_UNAVAILABLE");return rows.getFirst();
    }
    public static String version(Map<String,Object> c) {
        return version(c,false);
    }
    public static String sourceVersion(Map<String,Object> c){return version(c,true);}
    private static String version(Map<String,Object> c,boolean sourceOnly) {
        var baseline=new TreeMap<String,Object>();
        for(String field:List.of("occurrence_id","credential_set_id","credential_revision","scope_id","scope_revision","response_origin_version","latest_object_version","risk_evidence_revision","scope_version","identity_id","validation_revision","validation_approval_revision","asset_id","scope_enabled","connection_status","auth_ref","approved_ref","content_type","history_limit"))if(!sourceOnly||!Set.of("risk_evidence_revision","asset_id").contains(field))baseline.put(field,Objects.toString(c.get(field),""));
        return digest(JSON.writeValueAsString(baseline));
    }
    public static String digest(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException("DIGEST_UNAVAILABLE");}}
    public static long number(Map<String,Object> c,String key){return ((Number)c.get(key)).longValue();}
    public static OffsetDateTime time(Object value){return value==null?null:value instanceof OffsetDateTime t?t:value instanceof java.sql.Timestamp t?t.toInstant().atOffset(ZoneOffset.UTC):OffsetDateTime.parse(value.toString());}
    public static Map<String,Object> facts(Object... entries){var result=new LinkedHashMap<String,Object>();for(int i=0;i<entries.length;i+=2)result.put((String)entries[i],entries[i+1]);return result;}
}
