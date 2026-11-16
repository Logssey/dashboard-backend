package com.logssey.secret.policy;

import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@Service
public class SecretConnectionPolicyDefaults {
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final SecretScopeChangeService changes;
    private final org.springframework.transaction.support.TransactionTemplate transaction;
    public SecretConnectionPolicyDefaults(JdbcTemplate jdbc,SecretAccessService access,
            SecretCommandExecutor commands,SecretScopeChangeService changes,org.springframework.transaction.PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.access=access;this.commands=commands;this.changes=changes;
        this.transaction=new org.springframework.transaction.support.TransactionTemplate(manager);
    }
    public record Selection(Long policyId,Long policyVersion,Long expectedSettingsVersion,
                            String idempotencyKey,Boolean applyMatchingScopes) { }

    public Map<String,Object> settings(String login,long connection) {
        var actor=access.requirePrincipal(login);
        access.requireConnectionFactsRead(actor,connection);
        var row=connection(connection,false);
        var selected=jdbc.queryForList("SELECT policy_id,policy_version FROM secret_connection_policy_defaults WHERE connection_id=?",connection);
        var policy=selected.isEmpty()?null:selected.getFirst();
        var options=jdbc.queryForList("""
                SELECT p.policy_id,p.version,
                  (SELECT count(DISTINCT scope_id) FROM secret_storage_policy_rules r WHERE r.policy_id=p.policy_id
                    AND r.policy_version=p.version AND r.connection_id=?) AS scope_count,
                  (SELECT string_agg(DISTINCT effect,',' ORDER BY effect) FROM secret_storage_policy_rules r
                    WHERE r.policy_id=p.policy_id AND r.policy_version=p.version AND r.connection_id=?) AS effects
                FROM secret_storage_policies p WHERE p.status='ACTIVE' AND p.valid_from<=clock_timestamp()
                  AND (p.valid_until IS NULL OR p.valid_until>clock_timestamp())
                  AND EXISTS(SELECT 1 FROM secret_storage_policy_rules r WHERE r.policy_id=p.policy_id
                    AND r.policy_version=p.version AND r.connection_id=?) ORDER BY p.policy_id,p.version DESC
                """,connection,connection,connection).stream().map(value -> facts("policyId",value.get("policy_id"),"version",value.get("version"),
                        "label",("ALLOW".equals(value.get("effects"))?"보관 허용":"DENY".equals(value.get("effects"))?"보관 금지":"보관 허용·금지 혼합")
                            +" · 검사 대상 "+value.get("scope_count")+"개","scopeCount",value.get("scope_count"))).toList();
        long total=jdbc.queryForObject("""
                SELECT count(*) FROM secret_connection_scopes WHERE connection_id=? AND enabled
                  AND content_type IN ('GITHUB_REPOSITORY_FILES','AWS_SECRETS_MANAGER_VALUE',
                    'AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT','NOTION_PAGE_CONTENT')
                """,Long.class,connection);
        long applicable=policy==null?0:scopes(connection,number(policy,"policy_id"),number(policy,"policy_version")).size();
        return facts("connectionId",connection,"settingsVersion",row.get("settings_version"),
                "selectedPolicyId",policy==null?null:policy.get("policy_id"),
                "selectedPolicyVersion",policy==null?null:policy.get("policy_version"),
                "policyOptions",options,"applicableScopeCount",applicable,"ruleUpdateRequiredScopeCount",total-applicable,
                "canManage",access.hasConnectionRole(actor,connection,SecretRole.SECURITY));
    }

    public Map<String,Object> select(String login,long connection,Selection request) {
        if(request==null || request.policyId()==null || request.policyVersion()==null
                || request.policyId()<=0 || request.policyVersion()<=0 || request.expectedSettingsVersion()==null)
            throw new ApiException(ErrorCode.INVALID_INPUT);
        var actor=access.requirePrincipal(login);
        commands.execute(actor,SecretCommandExecutor.Kind.SOURCE_CONNECTION_CHANGE,request.idempotencyKey(),
                SecretCommandExecutor.digestSafeIds(connection,request.policyId(),request.policyVersion(),request.expectedSettingsVersion(),
                        Boolean.TRUE.equals(request.applyMatchingScopes())?1L:0L),
                () -> access.requireConnectionRole(actor,connection,SecretRole.SECURITY),() -> {
                    var row=connection(connection,true);
                    SecretCommandExecutor.requireExpectedVersion(request.expectedSettingsVersion(),number(row,"settings_version"));
                    if(!Boolean.TRUE.equals(jdbc.queryForObject("""
                            SELECT EXISTS(SELECT 1 FROM secret_storage_policies p WHERE p.policy_id=? AND p.version=?
                              AND p.status='ACTIVE' AND p.valid_from<=clock_timestamp()
                              AND (p.valid_until IS NULL OR p.valid_until>clock_timestamp())
                              AND EXISTS(SELECT 1 FROM secret_storage_policy_rules r WHERE r.policy_id=p.policy_id
                                AND r.policy_version=p.version AND r.connection_id=?))
                            """,Boolean.class,request.policyId(),request.policyVersion(),connection)))
                        throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
                    jdbc.update("""
                            INSERT INTO secret_connection_policy_defaults(connection_id,policy_id,policy_version,selected_by_user_id)
                            VALUES(?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET policy_id=excluded.policy_id,
                              policy_version=excluded.policy_version,selected_by_user_id=excluded.selected_by_user_id,selected_at=clock_timestamp()
                            """,connection,request.policyId(),request.policyVersion(),actor.userId());
                    jdbc.update("UPDATE secret_connections SET settings_version=settings_version+1,updated_at=clock_timestamp() WHERE connection_id=?",connection);
                    return new SecretCommandResult(connection,request.expectedSettingsVersion()+1,SecretCommandResult.Status.SUCCEEDED);
                });
        var results=new ArrayList<Map<String,Object>>();
        if(Boolean.TRUE.equals(request.applyMatchingScopes())) {
            for(var scope:scopes(connection,request.policyId(),request.policyVersion())) {
                long id=number(scope,"scope_id");
                try {
                    var outcome=transaction.execute(ignored -> apply(login,connection,id,request));
                    results.add(Objects.requireNonNull(outcome));
                } catch(ApiException failure) {
                    results.add(facts("scopeId",id,"status","FAILED","errorCode",failure.errorCode().name()));
                }
            }
        }
        var result=settings(login,connection);result.put("items",results);result.put("requiresSnapshotRefresh",true);
        return result;
    }

    private Map<String,Object> apply(String login,long connection,long id,Selection request) {
        connection(connection,true);
        var selected=jdbc.queryForList("SELECT policy_id,policy_version FROM secret_connection_policy_defaults WHERE connection_id=?",connection);
        if(selected.isEmpty() || !Objects.equals(selected.getFirst().get("policy_id"),request.policyId())
                || !Objects.equals(selected.getFirst().get("policy_version"),request.policyVersion()))
            throw new ApiException(ErrorCode.CONFLICT);
        var current=scopes(connection,request.policyId(),request.policyVersion()).stream()
                .filter(scope -> number(scope,"scope_id")==id).findFirst().orElseThrow(() -> new ApiException(ErrorCode.CONFLICT));
        var existing=jdbc.queryForList("SELECT policy_id,policy_version FROM secret_scope_policy_bindings WHERE scope_id=? AND effective_until IS NULL",id);
        if(!existing.isEmpty() && Objects.equals(existing.getFirst().get("policy_id"),request.policyId())
                && Objects.equals(existing.getFirst().get("policy_version"),request.policyVersion()))
            return facts("scopeId",id,"status","UNCHANGED");
        String origin=current.get("response_origin").toString();long version=number(current,"response_origin_version");
        var preview=changes.preview(id,new SecretPolicyContracts.PreviewRequest(origin,request.policyId(),request.policyVersion(),version),login);
        if(!preview.canSubmit())return facts("scopeId",id,"status","BLOCKED","reasonCodes",preview.remainingReasonCodes());
        var changed=changes.propose(id,new SecretPolicyContracts.ProposalRequest(origin,request.policyId(),request.policyVersion(),
                "SOURCE_CLASSIFICATION","CHANGE:DEFAULT-"+connection,version,preview.approvalMode(),null,
                "default-"+connection+"-"+id+"-"+request.policyId()+"-"+request.policyVersion()+"-"+version),login);
        return facts("scopeId",id,"status",changed.changeResult().effect(),"approvalMode",preview.approvalMode());
    }

    private List<Map<String,Object>> scopes(long connection,long policy,long version) {
        return jdbc.queryForList("""
                SELECT s.scope_id,s.response_origin,s.response_origin_version FROM secret_connection_scopes s
                WHERE s.connection_id=? AND s.enabled
                  AND s.content_type IN ('GITHUB_REPOSITORY_FILES','AWS_SECRETS_MANAGER_VALUE',
                    'AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT','NOTION_PAGE_CONTENT')
                  AND EXISTS(SELECT 1 FROM secret_storage_policies p
                  JOIN secret_storage_policy_rules r ON r.policy_id=p.policy_id AND r.policy_version=p.version
                  WHERE p.policy_id=? AND p.version=? AND p.status='ACTIVE' AND p.valid_from<=clock_timestamp()
                    AND (p.valid_until IS NULL OR p.valid_until>clock_timestamp())
                    AND r.scope_id=s.scope_id AND r.scope_revision=s.revision AND r.connection_id=s.connection_id
                    AND r.scope_fingerprint=md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text))
                ORDER BY s.scope_id
                """,connection,policy,version);
    }
    private Map<String,Object> connection(long id,boolean lock) {
        return jdbc.queryForList("SELECT * FROM secret_connections WHERE connection_id=?"+(lock?" FOR UPDATE":""),id)
                .stream().findFirst().orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }
    private static long number(Map<String,Object> row,String key) { return ((Number)row.get(key)).longValue(); }
}

@RestController
@RequestMapping("/api/v1/secrets/connections/{connectionId}/default-storage-policy")
class SecretConnectionPolicyDefaultsController {
    private final SecretConnectionPolicyDefaults service;
    SecretConnectionPolicyDefaultsController(SecretConnectionPolicyDefaults service) { this.service=service; }
    @GetMapping Map<String,Object> settings(@PathVariable long connectionId,Authentication actor) {
        return service.settings(actor==null?null:actor.getName(),connectionId);
    }
    @PutMapping Map<String,Object> select(@PathVariable long connectionId,
            @RequestBody SecretConnectionPolicyDefaults.Selection request,Authentication actor) {
        return service.select(actor==null?null:actor.getName(),connectionId,request);
    }
}
