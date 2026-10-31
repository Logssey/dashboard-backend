package com.logssey.secret.connection;

import java.util.Map;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import static com.logssey.secret.command.SecretCommandExecutor.requireExpectedVersion;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

@RestController
@RequestMapping("/api/v1/secrets/scopes/{scopeId}/display-alias")
public class SecretScopeAliasController {
    public record Request(String safeDisplayAlias,Long expectedScopeRevision,Long expectedAliasVersion){}
    private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretReadSnapshots snapshots;
    public SecretScopeAliasController(JdbcTemplate jdbc,SecretAccessService access,SecretReadSnapshots snapshots){this.jdbc=jdbc;this.access=access;this.snapshots=snapshots;}
    @PatchMapping @Transactional
    public Map<String,Object> update(@PathVariable long scopeId,@RequestBody Request r,Authentication a){
        var actor=access.requirePrincipal(a==null?null:a.getName());
        if(r==null||!SecretDisplayLabels.safeAlias(r.safeDisplayAlias()))throw new ApiException(ErrorCode.INVALID_INPUT);
        var rows=jdbc.queryForList("SELECT connection_id,revision,alias_version FROM secret_connection_scopes WHERE scope_id=? FOR UPDATE",scopeId);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);var s=rows.getFirst();
        access.requireConnectionRole(actor,((Number)s.get("connection_id")).longValue(),SecretRole.OPERATIONS);
        requireExpectedVersion(r.expectedScopeRevision(),((Number)s.get("revision")).longValue());requireExpectedVersion(r.expectedAliasVersion(),((Number)s.get("alias_version")).longValue());
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias=?,alias_version=alias_version+1 WHERE scope_id=?",r.safeDisplayAlias(),scopeId);
        jdbc.update("INSERT INTO secret_scope_alias_history(scope_id,safe_display_alias,changed_by_user_id,scope_revision) VALUES(?,?,?,?)",scopeId,r.safeDisplayAlias(),actor.userId(),s.get("revision"));
        jdbc.update("INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version) VALUES('SCOPE_ALIAS_CHANGED',?,'SCOPE',?,?)",actor.userId(),scopeId,((Number)s.get("alias_version")).longValue()+1);
        snapshots.invalidateScope(scopeId);
        return facts("scopeId",scopeId,"safeDisplayAlias",r.safeDisplayAlias(),"scopeRevision",s.get("revision"),"aliasVersion",((Number)s.get("alias_version")).longValue()+1,"requiresSnapshotRefresh",true);
    }
}
