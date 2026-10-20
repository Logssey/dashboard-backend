package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import tools.jackson.databind.ObjectMapper;

@Service
public class SecretRunQueryService {
    private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretReadSnapshots snapshots;
    private final SecretRunService runs;private final ObjectMapper json;
    public SecretRunQueryService(JdbcTemplate jdbc,SecretAccessService access,SecretReadSnapshots snapshots,SecretRunService runs,ObjectMapper json){this.jdbc=jdbc;this.access=access;this.snapshots=snapshots;this.runs=runs;this.json=json;}
    @Transactional(readOnly=true)
    public Map<String,Object> status(String login,long runId){
        var actor=access.requirePrincipal(login);var result=runs.status(runId,login);
        @SuppressWarnings("unchecked") Map<String,Object> safe=json.convertValue(result,Map.class);
        safe.put("capabilities",Map.of("canViewFindings",access.hasConnectionRole(actor,result.connectionId(),SecretRole.SECURITY)));
        return safe;
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> list(String login,String type,String status,Long connectionId,OffsetDateTime from,OffsetDateTime to,int page,int size,String snapshotId){
        return list(login,type,status,"ALL",connectionId,from,to,page,size,snapshotId);
    }
    @Transactional(isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> list(String login,String type,String status,String provider,Long connectionId,OffsetDateTime from,OffsetDateTime to,int page,int size,String snapshotId){
        if(!Set.of("ALL","GITHUB","AWS","NOTION","KUBERNETES").contains(provider))throw new ApiException(ErrorCode.INVALID_INPUT);
        page(page,size);if(!Set.of("ALL","MANUAL","SCHEDULED","REVALIDATION").contains(type)||!Set.of("ALL","PENDING","RUNNING","SUCCEEDED","PARTIAL","FAILED","SKIPPED","CANCELLED").contains(status)
            ||(from==null)!=(to==null)||from!=null&&!from.isBefore(to)||connectionId!=null&&connectionId<=0)throw new ApiException(ErrorCode.INVALID_INPUT);
        var actor=access.requirePrincipal(login);access.requireAnyRole(actor);
        if(connectionId!=null&&!access.canReadConnectionFacts(actor,connectionId))throw new ApiException(ErrorCode.FORBIDDEN);
        var f=new TreeMap<String,String>();f.put("type",type);f.put("status",status);f.put("provider",provider);if(connectionId!=null)f.put("connectionId",connectionId.toString());if(from!=null){f.put("from",from.toInstant().toString());f.put("to",to.toInstant().toString());}
        String revision=snapshots.authorizationRevision(actor.userId());SecretReadSnapshots.Header h;
        if(snapshotId!=null)h=snapshots.require(snapshotId,actor.userId(),"HISTORY",f,revision);
        else {
            var subjects=new ArrayList<SecretReadSnapshots.Subject>();
            for(var row:jdbc.queryForList("SELECT run_id,connection_id,requested_at FROM secret_scan_runs ORDER BY requested_at DESC,run_id DESC")){
                long connection=((Number)row.get("connection_id")).longValue();if(!access.canReadConnectionFacts(actor,connection)||connectionId!=null&&connectionId!=connection)continue;
                var at=(java.sql.Timestamp)row.get("requested_at");if(from!=null&&(at.toInstant().isBefore(from.toInstant())||!at.toInstant().isBefore(to.toInstant())))continue;
                long id=((Number)row.get("run_id")).longValue();var result=runs.status(id,login);
                if(!provider.equals("ALL")&&!provider.equals(result.provider()))continue;
                if(!type.equals("ALL")&&!type.equals(result.triggerType())||!status.equals("ALL")&&!status.equals(result.status()))continue;
                @SuppressWarnings("unchecked") Map<String,Object> safe=json.convertValue(result,Map.class);safe.remove("scopeResults");safe.put("displayName",safe.get("safeDisplayAlias"));
                safe.put("capabilities",Map.of("canViewFindings",access.hasConnectionRole(actor,connection,SecretRole.SECURITY)));
                subjects.add(new SecretReadSnapshots.Subject("ScanRun",id,null,safe));
            }
            h=snapshots.create(actor.userId(),"HISTORY",f,revision,!access.hasGlobalRole(actor,SecretRole.SECURITY),subjects);
        }
        return facts("items",snapshots.page(h,"ScanRun",page,size),"total",snapshots.count(h,"ScanRun"),"page",page,"size",size,"unit","ScanRun","filters",f,
            "snapshotId",h.snapshotId(),"asOf",h.asOf(),"expiresAt",h.expiresAt(),"historyComplete",false,"retainedFrom",null);
    }
    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public Map<String,Object> findings(String login,long runId,int page,int size){
        page(page,size);var actor=access.requirePrincipal(login);access.requireAnyRole(actor);
        if(!access.hasAnyRole(actor,Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR)))throw new ApiException(ErrorCode.FORBIDDEN);
        if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_scan_runs WHERE run_id=?)",Boolean.class,runId)))throw new ApiException(ErrorCode.NOT_FOUND);
        var named=new NamedParameterJdbcTemplate(jdbc);String from="""
            FROM secret_findings f JOIN secret_occurrences o USING(occurrence_id)
            JOIN secret_credential_sets k USING(credential_set_id) JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            WHERE f.run_id=:run AND
            """+SecretOccurrenceAccessSql.predicate("o",":userId");
        var args=new HashMap<String,Object>();args.put("run",runId);args.put("userId",actor.userId());
        long total=named.queryForObject("SELECT count(*)"+from,args,Long.class);args.put("limit",size);args.put("offset",(long)page*size);
        if(total==0&&!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_scan_runs r JOIN secret_role_grants g ON g.role='SECURITY' AND g.user_id=? AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=r.connection_id) WHERE r.run_id=?)",Boolean.class,actor.userId(),runId)))throw new ApiException(ErrorCode.NOT_FOUND);
        var items=named.query("SELECT f.finding_id,f.occurrence_id,k.credential_set_id,k.masked_label,k.component_state,f.rule_id,f.rule_version,s.response_origin"+from+" ORDER BY f.finding_id LIMIT :limit OFFSET :offset",args,
            (rs,n)->facts("findingId",rs.getLong("finding_id"),"occurrenceId",rs.getLong("occurrence_id"),"credentialSetId",rs.getLong("credential_set_id"),"secretId",rs.getLong("credential_set_id"),
                "maskedLabel",rs.getString("masked_label"),"componentState",rs.getString("component_state"),"ruleId",rs.getString("rule_id"),"ruleVersion",rs.getString("rule_version"),"origin",rs.getString("response_origin")));
        return facts("items",items,"total",total,"unit","Finding","page",page,"size",size,"runId",runId,"asOf",OffsetDateTime.now());
    }
    private static void page(int p,int s){if(p<0||p>1_000_000||s<1||s>100)throw new ApiException(ErrorCode.INVALID_INPUT);}
}
