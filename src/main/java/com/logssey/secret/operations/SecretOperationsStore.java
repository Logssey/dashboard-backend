package com.logssey.secret.operations;

import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import static com.logssey.secret.operations.SecretOperationsHealth.*;

/** Shared operational metadata only. Never reads a provider reference, token or source body. */
public final class SecretOperationsStore {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Duration grace,queueGrace;
    private final int expected;
    private final String deployment,prefix;
    public SecretOperationsStore(JdbcTemplate jdbc,PlatformTransactionManager manager,Duration grace,Duration queueGrace,int expected){
        this(jdbc,manager,grace,queueGrace,expected,"secret-worker");
    }
    public SecretOperationsStore(JdbcTemplate jdbc,PlatformTransactionManager manager,Duration grace,Duration queueGrace,int expected,String deployment){
        this.jdbc=jdbc;this.tx=new TransactionTemplate(manager);this.grace=grace;this.queueGrace=queueGrace;this.expected=Math.max(1,expected);
        this.deployment=deployment;
        try{this.prefix=java.util.HexFormat.of().withUpperCase().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(deployment.getBytes(java.nio.charset.StandardCharsets.UTF_8)))+":";}
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    public record Beat(UUID instanceId,String deploymentKey,String component,boolean enabled,String state,long intervalMs,
                       OffsetDateTime pollStarted,OffsetDateTime pollFinished,OffsetDateTime success,Long activeJob,String errorCode){}
    public void heartbeat(Beat b){
        jdbc.update("""
          INSERT INTO secret_worker_heartbeats(instance_id,deployment_key,component,enabled,state,poll_interval_ms,started_at,last_heartbeat_at,last_poll_started_at,last_poll_finished_at,last_success_at,active_job_id,error_code)
          VALUES(?,?,?,?,?,?,clock_timestamp(),clock_timestamp(),?,?,?,?,?)
          ON CONFLICT(instance_id,component) DO UPDATE SET enabled=excluded.enabled,state=excluded.state,poll_interval_ms=excluded.poll_interval_ms,
          last_heartbeat_at=clock_timestamp(),last_poll_started_at=excluded.last_poll_started_at,last_poll_finished_at=excluded.last_poll_finished_at,
          last_success_at=excluded.last_success_at,active_job_id=excluded.active_job_id,error_code=excluded.error_code
          """,b.instanceId(),b.deploymentKey(),b.component(),b.enabled(),b.state(),b.intervalMs(),b.pollStarted(),b.pollFinished(),b.success(),b.activeJob(),safeCode(b.errorCode()));
    }
    public Map<String,Object> health(){
        var now=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);
        var rows=jdbc.queryForList("""
          SELECT h.*,EXISTS(SELECT 1 FROM secret_jobs j WHERE j.job_id=h.active_job_id AND j.status='LEASED' AND j.lease_until>clock_timestamp()) AS active_lease_valid
          FROM secret_worker_heartbeats h WHERE h.deployment_key=?
          """,deployment);
        var components=COMPONENTS.stream().map(c->component(c,rows,now,expected,grace)).toList();
        var queue=jdbc.queryForMap("""
          SELECT count(*) FILTER(WHERE status='PENDING' AND available_at<=clock_timestamp()) AS ready,
            count(*) FILTER(WHERE status='PENDING' AND available_at>clock_timestamp()) AS delayed,
            count(*) FILTER(WHERE status='LEASED') AS leased,
            count(*) FILTER(WHERE status='LEASED' AND lease_until<=clock_timestamp()) AS expired,
            coalesce(max(extract(epoch FROM clock_timestamp()-available_at)) FILTER(WHERE status='PENDING' AND available_at<=clock_timestamp()),0) AS oldest,
            count(*) FILTER(WHERE status='FAILED' AND finished_at>clock_timestamp()-interval '24 hours') AS failed
          FROM secret_jobs
          """);
        long partial=jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs WHERE result_status='PARTIAL' AND finished_at>clock_timestamp()-interval '24 hours'",Long.class);
        var counts=jdbc.queryForMap("SELECT count(*) AS total,count(*) FILTER(WHERE status='OPEN') AS open,count(*) FILTER(WHERE status='RECOVERED') AS recovered FROM secret_operations_alerts WHERE starts_with(dedupe_key,?)",prefix);
        var maintenance=component("MAINTENANCE",rows,now,1,grace);
        return facts("status","AVAILABLE","asOf",now,"components",components,
            "queue",facts("status","AVAILABLE","ready",queue.get("ready"),"delayed",queue.get("delayed"),"leased",queue.get("leased"),"expiredLeases",queue.get("expired"),"oldestReadySeconds",queue.get("oldest"),"failed24h",queue.get("failed"),"partial24h",partial),
            "alerts",counts,"maintenance",facts("ledgerPurgeEnabled",false,"snapshotCleanupEnabled",maintenance.get("enabled"),"lastSnapshotCleanupAt",maintenance.get("lastSuccessAt")),"reasonCode",null);
    }
    public Map<String,Object> alerts(String state,int page,int size){
        String where=" WHERE starts_with(dedupe_key,?) AND (?='ALL' OR status=?)";
        long total=jdbc.queryForObject("SELECT count(*) FROM secret_operations_alerts"+where,Long.class,prefix,state,state);
        var rows=jdbc.queryForList("SELECT * FROM secret_operations_alerts"+where+" ORDER BY CASE status WHEN 'OPEN' THEN 0 ELSE 1 END,last_seen_at DESC,alert_id DESC LIMIT ? OFFSET ?",prefix,state,state,size,Math.multiplyExact(page,size));
        var items=rows.stream().map(r->facts("id",r.get("alert_id"),"kind",r.get("kind"),"status",r.get("status"),"subjectType",r.get("subject_type"),"subjectId",r.get("subject_id"),"openedAt",r.get("opened_at"),"lastSeenAt",r.get("last_seen_at"),"recoveredAt",r.get("recovered_at"),"occurrences",r.get("occurrences"),"reasonCode",r.get("reason_code"))).toList();
        return facts("status","AVAILABLE","items",items,"total",total,"page",page,"size",size);
    }
    public int cleanupExpiredSnapshots(int limit){
        return Objects.requireNonNull(tx.execute(status->{
            jdbc.update("DELETE FROM secret_snapshot_retirements WHERE snapshot_id IN(SELECT snapshot_id FROM secret_snapshot_retirements WHERE retired_at<clock_timestamp()-interval '24 hours' ORDER BY retired_at LIMIT ?)",limit);
            return jdbc.update("""
              WITH retired AS(DELETE FROM secret_query_snapshots WHERE snapshot_id IN(
                SELECT snapshot_id FROM secret_query_snapshots WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT ? FOR UPDATE SKIP LOCKED
              ) RETURNING snapshot_id,owner_user_id)
              INSERT INTO secret_snapshot_retirements(snapshot_id,owner_user_id) SELECT snapshot_id,owner_user_id FROM retired ON CONFLICT DO NOTHING
              """,limit);
        }));
    }
    private record Alert(String key,String kind,String subjectType,String subjectId,String basis,String reason){}
    public void monitor(){
        tx.executeWithoutResult(status->{
            if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT pg_try_advisory_xact_lock(731044207013::bigint)",Boolean.class)))return;
            var health=health();var active=new LinkedHashMap<String,Alert>();
            @SuppressWarnings("unchecked") var components=(List<Map<String,Object>>)health.get("components");
            for(var c:components){
                String name=(String)c.get("component"),s=(String)c.get("status");
                if("STALE".equals(s)||"FAILED".equals(s))add(active,new Alert("COMPONENT:"+name,"STALE".equals(s)?"COMPONENT_STALE":"POLL_FAILED","COMPONENT",name,name+":"+s,"STALE".equals(s)?"WORKER_HEARTBEAT_STALE":"POLL_PROGRESS_FAILED"));
            }
            boolean executor=enabled(components,"EXECUTOR"),assessment=enabled(components,"ASSESSMENT"),permissions=enabled(components,"PERMISSIONS");
            var old=jdbc.queryForList("""
              SELECT job_id,kind,extract(epoch FROM clock_timestamp()-available_at)*1000 AS waiting_ms FROM secret_jobs WHERE status='PENDING' AND available_at<clock_timestamp()-(? * interval '1 millisecond') ORDER BY available_at LIMIT 100
              """,queueGrace.toMillis());
            var stalled=old.stream().filter(j->{
                String component="ASSESS".equals(j.get("kind"))?"ASSESSMENT":"ENRICH".equals(j.get("kind"))?"PERMISSIONS":"EXECUTOR";
                if(!enabled(components,component))return false;
                var healthComponent=components.stream().filter(c->component.equals(c.get("component"))).findFirst().orElseThrow();
                if(((Number)healthComponent.get("activeJobs")).longValue()>0)return false;
                Long poll=healthComponent.get("pollIntervalMs") instanceof Number n?n.longValue():null;
                return ((Number)j.get("waiting_ms")).longValue()>Math.max(queueGrace.toMillis(),poll==null?0:poll*3);
            }).findFirst();
            stalled.ifPresent(j->add(active,new Alert("GLOBAL:QUEUE","QUEUE_STALLED","GLOBAL","QUEUE",j.get("job_id").toString(),"READY_JOB_OVERDUE")));
            var leases=jdbc.queryForList("SELECT job_id,kind FROM secret_jobs WHERE status='LEASED' AND lease_until<clock_timestamp()-(? * interval '1 millisecond') ORDER BY lease_until LIMIT 100",grace.toMillis());
            leases.stream().filter(j->"ASSESS".equals(j.get("kind"))?assessment:"ENRICH".equals(j.get("kind"))?permissions:executor).findFirst().ifPresent(j->add(active,new Alert("GLOBAL:LEASES","LEASE_EXPIRED","GLOBAL","LEASES",j.get("job_id").toString(),"EXPIRED_LEASE_NOT_RECOVERED")));
            var runs=jdbc.queryForList("""
              SELECT * FROM(SELECT DISTINCT ON(r.connection_id) r.connection_id,r.run_id,r.result_status,r.failure_code
                FROM secret_scan_runs r JOIN secret_jobs j ON j.job_id=r.job_id JOIN secret_connections c ON c.connection_id=r.connection_id
                WHERE c.status='ACTIVE' AND j.kind='FULL_SCAN' AND r.scope_version=c.scope_version AND r.finished_at IS NOT NULL
                ORDER BY r.connection_id,r.finished_at DESC,r.run_id DESC) latest WHERE result_status IN('PARTIAL','FAILED')
              """);
            for(var r:runs){String id=r.get("connection_id").toString(),kind="PARTIAL".equals(r.get("result_status"))?"RUN_PARTIAL":"RUN_FAILED";
                add(active,new Alert("CONNECTION:"+id,kind,"CONNECTION",id,r.get("run_id").toString(),kind));}
            // These jobs intentionally have no ScanRun. A new successful job must
            // match both purpose and target before an old terminal failure clears.
            var failedTasks=jdbc.queryForList("""
              SELECT * FROM(SELECT DISTINCT ON(j.connection_id,j.kind,j.purpose,coalesce(j.target_occurrence_id,v.occurrence_id,j.job_id))
                j.job_id,j.connection_id,j.kind,j.purpose,j.status,coalesce(j.target_occurrence_id,v.occurrence_id,j.job_id) AS target_id
                FROM secret_jobs j LEFT JOIN secret_case_revalidations v ON v.job_id=j.job_id
                WHERE j.kind IN('REVALIDATE','ASSESS','ENRICH') AND j.status IN('FAILED','SUCCEEDED')
                  AND(j.status='SUCCEEDED' OR coalesce(j.last_error_code,'') NOT IN('STALE_BASELINE','PERMISSION_BASELINE_CHANGED','APPROVAL_CHANGED','CONTEXT_CHANGED','SCOPE_CHANGED'))
                ORDER BY j.connection_id,j.kind,j.purpose,coalesce(j.target_occurrence_id,v.occurrence_id,j.job_id),j.finished_at DESC,j.job_id DESC
              ) latest WHERE status='FAILED'
              """);
            for(var task:failedTasks){
                String id=task.get("connection_id").toString(),purpose=task.get("purpose").toString();
                String key="TASK:"+id+":"+task.get("kind")+":"+purpose+":"+task.get("target_id");
                add(active,new Alert(key,"RUN_FAILED","CONNECTION",id,task.get("job_id").toString(),purpose+"_JOB_FAILED"));
            }
            for(var alert:active.values())open(alert);
            for(var row:jdbc.queryForList("SELECT alert_id,dedupe_key FROM secret_operations_alerts WHERE status='OPEN' AND starts_with(dedupe_key,?) FOR UPDATE",prefix)){
                if(active.containsKey(((String)row.get("dedupe_key")).substring(prefix.length())))continue;
                jdbc.update("UPDATE secret_operations_alerts SET status='RECOVERED',recovered_at=clock_timestamp() WHERE alert_id=?",row.get("alert_id"));
                jdbc.update("INSERT INTO secret_operations_alert_events(alert_id,event_kind) VALUES(?,'RECOVERED')",row.get("alert_id"));
            }
        });
    }
    private static boolean enabled(List<Map<String,Object>> c,String name){return c.stream().anyMatch(v->name.equals(v.get("component"))&&Boolean.TRUE.equals(v.get("enabled")));}
    private static void add(Map<String,Alert> map,Alert a){map.put(a.key(),a);}
    private void open(Alert a){
        var prior=jdbc.queryForList("SELECT alert_id,status,basis_key FROM secret_operations_alerts WHERE dedupe_key=? FOR UPDATE",prefix+a.key());
        if(prior.isEmpty()){
            long id=jdbc.queryForObject("INSERT INTO secret_operations_alerts(dedupe_key,kind,subject_type,subject_id,status,opened_at,last_seen_at,basis_key,reason_code) VALUES(?,?,?,?,'OPEN',clock_timestamp(),clock_timestamp(),?,?) RETURNING alert_id",Long.class,prefix+a.key(),a.kind(),a.subjectType(),a.subjectId(),a.basis(),a.reason());
            jdbc.update("INSERT INTO secret_operations_alert_events(alert_id,event_kind) VALUES(?,'OPENED')",id);return;
        }
        var r=prior.getFirst();boolean reopen="RECOVERED".equals(r.get("status"));
        jdbc.update("UPDATE secret_operations_alerts SET kind=?,status='OPEN',opened_at=CASE WHEN status='RECOVERED' THEN clock_timestamp() ELSE opened_at END,last_seen_at=clock_timestamp(),recovered_at=NULL,occurrences=occurrences+?,basis_key=?,reason_code=? WHERE alert_id=?",a.kind(),reopen||!a.basis().equals(r.get("basis_key"))?1:0,a.basis(),a.reason(),r.get("alert_id"));
        if(reopen)jdbc.update("INSERT INTO secret_operations_alert_events(alert_id,event_kind) VALUES(?,'REOPENED')",r.get("alert_id"));
    }
    private static String safeCode(String value){return value==null?null:value.matches("[A-Z0-9_]{1,80}")?value:"POLL_FAILED";}
}
