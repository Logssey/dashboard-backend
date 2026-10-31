package com.logssey.secret.operations;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.*;

/** Pure health interpretation. A live process does not prove that its pollers progressed. */
public final class SecretOperationsHealth {
    private SecretOperationsHealth() {}
    public static final List<String> COMPONENTS = List.of("SCHEDULER","EXECUTOR","ASSESSMENT","PERMISSIONS");

    public static Map<String,Object> component(String name, List<Map<String,Object>> rows,
                                               OffsetDateTime now, int expected, Duration grace) {
        var matching = rows.stream().filter(r -> name.equals(r.get("component")))
                .sorted(Comparator.comparing((Map<String,Object> r) -> time(r,"started_at")).reversed()).toList();
        var out = facts("component",name,"enabled",null,"status","NOT_REGISTERED",
                "liveInstances",0,"expectedInstances",expected,"lastHeartbeatAt",null,
                "lastSuccessAt",null,"activeJobs",0,"pollIntervalMs",null);
        if (matching.isEmpty()) return out;
        var freshAll=matching.stream().filter(r->time(r,"last_heartbeat_at").isAfter(now.minus(grace))).toList();
        boolean enabled = freshAll.stream().anyMatch(r->Boolean.TRUE.equals(r.get("enabled")))
                || freshAll.isEmpty()&&Boolean.TRUE.equals(matching.getFirst().get("enabled"));
        out.put("enabled",enabled);
        out.put("lastHeartbeatAt",matching.stream().map(r->time(r,"last_heartbeat_at")).filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null));
        out.put("lastSuccessAt",matching.stream().map(r->time(r,"last_success_at")).filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null));
        if (!enabled) { out.put("status","DISABLED"); return out; }
        var fresh=freshAll.stream().filter(r->Boolean.TRUE.equals(r.get("enabled"))).toList();
        out.put("pollIntervalMs",fresh.stream().mapToLong(r->((Number)r.get("poll_interval_ms")).longValue()).max().orElse(0));
        out.put("liveInstances",fresh.size());
        out.put("activeJobs",fresh.stream().filter(r->r.get("active_job_id")!=null&&Boolean.TRUE.equals(r.get("active_lease_valid"))).count());
        if(fresh.size()<expected){out.put("status","STALE");return out;}
        boolean failed=false;int progressed=0;
        for(var row:fresh){
            if("FAILED".equals(row.get("state"))){failed=true;continue;}
            var started=time(row,"last_poll_started_at");
            var success=time(row,"last_success_at");
            long interval=((Number)row.get("poll_interval_ms")).longValue();
            var deadline=Duration.ofMillis(Math.max(grace.toMillis(),interval*3));
            boolean running="RUNNING".equals(row.get("state"));
            boolean liveLease=Boolean.TRUE.equals(row.get("active_lease_valid"));
            if(running && (liveLease || started!=null&&started.isAfter(now.minus(deadline)))) progressed++;
            else if(!running && success!=null&&success.isAfter(now.minus(deadline))) progressed++;
            else if(!time(row,"started_at").isAfter(now.minus(deadline))) failed=true;
        }
        out.put("status",progressed>=expected?"HEALTHY":failed?"FAILED":"NOT_REGISTERED");
        return out;
    }

    public static OffsetDateTime time(Map<String,Object> row,String field){
        Object v=row.get(field);
        return v instanceof OffsetDateTime t?t:v instanceof java.sql.Timestamp t?t.toInstant().atOffset(java.time.ZoneOffset.UTC):null;
    }
    public static LinkedHashMap<String,Object> facts(Object... pairs){
        var out=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;
    }
}
