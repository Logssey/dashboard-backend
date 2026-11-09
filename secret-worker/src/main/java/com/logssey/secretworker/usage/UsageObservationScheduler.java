package com.logssey.secretworker.usage;

import static com.logssey.secret.permission.core.SecretPermissionContext.*;
import com.logssey.secret.usage.core.SecretUsageContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Explicit per-target opt-in. Server startup itself never initiates a source scan. */
@Service
public class UsageObservationScheduler {
    private final JdbcTemplate jdbc;private final TransactionTemplate tx;private final SecretUsageContext context;
    public UsageObservationScheduler(JdbcTemplate jdbc,PlatformTransactionManager manager){this.jdbc=jdbc;this.tx=new TransactionTemplate(manager);this.context=new SecretUsageContext(jdbc);}
    public int reserveDue(){return tx.execute(status->{
        var rows=jdbc.queryForList("SELECT target_id,occurrence_id FROM secret_usage_targets WHERE enabled AND schedule_enabled AND next_scheduled_at<=clock_timestamp() ORDER BY next_scheduled_at,target_id LIMIT 100");int count=0;
        for(var row:rows){
            if(jdbc.queryForList("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR UPDATE SKIP LOCKED",number(row,"occurrence_id")).isEmpty())continue;
            if(jdbc.queryForList("SELECT target_id FROM secret_usage_targets WHERE target_id=? AND enabled AND schedule_enabled AND next_scheduled_at<=clock_timestamp() FOR UPDATE SKIP LOCKED",number(row,"target_id")).isEmpty())continue;
            var t=context.target(number(row,"target_id"));var c=context.occurrence(number(t,"occurrence_id"));
            if(!context.targetReasons(c,t).isEmpty()){
                // Keep approval and enablement intact, but do not let stale targets starve later due work.
                jdbc.update("UPDATE secret_usage_targets SET next_scheduled_at=clock_timestamp()+interval '5 minutes' WHERE target_id=?",number(t,"target_id"));
                continue;
            }
            if(!jdbc.queryForList("SELECT job_id FROM secret_jobs WHERE purpose='USAGE_OBSERVATION' AND target_occurrence_id=? AND status IN('PENDING','LEASED')",number(c,"occurrence_id")).isEmpty())continue;
            var now=context.now();context.enqueue(c,t,number(t,"approved_by_user_id"),now.minusDays(7),now,"SCHEDULED");
            jdbc.update("UPDATE secret_usage_targets SET next_scheduled_at=clock_timestamp()+interval '6 hours' WHERE target_id=?",number(t,"target_id"));count++;
        }return count;
    });}
}
