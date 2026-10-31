package com.logssey.secret.operations;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static com.logssey.secret.operations.SecretOperationsHealth.*;

class SecretOperationsHealthTest {
    final OffsetDateTime now=OffsetDateTime.parse("2026-10-31T00:00:00Z");
    Map<String,Object> row(){return facts("component","EXECUTOR","enabled",true,"state","IDLE","started_at",now.minusMinutes(30),"last_heartbeat_at",now.minusSeconds(10),"last_success_at",now.minusSeconds(15),"poll_interval_ms",30000L);}
    Map<String,Object> read(List<Map<String,Object>> rows){return component("EXECUTOR",rows,now,1,Duration.ofMinutes(2));}
    @Test void absentIsUnknownAndDisabledIsNotADeadWorker(){
        assertThat(read(List.of())).containsEntry("status","NOT_REGISTERED").containsEntry("enabled",null);
        var r=row();r.put("enabled",false);r.put("last_heartbeat_at",now.minusDays(1));
        assertThat(read(List.of(r))).containsEntry("status","DISABLED");
    }
    @Test void processHeartbeatDoesNotHideStoppedPoller(){var r=row();r.put("last_success_at",now.minusMinutes(20));assertThat(read(List.of(r))).containsEntry("status","FAILED");}
    @Test void expiredHeartbeatFailsEvenWithAnOldSuccessfulPoll(){var r=row();r.put("last_heartbeat_at",now.minusMinutes(3));assertThat(read(List.of(r))).containsEntry("status","STALE");}
    @Test void longActiveJobWithLiveLeaseIsHealthyButLostLeaseIsNot(){
        var r=row();r.put("state","RUNNING");r.put("last_poll_started_at",now.minusMinutes(20));r.put("active_job_id",5L);r.put("active_lease_valid",true);
        assertThat(read(List.of(r))).containsEntry("status","HEALTHY");r.put("active_lease_valid",false);assertThat(read(List.of(r))).containsEntry("status","FAILED");
    }
    @Test void disabledProcessCannotHideFreshEnabledWorkerButCanReplaceAStaleOne(){var old=row();var current=row();current.put("started_at",now.minusMinutes(1));current.put("enabled",false);assertThat(read(List.of(old,current))).containsEntry("status","HEALTHY");old.put("last_heartbeat_at",now.minusHours(1));assertThat(read(List.of(old,current))).containsEntry("status","DISABLED");}
    @Test void expectedTwoInstancesNeedTwoProgressingWorkers(){var good=row();var bad=row();bad.put("state","FAILED");assertThat(component("EXECUTOR",List.of(good,bad),now,2,Duration.ofMinutes(2))).containsEntry("status","FAILED");}
    @Test void successfulIdlePollNeedsNoScanOrFindingsToBeHealthy(){assertThat(read(List.of(row()))).containsEntry("status","HEALTHY").containsEntry("activeJobs",0L);}
}
