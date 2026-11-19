package com.logssey.iacworker.state;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.ClaimedIacJob;
import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProcessor;

import org.neo4j.driver.exceptions.Neo4jException;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/**
 * CHECK_STATE (State): 매일 tfstate 를 읽을 수 있는 주체를 기록한다. 결과는 작업 stats 에 남겨 /state/summary 가 읽는다.
 * State 파일 안의 민감값 확인은 아직 하지 않는다.
 */
public class CheckStateProcessor implements IacJobProcessor {

    private final StateReaders readers;
    private final JdbcTemplate jdbc;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public CheckStateProcessor(StateReaders readers, JdbcTemplate jdbc) {
        this.readers = readers;
        this.jdbc = jdbc;
    }

    @Override
    public IacJobKind kind() {
        return IacJobKind.CHECK_STATE;
    }

    @Override
    public void process(ClaimedIacJob job, IacJobExecutionService execution) {
        List<String> arns = jdbc.queryForList("SELECT arn FROM iac_data_assets WHERE kind = 'TFSTATE' ORDER BY arn", String.class);
        List<StateReaders.Bucket> buckets;
        try {
            buckets = readers.tfstateReaders(arns);
        } catch (Neo4jException e) {
            throw new IacJobFailure(IacJobFailureCode.GRAPH_UNAVAILABLE, true);
        }
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("tfstate", buckets);
        stats.put("readerCount", buckets.stream().flatMap(b -> b.readers().stream()).distinct().count());
        String json = mapper.writeValueAsString(stats);

        boolean written = execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            jdbc.update("UPDATE iac_jobs SET stats = ?::jsonb WHERE job_id = ?", json, job.jobId());
            jdbc.update("""
                    INSERT INTO iac_audit_events (actor_kind, entity_type, entity_id, event_type, after_safe)
                    VALUES ('WORKER', 'JOB', ?, 'STATE_CHECKED', jsonb_build_object('readerCount', ?::int))
                    """, job.jobId(), stats.get("readerCount"));
        });
        if (!written) {
            throw new IacJobFailure(IacJobFailureCode.LEASE_EXPIRED, true);
        }
    }
}
