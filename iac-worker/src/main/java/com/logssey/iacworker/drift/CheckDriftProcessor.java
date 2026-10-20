package com.logssey.iacworker.drift;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;

import com.logssey.iacworker.ClaimedIacJob;
import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProcessor;

import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * CHECK_DRIFT (③, FR-S1): main 의 매일 refresh plan 에서 코드 밖 변경을 찾아 DRIFT 발견 건으로 남긴다.
 * 이번에 다시 나오지 않은 열린 드리프트는 고쳐진 것으로 본다 (코드 반영 또는 되돌리기).
 */
public class CheckDriftProcessor implements IacJobProcessor {

    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private final JdbcTemplate jdbc;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public CheckDriftProcessor(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public IacJobKind kind() {
        return IacJobKind.CHECK_DRIFT;
    }

    @Override
    public void process(ClaimedIacJob job, IacJobExecutionService execution) {
        long runId = Objects.requireNonNull(job.runId(), "CHECK_DRIFT needs the main-branch run");
        var run = jdbc.query("""
                SELECT r.status, p.full_name, p.environment FROM iac_runs r JOIN iac_repos p ON p.repo_id = r.repo_id
                WHERE r.run_id = ?
                """, (rs, row) -> new String[] {rs.getString("status"), rs.getString("full_name"),
                rs.getString("environment")}, runId).stream().findFirst().orElse(null);
        if (run == null || !"ANALYZING".equals(run[0])) {
            return;
        }
        byte[] gzip = jdbc.query("SELECT content FROM iac_plan_payloads WHERE run_id = ?",
                (rs, row) -> rs.getBytes("content"), runId).stream().findFirst()
                .orElseThrow(() -> new IacJobFailure(IacJobFailureCode.PLAN_MISSING, false));
        JsonNode plan = parse(gzip);

        List<DriftClassifier.Drift> drifts = new ArrayList<>();
        int noise = 0;
        for (JsonNode entry : plan.path("resource_drift")) {
            var drift = DriftClassifier.classify(entry);
            if (drift.ruleId() == null) noise++;
            else drifts.add(drift);
        }
        Map<String, Integer> byRule = new TreeMap<>();
        drifts.forEach(d -> byRule.merge(d.ruleId(), 1, Integer::sum));
        String verdict = byRule.containsKey("drift.high") ? "WARN" : drifts.isEmpty() ? "PASS" : "INFO";
        String highest = byRule.containsKey("drift.high") ? "HIGH" : byRule.containsKey("drift.medium") ? "MEDIUM"
                : byRule.containsKey("drift.low") ? "LOW" : null;
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("drifts", drifts.size());
        stats.put("noise", noise);
        stats.put("byRule", byRule);

        boolean written = execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            for (var drift : drifts) {
                Map<String, Object> params = new LinkedHashMap<>();
                params.put("action", drift.action());
                params.put("attributes", drift.attributes());
                jdbc.update("""
                        INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address,
                                                  params, fingerprint, last_run_id, last_job_id, first_seen_at, last_seen_at)
                        SELECT rule_id, 'DRIFT', default_enforcement, default_severity, ?, ?, ?::jsonb, ?, ?, ?, now(), now()
                        FROM iac_rules WHERE rule_id = ?
                        ON CONFLICT (fingerprint) DO UPDATE
                        SET rule_id = EXCLUDED.rule_id, enforcement = EXCLUDED.enforcement, severity = EXCLUDED.severity,
                            params = EXCLUDED.params, last_run_id = EXCLUDED.last_run_id, last_job_id = EXCLUDED.last_job_id,
                            last_seen_at = EXCLUDED.last_seen_at,
                            status = CASE WHEN iac_findings.status = 'ACCEPTED' THEN 'ACCEPTED' ELSE 'OPEN' END,
                            version = iac_findings.version + 1
                        """, run[2], drift.address(), mapper.writeValueAsString(params),
                        fingerprint(drift.address(), run[1]), runId, job.jobId(), drift.ruleId());
            }
            stats.put("fixed", jdbc.update("""
                    UPDATE iac_findings SET status = 'FIXED', version = version + 1
                    WHERE source = 'DRIFT' AND status = 'OPEN' AND last_job_id IS DISTINCT FROM ?
                    """, job.jobId()));
            jdbc.update("""
                    UPDATE iac_runs SET status = 'DONE', verdict = ?, highest_severity = ?, finished_at = now()
                    WHERE run_id = ? AND status = 'ANALYZING'
                    """, verdict, highest, runId);
            jdbc.update("DELETE FROM iac_plan_payloads WHERE run_id = ?", runId);
            String json = mapper.writeValueAsString(stats);
            jdbc.update("UPDATE iac_jobs SET stats = ?::jsonb WHERE job_id = ?", json, job.jobId());
            jdbc.update("""
                    INSERT INTO iac_audit_events (actor_kind, entity_type, entity_id, event_type, after_safe)
                    VALUES ('WORKER', 'RUN', ?, 'DRIFT_CHECKED', ?::jsonb)
                    """, runId, json);
        });
        if (!written) {
            throw new IacJobFailure(IacJobFailureCode.LEASE_EXPIRED, true);
        }
    }

    /** 같은 리소스의 드리프트는 분류가 바뀌어도 한 건으로 이어진다. */
    private static String fingerprint(String address, String repo) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(("drift\n" + address + "\n" + repo + "\nMAIN").getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private JsonNode parse(byte[] gzip) {
        try (var in = new GZIPInputStream(new ByteArrayInputStream(gzip))) {
            return mapper.readTree(in);
        } catch (IOException | JacksonException e) {
            throw new IacJobFailure(IacJobFailureCode.PLAN_INVALID, false);
        }
    }
}
