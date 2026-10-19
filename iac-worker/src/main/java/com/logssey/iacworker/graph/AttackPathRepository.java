package com.logssey.iacworker.graph;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AttackPathRepository {

    private final JdbcTemplate jdbc;

    public AttackPathRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<GraphEnricher.DataAsset> dataAssets() {
        return jdbc.query("SELECT data_asset_id, arn, tier FROM iac_data_assets ORDER BY data_asset_id",
                (rs, row) -> new GraphEnricher.DataAsset(rs.getLong("data_asset_id"), rs.getString("arn"),
                        rs.getInt("tier")));
    }

    /** 이번 작업에서 찾은 경로는 OPEN 으로 두고 마지막 확인 시각을 올린다. */
    public void upsertOpen(String fingerprint, String hopsJson, int length, long dataAssetId, int tier,
                           String severity, long jobId) {
        jdbc.update("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, status, last_job_id, first_seen_at, last_seen_at)
                VALUES (?, 'internet', ?, ?, ?, 'PROD', ?::jsonb, ?, 'OPEN', ?, now(), now())
                ON CONFLICT (fingerprint) DO UPDATE
                SET status = 'OPEN', tier = EXCLUDED.tier, severity = EXCLUDED.severity, hops = EXCLUDED.hops,
                    last_job_id = EXCLUDED.last_job_id, last_seen_at = EXCLUDED.last_seen_at
                """, fingerprint, dataAssetId, tier, severity, hopsJson, length, jobId);
    }

    /** 이번 작업에서 다시 찾지 못한 열린 경로는 닫는다. */
    public int closeNotSeenBy(long jobId) {
        return jdbc.update("""
                UPDATE iac_attack_paths SET status = 'CLOSED'
                WHERE status = 'OPEN' AND last_job_id IS DISTINCT FROM ?
                """, jobId);
    }

    public void audit(long jobId, String afterSafeJson) {
        jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, entity_type, entity_id, event_type, after_safe)
                VALUES ('WORKER', 'JOB', ?, 'GRAPH_ENRICHED', ?::jsonb)
                """, jobId, afterSafeJson);
    }
}
