package com.logssey.runtime.query;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import com.logssey.runtime.query.dto.RuntimeFindingResponse;
import com.logssey.runtime.query.dto.RuntimeFindingResponse.AssetSummary;
import com.logssey.runtime.query.dto.RuntimeFindingResponse.ProcessSummary;
import com.logssey.runtime.query.dto.RuntimeFindingResponse.Rule;
import com.logssey.runtime.query.dto.RuntimeFindingResponse.TargetSummary;
import com.logssey.runtime.query.dto.RuntimeFindingUpdateRequest;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse;
import com.logssey.runtime.query.dto.RuntimeSensorListResponse.SensorItem;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RuntimeQueryRepository {

    private final JdbcClient jdbcClient;

    public RuntimeQueryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public RuntimeCounts counts(String clusterId, Instant from, Instant to) {
        String clusterCondition = clusterCondition(clusterId, "a.cluster_id");
        String sql = """
                SELECT
                    (SELECT count(*) FROM runtime_events e
                     LEFT JOIN runtime_assets ea ON ea.runtime_asset_id = e.runtime_asset_id
                     WHERE e.occurred_at >= :from AND e.occurred_at < :to %s) AS event_count,
                    (SELECT count(*) FROM runtime_events se
                     LEFT JOIN runtime_assets sa ON sa.runtime_asset_id = se.runtime_asset_id
                     WHERE se.occurred_at >= :from AND se.occurred_at < :to
                       AND se.handling_status = 'SUPPRESSED' %s) AS suppressed_count,
                    (SELECT count(*) FROM runtime_raw_events re
                     WHERE re.received_at >= :from AND re.received_at < :to
                       AND re.processing_status = 'RATE_LIMITED'
                       AND (:allClusters OR re.cluster_id = :clusterId)) AS rate_limited_count,
                    (SELECT count(*) FROM runtime_events oe
                     LEFT JOIN runtime_assets oa ON oa.runtime_asset_id = oe.runtime_asset_id
                     WHERE oe.occurred_at >= :from AND oe.occurred_at < :to
                       AND oe.handling_status = 'OBSERVED' %s) AS observed_count,
                    count(*) FILTER (WHERE f.review_status = 'UNREVIEWED') AS unreviewed_count,
                    count(DISTINCT a.workload_name) FILTER (WHERE a.workload_name IS NOT NULL) AS workload_count,
                    (SELECT count(*) FROM runtime_events ue
                     LEFT JOIN runtime_assets ua ON ua.runtime_asset_id = ue.runtime_asset_id
                     WHERE ue.occurred_at >= :from AND ue.occurred_at < :to
                       AND ue.asset_resolution_status = 'UNRESOLVED' %s) AS unresolved_count
                FROM runtime_findings f
                LEFT JOIN runtime_assets a ON a.runtime_asset_id = f.runtime_asset_id
                WHERE f.last_seen_at >= :from AND f.last_seen_at < :to %s
                """.formatted(
                clusterCondition(clusterId, "ea.cluster_id"),
                clusterCondition(clusterId, "sa.cluster_id"),
                clusterCondition(clusterId, "oa.cluster_id"),
                clusterCondition(clusterId, "ua.cluster_id"),
                clusterCondition);
        return withRangeAndCluster(jdbcClient.sql(sql), clusterId, from, to)
                .query((rs, rowNum) -> new RuntimeCounts(
                        rs.getLong("event_count"),
                        rs.getLong("suppressed_count"),
                        rs.getLong("rate_limited_count"),
                        rs.getLong("observed_count"),
                        rs.getLong("unreviewed_count"),
                        rs.getLong("workload_count"),
                        rs.getLong("unresolved_count")))
                .single();
    }

    public List<RuntimeOverviewResponse.RuleCount> countsByRule(String clusterId, Instant from, Instant to) {
        String sql = """
                SELECT f.rule_key, f.rule_title, count(*) AS count
                FROM runtime_findings f
                LEFT JOIN runtime_assets a ON a.runtime_asset_id = f.runtime_asset_id
                WHERE f.last_seen_at >= :from AND f.last_seen_at < :to %s
                GROUP BY f.rule_key, f.rule_title
                ORDER BY count DESC, f.rule_key
                """.formatted(clusterCondition(clusterId, "a.cluster_id"));
        return withRangeAndCluster(jdbcClient.sql(sql), clusterId, from, to)
                .query((rs, rowNum) -> new RuntimeOverviewResponse.RuleCount(
                        rs.getString("rule_key"), rs.getString("rule_title"), rs.getLong("count")))
                .list();
    }

    public SensorCounts sensorCounts(String clusterId) {
        String sql = """
                SELECT
                    count(*) AS total,
                    count(*) FILTER (WHERE status = 'HEALTHY') AS healthy,
                    count(*) FILTER (WHERE status = 'DEGRADED') AS degraded,
                    count(*) FILTER (WHERE status = 'OFFLINE') AS offline,
                    count(*) FILTER (WHERE status = 'UNKNOWN') AS unknown
                FROM runtime_sensors
                WHERE (:allClusters OR cluster_id = :clusterId)
                """;
        return withCluster(jdbcClient.sql(sql), clusterId)
                .query((rs, rowNum) -> new SensorCounts(
                        rs.getLong("total"), rs.getLong("healthy"), rs.getLong("degraded"),
                        rs.getLong("offline"), rs.getLong("unknown")))
                .single();
    }

    public List<RuntimeFindingResponse> findFindings(String clusterId, String namespace,
                                                     String reviewStatus, String ruleKey, int limit) {
        String sql = """
                SELECT f.*, a.cluster_id, a.namespace, a.workload_kind, a.workload_name,
                       a.pod_uid, a.pod_name, a.container_name, a.image, a.image_digest,
                       a.node_name, a.service_account_name, a.valid_to,
                       u.display_name AS assignee_display_name,
                       COALESCE((SELECT array_agg(DISTINCT e.source ORDER BY e.source)
                                 FROM runtime_finding_events fe
                                 JOIN runtime_events e ON e.runtime_event_id = fe.runtime_event_id
                                 WHERE fe.finding_id = f.finding_id), ARRAY[]::varchar[]) AS sensors
                FROM runtime_findings f
                LEFT JOIN runtime_assets a ON a.runtime_asset_id = f.runtime_asset_id
                LEFT JOIN dashboard_users u ON u.user_id = f.assignee_user_id
                WHERE (:allClusters OR a.cluster_id = :clusterId)
                  AND (:allNamespaces OR a.namespace = :namespace)
                  AND (:allReviewStatuses OR f.review_status = :reviewStatus)
                  AND (:allRules OR f.rule_key = :ruleKey)
                ORDER BY f.last_seen_at DESC, f.finding_id DESC
                LIMIT :limit
                """;
        return jdbcClient.sql(sql)
                .param("allClusters", "ALL".equals(clusterId))
                .param("clusterId", clusterId)
                .param("allNamespaces", "ALL".equals(namespace))
                .param("namespace", namespace)
                .param("allReviewStatuses", "ALL".equals(reviewStatus))
                .param("reviewStatus", reviewStatus)
                .param("allRules", "ALL".equals(ruleKey))
                .param("ruleKey", ruleKey)
                .param("limit", limit)
                .query((rs, rowNum) -> finding(rs))
                .list();
    }

    public long countFindings(String clusterId, String namespace, String reviewStatus, String ruleKey) {
        return jdbcClient.sql("""
                        SELECT count(*)
                        FROM runtime_findings f
                        LEFT JOIN runtime_assets a ON a.runtime_asset_id = f.runtime_asset_id
                        WHERE (:allClusters OR a.cluster_id = :clusterId)
                          AND (:allNamespaces OR a.namespace = :namespace)
                          AND (:allReviewStatuses OR f.review_status = :reviewStatus)
                          AND (:allRules OR f.rule_key = :ruleKey)
                        """)
                .param("allClusters", "ALL".equals(clusterId))
                .param("clusterId", clusterId)
                .param("allNamespaces", "ALL".equals(namespace))
                .param("namespace", namespace)
                .param("allReviewStatuses", "ALL".equals(reviewStatus))
                .param("reviewStatus", reviewStatus)
                .param("allRules", "ALL".equals(ruleKey))
                .param("ruleKey", ruleKey)
                .query(Long.class)
                .single();
    }

    public Optional<RuntimeFindingResponse> findFinding(long findingId) {
        return jdbcClient.sql("""
                        SELECT f.*, a.cluster_id, a.namespace, a.workload_kind, a.workload_name,
                               a.pod_uid, a.pod_name, a.container_name, a.image, a.image_digest,
                               a.node_name, a.service_account_name, a.valid_to,
                               u.display_name AS assignee_display_name,
                               COALESCE((SELECT array_agg(DISTINCT e.source ORDER BY e.source)
                                         FROM runtime_finding_events fe
                                         JOIN runtime_events e ON e.runtime_event_id = fe.runtime_event_id
                                         WHERE fe.finding_id = f.finding_id), ARRAY[]::varchar[]) AS sensors
                        FROM runtime_findings f
                        LEFT JOIN runtime_assets a ON a.runtime_asset_id = f.runtime_asset_id
                        LEFT JOIN dashboard_users u ON u.user_id = f.assignee_user_id
                        WHERE f.finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .query((rs, rowNum) -> finding(rs))
                .optional();
    }

    public List<SensorItem> findSensors(String clusterId) {
        return withCluster(jdbcClient.sql("""
                        SELECT sensor_id, cluster_id, node_name, sensor_type, version, driver, status,
                               last_heartbeat_at, last_event_at, rule_set_version, queue_depth, error_message
                        FROM runtime_sensors
                        WHERE (:allClusters OR cluster_id = :clusterId)
                        ORDER BY node_name, sensor_type
                        """), clusterId)
                .query((rs, rowNum) -> new SensorItem(
                        rs.getLong("sensor_id"),
                        rs.getString("cluster_id"),
                        rs.getString("node_name"),
                        rs.getString("sensor_type"),
                        rs.getString("version"),
                        rs.getString("driver"),
                        rs.getString("status"),
                        format(instant(rs, "last_heartbeat_at")),
                        format(instant(rs, "last_event_at")),
                        rs.getString("rule_set_version"),
                        nullableLong(rs, "queue_depth"),
                        rs.getString("error_message")))
                .list();
    }

    public long findUserId(String loginId) {
        return jdbcClient.sql("SELECT user_id FROM dashboard_users WHERE login_id = :loginId")
                .param("loginId", loginId)
                .query(Long.class)
                .single();
    }

    public boolean assigneeExists(Long userId) {
        if (userId == null) {
            return true;
        }
        return jdbcClient.sql("SELECT count(*) FROM dashboard_users WHERE user_id = :userId")
                .param("userId", userId)
                .query(Long.class)
                .single() == 1;
    }

    public int updateFinding(long findingId, long changedBy, CurrentFinding current,
                             RuntimeFindingUpdateRequest request, String nextReviewStatus,
                             String nextActionStatus, String nextDisposition, Long nextAssignee, String nextNote) {
        jdbcClient.sql("""
                        INSERT INTO runtime_finding_history
                            (finding_id, changed_by_user_id, previous_review_status, next_review_status,
                             previous_action_status, next_action_status, previous_disposition, next_disposition,
                             previous_assignee_user_id, next_assignee_user_id, previous_note, next_note)
                        VALUES
                            (:findingId, :changedBy, :previousReview, :nextReview,
                             :previousAction, :nextAction, :previousDisposition, :nextDisposition,
                             :previousAssignee, :nextAssignee, :previousNote, :nextNote)
                        """)
                .param("findingId", findingId)
                .param("changedBy", changedBy)
                .param("previousReview", current.reviewStatus())
                .param("nextReview", nextReviewStatus)
                .param("previousAction", current.actionStatus())
                .param("nextAction", nextActionStatus)
                .param("previousDisposition", current.disposition())
                .param("nextDisposition", nextDisposition)
                .param("previousAssignee", current.assigneeUserId())
                .param("nextAssignee", nextAssignee)
                .param("previousNote", current.note())
                .param("nextNote", nextNote)
                .update();

        return jdbcClient.sql("""
                        UPDATE runtime_findings
                        SET review_status = :reviewStatus,
                            action_status = :actionStatus,
                            disposition = :disposition,
                            assignee_user_id = :assigneeUserId,
                            note = :note,
                            version = version + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE finding_id = :findingId AND version = :version
                        """)
                .param("reviewStatus", nextReviewStatus)
                .param("actionStatus", nextActionStatus)
                .param("disposition", nextDisposition)
                .param("assigneeUserId", nextAssignee)
                .param("note", nextNote)
                .param("findingId", findingId)
                .param("version", request.version())
                .update();
    }

    public Optional<CurrentFinding> findCurrent(long findingId) {
        return jdbcClient.sql("""
                        SELECT review_status, action_status, disposition, assignee_user_id, note, version
                        FROM runtime_findings WHERE finding_id = :findingId
                        """)
                .param("findingId", findingId)
                .query((rs, rowNum) -> new CurrentFinding(
                        rs.getString("review_status"), rs.getString("action_status"),
                        rs.getString("disposition"), nullableLong(rs, "assignee_user_id"),
                        rs.getString("note"), rs.getLong("version")))
                .optional();
    }

    private static RuntimeFindingResponse finding(ResultSet rs) throws SQLException {
        AssetSummary asset = rs.getString("cluster_id") == null ? null : new AssetSummary(
                rs.getString("cluster_id"), rs.getString("namespace"), rs.getString("workload_kind"),
                rs.getString("workload_name"), rs.getString("pod_uid"), rs.getString("pod_name"),
                rs.getString("container_name"), rs.getString("image"), rs.getString("image_digest"),
                rs.getString("node_name"), rs.getString("service_account_name"), rs.getObject("valid_to") != null);
        java.sql.Array sensorArray = rs.getArray("sensors");
        List<String> sensors = sensorArray == null
                ? List.of()
                : List.of((String[]) sensorArray.getArray());
        return new RuntimeFindingResponse(
                rs.getLong("finding_id"), rs.getString("display_id"),
                new Rule(rs.getString("rule_key"), rs.getString("rule_title"), rs.getString("rule_version")),
                rs.getString("review_status"), rs.getString("action_status"), rs.getString("disposition"),
                rs.getString("source_priority"), rs.getString("evaluation_status"), rs.getString("final_severity"),
                format(instant(rs, "first_seen_at")), format(instant(rs, "last_seen_at")),
                rs.getLong("occurrence_count"), sensors, asset,
                new ProcessSummary(rs.getString("process_executable"), rs.getString("parent_executable"), rs.getString("user_id")),
                new TargetSummary(rs.getString("target_type"), rs.getString("target_name"), rs.getString("operation")),
                nullableLong(rs, "assignee_user_id"), rs.getString("assignee_display_name"),
                rs.getString("note"), rs.getLong("version"));
    }

    private static JdbcClient.StatementSpec withRangeAndCluster(JdbcClient.StatementSpec spec, String clusterId,
                                                                 Instant from, Instant to) {
        return withCluster(spec, clusterId)
                .param("from", OffsetDateTime.ofInstant(from, ZoneOffset.UTC))
                .param("to", OffsetDateTime.ofInstant(to, ZoneOffset.UTC));
    }

    private static JdbcClient.StatementSpec withCluster(JdbcClient.StatementSpec spec, String clusterId) {
        return spec.param("allClusters", "ALL".equals(clusterId)).param("clusterId", clusterId);
    }

    private static String clusterCondition(String clusterId, String column) {
        return "ALL".equals(clusterId) ? "" : " AND " + column + " = :clusterId";
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private static String format(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    public record RuntimeCounts(long eventCount, long suppressedCount, long rateLimitedCount,
                                long observedCount,
                                long unreviewedCount, long workloadCount, long unresolvedCount) {
    }

    public record SensorCounts(long total, long healthy, long degraded, long offline, long unknown) {
    }

    public record CurrentFinding(String reviewStatus, String actionStatus, String disposition,
                                 Long assigneeUserId, String note, long version) {
    }
}
