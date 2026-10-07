package com.logssey.overview;

import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.overview.dto.response.PriorityFindingListResponse.AssetRef;
import com.logssey.overview.dto.response.PriorityFindingListResponse.PriorityFinding;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** 통합 현황 집계용 조회. 숫자 세기가 대부분이라 SQL로 직접 조회한다 */
@Repository
public class OverviewQueryRepository {

    /**
     * 숫자에 포함할 탐지 이벤트 조건 (보안 점수, 전체 탐지 수, 위험 추이).
     * 결정: 조치 완료·위험 수용 건도 전부 포함한다.
     * 나중에 기준이 바뀌면 이 한 줄만 고친다. 예: "action_status NOT IN ('RESOLVED', 'RISK_ACCEPTED')"
     */
    static final String COUNTED_EVENTS = "TRUE";

    private final JdbcClient jdbcClient;

    public OverviewQueryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record EventCounts(long unreviewedCritical, long total, long unreviewed, long critical, long high) {
    }

    public EventCounts countEvents(EnvironmentFilter environment) {
        String sql = """
                SELECT
                    count(*) FILTER (WHERE review_status = 'UNREVIEWED' AND severity = 'CRITICAL') AS unreviewed_critical,
                    count(*)                                                                   AS total,
                    count(*) FILTER (WHERE review_status = 'UNREVIEWED')                       AS unreviewed,
                    count(*) FILTER (WHERE severity = 'CRITICAL')                              AS critical,
                    count(*) FILTER (WHERE severity = 'HIGH')                                  AS high
                FROM detection_events
                WHERE %s
                """.formatted(COUNTED_EVENTS) + environmentCondition(environment, "environment");
        return withEnvironment(jdbcClient.sql(sql), environment)
                .query((rs, rowNum) -> new EventCounts(
                        rs.getLong("unreviewed_critical"),
                        rs.getLong("total"),
                        rs.getLong("unreviewed"),
                        rs.getLong("critical"),
                        rs.getLong("high")))
                .single();
    }

    public long countAssets(EnvironmentFilter environment) {
        String sql = "SELECT count(*) FROM assets WHERE TRUE" + environmentCondition(environment, "environment");
        return withEnvironment(jdbcClient.sql(sql), environment).query(Long.class).single();
    }

    public record ProviderAssetCount(String provider, long count) {
    }

    public List<ProviderAssetCount> countAssetsByProvider(EnvironmentFilter environment) {
        String sql = "SELECT provider, count(*) AS cnt FROM assets WHERE TRUE"
                + environmentCondition(environment, "environment")
                + " GROUP BY provider";
        return withEnvironment(jdbcClient.sql(sql), environment)
                .query((rs, rowNum) -> new ProviderAssetCount(rs.getString("provider"), rs.getLong("cnt")))
                .list();
    }

    public record DailySeverityCount(LocalDate date, String severity, long count) {
    }

    /** [from, to) 구간의 탐지를 한국 날짜·심각도별로 센다 */
    public List<DailySeverityCount> countDailyBySeverity(Instant from, Instant to, EnvironmentFilter environment) {
        String sql = """
                SELECT (detected_at AT TIME ZONE 'Asia/Seoul')::date AS day, severity, count(*) AS cnt
                FROM detection_events
                WHERE detected_at >= :from AND detected_at < :to AND %s
                """.formatted(COUNTED_EVENTS)
                + environmentCondition(environment, "environment")
                + " GROUP BY day, severity";
        return withEnvironment(jdbcClient.sql(sql), environment)
                .param("from", OffsetDateTime.ofInstant(from, java.time.ZoneOffset.UTC))
                .param("to", OffsetDateTime.ofInstant(to, java.time.ZoneOffset.UTC))
                .query((rs, rowNum) -> new DailySeverityCount(
                        rs.getObject("day", LocalDate.class),
                        rs.getString("severity"),
                        rs.getLong("cnt")))
                .list();
    }

    public long countUnreviewed(EnvironmentFilter environment) {
        String sql = "SELECT count(*) FROM detection_events WHERE review_status = 'UNREVIEWED'"
                + environmentCondition(environment, "environment");
        return withEnvironment(jdbcClient.sql(sql), environment).query(Long.class).single();
    }

    /** 미검토만, 심각도 높은 순 → 같으면 최신순 */
    public List<PriorityFinding> findPriorityFindings(EnvironmentFilter environment, int limit) {
        String sql = """
                SELECT e.event_id, e.display_id, e.severity, e.title, e.environment, e.owner_team,
                       e.review_status, e.action_status, e.detected_at, e.domain, e.evidence, e.recommendation,
                       a.asset_id, a.name AS asset_name, a.provider, a.asset_type
                FROM detection_events e
                LEFT JOIN assets a ON a.asset_id = e.asset_id
                WHERE e.review_status = 'UNREVIEWED'
                """
                + environmentCondition(environment, "e.environment")
                + """
                 ORDER BY CASE e.severity
                              WHEN 'CRITICAL' THEN 1
                              WHEN 'HIGH' THEN 2
                              WHEN 'MEDIUM' THEN 3
                              ELSE 4
                          END,
                          e.detected_at DESC
                 LIMIT :limit
                """;
        return withEnvironment(jdbcClient.sql(sql), environment)
                .param("limit", limit)
                .query((rs, rowNum) -> {
                    long assetId = rs.getLong("asset_id");
                    AssetRef asset = rs.wasNull() ? null : new AssetRef(
                            assetId, rs.getString("asset_name"), rs.getString("provider"), rs.getString("asset_type"));
                    return new PriorityFinding(
                            rs.getLong("event_id"),
                            rs.getString("display_id"),
                            rs.getString("severity"),
                            rs.getString("title"),
                            asset,
                            rs.getString("environment"),
                            rs.getString("owner_team"),
                            rs.getString("review_status"),
                            rs.getString("action_status"),
                            OverviewService.formatInstant(rs.getObject("detected_at", OffsetDateTime.class).toInstant()),
                            rs.getString("domain"),
                            rs.getString("evidence"),
                            rs.getString("recommendation"));
                })
                .list();
    }

    private static String environmentCondition(EnvironmentFilter environment, String column) {
        return environment.isAll() ? "" : " AND " + column + " = :environment";
    }

    private static JdbcClient.StatementSpec withEnvironment(JdbcClient.StatementSpec spec, EnvironmentFilter environment) {
        return environment.isAll() ? spec : spec.param("environment", environment.name());
    }
}
