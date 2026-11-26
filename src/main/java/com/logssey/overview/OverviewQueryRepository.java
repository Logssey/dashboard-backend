package com.logssey.overview;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.logssey.overview.dto.response.PriorityFindingListResponse.AssetRef;
import com.logssey.overview.dto.response.PriorityFindingListResponse.PriorityFinding;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * 통합 현황의 연결 자산 수. 각 보안 기능이 실제로 본 자산을 센다 (샘플 assets 표는 쓰지 않는다).
 * - AWS: 컴플라이언스 최신 점검이 본 클라우드 자원
 * - Kubernetes: 실행 중인 워크로드 (취약점 관리 L1 수집 + 런타임 센서). 운영 클러스터라 PROD
 * - GitHub: 검사한 레포 (코드 취약점·IaC·취약점 관리 레포 스캔). IaC 레포는 등록 환경, 나머지는 PROD
 * 처음 만든 공통 탐지 이벤트(detection_events)도 행이 있으면 함께 센다 (운영에는 행이 없다).
 */
@Repository
public class OverviewQueryRepository {

    private final JdbcClient jdbcClient;

    public OverviewQueryRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /**
     * 숫자에 포함할 탐지 이벤트 조건. 결정: 조치 완료·위험 수용 건도 전부 포함한다.
     * 시크릿은 대응 건(SecretOverviewProjection)으로 세므로 SECRETS 도메인 이벤트는 뺀다
     */
    static final String COUNTED_EVENTS = "e.domain IS DISTINCT FROM 'SECRETS'";

    /** 기존 탐지 이벤트 전체 (심각도 높은 순 → 최신순) */
    public List<PriorityFinding> legacyEvents(EnvironmentFilter environment) {
        return jdbcClient.sql("""
                SELECT e.event_id, e.display_id, e.severity, e.title, e.environment, e.owner_team,
                       e.review_status, e.action_status, e.detected_at, e.domain, e.evidence, e.recommendation,
                       a.asset_id, a.name AS asset_name, a.provider, a.asset_type
                FROM detection_events e
                LEFT JOIN assets a ON a.asset_id = e.asset_id
                WHERE %s AND (:environment = 'ALL' OR e.environment = :environment)
                ORDER BY CASE e.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                         e.detected_at DESC
                """.formatted(COUNTED_EVENTS))
                .param("environment", environment.name())
                .query((rs, rowNum) -> {
                    long assetId = rs.getLong("asset_id");
                    AssetRef asset = rs.wasNull() ? null : new AssetRef(
                            assetId, rs.getString("asset_name"), rs.getString("provider"), rs.getString("asset_type"));
                    return new PriorityFinding(rs.getLong("event_id"), rs.getString("display_id"), rs.getString("severity"),
                            rs.getString("title"), asset, rs.getString("environment"), rs.getString("owner_team"),
                            rs.getString("review_status"), rs.getString("action_status"),
                            OverviewService.formatInstant(rs.getObject("detected_at", OffsetDateTime.class).toInstant()),
                            rs.getString("domain"), rs.getString("evidence"), rs.getString("recommendation"));
                })
                .list();
    }

    public long countAwsAssets(EnvironmentFilter environment) {
        return jdbcClient.sql("""
                WITH latest AS (
                    SELECT DISTINCT ON (target_key, environment) run_id, environment
                    FROM compliance_runs ORDER BY target_key, environment, created_at DESC, run_id DESC)
                SELECT count(DISTINCT coalesce(r.asset_uid, r.asset))
                FROM compliance_results r JOIN latest l ON l.run_id = r.run_id
                WHERE (:environment = 'ALL' OR upper(l.environment) = :environment)
                """).param("environment", environment.name()).query(Long.class).single();
    }

    public long countKubernetesWorkloads(EnvironmentFilter environment) {
        if (environment == EnvironmentFilter.DEV) return 0;
        return jdbcClient.sql("""
                SELECT count(*) FROM (
                    SELECT namespace, name FROM reach_workloads
                    UNION
                    SELECT namespace, workload_name FROM runtime_assets WHERE valid_to IS NULL AND workload_name IS NOT NULL
                ) w
                """).query(Long.class).single();
    }

    public long countRepositories(EnvironmentFilter environment) {
        record Repo(String name, String environment) {
        }
        List<Repo> repos = jdbcClient.sql("""
                SELECT repository AS name, 'PROD' AS environment FROM code_scans
                UNION ALL SELECT full_name, environment FROM iac_repos
                UNION ALL SELECT repo_name, 'PROD' FROM reach_targets WHERE target_type = 'REPO' AND repo_name IS NOT NULL
                """).query((rs, n) -> new Repo(rs.getString("name"), rs.getString("environment"))).list();
        Set<String> names = new HashSet<>();
        for (Repo repo : repos) {
            if (environment.isAll() || environment.name().equals(repo.environment())) {
                // 레포는 소유자를 붙이기도(Logssey/service-backend) 안 붙이기도 해서 이름만 비교한다
                names.add(repo.name().substring(repo.name().indexOf('/') + 1).toLowerCase(Locale.ROOT));
            }
        }
        return names.size();
    }
}
