package com.logssey.overview;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.overview.OverviewQueryRepository.DailySeverityCount;
import com.logssey.overview.OverviewQueryRepository.EventCounts;
import com.logssey.overview.OverviewQueryRepository.ProviderAssetCount;
import com.logssey.overview.dto.response.AssetSummaryResponse;
import com.logssey.overview.dto.response.OverviewSummaryResponse;
import com.logssey.overview.dto.response.PriorityFindingListResponse;
import com.logssey.overview.dto.response.RiskTrendResponse;
import com.logssey.overview.dto.response.PriorityFindingListResponse.PriorityFinding;
import com.logssey.secret.query.SecretOverviewProjection;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** 통합 현황 계산. 보안 점수 등 계산은 여기 한 곳에서만 한다 (API 명세 0.5) */
@Service
@Transactional(readOnly = true, isolation = org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
public class OverviewService {

    static final ZoneId KOREA = ZoneId.of("Asia/Seoul");

    private static final int CRITICAL_PENALTY = 4;
    private static final int HIGH_PENALTY = 1;
    private static final String SCORE_RULE = "CRITICAL -" + CRITICAL_PENALTY + ", HIGH -" + HIGH_PENALTY;

    private final OverviewQueryRepository queryRepository;
    private final SecretOverviewProjection secrets;

    public OverviewService(OverviewQueryRepository queryRepository, SecretOverviewProjection secrets) {
        this.queryRepository = queryRepository;
        this.secrets = secrets;
    }

    public OverviewSummaryResponse getSummary(EnvironmentFilter environment, String login) {
        EventCounts counts = queryRepository.countEvents(environment);
        var secret = secrets.read(login,environment.name());
        long secretCritical=secret.cases().stream().filter(c -> "CRITICAL".equals(c.severity())).count();
        long secretHigh=secret.cases().stream().filter(c -> "HIGH".equals(c.severity())).count();
        long secretAction=secret.cases().stream().filter(SecretOverviewProjection.Case::needsAction).count();
        long secretUrgent=secret.cases().stream().filter(SecretOverviewProjection.Case::needsAction)
                .filter(c -> "CRITICAL".equals(c.severity())).count();
        long assetCount = queryRepository.countAssets(environment);
        int score = (int) Math.max(0, 100 - (counts.critical()+secretCritical) * CRITICAL_PENALTY - (counts.high()+secretHigh) * HIGH_PENALTY);
        Instant collectedAt=latest(queryRepository.latestDetection(environment),secret.lastObservedAt());
        boolean available="AVAILABLE".equals(secret.status());
        return new OverviewSummaryResponse(
                counts.unreviewedCritical()+secretUrgent,
                counts.total()+secret.cases().size(),
                counts.unreviewed()+secretAction,
                assetCount,
                score,
                SCORE_RULE,
                formatInstant(collectedAt),new OverviewSummaryResponse.SecretIntegration(secret.status(),"ResponseCase","PRODUCTION",
                    available?(long)secret.cases().size():null,available?secret.unassessedCount():null,
                    available?secret.notApplicableCount():null,secret.restrictedCoverage()));
    }

    public RiskTrendResponse getRiskTrend(EnvironmentFilter environment, int days, String login) {
        if (days < 1 || days > 30) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "days는 1~30 사이여야 합니다.");
        }
        LocalDate today = LocalDate.now(KOREA);
        LocalDate firstDay = today.minusDays(days - 1L);
        Instant from = firstDay.atStartOfDay(KOREA).toInstant();
        Instant to = today.plusDays(1).atStartOfDay(KOREA).toInstant();

        // 0건인 날도 빠지지 않게 날짜 칸을 먼저 만든다
        Map<LocalDate, Map<Severity, Long>> byDay = new LinkedHashMap<>();
        for (LocalDate day = firstDay; !day.isAfter(today); day = day.plusDays(1)) {
            byDay.put(day, new EnumMap<>(Severity.class));
        }
        for (DailySeverityCount row : queryRepository.countDailyBySeverity(from, to, environment)) {
            Map<Severity, Long> counts = byDay.get(row.date());
            if (counts != null) {
                counts.merge(Severity.valueOf(row.severity()), row.count(), Long::sum);
            }
        }

        // Current Secret cases grouped by opening day, never raw findings or locations.
        for(var secret:secrets.read(login,environment.name()).cases()) {
            var counts=byDay.get(secret.openedAt().atZone(KOREA).toLocalDate());
            if(counts!=null) {
                Severity grade="NOT_APPLICABLE".equals(secret.assessmentStatus())?Severity.NOT_APPLICABLE
                        :secret.severity()==null||"UNASSESSED".equals(secret.severity())?Severity.UNASSESSED:Severity.valueOf(secret.severity());
                counts.merge(grade,1L,Long::sum);
            }
        }

        List<RiskTrendResponse.DayCount> result = new ArrayList<>();
        byDay.forEach((day, counts) -> {
            long critical = counts.getOrDefault(Severity.CRITICAL, 0L);
            long high = counts.getOrDefault(Severity.HIGH, 0L);
            long medium = counts.getOrDefault(Severity.MEDIUM, 0L);
            long low = counts.getOrDefault(Severity.LOW, 0L);
            long unassessed=counts.getOrDefault(Severity.UNASSESSED,0L);
            long notApplicable=counts.getOrDefault(Severity.NOT_APPLICABLE,0L);
            result.add(new RiskTrendResponse.DayCount(
                    day.toString(), critical + high + medium + low + unassessed + notApplicable,
                    critical, high, medium, low,unassessed,notApplicable));
        });
        return new RiskTrendResponse(result);
    }

    public AssetSummaryResponse getAssetSummary(EnvironmentFilter environment) {
        Map<String, Long> countByProvider = new LinkedHashMap<>();
        for (ProviderAssetCount row : queryRepository.countAssetsByProvider(environment)) {
            countByProvider.put(row.provider(), row.count());
        }
        // Descriptions name the asset class; no invented account, region or cluster counts.
        List<AssetSummaryResponse.ProviderCount> providers = List.of(
                new AssetSummaryResponse.ProviderCount("AWS", "등록된 클라우드 자산",
                        countByProvider.getOrDefault("AWS", 0L)),
                new AssetSummaryResponse.ProviderCount("KUBERNETES", "등록된 클러스터 자산",
                        countByProvider.getOrDefault("KUBERNETES", 0L)),
                new AssetSummaryResponse.ProviderCount("GITHUB", "소스 코드 저장소",
                        countByProvider.getOrDefault("GITHUB", 0L)));
        long total = providers.stream().mapToLong(AssetSummaryResponse.ProviderCount::count).sum();
        return new AssetSummaryResponse(total, providers);
    }

    public PriorityFindingListResponse getPriorityFindings(EnvironmentFilter environment, int limit, String login) {
        if (limit < 1 || limit > 20) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "limit은 1~20 사이여야 합니다.");
        }
        var items=new ArrayList<>(queryRepository.findPriorityFindings(environment, limit));
        var cases=secrets.read(login,environment.name()).cases().stream().filter(SecretOverviewProjection.Case::needsAction).toList();
        for(var c:cases)items.add(new PriorityFinding(null,"SEC-"+c.id(),c.severity(),c.maskedLabel(),null,
            c.environment(),c.ownerTeam(),null,c.stage(),formatInstant(c.openedAt()),"SECRETS",null,
            "발견 위치와 판단 근거를 확인하고 담당자와 조치 내용을 기록하세요.","SECRET_CASE",c.id(),
            "/secrets/cases/"+c.id()+"?origin=PRODUCTION",c.assessmentStatus()));
        items.sort(java.util.Comparator.comparingInt((PriorityFinding p) -> priority(p.severity()))
            .thenComparing(PriorityFinding::detectedAt,java.util.Comparator.reverseOrder())
            .thenComparing(PriorityFinding::sourceType).thenComparingLong(PriorityFinding::sourceId));
        return new PriorityFindingListResponse(items.stream().limit(limit).toList(),
                queryRepository.countUnreviewed(environment)+cases.size());
    }

    /** API 명세 0.5: 시간은 ISO 8601 UTC (예: 2026-10-06T05:30:00Z) */
    static String formatInstant(Instant instant) {
        return instant==null?null:instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private static Instant latest(Instant a,Instant b) { return a==null?b:b==null||a.isAfter(b)?a:b; }
    private static int priority(String grade) {
        return grade==null?5:switch(grade){case "CRITICAL"->0;case "HIGH"->1;case "MEDIUM"->2;case "LOW"->3;default->4;};
    }
    private enum Severity { CRITICAL, HIGH, MEDIUM, LOW, UNASSESSED, NOT_APPLICABLE }
}
