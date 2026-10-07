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

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** 통합 현황 계산. 보안 점수 등 계산은 여기 한 곳에서만 한다 (API 명세 0.5) */
@Service
@Transactional(readOnly = true)
public class OverviewService {

    static final ZoneId KOREA = ZoneId.of("Asia/Seoul");

    private static final int CRITICAL_PENALTY = 4;
    private static final int HIGH_PENALTY = 1;
    private static final String SCORE_RULE = "CRITICAL -" + CRITICAL_PENALTY + ", HIGH -" + HIGH_PENALTY;

    /** 샘플 단계의 "마지막 수집 시각"은 서버를 켠 시각이다 */
    private final Instant collectedAt = Instant.now();

    private final OverviewQueryRepository queryRepository;

    public OverviewService(OverviewQueryRepository queryRepository) {
        this.queryRepository = queryRepository;
    }

    public OverviewSummaryResponse getSummary(EnvironmentFilter environment) {
        EventCounts counts = queryRepository.countEvents(environment);
        long assetCount = queryRepository.countAssets(environment);
        int score = (int) Math.max(0, 100 - counts.critical() * CRITICAL_PENALTY - counts.high() * HIGH_PENALTY);
        return new OverviewSummaryResponse(
                counts.unreviewedCritical(),
                counts.total(),
                counts.unreviewed(),
                assetCount,
                score,
                SCORE_RULE,
                formatInstant(collectedAt));
    }

    public RiskTrendResponse getRiskTrend(EnvironmentFilter environment, int days) {
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

        List<RiskTrendResponse.DayCount> result = new ArrayList<>();
        byDay.forEach((day, counts) -> {
            long critical = counts.getOrDefault(Severity.CRITICAL, 0L);
            long high = counts.getOrDefault(Severity.HIGH, 0L);
            long medium = counts.getOrDefault(Severity.MEDIUM, 0L);
            long low = counts.getOrDefault(Severity.LOW, 0L);
            result.add(new RiskTrendResponse.DayCount(
                    day.toString(), critical + high + medium + low, critical, high, medium, low));
        });
        return new RiskTrendResponse(result);
    }

    public AssetSummaryResponse getAssetSummary(EnvironmentFilter environment) {
        Map<String, Long> countByProvider = new LinkedHashMap<>();
        for (ProviderAssetCount row : queryRepository.countAssetsByProvider(environment)) {
            countByProvider.put(row.provider(), row.count());
        }
        // 화면 카드 순서대로, 0개여도 항상 3개를 보낸다. 설명 문구는 샘플 값
        List<AssetSummaryResponse.ProviderCount> providers = List.of(
                new AssetSummaryResponse.ProviderCount("AWS", "1개 계정 · 도쿄 리전",
                        countByProvider.getOrDefault("AWS", 0L)),
                new AssetSummaryResponse.ProviderCount("KUBERNETES", "1개 클러스터",
                        countByProvider.getOrDefault("KUBERNETES", 0L)),
                new AssetSummaryResponse.ProviderCount("GITHUB", "소스 코드 저장소",
                        countByProvider.getOrDefault("GITHUB", 0L)));
        long total = providers.stream().mapToLong(AssetSummaryResponse.ProviderCount::count).sum();
        return new AssetSummaryResponse(total, providers);
    }

    public PriorityFindingListResponse getPriorityFindings(EnvironmentFilter environment, int limit) {
        if (limit < 1 || limit > 20) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "limit은 1~20 사이여야 합니다.");
        }
        return new PriorityFindingListResponse(
                queryRepository.findPriorityFindings(environment, limit),
                queryRepository.countUnreviewed(environment));
    }

    /** API 명세 0.5: 시간은 ISO 8601 UTC (예: 2026-10-06T05:30:00Z) */
    static String formatInstant(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private enum Severity { CRITICAL, HIGH, MEDIUM, LOW }
}
