package com.logssey.overview;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.overview.dto.response.AssetSummaryResponse;
import com.logssey.overview.dto.response.OverviewSummaryResponse;
import com.logssey.overview.dto.response.PriorityFindingListResponse;
import com.logssey.overview.dto.response.PriorityFindingListResponse.PriorityFinding;
import com.logssey.overview.dto.response.RiskTrendResponse;
import com.logssey.secret.query.SecretOverviewProjection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 통합 현황 계산. 보안 점수 등 계산은 여기 한 곳에서만 한다 (API 명세 0.5).
 *
 * 세는 단위: 각 기능의 "지금 열린" 위험을 같은 원인끼리 묶은 한 건 (OverviewItem.groupKey). 묶음의 심각도는 가장 높은 것.
 * 시크릿은 대응 건(case)이 이미 한 건이다. 모든 카드(건수·점수·추이·우선 목록)가 같은 단위를 쓴다.
 */
@Service
@Transactional(readOnly = true, isolation = org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
public class OverviewService {

    static final ZoneId KOREA = ZoneId.of("Asia/Seoul");

    /** 점수 규칙 (ADR-D006). 위험 판단 방식이 정해지면 이 두 값과 penalty() 만 바꾼다 */
    private static final int CRITICAL_PENALTY = 4;
    private static final int HIGH_PENALTY = 1;
    private static final String SCORE_RULE = "CRITICAL -" + CRITICAL_PENALTY + ", HIGH -" + HIGH_PENALTY;

    private final OverviewQueryRepository queryRepository;
    private final SecretOverviewProjection secrets;
    private final OverviewSources sources;

    /** 시크릿만 보는 구성 (시크릿 통합 테스트) */
    public OverviewService(OverviewQueryRepository queryRepository, SecretOverviewProjection secrets) {
        this(queryRepository, secrets, null);
    }

    @Autowired
    public OverviewService(OverviewQueryRepository queryRepository, SecretOverviewProjection secrets, OverviewSources sources) {
        this.queryRepository = queryRepository;
        this.secrets = secrets;
        this.sources = sources;
    }

    /** 같은 원인으로 묶은 한 건 */
    private record Group(OverviewPart part, String severity, String title, String environment, boolean needsAction,
                         Instant firstSeenAt, String detailPath, int count) {
    }

    private record PartView(OverviewPart part, String status, List<Group> groups, Instant dataAsOf) {
    }

    private record Snapshot(SecretOverviewProjection.Result secret, List<PartView> parts, List<PriorityFinding> legacy) {
        List<Group> groups() {
            return parts.stream().flatMap(p -> p.groups().stream()).toList();
        }
    }

    private Snapshot snapshot(EnvironmentFilter environment, String login) {
        var secret = secrets.read(login, environment.name());
        List<PartView> parts = new ArrayList<>();
        List<Group> secretGroups = secret.cases().stream().map(c -> new Group(OverviewPart.SECRET, secretSeverity(c),
                c.maskedLabel(), c.environment(), c.needsAction(), c.openedAt(), null, 1)).toList();
        parts.add(new PartView(OverviewPart.SECRET, "AVAILABLE".equals(secret.status()) ? "CONNECTED" : secret.status(),
                secretGroups, secret.lastObservedAt()));
        var legacy = queryRepository.legacyEvents(environment);
        if (!legacy.isEmpty()) {
            List<Group> legacyGroups = legacy.stream().map(e -> new Group(OverviewPart.LEGACY, OverviewItem.severity(e.severity()),
                    e.title(), e.environment(), "UNREVIEWED".equals(e.reviewStatus()), Instant.parse(e.detectedAt()), null, 1)).toList();
            parts.add(new PartView(OverviewPart.LEGACY, "CONNECTED", legacyGroups,
                    legacyGroups.stream().map(Group::firstSeenAt).max(Comparator.naturalOrder()).orElse(null)));
        }
        if (sources != null) {
            for (var data : sources.read(login)) {
                List<OverviewItem> items = data.items().stream()
                        .filter(i -> environment.isAll() || environment.name().equals(i.environment())).toList();
                parts.add(new PartView(data.part(), data.status(), group(items), data.dataAsOf()));
            }
        }
        return new Snapshot(secret, parts, legacy);
    }

    /** 같은 groupKey 를 한 건으로. 심각도는 가장 높은 것, 처음 본 때는 가장 이른 것 */
    static List<Group> group(List<OverviewItem> items) {
        Map<String, List<OverviewItem>> byKey = new LinkedHashMap<>();
        for (OverviewItem item : items) {
            byKey.computeIfAbsent(item.environment() + "|" + item.groupKey(), k -> new ArrayList<>()).add(item);
        }
        List<Group> groups = new ArrayList<>();
        byKey.values().forEach(members -> {
            OverviewItem top = members.stream().min(Comparator.comparingInt(i -> OverviewItem.rank(i.severity()))).orElseThrow();
            Instant first = members.stream().map(OverviewItem::firstSeenAt).filter(java.util.Objects::nonNull)
                    .min(Comparator.naturalOrder()).orElse(null);
            groups.add(new Group(top.part(), top.severity(), top.title(), top.environment(),
                    members.stream().anyMatch(OverviewItem::needsAction), first, top.detailPath(), members.size()));
        });
        return groups;
    }

    public OverviewSummaryResponse getSummary(EnvironmentFilter environment, String login) {
        Snapshot snapshot = snapshot(environment, login);
        List<Group> groups = snapshot.groups();
        long critical = count(groups, "CRITICAL"), high = count(groups, "HIGH");
        int score = (int) Math.max(0, 100 - penalty(critical, high));
        Instant collectedAt = snapshot.parts().stream().map(PartView::dataAsOf).filter(java.util.Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null);
        var secret = snapshot.secret();
        boolean available = "AVAILABLE".equals(secret.status());
        List<OverviewSummaryResponse.PartSummary> parts = snapshot.parts().stream().map(p -> {
            long c = count(p.groups(), "CRITICAL"), h = count(p.groups(), "HIGH");
            return new OverviewSummaryResponse.PartSummary(p.part().name(), p.part().label(), p.status(), p.part().link(),
                    c, h, count(p.groups(), "MEDIUM"), count(p.groups(), "LOW"),
                    p.groups().stream().filter(g -> OverviewItem.rank(g.severity()) >= 4).count(),
                    p.groups().size(), penalty(c, h), formatInstant(p.dataAsOf()));
        }).toList();
        return new OverviewSummaryResponse(
                groups.stream().filter(Group::needsAction).filter(g -> "CRITICAL".equals(g.severity())).count(),
                groups.size(),
                groups.stream().filter(Group::needsAction).count(),
                assetTotal(environment),
                score,
                SCORE_RULE,
                formatInstant(collectedAt), new OverviewSummaryResponse.SecretIntegration(secret.status(), "ResponseCase", "ALL",
                    available ? (long) secret.cases().size() : null, available ? secret.unassessedCount() : null,
                    available ? secret.notApplicableCount() : null, secret.restrictedCoverage()),
                parts);
    }

    public RiskTrendResponse getRiskTrend(EnvironmentFilter environment, int days, String login) {
        if (days < 1 || days > 30) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "days는 1~30 사이여야 합니다.");
        }
        LocalDate today = LocalDate.now(KOREA);
        LocalDate firstDay = today.minusDays(days - 1L);

        // 0건인 날도 빠지지 않게 날짜 칸을 먼저 만든다
        Map<LocalDate, Map<Severity, Long>> byDay = new LinkedHashMap<>();
        for (LocalDate day = firstDay; !day.isAfter(today); day = day.plusDays(1)) {
            byDay.put(day, new EnumMap<>(Severity.class));
        }
        // 지금 열린 위험(묶은 한 건)을 처음 본 날로 나눈다. 시크릿은 대응 건이 열린 날
        for (Group group : snapshot(environment, login).groups()) {
            if (group.firstSeenAt() == null) continue;
            var counts = byDay.get(group.firstSeenAt().atZone(KOREA).toLocalDate());
            if (counts != null) counts.merge(Severity.valueOf(group.severity()), 1L, Long::sum);
        }

        List<RiskTrendResponse.DayCount> result = new ArrayList<>();
        byDay.forEach((day, counts) -> {
            long critical = counts.getOrDefault(Severity.CRITICAL, 0L);
            long high = counts.getOrDefault(Severity.HIGH, 0L);
            long medium = counts.getOrDefault(Severity.MEDIUM, 0L);
            long low = counts.getOrDefault(Severity.LOW, 0L);
            long unassessed = counts.getOrDefault(Severity.UNASSESSED, 0L);
            long notApplicable = counts.getOrDefault(Severity.NOT_APPLICABLE, 0L);
            result.add(new RiskTrendResponse.DayCount(
                    day.toString(), critical + high + medium + low + unassessed + notApplicable,
                    critical, high, medium, low, unassessed, notApplicable));
        });
        return new RiskTrendResponse(result);
    }

    public AssetSummaryResponse getAssetSummary(EnvironmentFilter environment) {
        List<AssetSummaryResponse.ProviderCount> providers = List.of(
                new AssetSummaryResponse.ProviderCount("AWS", "컴플라이언스로 점검한 클라우드 자원",
                        queryRepository.countAwsAssets(environment)),
                new AssetSummaryResponse.ProviderCount("KUBERNETES", "실행 중인 워크로드",
                        queryRepository.countKubernetesWorkloads(environment)),
                new AssetSummaryResponse.ProviderCount("GITHUB", "검사한 소스 코드 저장소",
                        queryRepository.countRepositories(environment)));
        long total = providers.stream().mapToLong(AssetSummaryResponse.ProviderCount::count).sum();
        return new AssetSummaryResponse(total, providers);
    }

    public PriorityFindingListResponse getPriorityFindings(EnvironmentFilter environment, int limit, String login) {
        if (limit < 1 || limit > 20) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "limit은 1~20 사이여야 합니다.");
        }
        Snapshot snapshot = snapshot(environment, login);
        List<PriorityFinding> items = new ArrayList<>();
        var cases = snapshot.secret().cases().stream().filter(SecretOverviewProjection.Case::needsAction).toList();
        for (var c : cases) items.add(new PriorityFinding(null, "SEC-" + c.id(), c.severity(), c.maskedLabel(), null,
                c.environment(), c.ownerTeam(), null, c.stage(), formatInstant(c.openedAt()), "SECRETS", null,
                "발견 위치와 판단 근거를 확인하고 담당자와 조치 내용을 기록하세요.", "SECRET_CASE", c.id(),
                "/secrets/cases/" + c.id() + "?origin=" + c.caseOrigin(), c.assessmentStatus()));
        var legacy = snapshot.legacy().stream().filter(e -> "UNREVIEWED".equals(e.reviewStatus())).toList();
        items.addAll(legacy);
        long open = cases.size() + legacy.size();
        for (PartView part : snapshot.parts()) {
            if (part.part() == OverviewPart.SECRET || part.part() == OverviewPart.LEGACY) continue;
            for (Group g : part.groups()) {
                if (!g.needsAction()) continue;
                open++;
                items.add(new PriorityFinding(null, part.part().label(), g.severity(), g.title(), null, g.environment(),
                        null, null, "OPEN", formatInstant(g.firstSeenAt()), null,
                        g.count() > 1 ? "같은 원인 " + g.count() + "건을 한 건으로 묶었어요." : null, null,
                        "PART_FINDING", 0, g.detailPath(), OverviewItem.rank(g.severity()) <= 3 ? "ASSESSED" : "UNASSESSED"));
            }
        }
        items.sort(Comparator.comparingInt((PriorityFinding p) -> OverviewItem.rank(p.severity()))
                .thenComparing(PriorityFinding::detectedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(PriorityFinding::sourceType).thenComparingLong(PriorityFinding::sourceId));
        return new PriorityFindingListResponse(items.stream().limit(limit).toList(), open);
    }

    private long assetTotal(EnvironmentFilter environment) {
        return getAssetSummary(environment).totalCount();
    }

    private static long penalty(long critical, long high) {
        return critical * CRITICAL_PENALTY + high * HIGH_PENALTY;
    }

    private static long count(List<Group> groups, String severity) {
        return groups.stream().filter(g -> severity.equals(g.severity())).count();
    }

    private static String secretSeverity(SecretOverviewProjection.Case c) {
        if ("NOT_APPLICABLE".equals(c.assessmentStatus())) return "NOT_APPLICABLE";
        return c.severity() == null || "UNASSESSED".equals(c.severity()) ? "UNASSESSED" : OverviewItem.severity(c.severity());
    }

    /** API 명세 0.5: 시간은 ISO 8601 UTC (예: 2026-10-06T05:30:00Z) */
    static String formatInstant(Instant instant) {
        return instant == null ? null : instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private enum Severity { CRITICAL, HIGH, MEDIUM, LOW, UNASSESSED, NOT_APPLICABLE }
}
