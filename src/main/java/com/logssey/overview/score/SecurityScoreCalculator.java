package com.logssey.overview.score;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.logssey.overview.OverviewPart;

/**
 * 통합 현황 보안 점수 (dashboard-design-docs ADR-D012). 입력만으로 계산하는 순수 계산이다.
 * <ol>
 *   <li>열린 위험을 자산에 붙인다(결정 4). 못 붙이면 그 기능의 미분류 자산이다(결정 3)</li>
 *   <li>자산마다 평가 상태를 정한다: 원천의 마지막 성공 검사가 기준 안이면 평가됨, 지났으면 평가 끊김, 없으면 평가 안 됨</li>
 *   <li>자산 감점 = 열린 위험 중 가장 큰 감점(누적하지 않음). 평가 끊김은 최소 HIGH 맨 위(73)</li>
 *   <li>보안 점수 = 100 − Σ(가중치 × 자산 감점) ÷ Σ가중치. 평가 안 됨 자산은 넣지 않는다</li>
 * </ol>
 */
public final class SecurityScoreCalculator {

    public static final String SCORE_RULE = "ADR-D012";

    /** 등급 구간 맨 위 값. 구간은 맨 위 − 25 ~ 맨 위 (결정 1) */
    static final Map<String, Integer> TOP = Map.of("CRITICAL", 99, "HIGH", 73, "MEDIUM", 47);
    static final int BAND = 25;
    /** 미평가와 평가 끊김은 HIGH 맨 위 값으로 본다 (결정 4·5) */
    static final int UNKNOWN_FLOOR = 73;
    /** 처리 기한(일). 미평가는 HIGH 기한 */
    static final Map<String, Integer> DEADLINE_DAYS = Map.of("CRITICAL", 3, "HIGH", 7, "MEDIUM", 30, "UNASSESSED", 7);
    /** 평가 기준: 이미지 실행 중 판정 48시간, 손으로 돌리는 컴플라이언스 30일, 그 밖 7일 */
    static final Map<OverviewPart, Duration> FRESH = new EnumMap<>(Map.of(
            OverviewPart.VULNERABILITY, Duration.ofHours(48),
            OverviewPart.COMPLIANCE, Duration.ofDays(30)));
    static final Duration DEFAULT_FRESH = Duration.ofDays(7);
    static final List<String> GRADES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED");
    static final Map<String, String> AREA_LABELS = new LinkedHashMap<>();
    static {
        AREA_LABELS.put("DATA", "데이터");
        AREA_LABELS.put("CREDENTIAL", "자격 증명");
        AREA_LABELS.put("DEPLOY", "배포");
        AREA_LABELS.put("WORKLOAD", "워크로드");
        AREA_LABELS.put("UNCLASSIFIED", "미분류");
    }
    private static final Set<String> UNREADABLE = Set.of("NOT_AUTHORIZED", "ERROR");

    private SecurityScoreCalculator() {}

    private record Placed(OverviewPart part, ScoreSource.Finding finding, Integer deduction) {}

    /** 자산 칸. config가 null이면 그 기능의 미분류 자산이다 */
    private static final class Slot {
        final ScoreAssets.Asset config;
        final OverviewPart unclassifiedPart;
        final List<Placed> placed = new ArrayList<>();
        String status = "NOT_EVALUATED";
        Instant lastEvaluatedAt;

        Slot(ScoreAssets.Asset config, OverviewPart unclassifiedPart) {
            this.config = config;
            this.unclassifiedPart = unclassifiedPart;
        }

        String id() { return config != null ? config.id() : "unclassified-" + unclassifiedPart.name().toLowerCase(); }
        String name() { return config != null ? config.name() : "미분류-" + unclassifiedPart.label(); }
        int tier() { return config != null ? config.tier() : 1; }
        int weight() { return config != null ? config.weight() : 3; }
        String area() { return config != null ? config.area() : "UNCLASSIFIED"; }
        boolean scoring() { return placed.stream().anyMatch(p -> p.deduction() != null); }

        /** 점수에 넣나: 평가 안 됨은 빼고, 미분류는 점수에 들어가는 열린 위험이 있을 때만 */
        boolean included() { return !"NOT_EVALUATED".equals(status) && (config != null || scoring()); }

        int deduction() {
            int worst = placed.stream().map(Placed::deduction).filter(Objects::nonNull).max(Integer::compare).orElse(0);
            return "STALE".equals(status) ? Math.max(worst, UNKNOWN_FLOOR) : worst;
        }

        int deductionOf(OverviewPart part) {
            return placed.stream().filter(p -> p.part() == part).map(Placed::deduction).filter(Objects::nonNull)
                    .max(Integer::compare).orElse(0);
        }
    }

    /**
     * @param arnKinds iac_data_assets의 ARN → kind (RDS·TFSTATE·SECRET·S3). 데이터 자산을 ARN으로 찾을 때 쓴다
     */
    public static SecurityScoreResponse calculate(ScoreAssets config, Map<String, String> arnKinds,
                                                  List<ScoreSource.Result> results, Instant now) {
        List<Slot> slots = new ArrayList<>();
        config.assets().forEach(a -> slots.add(new Slot(a, null)));
        Map<OverviewPart, Slot> unclassified = new EnumMap<>(OverviewPart.class);
        Map<OverviewPart, ScoreSource.Result> byPart = new EnumMap<>(OverviewPart.class);
        for (var result : results) {
            byPart.put(result.part(), result);
            var slot = new Slot(null, result.part());
            unclassified.put(result.part(), slot);
            slots.add(slot);
        }

        // 1. 열린 위험을 자산에 붙인다
        for (var result : results) {
            for (var finding : result.findings()) {
                var asset = resolve(config, arnKinds, finding.hint());
                Slot slot = asset == null ? unclassified.get(result.part())
                        : slots.stream().filter(s -> s.config == asset).findFirst().orElseThrow();
                slot.placed.add(new Placed(result.part(), finding, deductionOf(finding)));
            }
        }

        // 2. 평가 상태
        for (var slot : slots) {
            List<OverviewPart> parts = slot.config == null ? List.of(slot.unclassifiedPart)
                    : slot.config.sources().stream().map(OverviewPart::valueOf).toList();
            boolean fresh = false;
            Instant last = null;
            for (var part : parts) {
                var result = byPart.get(part);
                if (result == null || UNREADABLE.contains(result.status())) continue;
                for (var coverage : result.coverage()) {
                    if (coverage.lastSuccessAt() == null) continue;
                    if (slot.config != null && !covers(coverage.scope(), slot.config)) continue;
                    if (last == null || coverage.lastSuccessAt().isAfter(last)) last = coverage.lastSuccessAt();
                    if (!coverage.lastSuccessAt().isBefore(now.minus(FRESH.getOrDefault(part, DEFAULT_FRESH)))) fresh = true;
                }
            }
            slot.lastEvaluatedAt = last;
            slot.status = fresh ? "EVALUATED" : last != null ? "STALE" : "NOT_EVALUATED";
        }

        // 3. 점수
        List<Slot> included = slots.stream().filter(Slot::included).toList();
        Integer score = score(included, Slot::deduction);

        int allWeight = slots.stream().filter(s -> s.config != null).mapToInt(Slot::weight).sum();
        int evaluatedWeight = slots.stream().filter(s -> s.config != null && !"NOT_EVALUATED".equals(s.status))
                .mapToInt(Slot::weight).sum();
        int coverage = allWeight == 0 ? 0 : (int) Math.round(100.0 * evaluatedWeight / allWeight);

        List<SecurityScoreResponse.Area> areas = new ArrayList<>();
        AREA_LABELS.forEach((area, label) -> areas.add(new SecurityScoreResponse.Area(area, label,
                score(included.stream().filter(s -> area.equals(s.area())).toList(), Slot::deduction))));

        List<SecurityScoreResponse.Part> parts = results.stream().map(r -> {
            Instant last = r.coverage().stream().map(ScoreSource.Coverage::lastSuccessAt).filter(Objects::nonNull)
                    .max(Comparator.naturalOrder()).orElse(null);
            int weight = included.stream().mapToInt(Slot::weight).sum();
            int penalty = weight == 0 ? 0 : (int) Math.round(
                    included.stream().mapToDouble(s -> s.weight() * s.deductionOf(r.part())).sum() / weight);
            return new SecurityScoreResponse.Part(r.part().name(), r.part().label(), r.status(), format(last),
                    r.findings().size(), penalty);
        }).toList();

        List<Placed> all = slots.stream().flatMap(s -> s.placed.stream()).toList();
        Map<String, Long> distribution = new LinkedHashMap<>();
        GRADES.forEach(g -> distribution.put(g, all.stream().filter(p -> g.equals(p.finding().grade())).count()));
        Long accepted = results.stream().map(ScoreSource.Result::acceptedCount).filter(Objects::nonNull)
                .reduce(Long::sum).orElse(null);
        var indicators = new SecurityScoreResponse.Indicators(
                distribution.get("CRITICAL"),
                all.stream().filter(p -> overdue(p.finding(), now)).count(),
                distribution.get("UNASSESSED"),
                slots.stream().filter(s -> s.config == null).mapToLong(s -> s.placed.stream()
                        .filter(p -> p.deduction() != null).count()).sum(),
                accepted,
                null,
                slots.stream().filter(s -> s.config != null && "STALE".equals(s.status)).map(Slot::name).toList(),
                distribution);

        List<SecurityScoreResponse.AssetScore> assets = slots.stream()
                .filter(s -> s.config != null || !s.placed.isEmpty())
                .map(s -> {
                    var worst = s.placed.stream().filter(p -> p.deduction() != null)
                            .max(Comparator.comparingInt(Placed::deduction))
                            .map(p -> new SecurityScoreResponse.Worst(p.part().name(), p.finding().title(), p.finding().grade(),
                                    p.deduction()))
                            .orElse(null);
                    boolean evaluated = !"NOT_EVALUATED".equals(s.status);
                    return new SecurityScoreResponse.AssetScore(s.id(), s.name(), s.tier(), s.weight(), s.area(), s.status,
                            evaluated ? 100 - s.deduction() : null, evaluated ? s.deduction() : 0,
                            format(s.lastEvaluatedAt), worst, s.placed.size());
                }).toList();

        return new SecurityScoreResponse(score, SCORE_RULE, config.version(), format(now), coverage, indicators, areas,
                assets, parts);
    }

    /** 100 − Σ(가중치 × 감점) ÷ Σ가중치를 정수로. 넣을 자산이 없으면 null("—") */
    private static Integer score(List<Slot> slots, java.util.function.ToIntFunction<Slot> deduction) {
        int weight = slots.stream().mapToInt(Slot::weight).sum();
        if (weight == 0) return null;
        double sum = slots.stream().mapToDouble(s -> (double) s.weight() * deduction.applyAsInt(s)).sum();
        return (int) Math.round(100 - sum / weight);
    }

    /** 점수에 들어가는 감점. LOW·해당 없음·모르는 값은 null(점수 밖). 미평가는 73, 근거 값은 구간 안으로 자른다 */
    static Integer deductionOf(ScoreSource.Finding finding) {
        String grade = finding.grade();
        if ("UNASSESSED".equals(grade)) return UNKNOWN_FLOOR;
        Integer top = TOP.get(grade);
        if (top == null) return null;
        if (finding.deduction() == null) return top;
        return Math.max(top - BAND, Math.min(top, finding.deduction()));
    }

    private static boolean overdue(ScoreSource.Finding finding, Instant now) {
        Integer days = DEADLINE_DAYS.get(finding.grade());
        return days != null && finding.firstSeenAt() != null && finding.firstSeenAt().plus(Duration.ofDays(days)).isBefore(now);
    }

    /** 단서로 자산을 찾는다. 못 찾으면 null(미분류) */
    static ScoreAssets.Asset resolve(ScoreAssets config, Map<String, String> arnKinds, ScoreSource.Hint hint) {
        if (hint == null) return null;
        switch (hint.type()) {
            case "ARN" -> {
                for (var asset : config.assets()) {
                    if (asset.arns().contains(hint.value())) return asset;
                }
                String kind = arnKinds.get(hint.value());
                if (kind == null) return null;
                return config.assets().stream().filter(a -> kind.equals(a.dataAssetKind())).findFirst().orElse(null);
            }
            case "APP" -> {
                return config.assets().stream().filter(a -> a.apps().contains(hint.value())).findFirst().orElse(null);
            }
            case "REPO" -> {
                String repo = repoName(hint.value());
                String path = hint.path() == null ? "" : hint.path();
                ScoreAssets.Asset best = null;
                int bestLength = -1;
                for (var asset : config.assets()) {
                    for (var rp : asset.repoPaths()) {
                        boolean repoMatches = "*".equals(rp.repository()) || rp.repository().equals(repo);
                        if (repoMatches && path.startsWith(rp.pathPrefix()) && rp.pathPrefix().length() > bestLength) {
                            best = asset;
                            bestLength = rp.pathPrefix().length();
                        }
                    }
                }
                return best;
            }
            default -> {
                return null;
            }
        }
    }

    /** 이 검사 범위가 자산에 걸리나. ALL은 그 기능이 다루는 자산 전체 */
    private static boolean covers(ScoreSource.Hint scope, ScoreAssets.Asset asset) {
        return switch (scope.type()) {
            case "ALL" -> true;
            case "APP" -> asset.apps().contains(scope.value());
            case "REPO" -> asset.repoPaths().stream()
                    .anyMatch(rp -> "*".equals(rp.repository()) || rp.repository().equals(repoName(scope.value())));
            default -> false;
        };
    }

    /** "Logssey/service-backend" → "service-backend" */
    static String repoName(String repository) {
        return repository == null ? "" : repository.substring(repository.lastIndexOf('/') + 1);
    }

    private static String format(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}
