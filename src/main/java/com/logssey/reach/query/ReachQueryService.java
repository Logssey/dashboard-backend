package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.l1.ReachL1Service;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;
import com.logssey.reach.query.dto.ReachFindingPageResponse;
import com.logssey.reach.query.dto.ReachSummaryResponse;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reach 대시보드 조회 API (API-04·05·08). 권한은 ADMIN (Reach API 명세 2-2). */
@Service
@Transactional(readOnly = true)
public class ReachQueryService {

    /** 목록 한 번에 주는 개수. 기본 20, 최대 100 (Reach API 명세 2-4) */
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    /** API-05 include (명세). RULE·vulnFunctions는 API-09·10 데이터가 생기면, verdictHistory는 따로 채운다 */
    private static final List<String> DETAIL_INCLUDES = List.of("RULE", "vulnFunctions", "reviewHistory", "verdictHistory");

    private final ReachQueryRepository repository;
    /** L1 범위(실행 중 기준)와 앱 코드(실행 중 미스캔 워크로드의 앱) */
    private final ReachProperties properties;

    public ReachQueryService(ReachQueryRepository repository, ReachProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    /** RUNNING은 L1이 켜졌을 때만 실행 중 기준이다. L1이 꺼진 설치는 LATEST와 같다 */
    private ReachQueryRepository.Basis basis(String requested) {
        var l1 = properties.l1();
        if (!"RUNNING".equals(requested) || !l1.enabled()) return ReachQueryRepository.Basis.LATEST;
        return new ReachQueryRepository.Basis(true, l1.cluster(), l1.namespaces(), ReachL1Service.FRESH);
    }

    /**
     * 하루 1번 재대조(PRD FR-11)의 대상: 운영에서 실행 중인 이미지마다 기본 범위(basis=RUNNING)가 쓰는 스캔.
     * L1이 꺼졌거나 신선한 조회가 없으면 실행 중인 이미지를 모르니 빈 목록이다. 예약 작업이 부르고 사람 권한은 보지 않는다
     */
    public List<Long> runningImageScanIds() {
        var running = basis("RUNNING");
        if (!running.running() || !repository.hasFreshObservation(running)) return List.of();
        return repository.scopeScanList(running).stream()
                .filter(s -> s.running() && "IMAGE".equals(s.targetType()))
                .map(ReachQueryRepository.ScopeScan::scanId)
                .toList();
    }

    /**
     * PR 검사의 기준 스캔(API-12 baselineScanId를 주지 않았을 때): 그 앱이 운영에서 실행 중인 이미지의 스캔.
     * 운영 이미지는 머지된 코드라 "운영에 없던 것"이 그 PR로 새로 생긴 Finding이다.
     * 이미지 빌드 검사의 스캔은 머지 전 PR 이미지일 수 있어 쓰지 않는다. 실행 중 이미지가 둘 이상(배포 중)이면 가장 최근 스캔이다.
     * 실행 중인 이미지를 모르면 없다(기준 없이 모든 Finding을 새 것으로 본다)
     */
    public Optional<Long> runningImageScan(String app) {
        var running = basis("RUNNING");
        if (app == null || !running.running() || !repository.hasFreshObservation(running)) return Optional.empty();
        return repository.scopeScanList(running).stream()
                .filter(s -> s.running() && "IMAGE".equals(s.targetType()) && app.equals(s.app()))
                .map(ReachQueryRepository.ScopeScan::scanId)
                .max(Long::compare);
    }

    public ReachFindingPageResponse findings(String loginId, ReachFindingFilter filter,
                                             Integer size, String cursor, String include) {
        requireAdmin(loginId);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (include != null && !include.equals("total")) throw new ApiException(ErrorCode.INVALID_INPUT);

        var after = cursor == null ? null : ReachFindingCursor.decode(cursor);
        if (after != null && after.filter() != filter.fingerprint()) throw new ApiException(ErrorCode.INVALID_INPUT);
        scopeTarget(filter.target(), filter.scanId());

        var basis = basis(filter.basis());
        var rows = repository.findings(filter, basis, after, limit + 1);    // 하나 더 가져와 다음 페이지 확인
        boolean hasNext = rows.size() > limit;
        var page = hasNext ? rows.subList(0, limit) : rows;

        String nextCursor = null;
        if (hasNext) {
            var last = page.get(page.size() - 1);
            nextCursor = new ReachFindingCursor(last.statusRank(), last.severityRank(), last.cveYear(),
                    last.cveNumber(), last.item().id(), filter.fingerprint()).encode();
        }
        Long totalCount = "total".equals(include) ? repository.countFindings(filter, basis) : null;
        return new ReachFindingPageResponse(page.stream().map(ReachQueryRepository.Row::item).toList(),
                nextCursor, hasNext, totalCount);
    }

    private void requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        if (!repository.isAdmin(loginId)) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    /**
     * 기준 범위 검사 (API-04·08 target·scanId). 범위의 대상 ID를 돌려준다.
     * 없는 대상·스캔은 404, 끝나지 않은 스캔은 409(SCAN_NOT_READY: 공통 코드가 없어 CONFLICT, API-11과 같음),
     * 스캔이 target과 다른 대상이면 400
     */
    private Long scopeTarget(Long target, Long scanId) {
        if (target != null && !repository.targetExists(target)) throw new ApiException(ErrorCode.NOT_FOUND);
        if (scanId == null) return target;
        var scan = repository.scanState(scanId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!"SUCCEEDED".equals(scan.status())) throw new ApiException(ErrorCode.CONFLICT);
        if (target != null && target != scan.targetId()) throw new ApiException(ErrorCode.INVALID_INPUT);
        return scan.targetId();
    }

    /** API-08. scope는 target·scanId가 없으면 (null, null)이다. 대상이 여럿이라 기준 스캔이 하나가 아니다 */
    /** basis 없이(RUNNING) */
    public ReachSummaryResponse summary(String loginId, Long target, Long scanId, List<String> deployment,
                                        List<String> include) {
        return summary(loginId, target, scanId, deployment, include, null);
    }

    public ReachSummaryResponse summary(String loginId, Long target, Long scanId, List<String> deployment,
                                        List<String> include, String basisParam) {
        requireAdmin(loginId);
        String requested = ReachFindingFilter.checkedBasis(basisParam);
        var basis = basis(requested);
        var deployments = ReachCodes.checked(deployment, ReachCodes.DEPLOYMENTS);
        var includes = ReachCodes.checked(include, List.of("matrix"));
        Long scopeTarget = scopeTarget(target, scanId);
        Long scopeScan = scanId != null ? scanId : scopeTarget == null ? null : repository.baselineScan(scopeTarget);

        // 명세: 모든 값을 0까지 준다. LinkedHashMap은 넣은 순서를 지킨다
        var byStatus = zeros(ReachCodes.STATUSES);
        var byReason = zeros(ReachCodes.NOT_ANALYZED_REASONS);
        var bySeverity = zeros(ReachCodes.SEVERITIES);
        var byMethod = zeros(ReachCodes.METHODS);
        var byReviewState = zeros(ReachCodes.REVIEW_STATES);
        var byDeployment = zeros(ReachCodes.DEPLOYMENTS);
        var matrix = new LinkedHashMap<String, Map<String, Long>>();   // 0인 칸은 넣지 않는다
        long total = 0;

        for (var row : repository.summaryRows(scanId, target, basis, deployments)) {
            long n = row.count();
            total += n;
            byStatus.merge(row.status(), n, Long::sum);
            bySeverity.merge(row.severity(), n, Long::sum);
            byReviewState.merge(row.reviewState(), n, Long::sum);
            byDeployment.merge(row.deployment(), n, Long::sum);
            if (row.method() != null) byMethod.merge(row.method(), n, Long::sum);              // NOT_ANALYZED는 방식 없음
            if (row.notAnalyzedReason() != null) byReason.merge(row.notAnalyzedReason(), n, Long::sum);
            matrix.computeIfAbsent(row.severity(), k -> new LinkedHashMap<>()).merge(row.status(), n, Long::sum);
            }

        long unreachable = byStatus.get("UNREACHABLE");
        long judged = byStatus.get("REACHABLE") + unreachable + byStatus.get("UNKNOWN");   // NOT_ANALYZED 제외 (PRD M-01)
        return new ReachSummaryResponse(
                new ReachSummaryResponse.Scope(scopeTarget, scopeScan),
                scopeTarget == null ? basisInfo(requested, basis) : null,
                new ReachSummaryResponse.Totals(total),
                byStatus, byReason, bySeverity, byMethod, byReviewState, byDeployment,
                includes.contains("matrix") ? matrix : null,
                new ReachSummaryResponse.NoiseReduction(unreachable, judged, ratio(unreachable, judged)),
                new ReachSummaryResponse.Coverage(judged, total, ratio(judged, total)),
                OffsetDateTime.now());
    }

    /** API-08 basis: 기본 범위로 쓴 스캔과 실행 중인데 스캔이 없는 워크로드 */
    private ReachSummaryResponse.Basis basisInfo(String requested, ReachQueryRepository.Basis basis) {
        boolean running = repository.hasFreshObservation(basis);
        var applied = running ? basis : ReachQueryRepository.Basis.LATEST;
        var scans = repository.scopeScanList(applied).stream()
                .map(s -> new ReachSummaryResponse.ScopeScan(s.app(), s.targetType(), s.targetId(), s.scanId(),
                        s.imageDigest(), s.running()))
                .toList();
        var unscanned = repository.unscannedRunning(applied).stream()
                .map(w -> new ReachSummaryResponse.UnscannedWorkload(properties.appOfImage(w.imageRepository()).orElse(null),
                        w.namespace(), w.name(), w.container(), w.imageRepository(), w.imageDigest()))
                .toList();
        return new ReachSummaryResponse.Basis(requested, running ? "RUNNING" : "LATEST", scans, unscanned);
    }

    private static Map<String, Long> zeros(List<String> keys) {
        var map = new LinkedHashMap<String, Long>();
        keys.forEach(key -> map.put(key, 0L));
        return map;
    }

    /** 소수 셋째 자리 반올림, 분모 0이면 null (명세 API-08) */
    private static Double ratio(long numerator, long denominator) {
        return denominator == 0 ? null : Math.round(numerator * 1000.0 / denominator) / 1000.0;
    }

    /** API-05. 없는 id면 404. include는 명세의 네 값을 받고, 지금은 reviewHistory만 채운다 */
    public ReachFindingDetailResponse finding(String loginId, long findingId, List<String> include) {
        requireAdmin(loginId);
        var includes = ReachCodes.checked(include, DETAIL_INCLUDES);
        var detail = repository.finding(findingId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return includes.contains("reviewHistory") ? detail.withReviewHistory(repository.reviewHistory(findingId)) : detail;
    }
}