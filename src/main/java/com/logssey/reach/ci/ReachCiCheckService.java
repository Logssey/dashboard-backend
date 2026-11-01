package com.logssey.reach.ci;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.ci.dto.ReachCiCheckCreatedResponse;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reach CI 검사 (API-12)와 스캔 요청 (API-01). 실행은 검사와 스캔을 QUEUED로 만들고, 결과 조회는 스캔이 끝났으면 게이트를 계산한다.
 * 명세의 인증은 GitHub OIDC지만 아직 붙이지 않아(SecurityConfig 변경과 라이브러리 추가는 팀 결정) 지금은 대시보드 ADMIN 세션으로 받는다
 */
@Service
@Transactional
public class ReachCiCheckService {

    /** 교차 확인 스캐너 (명세 API-01 options.crossCheck). 주 스캐너는 Trivy */
    private static final List<String> CROSS_CHECKS = List.of("GRYPE");
    /** 멱등 키 길이 (명세 2-7: 1~64자) */
    private static final int KEY_MAX = 64;
    /** V37 칸 길이 */
    private static final int REPOSITORY_MAX = 200;
    private static final int REF_MAX = 255;

    private final ReachCiCheckRepository repository;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public ReachCiCheckService(ReachCiCheckRepository repository) {
        this.repository = repository;
    }

    /** 실행 결과. replayed면 같은 멱등 키로 이미 만든 검사를 다시 준 것이다 */
    public record Created(ReachCiCheckCreatedResponse check, boolean replayed) {}

    /** API-12 실행 */
    public Created create(String loginId, String idempotencyKey, ReachCiCheckRequest request) {
        long userId = requireAdmin(loginId);
        if (request == null) throw invalid();
        String key = key(idempotencyKey);
        validate(request);
        var pr = request.pullRequest();
        var plan = new Plan(request.mode(), request.repository(),
                request.headCommit() == null ? null : ReachTargets.commit(request.headCommit()),
                pr == null ? null : pr.number(), pr == null ? null : pr.baseRef(), pr == null ? null : pr.headRef(),
                request.policy() == null ? "REPORT_ONLY" : request.policy(), request.baselineScanId(), "{}");
        return open(userId, key, request, request.target(), request.rescanOf(), plan);
    }

    /**
     * API-01 스캔 요청. 명세대로 mode = MANUAL인 CI 검사를 함께 만든다(러너는 검사 ID로 결과를 올린다).
     * GitHub workflow_dispatch 호출은 아직 하지 않아 스캔은 QUEUED로 남는다
     */
    public Created createScan(String loginId, String idempotencyKey, ReachScanRequest request) {
        long userId = requireAdmin(loginId);
        if (request == null) throw invalid();
        String key = key(idempotencyKey);
        if ((request.target() == null) == (request.rescanOf() == null)) throw invalid();   // 둘 중 하나만
        var options = request.options();
        var crossCheck = options == null || options.crossCheck() == null ? List.of("GRYPE")
                : ReachCodes.checked(options.crossCheck(), CROSS_CHECKS);
        var stored = new LinkedHashMap<String, Object>();
        stored.put("crossCheck", crossCheck);
        stored.put("l1", options == null || options.l1() == null || options.l1());
        stored.put("l2", options == null || options.l2() == null || options.l2());

        // 레포 대상이면 레포와 커밋을 검사에도 남긴다. 이미지 대상은 레포를 모른다(서비스 등록 목록 PRD FR-15 전)
        var repo = request.target() == null ? null : request.target().repo();
        boolean repoTarget = request.target() != null && "REPO".equals(request.target().type()) && repo != null;
        var plan = new Plan("MANUAL", repoTarget ? repo.name() : null, repoTarget ? ReachTargets.commit(repo.commit()) : null,
                null, null, null, "REPORT_ONLY", null, mapper.writeValueAsString(stored));
        return open(userId, key, request, request.target(), request.rescanOf(), plan);
    }

    /** 검사 칸 중 요청마다 다른 것. 스캔 id와 멱등 키는 open()이 채운다 */
    private record Plan(String mode, String repository, String headCommit, Integer prNumber, String prBaseRef,
                        String prHeadRef, String policy, Long baselineScanId, String options) {}

    /**
     * 멱등 키를 보고 처음이면 대상·스캔·검사를 만든다 (명세 2-7).
     * 키는 호출 주체별이다. 지금은 USER:<user_id>, OIDC를 붙이면 CI:<repository>로 바꾼다
     */
    private Created open(long userId, String key, Object request, ReachTargetRequest target, Long rescanOf, Plan plan) {
        String scope = "USER:" + userId;
        String hash = sha256(mapper.writeValueAsString(request));
        repository.lockIdempotencyKey(scope, key);
        var existing = repository.checkByKey(scope, key);
        if (existing.isPresent()) {
            // 명세의 409는 IDEMPOTENCY_CONFLICT지만 공통 ErrorCode에 없어 같은 상태 코드의 CONFLICT를 쓴다
            if (!existing.get().requestHash().equals(hash)) throw new ApiException(ErrorCode.CONFLICT);
            return new Created(created(existing.get().checkId()), true);
        }

        long targetId = rescanOf != null ? rescanTarget(rescanOf) : target(target);
        long scanId = repository.insertScan(targetId, plan.mode(), rescanOf, userId);
        long checkId = repository.insertCheck(new ReachCiCheckRepository.NewCheck(scanId, plan.mode(),
                plan.repository(), plan.headCommit(), plan.prNumber(), plan.prBaseRef(), plan.prHeadRef(),
                plan.policy(), plan.baselineScanId(), plan.options(), scope, key, hash));
        return new Created(created(checkId), false);
    }

    /** API-12 결과 조회. 명세는 ADMIN 세션도 받는다 */
    @Transactional(readOnly = true)
    public ReachCiCheckResponse check(String loginId, long checkId) {
        requireAdmin(loginId);
        var c = repository.check(checkId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        boolean done = "SUCCEEDED".equals(c.scanStatus());
        var pr = c.prNumber() == null ? null
                : new ReachCiCheckResponse.PullRequest(c.prNumber(), c.prBaseRef(), c.prHeadRef());
        return new ReachCiCheckResponse(c.id(), c.mode(), c.repository(), c.headCommit(), pr,
                c.scanId(), c.scanStatus(), c.policy(), c.baselineScanId(),
                done ? gate(c.scanId(), c.baselineScanId(), c.policy()) : null,
                // API-04는 아직 scanId를 받지 않는다(1단계에서 뺌). 명세의 주소를 그대로 준다
                done ? "/api/v1/reach/findings?scanId=" + c.scanId() : null,
                c.finishedAt());
    }

    /**
     * 게이트 (명세 6-2). 조건마다 새 Finding을 세고 가장 나쁜 결과를 따른다(FAIL > WARN > PASS).
     * 명세에 없어 정한 것: REPORT_ONLY도 걸린 조건(reasons)은 그대로 준다. 결과는 늘 PASS다.
     * 게이트로 바꿀지 정하는 기준(경고에 걸린 Finding을 모두 검토)을 보려면 리포트 전용 기간의 조건이 필요하다
     */
    private ReachCiCheckResponse.Gate gate(long scanId, Long baselineScanId, String policy) {
        var byStatus = new LinkedHashMap<String, Long>();
        ReachCodes.STATUSES.forEach(status -> byStatus.put(status, 0L));
        long reachableHigh = 0, reachableOther = 0, unknown = 0, notAnalyzedHigh = 0;
        for (var row : repository.newFindingCounts(scanId, baselineScanId)) {
            long n = row.count();
            byStatus.merge(row.status(), n, Long::sum);
            boolean high = "CRITICAL".equals(row.severity()) || "HIGH".equals(row.severity());
            switch (row.status()) {
                case "REACHABLE" -> { if (high) reachableHigh += n; else reachableOther += n; }
                case "UNKNOWN" -> unknown += n;
                case "NOT_ANALYZED" -> { if (high) notAnalyzedHigh += n; }
                default -> { }   // UNREACHABLE은 통과 (근거는 결과에 남아 있다)
            }
        }

        var reasons = new ArrayList<ReachCiCheckResponse.Reason>();
        reason(reasons, "REACHABLE_CRITICAL_HIGH", reachableHigh, "새 Finding 중 REACHABLE인 CRITICAL·HIGH %d건");
        reason(reasons, "REACHABLE_OTHER", reachableOther, "새 Finding 중 REACHABLE인 MEDIUM 이하 %d건");
        reason(reasons, "UNKNOWN_ANY", unknown, "새 Finding 중 UNKNOWN %d건");
        reason(reasons, "NOT_ANALYZED_CRITICAL_HIGH", notAnalyzedHigh, "새 Finding 중 NOT_ANALYZED인 CRITICAL·HIGH %d건");

        String result = "PASS";
        if ("GATE".equals(policy)) {
            if (reachableHigh > 0) result = "FAIL";
            else if (!reasons.isEmpty()) result = "WARN";   // FAIL 조건 말고는 모두 WARN이다
        }
        long total = byStatus.values().stream().mapToLong(Long::longValue).sum();
        return new ReachCiCheckResponse.Gate(result, "FAIL".equals(result) ? 1 : 0, reasons,
                new ReachCiCheckResponse.NewFindings(total, byStatus));
    }

    /** 0건인 조건은 넣지 않는다 */
    private static void reason(List<ReachCiCheckResponse.Reason> reasons, String condition, long count, String summary) {
        if (count > 0) reasons.add(new ReachCiCheckResponse.Reason(condition, count, summary.formatted(count)));
    }

    private ReachCiCheckCreatedResponse created(long checkId) {
        var c = repository.check(checkId).orElseThrow();
        return new ReachCiCheckCreatedResponse(c.id(), c.mode(), c.scanId(), c.scanStatus(), c.policy(), c.createdAt());
    }

    /** 대상을 찾거나 만든다. 이미 있는 대상의 app과 요청한 app이 다르면 어느 서비스인지 모르니 422 */
    private long target(ReachTargetRequest request) {
        var resolved = ReachTargets.resolve(request);
        var target = repository.findOrCreateTarget(resolved);
        if (!target.app().equals(resolved.app())) throw new ApiException(ErrorCode.UNPROCESSABLE);
        return target.id();
    }

    /** 저장된 SBOM을 다시 쓰는 재대조라 원래 스캔이 성공했어야 한다. 없거나 안 끝났으면 대상을 정하지 못한 것으로 422 */
    private long rescanTarget(long rescanOf) {
        return repository.scan(rescanOf)
                .filter(scan -> "SUCCEEDED".equals(scan.scanStatus()))
                .map(ReachCiCheckRepository.ScanRow::targetId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNPROCESSABLE));
    }

    /**
     * 명세 API-12 표. PR은 레포 대상이고 커밋이 headCommit과 같아야 한다. IMAGE_BUILD는 이미지 대상이다.
     * 재대조(rescanOf)는 SCHEDULE과 MANUAL에서만 받는다
     */
    private void validate(ReachCiCheckRequest r) {
        if (!in(r.mode(), ReachCodes.TRIGGERS) || r.repository() == null || r.repository().isBlank()
                || r.repository().length() > REPOSITORY_MAX) {
            throw invalid();
        }
        if (r.policy() != null && !ReachCodes.POLICIES.contains(r.policy())) throw invalid();
        if ((r.target() == null) == (r.rescanOf() == null)) throw invalid();   // 둘 중 하나만
        if (r.headCommit() != null) ReachTargets.commit(r.headCommit());
        var pr = r.pullRequest();
        if (pr != null && (pr.number() == null || pr.number() < 1 || tooLong(pr.baseRef()) || tooLong(pr.headRef()))) {
            throw invalid();
        }
        switch (r.mode()) {
            case "PR" -> {
                if (r.headCommit() == null || r.target() == null || !"REPO".equals(r.target().type())
                        || r.target().repo() == null || r.target().repo().commit() == null
                        || !r.headCommit().equalsIgnoreCase(r.target().repo().commit())) {
                    throw invalid();
                }
            }
            case "IMAGE_BUILD" -> {
                if (r.target() == null || !"IMAGE".equals(r.target().type())) throw invalid();
            }
            default -> { }   // SCHEDULE, MANUAL은 target이나 rescanOf
        }
        if (r.baselineScanId() != null) {
            // 기준 스캔은 끝난 스캔이어야 비교할 판정이 있다
            boolean ok = repository.scan(r.baselineScanId()).map(s -> "SUCCEEDED".equals(s.scanStatus())).orElse(false);
            if (!ok) throw invalid();
        }
    }

    /** 헤더가 없거나 비었거나 64자를 넘으면 400 (명세 2-7) */
    private static String key(String value) {
        if (value == null || value.isBlank() || value.length() > KEY_MAX) throw invalid();
        return value;
    }

    private static boolean tooLong(String value) {
        return value != null && value.length() > REF_MAX;
    }

    /** List.of(...).contains(null)은 NullPointerException이라 null을 먼저 거른다 */
    private static boolean in(String value, List<String> allowed) {
        return value != null && allowed.contains(value);
    }

    /** 같은 키로 온 본문이 같은지 비교하려고 남기는 지문. record는 칸 순서대로 직렬화돼 같은 본문이면 같은 값이다 */
    static String sha256(String value) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);   // 자바 표준이라 늘 있다
        }
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }

    private static ApiException invalid() {
        return new ApiException(ErrorCode.INVALID_INPUT);
    }
}
