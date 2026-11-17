package com.logssey.reach.ci;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.ci.auth.ReachCiAccess;
import com.logssey.reach.ci.auth.ReachCiCaller;
import com.logssey.reach.ci.dto.ReachCiCheckCreatedResponse;
import com.logssey.reach.ci.dto.ReachCiCheckPageResponse;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reach CI 검사 (API-12)와 스캔 요청 (API-01). 실행은 검사와 스캔을 QUEUED로 만들고, 결과 조회는 스캔이 끝났으면 게이트를 계산한다.
 * API-12는 대시보드 ADMIN 세션과 GitHub OIDC 토큰(CI) 둘 다 받는다(명세 2-2). CI가 할 수 있는 일은 ReachCiAccess가 정한다
 */
@Service
@Transactional
public class ReachCiCheckService {

    /** 교차 확인 스캐너 (명세 API-01 options.crossCheck). 주 스캐너는 Trivy */
    private static final List<String> CROSS_CHECKS = List.of("GRYPE");
    /** 멱등 키 길이 (명세 2-7: 1~64자) */
    private static final int KEY_MAX = 64;
    /** 목록 크기 (명세 2-4, 스캔 이력과 같다) */
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;
    /** V37 칸 길이 */
    private static final int REPOSITORY_MAX = 200;
    private static final int REF_MAX = 255;

    private final ReachCiCheckRepository repository;
    /** 감시 대상 앱 (PRD FR-15). 요청의 레포·이미지가 어느 앱인지 정한다 */
    private final ReachProperties properties;
    private final ReachCiAccess access;
    /** API-01이 러너(서비스 레포의 Reach 워크플로)를 띄운다. 설정이 없으면 스캔은 QUEUED로 남는다 */
    private final ReachScanDispatcher dispatcher;
    private final JsonMapper mapper = JsonMapper.builder().build();

    @Autowired
    ReachCiCheckService(ReachCiCheckRepository repository, ReachProperties properties, ReachCiAccess access,
                        ReachScanDispatcher dispatcher) {
        this.repository = repository;
        this.properties = properties;
        this.access = access;
        this.dispatcher = dispatcher;
    }

    /** CI 설정 없이(CI 토큰은 모두 거부, 러너를 띄우지 않음) */
    ReachCiCheckService(ReachCiCheckRepository repository, ReachProperties properties) {
        this(repository, properties, ReachCiAccess.closed(), ReachScanDispatcher.NONE);
    }

    /** 러너를 띄우는 것만 바꾼다(테스트) */
    ReachCiCheckService(ReachCiCheckRepository repository, ReachProperties properties, ReachScanDispatcher dispatcher) {
        this(repository, properties, ReachCiAccess.closed(), dispatcher);
    }

    /** 실행 결과. replayed면 같은 멱등 키로 이미 만든 검사를 다시 준 것이다 */
    public record Created(ReachCiCheckCreatedResponse check, boolean replayed) {}

    /** API-12 실행 (대시보드 세션) */
    public Created create(String loginId, String idempotencyKey, ReachCiCheckRequest request) {
        long userId = requireAdmin(loginId);
        if (request == null) throw invalid();
        String key = key(idempotencyKey);
        validate(request);
        return open(Requester.user(userId), key, request, request.target(), request.rescanOf(), plan(request));
    }

    /** API-12 실행 (CI 토큰). 본문 형식(400)을 먼저 보고 CI가 할 수 있는 일인지(403) 본다 */
    public Created createForCi(ReachCiCaller caller, String idempotencyKey, ReachCiCheckRequest request) {
        if (request == null) throw invalid();
        String key = key(idempotencyKey);
        validate(request);
        access.authorizeCreate(caller, request);
        return open(Requester.ci(caller), key, request, request.target(), request.rescanOf(), plan(request));
    }

    private static Plan plan(ReachCiCheckRequest request) {
        var pr = request.pullRequest();
        return new Plan(request.mode(), request.repository(),
                request.headCommit() == null ? null : ReachTargets.commit(request.headCommit()),
                pr == null ? null : pr.number(), pr == null ? null : pr.baseRef(), pr == null ? null : pr.headRef(),
                request.policy() == null ? "REPORT_ONLY" : request.policy(), request.baselineScanId(), "{}");
    }

    /**
     * API-01 스캔 요청. 명세대로 mode = MANUAL인 CI 검사를 함께 만들고, 대상의 레포에서 Reach 워크플로를
     * workflow_dispatch로 띄운다(ARD AD-18 ③). 러너는 받은 검사 ID로 결과를 올린다(API-13).
     * 띄우지 못하면 503이고 이 요청의 대상·스캔·검사는 되돌아간다(같은 멱등 키로 다시 요청하면 새로 띄운다).
     * 띄우는 설정이 없거나 재대조(rescanOf)면 띄우지 않아 스캔은 QUEUED로 남는다(러너가 저장된 SBOM 재대조를 아직 못 한다)
     */
    /** API-01 422 메시지. 명세의 사유 코드 UNSUPPORTED_ECOSYSTEM (공통 ErrorCode에 없어 메시지로 준다) */
    static final String UNSUPPORTED_ECOSYSTEM =
            "UNSUPPORTED_ECOSYSTEM: Reach는 Java(maven) 앱만 스캔합니다. 이 앱은 설치 설정에서 다른 생태계로 등록돼 있습니다.";

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

        // 검사에 대상의 레포를 남긴다. 러너를 띄울 레포이고, 그 레포의 토큰만 결과를 올린다(ReachCiAccess).
        // 이미지 대상은 설정(logssey.reach.apps)에서 그 이미지 앱의 레포를 찾는다
        var resolved = request.target() == null ? null : ReachTargets.resolve(request.target(), properties);
        var app = resolved == null ? null : app(resolved.app());
        boolean repoTarget = resolved != null && "REPO".equals(resolved.type());
        String repo = repoTarget ? resolved.repoName() : app == null ? null : app.repo();
        // 지금 Reach 워크플로는 Gradle bootJar·이미지의 /app/app.jar를 전제로 해서, maven이 아닌 앱(Node·프론트)은
        // 빌드·jar 꺼내기에서 실패한 스캔만 남는다. 아무것도 남기지 않고 422 (러너가 jar 없는 대상을 받게 되면 푼다)
        if (app != null && !app.scannable() && dispatcher.enabled()) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, UNSUPPORTED_ECOSYSTEM);
        }
        var plan = new Plan("MANUAL", repo, repoTarget ? resolved.repoCommit() : null,
                null, null, null, "REPORT_ONLY", null, mapper.writeValueAsString(stored));
        var created = open(Requester.user(userId), key, request, request.target(), request.rescanOf(), plan);

        if (!created.replayed() && resolved != null && dispatcher.enabled()) {
            // 레포가 없는 이미지 앱(설정에 image만)은 띄울 워크플로가 없다 (명세 TARGET_UNRESOLVED → UNPROCESSABLE)
            if (repo == null) throw new ApiException(ErrorCode.UNPROCESSABLE);
            dispatcher.dispatch(repo.substring(repo.lastIndexOf('/') + 1),
                    inputs(created.check().id(), resolved, app));
        }
        return created;
    }

    private ReachProperties.App app(String code) {
        return properties.apps().stream().filter(a -> a.code().equals(code)).findFirst().orElse(null);
    }

    /**
     * 워크플로 inputs (서비스 레포 reach.yml의 workflow_dispatch). 워크플로에 없는 이름을 보내면 GitHub이 거부해
     * 늘 같은 이름을 모두 보내고 쓰지 않는 값은 빈 문자열이다. path는 레포 대상이면 요청의 하위 경로, 이미지면 앱의 경로
     */
    private static Map<String, String> inputs(long checkId, ReachTargets.Resolved target, ReachProperties.App app) {
        boolean repo = "REPO".equals(target.type());
        String path = repo ? target.repoPath() : app == null ? null : app.path();
        var inputs = new LinkedHashMap<String, String>();
        inputs.put("check_id", Long.toString(checkId));
        inputs.put("target_type", target.type());
        inputs.put("commit", repo ? target.repoCommit() : "");
        inputs.put("path", path == null ? "" : path);
        inputs.put("image_repository", repo ? "" : target.imageRepository());
        inputs.put("image_digest", repo ? "" : target.imageDigest());
        return inputs;
    }

    /**
     * 요청한 주체 (V34 requested_by_*, V37 idempotency_scope). 사람은 USER:<user_id>,
     * CI는 CI:<토큰의 repository>이고 스캔에 토큰의 repository·sub를 남긴다(11/02 결정 ④)
     */
    private record Requester(String scope, Long userId, String repository, String subject) {
        static Requester user(long userId) {
            return new Requester("USER:" + userId, userId, null, null);
        }

        static Requester ci(ReachCiCaller caller) {
            return new Requester(caller.scope(), null, caller.repository(), caller.subject());
        }
    }

    /** 검사 칸 중 요청마다 다른 것. 스캔 id와 멱등 키는 open()이 채운다 */
    private record Plan(String mode, String repository, String headCommit, Integer prNumber, String prBaseRef,
                        String prHeadRef, String policy, Long baselineScanId, String options) {}

    /**
     * 멱등 키를 보고 처음이면 대상·스캔·검사를 만든다 (명세 2-7).
     * 키는 호출 주체별이다(USER:<user_id>, CI:<repository>)
     */
    private Created open(Requester requester, String key, Object request, ReachTargetRequest target, Long rescanOf,
                         Plan plan) {
        String scope = requester.scope();
        String hash = sha256(mapper.writeValueAsString(request));
        repository.lockIdempotencyKey(scope, key);
        var existing = repository.checkByKey(scope, key);
        if (existing.isPresent()) {
            // 명세의 409는 IDEMPOTENCY_CONFLICT지만 공통 ErrorCode에 없어 같은 상태 코드의 CONFLICT를 쓴다
            if (!existing.get().requestHash().equals(hash)) throw new ApiException(ErrorCode.CONFLICT);
            return new Created(created(existing.get().checkId()), true);
        }

        long targetId = rescanOf != null ? rescanTarget(rescanOf) : target(target);
        long scanId = requester.userId() != null
                ? repository.insertScan(targetId, plan.mode(), rescanOf, requester.userId())
                : repository.insertCiScan(targetId, plan.mode(), requester.repository(), requester.subject());
        long checkId = repository.insertCheck(new ReachCiCheckRepository.NewCheck(scanId, plan.mode(),
                plan.repository(), plan.headCommit(), plan.prNumber(), plan.prBaseRef(), plan.prHeadRef(),
                plan.policy(), plan.baselineScanId(), plan.options(), scope, key, hash));
        return new Created(created(checkId), false);
    }

    /** API-12 결과 조회 (대시보드 세션) */
    @Transactional(readOnly = true)
    public ReachCiCheckResponse check(String loginId, long checkId) {
        requireAdmin(loginId);
        return view(checkId);
    }

    /** API-12 결과 조회 (CI 토큰). 검사를 만든 레포의 토큰만 */
    @Transactional(readOnly = true)
    public ReachCiCheckResponse checkForCi(ReachCiCaller caller, long checkId) {
        access.requireOwner(caller, repository.checkOwner(checkId));
        return view(checkId);
    }

    /**
     * API-12 목록 (대시보드 세션만). 최신 검사부터. 항목은 결과 조회와 같은 모양이고, 끝난 검사는 게이트를 함께 준다.
     * 게이트는 검사마다 새 Finding을 한 번 센다(페이지 크기만큼 쿼리, 최대 100)
     */
    @Transactional(readOnly = true)
    public ReachCiCheckPageResponse checks(String loginId, ReachCiCheckFilter filter, Integer size, String cursor,
                                           String include) {
        requireAdmin(loginId);
        int limit = size == null ? DEFAULT_SIZE : size;
        if (limit < 1 || limit > MAX_SIZE) throw invalid();
        if (include != null && !include.equals("total")) throw invalid();
        var after = cursor == null ? null : ReachCiCheckCursor.decode(cursor);
        if (after != null && after.filter() != filter.fingerprint()) throw invalid();

        var rows = repository.checks(filter, after == null ? null : after.checkId(), limit + 1);   // 하나 더 읽어 다음 페이지 확인
        boolean hasNext = rows.size() > limit;
        var page = hasNext ? rows.subList(0, limit) : rows;
        var items = page.stream().map(this::view).toList();
        String nextCursor = hasNext ? new ReachCiCheckCursor(page.get(page.size() - 1).id(), filter.fingerprint()).encode() : null;
        Long totalCount = "total".equals(include) ? repository.countChecks(filter) : null;
        return new ReachCiCheckPageResponse(items, nextCursor, hasNext, totalCount);
    }

    private ReachCiCheckResponse view(long checkId) {
        return view(repository.check(checkId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND)));
    }

    private ReachCiCheckResponse view(ReachCiCheckRepository.CheckRow c) {
        boolean done = "SUCCEEDED".equals(c.scanStatus());
        var pr = c.prNumber() == null ? null
                : new ReachCiCheckResponse.PullRequest(c.prNumber(), c.prBaseRef(), c.prHeadRef());
        return new ReachCiCheckResponse(c.id(), c.mode(), c.repository(), c.headCommit(), pr,
                c.scanId(), c.scanStatus(), c.policy(), c.baselineScanId(),
                done ? gate(c.scanId(), c.baselineScanId(), c.policy()) : null,
                // API-04는 아직 scanId를 받지 않는다(1단계에서 뺌). 명세의 주소를 그대로 준다
                done ? "/api/v1/reach/findings?scanId=" + c.scanId() : null,
                c.createdAt(), c.finishedAt());
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
        var resolved = ReachTargets.resolve(request, properties);
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
