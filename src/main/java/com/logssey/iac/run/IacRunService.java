package com.logssey.iac.run;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.iac.auth.IacCiCaller;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * CI 가 PR 마다 run 을 등록하고 민감값을 지운 plan 을 올린다 (API 계약 CI API).
 * 대시보드 관리자(세션) 또는 infrastructure 의 iac-report 워크플로(GitHub OIDC, IacCiSecurityConfig)가 부른다.
 * CI 는 토큰의 레포에 속한 run 만 다루고, 기록에는 사용자 없이 CI 로 남는다.
 */
@Service
public class IacRunService {

    static final Duration PLAN_TTL = Duration.ofHours(1);
    private static final Pattern FINDING = Pattern.compile("^\\[(gate\\.[a-z_]+)] (.*)$");
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private final IacRunRepository repository;
    private final IacPlanInspector inspector;
    private final TransactionTemplate transaction;

    public IacRunService(IacRunRepository repository, IacPlanInspector inspector,
                         PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.inspector = inspector;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public IacRunCreatedResponse register(IacRunRequest request, String loginId) {
        return register(request, () -> requireAdmin(loginId));
    }

    /** CI: 요청의 레포가 토큰의 레포와 같고, 실행 종류가 그 워크플로의 것이어야 한다 (iac-report → PR, iac-drift → PUSH) */
    public IacRunCreatedResponse registerByCi(IacRunRequest request, IacCiCaller caller) {
        if (!request.repo().equals(caller.repository()) || !(request.isPush() ? "PUSH" : "PR").equals(caller.trigger())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        return register(request, () -> null);
    }

    private IacRunCreatedResponse register(IacRunRequest request, Supplier<Long> actorOf) {
        return Objects.requireNonNull(transaction.execute(status -> {
            Long actor = actorOf.get();
            if (request.isPush() == (request.prNumber() != null)) {
                // PR 은 번호가 있어야 하고, main 점검은 번호가 없어야 한다
                throw new ApiException(ErrorCode.INVALID_INPUT);
            }
            var repo = repository.enabledRepo(request.repo()).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
            var findings = gateFindings(request);
            boolean blocked = "BLOCKED".equals(request.gate().status())
                    || findings.values().stream().anyMatch(f -> "BLOCK".equals(f.rule().enforcement()));
            String highest = findings.values().stream().map(f -> f.rule().severity()).filter(Objects::nonNull)
                    .min((a, b) -> SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b)).orElse(null);

            repository.lockPullRequest(repo.repoId(), request.prNumber());
            OffsetDateTime now = repository.databaseNow();
            String runStatus = blocked ? "GATE_FAILED" : "PLANNING";
            long runId = repository.insertRun(repo.repoId(), request.prNumber(),
                    request.isPush() ? null : prTitle(request.prTitle()), request.headSha(),
                    request.isPush() ? "PUSH" : "PR", runStatus, blocked ? "BLOCK" : null, blocked ? highest : null,
                    actor, blocked ? now : null);
            repository.supersede(repo.repoId(), request.prNumber(), runId);

            for (var entry : findings.entrySet()) {
                var finding = entry.getValue();
                repository.upsertFinding(finding.rule(), "GATE", repo.environment(), finding.address(), entry.getKey(),
                        runId, now);
            }
            repository.fixMissing(repo.repoId(), request.prNumber(), "GATE", findings.keySet());
            repository.audit(actor, "RUN", runId, "RUN_REGISTERED",
                    "{\"status\":\"" + runStatus + "\",\"gateFindings\":" + findings.size() + "}");
            return new IacRunCreatedResponse(runId, runStatus);
        }));
    }

    public IacPlanAcceptedResponse uploadPlan(long runId, byte[] gzip, String loginId) {
        return uploadPlan(runId, gzip, () -> requireAdmin(loginId));
    }

    public IacPlanAcceptedResponse uploadPlanByCi(long runId, byte[] gzip, IacCiCaller caller) {
        requireRunOf(runId, caller);
        return uploadPlan(runId, gzip, () -> null);
    }

    private IacPlanAcceptedResponse uploadPlan(long runId, byte[] gzip, Supplier<Long> actorOf) {
        if (gzip.length == 0) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (gzip.length > IacPlanInspector.MAX_COMPRESSED_BYTES) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        }
        // 압축 해제와 검사는 DB 잠금 밖에서 한다
        inspector.inspect(gzip);
        return Objects.requireNonNull(transaction.execute(status -> {
            Long actor = actorOf.get();
            var run = repository.lockRun(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
            if (!"PLANNING".equals(run.status())) {
                // SUPERSEDED·GATE_FAILED·이미 분석 중인 run 에는 올릴 수 없다
                throw new ApiException(ErrorCode.CONFLICT);
            }
            repository.storePlan(runId, gzip, repository.databaseNow().plus(PLAN_TTL));
            repository.markAnalyzing(runId);
            repository.enqueueAnalysis(runId, "PUSH".equals(run.trigger()), actor);
            repository.audit(actor, "RUN", runId, "PLAN_UPLOADED", "{\"sizeBytes\":" + gzip.length + "}");
            return new IacPlanAcceptedResponse(runId, "ANALYZING");
        }));
    }

    public IacRunStatusResponse status(long runId, String loginId) {
        requireAdmin(loginId);
        return repository.status(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    public IacRunStatusResponse statusByCi(long runId, IacCiCaller caller) {
        requireRunOf(runId, caller);
        return repository.status(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    /** 다른 레포·다른 종류의 run 은 없는 것처럼 404 */
    private void requireRunOf(long runId, IacCiCaller caller) {
        if (!repository.runOwner(runId).map(caller::equals).orElse(false)) {
            throw new ApiException(ErrorCode.NOT_FOUND);
        }
    }

    /** 지문 → 발견 건. 지문은 규칙 + 대상 + 레포 + PR 번호, main 점검은 PR 번호 대신 MAIN (설계 지문 규칙). */
    private Map<String, GateFinding> gateFindings(IacRunRequest request) {
        Map<String, GateFinding> findings = new LinkedHashMap<>();
        for (var finding : request.gate().findings()) {
            var matcher = FINDING.matcher(finding.msg());
            if (!matcher.matches()) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "규칙 ID 가 없는 발견 건입니다.");
            }
            var rule = repository.rule(matcher.group(1))
                    .orElseThrow(() -> new ApiException(ErrorCode.INVALID_INPUT, "알 수 없는 규칙입니다."));
            String text = matcher.group(2);
            int colon = text.indexOf(": ");
            String address = colon < 0 ? null : text.substring(colon + 2);
            String fingerprint = sha256(rule.ruleId() + "\n" + Objects.toString(address, "") + "\n"
                    + request.repo() + "\n" + (request.isPush() ? "MAIN" : request.prNumber()));
            findings.putIfAbsent(fingerprint, new GateFinding(rule, address));
        }
        return findings;
    }

    /** PR 제목: 제어 문자(줄바꿈 포함)는 공백으로, 앞뒤 공백은 지우고, 비면 저장하지 않는다 */
    static String prTitle(String title) {
        if (title == null) return null;
        String clean = title.replaceAll("\\p{Cntrl}", " ").strip();
        return clean.isEmpty() ? null : clean;
    }

    private long requireAdmin(String loginId) {
        if (loginId == null) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private record GateFinding(IacRunRepository.Rule rule, String address) {
    }
}
