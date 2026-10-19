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
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * CI 가 PR 마다 run 을 등록하고 민감값을 지운 plan 을 올린다 (API 계약 CI API).
 * S3 에서는 로그인한 관리자만 부를 수 있다. GitHub OIDC 검증은 S4 에서 붙인다.
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
        return Objects.requireNonNull(transaction.execute(status -> {
            long actor = requireAdmin(loginId);
            var repo = repository.enabledRepo(request.repo()).orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
            var findings = gateFindings(request);
            boolean blocked = "BLOCKED".equals(request.gate().status())
                    || findings.values().stream().anyMatch(f -> "BLOCK".equals(f.rule().enforcement()));
            String highest = findings.values().stream().map(f -> f.rule().severity()).filter(Objects::nonNull)
                    .min((a, b) -> SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b)).orElse(null);

            repository.lockPullRequest(repo.repoId(), request.prNumber());
            OffsetDateTime now = repository.databaseNow();
            String runStatus = blocked ? "GATE_FAILED" : "PLANNING";
            long runId = repository.insertRun(repo.repoId(), request.prNumber(), request.headSha(), runStatus,
                    blocked ? "BLOCK" : null, blocked ? highest : null, actor, blocked ? now : null);
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
        if (gzip.length == 0) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (gzip.length > IacPlanInspector.MAX_COMPRESSED_BYTES) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
        }
        // 압축 해제와 검사는 DB 잠금 밖에서 한다
        inspector.inspect(gzip);
        return Objects.requireNonNull(transaction.execute(status -> {
            long actor = requireAdmin(loginId);
            var run = repository.lockRun(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
            if (!"PLANNING".equals(run.status())) {
                // SUPERSEDED·GATE_FAILED·이미 분석 중인 run 에는 올릴 수 없다
                throw new ApiException(ErrorCode.CONFLICT);
            }
            repository.storePlan(runId, gzip, repository.databaseNow().plus(PLAN_TTL));
            repository.markAnalyzing(runId);
            repository.enqueueAnalysis(runId, actor);
            repository.audit(actor, "RUN", runId, "PLAN_UPLOADED", "{\"sizeBytes\":" + gzip.length + "}");
            return new IacPlanAcceptedResponse(runId, "ANALYZING");
        }));
    }

    public IacRunStatusResponse status(long runId, String loginId) {
        requireAdmin(loginId);
        return repository.status(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    /** 지문 → 발견 건. 지문은 규칙 + 대상 + 레포 + PR 번호 (설계 지문 규칙). */
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
                    + request.repo() + "\n" + request.prNumber());
            findings.putIfAbsent(fingerprint, new GateFinding(rule, address));
        }
        return findings;
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
