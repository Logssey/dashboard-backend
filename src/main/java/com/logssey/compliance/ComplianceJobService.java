package com.logssey.compliance;

import static com.logssey.compliance.ComplianceJobDtos.ClaimedJob;
import static com.logssey.compliance.ComplianceJobDtos.CancelJobResponse;
import static com.logssey.compliance.ComplianceJobDtos.CompletionResponse;
import static com.logssey.compliance.ComplianceJobDtos.ConnectionCompletionRequest;
import static com.logssey.compliance.ComplianceJobDtos.ConnectionCompletionResponse;
import static com.logssey.compliance.ComplianceJobDtos.CreateJobRequest;
import static com.logssey.compliance.ComplianceJobDtos.CreateJobResponse;
import static com.logssey.compliance.ComplianceJobDtos.FailureRequest;
import static com.logssey.compliance.ComplianceJobDtos.JobListResponse;
import static com.logssey.compliance.ComplianceJobDtos.JobSummary;
import static com.logssey.compliance.ComplianceJobDtos.LeaseRequest;
import static com.logssey.compliance.ComplianceJobDtos.LeaseResponse;
import static com.logssey.compliance.ComplianceJobDtos.ScanScope;
import static com.logssey.compliance.ComplianceJobDtos.ScopeCatalogResponse;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
public class ComplianceJobService {

    private static final int MAX_JOBS = 50;
    private static final int MAX_REGIONS = 30;
    private static final int MAX_SERVICES = 100;
    private static final int MAX_CHECKS = 1_000;
    private static final Pattern REGION = Pattern.compile("^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\\d$");
    private static final Pattern WORKER_ID = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$");
    private static final Pattern ERROR_CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,79}$");

    private final ComplianceJobRepository repository;
    private final ComplianceRepository complianceRepository;
    private final ComplianceService compliance;
    private final ComplianceTargetRepository targets;
    private final ProwlerScopeCatalog scopeCatalog;
    private final String targetKey;
    private final boolean executionEnabled;
    private final boolean connectionTestsEnabled;
    private final int leaseSeconds;
    private final int retryDelaySeconds;

    public ComplianceJobService(ComplianceJobRepository repository, ComplianceRepository complianceRepository,
                                ComplianceService compliance, ComplianceTargetRepository targets,
                                ProwlerScopeCatalog scopeCatalog,
                                @Value("${logssey.compliance.target-key:default}") String targetKey,
                                @Value("${logssey.compliance.worker-lease-seconds:900}") int leaseSeconds,
                                @Value("${logssey.compliance.worker-retry-delay-seconds:30}") int retryDelaySeconds,
                                @Value("${logssey.compliance.execution-enabled:true}") boolean executionEnabled,
                                @Value("${logssey.compliance.connection-tests-enabled:false}")
                                boolean connectionTestsEnabled) {
        this.repository = repository;
        this.complianceRepository = complianceRepository;
        this.compliance = compliance;
        this.targets = targets;
        this.scopeCatalog = scopeCatalog;
        this.targetKey = targetKey;
        this.executionEnabled = executionEnabled;
        this.connectionTestsEnabled = connectionTestsEnabled;
        this.leaseSeconds = Math.max(60, Math.min(3_600, leaseSeconds));
        this.retryDelaySeconds = Math.max(1, Math.min(600, retryDelaySeconds));
    }

    @Transactional
    public CreateJobResponse create(String loginId, CreateJobRequest request) {
        requireAdmin(loginId);
        if (!executionEnabled) {
            throw new ApiException(ErrorCode.CONFLICT, "자동 점검 실행은 운영 연결을 완료한 뒤 활성화됩니다.");
        }
        if (request == null) throw new ApiException(ErrorCode.INVALID_INPUT);
        String requestedTarget = target(request.targetKey());
        var target = targets.executionSnapshot(requestedTarget)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND, "등록된 점검 대상을 찾을 수 없습니다."));
        if (!target.enabled() || !"VERIFIED".equals(target.connectionStatus())) {
            throw new ApiException(ErrorCode.CONFLICT, "연결 확인을 마치고 활성화한 대상만 점검할 수 있습니다.");
        }
        String environment = ComplianceService.environment(request.environment(), false);
        ScanScope scope = normalizeScope(request.scope());
        if (scope.regions().isEmpty() && !target.defaultRegions().isEmpty()) {
            scope = new ScanScope(target.defaultRegions(), scope.services(), scope.checks());
        }
        long jobId = repository.insertAssessment(target, environment, scope, loginId);
        return new CreateJobResponse(jobId, "QUEUED");
    }

    @Transactional(readOnly = true)
    public JobListResponse jobs(String requestedTarget, int limit) {
        if (limit < 1 || limit > MAX_JOBS) throw new ApiException(ErrorCode.INVALID_INPUT);
        return new JobListResponse(repository.jobs(target(requestedTarget), limit));
    }

    @Transactional(readOnly = true)
    public JobSummary job(String requestedTarget, long jobId) {
        return repository.job(target(requestedTarget), jobId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    @Transactional
    public CancelJobResponse cancel(String loginId, String requestedTarget, long jobId) {
        requireAdmin(loginId);
        String selectedTarget = target(requestedTarget);
        var existing = repository.job(selectedTarget, jobId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (repository.cancel(selectedTarget, jobId)) {
            if ("CONNECTION_TEST".equals(existing.jobKind())) {
                var snapshot = repository.jobTargetSnapshot(jobId);
                snapshot.ifPresent(value -> targets.markNotTested(value.targetKey(), value.targetVersion()));
            }
            return new CancelJobResponse(jobId, "CANCELLED");
        }
        throw new ApiException(ErrorCode.CONFLICT,
                "현재 상태(" + existing.status() + ")에서는 점검을 취소할 수 없습니다.");
    }

    public ScopeCatalogResponse scopeCatalog() {
        return new ScopeCatalogResponse("aws", executionEnabled, connectionTestsEnabled,
                scopeCatalog.version(), scopeCatalog.commit(), scopeCatalog.services(), scopeCatalog.checkItems());
    }

    @Transactional
    public ClaimedJob claim(String workerId) {
        String normalizedWorker = normalizeWorkerId(workerId);
        for (var expired : repository.failExhaustedLeases()) {
            if ("CONNECTION_TEST".equals(expired.jobKind())) {
                targets.markFailed(expired.targetKey(), expired.targetVersion(), "LEASE_EXPIRED");
            }
        }
        return repository.claim(normalizedWorker, UUID.randomUUID(), leaseSeconds, scopeCatalog.version(),
                        executionEnabled, connectionTestsEnabled)
                .orElse(null);
    }

    @Transactional
    public LeaseResponse heartbeat(long jobId, LeaseRequest request) {
        if (request == null || request.leaseToken() == null || request.leaseGeneration() < 1) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var until = repository.heartbeat(jobId, request.leaseToken(), request.leaseGeneration(), leaseSeconds)
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT, "점검 작업 임대가 만료되었거나 변경되었습니다."));
        return new LeaseResponse(until);
    }

    @Transactional
    public CompletionResponse complete(long jobId, UUID token, long generation, MultipartFile file) {
        if (token == null || generation < 1) throw new ApiException(ErrorCode.INVALID_INPUT);
        var lease = repository.lockLease(jobId, token, generation)
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT, "점검 작업 임대가 만료되었거나 변경되었습니다."));
        if (!"ASSESSMENT".equals(lease.jobKind())) throw new ApiException(ErrorCode.CONFLICT);
        var imported = compliance.importProwlerResult(lease.targetKey(),
                "compliance-worker/job-" + jobId, lease.environment(), file);
        repository.succeed(jobId, imported.runId());
        return new CompletionResponse(jobId, imported.runId(), "SUCCEEDED");
    }

    @Transactional
    public ConnectionCompletionResponse completeConnection(long jobId, ConnectionCompletionRequest request) {
        if (request == null || request.leaseToken() == null || request.leaseGeneration() < 1
                || request.accountId() == null || !request.accountId().matches("^[0-9]{12}$")
                || request.callerArn() == null || request.callerArn().length() > 620) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var lease = repository.lockLease(jobId, request.leaseToken(), request.leaseGeneration())
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT, "연결 확인 작업 임대가 만료되었거나 변경되었습니다."));
        if (!"CONNECTION_TEST".equals(lease.jobKind())) throw new ApiException(ErrorCode.CONFLICT);
        if (!lease.targetAccountId().equals(request.accountId())) {
            targets.markFailed(lease.targetKey(), lease.targetVersion(), "TARGET_ACCOUNT_MISMATCH");
            repository.failOrRetry(jobId, false, "TARGET_ACCOUNT_MISMATCH", retryDelaySeconds);
            throw new ApiException(ErrorCode.CONFLICT, "연결된 AWS 계정이 등록한 계정과 다릅니다.");
        }
        if (!targets.markVerified(lease.targetKey(), lease.targetVersion(), request.accountId())) {
            repository.failOrRetry(jobId, false, "TARGET_CHANGED", retryDelaySeconds);
            throw new ApiException(ErrorCode.CONFLICT, "연결 확인 중 대상 정보가 변경되었습니다.");
        }
        repository.succeedConnection(jobId, request.accountId());
        return new ConnectionCompletionResponse(jobId, lease.targetKey(), "SUCCEEDED");
    }

    @Transactional
    public void fail(long jobId, FailureRequest request) {
        if (request == null || request.leaseToken() == null || request.leaseGeneration() < 1
                || request.errorCode() == null || !ERROR_CODE.matcher(request.errorCode()).matches()) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var lease = repository.lockLease(jobId, request.leaseToken(), request.leaseGeneration())
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT, "점검 작업 임대가 만료되었거나 변경되었습니다."));
        boolean retry = request.retryable() && lease.attemptCount() < lease.maxAttempts();
        repository.failOrRetry(jobId, retry, request.errorCode(), retryDelaySeconds);
        if (!retry && "CONNECTION_TEST".equals(lease.jobKind())) {
            targets.markFailed(lease.targetKey(), lease.targetVersion(), request.errorCode());
        }
    }

    private ScanScope normalizeScope(ScanScope input) {
        if (input == null) return new ScanScope(List.of(), List.of(), List.of());
        var regions = normalizedList(input.regions(), MAX_REGIONS, "리전");
        var services = normalizedList(input.services(), MAX_SERVICES, "서비스");
        var checks = normalizedList(input.checks(), MAX_CHECKS, "Check");
        if (!services.isEmpty() && !checks.isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "서비스와 개별 Check는 동시에 지정할 수 없습니다.");
        }
        for (String region : regions) {
            if (!REGION.matcher(region).matches()) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 AWS 리전 형식입니다: " + region);
            }
        }
        for (String service : services) {
            if (!scopeCatalog.supportsService(service)) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 AWS 서비스입니다: " + service);
            }
        }
        for (String check : checks) {
            if (!scopeCatalog.supportsCheck(check)) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 Check입니다: " + check);
            }
        }
        return new ScanScope(regions, services, checks);
    }

    private static List<String> normalizedList(List<String> values, int max, String label) {
        if (values == null || values.isEmpty()) return List.of();
        if (values.size() > max) {
            throw new ApiException(ErrorCode.INVALID_INPUT, label + " 선택 개수가 너무 많습니다.");
        }
        var normalized = new LinkedHashSet<String>();
        for (String value : values) {
            if (value == null) throw new ApiException(ErrorCode.INVALID_INPUT);
            String item = value.trim().toLowerCase(Locale.ROOT);
            if (item.isEmpty() || item.length() > 180) throw new ApiException(ErrorCode.INVALID_INPUT);
            normalized.add(item);
        }
        return List.copyOf(new ArrayList<>(normalized));
    }

    private static String normalizeWorkerId(String workerId) {
        if (workerId == null || !WORKER_ID.matcher(workerId.trim()).matches()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "Worker 식별자가 올바르지 않습니다.");
        }
        return workerId.trim();
    }

    private void requireAdmin(String loginId) {
        if (!complianceRepository.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
    }

    private String target(String requestedTarget) {
        String value = requestedTarget == null || requestedTarget.isBlank() ? targetKey : requestedTarget.trim();
        if (!value.matches("^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "점검 대상 키가 올바르지 않습니다.");
        }
        return value;
    }
}
