package com.logssey.compliance;

import static com.logssey.compliance.ComplianceJobDtos.ClaimedJob;
import static com.logssey.compliance.ComplianceJobDtos.CancelJobResponse;
import static com.logssey.compliance.ComplianceJobDtos.CompletionResponse;
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
    private final ProwlerScopeCatalog scopeCatalog;
    private final String targetKey;
    private final boolean executionEnabled;
    private final int leaseSeconds;
    private final int retryDelaySeconds;

    public ComplianceJobService(ComplianceJobRepository repository, ComplianceRepository complianceRepository,
                                ComplianceService compliance, ProwlerScopeCatalog scopeCatalog,
                                @Value("${logssey.compliance.target-key:default}") String targetKey,
                                @Value("${logssey.compliance.worker-lease-seconds:900}") int leaseSeconds,
                                @Value("${logssey.compliance.worker-retry-delay-seconds:30}") int retryDelaySeconds,
                                @Value("${logssey.compliance.execution-enabled:true}") boolean executionEnabled) {
        this.repository = repository;
        this.complianceRepository = complianceRepository;
        this.compliance = compliance;
        this.scopeCatalog = scopeCatalog;
        this.targetKey = targetKey;
        this.executionEnabled = executionEnabled;
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
        String environment = ComplianceService.environment(request.environment(), false);
        ScanScope scope = normalizeScope(request.scope());
        long jobId = repository.insert(targetKey, environment, scope, loginId);
        return new CreateJobResponse(jobId, "QUEUED");
    }

    @Transactional(readOnly = true)
    public JobListResponse jobs(int limit) {
        if (limit < 1 || limit > MAX_JOBS) throw new ApiException(ErrorCode.INVALID_INPUT);
        return new JobListResponse(repository.jobs(targetKey, limit));
    }

    @Transactional(readOnly = true)
    public JobSummary job(long jobId) {
        return repository.job(targetKey, jobId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    @Transactional
    public CancelJobResponse cancel(String loginId, long jobId) {
        requireAdmin(loginId);
        if (repository.cancel(targetKey, jobId)) return new CancelJobResponse(jobId, "CANCELLED");
        var existing = repository.job(targetKey, jobId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        throw new ApiException(ErrorCode.CONFLICT,
                "현재 상태(" + existing.status() + ")에서는 점검을 취소할 수 없습니다.");
    }

    public ScopeCatalogResponse scopeCatalog() {
        return new ScopeCatalogResponse("aws", executionEnabled, scopeCatalog.version(), scopeCatalog.commit(),
                scopeCatalog.services(), scopeCatalog.checkItems());
    }

    @Transactional
    public ClaimedJob claim(String workerId) {
        String normalizedWorker = normalizeWorkerId(workerId);
        repository.failExhaustedLeases(targetKey);
        return repository.claim(targetKey, normalizedWorker, UUID.randomUUID(), leaseSeconds, scopeCatalog.version())
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
        var imported = compliance.importProwlerResult("compliance-worker/job-" + jobId, lease.environment(), file);
        repository.succeed(jobId, imported.runId());
        return new CompletionResponse(jobId, imported.runId(), "SUCCEEDED");
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
                throw new ApiException(ErrorCode.INVALID_INPUT, "Prowler 5.46.0에 없는 서비스입니다: " + service);
            }
        }
        for (String check : checks) {
            if (!scopeCatalog.supportsCheck(check)) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "Prowler 5.46.0에 없는 Check입니다: " + check);
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
}
