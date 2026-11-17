package com.logssey.compliance;

import static com.logssey.compliance.ComplianceTargetDtos.ConnectionTestResponse;
import static com.logssey.compliance.ComplianceTargetDtos.CreateTargetRequest;
import static com.logssey.compliance.ComplianceTargetDtos.TargetListResponse;
import static com.logssey.compliance.ComplianceTargetDtos.TargetSummary;
import static com.logssey.compliance.ComplianceTargetDtos.UpdateTargetRequest;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ComplianceTargetService {

    private static final Pattern TARGET_KEY = Pattern.compile("^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$");
    private static final Pattern ACCOUNT_ID = Pattern.compile("^[0-9]{12}$");
    private static final Pattern ROLE_ARN = Pattern.compile(
            "^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$");
    private static final Pattern REGION = Pattern.compile("^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\\d$");
    private static final int MAX_REGIONS = 30;

    private final ComplianceTargetRepository targets;
    private final ComplianceJobRepository jobs;
    private final ComplianceRepository compliance;
    private final boolean connectionTestsEnabled;

    public ComplianceTargetService(ComplianceTargetRepository targets, ComplianceJobRepository jobs,
                                   ComplianceRepository compliance,
                                   @Value("${logssey.compliance.connection-tests-enabled:false}")
                                   boolean connectionTestsEnabled) {
        this.targets = targets;
        this.jobs = jobs;
        this.compliance = compliance;
        this.connectionTestsEnabled = connectionTestsEnabled;
    }

    @Transactional(readOnly = true)
    public TargetListResponse list() {
        return new TargetListResponse(targets.list());
    }

    @Transactional(readOnly = true)
    public TargetSummary target(String targetKey) {
        return targets.find(normalizeKey(targetKey)).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    @Transactional
    public TargetSummary create(String loginId, CreateTargetRequest request) {
        requireAdmin(loginId);
        if (request == null) throw new ApiException(ErrorCode.INVALID_INPUT);
        String targetKey = normalizeKey(request.targetKey());
        String displayName = displayName(request.displayName());
        Role role = role(request.awsAccountId(), request.roleArn());
        List<String> regions = regions(request.defaultRegions());
        String externalId = "logssey-" + UUID.randomUUID();
        try {
            return targets.insert(targetKey, displayName, role.accountId(), role.arn(), externalId, regions, loginId);
        } catch (DataIntegrityViolationException e) {
            throw new ApiException(ErrorCode.CONFLICT, "같은 대상 키 또는 역할 ARN이 이미 등록되어 있습니다.");
        }
    }

    @Transactional
    public TargetSummary update(String loginId, String targetKey, UpdateTargetRequest request) {
        requireAdmin(loginId);
        if (request == null || request.expectedVersion() < 1) throw new ApiException(ErrorCode.INVALID_INPUT);
        String normalizedKey = normalizeKey(targetKey);
        TargetSummary current = targets.find(normalizedKey)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        String displayName = displayName(request.displayName());
        Role role = role(request.awsAccountId(), request.roleArn());
        List<String> regions = regions(request.defaultRegions());
        boolean enabled = Boolean.TRUE.equals(request.enabled());
        boolean identityChanged = !current.awsAccountId().equals(role.accountId())
                || !current.roleArn().equals(role.arn());
        if (enabled && (identityChanged || !"VERIFIED".equals(current.connectionStatus()))) {
            throw new ApiException(ErrorCode.CONFLICT, "연결 확인이 끝난 현재 역할만 점검 대상으로 활성화할 수 있습니다.");
        }
        try {
            return targets.update(normalizedKey, request.expectedVersion(), displayName, role.accountId(), role.arn(),
                            regions, enabled, loginId)
                    .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT, "대상 정보가 변경되었습니다. 다시 조회하세요."));
        } catch (DataIntegrityViolationException e) {
            throw new ApiException(ErrorCode.CONFLICT, "같은 역할 ARN이 이미 등록되어 있습니다.");
        }
    }

    @Transactional
    public ConnectionTestResponse verify(String loginId, String targetKey) {
        requireAdmin(loginId);
        if (!connectionTestsEnabled) {
            throw new ApiException(ErrorCode.CONFLICT, "AWS 연결 확인 Worker를 준비한 뒤 활성화됩니다.");
        }
        String normalizedKey = normalizeKey(targetKey);
        var target = targets.executionSnapshot(normalizedKey)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!targets.markVerifying(normalizedKey, target.version(), loginId)) {
            throw new ApiException(ErrorCode.CONFLICT, "이미 연결 확인 중이거나 대상 정보가 변경되었습니다.");
        }
        try {
            long jobId = jobs.insertConnectionTest(target, loginId);
            return new ConnectionTestResponse(jobId, "QUEUED");
        } catch (DataIntegrityViolationException e) {
            throw new ApiException(ErrorCode.CONFLICT, "이미 연결 확인 작업이 진행 중입니다.");
        }
    }

    public boolean connectionTestsEnabled() {
        return connectionTestsEnabled;
    }

    private void requireAdmin(String loginId) {
        if (!compliance.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
    }

    private static String normalizeKey(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!TARGET_KEY.matcher(normalized).matches()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "대상 키는 3~100자의 영문 소문자, 숫자, 하이픈만 사용할 수 있습니다.");
        }
        return normalized;
    }

    private static String displayName(String value) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.length() < 2 || normalized.length() > 120) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "대상 이름은 2~120자로 입력하세요.");
        }
        return normalized;
    }

    private static Role role(String accountId, String roleArn) {
        String normalizedAccount = accountId == null ? "" : accountId.trim();
        String normalizedArn = roleArn == null ? "" : roleArn.trim();
        Matcher matcher = ROLE_ARN.matcher(normalizedArn);
        if (!ACCOUNT_ID.matcher(normalizedAccount).matches() || !matcher.matches()
                || !normalizedAccount.equals(matcher.group(2))) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "역할 ARN과 AWS 계정 ID가 일치해야 합니다.");
        }
        return new Role(normalizedAccount, normalizedArn);
    }

    private static List<String> regions(List<String> values) {
        if (values == null || values.isEmpty()) return List.of();
        if (values.size() > MAX_REGIONS) throw new ApiException(ErrorCode.INVALID_INPUT, "기본 리전이 너무 많습니다.");
        var normalized = new LinkedHashSet<String>();
        for (String value : values) {
            String region = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
            if (!REGION.matcher(region).matches()) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 AWS 리전 형식입니다: " + region);
            }
            normalized.add(region);
        }
        return List.copyOf(new ArrayList<>(normalized));
    }

    private record Role(String accountId, String arn) {}
}
