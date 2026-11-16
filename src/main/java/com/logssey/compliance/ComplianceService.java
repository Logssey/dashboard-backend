package com.logssey.compliance;

import static com.logssey.compliance.ComplianceDtos.CatalogFramework;
import static com.logssey.compliance.ComplianceDtos.CatalogResponse;
import static com.logssey.compliance.ComplianceDtos.FrameworkSummary;
import static com.logssey.compliance.ComplianceDtos.ImportResponse;
import static com.logssey.compliance.ComplianceDtos.OverviewResponse;
import static com.logssey.compliance.ComplianceDtos.ResultCounts;
import static com.logssey.compliance.ComplianceDtos.RunDetailResponse;
import static com.logssey.compliance.ComplianceDtos.RunListResponse;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
public class ComplianceService {

    private static final int MAX_RUNS = 50;
    private static final int DETAIL_RESULTS = 300;

    private final ComplianceRepository repository;
    private final ComplianceCatalog catalog;
    private final ProwlerOcsfNormalizer normalizer;
    private final String targetKey;
    private final long maxImportBytes;

    public ComplianceService(ComplianceRepository repository, ComplianceCatalog catalog,
                             ProwlerOcsfNormalizer normalizer,
                             @Value("${logssey.compliance.target-key:default}") String targetKey,
                             @Value("${logssey.compliance.max-import-bytes:8388608}") long maxImportBytes) {
        this.repository = repository;
        this.catalog = catalog;
        this.normalizer = normalizer;
        this.targetKey = targetKey;
        this.maxImportBytes = maxImportBytes;
    }

    @Transactional(readOnly = true)
    public OverviewResponse overview(String environment) {
        String selectedEnvironment = environment(environment, true);
        var latest = repository.latestRun(targetKey, selectedEnvironment).orElse(null);
        return new OverviewResponse(latest, latest == null
                ? emptyFrameworkSummaries()
                : frameworkSummaries(latest.runId()));
    }

    @Transactional(readOnly = true)
    public RunListResponse runs(String environment, int limit) {
        if (limit < 1 || limit > MAX_RUNS) throw new ApiException(ErrorCode.INVALID_INPUT);
        return new RunListResponse(repository.runs(targetKey, environment(environment, true), limit));
    }

    @Transactional(readOnly = true)
    public RunDetailResponse run(long runId) {
        var run = repository.run(targetKey, runId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        var results = repository.results(runId, DETAIL_RESULTS + 1);
        boolean truncated = results.size() > DETAIL_RESULTS;
        if (truncated) results = results.subList(0, DETAIL_RESULTS);
        return new RunDetailResponse(run, frameworkSummaries(runId), results, truncated);
    }

    public CatalogResponse catalog() {
        var frameworks = catalog.frameworks().stream().map(framework -> {
            int mappings = framework.controls().stream().mapToInt(control -> control.mappings().size()).sum();
            int manual = (int) framework.controls().stream().filter(ComplianceCatalog.Control::manualEvidenceRequired).count();
            return new CatalogFramework(framework.id(), framework.name(), framework.shortName(), framework.version(),
                    framework.catalogStatus(), framework.controls().size(), mappings, manual);
        }).toList();
        return new CatalogResponse(catalog.source().prowlerVersion(), catalog.source().generatedAt(), frameworks);
    }

    @Transactional
    public ImportResponse importProwler(String loginId, String environment, MultipartFile file) {
        if (!repository.isAdmin(loginId)) throw new ApiException(ErrorCode.FORBIDDEN);
        return importProwlerResult(loginId, environment, file);
    }

    /** Worker endpoint가 유효한 임대를 잠근 뒤 같은 트랜잭션에서 호출한다. */
    ImportResponse importProwlerResult(String actor, String environment, MultipartFile file) {
        String selectedEnvironment = environment(environment, false);
        if (file == null || file.isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "Prowler JSON 파일을 선택해 주세요.");
        }
        if (file.getSize() > maxImportBytes) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE,
                    "Prowler JSON 파일은 최대 " + (maxImportBytes / 1024 / 1024) + "MB까지 가져올 수 있습니다.");
        }

        final byte[] bytes;
        try {
            bytes = file.getBytes();
        } catch (IOException e) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "업로드한 파일을 읽을 수 없습니다.");
        }
        var normalized = normalizer.normalize(bytes, selectedEnvironment);
        var counts = counts(normalized);
        var assessments = assess(normalized);
        String status = normalized.warningCount() > 0 ? "COMPLETED_WITH_WARNINGS" : "COMPLETED";
        long runId = repository.insertRun(targetKey, selectedEnvironment, status, normalized.product(),
                normalized.version(), sha256(bytes), normalized, counts, actor);
        repository.insertResults(runId, new ArrayList<>(normalized.results().values()));
        repository.insertAssessments(runId, assessments);
        return new ImportResponse(runId, status, normalized.results().size(), normalized.duplicateCount(),
                normalized.warningCount(), frameworkSummaries(runId));
    }

    private List<ComplianceRepository.AssessmentInput> assess(ProwlerOcsfNormalizer.NormalizedImport normalized) {
        var observedByCheck = new HashMap<String, Set<String>>();
        for (var result : normalized.results().values()) {
            observedByCheck.computeIfAbsent(result.checkKey(), ignored -> new HashSet<>()).add(result.result());
        }

        var assessments = new ArrayList<ComplianceRepository.AssessmentInput>();
        for (var framework : catalog.frameworks()) {
            for (var control : framework.controls()) {
                var mapped = new HashSet<String>();
                boolean allMappingsAreTechnical = true;
                for (var mapping : control.mappings()) {
                    mapped.add(mapping.key());
                    allMappingsAreTechnical &= "TECHNICAL".equals(mapping.coverage());
                }
                int observed = 0;
                int failed = 0;
                for (String check : mapped) {
                    var statuses = observedByCheck.get(check);
                    if (statuses == null) continue;
                    observed++;
                    if (statuses.contains("FAIL") || statuses.contains("ERROR")) failed++;
                }

                String status;
                if (failed > 0) {
                    status = "TECHNICAL_FAIL";
                } else if (mapped.isEmpty() || observed == 0) {
                    status = "NOT_ASSESSED";
                } else if (observed == mapped.size() && allMappingsAreTechnical
                        && !control.manualEvidenceRequired()) {
                    status = "TECHNICALLY_SATISFIED";
                } else {
                    status = "NEEDS_REVIEW";
                }
                assessments.add(new ComplianceRepository.AssessmentInput(framework.id(), control.id(), status,
                        mapped.size(), observed, failed));
            }
        }
        return assessments;
    }

    private List<FrameworkSummary> frameworkSummaries(long runId) {
        var counts = new HashMap<String, Map<String, Integer>>();
        for (var row : repository.assessmentCounts(runId)) {
            counts.computeIfAbsent(row.frameworkId(), ignored -> new HashMap<>()).put(row.status(), row.count());
        }
        return catalog.frameworks().stream().map(framework -> {
            var status = counts.getOrDefault(framework.id(), Map.of());
            int manual = (int) framework.controls().stream().filter(ComplianceCatalog.Control::manualEvidenceRequired).count();
            return new FrameworkSummary(framework.id(), framework.name(), framework.shortName(), framework.version(),
                    framework.controls().size(), status.getOrDefault("TECHNICAL_FAIL", 0),
                    status.getOrDefault("TECHNICALLY_SATISFIED", 0), status.getOrDefault("NEEDS_REVIEW", 0),
                    status.getOrDefault("NOT_ASSESSED", 0), manual);
        }).toList();
    }

    private List<FrameworkSummary> emptyFrameworkSummaries() {
        return catalog.frameworks().stream().map(framework -> {
            int manual = (int) framework.controls().stream().filter(ComplianceCatalog.Control::manualEvidenceRequired).count();
            return new FrameworkSummary(framework.id(), framework.name(), framework.shortName(), framework.version(),
                    framework.controls().size(), 0, 0, 0, framework.controls().size(), manual);
        }).toList();
    }

    private static ResultCounts counts(ProwlerOcsfNormalizer.NormalizedImport normalized) {
        long pass = 0, fail = 0, error = 0, review = 0;
        for (var result : normalized.results().values()) {
            switch (result.result()) {
                case "PASS" -> pass++;
                case "FAIL" -> fail++;
                case "ERROR" -> error++;
                default -> review++;
            }
        }
        return new ResultCounts(normalized.results().size(), pass, fail, error, review);
    }

    static String environment(String value, boolean allowAll) {
        String normalized = value == null ? "ALL" : value.trim().toUpperCase(Locale.ROOT);
        if (allowAll && normalized.equals("ALL")) return "ALL";
        return switch (normalized) {
            case "PROD" -> "prod";
            case "DEV" -> "dev";
            default -> throw new ApiException(ErrorCode.INVALID_INPUT, "환경은 prod 또는 dev만 선택할 수 있습니다.");
        };
    }

    private static String sha256(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", e);
        }
    }
}
