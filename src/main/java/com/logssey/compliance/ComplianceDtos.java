package com.logssey.compliance;

import static com.logssey.compliance.ComplianceTargetDtos.AssessmentProfile;

import java.time.OffsetDateTime;
import java.util.List;

public final class ComplianceDtos {
    private ComplianceDtos() {}

    public record ResultCounts(long total, long pass, long fail, long error, long needsReview) {}

    public record RunSummary(long runId, String environment, String status, String source, String product,
                             String scannerVersion, ResultCounts counts, int duplicateCount, int warningCount,
                             String createdBy, OffsetDateTime finishedAt) {}

    public record FrameworkSummary(String id, String name, String shortName, String version, int totalControls,
                                   int technicalFail, int technicallySatisfied, int needsReview,
                                   int notAssessed, int manualControls) {}

    public record OverviewResponse(RunSummary latestRun, List<FrameworkSummary> frameworks) {}
    public record RunListResponse(List<RunSummary> items) {}

    public record ImprovementGuide(String disposition, String expectedState, String applicability,
                                   String changeImpact, String verification, String rollback,
                                   String sourceUrl, String sourceVersion) {}

    public record ResultItem(long resultId, String checkId, String title, String provider, String result,
                             String asset, String currentValue, String expectedValue, OffsetDateTime observedAt,
                             String region, String severity, String assetType, ImprovementGuide guide) {
        public ResultItem(long resultId, String checkId, String title, String provider, String result,
                          String asset, String currentValue, String expectedValue, OffsetDateTime observedAt,
                          String region, String severity, String assetType) {
            this(resultId, checkId, title, provider, result, asset, currentValue, expectedValue,
                    observedAt, region, severity, assetType, null);
        }

        ResultItem withGuide(ImprovementGuide selectedGuide) {
            return new ResultItem(resultId, checkId, title, provider, result, asset, currentValue,
                    expectedValue, observedAt, region, severity, assetType, selectedGuide);
        }
    }

    public record AssessmentContext(AssessmentProfile profile, String policyVersion,
                                    List<String> inferredServices) {}

    public record RunDetailResponse(RunSummary run, List<FrameworkSummary> frameworks,
                                    List<ResultItem> results, boolean resultsTruncated,
                                    AssessmentContext assessmentContext) {}

    public record ImportResponse(long runId, String status, int importedCount, int duplicateCount,
                                 int warningCount, List<FrameworkSummary> frameworks) {}

    public record CatalogResponse(String prowlerVersion, String generatedAt, List<CatalogFramework> frameworks) {}
    public record CatalogFramework(String id, String name, String shortName, String version,
                                   String status, int controls, int mappings, int manualControls) {}
}
