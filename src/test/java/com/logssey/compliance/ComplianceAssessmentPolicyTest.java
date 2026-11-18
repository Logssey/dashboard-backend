package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;

import com.logssey.compliance.ComplianceTargetDtos.AssessmentProfile;

import org.junit.jupiter.api.Test;

class ComplianceAssessmentPolicyTest {

    private final ComplianceService service = new ComplianceService(
            null, new ComplianceCatalog(), new ProwlerOcsfNormalizer(),
            new ComplianceCheckPolicyCatalog(), null, new ProwlerScopeCatalog(), "test", 1024);

    @Test
    void optionalServiceAbsenceRequiresReviewInsteadOfFailingControl() {
        var assessments = service.assess(importWith("bedrock_guardrails_configured", "FAIL"));

        assertThat(status(assessments, "isms", "2.10.2")).isEqualTo("NEEDS_REVIEW");
    }

    @Test
    void explicitlyUnusedServiceDoesNotAffectMappedControl() {
        var profile = new AssessmentProfile(1, Map.of("bedrock", "NOT_USED"), Map.of());
        var assessments = service.assess(importWith("bedrock_guardrails_configured", "FAIL"), profile, Set.of());

        assertThat(status(assessments, "isms", "2.10.2")).isEqualTo("NOT_ASSESSED");
    }

    @Test
    void explicitlyUsedServiceMakesItsFailureApplicable() {
        var profile = new AssessmentProfile(1, Map.of("bedrock", "USED"), Map.of());
        var assessments = service.assess(importWith("bedrock_guardrails_configured", "FAIL"), profile, Set.of());

        assertThat(status(assessments, "isms", "2.10.2")).isEqualTo("TECHNICAL_FAIL");
    }

    @Test
    void observedResourceOverridesStaleNotUsedDeclaration() {
        var staleProfile = new AssessmentProfile(1, Map.of("bedrock", "NOT_USED"), Map.of());
        var assessments = service.assess(
                importWith("bedrock_guardrails_configured", "FAIL"), staleProfile, Set.of("bedrock"));

        assertThat(status(assessments, "isms", "2.10.2")).isEqualTo("TECHNICAL_FAIL");
    }

    @Test
    void explicitPolicyDecisionControlsArchitectureCheckApplicability() {
        var required = new AssessmentProfile(1, Map.of(), Map.of("MULTI_REGION", "REQUIRED"));
        var notRequired = new AssessmentProfile(1, Map.of(), Map.of("MULTI_REGION", "NOT_REQUIRED"));

        assertThat(status(service.assess(importWith("vpc_different_regions", "FAIL"), required, Set.of()),
                "isms", "2.9.2")).isEqualTo("TECHNICAL_FAIL");
        assertThat(status(service.assess(importWith("vpc_different_regions", "FAIL"), notRequired, Set.of()),
                "isms", "2.9.2")).isEqualTo("NOT_ASSESSED");
    }

    @Test
    void directApplicableFailureStillFailsControl() {
        var assessments = service.assess(importWith("securityhub_enabled", "FAIL"));

        assertThat(status(assessments, "isms", "2.10.1")).isEqualTo("TECHNICAL_FAIL");
    }

    @Test
    void csapPartialAndSupportingFailuresCannotFailWholeRequirement() {
        var assessments = service.assess(importWith("ecr_registry_scan_images_on_push_enabled", "FAIL"));

        assertThat(status(assessments, "csap", "3.3.2")).isEqualTo("NEEDS_REVIEW");
        assertThat(status(assessments, "csap", "9.2.4")).isEqualTo("NEEDS_REVIEW");
    }

    @Test
    void collectionErrorRequiresReviewInsteadOfBecomingConfigurationFailure() {
        var assessments = service.assess(importWith("securityhub_enabled", "ERROR"));

        assertThat(status(assessments, "isms", "2.10.1")).isEqualTo("NEEDS_REVIEW");
    }

    @Test
    void indeterminateResultCannotBecomeTechnicalSatisfaction() {
        var assessments = service.assess(importWith("securityhub_enabled", "NEEDS_REVIEW"));

        assertThat(status(assessments, "isms", "2.10.1")).isEqualTo("NEEDS_REVIEW");
    }

    private static ProwlerOcsfNormalizer.NormalizedImport importWith(String checkId, String result) {
        var finding = new ProwlerOcsfNormalizer.NormalizedResult(
                checkId, checkId, "aws", result, "AWS Account", "observed", "expected",
                OffsetDateTime.parse("2026-11-18T00:00:00Z"), "global", "Unknown", "fingerprint",
                "account", "AwsAccount", "prod");
        return new ProwlerOcsfNormalizer.NormalizedImport(
                Map.of("finding", finding), 1, 0, 0, "Prowler", "5.46.0");
    }

    private static String status(java.util.List<ComplianceRepository.AssessmentInput> assessments,
                                 String framework, String control) {
        return assessments.stream()
                .filter(item -> item.frameworkId().equals(framework) && item.controlId().equals(control))
                .findFirst().orElseThrow().status();
    }
}
