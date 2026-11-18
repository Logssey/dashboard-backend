package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;

import com.logssey.compliance.ComplianceTargetDtos.AssessmentProfile;

import org.junit.jupiter.api.Test;

class ComplianceCheckPolicyCatalogTest {

    private final ComplianceCheckPolicyCatalog catalog = new ComplianceCheckPolicyCatalog();

    @Test
    void conditionalChecksRequireReviewAndExposeSafeGuidance() {
        var scope = new ProwlerScopeCatalog();
        assertThat(catalog.size()).isGreaterThanOrEqualTo(24);
        assertThat(catalog.version()).isEqualTo("2026-11-18.1");
        assertThat(catalog.checkIds()).allMatch(scope::supportsCheck);
        assertThat(catalog.applicability("aws", "bedrock_guardrails_configured",
                AssessmentProfile.empty(), Set.of())).isEqualTo(ComplianceCheckPolicyCatalog.ApplicabilityStatus.UNKNOWN);
        assertThat(catalog.applicability("aws", "bedrock_guardrails_configured",
                new AssessmentProfile(1, Map.of("bedrock", "NOT_USED"), Map.of()), Set.of()))
                .isEqualTo(ComplianceCheckPolicyCatalog.ApplicabilityStatus.NOT_APPLICABLE);
        assertThat(catalog.applicability("aws", "securityhub_enabled",
                AssessmentProfile.empty(), Set.of())).isEqualTo(ComplianceCheckPolicyCatalog.ApplicabilityStatus.APPLICABLE);

        var kms = catalog.guide("aws", "s3_bucket_kms_encryption", "fallback");
        assertThat(kms.expectedState()).contains("SSE-KMS", "서버 측 암호화");
        assertThat(kms.applicability()).contains("SSE-S3");
        assertThat(kms.changeImpact()).contains("비용", "권한");
        assertThat(kms.verification()).isNotBlank();
        assertThat(kms.rollback()).isNotBlank();
        assertThat(kms.sourceUrl()).startsWith("https://hub.prowler.com/check/");
        assertThat(kms.sourceVersion()).isEqualTo("5.46.0");
    }

    @Test
    void iamHardwareMfaGuideSeparatesConsoleUsersFromAutomation() {
        var guide = catalog.guide("aws", "iam_user_hardware_mfa_enabled", "fallback");

        assertThat(guide.applicability()).contains("콘솔", "비콘솔");
        assertThat(guide.expectedState()).contains("IAM Role", "임시 자격증명");
    }
}
