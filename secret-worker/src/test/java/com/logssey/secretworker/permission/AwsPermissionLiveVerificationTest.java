package com.logssey.secretworker.permission;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secretworker.validation.AwsCredentialValidator;
import com.logssey.secretworker.validation.AwsKeyMaterial;
import com.logssey.secretworker.validation.AwsValidationResult;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

/**
 * Explicit, read-only operator check. No source fixture, database, assertion or discovered-key
 * identity is created. Ordinary tests and CI do not use local profiles or contact AWS.
 */
@EnabledIfEnvironmentVariable(named = "SECRET_LIVE_AWS_PERMISSION_VERIFY", matches = "true")
class AwsPermissionLiveVerificationTest {
    @Test void explicitProfileCanAuthenticateAndReadItsBoundPolicyCandidates() {
        String profile = System.getenv("SECRET_LIVE_AWS_PROFILE");
        assertTrue(profile != null && profile.matches("[A-Za-z0-9._-]{1,100}"),
                "Set an explicit approved profile for this read-only check");
        try (var source = SecretAwsSourceCredentials.profile(profile)) {
            var credentials = source.resolveCredentials();
            var material = new AwsKeyMaterial(credentials.accessKeyId(), credentials.secretAccessKey(),
                    credentials instanceof AwsSessionCredentials session ? session.sessionToken() : null);
            var validation = new AwsCredentialValidator(true).validate(material);
            assertTrue(validation.status() == AwsValidationResult.Status.VALID,
                    "The explicit profile did not complete the STS authentication check");
            var identity = validation.identity();
            assertTrue(identity != null && "AWS".equals(identity.provider()),
                    "STS did not return a supported bound identity");
            // Bind to the identity just authenticated, never to a user-entered principal ARN.
            var candidate = new AwsPermissionObserver().observe(Map.of(
                    "principal_type", identity.principalType(),
                    "principal_ref", identity.principalRef(),
                    "principal_id", identity.principalId(),
                    "account_ref", identity.accountRef()), source);
            assertTrue("PARTIAL".equals(candidate.status()),
                    "Policy candidates must not claim complete effective permission coverage");
            assertTrue(candidate.policyDocumentCount() > 0,
                    "No bound policy document was read; review IAM read access or attached policies");
            assertTrue(!candidate.capabilities().isEmpty(),
                    "No supported capability candidate was observed in the bound policy documents");
            assertTrue(candidate.coverage().values().stream().anyMatch(v -> !"COMPLETE".equals(v)),
                    "A read-only observation must retain its unproven coverage");
            assertTrue("NONE_UNTIL_HUMAN_CONFIRMATION".equals(candidate.facts().get("assessmentEffect")),
                    "Read-only policy collection must not change the risk assessment");
        }
    }
}
