package com.logssey.secret.risk.permission;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SecretPermissionReadinessTest {
    @Test void cannotDiagnoseAnAccountScopedCollectorUntilTheFoundKeyIdentityIsKnown() {
        var result = SecretPermissionReadiness.describe(
                List.of("FRESH_IDENTITY_VALIDATION_REQUIRED"), false, false);
        assertThat(result).containsEntry("nextAction", "VALIDATE_CREDENTIAL");
        assertThat(check(result, "KEY_IDENTITY")).containsEntry("status", "BLOCKED");
        assertThat(check(result, "COLLECTOR")).containsEntry("status", "WAITING")
                .containsEntry("action", null);
    }

    @Test void afterIdentityValidationTheMissingCollectorHasItsOwnAction() {
        var result = SecretPermissionReadiness.describe(
                List.of("APPROVED_COLLECTOR_REQUIRED"), true, false);
        assertThat(result).containsEntry("nextAction", "CHOOSE_APPROVED_COLLECTOR");
        assertThat(check(result, "COLLECTOR")).containsEntry("status", "BLOCKED");
    }

    @Test void anUnavailableFeatureOrUnsupportedCredentialDoesNotDirectUsersToRevalidate() {
        var disabled = SecretPermissionReadiness.describe(
                List.of("WORKER_NOT_CONFIGURED", "FRESH_IDENTITY_VALIDATION_REQUIRED"), false, false);
        assertThat(disabled).containsEntry("nextAction", "CONTACT_OPERATIONS");
        var unsupported = SecretPermissionReadiness.describe(
                List.of("UNSUPPORTED_TYPE", "FRESH_IDENTITY_VALIDATION_REQUIRED"), false, false);
        assertThat(unsupported).containsEntry("nextAction", "MANUAL_PERMISSION_REVIEW");
        assertThat(check(unsupported, "SUPPORTED_CREDENTIAL")).containsEntry("status", "UNSUPPORTED");
    }

    @Test void readyOnlyDescribesEligibilityAndDoesNotPretendPermissionsHaveBeenConfirmed() {
        var result = SecretPermissionReadiness.describe(List.of(), true, true);
        assertThat(result).containsEntry("nextAction", "REQUEST_PERMISSIONS");
        assertThat(result.toString()).doesNotContain("CONFIRMED", "severity", "principal", "policyDocument");
        assertThat(check(result, "COLLECTOR")).containsEntry("status", "READY");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> check(Map<String, Object> result, String code) {
        return ((List<Map<String, Object>>) result.get("checks")).stream()
                .filter(row -> code.equals(row.get("code"))).findFirst().orElseThrow();
    }
}
