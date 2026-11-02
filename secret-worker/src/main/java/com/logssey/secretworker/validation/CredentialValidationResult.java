package com.logssey.secretworker.validation;

import java.time.Instant;
import java.util.Set;

/** Safe metadata only. No body, header, profile or exception text. */
public record CredentialValidationResult(
        String result,
        String reasonCode,
        Instant providerCheckedAt,
        Integer httpStatus,
        Instant nextDueAt,
        com.logssey.secret.permission.core.SecretProviderIdentity identity) {
    public CredentialValidationResult(String result,String reasonCode,Instant providerCheckedAt,Integer httpStatus,Instant nextDueAt){this(result,reasonCode,providerCheckedAt,httpStatus,nextDueAt,null);}
    public CredentialValidationResult {
        if (!Set.of("VALID", "INVALID", "UNKNOWN", "UNCHECKED").contains(result)
                || reasonCode == null
                || !reasonCode.matches("[A-Z0-9_]{1,80}")
                || Set.of("VALID", "INVALID").contains(result) && providerCheckedAt == null
                || "UNCHECKED".equals(result) && providerCheckedAt != null)
            throw new IllegalArgumentException("INVALID_VALIDATION_RESULT");
        if(identity!=null&&!"VALID".equals(result))throw new IllegalArgumentException("IDENTITY_REQUIRES_VALID_RESULT");
    }

    public static CredentialValidationResult unchecked(String reason) {
        return new CredentialValidationResult("UNCHECKED", reason, null, null, null);
    }

    public static CredentialValidationResult unknown(String reason) {
        return new CredentialValidationResult("UNKNOWN", reason, null, null, null);
    }

    public boolean retryable() {
        return "UNCHECKED".equals(result) && "RATE_BUDGET_EXHAUSTED".equals(reasonCode)
                || "UNKNOWN".equals(result)
                        && Set.of(
                                        "RATE_LIMITED",
                                        "PROVIDER_UNAVAILABLE",
                                        "CLIENT_FAILURE",
                                        "SOURCE_UNAVAILABLE")
                                .contains(reasonCode);
    }
}
