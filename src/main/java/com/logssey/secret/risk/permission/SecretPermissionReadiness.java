package com.logssey.secret.risk.permission;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Describes existing request guards; it neither grants permission nor supplies missing proof. */
final class SecretPermissionReadiness {
    private SecretPermissionReadiness() {}

    static Map<String, Object> describe(List<String> blockedReasons, boolean identityKnown,
                                        boolean approvedCollectorFound) {
        var reasons = Set.copyOf(blockedReasons);
        var checks = new ArrayList<Map<String, Object>>();
        checks.add(check("FEATURE_CONFIGURATION", reasons.contains("WORKER_NOT_CONFIGURED"),
                "CONTACT_OPERATIONS", false));
        checks.add(check("SECURITY_ROLE", reasons.contains("SECURITY_REQUIRED"),
                "CONTACT_SECURITY", false));
        checks.add(check("SUPPORTED_CREDENTIAL", reasons.contains("UNSUPPORTED_TYPE") || reasons.contains("CROSS_SOURCE_PERMISSION_UNSUPPORTED"),
                "MANUAL_PERMISSION_REVIEW", true));
        checks.add(check("COMPLETE_CREDENTIAL", reasons.contains("COMPLETE_IDENTITY_REQUIRED"),
                "COLLECT_COMPLETE_CREDENTIAL", false));
        checks.add(check("SOURCE_ACCESS", reasons.contains("SOURCE_UNAVAILABLE"),
                "REVIEW_CONNECTION", false));
        checks.add(check("KEY_IDENTITY", !identityKnown,
                "VALIDATE_CREDENTIAL", false));
        if (!identityKnown) {
            checks.add(fact("COLLECTOR", "WAITING", null));
        } else {
            checks.add(check("COLLECTOR", !approvedCollectorFound,
                    "CHOOSE_APPROVED_COLLECTOR", false));
        }
        String next = checks.stream()
                .filter(row -> "BLOCKED".equals(row.get("status"))
                        || "UNSUPPORTED".equals(row.get("status")))
                .map(row -> (String) row.get("action"))
                .findFirst().orElse("REQUEST_PERMISSIONS");
        return Map.of("nextAction", next, "checks", List.copyOf(checks));
    }

    private static Map<String, Object> check(String code, boolean blocked, String action,
                                              boolean unsupported) {
        return fact(code, blocked ? unsupported ? "UNSUPPORTED" : "BLOCKED" : "READY",
                blocked ? action : null);
    }

    private static Map<String, Object> fact(String code, String status, String action) {
        var result = new LinkedHashMap<String, Object>();
        result.put("code", code);
        result.put("status", status);
        result.put("action", action);
        return result;
    }
}
