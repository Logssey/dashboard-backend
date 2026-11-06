package com.logssey.secret.response;

import java.util.regex.Pattern;

/** Supported location rechecks. AWS resources are parsed again by the worker before any read. */
public final class SecretLocationScopePolicy {
    private static final String REGION = "[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+";
    private static final String EXACT_SEGMENT = "(?:[^/?#%*\\\\\\p{Cntrl}]|%[0-9A-Fa-f]{2})+";
    private static final Pattern SECRET = Pattern.compile("^aws://[0-9]{12}/" + REGION
            + "/secrets-manager/secret/" + EXACT_SEGMENT + "$", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern PARAMETER = Pattern.compile("^aws://[0-9]{12}/" + REGION
            + "/ssm/parameter/" + EXACT_SEGMENT + "$", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern OBJECT = Pattern.compile("^aws://[0-9]{12}/" + REGION
            + "/s3/object/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/" + EXACT_SEGMENT + "$",
            Pattern.UNICODE_CHARACTER_CLASS);

    private SecretLocationScopePolicy() { }

    public static boolean approved(String provider, String contentType, String historyLimit,
                                   String approvedRef) {
        if ("GITHUB".equals(provider))
            return SecretGithubScopePolicy.approved(contentType, historyLimit, approvedRef);
        if ("NOTION".equals(provider))
            return com.logssey.secret.notion.NotionScopeSql.valid(contentType, approvedRef, historyLimit);
        return "AWS".equals(provider) && awsApproved(contentType, historyLimit, approvedRef);
    }

    static boolean approved(String contentType, String historyLimit, String approvedRef) {
        if (SecretGithubScopePolicy.approved(contentType, historyLimit, approvedRef)) return true;
        if (com.logssey.secret.notion.NotionScopeSql.valid(contentType, approvedRef, historyLimit)) return true;
        return awsApproved(contentType, historyLimit, approvedRef);
    }

    private static boolean awsApproved(String contentType, String historyLimit, String approvedRef) {
        if (!"CURRENT_VALUE_ONLY".equals(historyLimit) || approvedRef == null
                || approvedRef.length() > 500) return false;
        return switch (contentType == null ? "" : contentType) {
            case "AWS_SECRETS_MANAGER_VALUE" -> SECRET.matcher(approvedRef).matches();
            case "AWS_SSM_PARAMETER_VALUE" -> PARAMETER.matcher(approvedRef).matches();
            case "AWS_S3_OBJECT_CONTENT" -> OBJECT.matcher(approvedRef).matches();
            default -> false;
        };
    }
}
