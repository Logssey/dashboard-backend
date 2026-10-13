package com.logssey.secretworker.aws;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One explicitly approved AWS account and IAM metadata location. */
public record AwsApprovedScope(String accountId, Kind kind) {
    private static final Pattern IAM_KEYS = Pattern.compile(
            "^aws://([0-9]{12})/global/iam/access-keys$");

    public enum Kind { IAM_ACCESS_KEY_METADATA }

    public static AwsApprovedScope parse(String contentType, String approvedRef, String historyLimit) {
        if (!"IAM_ACCESS_KEY_METADATA".equals(contentType)
                || historyLimit != null && !"CURRENT_STATE_ONLY".equals(historyLimit)) {
            throw new IllegalArgumentException("UNSUPPORTED_AWS_SCOPE");
        }
        Matcher matcher = IAM_KEYS.matcher(approvedRef == null ? "" : approvedRef);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("INVALID_AWS_SCOPE");
        }
        return new AwsApprovedScope(matcher.group(1), Kind.IAM_ACCESS_KEY_METADATA);
    }
}
