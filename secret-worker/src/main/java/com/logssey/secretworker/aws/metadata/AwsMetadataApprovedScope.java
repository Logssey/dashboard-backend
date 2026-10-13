package com.logssey.secretworker.aws.metadata;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact scope contract; one approved service in one region, or the global S3 bucket list. */
public record AwsMetadataApprovedScope(String accountId, String region,
                                       AwsMetadataCollector.Service service) {
    private static final String REGION = "[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]+";
    private static final Pattern SECRETS = Pattern.compile(
            "^aws://([0-9]{12})/(" + REGION + ")/secrets-manager/all$");
    private static final Pattern PARAMETERS = Pattern.compile(
            "^aws://([0-9]{12})/(" + REGION + ")/ssm/parameters$");
    private static final Pattern BUCKETS = Pattern.compile(
            "^aws://([0-9]{12})/global/s3/buckets$");

    public static boolean supports(String contentType) {
        return "AWS_SECRETS_MANAGER_METADATA".equals(contentType)
                || "AWS_SSM_PARAMETER_METADATA".equals(contentType)
                || "AWS_S3_BUCKET_METADATA".equals(contentType);
    }

    public static AwsMetadataApprovedScope parse(String contentType, String approvedRef,
                                                 String historyLimit) {
        if (!"CURRENT_STATE_ONLY".equals(historyLimit) || approvedRef == null) {
            throw new IllegalArgumentException("INVALID_AWS_METADATA_SCOPE");
        }
        Pattern pattern;
        AwsMetadataCollector.Service service;
        switch (contentType) {
            case "AWS_SECRETS_MANAGER_METADATA" -> {
                pattern = SECRETS;
                service = AwsMetadataCollector.Service.SECRETS_MANAGER;
            }
            case "AWS_SSM_PARAMETER_METADATA" -> {
                pattern = PARAMETERS;
                service = AwsMetadataCollector.Service.SSM_PARAMETER;
            }
            case "AWS_S3_BUCKET_METADATA" -> {
                pattern = BUCKETS;
                service = AwsMetadataCollector.Service.S3_BUCKET;
            }
            default -> throw new IllegalArgumentException("UNSUPPORTED_AWS_METADATA_SCOPE");
        }
        Matcher match = pattern.matcher(approvedRef);
        if (!match.matches()) throw new IllegalArgumentException("INVALID_AWS_METADATA_SCOPE");
        return new AwsMetadataApprovedScope(match.group(1),
                service == AwsMetadataCollector.Service.S3_BUCKET ? "global" : match.group(2), service);
    }

    @Override public String toString() {
        return "AwsMetadataApprovedScope[region=" + region + ", service=" + service + "]";
    }
}
