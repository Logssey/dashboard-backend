package com.logssey.secretworker.aws.content;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/** One explicitly approved AWS value. Metadata-only scopes cannot be parsed here. */
public final class AwsContentScope {
    public enum Kind { SECRETS_MANAGER, SSM_PARAMETER, S3_OBJECT }

    private static final Pattern ACCOUNT = Pattern.compile("[0-9]{12}");
    private static final Pattern REGION = Pattern.compile("[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+");
    private static final Pattern BUCKET = Pattern.compile("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]");

    private final Kind kind;
    private final String accountId;
    private final String region;
    private final String resource;
    private final String objectKey;

    private AwsContentScope(Kind kind, String accountId, String region, String resource,
                            String objectKey) {
        this.kind = kind;
        this.accountId = accountId;
        this.region = region;
        this.resource = resource;
        this.objectKey = objectKey;
    }

    public static AwsContentScope fromApprovedRef(String contentType, String approvedRef,
                                                   String historyLimit) {
        if (!"CURRENT_VALUE_ONLY".equals(historyLimit)) throw invalid();
        // V3 secret_connection_scopes.approved_ref is VARCHAR(500).
        if (approvedRef == null || approvedRef.length() > 500) throw invalid();
        Kind kind = switch (contentType == null ? "" : contentType) {
            case "AWS_SECRETS_MANAGER_VALUE" -> Kind.SECRETS_MANAGER;
            case "AWS_SSM_PARAMETER_VALUE" -> Kind.SSM_PARAMETER;
            case "AWS_S3_OBJECT_CONTENT" -> Kind.S3_OBJECT;
            default -> throw invalid();
        };
        URI uri;
        try {
            uri = URI.create(approvedRef);
        } catch (RuntimeException error) {
            throw invalid();
        }
        if (!"aws".equals(uri.getScheme()) || uri.getRawAuthority() == null
                || !uri.getRawAuthority().equals(uri.getHost()) || uri.getRawUserInfo() != null
                || uri.getPort() != -1 || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !ACCOUNT.matcher(uri.getHost()).matches() || uri.getRawPath() == null) {
            throw invalid();
        }
        String[] parts = uri.getRawPath().split("/", -1);
        int expected = kind == Kind.S3_OBJECT ? 6 : 5;
        if (parts.length != expected || !parts[0].isEmpty()
                || !REGION.matcher(parts[1]).matches()) throw invalid();
        String account = uri.getHost();
        String region = parts[1];
        String resource;
        String key = null;
        switch (kind) {
            case SECRETS_MANAGER -> {
                if (!"secrets-manager".equals(parts[2]) || !"secret".equals(parts[3])) throw invalid();
                resource = decode(parts[4]);
                if (!resource.matches("arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:"
                        + Pattern.quote(region) + ":" + account + ":secret:[A-Za-z0-9/_+=.@-]{1,512}")) {
                    throw invalid();
                }
            }
            case SSM_PARAMETER -> {
                if (!"ssm".equals(parts[2]) || !"parameter".equals(parts[3])) throw invalid();
                resource = decode(parts[4]);
                if (!resource.matches("arn:(?:aws|aws-us-gov|aws-cn):ssm:"
                        + Pattern.quote(region) + ":" + account + ":parameter/[A-Za-z0-9_./-]{1,1011}")) {
                    throw invalid();
                }
            }
            case S3_OBJECT -> {
                if (!"s3".equals(parts[2]) || !"object".equals(parts[3])
                        || !BUCKET.matcher(parts[4]).matches() || parts[4].contains("..")) throw invalid();
                resource = parts[4];
                key = decode(parts[5]);
                if (key.getBytes(StandardCharsets.UTF_8).length > 1024 || key.indexOf('*') >= 0) {
                    throw invalid();
                }
            }
            default -> throw invalid();
        }
        return new AwsContentScope(kind, account, region, resource, key);
    }

    public Kind kind() { return kind; }
    public String accountId() { return accountId; }
    public String region() { return region; }
    public String resource() { return resource; }
    public String objectKey() { return objectKey; }
    @Override public String toString() {
        return "AwsContentScope[kind=" + kind + "]";
    }

    private static String decode(String raw) {
        if (raw.isEmpty() || raw.equals(".") || raw.equals("..")) throw invalid();
        String decoded;
        try {
            decoded = URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (RuntimeException error) {
            throw invalid();
        }
        if (decoded.isBlank() || decoded.chars().anyMatch(c -> c < 32 || c == 127 || c == '\\')) {
            throw invalid();
        }
        return decoded;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid exact AWS content scope");
    }
}
