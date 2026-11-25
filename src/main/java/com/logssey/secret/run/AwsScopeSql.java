package com.logssey.secret.run;

/** Fixed SQL predicate for executable AWS scopes. The alias is never user input. */
public final class AwsScopeSql {
    private static final String REGION = "[a-z]{2}(-[a-z0-9]+){1,3}-[0-9]+";
    // A percent-encoded resource occupies exactly one path segment. The worker also parses
    // the ARN or object key and checks the account/region before reading a value.
    private static final String EXACT_SEGMENT = "([^/?#%*]|%[0-9A-Fa-f]{2})+";

    private AwsScopeSql() { }

    public static String predicate(String alias) {
        if (!"s".equals(alias) && !"unsupported".equals(alias)) {
            throw new IllegalArgumentException("Invalid scope SQL alias");
        }
        return "(" + alias + ".history_limit IS NULL AND " + alias + ".content_type = 'IAM_ACCESS_KEY_METADATA'"
                + " AND " + alias + ".approved_ref ~ '^aws://[0-9]{12}/global/iam/access-keys$'"
                + " OR " + alias + ".history_limit = 'CURRENT_STATE_ONLY' AND ("
                + "(" + alias + ".content_type = 'IAM_ACCESS_KEY_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/global/iam/access-keys$')"
                + " OR (" + alias + ".content_type = 'AWS_SECRETS_MANAGER_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + REGION + "/secrets-manager/all$')"
                + " OR (" + alias + ".content_type = 'AWS_SSM_PARAMETER_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + REGION + "/ssm/parameters$')"
                + " OR (" + alias + ".content_type = 'AWS_S3_BUCKET_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/global/s3/buckets$')"
                + ") OR (" + alias + ".history_limit = 'CURRENT_VALUE_ONLY'"
                + " AND char_length(" + alias + ".approved_ref) <= 500 AND ("
                + "(" + alias + ".content_type = 'AWS_SECRETS_MANAGER_VALUE' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + REGION
                + "/secrets-manager/secret/" + EXACT_SEGMENT + "$')"
                + " OR (" + alias + ".content_type = 'AWS_SSM_PARAMETER_VALUE' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + REGION
                + "/ssm/parameter/" + EXACT_SEGMENT + "$')"
                + " OR (" + alias + ".content_type = 'AWS_S3_OBJECT_CONTENT' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + REGION
                + "/s3/(object|prefix)/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/" + EXACT_SEGMENT + "$')"
                + ")))";
    }
}
