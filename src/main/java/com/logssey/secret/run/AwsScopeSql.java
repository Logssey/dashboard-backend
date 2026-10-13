package com.logssey.secret.run;

/** Fixed SQL predicate for executable AWS scopes. The alias is never user input. */
public final class AwsScopeSql {
    private static final String REGION = "[a-z]{2}(-[a-z0-9]+){1,3}-[0-9]+";

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
                + "))";
    }
}
