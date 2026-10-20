package com.logssey.secret.connection;

/** Human-provided labels never fall back to collected paths or authentication references. */
public final class SecretDisplayLabels {
    private SecretDisplayLabels() { }
    private static final java.util.regex.Pattern CREDENTIAL_LIKE=java.util.regex.Pattern.compile(
        "AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|(?:secret_|ntn_)[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{24,}|[0-9]{10,}");
    public static boolean safeAlias(String alias) {
        return alias==null||alias.matches("[A-Za-z가-힣][A-Za-z0-9가-힣 _-]{0,79}")&&!CREDENTIAL_LIKE.matcher(alias).find();
    }
    public static String location(String alias,long occurrenceId) {
        return (alias!=null&&safeAlias(alias)?alias+" · ":"")+"위치 #"+occurrenceId;
    }
}
