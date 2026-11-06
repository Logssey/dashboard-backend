package com.logssey.secret.notion;

import java.util.Locale;

/** Fixed page coordinates shared by approved-source API checks and the worker. */
public final class NotionScopeSql {
    public static final String CONTENT_TYPE = "NOTION_PAGE_CONTENT";
    public static final String HISTORY_LIMIT = "CURRENT_VERSION_ONLY";
    public static final String PAGE_ID = "(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
    public static final String REFERENCE_PATTERN = "^notion://pages/" + PAGE_ID + "$";

    private NotionScopeSql() { }

    public static boolean valid(String contentType, String reference, String historyLimit) {
        return CONTENT_TYPE.equals(contentType) && HISTORY_LIMIT.equals(historyLimit)
                && reference != null && reference.matches(REFERENCE_PATTERN);
    }

    public static String pageId(String reference) {
        if (reference == null || !reference.matches(REFERENCE_PATTERN))
            throw new IllegalArgumentException("INVALID_NOTION_SCOPE");
        String id = reference.substring("notion://pages/".length()).replace("-", "")
                .toLowerCase(Locale.ROOT);
        return id.substring(0, 8) + "-" + id.substring(8, 12) + "-" + id.substring(12, 16)
                + "-" + id.substring(16, 20) + "-" + id.substring(20);
    }

    public static String predicate(String alias) {
        if (!"s".equals(alias) && !"unsupported".equals(alias))
            throw new IllegalArgumentException("INVALID_SCOPE_SQL_ALIAS");
        return "(" + alias + ".content_type='" + CONTENT_TYPE + "' AND " + alias
                + ".history_limit='" + HISTORY_LIMIT + "' AND " + alias + ".approved_ref ~ '"
                + REFERENCE_PATTERN + "')";
    }
}
