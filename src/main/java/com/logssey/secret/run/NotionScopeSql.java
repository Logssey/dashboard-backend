package com.logssey.secret.run;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Fixed SQL predicate and parser for executable Notion scopes: exactly one page at its current
 * version. Kept in sync with the worker's NotionApprovedScope. The alias is never user input.
 */
public final class NotionScopeSql {
    public static final String CONTENT_TYPE = "NOTION_PAGE_CONTENT";
    public static final String HISTORY_LIMIT = "CURRENT_VERSION_ONLY";
    static final String APPROVED_REF_PATTERN =
            "^notion://pages/([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$";
    private static final Pattern APPROVED_REF = Pattern.compile(APPROVED_REF_PATTERN);

    private NotionScopeSql() { }

    public static String predicate(String alias) {
        if (!"s".equals(alias) && !"unsupported".equals(alias)) {
            throw new IllegalArgumentException("Invalid scope SQL alias");
        }
        return "(" + alias + ".content_type = '" + CONTENT_TYPE + "' AND " + alias
                + ".history_limit = '" + HISTORY_LIMIT + "' AND " + alias
                + ".approved_ref ~ '" + APPROVED_REF_PATTERN + "')";
    }

    public static boolean approved(String contentType, String historyLimit, String approvedRef) {
        return CONTENT_TYPE.equals(contentType) && HISTORY_LIMIT.equals(historyLimit)
                && approvedRef != null && APPROVED_REF.matcher(approvedRef).matches();
    }

    /** The 32 lowercase hex digits of an approved page reference, or null. */
    public static String pageId(String approvedRef) {
        if (approvedRef == null) return null;
        var match = APPROVED_REF.matcher(approvedRef);
        return match.matches() ? match.group(1).replace("-", "").toLowerCase(Locale.ROOT) : null;
    }
}
