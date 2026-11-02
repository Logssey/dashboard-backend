package com.logssey.secretworker.notion;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * One explicitly approved Notion page, read at its current version only. Child pages, databases,
 * attachments and images are outside the scope and are never followed.
 *
 * <p>approved_ref: {@code notion://pages/<page id>} (32 hex digits, with or without hyphens).
 */
public record NotionApprovedScope(String pageId) {
    public static final String CONTENT_TYPE = "NOTION_PAGE_CONTENT";
    public static final String HISTORY_LIMIT = "CURRENT_VERSION_ONLY";
    /** Kept in sync with the scheduler's SQL guard. */
    public static final String APPROVED_REF_SQL_PATTERN =
            "^notion://pages/([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$";
    private static final Pattern PAGE_ID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    public NotionApprovedScope {
        if (pageId == null || !PAGE_ID.matcher(pageId).matches()) {
            throw new IllegalArgumentException("Invalid Notion page id");
        }
    }

    public static NotionApprovedScope fromApprovedRef(String approvedRef, String historyLimit) {
        if (!HISTORY_LIMIT.equals(historyLimit)) {
            throw new IllegalArgumentException("Unsupported Notion history range");
        }
        if (approvedRef == null || !approvedRef.matches(APPROVED_REF_SQL_PATTERN)) {
            throw new IllegalArgumentException("Invalid Notion approved_ref");
        }
        URI uri = URI.create(approvedRef);
        if (!"notion".equals(uri.getScheme()) || !"pages".equals(uri.getHost())
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Invalid Notion approved_ref");
        }
        String raw = uri.getPath().substring(1).replace("-", "").toLowerCase(Locale.ROOT);
        return new NotionApprovedScope(raw.substring(0, 8) + "-" + raw.substring(8, 12) + "-"
                + raw.substring(12, 16) + "-" + raw.substring(16, 20) + "-" + raw.substring(20));
    }

    /** Stable source object reference stored with findings. Contains no title or URL. */
    public String sourceObjectRef() {
        return "notion/pages/" + pageId;
    }
}
