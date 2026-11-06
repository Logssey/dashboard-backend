package com.logssey.secretworker.notion;

import com.logssey.secret.notion.NotionScopeSql;
import java.util.Locale;

/** One explicitly approved page at its current version. */
public record NotionApprovedScope(String pageId) {
  public static final String CONTENT_TYPE = NotionScopeSql.CONTENT_TYPE;
  public static final String HISTORY_LIMIT = NotionScopeSql.HISTORY_LIMIT;
  public static final String APPROVED_REF_SQL_PATTERN = NotionScopeSql.REFERENCE_PATTERN;

  public NotionApprovedScope {
    pageId = canonicalId(pageId);
  }

  public static NotionApprovedScope fromApprovedRef(String reference, String historyLimit) {
    if (!HISTORY_LIMIT.equals(historyLimit)
        || reference == null
        || !reference.matches(APPROVED_REF_SQL_PATTERN)) {
      throw new IllegalArgumentException("INVALID_NOTION_SCOPE");
    }
    return new NotionApprovedScope(reference.substring("notion://pages/".length()));
  }

  public static String canonicalId(String value) {
    if (value == null
        || !value.matches(
            "[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
      throw new IllegalArgumentException("INVALID_NOTION_ID");
    }
    String hex = value.replace("-", "").toLowerCase(Locale.ROOT);
    return hex.substring(0, 8)
        + "-"
        + hex.substring(8, 12)
        + "-"
        + hex.substring(12, 16)
        + "-"
        + hex.substring(16, 20)
        + "-"
        + hex.substring(20);
  }

  public String sourceObjectRef() {
    return "notion/pages/" + pageId;
  }
}
