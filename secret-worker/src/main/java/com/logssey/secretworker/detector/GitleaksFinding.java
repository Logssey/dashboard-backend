package com.logssey.secretworker.detector;

/** Location and rule evidence only. The original object remains in worker memory. */
public record GitleaksFinding(String ruleId, int startLine, int endLine, int startColumn, int endColumn) {
}
