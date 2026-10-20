package com.logssey.iac.finding;

public record FindingResponse(long findingId, String status, Long assigneeUserId, long version) {
}
