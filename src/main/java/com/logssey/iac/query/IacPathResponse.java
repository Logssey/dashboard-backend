package com.logssey.iac.query;

import java.time.OffsetDateTime;

import tools.jackson.databind.JsonNode;

/** hops 는 [{kind, id, name}] (인터넷부터 데이터까지). */
public record IacPathResponse(long pathId, String status, int tier, String severity, int length, JsonNode hops,
                              Target target, OffsetDateTime firstSeenAt, OffsetDateTime lastSeenAt) {

    public record Target(String arn, String kind) {
    }
}
