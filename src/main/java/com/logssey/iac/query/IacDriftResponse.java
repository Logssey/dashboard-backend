package com.logssey.iac.query;

import java.time.OffsetDateTime;
import java.util.List;

/** S-01 F 드리프트 한 건. 바뀐 속성 이름만 있고 값은 없다 (SR-4). */
public record IacDriftResponse(long findingId, String ruleId, String enforcement, String severity, String address,
                               String action, List<String> attributes, String status, Long assigneeUserId,
                               long version, OffsetDateTime firstSeenAt, OffsetDateTime lastSeenAt) {
}
