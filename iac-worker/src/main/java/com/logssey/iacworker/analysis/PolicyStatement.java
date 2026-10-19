package com.logssey.iacworker.analysis;

import java.util.List;

/** Cartography AWSPolicyStatement 와 같은 모양. 조건은 원문 JSON 그대로 둔다. */
public record PolicyStatement(String effect, List<String> actions, List<String> notActions,
                              List<String> resources, List<String> notResources, String condition) {
}
