package com.logssey.iacworker.analysis;

import java.util.List;

/** IAM 정책 시뮬레이터. 돌려주는 값은 EvalDecision 그대로 (allowed, explicitDeny, implicitDeny). */
public interface IamSimulator {
    String decide(List<String> policyDocuments, String action, String resourceArn);
}
