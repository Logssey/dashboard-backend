package com.logssey.credential.risk;

/** 키 하나에서 찾은 위험 한 건. 나중에 detection_events(domain = SECRETS)로 저장한다 */
public record TokenRiskFinding(String issuer, String externalId, RiskType type, Severity severity) {
}
