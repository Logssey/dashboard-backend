package com.logssey.iac.query;

/** S-01 G 제안 조치. source 는 ①(경로)·③(State). pathsCut 은 이 조치로 닫히는 열린 경로 수. */
public record IacRemediationResponse(String action, String source, long pathsCut, long tier1PathsCut,
                                     String templateKey) {
}
