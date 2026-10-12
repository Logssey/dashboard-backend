package com.logssey.credential.notion;

import java.util.List;

import com.logssey.credential.CollectedCredential;
import com.logssey.credential.risk.TokenRiskFinding;

/**
 * 한 번의 수집 결과.
 * 실패해도 기존에 저장한 목록은 지우지 않는다. 이 규칙은 DB 저장 단계(credentials 테이블 확정 후)에서 지킨다.
 *
 * @param success     수집 성공 여부
 * @param credentials 수집한 키. 실패하면 비어 있다
 * @param findings    위험 판단 결과
 * @param failure     실패 이유. 성공하면 null
 */
public record NotionCollectionResult(
        boolean success,
        List<CollectedCredential> credentials,
        List<TokenRiskFinding> findings,
        CollectionFailure failure) {

    public NotionCollectionResult {
        credentials = List.copyOf(credentials);
        findings = List.copyOf(findings);
    }

    static NotionCollectionResult succeeded(List<CollectedCredential> credentials, List<TokenRiskFinding> findings) {
        return new NotionCollectionResult(true, credentials, findings, null);
    }

    static NotionCollectionResult failed(CollectionFailure failure) {
        return new NotionCollectionResult(false, List.of(), List.of(), failure);
    }
}
