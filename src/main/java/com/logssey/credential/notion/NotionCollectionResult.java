package com.logssey.credential.notion;

import java.util.List;

import com.logssey.credential.CollectedCredential;

/**
 * 한 번의 수집 결과. 위험 등급은 들어 있지 않다 (목록 정보는 등급의 근거가 아님).
 * 실패해도 기존에 저장한 목록은 지우지 않는다. 이 규칙은 DB 저장 단계에서 지킨다.
 *
 * @param success     수집 성공 여부
 * @param credentials 수집한 키. 실패하면 비어 있다
 * @param failure     실패 이유. 성공하면 null
 */
public record NotionCollectionResult(
        boolean success,
        List<CollectedCredential> credentials,
        CollectionFailure failure) {

    public NotionCollectionResult {
        credentials = List.copyOf(credentials);
    }

    static NotionCollectionResult succeeded(List<CollectedCredential> credentials) {
        return new NotionCollectionResult(true, credentials, null);
    }

    static NotionCollectionResult failed(CollectionFailure failure) {
        return new NotionCollectionResult(false, List.of(), failure);
    }
}
