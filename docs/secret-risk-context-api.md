# Secret 권한·자산 근거 조회

심각도 정책은 기존 `severity-v2`를 사용한다. 이 API는 기존 근거와 적용 규칙을 설명하며, 공급자 권한을 새로 조회하거나 룰·정책·등급을 변경하지 않는다. 인증 성공과 자산 연결만으로 실제 접근 권한을 확정하지 않는다.

## 위치별 근거

`GET /api/v1/secrets/occurrences/{id}/risk`는 기존 응답에 `analysisContext`를 제공한다.

| 필드 | 의미 |
|---|---|
| `occurrenceId`, `evidenceRevision`, `profileVersion`, `readAt` | 선택 위치·근거 revision·`risk-context-v1`·현재 조회 시각 |
| `source` | 수집 원천·발급자·자격 증명 유형. 원천과 키 발급자를 구분 |
| `access` | 입증된 읽기 범위·관측 시각·수용 수준·근거 ID. 불충분한 범위 주장을 확정 범위의 근거로 표시하지 않음 |
| `permissions` | 적격한 수용 근거의 기능 코드·대상 단위·조회 완전성·수용 수준·매핑 버전·한계 |
| `asset` | 등록 자산의 안전한 별칭·환경·수용된 분류. 연결과 분류·권한 증명을 구분 |
| `explanation` | 기존 자동 평가의 정책·규칙·입력과 부족 사유. 현재 근거와 과거 평가의 시점을 구분 |
| `limitations` | 자동 권한 분석 미지원, 수동 자산 연결·인증 성공의 해석 한계 |

만료·미수용·다른 위치·부모 참조 불일치 근거는 확인된 권한이나 분류로 승격하지 않는다. 조회는 대상 위치 권한을 재검사하고 평가 이력을 추가하지 않는다. 원문 키·원시 정책·인증 헤더는 응답에 포함하지 않는다.

## 등록 자산 선택

`GET /api/v1/secrets/occurrences/{id}/risk-assets?page=0&size=20`

- 응답: `occurrenceId,evidenceRevision,items,total,page,size,capabilities,limitations`.
- `items`: `assetId,label,provider,assetType,environment`. 자격 증명처럼 보이는 표시명은 안전한 별칭으로 대체한다.
- 전역 SECURITY는 해당 발급자에 맞는 자산 목록과 `canLinkAsset=true`를 받는다.
- 연결 범위 SECURITY·조치 담당자는 기존에 연결된 자산의 허용 정보만 조회하며 다른 자산 목록이나 연결 권한을 얻지 않는다.
- 메타데이터 항목은 새 자산 연결 대상이 아니다. 페이지 크기는 최대 100이다.

기존 `POST /api/v1/secrets/occurrences/{id}/risk-evidence`의 `ASSET_CLASSIFICATION` 제출에 선택적인 `assetId`를 포함할 수 있다. 기존 필수 근거·시각·`expectedEvidenceRevision`·멱등 키·CSRF·권한 검사는 유지한다. 서버가 해당 자산 부모 참조를 추가하므로 클라이언트는 이전 자산 참조를 같이 보내지 않는다.

자산 변경은 전역 SECURITY만 수행한다. 자산 발급자·분류 환경·메타데이터 제외 조건과 참조 적격성을 검사한다. 같은 트랜잭션에서 자산 연결, 이전 분류·권한 근거의 추가 전용 철회, 새 분류 기록, 감사와 재평가 예약을 수행한다. 검증 실패는 전체 롤백한다. 기존 확정 높은 등급은 기존 HOLD·독립 교정 원칙에 따라 보존한다. 자산 선택 자체는 공급자 권한 증명이 아니다.

`assetId`가 없는 기존 요청의 계약·멱등 본문은 유지한다. 권한을 철회한 후의 같은 명령 재시도도 현재 권한 검사를 우회하지 못한다.
