# Runtime rule pack

런타임 규칙의 기준 원본은 `src/main/resources/runtime/rules/runtime-rule-pack-v1.yaml`이다.
룰팩은 애플리케이션 시작 시 안전한 YAML 파서로 읽고, 중복 규칙 키·중복 센서 매핑·잘못된
상태 조합을 검증한다. 현재 pack version은 `1.0.0`이며 RUN-001부터 RUN-024까지 24개
규칙을 포함한다.

## 운영 상태

| Mode | 개수 | 저장 동작 |
|---|---:|---|
| `DETECT` | 12 | 이벤트를 저장하고 동일 행위를 Finding으로 그룹화한다. |
| `OBSERVE` | 6 | 이벤트 증거만 저장하며 Finding과 알림을 만들지 않는다. |
| `DRAFT` | 6 | 카탈로그에는 노출하지만 센서 source rule과 연결하지 않는다. |

`OBSERVE`는 정상 행위 기준선과 오탐률을 확인하기 위한 단계다. 운영 데이터와 예외 정책이
충분히 쌓인 뒤 별도 변경으로 `DETECT` 승격 여부를 결정한다. `DRAFT`는 필요한 센서와
Context가 준비되기 전까지 수집 경로에 진입할 수 없다.

## 이벤트 양 제어

각 규칙은 `noiseBudgetPerMinute`를 가진다. 수집 시 전역 상한과 규칙별 예산 중 더 작은 값을
노드·규칙 단위 분당 한도로 사용한다. 한도를 넘은 원본은 `RATE_LIMITED`로 기록되며 운영
화면에서 별도 집계한다.

## 조회 API

로그인 사용자는 `GET /api/v1/runtime/rules`에서 pack version과 전체 규칙의 mode, maturity,
센서, MITRE technique, 이벤트 예산, 담당 조직을 조회할 수 있다. 운영 Overview는
`observedEventCount`를 별도 제공해 Finding 수와 관찰 이벤트 양을 혼동하지 않게 한다.

## 변경 절차

1. YAML 룰팩의 규칙과 source rule 매핑을 변경한다.
2. 동일 내용을 새 Flyway migration으로 스냅샷한다. 이미 배포된 migration은 수정하지 않는다.
3. Falco/Tetragon 규칙 파일과 source rule 이름을 일치시킨다.
4. 룰팩 단위 테스트, 정규화 테스트, DB migration, 센서 규칙 검증을 모두 통과시킨다.
5. `OBSERVE`에서 수집량·오탐·업무 영향을 확인한 뒤 `DETECT` 승격을 별도 리뷰한다.

자동 차단은 이 룰팩의 범위가 아니다. `DETECT`도 탐지와 Finding 생성을 의미하며,
response action은 별도 승인·감사 설계가 완료되기 전까지 비활성 상태를 유지한다.
