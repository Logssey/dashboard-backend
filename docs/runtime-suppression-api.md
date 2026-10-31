# Runtime 탐지 예외 정책

Runtime 예외는 탐지 규칙을 수정하거나 이벤트를 삭제하지 않는다. 승인된 정상 행위와
정확히 일치하는 이벤트만 Finding 생성에서 제외하며, 원본 이벤트와 정규화 이벤트에는
`SUPPRESSED` 상태와 적용된 `suppressionId`를 남긴다.

## 안전 조건

- 예외는 클러스터와 규칙을 반드시 지정한다.
- Namespace, Workload, 실행 파일, 대상 경로 중 하나 이상의 구체적인 범위가 필요하다.
- 와일드카드 대신 정확한 값과 대상 경로 prefix만 사용한다.
- `TICKET:` 또는 `CHANGE:` 근거와 10자 이상의 설명이 필요하다.
- 만료 기간은 최대 30일이며 자동으로 연장되지 않는다.
- 생성 요청은 사용자별 멱등키와 요청 digest로 보호한다.
- 취소는 현재 version을 요구하며 작성자와 시각, 취소 사유를 보존한다.

현재 대시보드 계정 모델에 맞춰 ADMIN만 관리할 수 있다. 역할 모델이 확장되면
별도의 Runtime Security 관리자와 승인자 분리를 적용한다.

## API

```text
GET  /api/v1/runtime/suppressions?activeOnly=true
POST /api/v1/runtime/suppressions
POST /api/v1/runtime/suppressions/{suppressionId}/revoke
```

생성 요청 예시:

```json
{
  "ruleKey": "RUN-003",
  "clusterId": "logssey-prod",
  "namespace": "reused",
  "workloadName": "reused-api",
  "processExecutable": "/app/reused-api",
  "targetNamePrefix": "/var/run/secrets/kubernetes.io/serviceaccount/",
  "operation": "OPEN",
  "reasonCode": "APPROVED_OPERATION",
  "evidenceRef": "CHANGE:RUNTIME-100",
  "comment": "승인된 Kubernetes API 인증 동작",
  "expiresAt": "2026-11-03T00:00:00Z",
  "idempotencyKey": "runtime-suppression-20261027-001"
}
```

취소 요청 예시:

```json
{
  "version": 1,
  "reason": "승인된 작업 기간이 종료되어 예외를 취소함"
}
```

대시보드 Overview의 `summary.suppressedEventCount`로 조회 기간 내 억제된 이벤트 수를
확인할 수 있다. 이 값이 갑자기 증가하면 정상 행위 증가인지 과도하게 넓은 예외인지
검토해야 한다.

## 수집 폭주 방어

- 단일 이벤트 본문은 기본 256 KiB를 넘을 수 없다.
- 기본적으로 `클러스터 + 노드 + 규칙`마다 분당 300건까지 정규화한다.
- 분당 윈도우는 PostgreSQL에서 원자적으로 증가하므로 백엔드가 여러 대여도 한도가 같다.
- 한도 초과 원본은 삭제하지 않고 `RATE_LIMITED` 상태로 저장하며 Finding으로 만들지 않는다.
- Overview의 `summary.rateLimitedEventCount`와 `runtime_ingest_rate_windows` 집계로 폭주 여부를 확인한다.

환경별 조정 값:

```text
RUNTIME_MAX_PAYLOAD_BYTES=262144
RUNTIME_MAX_EVENTS_PER_RULE_NODE_MINUTE=300
```
