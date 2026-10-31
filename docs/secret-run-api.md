# Secret 수동 실행 API (MVP)

새 스캔은 `POST /api/v1/secrets/runs`로 작업만 등록한다. API 요청과 서버 시작 과정은 원천 콘텐츠를 읽거나 탐지 도구를 실행하지 않는다. 별도 Java 워커가 `secret_jobs`에서 작업을 선점하고 결과를 저장한다.

```http
POST /api/v1/secrets/runs
Content-Type: application/json

{"connectionId": 1, "idempotencyKey": "manual-request-1"}
```

`connectionId`는 이미 등록된 ACTIVE GitHub 연결이나 지원되는 승인 범위를 가진 ACTIVE AWS 연결이어야 한다. AWS 범위는 IAM 접근 키·Secrets Manager/SSM/S3 목록 메타데이터와 정확히 승인된 Secret·Parameter·S3 객체 현재 값이며, 실행하려면 별도 워커의 AWS 수집 옵션을 켜야 한다. 지원되지 않는 공급자·범위는 409로 거부한다. 요청은 원천 URL, 자격 증명, 범위를 받지 않는다. 등록 시 `enabled=true`인 승인 범위만 `secret_run_scopes`에 복사하며, 연결의 `scope_version`을 실행에 기록한다. 승인 범위가 없거나 연결이 중지되면 409, 연결이 없으면 404다. 등록은 정기 검사 `next_due_at`을 바꾸지 않는다.

성공 응답은 `202 Accepted`, `Location: /api/v1/secrets/runs/{runId}`, `{ "runId": 1, "status": "PENDING" }`이다. 동일 사용자의 동일 `idempotencyKey` 재요청은 완료 후에도 처음 실행 ID를 반환한다. 키는 사용자 ID와 함께 해시해 저장하며 원문을 DB에 남기지 않는다. 같은 키를 다른 연결에 재사용하거나 이미 진행 중인 연결에 **다른 새 키**로 요청하면 409를 반환한다. 키를 생략하고 진행 중인 연결을 다시 요청하면 기존 실행 ID를 반환한다. 동시 요청은 DB 연결 행 잠금과 멱등 키 잠금으로 한 작업만 예약한다.

`GET /api/v1/secrets/runs/{runId}`는 전체 `status`, 수집·탐지·검증 단계 상태, 승인 범위 수와 완료·불완전 범위 수, 수집 객체 수, 시도 횟수, 요청·시작·종료 시각 및 허용된 실패 코드만 반환한다. `scopeResults`에는 각 범위의 `runScopeId`, `contentType`, AWS 리전(해당 시), `collectionStatus`, `objectCount`, 고정된 `gapCode`가 들어간다. 작업의 `LEASED`는 화면 상태 `RUNNING`, 정상 종료의 `PARTIAL`은 그대로 `PARTIAL`로 표시한다. 연결의 `auth_ref`, 승인 범위의 `approved_ref`, AWS 계정 ID·리소스명·ARN, 키 원문과 임의 공급자 오류는 응답하지 않는다.

현재 별도의 `secret_role_grants`와 연결별 소유권 모델은 아직 없어서, POST/GET 모두 기존 `dashboard_users`에 실제 등록된 `ADMIN` 계정에만 허용한다. 이 임시 제한은 Secret 역할과 연결 범위 권한을 구현할 때 교체해야 한다. 기존 `/api/v1/credentials` 조회와 동기 `/api/v1/credentials/scan`은 화면 전환 기간의 호환 경로이며 새 화면은 이 실행 API를 사용한다. POST는 기존 세션 인증과 CSRF 헤더를 요구한다.
