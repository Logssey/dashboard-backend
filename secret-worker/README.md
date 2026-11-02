# Secret 작업 예약 워커

작업 예약, DB 기반 실행 관리, 승인된 GitHub 파일·AWS 메타데이터/정확한 값의 수집·탐지·정규화, 지원 유형의 유효성 확인과 조치 후 위치 재검사를 제공한다. 원천별 수집과 외부 검증은 각각 명시적인 활성화·승인 설정이 필요하다.

Java 21 / Spring Boot를 사용하는 별도 프로세스다. 대시보드 API에는 워커 의존성이나 스케줄러를 넣지 않았다. 기준은 Secret ADR-S002, ADR-S008과 `database-schema.md`다.

운영 이미지는 저장소 루트 `Dockerfile --target worker`로 빌드한다. API·워커 분리, 파일 기반 비밀 공급, AWS 임시 역할, Flyway 적용과 운영 점검은 [배포·운영 절차](../docs/secret-deployment.md)를 따른다. 기존 개인 프로필은 개발 모드에 남기고 운영에서는 명시적인 `WORKLOAD` 모드를 사용한다.

## 동작

- 기본 30초마다 DB의 현재 시각으로 도래한 연결을 확인한다. 기본 검사 주기는 6시간이다.
- `ACTIVE` GitHub·AWS 연결에 예정 시각과 지원되는 활성 승인 범위가 있어야 예약한다. 미지원 공급자와 `PAUSED`, `ERROR`, 미승인 범위는 건너뛴다.
- 연결 행을 `FOR UPDATE SKIP LOCKED`로 잠그고, 작업·검사 실행·승인 범위 스냅샷·다음 예정 시각을 한 트랜잭션에서 저장한다.
- 같은 연결의 `FULL_SCAN` 작업이 `PENDING` 또는 `LEASED`이면 새 작업을 만들지 않는다. 여러 프로세스와 반복 호출의 중복도 DB 고유 제약으로 막는다.
- 다음 시각은 **실제 정기 예약 시각 + 6시간**이다. 수동 요청·실패·마지막 성공이 정기 시각을 바꾸지 않는다.
- 장시간 중단 후에는 놓친 슬롯을 한 번 예약하고 과거 슬롯을 연속 재생하지 않는다.
- 예약은 실행 성공을 뜻하지 않는다. 시작·종료·마지막 수집 성공·수집 건수는 채우지 않는다.

## 작업 실행 계약

- `SECRET_JOB_EXECUTOR_ENABLED=true`이고 `SecretJobProcessor` 빈이 있을 때만 예약된 작업을 소비한다. 처리기가 없으면 활성화 설정만으로 작업을 선점하지 않는다.
- DB의 도래한 `PENDING` 작업을 `FOR UPDATE SKIP LOCKED`로 선점한다. 매 시도에 새로운 리스 토큰을 발급하고 `attempt_no`를 올린다. 한 번에 작업을 하나씩 선점한 뒤 처리해 대기 중 리스 만료를 피한다.
- 처리기는 네트워크 호출 전에 승인 범위 스냅샷을 읽고, 오래 걸리는 작업에서는 `renewLease`로 리스를 갱신한다. 실행 중 DB 결과 저장은 `persistIfLeased(jobId, leaseToken, ...)` 안에서 수행한다. 이 콜백에는 짧은 DB 쓰기만 넣고 네트워크 호출을 넣지 않는다. 만료되거나 교체된 리스의 쓰기·갱신·완료·실패 보고는 거부된다.
- 처리기가 반환되어도 수집·탐지·검증 단계와 예약된 모든 범위가 완결되지 않으면 성공 종료를 허용하지 않는다. 수집 범위 중 실패·부분 누락·미지원이 있으면 전체 결과를 `PARTIAL`로 기록하고 정상 0건과 구분한다. 수집이 완전히 성공하고 각 범위의 완료 시각이 있을 때에만 마지막 수집 성공 시각을 가장 늦은 범위 완료 시각으로 갱신한다.
- 일시 실패와 만료된 리스는 지수 백오프 후 같은 실행 ID로 재시도한다. 최대 시도 횟수에 도달하면 작업과 실행을 `FAILED`로 종료한다. 지난 성공 단계와 범위는 보존하고 진행 중·부분 실패·실패 단계는 다시 대기시킨다.
- 실패 코드는 `SecretJobFailureCode`에 정의된 값만 저장한다. 공급자 응답 본문, 예외 메시지와 원문은 DB 또는 로그에 기록하지 않는다. 처리기는 결과 저장의 멱등성도 보장해야 한다.

GitHub `SecretJobProcessor`는 `GITHUB` 연결의 승인된 현재 커밋만 처리한다. API 프로세스는 실행 서비스를 호출하지 않는다. 실행 프로세스에서 `SECRET_GITHUB_PIPELINE_ENABLED=true`와 `SECRET_JOB_EXECUTOR_ENABLED=true`를 함께 설정해야 수집을 시작한다. AWS 연결은 별도의 AWS 처리기가 지원하는 메타데이터/정확한 값 범위만 처리한다.

## GitHub 수집·탐지 실행

읽기 전용 GitHub App의 `SECRET_GITHUB_APP_ID`, `SECRET_GITHUB_INSTALLATION_ID`, `SECRET_GITHUB_PRIVATE_KEY_PATH`와 Gitleaks 8.30.1 실행 파일 경로 `SECRET_GITLEAKS_PATH`를 워커 환경에 지정한다. 정규화용 HMAC 키는 32바이트 이상을 base64로 인코딩해 `SECRET_FINGERPRINT_KEY_BASE64`에, 키 버전은 `SECRET_FINGERPRINT_KEY_VERSION`에 지정한다. 실제 값은 Git이나 DB에 넣지 않는다.

처리기는 `github://owner/repository/branch/path/` 형식의 승인된 범위와 `CURRENT_COMMIT_ONLY`만 수집한다. 파일 크기·총 바이트·트리 깊이 제한을 넘기거나 원천 요청이 실패하면 해당 범위를 `PARTIAL` 또는 `FAILED`로 기록한다. 파일 바이트는 메모리에서 Gitleaks `stdin`으로 넘겨 즉시 정규화하고, DB에는 키의 HMAC과 마스킹 라벨, 발견 위치·규칙만 저장한다. 같은 실행에서 동일한 완전 AWS 키는 한 번만 검증하고, 파일별 발견 위치는 모두 보존한다. 검증 호출은 DB 트랜잭션 밖에서 수행한다.

```powershell
.\gradlew.bat :secret-worker:bootJar
java -jar .\secret-worker\build\libs\secret-worker-0.0.1-SNAPSHOT.jar --logssey.secret.scheduler.enabled=false --logssey.secret.executor.enabled=true --logssey.secret.github.enabled=true
```

`Logssey/test-find-key`의 승인된 `fixtures/` 16개 파일을 실제 GitHub App으로 읽은 로컬 검증에서 작업은 `SUCCEEDED`로 종료됐고, 7개 완전 키·2개 불완전 후보·15개 발견 위치가 저장됐다. 합성 원문 28개 긴 토큰이 DB 덤프와 워커 로그에 없는 것도 확인했다.

## Notion 페이지 수집·탐지 실행

읽기 전용 Notion 연결(콘텐츠 읽기 권한만)의 토큰을 파일로 두고 `SECRET_NOTION_TOKEN_PATH`에 경로를 지정한다. 토큰 값은 Git, DB, 로그에 넣지 않는다. `SECRET_NOTION_PIPELINE_ENABLED=true`와 `SECRET_JOB_EXECUTOR_ENABLED=true`를 함께 설정해야 수집을 시작하며, Gitleaks 경로와 지문 키는 GitHub과 같은 설정을 쓴다.

- 범위 하나는 승인된 페이지 하나다: `content_type='NOTION_PAGE_CONTENT'`, `approved_ref='notion://pages/<페이지 ID 32자리>'`, `history_limit='CURRENT_VERSION_ONLY'`. 하위 페이지, 데이터베이스, 첨부 파일, 이미지는 읽지 않는다. 예시는 `local/register-notion-test-schedule.sql`.
- 호출은 고정 호스트 `api.notion.com`의 `GET /v1/pages/{id}`(버전·휴지통·웹 게시 여부)와 `GET /v1/pages/{id}/markdown` 두 가지뿐이다. 페이지 본문은 메모리에서 Gitleaks `stdin`으로 넘기고, DB에는 GitHub과 같이 HMAC, 마스킹 라벨, 위치, 규칙만 저장한다. 발견 위치는 `notion/pages/<id>`, 객체 버전은 `last_edited_time`이다.
- 공유되지 않은 페이지(404), 권한 오류(401/403), 휴지통 페이지는 정상 0건이 아니라 `FAILED`와 `NOTION_*` 코드로 기록한다. 본문이 잘렸거나(`truncated`, `unknown_block_ids`) 탐지기가 찾은 위치를 정규화기가 키로 연결하지 못하면 `PARTIAL`과 `NOTION_CONTENT_TRUNCATED`/`NOTION_UNATTRIBUTED_FINDINGS`로 남긴다. 공용 정규화기는 `NAME=value` 형태만 키로 인정하므로, "노션 토큰: ntn_..."처럼 한글 문장이나 표에 적힌 키는 지금 이 코드로만 드러난다.
- 페이지가 웹에 게시돼 있으면(`public_url` 존재) 위치마다 `ACCESS_SCOPE` 근거를 `BROAD`(`PUBLISHED_TO_WEB_CONFIRMED`)로 저장한다. 게시되지 않은 페이지는 워크스페이스 안에서 누가 읽는지 증명하지 못하므로 `UNKNOWN`으로 둔다.
- 발견한 Notion 토큰은 `SECRET_NOTION_VALIDATION_ENABLED=true`일 때만 `NotionTokenValidator`가 고정 엔드포인트 `GET https://api.notion.com/v1/users/me`로 확인한다(`NOTION_GET_SELF`/`NOTION_SELF`). 200은 `VALID/AUTHENTICATED`, Notion의 `unauthorized` 401만 `INVALID/AUTHENTICATION_REJECTED`, 403·404는 `UNKNOWN/ACCESS_LIMITED`, 429·5xx·시간 초과는 재시도 가능한 `UNKNOWN`이다. 만료·폐기는 추측하지 않는다. 페이지 안의 AWS 키·GitHub 토큰은 기존 검증기 설정을 그대로 따른다.
- 조치 후 수동 재검증(`REVALIDATE`)과 API의 수동 실행·연결 관리 화면은 아직 Notion을 지원하지 않는다.

## AWS 키 검증 어댑터

`AwsCredentialValidator`는 메모리의 완전한 AWS access key ID·secret access key 쌍만 AWS STS `GetCallerIdentity`로 확인한다. `ASIA` 임시 키에는 session token도 필요하다. 호출은 발견한 키로 직접 서명하며 워커의 AWS 프로필이나 기본 자격 증명을 사용하지 않는다. STS 대상은 `us-east-1`의 공식 HTTPS 엔드포인트로 고정했다. 리소스 권한·실제 사용 여부는 이 결과로 판단하지 않는다.

`SECRET_AWS_VALIDATION_ENABLED`는 기본 `false`다. 비활성 또는 불완전한 쌍은 `UNCHECKED`로, 명확한 키 ID 부재·세션 만료는 `INVALID`로, 서명 불일치·권한 오류·호출 제한·네트워크 오류는 `UNKNOWN`으로 반환한다. 결과에는 안전한 사유 코드, 검사 시각, 방법과 버전만 담는다. 원문 자격 증명, 공급자 오류 본문과 예외 메시지는 결과나 로그에 넣지 않는다. `SECRET_AWS_VALIDATION_ENABLED=true`로 명시적으로 켠 경우에만 GitHub 처리기가 발견한 완전한 AWS 키를 STS에 전달한다. 합성 실험 저장소 `Logssey/test-find-key`는 설정과 관계없이 STS 호출을 차단하고 `UNCHECKED/SYNTHETIC_FIXTURE`로 기록한다. 기본 비활성일 때는 `UNCHECKED/DISABLED`로 기록한다. 검증이 불확실하거나 저장에 실패하면 실행의 검증 단계를 `PARTIAL`로 표시하며 발견 위치는 유지한다.

`V3__create_secret_scheduler_tables.sql`은 연결·작업·실행을, V4는 탐지 키·발견 위치·도구 실행을, V5는 안전한 검증 시도 이력을 저장한다. API와 워커는 같은 Flyway 마이그레이션을 패키징한다. 공유된 V1·V2는 변경하지 않았다.

작업 종류는 `FULL_SCAN`, `REVALIDATE`, DB 전용 `ASSESS`다. 수동 전체 검사는 `POST /api/v1/secrets/runs`로 등록하며 실행 상태는 `GET /api/v1/secrets/runs/{runId}`로 조회한다. REVALIDATE의 유효성 확인과 조치 후 위치 재검사는 서로 다른 목적이다. [위치 재검사 지원·해결 경계](../docs/secret-location-recheck.md), [DB 통합 테스트 실행](../docs/secret-integration-tests.md)을 따른다. 위치별 수용 권한·등록 자산·판정 이유는 [v2 권한·자산 근거 API](../docs/secret-risk-context-api.md)로 조회한다.

## 실행

아래 명령은 `dashboard-backend` 디렉터리에서 실행한다. Java 21과 실행 중인 PostgreSQL이 필요하다. 로컬에서는 기존 `.env`의 DB 값을 사용한다. 별도 계정은 `SECRET_DB_URL`, `SECRET_DB_USERNAME`, `SECRET_DB_PASSWORD`로 지정할 수 있다.

```powershell
.\gradlew.bat :secret-worker:bootJar
java -jar .\secret-worker\build\libs\secret-worker-0.0.1-SNAPSHOT.jar --logssey.secret.scheduler.enabled=true --debug=false
```

스케줄러는 기본 비활성이다. 위처럼 명시적으로 활성화하거나 `SECRET_SCHEDULER_ENABLED=true`를 설정한다. 워커를 실행하면 Flyway가 적용되지만 연결이나 대상 저장소는 자동 등록하지 않는다. 기존 API 실행 명령은 그대로다.

로컬 테스트 연결은 마이그레이션이 적용된 뒤 `local/register-test-schedule.sql`을 DB에 한 번 실행해 등록한다. 이 SQL은 재실행해도 기존 일정과 상태를 덮어쓰지 않는다. 수집 대상 참조는 `Logssey/test-find-key`, `main`, `fixtures/`, 현재 커밋만으로 고정한다. 첫 예정 시각은 등록 시점이다.

현재 작업 공간의 Compose 프로젝트를 사용하는 예:

```powershell
Get-Content -Raw .\secret-worker\local\register-test-schedule.sql |
    docker compose -p logssey-solution-dev exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

설정:

- `SECRET_SCHEDULING_POOL_SIZE`: 스케줄러 스레드 수, 기본 `3`. 예약, 외부 작업 실행, DB 전용 `ASSESS` 폴러가 함께 진행하므로 긴 수집 작업이 다른 두 폴러를 막지 않는다. 각 폴러의 반복 실행은 순차적이며 DB 리스·잠금 제약은 그대로 적용된다. [Spring Boot 스케줄러 설정](https://docs.spring.io/spring-boot/4.1/reference/features/task-execution-and-scheduling.html)을 사용하며 가상 스레드를 활성화하면 이 풀 크기 설정은 적용되지 않는다.
- `SECRET_SCHEDULER_POLL_DELAY`: DB 확인 간격, 기본 `30s`.
- `SECRET_SCAN_INTERVAL`: 예약 간격, 기본 `6h`. 테스트에서만 짧게 바꾼다.
- `SECRET_SCHEDULER_BATCH_SIZE`: 한 번에 예약할 연결 수, 기본 `100`.
- `SECRET_JOB_MAX_ATTEMPTS`: 작업 최대 시도 횟수, 기본 `3`.
- `SECRET_JOB_EXECUTOR_ENABLED`: 작업 실행기 활성화 여부, 기본 `false`.
- `SECRET_JOB_POLL_DELAY`: 작업 확인 간격, 기본 `30s`.
- `SECRET_JOB_LEASE_DURATION`: 한 시도의 리스 기간, 기본 `5m`.
- `SECRET_JOB_BATCH_SIZE`: 한 번의 확인에서 처리할 최대 작업 수, 기본 `10`.
- `SECRET_JOB_RETRY_INITIAL_DELAY`: 첫 재시도 대기, 기본 `30s`.
- `SECRET_JOB_RETRY_MAX_DELAY`: 재시도 대기 상한, 기본 `30m`.

확인용 SQL:

```sql
SELECT connection_id, status, next_due_at, last_collection_success_at FROM secret_connections;
SELECT job_id, connection_id, scheduled_at, status, attempt_no FROM secret_jobs ORDER BY job_id;
SELECT run_id, collection_status, result_status, started_at, finished_at FROM secret_scan_runs;
```

운영에서 스키마 적용을 별도 배포 단계로 수행하면 워커는 `spring.flyway.enabled=false`로 실행한다. DB 계정과 자격 증명 보관 위치의 운영 배치는 기존 배포 ADR에서 결정한다.

## 검증

```powershell
.\gradlew.bat :secret-worker:test
```

Docker가 필요하다. Testcontainers의 별도 PostgreSQL 18.6에서 실제 Flyway 마이그레이션과 예약·실행 상태를 검증하며 개발 DB를 초기화하지 않는다. 동시 예약과 선점, 리스 만료 복구, 재시도 상한과 백오프, 오래된 토큰 차단, 완료 조건, 정상 0건과 부분 실패의 차이, 원문성 예외 메시지 차단을 검사한다.

## 발견 키 인증 검증의 운영 등록

모든 기본값은 비활성이다. 외부 인증 호출에는 (1) 공급자 전역 플래그, (2) 연결의 등록 profile 활성화, (3) SECURITY의 현재 scope 승인이 모두 필요하다. 수집 자격 증명으로 발견 키의 인증을 대신하지 않는다. 연결 테스트와 유효성 확인은 별도 작업이다.

배포 담당자는 API와 워커에 같은 `SECRET_AWS_VALIDATION_ENABLED` 값을 공급한다. 수집 실행기·수집원 파이프라인·AWS 본문 읽기는 각각의 별도 설정과 승인이 필요하다. 플래그만 true로 바꿔도 연결이나 scope는 활성화되지 않는다. 승인된 합성 fixture는 모든 설정에서 실제 호출을 생략한다. TEST 표식만으로 합성으로 인정하지 않는다.

연결 profile은 검토된 운영 배포에서 다음 트랜잭션으로 등록한다. `target_id`와 `actor_id`는 현재 승인 연결과 해당 연결 OPERATIONS 사용자 ID로 바꾼다. SQL은 운영 DB 배포 권한으로만 실행하며 일반 대시보드에서 SQL·profile 이름·endpoint·비밀을 입력받지 않는다. 예시는 연결의 키 원문이나 인증 참조를 읽지 않는다.

```sql
DO $$
DECLARE target_id BIGINT := 42; actor_id BIGINT := 7; enable_profile BOOLEAN := true;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM secret_role_grants WHERE user_id=actor_id
      AND role='OPERATIONS' AND revoked_at IS NULL
      AND (connection_id IS NULL OR connection_id=target_id)) THEN
    RAISE EXCEPTION 'VALIDATION_OPERATOR_REQUIRED';
  END IF;
  PERFORM 1 FROM secret_connections WHERE connection_id=target_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'CONNECTION_NOT_FOUND'; END IF;
  UPDATE secret_connections SET validation_enabled=enable_profile,
      validation_profile_version='credential-validation-v1',
      validation_revision=validation_revision+1 WHERE connection_id=target_id;
  UPDATE secret_connection_scopes SET validation_approved=false,
      validation_approval_revision=validation_approval_revision+1
      WHERE connection_id=target_id;
  UPDATE secret_validation_attempts SET current_eligible=false,
      ineligible_reason_code='APPROVAL_CHANGED'
      WHERE job_id IN (SELECT job_id FROM secret_jobs WHERE connection_id=target_id)
        AND current_eligible;
  UPDATE secret_jobs SET status='CANCELLED',last_error_code='APPROVAL_CHANGED',
      finished_at=clock_timestamp() WHERE connection_id=target_id
      AND purpose='CREDENTIAL_VALIDITY' AND status='PENDING';
  INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,
      target_version,safe_changes)
      SELECT 'VALIDATION_PROFILE_CHANGED',actor_id,'CONNECTION',connection_id,
          validation_revision,jsonb_build_object('enabled',enable_profile,
          'profileVersion','credential-validation-v1')
      FROM secret_connections WHERE connection_id=target_id;
END $$;
```

profile 변경은 이전 scope 승인을 철회한다. 이후 해당 범위 SECURITY가 `GET /api/v1/secrets/scopes/{id}/validation-policy`로 현재 revision을 확인한 뒤 `PATCH`에 `{expectedValidationApprovalRevision,idempotencyKey,enabled:true,reasonCode:"VALIDATION_APPROVED"}`를 보낸다. 철회는 `enabled:false`, `reasonCode:"VALIDATION_DISABLED"`다. 키·토큰·URL·헤더 필드는 거부한다. 서버 또는 연결 profile이 꺼진 상태에서는 scope 허용만으로 외부 호출하지 않는다.

상태 조회는 `GET /api/v1/secrets/{id}/validation?occurrenceId=...`이며 실제 요청은 `POST /api/v1/secrets/{id}/validation-requests`의 `{occurrenceId,expectedContextVersion,idempotencyKey}`다. 요청자는 SECURITY 또는 현재 할당된 REMEDIATOR다. OPERATIONS는 연결 운영 권한만으로 이 명령을 실행하지 못한다. 반환된 `requestId`는 기존 REVALIDATE/CREDENTIAL_VALIDITY 작업 ID이며 접수는 인증 성공이 아니다.

워커는 현재 원천을 재취득하고 같은 HMAC·키 revision을 확인한 뒤 DB 트랜잭션 밖에서 인증한다. 원문은 DB·큐·파일·로그에 남기지 않는다. 기본 한도는 공급자 분당 30회, 동시 2개, 실행당 500회/30분, 요청 8초, 최초 포함 3회다. backoff·다음 도래 시각은 DB에 남기고 장시간 sleep으로 worker를 점유하지 않는다. 전송 중 승인 철회의 응답은 이력에만 남으며 현재 인증 성공으로 사용하지 않는다.

유효성 조회·이력은 최근 완료 시도, 마지막 인증 성공, 마지막 확정 응답, 현재 신선도를 분리한다. HTTP 오류·timeout·원문 삭제는 키 폐기나 위치 해결을 뜻하지 않는다. GitHub installation token·미등록 유형은 PAT capability로 보내지 않는다. provider wire logging과 APM의 HTTP header/body 캡처를 활성화하지 않는다.

### GitHub PAT validation

`SECRET_GITHUB_VALIDATION_ENABLED=false` remains the default in both API and worker.
Enable the registered `credential-validation-v1` connection profile using the operator procedure above, then have SECURITY enable the exact source scope policy. The source connection credentials only reacquire approved content; each discovered Classic or Fine-grained PAT authenticates itself with `GET https://api.github.com/user`, API version `2026-03-10`. An installation token is a separate, unsupported capability. No permissions, expiry or revocation cause is inferred.

The worker uses a 3-second connect bound and an 8-second total bound, no redirects, at most 64 KiB response, at most 2 concurrent provider requests, 30 requests/provider/minute, 500 requests/run and a 30-minute validation phase. API manual requests are limited to 10 new commands per actor/minute; idempotent replay is exempt. Retry-After is bounded to 15 minutes; retries otherwise use persisted exponential delay and jitter. Five GitHub authentication rejections within a 60-second window open a 15-minute safety pause. Only response metadata and safe result codes persist. A protected source-version digest records actual GitHub blob evidence; AWS value readers currently supply no provider version, so their digest explicitly records a version-unavailable protected scope/source basis.

A repository-name safety guard produces `SOURCE_GUARD_BLOCKED`; only explicit synthetic scope configuration or a current exact manifest/fingerprint attestation produces `SYNTHETIC_FIXTURE`. A TEST environment label never establishes synthetic contents. The optional repository-access sink receives safe metadata after successful run-scope persistence inside the live-lease transaction. Missing, malformed or conflicting private/visibility fields produce UNKNOWN access scope. Repository metadata failures do not fail otherwise successful collection.

SDK header/wire logging stays disabled. GitHub PAT validation also fails closed when the JVM `jdk.httpclient.HttpClient.log` diagnostic setting is nonempty. AWS uses the registered Apache5 transport with explicit connection bounds ([AWS SDK builder contract](https://docs.aws.amazon.com/java/api/latest/software/amazon/awssdk/http/apache5/Apache5HttpClient.Builder.html)).
