# Secret 작업 예약 워커

현재 구현은 작업 예약과 DB 기반 실행 관리를 제공한다. GitHub API, 개인키, 탐지 도구를 호출하는 처리기는 아직 없으므로 파일 내용을 읽지 않는다. 실행기는 기본 비활성화다.

Java 21 / Spring Boot를 사용하는 별도 프로세스다. 대시보드 API에는 워커 의존성이나 스케줄러를 넣지 않았다. 기준은 Secret ADR-S002, ADR-S008과 `database-schema.md`다.

## 동작

- 기본 30초마다 DB의 현재 시각으로 도래한 연결을 확인한다. 기본 검사 주기는 6시간이다.
- `ACTIVE` 연결에 예정 시각과 활성 승인 범위가 있어야 예약한다. `PAUSED`, `ERROR`, 미승인 범위는 건너뛴다.
- 연결 행을 `FOR UPDATE SKIP LOCKED`로 잠그고, 작업·검사 실행·승인 범위 스냅샷·다음 예정 시각을 한 트랜잭션에서 저장한다.
- 같은 연결의 `FULL_SCAN` 작업이 `PENDING` 또는 `LEASED`이면 새 작업을 만들지 않는다. 여러 프로세스와 반복 호출의 중복도 DB 고유 제약으로 막는다.
- 다음 시각은 **이전 예정 시각 + 6시간**이다. 서버 재시작, 실패, 마지막 성공 시각 때문에 주기가 뒤로 밀리지 않는다.
- 장시간 중단 후에는 가장 오래된 예정 시각부터 예약한다. 미완료 작업이 있는 동안 다음 시각을 더 밀지 않고 지연을 보존하므로 대기열을 무한히 늘리지 않는다.
- 예약은 실행 성공을 뜻하지 않는다. 시작·종료·마지막 수집 성공·수집 건수는 채우지 않는다.

## 작업 실행 계약

- `SECRET_JOB_EXECUTOR_ENABLED=true`이고 `SecretJobProcessor` 빈이 있을 때만 예약된 작업을 소비한다. 처리기가 없으면 활성화 설정만으로 작업을 선점하지 않는다.
- DB의 도래한 `PENDING` 작업을 `FOR UPDATE SKIP LOCKED`로 선점한다. 매 시도에 새로운 리스 토큰을 발급하고 `attempt_no`를 올린다. 한 번에 작업을 하나씩 선점한 뒤 처리해 대기 중 리스 만료를 피한다.
- 처리기는 네트워크 호출 전에 승인 범위 스냅샷을 읽고, 오래 걸리는 작업에서는 `renewLease`로 리스를 갱신한다. 실행 중 DB 결과 저장은 `persistIfLeased(jobId, leaseToken, ...)` 안에서 수행한다. 이 콜백에는 짧은 DB 쓰기만 넣고 네트워크 호출을 넣지 않는다. 만료되거나 교체된 리스의 쓰기·갱신·완료·실패 보고는 거부된다.
- 처리기가 반환되어도 수집·탐지·검증 단계와 예약된 모든 범위가 완결되지 않으면 성공 종료를 허용하지 않는다. 수집 범위 중 실패·부분 누락·미지원이 있으면 전체 결과를 `PARTIAL`로 기록하고 정상 0건과 구분한다. 수집이 완전히 성공하고 각 범위의 완료 시각이 있을 때에만 마지막 수집 성공 시각을 가장 늦은 범위 완료 시각으로 갱신한다.
- 일시 실패와 만료된 리스는 지수 백오프 후 같은 실행 ID로 재시도한다. 최대 시도 횟수에 도달하면 작업과 실행을 `FAILED`로 종료한다. 지난 성공 단계와 범위는 보존하고 진행 중·부분 실패·실패 단계는 다시 대기시킨다.
- 실패 코드는 `SecretJobFailureCode`에 정의된 값만 저장한다. 공급자 응답 본문, 예외 메시지와 원문은 DB 또는 로그에 기록하지 않는다. 처리기는 결과 저장의 멱등성도 보장해야 한다.

현재 `SecretJobProcessor` 구현은 없다. 수집기와 탐지기를 연결하는 PR에서 이 계약을 구현하고 실행기를 활성화한다. API 프로세스는 실행 서비스를 호출하지 않는다.

`V3__create_secret_scheduler_tables.sql`에 연결, 승인 범위, 작업, 검사 실행, 실행 범위 테이블 5개를 추가했다. API와 워커는 같은 원본 Flyway 마이그레이션을 패키징한다. 공유된 V1·V2는 변경하지 않았다.

이번 단계의 작업 종류는 `FULL_SCAN`뿐이다. 공급자 호출, 수동 재검증과 조회 API는 다음 단계에서 구현한다. 향후 `REVALIDATE`는 자격 증명 테이블과 FK를 추가하는 새 마이그레이션으로 확장한다.

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
