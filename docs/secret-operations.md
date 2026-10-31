# Secret 운영 상태와 복구 자동화

심각도 v2는 유지한다. 운영 상태는 수집/처리의 정상 여부이며 발견 키의 심각도·유효성·노출 판정과 별개다. 원천 쓰기나 외부 메시지 전송을 수행하지 않는다.

## 운영 상태 API

- `GET /api/v1/secrets/operations/health`: 현재 운영 컴포넌트, 큐, 내부 알림 수, 임시 스냅샷 정리 상태.
- `GET /api/v1/secrets/operations/alerts?state=OPEN&page=0&size=20`: 상태는 OPEN/RECOVERED/ALL, 크기 1–100.
- 현재 전역 SECURITY 또는 OPERATIONS만 읽는다. 범위 한정 권한만 있으면 403이며 숨겨진 연결의 수를 반환하지 않는다. 조회는 DB 기록을 생성하거나 원천을 읽지 않는다.
- DB 조회가 불가능하면 `status=UNAVAILABLE`, 사유 `DATABASE_UNAVAILABLE`, 알 수 없는 수는 null이다. 0건 성공으로 바꾸지 않는다. 공개 health endpoint는 아니므로 비로그인 상태에서는 로그인 경계가 먼저 적용된다.

워커의 독립 heartbeat 스레드는 실제 예약/실행/평가/권한 관측 폴러와 별도로 돌며 각 폴러의 시작·완료·성공·실패와 활성 작업을 기록한다. DB의 프로세스 시작 시각은 한 번만 정하고 폴러 시작 시각과 구분한다. 유휴 상태에서도 마지막 성공한 폴링을 남긴다. API의 별도 예약 작업이 워커 전체가 정지한 경우에도 내부 알림을 생성한다. 여러 감시자의 중복 실행은 DB advisory lock으로 제한한다.

상태는 HEALTHY, DISABLED, STALE, FAILED, NOT_REGISTERED다. 첫 기록이 없으면 아직 등록/시작을 확인하지 못한 것이고, heartbeat만 새로워도 폴러가 진행하지 않으면 정상으로 보지 않는다. 기대 수만큼 실제 진행 중인 인스턴스가 있어야 HEALTHY다. 과거 종료된 인스턴스는 현재 기대 수를 채운 정상 인스턴스를 실패로 만들지 않는다. 현재 활동 중인 활성 인스턴스를 다른 비활성 인스턴스 한 개가 숨기지 않는다.

API와 워커의 `logssey.secret.operations.deployment-key`를 같게 설정한다. heartbeat와 내부 알림은 이 그룹별로 조회/복구한다. 서로 다른 환경은 DB와 비밀도 분리한다. `expected-instances` 기본값은 1이며 복제 수 변경 시 함께 검토한다. 기본 heartbeat/감시 주기는 30초, 유예는 2분이다. 실제 폴링 간격도 반영하며 수집이 30초 안에 시작/완료된다고 보장하지 않는다.

큐는 도래 대기·미래 재시도·리스 작업·만료 리스를 구분한다. 기능이 꺼져 있는 작업을 정체 알림으로 만들지 않는다. 현재 유효 리스 작업을 정상 처리하는 동안의 대기를 정지로 간주하지 않는다. 최신 전체 검사의 부분 실패는 발견 0건이어도 부분 실패로 남는다. 현재 범위 버전의 다음 성공은 이전 실패/부분 실패 감시 조건을 해소한다.

내부 알림은 조건별 하나의 열린 기록을 유지한다. 동일 원인의 반복 관측은 새 알림을 쌓지 않고, 새 실패 근거/재개에만 발생 횟수를 올린다. OPENED/RECOVERED/REOPENED 전이는 변경·삭제할 수 없는 이력이다. RECOVERED는 감시 조건이 더 이상 현재 적용되지 않음을 뜻하며 외부 키의 폐기·보안 대응 해결을 증명하지 않는다. API·DB까지 함께 중단되면 내부 알림 저장이 불가능하므로 플랫폼 생존/DB 감시는 별도로 필요하다.

재검증·평가·권한 관측의 최종 실패도 ScanRun을 만들지 않고 작업 목적과 대상별로 추적한다. 같은 목적·대상의 후속 성공이 있어야 이전 실패를 복구로 전환하며 시간 경과만으로 닫지 않는다. 정상 취소·오래된 기준의 취소와 작업을 정상 완료한 INVALID 인증 결과는 운영 실패 알림이 아니다.

## 권한과 보존

V35는 운영 heartbeat·알림·전이 원장을 추가하고 기존 `secret_audit_events`의 수정/삭제를 DB 트리거로 차단한다. 공개된 과거 마이그레이션을 수정하지 않는다. 워커는 실행/평가 데이터에 필요한 쓰기만 갖고 정책·역할·자산·인증 참조를 바꾸지 않는다. API는 공유 CNAPP 계정의 별도 검토를 거치며 내부 감시에는 운영 알림 테이블의 쓰기가 필요하다.

```sh
python deploy/render_secret_worker_grants.py --worker-role logssey_secret_worker > /secure/review-worker-grants.sql
psql 'service=logssey_secret_monitor' -X -v ON_ERROR_STOP=1 -f deploy/secret_retention_check.sql
```

첫 명령은 검토용 SQL만 출력하고 역할/비밀번호 생성이나 DB 연결을 하지 않는다. DBA는 전용 비소유자 역할에 적용하기 전에 역할 상속·PUBLIC 권한·소유권과 실제 워커 흐름을 함께 검사한다. 기존 운영 역할을 자동 변경하지 않는다. 합성 복원 DB에서 heartbeat·예약 시각 갱신의 허용과 정책/자산/인증 참조 변경·감사 삭제·DDL 거부를 확인했다. 실제 운영 역할 검증을 대신하지 않는다.

워커는 만료된 파생 조회 스냅샷만 한 번에 최대 500개 정리하고 기존의 24시간 retirements 표식을 유지한다. 업무 원장의 보존 일수를 임의로 정하거나 작업·실행·키·근거·감사 이력을 삭제하지 않는다. dry-run은 FK와 불변 보호를 보여 준다. 향후 정리 설계에는 미해결 건, 조사 보존, 최초/최근 발견 참조, 재검사·해결 증거, 평가 연결, 멱등 명령 참조와 백업의 보존도 포함해야 한다.

## 암호화 백업과 격리 복원 시험

Python 3.10+, `deploy/requirements-operations.txt`, PostgreSQL 18의 pg_dump/pg_restore와 검토된 [age](https://github.com/FiloSottile/age)가 필요하다. 신뢰할 수 있는 설치 경로를 설정한다. 복원할 아카이브는 신뢰한 DB/백업 운영자가 생성한 것만 사용한다. 암호화만으로 발신자 신원을 보장하지 않으므로 저장소 접근 통제도 필요하다.

`deploy/recovery-config.example.json`을 저장소 밖으로 복사한다. DB 접속은 외부 libpq service/password 파일, age 수신자는 공개 recipient 파일을 사용한다. age 복호화 identity와 HMAC 복구 기준은 백업 산출물과 다른 보호 위치에 보관한다. 설정·원문 키·백업은 Git에 넣지 않는다.

HMAC 기준은 실제 배포된 읽기 전용 비밀 마운트/버전에서 확보한 키 확인값이다.

```sh
python deploy/runtime_key_check.py --kind fingerprint --version reviewed-v1 --key-file /secure/deployed-fingerprint.b64
```

이 출력 자체는 승인이 아니다. 기존 데이터에 처음 적용할 때 운영자가 실제 런타임/비밀 버전 이력과 필요하면 승인된 원천의 재취득 비교로 확인한 뒤 별도 보호 파일에 다음 형식으로 승인한다. 기존 DB의 HMAC에서 원래 키를 추론하거나 자동으로 첫 제출을 신뢰하지 않는다.

```json
{"format":"logssey-approved-runtime-keys-v1","approvalRef":"TICKET:OPS-101","keys":[{"kind":"fingerprint","version":"reviewed-v1","check":"operator-verified-64-hex-digest"}]}
```

사용한 fingerprint/metadata 버전별 모든 복구 키가 필요하다. 같은 버전 이름에 다른 키 재료를 넣으면 백업/복원 검증을 거부한다. 키는 32바이트 이상 난수의 base64이고 확인값은 원문 키가 아니다.

```sh
python deploy/secret_recovery.py backup --config /secure/recovery-config.json
python deploy/secret_recovery.py restore-drill --config /secure/recovery-config.json --bundle backup-<completed-id>
python deploy/secret_recovery.py tick --config /secure/recovery-config.json
```

백업은 읽기 전용 일관성 스냅샷을 내보내고 같은 스냅샷의 pg_dump를 age에 파이프로 넘긴다. 이 백업은 **공유 DB 전체**이며 다른 CNAPP 데이터·사용자·자산도 포함하므로 공통 DB/백업 담당자의 접근·저장 정책을 적용한다. 평문 DB 덤프를 파일에 쓰지 않는다. 키 원문·버전 확인값·검증 건수의 복구 묶음도 따로 암호화하고 DB 암호문의 SHA-256과 연결한다. 압축을 암호화로 부르지 않는다.

복원은 DBA가 별도로 만든 `secret_restore_admin*` DB와 `logssey.restore_admin=enabled` 표식, 승인 호스트 목록을 요구한다. 도구는 새 무작위 `secret_restore_*` 빈 DB만 만들며 기존 DB를 덮어쓰거나 지우지 않는다. 기본 예시는 loopback만 허용한다. 성공한 복원 DB는 검토를 위해 남긴다. `max_retained_drills` 한도에 도달하면 중단하며 운영자가 검토·정리한다. 운영 환경에 자동으로 DB 생성 권한을 부여하지 않는다.

복원 결과는 주요 원장/마이그레이션 건수·공유 사용자/자산·존재하는 권한 관측/판정 기록·보존 버전·FK와 HMAC의 실제 키 재료를 확인하고 검증한 테이블 목록을 남긴다. 현재 키 파일을 잃었어도 별도 age identity와 승인 기준이 있으면 암호화 묶음에서 보호된 외부 디렉터리로 복구한다. Linux 파일 모드는 디렉터리 0700/키 0600이다. Windows는 별도 NTFS ACL을 확인한다. 키 원문·공급자/DB 오류 본문은 출력하지 않는다.

tick은 명시한 백업/복원 주기를 읽고 DB advisory lock으로 중복 실행을 막는다. 주기가 0인 예시 설정은 실행을 거부한다. systemd service/timer는 이 실행기를 1분마다 깨우는 설치 예시이며 백업 주기나 보존 일수를 대신 정하지 않는다. 실제 환경에 설치하거나 활성화하지 않았다. 완료/실패는 보호된 산출물의 schedule-state.json과 종료 코드로 감시한다. 백업 계정은 읽기 전용으로 두고 복원용 생성 권한은 격리 관리 계정에만 둔다.

RPO/RTO는 사용자가 정한다. 도구는 백업 시점·소요 시간·복원 시간·목표 초과를 보고하고, 미설정 목표는 NOT_CONFIGURED로 남긴다. 논리 백업만으로 운영 PITR/고가용성을 제공하지 않는다. 팀 DB의 관리형 백업과 함께 검토한다. 격리된 합성 PG18에서 암호화 백업→스케줄 실행→실제 복원, 동일 버전/다른 키 거부, 잘못된 복원 대상 거부와 현재 키 파일 소실 복구를 시험했다.

## 고정 HMAC와 점검 중단 이전

MVP는 승인한 고정 키/버전과 복구를 사용한다. 버전 문자열만 바꾸거나 같은 버전에 다른 키를 연결하지 않는다. 무중단 회전 기능은 없다. 이전이 필요하면 워커/예약을 중지하고 리스 종료와 백업을 확인한 뒤, 이전·새 키로 승인 원천을 메모리에서 재취득해 비교 가능한 대상만 연결한다. 원천이 없거나 권한이 없어 비교하지 못한 과거 기록은 보존하며 자동 합치기·해결을 하지 않는다. 시험 합성 manifest, 재검사 기준, 보호된 신원 참조도 버전에 연결돼 있으므로 함께 검토한다. 승인 기준/운영 설정을 갱신하고 재검사와 이력 연속성을 확인한 뒤 재개한다. 이 절차의 실제 원장 이전 엔진은 별도 개발 사항이며 자동 키 회전으로 표시하지 않는다.
