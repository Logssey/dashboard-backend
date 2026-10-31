# Secret 배포와 운영 확인

API, 정적 프론트, 별도 Java 워커를 독립 프로세스로 배포한다. 이 문서는 실행 가능한 이미지·설정 예시와 점검 절차다. 실제 운영 인프라 생성·배포나 운영 자격 증명 설정이 완료됐다는 의미는 아니다. Notion·K8s 수집과 심각도 정책 변경을 포함하지 않는다.

## 배치

```text
브라우저 ─ HTTPS 종료 장치 ─ 프론트 nginx ─ /api/v1/ ─ API
                                                   │
                                  PostgreSQL ─ 별도 Secret 워커
                                                   │
                                      승인 GitHub / AWS 읽기
```

- `Dockerfile --target api`: Java 21 API, UID 10001. 수집·탐지 스케줄러를 실행하지 않는다.
- `Dockerfile --target worker`: Java 21 비웹 워커, UID 10001, Gitleaks 8.30.1. 탐지 입력·출력을 메모리/파이프로 처리한다.
- 프론트 저장소의 `Dockerfile`: Node 24로 정적 빌드 후 UID 101 nginx로 제공한다. nginx의 `/api/v1/` 프록시와 SPA fallback을 사용한다. Vite 개발 서버의 프록시는 운영 빌드에 적용되지 않는다.
- `deploy/compose.yaml`은 세 이미지를 연결하는 단일 호스트 예시다. 기존 개발 DB Compose와 독립이며 DB·IAM·TLS·원천 범위를 만들지 않는다. 호스트의 HTTPS 종료 장치만 `127.0.0.1:8088`에 연결한다. 컨테이너에 개인 AWS 디렉터리·소스 저장소·Docker 소켓을 마운트하지 않는다.
- 운영 DB는 PostgreSQL 18 계열, 전송은 `sslmode=verify-full`을 사용한다. PostgreSQL JDBC의 기본 검증 경로가 컨테이너 안의 OS/JVM CA 저장소와 같다고 가정하지 않는다. DB 서버 인증서의 신뢰 체인을 검증할 CA 파일을 `/run/secrets/db-root-ca.crt`로 공급하고 예시 URL의 `sslrootcert`로 명시한다. 서버 호스트 이름도 인증서와 일치해야 한다.

## 이미지와 비밀 공급

각 저장소 루트에서 빌드한다. Dockerfile의 공식 Temurin/Node/nginx 기반 이미지는 검토한 multi-platform digest로 고정했다. 보안 업데이트 시 digest를 함께 갱신하고 다시 검사한다. 워커는 Gitleaks 공식 v8.30.1의 amd64/arm64 아카이브를 고정 SHA-256으로 확인하며 다른 아키텍처는 거부한다. [공식 릴리스](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)가 출처다.

```sh
# dashboard-backend 루트
docker build --target api -t logssey-api:reviewed .
docker build --target worker -t logssey-secret-worker:reviewed .
# dashboard-frontend 루트
docker build -t logssey-frontend:reviewed .
```

빌드 전 해당 커밋의 API·워커 테스트와 프론트 테스트/빌드를 수행한다. `.dockerignore`는 소스 입력만 허용하며 `.env`, PEM, Git 이력, 수집 결과를 제외한다. 레지스트리 게시 후 배포 변수에는 `registry/image@sha256:...`를 사용한다. 실제 빌드·이미지 검사·컨테이너 실행 검증은 Docker 엔진이 있는 배포 환경에서 수행해야 한다.

`deploy/api.properties.example`, `deploy/worker.properties.example`를 **저장소 밖** 운영 설정으로 복사한다. 샘플의 `replace-*`를 승인 DB 주소·사용자로 바꾸고 두 앱 모두 Flyway 자동 실행을 끈다. 비밀은 별도 디렉터리에 파일로 공급하며 Spring `configtree:/run/secrets/`로 읽는다. 파일 이름이 속성 이름이고 내용이 값이다.

| 프로세스 | 필수/조건부 비밀 파일 |
|---|---|
| API | `spring.datasource.password`, `logssey.admin.password`, DB 신뢰 CA 파일 `db-root-ca.crt`; GitHub 연결 테스트 활성화 시 `github-app.pem` |
| 워커 | `spring.datasource.password`, DB 신뢰 CA 파일 `db-root-ca.crt`; 콘텐츠 탐지 활성화 시 `logssey.secret.detection.fingerprint-key`; AWS 수집 활성화 시 `logssey.secret.aws.collection.identity-key`; GitHub 수집 활성화 시 `github-app.pem` |

HMAC 키는 각각 32바이트 이상을 base64로 인코딩해 공급하고 해당 버전을 설정한다. DB 비밀번호와 HMAC·GitHub 키를 이미지 빌드 인수, Compose 변수, Git, DB의 연결 참조에 넣지 않는다. 파일은 실행 UID만 읽게 하고 원문·값은 일반 로그나 `docker inspect` 환경변수에 노출하지 않는다. Windows 바인드 마운트는 실제 권한 동작이 다를 수 있으므로 운영 리눅스/오케스트레이터의 secret 볼륨에서 읽기 권한을 확인한다.

API·워커가 사용하는 DB 계정은 서로 분리하고 DB 소유자/슈퍼유저로 실행하지 않는다. 마이그레이션 계정만 DDL을 가진다. 워커에는 Secret 작업·근거·평가 처리에 필요한 테이블/시퀀스 권한만 주고, 다른 솔루션 쓰기·사용자 생성·DDL을 주지 않는다. 감사/근거 원장의 갱신·삭제 제한은 실제 사용하는 SQL과 대조해 DBA가 검증한다. 이 예시는 운영 DB 역할·GRANT를 자동 생성하지 않는다.

## AWS: 개인 프로필에서 워크로드 역할로

`SECRET_AWS_CREDENTIALS_MODE=PROFILE`이 기존 기본값이다. 명시한 `SECRET_AWS_PROFILE`과 DB `auth_ref=aws-profile:<이름>`을 그대로 사용하며 실패해도 다른 자격 증명으로 넘어가지 않는다.

운영에서는 API·워커에 `SECRET_AWS_CREDENTIALS_MODE=WORKLOAD`를 설정하고 워커의 `SECRET_AWS_PROFILE`을 비운다. 등록 연결의 참조는 **`aws-workload:default`**다. IRSA 관련 환경/시스템 설정이 하나라도 있으면 Web Identity를, 그렇지 않고 컨테이너 설정이 있으면 Container를, 둘 다 없으면 Instance Profile을 **하나만 선택**한다. 설정이 비었거나 잘못돼도 다른 역할로 넘어가지 않는다. 환경변수의 정적 access key, JVM 정적 키, 공유 개인 프로필과 credential process를 조회하지 않는다. 명시 프로필이 남아 있으면 워커 시작을 거부한다. [AWS 임시 자격 증명 공급자](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/credentials-chain.html)를 사용하며 공급자는 프로세스 종료 시 닫는다.

- EKS IRSA: 승인 ServiceAccount의 역할 신뢰 정책과 토큰 볼륨을 구성한다. `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`을 플랫폼이 공급하며 UID 10001이 토큰을 읽을 수 있어야 한다. K8s에 **배포**하는 것과 K8s Secret을 **수집**하는 것은 별도 기능이다.
- ECS: API/워커에 각각 task role을 연결하고 플랫폼이 공급하는 container credential 환경을 사용한다. 호스트의 정적 키를 전달하지 않는다.
- EC2: 전용 instance profile과 IMDS 접근 경계를 구성한다. 다른 프로세스와 역할이 공유되는 단일 호스트 배치의 한계를 검토한다.
- API 연결 테스트는 그 API 역할로 STS 신원만 확인한다. 워커는 실행할 승인 범위의 계정과 STS 계정을 다시 대조한다. API 신원 테스트 성공이 워커의 본문 읽기 성공이나 모든 권한 보유를 뜻하지 않는다.

새 역할에는 필요한 읽기만 부여한다. IAM 메타데이터는 `ListUsers`, `ListAccessKeys`, `GetAccessKeyLastUsed`, `GetAccountSummary`; 목록 메타데이터는 `ListSecrets`, `DescribeParameters`, `ListAllMyBuckets`를 사용한다. 본문 읽기는 별도 승인한 **정확한** Secret ARN의 `GetSecretValue`, Parameter ARN의 `GetParameter`, S3 객체 ARN의 `GetObject`/버전 읽기로 한정한다. 고객 관리 KMS 키가 필요하면 해당 키와 서비스 경로로 `Decrypt`를 제한한다. 삭제·수정·키 회전 권한을 부여하지 않는다. 이 문서의 안내는 IAM 변경을 실행하지 않는다.

기존 연결을 새 역할로 전환할 때는 수동 DB 한 줄 변경으로 실행 중 작업의 인증을 바꾸지 않는다. 해당 연결을 중지하고 진행 리스 종료를 확인한 다음 운영 변경 절차에서 인증 참조·scope version을 함께 갱신하고 이전 대기 작업을 정리한다. 정확한 범위·계정·보안 담당자 승인을 재확인한 뒤 다시 활성화한다. 연결 등록/역할 전환 자체의 운영 관리 UI는 별도 과제다.

## 마이그레이션과 기동

1. 현재 스키마·Flyway 이력과 백업을 확인한다. 공유된 버전 SQL을 수정하지 않는다. 복제한 별도 DB에서 **전체 마이그레이션 + 앱 검사**를 먼저 수행한다.
2. 배포 담당자 한 명이 앱과 같은 **Flyway 12.4.0** 및 PostgreSQL 드라이버로 검토된 SQL을 적용한다. 접속 비밀은 저장소 밖의 접근 제한 설정에 넣는다.

   ```sh
   flyway -configFiles=/secure/flyway.conf -locations=filesystem:src/main/resources/db/migration validate
   flyway -configFiles=/secure/flyway.conf -locations=filesystem:src/main/resources/db/migration migrate
   ```

3. API와 워커는 `spring.flyway.enabled=false`로 실행한다. API는 JPA `validate`를 유지한다. 운영 실패를 `clean`, `repair` 또는 과거 SQL 수정으로 덮지 않는다.
4. 외부 경로에 리뷰한 두 설정 파일과 각 비밀 디렉터리를 준비한다. `SECRET_API_IMAGE`, `SECRET_WORKER_IMAGE`, `SECRET_FRONTEND_IMAGE`, `SECRET_API_CONFIG_FILE`, `SECRET_WORKER_CONFIG_FILE`, `SECRET_API_SECRETS_DIR`, `SECRET_WORKER_SECRETS_DIR`를 비밀 값이 아닌 경로/이미지 참조로 지정하고 다음을 실행한다.

   ```sh
   docker compose -p logssey-secret -f deploy/compose.yaml config --quiet
   docker compose -p logssey-secret -f deploy/compose.yaml up -d
   ```

5. 처음에는 샘플처럼 스케줄러·실행기·모든 수집 플래그를 끈다. DB 권한, 역할, HMAC 버전, Gitleaks 실행을 확인한 뒤 승인한 연결만 활성화한다. 정기 예약·실행기·GitHub 수집·AWS 메타데이터·AWS 본문·공급자 검증은 서로 다른 설정이다. API capability 설정과 워커의 실제 설정을 맞춘다. 플래그를 켜도 DB 범위/검증 승인을 대신하지 않는다.
6. 보안 담당자·연결 운영자·조치 담당자 권한을 별도로 부여한다. 일반 ADMIN 계정만으로 Secret 권한이 생기지 않는다. 최초 bootstrap 지정 후 실제 권한 이력을 확인한다.

HTTPS만 외부에 공개한다. API의 Secure/HttpOnly 세션과 CSRF를 유지하며 프론트와 API를 같은 origin으로 제공한다. 신뢰한 프록시만 API에 접근하게 한다. 현재 세션은 앱 메모리에 있으므로 초기 API는 단일 인스턴스로 운영하고 재시작 시 재로그인이 필요하다. 다중 API 인스턴스의 세션 공유/고가용성은 이 구성에 포함하지 않는다.

## 배포 후 확인

- HTTPS `/login` 로드 → 실제 로그인 → `/api/v1/auth/me` 정상 및 Secure 세션/CSRF 동작을 확인한다. 비로그인 Secret API는 401, 권한 없는 계정은 거부돼야 한다. 새로고침으로 `/secrets/...` 깊은 링크를 열어도 화면이 떠야 한다.
- 연결 테스트에서 신원/설치 인증을 확인하고, 승인 범위 한 곳을 수동 스캔한다. 요청은 실행 ID를 즉시 반환하고 워커가 기본 30초 내 도래 작업을 확인한다. 6시간 정기 예정은 수동 스캔으로 바뀌지 않는다.
- 실행·범위의 성공/부분 실패, 처리량, 키/위치 중복 방지, 상세 발견 위치, 미검증 이유, 담당자 변경과 대응·재검사 화면을 확인한다. 메타데이터 조회를 값 탐지로, 인증 실패를 키 폐기로 표시하지 않아야 한다.
- 같은 권한/출처/조회 기준에서 목록·요약·분포·상세 수를 대조한다. TEST 결과가 운영 대응 건 수에 합산되지 않는지, 제한 계정으로 숨긴 위치나 자산이 노출되지 않는지 확인한다.
- 합성 fixture로 재시도·타임아웃·부분 실패와 원문 비노출을 검사한다. 운영 키를 테스트용으로 저장소에 넣거나 로그 덤프를 공개하지 않는다. 외부 읽기를 실행하는 테스트에는 정확한 범위·별도 승인이 필요하다.

합성 시험에서 미리 알고 있는 긴 토큰이 DB 평문 덤프·API 응답·로그에 없는지 확인하는 도구를 제공한다. needle 파일과 검사 산출물은 저장소 밖 보호 경로에 두고, 압축된 custom dump 대신 평문 시험 덤프를 검사한다.

```sh
python deploy/assert-no-fixture-secrets.py --needles-file /secure/test-fixture-tokens.txt \
  --input /secure/test-db.sql --input /secure/test-api.json --input /secure/test-worker.log
```

이 검사는 알려진 합성 문자열의 비노출 검사이며 모든 비밀 형식의 비노출을 증명하지 않는다. 매칭 원문/파일명은 출력하지 않는다.

## 모니터링·중단·복구

`deploy/monitor-secret.sql`은 읽기 전용 집계다. 모니터링 전용 DB 서비스 파일을 써서 실행한다.

```sh
psql 'service=logssey_secret_monitor' -X -v ON_ERROR_STOP=1 -f deploy/monitor-secret.sql
```

워커는 비웹 프로세스이며 독립 스레드가 예약·실행·평가·권한 관측의 heartbeat와 실제 진행을 기록한다. API의 독립 타이머가 워커 정지·진행 정체·큐 지연·만료 리스·실패/부분 실패 조건을 내부 알림으로 저장하고 중복/복구를 관리한다. 연결 관리의 운영 상태에서 확인한다. 비활성 기능·미래 backoff·유효 리스의 장시간 작업·완료된 정상 0건은 실패로 합치지 않는다. 임계치와 기대 인스턴스 수는 배포 처리량에 맞춰 정한다. API/DB까지 함께 중단되면 내부 저장이 불가능하므로 배포 플랫폼의 별도 생존/DB 감시가 필요하다. 외부 Slack/메일 전송은 구성하지 않는다. 상세는 [운영 상태·복구 자동화](secret-operations.md)를 따른다.

기동 실패 또는 원문 노출 의심 시 먼저 워커를 중지하고 비밀/로그 접근을 제한한다. 원천 쓰기·키 폐기는 이 앱이 자동 수행하지 않는다. 정상 중지는 `docker compose ... stop worker`를 사용하며 DB 작업 행을 임의 삭제하지 않는다. 재시작 후 만료 리스 복구와 동일 실행의 재시도 결과를 확인한다. 롤백은 이전 이미지로 하되 새 스키마와의 호환성을 먼저 확인한다.

DB 백업은 승인한 `pg_dump` 계정으로 접근 제한·암호화 경로에 보관한다. 예:

```sh
pg_dump 'service=logssey_backup' --format=custom --file=/secure/backups/logssey.dump
# 격리된 빈 복원 DB를 DBA가 먼저 준비한 뒤에만 실행:
pg_restore --dbname='service=logssey_restore_drill' --no-owner --exit-on-error /secure/backups/logssey.dump
```

복원 DB에서 Flyway validate, 건수/권한, Secret 목록·대응 이력, 동일 HMAC 버전의 비교를 검사한다. `deploy/secret_recovery.py`는 암호화 논리 백업과 격리 복원 시험 및 명시한 주기의 실행기를 제공한다. 실제 운영 스케줄 설치·백업 저장소·PITR·RPO/RTO 달성은 배포 환경에서 별도로 확정·검증한다. 전체 원장 삭제와 HMAC 무중단 회전은 제공하지 않는다. 보호키의 초기 이력은 운영자의 승인된 실제 런타임 기준으로 확인하며 기존 DB HMAC만으로 실제 키를 역검증할 수 있다고 주장하지 않는다. [운영 상태·복구 자동화](secret-operations.md)의 고정 키 복구·점검 중단 이전 절차를 따른다.
