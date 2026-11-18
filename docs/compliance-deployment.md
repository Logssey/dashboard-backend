# 컴플라이언스 점검 배포 준비

이 문서는 대시보드 API와 독립 Prowler Worker를 배포하기 위한 경계만 정의한다. AWS 계정 연결, IAM 역할 생성, Re:Used 점검과 실제 배포는 별도 승인 후 진행한다.

## 구성

1. 브라우저는 `POST /api/v1/compliance/jobs`로 점검 범위를 등록한다.
2. API는 범위를 Prowler 5.46.0 카탈로그로 검증한 뒤 DB에 `QUEUED` 작업만 기록한다.
3. 독립 Worker가 내부 API에서 작업을 임대받고, 자신의 AWS workload role로 Prowler를 실행한다.
4. Worker는 JSON-OCSF 결과만 API에 제출한다. API는 임대 token과 generation이 모두 유효할 때만 결과를 저장한다.
5. API는 대상의 판정 프로필, 판정 정책 버전과 결과에서 확인한 서비스를 Run에 함께 저장한다. 이후 대상 설정이 바뀌어도 과거 Run은 다시 판정하지 않는다.
6. API 컨테이너에는 Prowler, AWS 점검 권한, Docker 소켓이 필요하지 않다.

## 적용성 판정 프로필

대상 등록 후 화면에서 조건부 Check의 적용성을 설정한다. 프로필은 AWS 연결 정보와 분리되어 있어 프로필만 변경해도 연결 확인 상태는 초기화되지 않으며, 변경 내용은 다음 Run부터 적용된다.

- 서비스 사용 여부: `USED`, `NOT_USED`, `UNKNOWN`
- 조직 정책 요구사항: `REQUIRED`, `NOT_REQUIRED`, `UNKNOWN`
- 실제 자산 유형이 결과에 포함되면 해당 서비스는 자동으로 사용 중인 것으로 판단한다. 실제 관측은 `NOT_USED` 선언보다 우선한다.
- 자산이 발견되지 않았다는 이유만으로 서비스를 `NOT_USED`로 판단하지 않는다.
- 적용 여부가 확정되지 않은 조건부 Check 결과는 통제 실패로 단정하지 않고 `NEEDS_REVIEW` 또는 `NOT_ASSESSED`로 남긴다.

Run 상세와 감사 보고서에는 당시의 프로필, 독립 판정 정책 버전, 자동 식별 서비스가 표시된다. 판정 정책 버전은 Prowler 버전과 별도로 관리하므로 매핑 또는 적용성 규칙만 바뀐 경우도 과거 Run과 구분할 수 있다.

## 이미지

```sh
docker build --target api -t logssey-dashboard-api:reviewed .
docker build --target compliance-worker -t logssey-compliance-worker:reviewed .
```

`compliance-worker` 이미지는 Prowler 5.46.0의 멀티 아키텍처 digest에 고정되어 있다. 공식 이미지의 비루트 `prowler` 사용자(UID/GID 1000)를 그대로 사용하므로 배포 설정에서 다른 UID로 덮어쓰지 않는다. 배포 시에는 두 이미지를 레지스트리에 올린 뒤 태그가 아니라 검토한 digest를 사용한다.

## 설정과 비밀값

API 설정에는 다음 값을 추가한다.

```properties
logssey.compliance.target-key=replace-service-key
logssey.compliance.target-name=replace-service-name
logssey.compliance.execution-enabled=false
logssey.compliance.connection-tests-enabled=false
logssey.compliance.worker-lease-seconds=900
logssey.compliance.worker-retry-delay-seconds=30
```

API secret 디렉터리의 `logssey.compliance.worker-token`과 Worker secret 디렉터리의 `logssey.compliance-worker.token`에는 동일한 32바이트 이상의 난수 토큰을 넣는다. 파일 권한은 Worker 또는 API 실행 UID만 읽을 수 있게 제한한다. 토큰을 properties, Compose 환경변수, Git에 저장하지 않는다.

Worker 설정은 [`deploy/compliance-worker.properties.example`](../deploy/compliance-worker.properties.example)을 복사해 외부에서 관리한다. Worker마다 고유한 `worker-id`를 사용한다.

운영에 처음 붙일 때는 API의 `execution-enabled`, `connection-tests-enabled`와 Worker의 `enabled`를 모두 `false`로 둔다. 이 상태에서는 기존 결과와 보고서를 조회할 수 있지만 AWS 호출은 발생하지 않는다. 전용 workload identity를 붙인 다음 Worker와 `connection-tests-enabled`만 먼저 켜 연결 확인을 수행한다. 대상 계정과 역할이 확인된 뒤 대상 자체를 활성화하고 마지막으로 `execution-enabled`를 켠다.

## DB 마이그레이션과 배포 순서

`V53__compliance_assessment_profiles.sql`은 기존 테이블에 JSONB 프로필과 Run 판정 스냅샷 열을 추가하는 확장형 마이그레이션이다. 기존 대상은 빈 프로필, 기존 Run은 `legacy` 정책 버전과 빈 자동 식별 서비스로 채워진다. 기존 열이나 데이터를 삭제하지 않는다.

1. 배포 전 백업과 Flyway 현재 버전을 확인한다.
2. `execution-enabled=false`, `connection-tests-enabled=false`인 API 이미지를 먼저 배포해 V53을 적용한다.
3. 대상 조회, 기존 Run 상세, 통합·규제별 보고서가 정상인지 확인한다.
4. 새 프론트를 배포하고 대상별 적용성 프로필을 검토한다.
5. Worker를 비활성 상태로 배포한 뒤 연결 확인만 활성화한다.
6. 합성 E2E와 테스트 계정 점검을 통과한 뒤에만 자동 점검을 활성화한다.

애플리케이션 롤백 시 추가된 V53 열은 그대로 둔다. 이전 API는 새 열을 참조하지 않으므로 데이터 삭제나 Flyway 강제 롤백 없이 이전 이미지로 돌아갈 수 있다. V53 열 삭제는 Run 판정 근거를 잃게 되므로 운영 롤백 절차에 포함하지 않는다.

## AWS 자격 증명 경계

- ECS에서는 compliance Worker task role만 연결한다. task execution role과 API task role에 점검 권한을 섞지 않는다.
- EKS에서는 compliance Worker ServiceAccount에만 EKS Pod Identity 또는 IRSA 역할을 연결한다.
- EC2/단일 호스트에서는 인스턴스 프로파일처럼 자동 회전되는 workload identity를 사용한다.
- 현재 단일 호스트 Compose에서는 API를 `127.0.0.1:8080`에만 게시하고 Compliance Worker만 host network를 사용한다. IMDS hop limit 1을 유지하므로 bridge network의 API·다른 Worker는 인스턴스 프로파일을 받을 수 없다.
- 정적 Access Key, 개인 `~/.aws`, Docker 소켓을 컨테이너에 전달하지 않는다.
- 대시보드 DB와 API 요청에는 AWS 비밀키를 저장하지 않는다.

권한은 두 단계로 나눈다. Worker의 호스트 역할에는 등록한 대상 역할을 맡을 수 있는 권한만 둔다.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::<대상 계정 ID>:role/<대상 점검 역할>"
  }]
}
```

대상 점검 역할의 신뢰 정책은 Worker 호스트 역할과 화면에서 발급한 대상별 External ID를 모두 일치시킨다. `Principal`에 계정 root나 와일드카드를 넣지 않는다.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<Logssey 계정 ID>:role/<Worker 호스트 역할>"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "logssey-<대상별 UUID>"}}
  }]
}
```

실제 AWS 조회 권한은 이 대상 점검 역할에만 연결한다. Prowler는 지원하는 AWS 점검 API가 매우 넓고 버전에 따라 달라지므로 정책을 수동으로 추측하지 않는다. 저장소의 `deploy/generate-compliance-iam-policy.sh`는 Prowler 5.46.0 소스 커밋과 IAM Policy Autopilot 0.4.0을 고정해 검토용 기준 정책을 만든다. 생성 결과는 IAM Access Analyzer·Policy Simulator와 별도 테스트 계정에서 검토한 뒤 역할에 연결한다. 생성 결과를 자동으로 AWS에 반영하지 않는다.

## Compose 사전 검토

```sh
export COMPLIANCE_WORKER_IMAGE='registry.example/logssey-compliance-worker@sha256:replace'
export COMPLIANCE_WORKER_CONFIG_FILE='/approved/compliance-worker.properties'
export COMPLIANCE_WORKER_SECRETS_DIR='/approved/compliance-worker-secrets'
docker compose -f deploy/compose.yaml -f deploy/compliance-compose.yaml --profile compliance config --quiet
```

이 Compose 예시는 네트워크와 프로세스 경계를 확인하기 위한 단일 호스트 예시다. AWS 역할이나 점검 대상을 생성하지 않는다.

기존 단일 호스트에 처음 추가할 때는 `deploy/bootstrap-compliance-host.py`를 root로 한 번 실행한다. 기존 Compose·배포 스크립트·API 설정을 먼저 백업하고, 비밀값을 출력하지 않은 채 비활성 Worker 설정을 추가한 뒤 구문 검사를 수행한다. 이 스크립트는 컨테이너를 시작하거나 기존 서비스를 재시작하지 않는다.

## 배포 전 확인

- API와 Worker 이미지 digest가 검토된 값인가
- API와 Worker token 파일이 서로 일치하고 저장소 밖에 있는가
- Worker만 AWS workload role을 갖는가
- Worker 호스트 역할은 정확한 대상 역할의 `sts:AssumeRole`만 허용하는가
- 대상 역할 신뢰 정책은 정확한 Worker 역할과 대상별 External ID를 모두 요구하는가
- 선택한 계정·리전·서비스가 승인 범위와 일치하는가
- CloudTrail에서 Worker 역할의 읽기 호출을 식별할 수 있는가
- 작업 취소, 임대 만료, 재시도, 중복 결과 거절을 합성 E2E에서 확인했는가
- V53 적용 후 기존 Run 조회와 보고서 생성이 유지되는가
- 대상별 서비스 사용 여부와 조직 정책 요구사항을 담당자가 검토했는가
- 새 Run 상세와 보고서에 판정 정책·프로필·자동 식별 서비스가 같은 값으로 남는가
- 실제 서비스 연결 전에 테스트 계정 결과로 ISMS-P·ISO 27001·CSAP 평가와 보고서를 검토했는가
