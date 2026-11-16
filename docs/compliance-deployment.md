# 컴플라이언스 점검 배포 준비

이 문서는 대시보드 API와 독립 Prowler Worker를 배포하기 위한 경계만 정의한다. AWS 계정 연결, IAM 역할 생성, Re:Used 점검과 실제 배포는 별도 승인 후 진행한다.

## 구성

1. 브라우저는 `POST /api/v1/compliance/jobs`로 점검 범위를 등록한다.
2. API는 범위를 Prowler 5.46.0 카탈로그로 검증한 뒤 DB에 `QUEUED` 작업만 기록한다.
3. 독립 Worker가 내부 API에서 작업을 임대받고, 자신의 AWS workload role로 Prowler를 실행한다.
4. Worker는 JSON-OCSF 결과만 API에 제출한다. API는 임대 token과 generation이 모두 유효할 때만 결과를 저장한다.
5. API 컨테이너에는 Prowler, AWS 점검 권한, Docker 소켓이 필요하지 않다.

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
logssey.compliance.worker-lease-seconds=900
logssey.compliance.worker-retry-delay-seconds=30
```

API secret 디렉터리의 `logssey.compliance.worker-token`과 Worker secret 디렉터리의 `logssey.compliance-worker.token`에는 동일한 32바이트 이상의 난수 토큰을 넣는다. 파일 권한은 Worker 또는 API 실행 UID만 읽을 수 있게 제한한다. 토큰을 properties, Compose 환경변수, Git에 저장하지 않는다.

Worker 설정은 [`deploy/compliance-worker.properties.example`](../deploy/compliance-worker.properties.example)을 복사해 외부에서 관리한다. Worker마다 고유한 `worker-id`를 사용한다.

운영에 처음 붙일 때는 API의 `execution-enabled`와 Worker의 `enabled`를 모두 `false`로 둔다. 이 상태에서는 기존 결과와 보고서를 조회할 수 있지만 새 자동 점검은 등록되지 않는다. Worker 이미지, 공유 토큰, workload identity와 합성 점검을 확인한 뒤 두 값을 함께 활성화한다.

## AWS 자격 증명 경계

- ECS에서는 compliance Worker task role만 연결한다. task execution role과 API task role에 점검 권한을 섞지 않는다.
- EKS에서는 compliance Worker ServiceAccount에만 EKS Pod Identity 또는 IRSA 역할을 연결한다.
- EC2/단일 호스트에서는 인스턴스 프로파일처럼 자동 회전되는 workload identity를 사용한다.
- 정적 Access Key, 개인 `~/.aws`, Docker 소켓을 컨테이너에 전달하지 않는다.
- 대시보드 DB와 API 요청에는 AWS 비밀키를 저장하지 않는다.

Prowler는 지원하는 AWS 점검 API가 매우 넓고 버전에 따라 달라진다. 배포 역할의 기준 정책은 수동으로 추측하지 않고 저장소에 포함된 `deploy/generate-compliance-iam-policy.sh`로 Prowler 5.46.0 소스에서 생성한다. 생성 결과는 IAM Policy Simulator와 별도 테스트 계정에서 검토한 뒤 역할에 연결한다.

## Compose 사전 검토

```sh
export COMPLIANCE_WORKER_IMAGE='registry.example/logssey-compliance-worker@sha256:replace'
export COMPLIANCE_WORKER_CONFIG_FILE='/approved/compliance-worker.properties'
export COMPLIANCE_WORKER_SECRETS_DIR='/approved/compliance-worker-secrets'
docker compose -f deploy/compose.yaml -f deploy/compliance-compose.yaml --profile compliance config --quiet
```

이 Compose 예시는 네트워크와 프로세스 경계를 확인하기 위한 단일 호스트 예시다. AWS 역할이나 점검 대상을 생성하지 않는다.

## 배포 전 확인

- API와 Worker 이미지 digest가 검토된 값인가
- API와 Worker token 파일이 서로 일치하고 저장소 밖에 있는가
- Worker만 AWS workload role을 갖는가
- 선택한 계정·리전·서비스가 승인 범위와 일치하는가
- CloudTrail에서 Worker 역할의 읽기 호출을 식별할 수 있는가
- 작업 취소, 임대 만료, 재시도, 중복 결과 거절을 합성 E2E에서 확인했는가
- 실제 서비스 연결 전에 테스트 계정 결과로 ISMS-P·ISO 27001·CSAP 평가와 보고서를 검토했는가
