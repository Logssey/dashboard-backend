# Reach CI (서비스 저장소용)

서비스 저장소의 GitHub Actions에서 Reach 분석을 돌려 대시보드에 올린다. 순서는 검사 등록(API-12) → SBOM·대조 → L2(호출 그래프·규칙) → 결과 묶음 → 업로드(API-13) → 게이트 확인이다.

이 폴더는 **원본**이다. 서비스 저장소에는 `reach.yml` 한 파일만 복사하고, 나머지는 워크플로가 이 저장소를 `REACH_REF` 커밋으로 받아 쓴다. 그래서 판정 데이터(`src/main/resources/reach/`)·분석기·스크립트가 한 커밋에 묶여 같은 입력이면 같은 판정이 나온다(NFR-04).

**초안이다.** 아래 "돌리기 전에 필요한 것"이 갖춰져야 동작한다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `reach.yml` | 서비스 저장소 `.github/workflows/reach.yml`로 복사할 워크플로. 작업 두 개(`pr`, `image`) |
| `reach-scan.sh` | 검사 등록부터 게이트까지 한 번에. 워크플로 밖(로컬)에서도 같은 순서로 돈다 |
| `install-tools.sh` | Trivy·Grype를 버전과 SHA-256으로 고정해 설치(infrastructure `iac-gate`와 같은 방식) |

## 두 작업

| 작업 | 언제 | 대상(API-12 `mode`) | 무엇을 스캔 |
| --- | --- | --- | --- |
| `pr` | PR이 열리거나 커밋이 더해질 때(`src/**`, Gradle 파일) | 레포(`PR`) | PR head에서 빌드한 bootJar(`trivy rootfs`) |
| `image` | 서비스의 CI/CD 워크플로가 끝난 뒤(`workflow_run`) | 이미지(`IMAGE_BUILD`) | CI/CD가 ECR에 올린 `pr-{sha}` 이미지(`trivy image`) + 그 안의 `/app/app.jar` |

- 서비스의 CI/CD 워크플로는 고치지 않는다. `image` 작업은 이미지를 받아 읽기만 하고 실행하지 않는다. API가 바뀌지 않아 이미지가 없으면 건너뛴다.
- 머지할 때도 CI/CD가 돌지만 이미지는 같은 digest라 같은 `Idempotency-Key`가 된다. 이때는 다시 스캔하지 않고 이미 끝난 검사 결과만 보인다.
- `workflow_run` 워크플로는 기본 브랜치에 있는 파일로만 돈다. `image` 작업은 `reach.yml`이 기본 브랜치에 머지된 뒤부터 동작한다.
- `POLICY`(저장소 변수 `REACH_POLICY`)가 `REPORT_ONLY`(기본)면 대시보드가 내려가 있어도 PR을 막지 않는다(`continue-on-error`). `GATE`면 게이트 `FAIL`(종료 코드 1)이 PR 검사 실패가 된다.
- 결과는 실행 요약(Step Summary)에 게이트·새 Finding 개수·대시보드 링크(`/vulnerabilities/scans?tab=ci&check=<id>`)로 남고, `verdicts.md`·`check.json`은 아티팩트로 7일 남는다.
- 채팅 서버(Node)는 L2를 지원하지 않아 넣지 않았다(`UNSUPPORTED_ECOSYSTEM`).

## 돌리기 전에 필요한 것

| 무엇 | 어디에 | 상태 |
| --- | --- | --- |
| 대시보드 주소 | 서비스 저장소 변수 `REACH_URL`(API), `REACH_UI_URL`(화면, 선택) | 배포 위치 미정 |
| 감시 대상 등록 | 대시보드 설정 `logssey.reach.apps`에 이 레포(`repo`, 하위 경로면 `path`)와 이미지 저장소(`image`)를 앱 코드로 등록한다(PRD FR-15). 스크립트는 app을 보내지 않고(`APP`을 주면 그 값) 대시보드가 이 설정으로 정한다. 등록 안 된 레포·이미지는 422 | 설치마다 |
| 이미지 저장소 | 서비스 저장소 변수 `REACH_ECR_REPOSITORY`(예: `logssey/reused-api`). 없으면 이미지 작업을 건너뛴다 | 설치마다 |
| CI 인증 | 대시보드가 `/api/v1/reach/ci/**`에서 GitHub OIDC 토큰(`aud = logssey-reach`)을 받아야 한다. 스크립트는 호출마다 새 토큰을 받아 `Authorization: Bearer`로 보낸다 | 미구현(지금은 ADMIN 세션만). `SecurityConfig`·OAuth2 라이브러리 팀 동의 필요 |
| dashboard-backend 읽기 | GitHub App 토큰. 비밀값 `REACH_APP_ID`, `REACH_APP_PRIVATE_KEY`(서비스 CI/CD의 gitops 토큰과 같은 방식) | 앱 미정. 나중에 분석기 이미지(GHCR)로 바꾸면 필요 없다 |
| ECR 읽기 역할 | 비밀값 `REACH_ECR_READ_ROLE_ARN`. `ecr:DescribeImages`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken`만. 신뢰 정책은 이 저장소의 `workflow_run`으로 제한 | 미정(infrastructure Terraform) |
| `REACH_REF` | `reach.yml`의 env. 이 폴더가 들어간 dashboard-backend 커밋 | `b261f45`(#94 머지). 규칙·분석기·스크립트가 바뀌면 그 커밋으로 올린다 |

## 로컬에서 돌려 보기

확인용 DB로 띄운 백엔드에 세션으로 올린다(로컬 DB 8080에는 올리지 않는다). 인증은 `REACH_CURL_OPTS`로 쿠키와 CSRF 헤더를 넘긴다.

```bash
bash deploy/reach/ci/install-tools.sh /tmp/reach-bin && export PATH=/tmp/reach-bin:$PATH
./gradlew :reach-analyzer:jar
(cd <service-backend> && ./gradlew bootJar -x test)

MODE=PR REPOSITORY=service-backend COMMIT=$(git -C <service-backend> rev-parse HEAD) PR_NUMBER=1 \
JAR=<service-backend>/build/libs/service-backend-0.0.1-SNAPSHOT.jar SOURCE=<service-backend> \
REACH_URL=http://localhost:<포트> REACH_CURL_OPTS="-b <쿠키 파일> -H X-XSRF-TOKEN:<토큰>" \
bash deploy/reach/ci/reach-scan.sh
```

- 같은 값으로 다시 돌리면 같은 검사를 다시 보고만 한다. 값 하나라도 다르면(예: `BASE_REF`를 뺌) 같은 키에 다른 본문이라 409다.
- 단계가 실패하면 실패 묶음(`failure.code = ANALYSIS_FAILED`, 실패한 단계)을 올려 스캔이 `FAILED`로 끝난다. 검사 등록 전(빌드 실패, 대시보드 연결 실패)은 대시보드에 남지 않고 워크플로만 실패한다.
- 이미지 모드는 `MODE=IMAGE_BUILD IMAGE_REPOSITORY=logssey/reused-api IMAGE_DIGEST=sha256:… IMAGE_REF=<trivy가 받을 이미지>`와, 그 이미지에서 꺼낸 jar를 `JAR`로 준다.
