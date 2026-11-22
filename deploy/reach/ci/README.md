# Reach CI (서비스 저장소용)

서비스 저장소의 GitHub Actions에서 Reach 분석을 돌려 대시보드에 올린다. 순서는 검사 등록(API-12) → SBOM·대조 → L2(호출 그래프·규칙) → 결과 묶음 → 업로드(API-13) → 게이트 확인이다.

이 폴더는 **원본**이다. 서비스 저장소에는 `reach.yml` 한 파일만 복사하고, 나머지는 워크플로가 이 저장소를 `REACH_REF` 커밋으로 받아 쓴다. 그래서 판정 데이터(`src/main/resources/reach/`)·분석기·스크립트가 한 커밋에 묶여 같은 입력이면 같은 판정이 나온다(NFR-04).

**초안이다.** 아래 "돌리기 전에 필요한 것"이 갖춰져야 동작한다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `reach.yml` | 서비스 저장소 `.github/workflows/reach.yml`로 복사할 워크플로. 작업 세 개(`pr`, `image`, `manual`) |
| `reach-scan.sh` | 검사 등록부터 게이트까지 한 번에. 워크플로 밖(로컬)에서도 같은 순서로 돈다 |
| `install-tools.sh` | Trivy·Grype·JaCoCo(에이전트·CLI)를 버전과 SHA-256으로 고정해 설치(infrastructure `iac-gate`와 같은 방식). JaCoCo 폴더는 `JACOCO_HOME` |
| `l3-run.sh` | L3: 스캔한 이미지를 JaCoCo 에이전트와 띄우고 서비스 저장소의 시나리오를 보내며 실행 기록을 요청 단계마다 끊어 남긴다(아래 "L3"). 대조는 `reach-scan.sh`가 L2 뒤에 한다 |

## 세 작업

| 작업 | 언제 | 대상(API-12 `mode`) | 무엇을 스캔 |
| --- | --- | --- | --- |
| `pr` | PR이 열리거나 커밋이 더해질 때(`src/**`, Gradle 파일) | 레포(`PR`) | PR head에서 빌드한 bootJar(`trivy rootfs`) |
| `image` | 서비스의 CI/CD 워크플로가 끝난 뒤(`workflow_run`) | 이미지(`IMAGE_BUILD`) | CI/CD가 ECR에 올린 `pr-{sha}` 이미지(`trivy image`) + 그 안의 `/app/app.jar`. 시나리오가 있으면 L3도 |
| `manual` | 대시보드에서 [스캔 요청](API-01)을 누를 때. 대시보드가 `workflow_dispatch`로 띄운다 | 대시보드가 만든 검사(`MANUAL`) | 레포 대상은 그 커밋에서 빌드한 bootJar, 이미지 대상은 그 digest 이미지 + `/app/app.jar` |

- `manual`은 검사를 등록하지 않고 받은 `check_id`에 올린다(`reach-scan.sh` `MODE=MANUAL`). 대시보드는 그 검사의 레포·기본 브랜치·`workflow_dispatch` 토큰만 받는다.
- 재대조: 대시보드가 하루 1번(기본 한국 04:30, `logssey.reach.rescan.cron`) 운영에서 실행 중인 이미지(L1)의 스캔마다 `SCHEDULE` 검사를 만들고 `manual`을 `rescan_of`와 함께 띄운다. API-01 `rescanOf`도 같다. 러너는 대시보드가 보관한 그 스캔의 SBOM(`GET /api/v1/reach/ci/checks/{id}/sbom`)을 오늘의 취약점 DB로 다시 대조하고, L2용 jar는 지금처럼 같은 digest 이미지에서 꺼낸다. 보관한 SBOM이 없으면(보관 전 스캔, 404) SBOM을 새로 만든다. `rescan_of` 입력이 없는 옛 `reach.yml`로는 재대조만 띄우지 못한다(GitHub 422, 대시보드 로그에 남음).
- **Java 앱 jar가 없는 대상도 스캔한다.** 레포 대상은 그 경로에 `gradlew`가 있을 때만 bootJar를 빌드하고, 없으면(예: Node 앱의 `package-lock.json`) `trivy fs`로 잠금 파일에서 SBOM을 만든다(`FS_DIR`). 이미지 대상은 `/app/app.jar`가 없으면(Node·nginx 이미지) jar 없이 이미지 SBOM만 쓴다. 이때 L2를 건너뛰고(`bundle.py --no-l2`) Finding은 모두 `NOT_ANALYZED`다: npm 등은 `UNSUPPORTED_ECOSYSTEM`, OS 패키지는 `OS_PACKAGE`, 이미지에 섞인 Java 패키지는 데이터가 없으면 `NO_VULN_FUNCTION_DATA`·있으면 `UNANALYZED_COPY`(앱 jar를 못 찾았다는 설명). SBOM·CVE 대조·L1(배포 여부)은 그대로라 취약점 목록과 실행 중 여부는 보인다.
- `manual`에서 스캔 전 단계(입력 확인, 빌드, 이미지 받기, 도구 설치)가 실패하면 실패 묶음(`failure.code` `BUILD_FAILED`·`IMAGE_PULL_FAILED`)을 올려 대시보드 스캔이 `QUEUED`에 남지 않고 `FAILED`로 끝난다. 스캔 단계 안의 실패는 지금처럼 `ANALYSIS_FAILED`다.
- `workflow_dispatch`도 기본 브랜치에 있는 파일로만 돈다. 대시보드는 기본 브랜치(`logssey.reach.ci.default-branch`)로 띄운다.
- 이미지 대상은 이미지 태그 `pr-{sha}`가 있으면 그 커밋을 받아 `verdict.py`에 설정 파일을 준다. 없으면 설정 파일 없이 판정한다.

- 서비스의 CI/CD 워크플로는 고치지 않는다. `image` 작업은 이미지를 받아 읽고, 시나리오가 있을 때만 L3로 러너 안에서 실행한다(아래). API가 바뀌지 않아 이미지가 없으면 건너뛴다.
- 머지할 때도 CI/CD가 돌지만 이미지는 같은 digest라 같은 `Idempotency-Key`가 된다. 이때는 다시 스캔하지 않고 이미 끝난 검사 결과만 보인다.
- `workflow_run` 워크플로는 기본 브랜치에 있는 파일로만 돈다. `image` 작업은 `reach.yml`이 기본 브랜치에 머지된 뒤부터 동작한다.
- `POLICY`(저장소 변수 `REACH_POLICY`)가 `REPORT_ONLY`(기본)면 대시보드가 내려가 있어도 PR을 막지 않는다(`continue-on-error`). `GATE`면 게이트 `FAIL`(종료 코드 1)이 PR 검사 실패가 된다. 게이트는 PR 검사에만 건다. 이미지 빌드 검사는 `GATE`여도 리포트 전용으로 등록한다(기준 스캔이 없어 운영에 이미 있는 Finding으로 실패하기 때문). PR 검사는 그 앱이 운영에서 실행 중인 이미지의 스캔과 비교해, 운영에 없던 Finding만 새 것으로 센다(실행 중 이미지를 모르면 모두 새 것). 비교한 스캔은 실행 요약에 나온다.
- 결과는 실행 요약(Step Summary)에 게이트·새 Finding 개수·대시보드 링크(`/vulnerabilities/scans?tab=ci&check=<id>`)로 남고, `verdicts.md`·`check.json`은 아티팩트로 7일 남는다.
- 채팅 서버(Node)는 L2를 지원하지 않아 넣지 않았다(`UNSUPPORTED_ECOSYSTEM`).

## L3 (실제 실행, FR-14)

`image` 작업은 서비스 저장소에 `.reach/l3-scenario.json`이 있으면 스캔 전에 `l3-run.sh`로 앱을 띄워 실행 기록을 남기고, `reach-scan.sh`가 L2 뒤에 그 기록을 대조해 결과 묶음의 `l3`에 넣는다. L3는 L2 판정 옆에 놓는 근거다: CVE마다 실제 실행이 취약 코드 쪽으로 어디까지 갔는지(취약 구간 / 취약 함수 / 없음), 어느 요청에서였는지, L2가 찾은 호출 경로를 어디까지 탔는지. 판정(status)·게이트는 바꾸지 않는다. 결과 형식은 `reach-analyzer/README.md` "L3 실행 확인".

기록(`l3-run.sh`)
1. 시나리오의 서비스(DB·캐시)를 띄우고, 같은 이미지를 JaCoCo 에이전트(`JAVA_TOOL_OPTIONS`, `output=tcpserver`)와 띄운다. 기록 범위는 `java.util.*` + 앱과 라이브러리의 최상위 패키지 전부(`java`·`javax`·`jdk`·`sun`은 뺌, JDK 전체를 넣으면 JVM이 안 뜬다)
2. 앱이 준비되면 에이전트의 기록을 읽고 비운다(구간 `startup`). 시나리오 단계를 하나 보낼 때마다 다시 읽고 비운다(구간 `001`, `002`, …, 반복 단계는 한 구간). 구간마다 `segments/<id>.exec`
3. `run.json`에 그 실행의 근거를 남긴다: 이미지 digest, 시나리오 버전, 설정 키 이름과 켜짐 여부(값은 안 남김), 보낸 요청 목록, 관측 시각, 기록 범위

대조(`reach-scan.sh`, L2 다음)
1. 그 이미지에서 꺼낸 `/app/app.jar`로 클래스 파일을 준비한다(`verdict/l3_runner.py classes`). Spring Boot jar의 class path 순서대로, multi-release jar는 이미지의 Java 버전에 맞는 클래스로. 판정 데이터(`vuln-functions.json`)가 가리키는 소스 파일과 L2 호출 경로 위의 클래스만(Re:Used api 전체면 XML 250MB, 이렇게 하면 구간마다 1MB 안쪽)
2. 구간마다 `jacococli report`로 XML을 만들고 `verdict/l3.py`가 대조한다. 클래스 파일이 실행된 것과 다르면(`does not match`) 결과를 만들지 않는다

- **시나리오는 데이터다.** 요청 목록·서비스 이미지·환경 변수만 적고, 러너는 그 안의 어떤 것도 셸에서 실행하지 않는다(PR head의 파일을 읽으므로). 형식은 `reach-analyzer/verdict/l3_runner.py` 맨 위 설명. JVM 옵션(`JAVA_TOOL_OPTIONS` 등)은 러너만 정한다
- 컨테이너에는 시나리오의 환경 변수와 러너가 만든 임시 비밀값(`generate`, 예: `JWT_SECRET`)만 들어가고 러너의 비밀값·토큰은 들어가지 않는다. 컨테이너는 실행마다 만든 Docker 네트워크에 있고 앱 포트와 에이전트 포트만 `127.0.0.1`에 연다
- 이미지와 시나리오는 PR이 만든 것이라 믿지 않는다: 시나리오 문자열에 제어 문자를 받지 않고, 로그에 찍는 글자는 GitHub 워크플로 명령(`::`, `##[`)이 되지 않게 바꾼다. 컨테이너가 디스크에 쓴 것은 읽지 않는다(실행 기록은 `jacococli`가 에이전트 포트로 읽어 직접 쓰고, 크기와 형식을 확인한다). 요청은 리다이렉트를 따라가지 않는다
- 로그에는 단계 이름·메서드·치환 전 경로·상태만 찍는다(요청·응답 본문, 헤더, 저장한 값은 안 찍음). 서비스 저장소가 공개라 로그도 공개다. 앱이 뜨지 않을 때만 앱 기동 로그 마지막 40줄을 보인다
- **L3가 실패해도 스캔은 계속된다**(`continue-on-error`). 묶음의 `l3`는 `{"error": "..."}`가 된다. 대조가 실패해도 같다. 실패한 실행은 `segments`·`run.json`을 남기지 않는다
- 아티팩트에 `segments/`(실행 기록)·`steps.json`·`run.json`·`l3-result.json`이 7일 남는다
- 대시보드는 `l3`를 Finding마다 저장해 판정 옆에 보인다(API-05 `l3`). 판정·검토·게이트는 바꾸지 않는다
- **실행 기록 보관과 재대조**: 방금 앱을 띄운 실행의 `segments/`와 `run.json`을 tar.xz 하나로 묶어(`l3_runner.py pack`, Re:Used api 약 0.3MB) 결과 묶음의 `l3Record`로 올리고, 대시보드가 이미지마다 보관한다(앱마다 최근 이미지 5개와 실행 중인 이미지의 것). 재대조(`rescan_of`)는 앱을 띄우지 않고 그 기록을 받아(`GET /api/v1/reach/ci/checks/{id}/l3-record`, 없으면 404 → L3 없이 올림) 오늘의 판정 데이터·취약점 목록과 다시 대조한다. 그래서 이미지는 그대로인데 새 CVE가 나오거나 판정 데이터가 늘어도 L3 근거가 붙는다. 이렇게 나온 결과는 `l3.run.rematch`가 true이고 관측 시각은 처음 관측한 때다. 클래스 파일은 지금처럼 같은 digest 이미지의 jar에서 꺼낸다
- `manual` 작업(대시보드 요청 스캔)은 앱을 띄우지 않는다. 재대조가 아니면 L3가 없다
- 한계: 기동 구간에는 준비 확인 요청이 들어 있다. 요청 뒤에 앱이 백그라운드로 하는 일은 다음 구간에 잡힐 수 있다. 러너의 설정(프로필, stub)이 운영과 다르면 결과가 다를 수 있어 설정 키를 근거에 남긴다
- 걸리는 시간(로컬, Re:Used api): 앱 기동 11~13초(에이전트 없이 9초), 요청 36개·구간 16개 기록까지 24초, 대조(리포트 16개) 약 5초. 메모리 약 540MB(에이전트 없이 470MB). 실행 기록 합계 2.4MB

## 돌리기 전에 필요한 것

| 무엇 | 어디에 | 상태 |
| --- | --- | --- |
| 대시보드 주소 | 서비스 저장소 변수 `REACH_URL`(API), `REACH_UI_URL`(화면, 선택) | Logssey 설치는 `https://logssey.re-used.store` (둘 다) |
| 감시 대상 등록 | 대시보드 설정 `logssey.reach.apps`에 이 레포(`repo`, 하위 경로면 `path`)와 이미지 저장소(`image`)를 앱 코드로 등록한다(PRD FR-15). 스크립트는 app을 보내지 않고(`APP`을 주면 그 값) 대시보드가 이 설정으로 정한다. 등록 안 된 레포·이미지는 422 | 설치마다 |
| 이미지 저장소 | 서비스 저장소 변수 `REACH_ECR_REPOSITORY`(예: `logssey/reused-api`). 없으면 이미지 작업을 건너뛴다 | 설치마다 |
| CI 인증 | 대시보드가 `/api/v1/reach/ci/**`에서 GitHub OIDC 토큰(`aud = logssey-reach`)을 받는다. 스크립트는 호출마다 새 토큰을 받아 `Authorization: Bearer`로 보낸다. 대시보드 설정 `logssey.reach.ci.repository-owner`(조직 이름)가 있어야 받고, PR 검사는 `pull_request` 이벤트, 이미지 검사는 기본 브랜치(`logssey.reach.ci.default-branch`, 기본 `main`)에서만 받는다. 조건은 API 명세 2-2 | 구현됨. 설치마다 조직 설정 |
| dashboard-backend 읽기 | GitHub App 토큰. 비밀값 `REACH_APP_ID`, `REACH_APP_PRIVATE_KEY`(서비스 CI/CD의 gitops 토큰과 같은 방식) | 앱 미정. 나중에 분석기 이미지(GHCR)로 바꾸면 필요 없다 |
| ECR 읽기 역할 | 비밀값 `REACH_ECR_READ_ROLE_ARN`. `ecr:DescribeImages`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken`만. 신뢰 정책은 이 저장소의 기본 브랜치 실행(`sub = repo:<조직>/<레포>:ref:refs/heads/<기본 브랜치>`, `image`의 `workflow_run`과 `manual`의 `workflow_dispatch`)으로 제한. 이 레포가 스캔할 이미지 저장소마다 읽기 권한 | Logssey 설치: infrastructure `logssey-dashboard/reach-ci.tf`(`logssey-dashboard-role-reach-ci-ecr-read`). 없거나 그 저장소 권한이 없으면 이미지 대상 `manual`은 `IMAGE_PULL_FAILED` |
| 대시보드가 워크플로를 띄우는 앱 | 대시보드 설정 `logssey.reach.dispatch.app-id`·`private-key`(운영은 `/run/secrets` 파일). 권한은 `Actions: write` 하나, 감시 대상 서비스 저장소에만 설치. 위 dashboard-backend 읽기 앱과 따로 둔다(그 앱 키는 서비스 CI가 쓴다). 설정이 없으면 대시보드 스캔 요청은 `QUEUED`로 남는다 | 미정 |
| `REACH_REF` | 서비스 저장소 변수(Settings → Secrets and variables → Actions → Variables). 이 폴더가 들어간 dashboard-backend `develop`의 커밋(40자) | 규칙·분석기·스크립트가 바뀌어 머지되면 대시보드 배포가 값을 그 커밋으로 옮긴다(아래 "판정 데이터·분석기를 바꾼 뒤"). 모든 작업이 시작할 때 값이 40자 커밋이고 `develop`에 들어 있는지 확인하며, 비어 있거나 다른 브랜치의 커밋이면 아무것도 받지 않고 멈춘다. `manual` 작업은 `reach-scan.sh`의 `MODE=MANUAL`이 들어간 커밋(#113) 이후, jar 없는 대상은 `--no-l2`가 들어간 커밋 이후, 재대조(`rescan_of`)는 `RESCAN_OF`가 들어간 커밋 이후여야 한다 |

## 판정 데이터·분석기를 바꾼 뒤

서비스 저장소의 스캔은 변수 `REACH_REF`가 가리키는 커밋의 판정 데이터·분석기·스크립트를 쓴다. 이 저장소에 머지한 것만으로는 스캔에 반영되지 않고, 변수가 그 커밋으로 옮겨져야 한다.

**자동**: 이 저장소 `develop`에 머지하면 Dashboard deploy가 API를 배포한 뒤 `reach-ref` 작업(`.github/scripts/reach-ref-set.sh`)이 변수를 그 커밋으로 옮긴다. 배포가 실패하면 옮기지 않는다(새 스크립트가 올리는 결과를 옛 API가 받지 못할 수 있어 배포가 먼저다). 값은 앞으로만 간다: 옛 실행을 다시 돌려도 더 새 값은 그대로 둔다.

| 설정 (이 저장소) | 값 |
| --- | --- |
| 변수 `REACH_REF_REPOSITORIES` | 변수를 옮길 서비스 저장소 이름(쉼표로 구분, 예: `service-backend`). 비어 있으면 작업을 건너뛴다 |
| 비밀값 `REACH_REF_APP_ID`, `REACH_REF_APP_PRIVATE_KEY` | 위 서비스 저장소에 설치되고 저장소 권한 `Variables: Read and write`가 있는 GitHub App. Logssey 설치는 대시보드가 워크플로를 띄우는 앱(`logssey.reach.dispatch.*`)에 이 권한을 더해 같이 쓴다(키는 따로 하나 더 받아 넣는다) |

- 변수 `REACH_REF` 자체는 서비스 저장소마다 한 번 손으로 만들어 둔다(작업은 있는 값을 바꾸기만 한다)
- 그 뒤에 시작하는 스캔부터 새 값을 쓴다: 다음 PR·이미지 검사, 대시보드의 [새 스캔]·[다시 대조], 매일 재대조. 어느 커밋으로 돌았는지는 각 스캔 실행의 요약(Summary)에 `Reach code: …@<커밋>`으로, 변수를 언제 무엇으로 옮겼는지는 Dashboard deploy 실행의 요약에 남는다
- **손으로**: 설정이 없거나 되돌려야 할 때는 서비스 저장소의 변수 값을 직접 바꾼다. 되돌린 값은 다음 배포가 다시 앞으로 옮긴다(되돌린 커밋이 새 커밋에 들어 있으므로). 막으려면 `REACH_REF_REPOSITORIES`를 비운다
- `reach.yml` 자체(단계, 입력)가 바뀐 경우에만 서비스 저장소의 사본을 다시 복사해 PR로 올린다

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
- L3: `IMAGE_REF=<이미지> JAR=<그 이미지의 app.jar> SCENARIO=<서비스 저장소>/.reach/l3-scenario.json JACOCO_HOME=/tmp/reach-bin/jacoco OUT=reach-out/l3 bash deploy/reach/ci/l3-run.sh` 뒤 `reach-scan.sh`에 `JACOCO_HOME=/tmp/reach-bin/jacoco L3_SEGMENTS=reach-out/l3/segments L3_RUN=reach-out/l3/run.json`을 더한다. `JACOCO_HOME`과 `TMPDIR`은 Docker가 마운트할 수 있는 곳이어야 한다
- 대시보드에서 요청한 스캔은 `MODE=MANUAL CHECK_ID=<검사 ID> TARGET_TYPE=REPO`(또는 `IMAGE`와 `IMAGE_REF`)로 같은 jar를 준다. 확인용 백엔드에 띄우는 설정이 없으면 스캔 요청이 `QUEUED`로 남아 이렇게 손으로 올려 볼 수 있다.
