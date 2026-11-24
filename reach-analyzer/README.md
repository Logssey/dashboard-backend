# Reach L2 분석기

스캐너가 찾은 CVE마다 "앱 코드에서 실제로 취약 함수에 닿는가"를 판정한다. 결과는 **도달 가능 / 도달 불가 / 미확인** 중 하나이고, 근거(호출 경로 또는 앱 코드의 사실)를 같이 남긴다. 설계는 `security-solution-docs/reachability-analysis`(ARD, 규칙 명세)를 따른다.

대시보드 서버와 따로 도는 명령줄 도구다. 감시 대상 서비스의 CI가 bootJar를 빌드한 뒤 실행하고, 결과는 `verdict/bundle.py`가 API-13 결과 묶음으로 바꿔 대시보드에 올린다(CI 연결은 다음 단계). 서버(`bootJar`)는 이 모듈에 의존하지 않는다.

## 구성

| 경로 | 내용 |
|---|---|
| `src/main/java/com/logssey/reach/analyzer/` | 분석기 (Java 21, ASM). bootJar의 바이트코드로 호출 그래프를 만들고 사실을 모은다 |
| `verdict/verdict.py` | 분석 결과 + 규칙 (+ Trivy 보고서, 레포 설정 파일) → CVE별 판정 |
| `verdict/bundle.py` | SBOM + 스캐너 결과(Trivy, Grype) + 분석 결과 + 판정 → API-13 결과 묶음(gzip) |
| `verdict/l3.py` | L3: JaCoCo XML(앱을 띄워 시나리오를 돌린 실행 기록) + 취약 구간(`vuln-functions.json`의 `l3`) + L2 호출 경로 → CVE별로 실제 실행이 어디까지 갔는지(구간·함수), 어느 요청에서인지. L2 판정을 바꾸지 않는 근거 |
| `verdict/l3_runner.py` | L3 러너 도우미: 서비스 저장소의 시나리오(JSON) 검사·실행, 요청 단계마다 실행 기록 끊기, 리포트용 클래스 파일 준비, 에이전트 기록 범위. `deploy/reach/ci/l3-run.sh`·`reach-scan.sh`가 부른다 |
| `../src/main/resources/reach/` | 판정 데이터. `vuln-functions.json`(CVE 16개의 취약 함수 49개), `rules.json`(사실·CVE별 규칙). 대시보드 API-09·10도 같은 파일을 쓴다 |
| `vulndata/` | 새 CVE의 판정 데이터 만들기: `vulndata.py`(자료 모으기·초안 검사·반영), `PROMPT.md`(AI에게 주는 지시문). 아래 "판정 데이터 만들기" |
| `src/main/java/…/MethodDiff.java` | 라이브러리 두 버전의 jar에서 코드가 바뀐 메서드와 줄 번호. `vulndata.py`가 쓴다 |
| `research/` | 취약 함수를 찾은 근거: CVE별 조사 JSON, 노트, BouncyCastle 재현 코드. 버전별 소스·diff 원본(약 14MB)은 넣지 않았다. `research/vulndata/`는 `vulndata.py`로 넣은 CVE의 기록(누가 확인했는지, 비교한 jar, AI가 남긴 확인 사항) |
| `scripts/make_spec.py` | 처음 14개 CVE를 만든 방법: `research/*.json` → `vuln-functions.json`. 다시 돌려도 `l3`와 `vulndata.py`로 넣은 CVE는 그대로 둔다 |
| `scripts/run-reach.sh` | 서비스 레포에 한 번에 돌리기 |
| `fixtures/` | 샘플 앱 5개(소스)와 사람이 정한 기대값 `expected.json` |
| `docs/` | PoC 작업 기록(`WORKLOG.md`), 실제 서비스에 대한 사람의 판정(`answer-key.md`) |

## 빌드·테스트

```bash
./gradlew :reach-analyzer:jar           # build/libs/reach-analyzer.jar (ASM 포함, java -jar로 실행)
./gradlew :reach-analyzer:fixtureTest   # 샘플 앱 7개 판정을 expected.json과 비교
./gradlew :reach-analyzer:verdictTest   # bundle.py·l3.py·l3_runner.py 단위 테스트
./gradlew :reach-analyzer:vulndataTest  # vulndata.py 단위 테스트 + MethodDiff(작은 jar 두 개를 만들어 비교)
```

`fixtureTest`·`verdictTest`·`vulndataTest`는 bash, `javac`, `jar`, `python3`이 필요해 `check`(`./gradlew build`·`test`)에는 넣지 않았다. 샘플 앱은 실제 bcprov 1.78.1, Jackson 2.16.1, commons-logging 1.3.0 jar를 넣어 만든다(Gradle이 받는다). Spring MVC·Boot·Tomcat은 실제 클래스·메서드 이름을 가진 스텁이다.

## 실행

```bash
REPO=<서비스 레포> OUT=<결과 폴더> bash reach-analyzer/scripts/run-reach.sh
```

직접 실행:

```bash
java -Xmx3g -jar reach-analyzer/build/libs/reach-analyzer.jar --app <bootJar 또는 압축 푼 폴더> \
  --spec src/main/resources/reach/vuln-functions.json --rules src/main/resources/reach/rules.json --out reach-result.json

python3 reach-analyzer/verdict/verdict.py --reach reach-result.json \
  --spec src/main/resources/reach/vuln-functions.json --rules src/main/resources/reach/rules.json \
  [--trivy <trivy.json>] [--repo <레포 경로>] --out verdicts.json --md verdicts.md
```

## 결과 묶음 (API-13)

스캐너 결과와 판정을 API-13이 받는 묶음으로 바꾼다. 스캐너가 찾은 매칭(purl × CVE) 하나가 Finding 하나다.

```bash
trivy rootfs --format cyclonedx -o sbom.cdx.json <bootJar가 든 폴더>     # SBOM
trivy sbom --format json -o trivy.json sbom.cdx.json                     # 대조
grype sbom:sbom.cdx.json -o json --file grype.json                       # 교차 확인 (선택)
python3 reach-analyzer/verdict/verdict.py ... --trivy trivy.json --out verdicts.json   # 위 "직접 실행"

python3 reach-analyzer/verdict/bundle.py --sbom sbom.cdx.json --trivy trivy.json --grype grype.json \
  --reach reach-result.json --verdicts verdicts.json \
  --spec src/main/resources/reach/vuln-functions.json --rules src/main/resources/reach/rules.json \
  --jar <bootJar> --stage sbom=succeeded:4 --stage match=succeeded:6 --stage l2=succeeded:15 \
  --out bundle.json.gz

# API-12로 검사를 등록한 뒤 (Content-Type이 없으면 form으로 읽혀 500이 난다)
curl -X PUT -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' \
  --data-binary @bundle.json.gz <대시보드>/api/v1/reach/ci/checks/<checkId>/results
```

- 판정한 CVE·패키지는 `verdicts.json`의 판정과 근거를 API 모양(명세 3-4, 3-5)으로 옮긴다. 사실 → 메모 → 적용 규칙 → 호출 경로 순서다. 호출 그래프가 취약 함수에 닿으면 규칙으로 판정했어도 후보 경로와 그 이유(메모)를 남긴다.
- 스캐너가 판정한 CVE를 판정 데이터 좌표와 **groupId가 같고 버전이 분석기가 읽은 데이터 jar(`reach-result.json` `package.jars`)와 같은 다른 jar**에 붙였으면(Grype가 Tomcat WebSocket CVE를 `tomcat-embed-core`에) 데이터 좌표의 판정과 근거를 그대로 쓰고, 맨 앞에 그 사실을 적은 메모를 더한다. 취약 함수는 클래스 이름으로 앱의 모든 jar에서 찾으므로 스캐너가 어느 jar를 댔는지와 판정은 상관없다. 서버(`ReachL3Input`)는 묶음이 이렇게 판정을 준 행에만 같은 CVE·같은 groupId의 L3 결과를 붙인다(잇는 기준은 여기 한 곳).
- 판정하지 않은 매칭은 `NOT_ANALYZED`와 사유: OS 패키지(`OS_PACKAGE`), maven이 아닌 생태계(`UNSUPPORTED_ECOSYSTEM`), 판정한 CVE의 groupId나 버전이 다른 패키지 사본(`UNANALYZED_COPY`, 예: 데이터는 Jackson 3 `tools.jackson.*`인데 Jackson 2 `com.fasterxml.*`), 취약 함수 데이터 없음(`NO_VULN_FUNCTION_DATA`).
- Trivy와 Grype가 같은 purl × CVE를 찾으면 한 Finding이다(Grype의 GHSA는 연결된 CVE로 맞춘다). 심각도가 다르면 Trivy 값을 쓰고 `severityNote`에 둘 다 남긴다.
- `vulnFunctionIds`는 `vuln-functions.json`의 함수 순서(API-10 id), `engine`의 버전은 두 데이터 파일의 스키마 버전(API-09·10 `version`)과 같다.
- Java 코드가 없는 대상(npm만, OS 패키지만)은 L2를 돌리지 않는다. `--reach`·`--verdicts`를 빼면 모든 매칭이 `NOT_ANALYZED`이고 `reachResult`는 빈 객체다. maven 패키지가 있는데 둘을 빼면 L2를 빠뜨린 것이라 실패한다.
- 러너가 분석 전에 실패했으면 `--failure-code`, `--failure-stage`, `--failure-message`로 실패 묶음(`tools`·`stages`·`failure`)만 만든다.
- 데이터 파일과 판정(`verdicts.json`)이 맞지 않으면(데이터에 있는 CVE·패키지인데 판정이 없음) 묶음을 만들지 않고 실패한다.

## L3 실행 확인

앱(같은 이미지)을 JaCoCo 에이전트와 함께 띄우고 요청 시나리오를 돌린 뒤, 취약 코드 쪽으로 **실제로 어디까지 실행됐는지**를 근거로 남긴다(PRD FR-14). L3는 L2 판정 옆에 놓는 근거이고 판정(status)을 바꾸지 않는다. L2가 무엇이라고 했든 판정 데이터가 있는 모든 CVE를 본다.

```bash
# 실행 기록(구간마다 1개) → XML. 클래스 파일은 그 이미지의 jar에서(verdict/l3_runner.py classes)
java -jar jacococli.jar report segments/001.exec --classfiles <클래스 폴더> --xml xml/001.xml
python3 reach-analyzer/verdict/l3.py --spec src/main/resources/reach/vuln-functions.json \
    --segments xml/ --sbom sbom.cdx.json --reach reach-result.json --scope '<에이전트 includes>' --out l3-result.json
```

- 실행 기록은 **구간**으로 나뉜다: `startup`(앱이 준비될 때까지, 준비 확인 요청 포함)과 시나리오 단계마다 하나(`001`, `002`, …). 그래서 결과가 "어느 요청에서 실행됐는지"를 말한다. 러너 쪽은 `deploy/reach/ci/README.md` "L3".
- 메서드가 아니라 **취약 구간** 단위로 본다. Tomcat `RealmBase.findSecurityConstraints`는 요청마다 실행되지만, 취약한 `/xxx/*` 비교 줄은 보안 제약이 있을 때만 실행된다.
- 취약 구간은 `vuln-functions.json` CVE마다 `l3`에 둔다: `version`(줄 번호가 맞는 라이브러리 버전), `regions`(클래스·메서드·desc·소스 파일·`lines` 줄 범위), `note`. 취약 버전과 수정 버전의 소스 jar를 비교해 sink 메서드 안에서 바뀐 줄로 잡고 사람이 골랐다(호출하는 쪽 sink에는 두지 않는다). `lines`가 없으면 메서드 전체다(bcprov 배포 jar에는 줄 번호가 없다).
- CVE마다 도달 수준 `reached`. SBOM에 없는 패키지의 CVE는 넣지 않는다.
  - `REGION`: 취약 구간이 실행됨
  - `FUNCTION`: 취약 함수(sink 메서드)는 실행됐지만 구간은 아님. `regionsChecked`가 true면 구간을 봤고 실행되지 않은 것, false면 구간을 확인하지 못한 것(라이브러리 버전이 `version`과 다름, 구간 데이터 없음, 줄 번호 없는 클래스)
  - `NONE`: 모두 확인할 수 있었고 실행된 것이 없음. 시나리오가 그 코드를 안 탔다는 뜻일 뿐 도달 불가의 근거가 아니다
  - `NOT_RECORDED`: 실행된 것이 없고 확인할 수 없는 것이 있음(기록 범위 밖, 리포트에 그 클래스가 없음)
- 근거
  - `during`: 그 수준에 닿은 구간 목록. `startupOnly`가 true면 앱이 뜨는 동안에만 실행된 것(요청으로 실행된 것과 구분)
  - `functions`, `regions`: 실행된 취약 함수와 구간마다 자기 `during`, 구간은 실행된 줄(`executedLines`). 확인하지 못한 구간에는 이유 `unchecked`(`OTHER_VERSION`, `OUT_OF_SCOPE`, `NO_CLASS_FILE`, `NO_METHOD`, `NO_LINE_NUMBERS`)
  - `paths`: L2가 호출 그래프로 경로를 찾은 sink마다(`--reach`) 진입점부터 **끊기지 않고** 실행된 단계 수(`reachedStep`/`of`). 진입점이 실행되지 않았으면 0이고, 중간 메서드가 다른 길로 실행된 것은 세지 않는다. 규칙으로 판정한 CVE(프레임워크가 부르는 코드)에는 경로가 없을 수 있다
- JaCoCo가 못 보는 것
  - 한 줄에서 부른 메서드가 예외를 던지면 그 줄은 실행됐어도 미실행으로 나온다. 이때 결과는 `FUNCTION`(함수까지)으로 남는다
  - 클래스 파일이 실행된 것과 다르면(다른 jar) 그 클래스는 전부 미실행으로 나온다. `jacococli`가 `does not match` 경고를 내니 그때는 결과를 쓰지 않는다
  - 에이전트가 뜨기 전에 로드된 JDK 클래스(`HashMap`, `regex.Pattern` 등)는 기록되지 않는다. 클래스 파일을 주지 않은 클래스는 `NOT_RECORDED`가 된다
  - 요청 뒤에 앱이 백그라운드로 하는 일은 다음 구간에 잡힐 수 있다
- 에이전트 범위: `includes=*`에 `inclbootstrapclasses=true`를 같이 주면 JVM이 뜨지 않는다. JDK는 `java.util.*`처럼 패키지를 골라 넣는다.

## 판정 데이터 만들기

판정 데이터가 없는 CVE는 `NO_VULN_FUNCTION_DATA`로 남는다. 새 CVE의 데이터는 세 단계로 만든다. AI는 후보까지만 만들고, 사람이 확인한 것만 데이터가 된다(PRD NFR-04).

| 단계 | 누가 | 하는 일 |
|---|---|---|
| `prepare` | 도구 | 권고문(GitHub Advisory Database. 검토 전 권고문에는 패키지가 없어, 그때는 CVE 기록의 영향 버전과 `--coordinates`로 채운다) → 설치 버전과 수정 버전의 jar·소스(Maven Central) → 코드가 바뀐 메서드(`MethodDiff`) → 권고문의 수정 커밋으로 후보를 좁힘 → 메서드마다 수정이 건드린 줄(L3 취약 구간 후보) |
| 초안 | AI | 묶음 폴더의 `PROMPT.md`대로 `draft.json`을 쓴다: 취약 함수, 호출 방식, 요약, 취약 구간, 사람이 확인할 것 |
| `check` → `apply` | 도구, 사람 | 초안이 가리키는 메서드·줄이 설치 버전 jar에 실제로 있는지 검사하고 검토 문서 `REVIEW.md`를 만든다. 사람이 확인한 뒤 `vuln-functions.json`에 넣는다 |

```bash
./gradlew :reach-analyzer:jar
cd reach-analyzer/vulndata

# 1. 자료 모으기. --installed는 서비스가 쓰는 버전(SBOM), --coordinates는 권고문에 패키지가 여럿일 때만
python3 vulndata.py prepare --cve CVE-2026-65637 --coordinates org.apache.tomcat.embed:tomcat-embed-core \
    --installed 11.0.24 --out ~/.vulndata/CVE-2026-65637

# 2. 초안: AI에게 그 폴더의 PROMPT.md를 따라 draft.json을 쓰게 한다 (예: Claude Code에서
#    "~/.vulndata/CVE-2026-65637/PROMPT.md를 따라 draft.json을 써 줘")

# 3. 검사. 오류가 있으면 종료 코드 1. REVIEW.md를 사람이 읽는다
python3 vulndata.py check ~/.vulndata/CVE-2026-65637

# 4. 확인이 끝나면 반영. 확인한 사람 이름이 research/vulndata/<CVE>.json에 남는다
python3 vulndata.py apply ~/.vulndata/CVE-2026-65637 --reviewed-by <이름>
```

**권고문이 아직 검토 전일 때**(GitHub Advisory Database에 `unreviewed`로만 있음. 최근 Tomcat CVE 다수가 그렇다): 권고문에 Maven 패키지·수정 버전·수정 커밋이 없다. 그때는 `--coordinates`를 꼭 주면 도구가 공식 CVE 기록(`cveawg.mitre.org`)의 영향 버전 범위로 채운다. 범위가 "이하(≤)"로 끝나면 수정 버전은 Maven Central에서 그 다음 릴리스다. 심각도·CVSS도 CVE 기록에서 가져온다(`advisory.md`의 "versions from"). 수정 커밋은 프로젝트 보안 페이지(Tomcat은 `tomcat.apache.org/security-11.html`의 "fixed with commit")에서 찾아 `--commit`으로 준다(여러 번 가능). 수정 커밋이 없으면 두 릴리스 사이에 바뀐 메서드가 모두 후보가 된다.

```bash
python3 vulndata.py prepare --cve CVE-2026-76183 --coordinates org.apache.tomcat.embed:tomcat-embed-websocket \
    --installed 11.0.24 --commit https://github.com/apache/tomcat/commit/e182d86b7d4cc19ec4c24c38f37acc004404fe8e \
    --out ~/.vulndata/CVE-2026-76183
```

묶음 폴더는 저장소 밖에 둔다(jar와 소스가 들어 있어 수십 MB다). Python 표준 라이브러리만 쓰고, 네트워크는 `api.github.com`·`github.com`·`cveawg.mitre.org`·`repo1.maven.org`에만 나간다. GitHub 요청 한도에 걸리면 `GITHUB_TOKEN`을 준다(`api.github.com`에만 보낸다).

`check`가 오류로 막는 것(사람 판단과 상관없이 틀린 것): jar에 없는 클래스·메서드·descriptor, 실행 코드가 없는 줄만 잡은 구간, 줄 번호가 없는 jar에 줄을 적은 구간, 권고문에서 온 값(패키지·버전·심각도)을 바꾼 것, 한국어 요약 없음. 확인으로 남기는 것(`REVIEW.md`에 표시): 수정에서 바뀌지 않은 메서드를 취약 함수로 잡은 것, 수정이 건드린 줄과 겹치지 않는 구간, 프레임워크가 실행하는 코드인데 `rules.json`에 규칙이 없는 것.

반영한 뒤 할 일:

- 호출 방식이 `app_calls_library`가 아니면 `rules.json`에 그 CVE의 규칙을 쓴다(사람이 쓴다). 규칙이 없으면 호출 그래프만으로 판정해 "도달 불가"가 잘못 나올 수 있다. 사실(fact)을 더하면 `ReachRuleServiceTest`의 기대값도 고친다.
- `fixtureTest`·`verdictTest`와 `./gradlew :test --tests 'com.logssey.reach.rule.*'`를 돌리고, 서비스 jar에 분석기를 돌려 판정을 읽는다.
- 데이터·규칙은 PR 하나로 올린다. 화면(API-09·10)과 분석이 같은 파일을 쓴다.

한계:

- Maven Central에 있는 Java 라이브러리만 된다. JDK 자체의 취약점은 비교할 jar가 없다.
- 스캐너가 CVE를 제품 이름으로 붙인 경우(Grype의 NVD 대조) 취약한 코드가 그 jar에 없을 수 있다. 예: CVE-2026-86248은 `tomcat-embed-core`에 붙지만 코드는 별도 jar `tomcat-coyote-ffm`에 있다. 그때는 그 jar의 대표 메서드를 sink로 두고 규칙(jar 유무)으로 판정한다.
- 후보는 "수정 커밋이 건드린 클래스 근처에서 코드가 바뀐 메서드"다. 데이터만 고친 수정(차단 목록 등)이나 권고문에 수정 커밋이 없는 CVE는 바뀐 메서드 전체가 후보가 되고, AI가 `method-diff.tsv`와 소스에서 찾는다. 사람 데이터가 있는 14개 CVE로 돌리면 13개에서 사람이 고른 취약 함수가 후보에 들어 있다(없는 하나는 차단 목록만 고친 CVE-2026-83557).
- 초안의 취약 함수는 그 패키지의 설치 버전 jar에 있는 메서드만 된다. 다른 라이브러리에서 부르는 쪽이나 다른 버전에서 바뀐 이름은 도구가 확인할 수 없어 `check`가 막는다. 필요하면 반영한 뒤 사람이 직접 더한다(분석기는 라이브러리 안의 호출을 따라가므로 부르는 쪽은 대개 필요 없다).
- 취약 구간의 줄 번호는 설치 버전 하나의 것이다. 서비스가 라이브러리 버전을 올리면 L3는 그 CVE를 "함수까지"로만 보인다.

## 판정 방식

- **호출 그래프**: bootJar의 바이트코드로 RTA 호출 그래프를 만든다. Spring 진입점(컨트롤러, `@Bean`, 리스너)과 모든 앱 메서드에서 출발해 취약 메서드에 닿는지 본다.
- **규칙**: 프레임워크가 스스로 실행하는 코드(Tomcat 인증, Spring MVC의 Jackson 변환)는 호출 그래프에 나오지 않는다. 그래서 "앱이 그 기능을 설정·사용하는가"를 사실로 확인한다. 규칙은 CVE마다 사람이 쓴다.
- **원칙**: 확신이 없으면 미확인이다. 취약 메서드가 jar에 없으면(버전 차이) 도달 불가가 아니라 미확인이다.

## 한계

- 리플렉션, 동적 프록시, JNI는 모델링하지 않는다(`fixtures/fixture-src/app-blindspots`에 알려진 누락으로 고정).
- 요청 본문을 타입 변수로 받는 공통 컨트롤러(`CrudController<T>`의 `create(@RequestBody T)`)는 하위 타입이 준 타입 인자를 DTO로 본다(`app-generic`). 그 메서드가 앱 밖(라이브러리 jar)의 클래스에 선언돼 있으면 아직 보지 못한다.
- JDK 내부 코드는 분석하지 않는다. JDK가 다시 불러줄 수 있는 메서드는 "약한 경로"로 표시한다.
- 런타임 설정(JRE의 `java.security` 등)은 이미지에서 따로 확인해야 한다. 레포 안의 설정 파일만 `--repo`로 본다.

## 라이선스

- jar에 ASM 9.8(BSD-3-Clause)이 들어 있다. 원문: jar 안의 `META-INF/ASM-LICENSE.txt`.
- `fixtures/fixture-src/spring-security-crypto/`는 Spring Security 7.1.1 공식 소스(Apache-2.0)이며 테스트에만 쓴다.
