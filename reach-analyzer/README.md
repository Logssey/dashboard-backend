# Reach L2 분석기

스캐너가 찾은 CVE마다 "앱 코드에서 실제로 취약 함수에 닿는가"를 판정한다. 결과는 **도달 가능 / 도달 불가 / 미확인** 중 하나이고, 근거(호출 경로 또는 앱 코드의 사실)를 같이 남긴다. 설계는 `security-solution-docs/reachability-analysis`(ARD, 규칙 명세)를 따른다.

대시보드 서버와 따로 도는 명령줄 도구다. 감시 대상 서비스의 CI가 bootJar를 빌드한 뒤 실행하고, 결과는 `verdict/bundle.py`가 API-13 결과 묶음으로 바꿔 대시보드에 올린다(CI 연결은 다음 단계). 서버(`bootJar`)는 이 모듈에 의존하지 않는다.

## 구성

| 경로 | 내용 |
|---|---|
| `src/main/java/com/logssey/reach/analyzer/` | 분석기 (Java 21, ASM). bootJar의 바이트코드로 호출 그래프를 만들고 사실을 모은다 |
| `verdict/verdict.py` | 분석 결과 + 규칙 (+ Trivy 보고서, 레포 설정 파일) → CVE별 판정 |
| `verdict/bundle.py` | SBOM + 스캐너 결과(Trivy, Grype) + 분석 결과 + 판정 → API-13 결과 묶음(gzip) |
| `../src/main/resources/reach/` | 판정 데이터. `vuln-functions.json`(CVE 14개의 취약 함수 46개), `rules.json`(사실·CVE별 규칙). 대시보드 API-09·10도 같은 파일을 쓴다 |
| `research/` | 취약 함수를 찾은 근거: CVE별 조사 JSON, 노트, BouncyCastle 재현 코드. 버전별 소스·diff 원본(약 14MB)은 넣지 않았다 |
| `scripts/make_spec.py` | `research/*.json` → `vuln-functions.json` 생성 |
| `scripts/run-reach.sh` | 서비스 레포에 한 번에 돌리기 |
| `fixtures/` | 샘플 앱 5개(소스)와 사람이 정한 기대값 `expected.json` |
| `docs/` | PoC 작업 기록(`WORKLOG.md`), 실제 서비스에 대한 사람의 판정(`answer-key.md`) |

## 빌드·테스트

```bash
./gradlew :reach-analyzer:jar           # build/libs/reach-analyzer.jar (ASM 포함, java -jar로 실행)
./gradlew :reach-analyzer:fixtureTest   # 샘플 앱 5개 판정을 expected.json과 비교
./gradlew :reach-analyzer:verdictTest   # bundle.py 단위 테스트
```

`fixtureTest`·`verdictTest`는 bash, `javac`, `jar`, `python3`이 필요해 `check`(`./gradlew build`·`test`)에는 넣지 않았다. 샘플 앱은 실제 bcprov 1.78.1, Jackson 2.16.1, commons-logging 1.3.0 jar를 넣어 만든다(Gradle이 받는다). Spring MVC·Boot·Tomcat은 실제 클래스·메서드 이름을 가진 스텁이다.

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
- 판정하지 않은 매칭은 `NOT_ANALYZED`와 사유: OS 패키지(`OS_PACKAGE`), maven이 아닌 생태계(`UNSUPPORTED_ECOSYSTEM`), 판정한 CVE의 다른 패키지 사본(`UNANALYZED_COPY`), 취약 함수 데이터 없음(`NO_VULN_FUNCTION_DATA`).
- Trivy와 Grype가 같은 purl × CVE를 찾으면 한 Finding이다(Grype의 GHSA는 연결된 CVE로 맞춘다). 심각도가 다르면 Trivy 값을 쓰고 `severityNote`에 둘 다 남긴다.
- `vulnFunctionIds`는 `vuln-functions.json`의 함수 순서(API-10 id), `engine`의 버전은 두 데이터 파일의 스키마 버전(API-09·10 `version`)과 같다.
- Java 코드가 없는 대상(npm만, OS 패키지만)은 L2를 돌리지 않는다. `--reach`·`--verdicts`를 빼면 모든 매칭이 `NOT_ANALYZED`이고 `reachResult`는 빈 객체다. maven 패키지가 있는데 둘을 빼면 L2를 빠뜨린 것이라 실패한다.
- 러너가 분석 전에 실패했으면 `--failure-code`, `--failure-stage`, `--failure-message`로 실패 묶음(`tools`·`stages`·`failure`)만 만든다.
- 데이터 파일과 판정(`verdicts.json`)이 맞지 않으면(데이터에 있는 CVE·패키지인데 판정이 없음) 묶음을 만들지 않고 실패한다.

## 판정 방식

- **호출 그래프**: bootJar의 바이트코드로 RTA 호출 그래프를 만든다. Spring 진입점(컨트롤러, `@Bean`, 리스너)과 모든 앱 메서드에서 출발해 취약 메서드에 닿는지 본다.
- **규칙**: 프레임워크가 스스로 실행하는 코드(Tomcat 인증, Spring MVC의 Jackson 변환)는 호출 그래프에 나오지 않는다. 그래서 "앱이 그 기능을 설정·사용하는가"를 사실로 확인한다. 규칙은 CVE마다 사람이 쓴다.
- **원칙**: 확신이 없으면 미확인이다. 취약 메서드가 jar에 없으면(버전 차이) 도달 불가가 아니라 미확인이다.

## 한계

- 리플렉션, 동적 프록시, JNI는 모델링하지 않는다(`fixtures/fixture-src/app-blindspots`에 알려진 누락으로 고정).
- JDK 내부 코드는 분석하지 않는다. JDK가 다시 불러줄 수 있는 메서드는 "약한 경로"로 표시한다.
- 런타임 설정(JRE의 `java.security` 등)은 이미지에서 따로 확인해야 한다. 레포 안의 설정 파일만 `--repo`로 본다.

## 라이선스

- jar에 ASM 9.8(BSD-3-Clause)이 들어 있다. 원문: jar 안의 `META-INF/ASM-LICENSE.txt`.
- `fixtures/fixture-src/spring-security-crypto/`는 Spring Security 7.1.1 공식 소스(Apache-2.0)이며 테스트에만 쓴다.
