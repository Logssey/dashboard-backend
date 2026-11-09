# Reach L2 분석기

스캐너가 찾은 CVE마다 "앱 코드에서 실제로 취약 함수에 닿는가"를 판정한다. 결과는 **도달 가능 / 도달 불가 / 미확인** 중 하나이고, 근거(호출 경로 또는 앱 코드의 사실)를 같이 남긴다. 설계는 `security-solution-docs/reachability-analysis`(ARD, 규칙 명세)를 따른다.

대시보드 서버와 따로 도는 명령줄 도구다. 감시 대상 서비스의 CI가 bootJar를 빌드한 뒤 실행하고, 결과는 API-13으로 대시보드에 올린다(결과 묶음 변환과 CI 연결은 다음 단계). 서버(`bootJar`)는 이 모듈에 의존하지 않는다.

## 구성

| 경로 | 내용 |
|---|---|
| `src/main/java/com/logssey/reach/analyzer/` | 분석기 (Java 21, ASM). bootJar의 바이트코드로 호출 그래프를 만들고 사실을 모은다 |
| `verdict/verdict.py` | 분석 결과 + 규칙 (+ Trivy 보고서, 레포 설정 파일) → CVE별 판정 |
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
```

`fixtureTest`는 bash, `javac`, `jar`, `python3`이 필요해 `check`(`./gradlew build`·`test`)에는 넣지 않았다. 샘플 앱은 실제 bcprov 1.78.1, Jackson 2.16.1, commons-logging 1.3.0 jar를 넣어 만든다(Gradle이 받는다). Spring MVC·Boot·Tomcat은 실제 클래스·메서드 이름을 가진 스텁이다.

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
