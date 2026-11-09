# 작업 기록: 판정 PoC (10/10)

각 단계마다 **무엇을 했는지, 왜 그렇게 판단했는지, 어떻게 했는지**를 남긴다.

---

## 0. 범위와 전제

- **목표**: 노션 계획 6-1(검증 마무리), 6-2(PoC) 중 클라우드 작업 공간에서 할 수 있는 것을 진행한다.
- **전제**: 이 작업 공간은 사용자 노트북에 연결되어 있지 않다. 실제 레포(`service-backend`), 이미지, AWS에는 접근할 수 없다.
- **그래서 이렇게 나눴다**
  - 여기서 직접 하는 것: CVE 조사, 판정 도구 작성, 샘플 앱으로 도구 검증
  - 노트북에서 돌리도록 준비만 하는 것: 실제 레포·이미지에 대한 확인과 판정 실행

---

## 1. 작업 환경 확인

### 무엇을 확인했나

| 항목 | 결과 |
|---|---|
| Java | OpenJDK 21.0.12 (우리 서비스와 같은 Java 21) |
| 빌드 도구 | Maven 3.9.11, Gradle 8.14.3 |
| Python | 3.13 |
| CPU·메모리 | 2코어, 7.8GB |
| Maven Central | **차단** (프록시가 403 반환) |
| GitHub 웹·API | **차단** (403) |
| raw.githubusercontent.com | 접근 가능 (소스 파일 원문 조회) |
| OSV, NVD, Tomcat·BouncyCastle 사이트, Docker Hub | 차단 |
| PyPI, npm | 접근 가능 |

### 로컬에 이미 설치된 라이브러리

| jar | 위치 | 용도 |
|---|---|---|
| ASM 9.8 | Maven 배포판 `lib/` | 바이트코드 분석 라이브러리 |
| bcprov-jdk18on 1.78.1 | Gradle 배포판 `lib/plugins/` | 실제 BouncyCastle 바이트코드로 테스트 |
| jackson-core·databind 2.16.1 | Gradle 배포판 `lib/` | 실제 Jackson(2.x) 바이트코드로 테스트 |
| commons-logging 1.3.0 | `/usr/share/java` | Spring Security 소스 컴파일용 |

### 판단

1. **SootUp은 여기서 테스트할 수 없다.** Maven Central이 막혀서 SootUp jar를 받을 수 없다. 테스트하지 못한 코드를 넘기는 건 위험하다고 판단했다.
2. **대신 ASM으로 호출 그래프 분석을 직접 구현한다.** ASM은 로컬에 이미 있고, Java 바이트코드 분석의 표준 라이브러리다(SootUp도 내부적으로 ASM으로 바이트코드를 읽는다). 알고리즘은 SootUp이 제공하는 것과 같은 계열(CHA, RTA)로 만든다. 노트북에서는 Maven Central에 접근할 수 있으니, 이후 정밀도를 높이고 싶으면 SootUp으로 교체할 수 있다.
3. **차단된 사이트는 우회하지 않는다.** 미러 사이트로 같은 내용을 받는 것은 하지 않고, 로컬에 있는 파일과 접근 가능한 출처만 쓴다.
4. **테스트용 샘플 앱은 실제 바이트코드와 스텁을 섞어 만든다.** BouncyCastle과 Jackson은 로컬에 있는 실제 jar를 쓰고, Spring Security의 Argon2 코드는 공개 소스(raw.githubusercontent.com)를 받아 컴파일한다. Spring MVC와 Tomcat처럼 구할 수 없는 부분은 클래스 이름과 호출 구조만 같은 스텁으로 만든다.

---

## 2. CVE 10개 조사 (정답지와 취약 함수 데이터)

### 무엇을 했나

- Tomcat 3개, BouncyCastle 2개, Jackson 5개를 라이브러리별로 나눠 병렬로 조사했다.
- CVE마다 취약한 버전과 고친 버전의 소스를 비교해서, 실제로 바뀐 메서드를 "취약 함수"로 정했다.

### 어떻게 했나

- github.com이 막혀 있어서 raw.githubusercontent.com으로 태그별 소스 파일을 받아 직접 diff했다.
- Tomcat은 보안 페이지 원본(tomcat-site 저장소의 `security-11.xml`)에서 수정 커밋 SHA를 얻고, 커밋 시점 파일과 태그 diff가 일치하는지 확인했다.
- JVM 메서드 디스크립터는 `javap`로 확인했다. BouncyCastle은 로컬 1.78.1 jar로, Tomcat은 시그니처 스텁을 컴파일해서 확인했다.
- 결함을 일부 재현했다. Tomcat 2건은 결함 로직을 옮겨 재현했고, BouncyCastle 2건과 Jackson 4건은 같은 결함이 있는 이전 버전의 실제 jar(bcprov 1.78.1, Jackson 2.16.1)로 재현했다. Jackson CVE-2026-89407은 2.16.1에 해당 메서드가 없어서 3.1.5의 정규식만 떼어 재현했다.
- 원본 근거(diff, 출처 URL)는 `data/research/*.json`, `*-notes.md`에 있다.

### 결과

| CVE | 취약 함수 | 발동 조건 | 누가 호출하나 |
|---|---|---|---|
| CVE-2026-65182 | `RealmBase.findSecurityConstraints` | 앱이 컨테이너 보안 제약을 추가하고, 한 컬렉션 안에서 긴 패턴이 짧은 패턴보다 먼저 옴 | 컨테이너 |
| CVE-2026-65905 | `DigestAuthenticator$NonceInfo.nonceCountValid` | Tomcat DIGEST 인증기 설치 | 컨테이너 |
| CVE-2026-68525 | `FormAuthenticator.restoreRequest`, `doAuthenticate` | Tomcat FORM 인증기 + 메서드별 제약 | 컨테이너 |
| CVE-2025-14813 | `G3413CTRBlockCipher.generateCRT` | GOST3412-2015 CTR 모드 사용 | 앱 코드 |
| CVE-2026-8763 | `PKIXNameConstraintValidator.emailIsConstrained` 등 | BouncyCastle로 인증서 경로 검증 | 앱 코드 + 런타임 설정 |
| CVE-2026-89407 | `NumberInput.looksLikeValidNumber` | 문자열로 온 값을 실수형 필드로 변환 | 프레임워크(Spring MVC) |
| CVE-2026-89425 | `UTF8DataInputJsonParser._reportInvalidToken` | DataInput API로 JSON 읽기 | 앱 코드 |
| CVE-2026-68497 | `CoreXMLDeserializers$Std._deserialize` | Duration·XMLGregorianCalendar 필드 | 프레임워크 |
| CVE-2026-91776 | `TypeDeserializerBase._findDeserializer` | @JsonTypeInfo + defaultImpl 같은 대체 동작 | 프레임워크 |
| CVE-2026-91777 | Collection/MapDeserializer 참조 누적기 | @JsonIdentityInfo 원소를 담는 컬렉션·맵 | 프레임워크 |

### 판단

1. **Tomcat 3개는 함수 도달만 보면 오탐이 난다.** Spring Boot 내장 Tomcat은 기본으로 NonLoginAuthenticator를 넣는다. 그래서 `AuthenticatorBase.invoke`와 `RealmBase.findSecurityConstraints`는 요청마다 실행된다. 다만 제약 목록이 비어 있어 취약한 구간에 들어가지 않는다. 그래서 "앱이 제약·인증기를 설정했나"를 보는 **규칙**으로 판정하기로 했다.
2. **Jackson 5개 중 4개는 데이터 타입이 결정한다.** readValue를 한 번이라도 부르면, 호출 그래프상 Jackson 내부의 거의 모든 역직렬화기에 닿는다(가상 호출의 과대 근사). 실제 취약 경로는 "어떤 타입을 역직렬화하느냐"에 달려 있다. 그래서 요청 본문 타입의 필드를 따라가는 규칙을 만들었다.
3. **BouncyCastle 2개는 호출 그래프로 판정할 수 있다.** 코드가 취약 클래스를 직접 부르는 구조라서다. 다만 CVE-2026-8763은 런타임 provider 순서에 따라 JDK의 TLS 검증이 BC로 갈 수 있어서, 그 설정은 규칙과 확인 스크립트로 따로 본다.
4. **수정 버전을 정정했다.**
   - Tomcat 10.1.x는 10.1.58이 릴리스되지 않아 실제 수정 버전은 10.1.59다(GHSA는 10.1.58로 표기).
   - bcprov는 CVE-2025-14813이 1.81.1에서, CVE-2026-8763이 1.85에서 고쳐진다. 둘 다 없애려면 1.85 이상이 필요하다.
   - 우리 앱 기준 업그레이드 대상: Tomcat 11.0.25, bcprov 1.85, Jackson 3.1.7 이상.
5. **심각도 표기 차이**: CVE-2025-14813을 Trivy는 CRITICAL로 보고했지만, CNA의 CVSS 벡터(C:H만 있음)로는 7.5(HIGH)다. 판정에는 영향이 없지만 보고서에는 출처를 같이 적는다.

---

## 3. 판정 도구 설계 (reach v0)

### 구성

| 파일 | 하는 일 |
|---|---|
| `tool/reach.jar` (Java 21 + ASM) | bootJar를 읽어 호출 그래프를 만들고, 취약 함수 도달 여부와 "사실(facts)"을 뽑는다 |
| `tool/verdict.py` (Python, 외부 라이브러리 없음) | reach 결과, Trivy 결과, 규칙을 합쳐 CVE별로 판정한다 |
| `data/vuln-functions.json` | CVE별 취약 함수 목록 (조사 결과에서 생성) |
| `data/rules.json` | 수집할 사실 38개와 CVE별 판정 규칙 |

### 왜 이렇게 만들었나

| 결정 | 이유 |
|---|---|
| 호출 그래프 알고리즘으로 RTA(Rapid Type Analysis) 사용 | CHA보다 정밀하다(실제로 `new`한 클래스만 가상 호출 대상으로 본다). 포인터 분석보다 가벼워서 노트북에서 돌아간다 |
| 진입점을 2단계로 넣음 | 1단계는 Spring 진입점(컨트롤러, @Bean, 리스너, 프레임워크 콜백)이다. 경로를 "어느 API에서 시작하는지"로 보여주기 위해서다. 2단계는 모든 앱 메서드다. 리플렉션 호출을 놓치지 않기 위해서다 |
| Object 메서드 호출과 JDK 콜백은 "약한 경로"로 분리 | 첫 시험에서 bcprov 도달 근거가 "Jackson 날짜 포맷 → Object.equals → BC 권한 클래스"처럼 의미 없는 경로로 나왔다. 이 간선을 두 번째 단계로 미루자 근거가 "AuthController.signup → EmailAuthService.signup → … → Argon2BytesGenerator"로 바뀌었다. 약한 경로로만 닿으면 "도달 가능"이 아니라 "미확인"이다 |
| 판정은 도달 가능 / 도달 불가 / 미확인 3가지 | 확신이 없으면 미확인이다. 규칙은 "도달 가능 조건 → 도달 불가 조건 → 미확인 조건 → 기본값" 순서로 평가한다 |
| 취약 메서드가 jar에 없으면 미확인 | 버전에 따라 메서드 이름이 바뀐다(예: BC 1.84에서 이름 변경). 못 찾았다고 도달 불가로 판정하면 위험하다 |
| 사실은 앱 코드에서만 수집 | 프레임워크 내부 코드는 앱과 무관하게 같은 일을 한다. 판정을 가르는 건 "앱이 무엇을 설정·호출하는가"다 |
| 역직렬화 타입 추적 | @RequestBody, @RequestPart, @Payload, 리스너 파라미터, HttpEntity, readValue 계열에 쓰인 클래스, TypeReference, Feign·HTTP Interface 응답 타입에서 시작해 필드 타입을 따라간다 |
| SootUp 대신 ASM으로 직접 구현 | 이 작업 공간에서는 SootUp을 받을 수 없어 테스트할 수 없었다. 알고리즘은 같은 계열(RTA)이고, 정밀도를 더 높여야 하면 노트북에서 SootUp으로 바꿀 수 있다 |

### 한계

- 리플렉션, 동적 프록시, JNI는 모델링하지 않는다. 2단계 진입점과 규칙으로 보완한다.
- JDK 내부 코드는 분석하지 않는다. JDK가 다시 불러줄 수 있는 메서드는 "약한 경로"로 가정한다.
- 규칙은 CVE마다 사람이 써야 한다. 이번 10개 CVE에 사실 38개, 규칙 10개가 들었다.
- 런타임 설정(java.security, 환경 변수)은 보지 못한다. 확인 스크립트로 따로 본다.

---

## 4. 검증: 샘플 앱 2개

### 구성

| 부분 | 출처 |
|---|---|
| BouncyCastle 1.78.1, Jackson 2.16.1 | 로컬에 설치된 실제 jar |
| Spring Security crypto 7.1.1 (Argon2PasswordEncoder 등 11개 파일) | 공식 소스를 받아 컴파일 |
| Spring MVC 어노테이션, Tomcat 인증기 | 실제와 같은 클래스·메서드 이름을 가진 스텁 |

- **app-like**: 우리 서비스 구조를 흉내 냈다. Argon2 비밀번호 인코더, @RequestBody 가입·로그인, 응답 전용 DTO의 BigDecimal, Jackson으로 채팅 메시지 읽기.
- **app-positive**: CVE마다 발동 조건을 일부러 넣었다. GOST CTR 사용, BC 인증서 검토기, Tomcat FORM·DIGEST 인증, double·Duration 필드, @JsonTypeInfo(defaultImpl), @JsonIdentityInfo, DataInput.
- 기대값은 소스를 보고 먼저 정해 뒀다(`test/expected.json`). 그다음 도구를 돌려 비교했다.

### 결과

- **20개 판정 모두 기대값과 일치했다.**
- 대표 경로 (app-positive, 실제 BouncyCastle 바이트코드):
  - CVE-2025-14813: `RiskyController.encrypt → LegacyCrypto.gostEncrypt → StreamBlockCipher.processBytes → G3413CTRBlockCipher.calculateByte → generateCRT`
  - CVE-2026-8763: `CertReview.review → PKIXCertPathReviewer.isValidCertPath → doChecks → checkNameConstraints → PKIXNameConstraintValidator.checkPermitted → … → emailIsConstrained`
- app-like에서 bcprov는 패키지 수준으로는 도달(Argon2 경로), 함수 수준으로는 도달 불가였다. 노션에 적은 수동 판정을 도구가 그대로 재현했다.
- app-like에서 Jackson 취약 함수 3개는 호출 그래프상 "도달"로 나왔다(readValue 과대 근사). 규칙이 "모델에 해당 기능이 없음"을 근거로 도달 불가로 판정했다. CVE-2026-89407은 응답 DTO의 BigDecimal 때문에 의도대로 미확인이 나왔다.

### 성능

| 시험 | 규모 | 시간 |
|---|---|---|
| 샘플 앱 | 클래스 약 5,300개 | 약 1초 |
| 대형 classpath | 라이브러리 315개, 클래스 약 8만 개 | 9초 (힙 1GB로도 실행됨) |
| 스트레스 | 앱 클래스 2,134개(Gradle 코어를 앱으로 간주), 도달 메서드 55,398개 | 18초 |

---

## 5. Eclipse Steady는 시도하지 않음

- **판단**: 시도하지 않았다.
- **이유**:
  1. 이 작업 공간에서는 Docker Hub와 Maven Central이 막혀 Steady 백엔드를 띄울 수 없다.
  2. 마지막 릴리스가 2021년(3.2)이고 공식 요구사항이 JDK 8이다. Eclipse 프로젝트 종료 검토가 10/14로 잡혀 있다.
  3. 자체 도구가 샘플 앱에서 기대값을 모두 맞췄다.
- 비교 기준이 꼭 필요하면 노트북에서 반나절 제한으로 시도할 수 있다.

---

## 6. 노트북에서 남은 일

| 스크립트 | 하는 일 | 결과 위치 |
|---|---|---|
| `scripts/verify-laptop.sh` | 노션 6-1의 노트북 항목(bcprov 누락 원인, bctls, Syft·lockfile) + provider 순서 + 정답지용 소스 grep. L1 digest 확인(데스크톱)과 OSV-Scanner(선택)는 제외 | `sca-eval/verify-report.txt` |
| `scripts/run-reach.sh` | 실제 bootJar로 판정 | `sca-eval/reach/verdicts.md` |

두 결과를 붙여 주면 정답지(`docs/answer-key.md`)와 도구 판정을 비교해서 PoC 6단계(비교·정리)를 마무리한다.

---

## 7. 전달 전 최종 검증

**어떻게 했나**: 테스트를 깨끗한 상태에서 다시 돌렸다. zip을 새 폴더에 README 순서 그대로 풀어서 테스트와 `run-reach.sh`를 실행했다. `run-reach.sh`에는 샘플 bootJar와 가짜 Trivy·Grype 결과를 넣었다. 노션 두 페이지도 다시 읽어 문서와 실제 동작을 대조했다.

| 발견 | 왜 문제인가 | 조치 |
|---|---|---|
| README의 `unzip reach-poc.zip -d reach-poc`는 `reach-poc/reach-poc/`를 만든다 | 안내대로 `cd`하면 `scripts/`가 없어 첫 명령부터 실패한다 | `unzip -oq reach-poc.zip && cd reach-poc`로 고쳤다. Windows 다운로드 폴더에서 WSL로 복사하는 줄도 추가했다 |
| 테스트가 이 작업 공간의 jar 경로(`/opt/gradle-8.14.3/lib`)를 고정으로 쓴다 | 다른 PC에서는 `run-tests.sh`가 원인 설명 없이 실패한다 | `GRADLE_LIB`, `COMMONS_LOGGING_JAR`로 경로를 바꿀 수 있게 했다. jar가 없으면 필요한 버전을 출력한다 |
| `verify-laptop.sh`가 "6-1 항목 5개"를 확인한다고 적었다 | 실제로는 노트북 항목 3개와 provider 순서, 소스 grep만 본다. L1은 데스크톱에서, OSV-Scanner는 선택으로 한다 | 스크립트 머리말, README, 이 문서, 노션을 실제 범위로 고쳤다 |
| "Jackson 4건은 실제 jar로 재현"에 버전이 없었다 | 3.1.5로 재현한 것으로 읽힐 수 있다 | 같은 결함이 있는 2.16.1로 재현했고, 89407은 정규식만 떼어 재현했다고 적었다 |
| 노션 종합 정리의 위험 표와 5-2 결론이 SootUp 기준이었다 | v0는 ASM으로 구현했고 Steady는 생략했다 | 현재 상태에 맞게 고쳤다 |

**결과**

- 새로 푼 zip에서 테스트 20/20 일치 (약 10초).
- `run-reach.sh`는 기본 경로로 끝까지 실행됐다. Trivy 결과만 읽고 Grype 결과는 건너뛰었다. 취약 함수 데이터가 없는 CVE는 "분석 대상 아님"으로 표시했다.
- jar 경로가 틀리면 테스트가 필요한 jar를 안내하고 종료 코드 1로 멈춘다.

---

## 8. 노트북 실행 결과와 89407 규칙 개선 (2026-10-10)

**무엇을 했나**: 노트북에서 `verify-laptop.sh`와 `run-reach.sh`를 실제 `service-backend` bootJar로 돌렸다. 결과로 정답지를 확정하고 도구 판정과 비교했다(`docs/answer-key.md`). 10개 중 9개가 일치했고, CVE-2026-89407만 도구는 미확인, 사람은 도달 불가였다.

**왜 불일치했나**: 89407의 안전망 사실 `dto.floating.any`(scope `all`)는 앱 클래스 어디든 실수형 필드가 있으면 미확인으로 보냈다. 실제 앱에서 걸린 것은 `SellerBriefResponse`, `SellerProfileResponse`의 `Double averageRating`뿐이었다. 둘 다 JDBC 행으로 `new` 해서 반환만 하는 응답 record다.

**어떻게 고쳤나**: Jackson은 누군가 타입을 알려줘야만 그 타입으로 역직렬화한다. 그래서 안전망을 "타입을 알려줄 수 있는 자리에 나온 타입"으로 좁혔다.

| 변경 | 내용 |
|---|---|
| `Facts.java`: scope `tokens` | 출발점: 역직렬화 루트 전체 + 앱 코드 어디든 있는 class 리터럴 + TypeReference 제네릭 + Jackson 어노테이션의 클래스 값(`@JsonDeserialize(as=…)`, `@JsonSubTypes` 등) + `@Cacheable`·`@CachePut` 반환 타입. 루트 수집이 놓치는 경우(예: `Class<T>`를 받는 공용 helper에 `Foo.class`를 넘기는 경우)를 잡는다 |
| `rules.json`: `dto.floating.tokens` | 89407의 미확인 조건을 `dto.floating.any`에서 `dto.floating.tokens`로 바꿨다 |
| `rules.json`: `jackson.polymorphicSerializer` | `GenericJackson(2)JsonRedisSerializer`는 `@class`로 아무 타입이나 지정할 수 있다. 이것과 `jackson.defaultTyping`이 있으면 미확인이다 |
| `rules.json`: 판정별 `info` | 판정에 쓰지 않고 보고서에 "참고"로만 보여줄 사실. 89407은 `dto.floating.any`를 계속 보여준다 |
| `reach-result.json`: `dto_type_tokens` | tokens 출발점 목록(앱 타입만). 판정 근거를 사람이 감사할 수 있게 남긴다 |
| 테스트: `app-tokens` fixture | 대조군. `PriceQuote`(BigDecimal)가 공용 helper를 거쳐서만 역직렬화된다. roots로는 안 잡히고 tokens로 잡혀 미확인이어야 한다 |
| 테스트: `app-like` 기대값 | 응답 전용 `ProductResponse`의 89407을 unknown에서 unreachable로 바꿨다 |

**결과**

- 테스트 21/21 일치 (app-like 10, app-positive 10, app-tokens 1).
- 실제 bootJar: 10개 모두 도달 불가. 정답지와 10/10 일치.
- 실제 앱에서 tokens 출발점은 97개였다(Kakao 응답 DTO, `Report` 엔티티, enum, logger용 class 리터럴 등). 넓게 잡았는데도 실수형 필드는 없었다.

**남은 한계**: tokens는 일부러 넓게 잡았다. 실수형 필드가 있는 JPA 엔티티를 `em.find(Foo.class)`로 읽기만 해도 미확인이 된다. 또 Spring이 메서드 시그니처로 타입을 정하는 경로 중 `@Cacheable` 외의 것(예: Spring Data REST)은 모델링하지 않았다.

---

## 9. 주입 실험: 실제 앱에 취약 코드를 넣어 잡는지 확인 (2026-10-10)

**무엇을 했나**: `service-backend`를 로컬 clone한 사본에 CVE별 취약 코드를 넣고 bootJar를 빌드해 판정했다(Spring Boot 4.1.1, Jackson 3.1.5, 실제 Tomcat·bcprov). 원래 레포는 건드리지 않았다. 기대값은 실행 전에 적었다.

| 실험 | 넣은 것 | 결과 |
|---|---|---|
| A 직접 | 규칙이 찾는 모양 그대로(`new DigestAuthenticator`, `new G3413CTRBlockCipher`, `@RequestBody`의 `double` 등) | 10/10 기대대로. 65182는 설계상 미확인, 나머지 도달 가능 |
| B 우회 | 하위 클래스, `@ServletSecurity`, JCE 이름 `"GOST3412-2015/CTR"`, `List<Line>` 안의 `BigDecimal`, 필드의 `@JsonTypeInfo`, `Map<String, Account>`, `ObjectReader.readValue(DataInput)` | 10/10 기대대로 |
| C 사각지대 | `Class.forName`으로 GOST CTR 생성, `readValue(json, Class.forName(name))`, mix-in의 `@JsonIdentityInfo` | 14813·89407은 예상대로 놓침(README의 리플렉션 한계). **91777은 미확인 예상이었는데 도달 가능(오탐)** |

A·B의 판정 20개는 모두 넣은 probe 코드의 줄을 근거로 가리켰다(판정만 맞고 이유가 틀린 경우 없음).

**고친 것: 91777 오탐**

- 원인: `readValue(json, Node.class)`가 있는 메서드의 class 리터럴(`NodeIdentityMixIn.class` 포함)이 모두 루트가 됐다. 그리고 `dto-collection-element-annotation`이 루트 타입 자체의 어노테이션도 셌다. 91777은 컬렉션·맵 원소일 때만 해당하므로 단일 객체는 해당하지 않는다.
- 수정(`Facts.java`): 타입 자체의 어노테이션은 `dto-annotation`(91776)에서만 센다. `dto-collection-element-annotation`은 (1) 컨테이너 필드의 원소 타입(기존), (2) 루트 자체가 컨테이너인 경우(`@RequestBody Map<String, Account>`, `TypeReference<List<Node>>`)의 원소 타입(새 `rootContainerElements`)만 센다.
- 고친 뒤 C의 91777은 `jsonIdentityInfo.any`(mix-in의 어노테이션)로 미확인이다.

**회귀 테스트**

| fixture | 내용 | 기대값 |
|---|---|---|
| `app-indirect` | 실험 B를 Jackson 2.16.1·스텁으로 옮긴 것. 91777은 루트 자체가 `Map<String, Account>`(새 경로) | 65182 미확인, 나머지 9개 도달 가능 |
| `app-blindspots` | 실험 C. 14813·89407은 **알려진 놓침을 고정**한다(한계를 없애면 테스트가 실패해 README를 고치라고 알려준다). 91777은 오탐 회귀 | 14813·89407 도달 불가, 91777 미확인 |

- 스텁 추가: `jakarta.servlet.annotation.ServletSecurity`, `HttpConstraint`.
- 테스트 34/34 일치(app-like 10, app-positive 10, app-tokens 1, app-indirect 10, app-blindspots 3).
- 고치기 전 코드로 빌드한 jar에서는 app-blindspots 91777이 reachable로 나와 테스트가 실패한다(회귀 테스트가 실제로 오탐을 잡는다).
- 고친 도구로 실제 jar 다시 실행: 원래 앱 10개 모두 도달 불가(변화 없음), A·B는 위와 같음, C의 91777만 미확인으로 바뀜.

**남은 문제: 호출 경로 근거가 엉뚱할 수 있다**

B의 89425는 판정은 맞았다(`IndirectProbeController#dataInput`의 DataInput 호출). 하지만 보고서의 취약 메서드 경로는 `AuditLogController.list → … → readTree → UTF8DataInputJsonParser`였다. probe가 DataInput 파서를 한 번 만들자 RTA가 앱 전체의 `JsonParser.nextToken()` 호출을 그 파서로 보낼 수 있다고 본 것이다. 보고서의 경로는 "가능한 경로 중 가장 짧은 것"이지 실제 경로가 아니다. 사람이 이 경로를 근거로 믿지 않도록 보고서에 표시하거나, 앱 코드 쪽 사실(fact)을 경로보다 앞에 보여주는 개선이 필요하다.

---

## 10. 남은 일 처리: 이미지 불일치, Jackson 2 사본, 근거 표시, CVE-2026-13506 (2026-10-10)

### 10-1. 이미지와 bootJar 불일치의 원인

- `Dockerfile`은 Gradle 빌드를 하지 않고 `build/libs/*.jar`를 그대로 복사한다.
- `sca-test/api:local`은 10/9 21:50에 빌드됐는데, 안의 jar는 앱 클래스 51개뿐이고 chatbot·report 패키지가 없다. 레포 bootJar(10/9 22:26 빌드, 앱 클래스 376개)와 다르다. bcprov는 9/24, anthropic-java는 9/27에 추가됐으므로 **9/21 무렵 빌드의 오래된 jar가 들어간 것**이다.
- 현재 bootJar로 `sca-test/api:6583020`을 새로 빌드했다(`--build-arg JAR_FILE=build/libs/service-backend-0.0.1-SNAPSHOT.jar`). 이미지 안 jar의 sha256이 분석한 bootJar와 같다. 기존 `:local`과 기존 스캔 결과는 덮어쓰지 않았다.
- 새 이미지 Trivy 결과(`sca-eval/sbom/api-6583020.trivy.cdx.json`, `sca-eval/vuln/api-6583020.trivy.json`): CRITICAL 5, HIGH 11, MEDIUM 7. 기존 `:local`은 3/5/4였다. 10/7 데스크톱의 ECR 배포 이미지 스캔(5/11/7)과 개수가 같다(같은 이미지라는 증명은 아니다).
- 참고: `build/libs/`에 plain jar도 있어서 기본값 `JAR_FILE=build/libs/*.jar`로는 COPY 원본이 2개가 된다. 이미지를 만들 때는 bootJar 경로를 지정한다.

### 10-2. 같은 CVE의 Jackson 2 사본

- 새 이미지 스캔에서 Jackson CVE 5개가 `tools.jackson`(3.1.5)뿐 아니라 `com.fasterxml.jackson`(2.21.5)에서도 나왔다. Jackson 2는 `com.anthropic:anthropic-java:2.34.0`만 끌어온다.
- 지금 판정은 Jackson 3 기준이다. 규칙은 앱 클래스만 보므로, SDK가 내부에서 Anthropic API 응답을 역직렬화하는 경로는 판정할 수 없다.
- 그런데 기존 보고서는 CVE당 한 줄이라 2.21.5 사본이 판정되지 않았다는 사실이 드러나지 않았다. 또 판정 행의 설치·수정 버전을 Trivy 결과의 첫 항목에서 가져와, 그 항목이 다른 패키지면 버전이 틀릴 수 있었다.
- 수정(`verdict.py`): 판정 행은 spec 패키지와 같은 Trivy 항목을 쓴다. 같은 CVE의 다른 패키지는 "분석 대상 아님" 행으로 따로 보여준다. 취약 함수 데이터가 없는 CVE도 패키지마다 한 줄씩 보여준다.

### 10-3. 근거 표시 개선 (`verdict.py`)

- 결정 근거에서 앱 코드의 사실(정확한 줄)을 먼저, 호출 경로를 나중에 보여준다.
- 호출 경로에 "가장 짧은 후보 경로이며 실제 경로와 다를 수 있다"를 표시한다(9절의 89425 사례).
- 규칙으로 판정한 CVE에서 호출 그래프 결과가 판정과 달라 보이면 이유를 붙인다. 취약 메서드 도달 "예"인데 도달 불가면 과대근사, 패키지 도달 "아니요"면 프레임워크가 실행하는 코드라 그래프 밖이라는 설명이다.

### 10-4. CVE-2026-13506 (bcprov, HIGH) 추가

- 내용: ASN.1을 지연 파싱(`ASN1InputStream(…, lazyEvaluate=true)`)할 때 `LazyEncodedSequence`를 펼칠 때마다 중첩 깊이 제한이 초기화된다. 깊게 중첩된 입력을 끝까지 순회하면 StackOverflowError(DoS). 1.85에서 수정.
- 방법: Trivy 참조의 수정 커밋 `bcgit/bc-java@77454da9` diff에서 바뀐 메서드를 정하고(`data/research/bc-src/diffs/LazyEncodedSequence_commit_77454da9.diff`), 1.81 jar에서 `javap`로 시그니처를 확인했다.
- 취약 함수: `LazyEncodedSequence.force()V`, `LazyEncodedSequence.getObjects()`, `LazyConstructionEnumeration.<init>([B)V`. `ASN1InputStream.buildObject`도 바뀌었지만 지연이 아닌 파싱과 공유하는 메서드라 넣으면 오탐이 나서 뺐다.
- 규칙: 호출 그래프(`sink`면 도달 가능, 약한 경로·메서드 없음이면 미확인).
- 결과: 실제 앱은 **도달 불가**(패키지는 Argon2 경로로 도달, 취약 메서드는 미도달).
- 대조군: `app-positive`에 `Asn1Lazy`(지연 파싱 후 `getObjects()` 순회)를 넣어 도달 가능을 고정했다. 실제 앱 사본에 같은 코드를 넣은 실험 D도 도달 가능이었고, 근거가 넣은 컨트롤러를 가리켰다. 다른 BC CVE 2개는 그대로 도달 불가였다.
- 주의: 오전에 14813·8763 근거로 쓴 Argon2 **클래스 단위** 폐포(jdeps)에는 `LazyEncodedSequence`가 들어 있다. 그래서 13506은 클래스 단위로는 배제할 수 없고, **메서드 단위** 호출 그래프로만 배제된다.

### 결과

- 테스트 36/36 일치 (app-like 11, app-positive 11, app-tokens 1, app-indirect 10, app-blindspots 3).
- 실제 앱 판정: 도달 불가 11개, 분석 대상 아님 12행(Jackson 2 사본 5, 취약 함수 데이터 없음 7: bcprov 0636, jackson-databind 19032·83557 각 2패키지, libpng, zlib).

### 남은 일

- (데스크톱) L1: 실행 중인 api digest로 스캔해 새 이미지 결과와 비교.
- Jackson 2 사본(anthropic-java 내부): SDK 클래스까지 규칙 대상으로 넓히거나, 신뢰 경계(Anthropic API 응답)를 근거로 사람이 판정.
- 취약 함수 데이터 없는 MEDIUM 3개(bcprov 0636, jackson-databind 19032·83557).
- 이미지 빌드 절차: CI에서 bootJar 경로를 지정하는지 확인(plain jar와 섞이면 COPY 실패 또는 오래된 jar 사용 위험).

---

## 11. MEDIUM 3개 추가, Jackson 2 사본 분석, 업그레이드 실험 (2026-10-10 밤)

### 11-1. 데이터 생성 경로 바로잡기

- `data/vuln-functions.json`은 `scripts/make_spec.py`가 `data/research/{tomcat,bouncycastle,jackson}.json`에서 생성한다. 10절에서 13506을 `vuln-functions.json`에 직접 넣어서, 다시 생성하면 사라지는 상태였다.
- 13506을 포함한 새 CVE 4개를 조사 파일(근거 포함)과 `make_spec.py`(`SUMMARY_KO`, 13506의 `buildObject`는 `EXCLUDE_SINKS`)에 넣고 다시 생성했다. 기존 10개 항목은 생성 전후가 같다(13506은 영어 요약 문구만 바뀜).
- `jackson.json`은 다시 직렬화하면 형식이 바뀌어서, 기존 내용을 건드리지 않고 끝에 텍스트로 덧붙였다.

### 11-2. MEDIUM 3개 추가

| CVE | 취약 함수 (수정 커밋 diff, javap 확인) | 판정 규칙 | 실제 앱 |
|---|---|---|---|
| CVE-2026-0636 (bcprov) LDAP 인젝션 | `LDAPStoreHelper.parseDN`·`search`, `X509LDAPCertStoreSpi.parseDN`·`search` (commit d20cdb84) | 호출 그래프 + BC LDAP 클래스 생성(`bc.ldapStoreNew`)이면 도달 가능. `CertStore.getInstance` 호출이 있으면 미확인(JCE 이름으로 리플렉션 선택) | 도달 불가 |
| CVE-2026-19032 (jackson-databind) Path URI 스킴 | `JDKFromStringDeserializer$NioPathHelper.deserialize` (3.x commit ce26eda3·d94bb632) | 89407과 같은 모양. 루트에서 닿는 타입의 `java.nio.file.Path` 필드면 도달 가능, tokens 범위면 미확인 | 도달 불가 |
| CVE-2026-83557 (jackson-databind) Comparable 기반 타입 | `DefaultBaseTypeLimitingValidator.isUnsafeBaseType`·`isSafeSubType` (2.x commit eb3b7fc0, 3.x는 javap로 확인) | `@JsonTypeInfo`가 없으면 도달 불가. 있고 루트 타입에 `Comparable` 필드가 있으면 도달 가능, 그 밖은 미확인 | 도달 불가 |

대조군:

- `app-positive`: `LdapCertLookup`(LDAPStoreHelper로 subject 검색), `ExtraController`(`Path` 필드, `@JsonTypeInfo` + `Comparable` 필드) → 세 개 모두 도달 가능.
- `app-indirect`: `LdapByJceName`(`CertStore.getInstance("LDAP", JDK LDAPCertStoreParameters, "BC")`) → 미확인. 처음에는 BC 전용 `X509LDAPCertStoreParameters.Builder`를 썼는데 도구가 도달 가능으로 판정했다. 이건 도구가 맞고(BC LDAP 저장소를 쓴다는 강한 신호) fixture가 의도한 "JCE 이름만" 시나리오가 아니었으므로 fixture를 고쳤다. 같은 앱의 83557은 `@JsonTypeInfo`가 비-Comparable 기반 타입에 있어 미확인이며, 이것도 기대값으로 고정했다.
- 실제 앱 사본 실험 E(세 개를 모두 넣음): 세 개 모두 도달 가능. 덤으로 13506도 도달 가능이 됐다. LDAP에서 받은 인증서를 BC `X509CertParser`가 지연 ASN.1로 파싱하는 실제 경로다(`LDAPStoreHelper.createCerts → X509CertParser.readDERCertificate → LazyEncodedSequence.force`).

테스트 44/44 일치 (app-like 14, app-positive 14, app-tokens 1, app-indirect 12, app-blindspots 3).

### 11-3. Jackson 2 사본(anthropic-java 내부) 분석

- Jackson 2(2.21.5)는 `com.anthropic:anthropic-java:2.34.0`만 끌어온다. SDK가 Anthropic API 응답을 자기 모델로 역직렬화할 때 쓴다.
- SDK 바이트코드(클래스 9,561개)를 검색했다. 주의: 이 세션 셸의 `grep`은 `ugrep -I`로 감싸져 바이너리를 건너뛰어서 처음엔 전부 0건이 나왔다. `command grep -a`로 다시 했고, `ObjectMapper` 3건·`java/lang/Double` 22건이 잡히는 것으로 검색이 동작함을 확인했다.

| 조건 | SDK에서 | 해당 CVE |
|---|---|---|
| `@JsonTypeInfo`, `@JsonSubTypes`, default typing, 문제 처리기 | 0건 | 91776, 83557 해당 없음 |
| `@JsonIdentityInfo` | 0건 | 91777 해당 없음 |
| `java.io.DataInput` | 0건 | 89425 해당 없음 |
| `javax.xml.datatype` | 0건 | 68497 해당 없음 |
| `java.nio.file.Path` | 15클래스. 업로드 요청 빌더와 설정·자격증명 파일 위치뿐, 응답 모델 필드 아님 | 19032 해당 없음 |
| `Double` 필드 | 22클래스 (응답 모델 포함) | 89407: 문자열로 온 숫자를 변환할 때만 해당. 입력이 Anthropic API 응답(TLS)이라 공격자가 통제하기 어렵다 |

- 판정 제안: 6개는 해당 없음(조건 부재), 89407은 "조건은 있으나 입력이 신뢰 경계 안"으로 위험 낮음. 사람 판정이므로 확정은 사용자가 한다.
- SDK 업그레이드로는 해결되지 않는다. SDK pom이 선언한 Jackson은 2.18.2(2.34.0)·2.19.4(최신 2.71.0)인데 앱에는 2.21.5가 들어 있다. **Jackson 2 버전은 Spring Boot 4.1.1의 `jackson-2-bom.version`(2.21.5)이 정한다**(`jackson-bom.version`=3.1.5도 같은 방식).

### 11-4. 업그레이드 실험

- 실험용 clone에 최소 수정 버전을 적용했다: `ext['jackson-bom.version']=3.1.7`, `ext['jackson-2-bom.version']=2.21.7`, `ext['tomcat.version']=11.0.25`, bcprov 1.85. Dockerfile에 `RUN apk upgrade --no-cache`.
- 결과: bootJar 라이브러리가 의도대로 바뀌었고, 이미지 Trivy는 CRITICAL 5·HIGH 11·MEDIUM 7 → (Java만) MEDIUM 2 → (`apk upgrade`까지) 0.
- `./gradlew test`: 945개 통과, 실패·에러 0 (5분 49초). `marketplaceE2E`는 돌리지 않았다.
- 제안서와 패치: `docs/upgrade-proposal.md`, `docs/upgrade.patch`. 실제 레포에는 적용하지 않았다.

### 11-5. CI 확인

- CI(`.github/workflows/ci.yml`)는 새 러너에서 `./gradlew build -x test` 후 `docker build`를 한다. `build.gradle`이 plain jar를 끄므로(109~111행) `build/libs/`에는 bootJar 하나만 생긴다. 10-1의 오래된 jar 문제는 로컬 `build/libs/`에 남은 9/21자 jar 때문이었고, CI에서는 생기지 않는다.
- CI는 이미지에 `org.opencontainers.image.revision` 라벨(커밋 SHA)을 붙인다. L1에서 digest로 커밋을 바로 찾을 수 있다.

### 결과 (11절)

- 테스트 44/44 일치. 실제 앱: 판정한 14개 모두 도달 불가. 분석 대상 아님은 Jackson 2 사본 7행과 OS 패키지 2행.

### 남은 일

- (데스크톱) L1: 실행 중인 digest의 revision 라벨과 스캔 결과 확인.
- Jackson 2 사본 판정 확정(제안은 answer-key).
- 업그레이드 적용 여부 결정, 적용 시 `marketplaceE2E`와 기동 확인.

### 11-6. 데스크톱용 스크립트 (`scripts/verify-desktop.sh`)

- L1과 배포본 기준 L2를 한 번에 한다: 실행 중인 api 이미지 digest(kubectl 또는 `DIGEST=`) → ECR 태그·OCI revision 라벨 → 이미지에서 `/app/app.jar` 추출 → sha256을 노트북 bootJar(`e9879efa…`)와 비교 → Trivy → 배포된 jar로 reach + verdict.
- 노트북에서 `IMAGE=sca-test/api:6583020`으로 2~4절을 시험했다(AWS 조회 제외). jar sha256 일치, 판정 결과가 노트북 판정과 같다.
