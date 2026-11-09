# 정답지: api 서비스 CVE 10개 (사람 판정)

도구 판정과 비교하기 위한 **사람이 내린 판정**이다. 도구와 독립적으로, 소스·설정과 CVE 조사 결과만 보고 정한다.

- 기준 시점: 2026-10-10 (`verify-laptop.sh` 결과 `sca-eval/verify-report.txt` 반영)
- 대상: `service-backend` (Spring Boot 4, Java 21) 레포 bootJar 기준. 이미지 jar와 다르다(아래 "대상 jar 차이" 참고)
- 상태 표시: **도달 불가 (확정)** / **도달 불가 (잠정, 확인 1개 남음)** / **확인 필요**

| CVE | 패키지 | 사람 판정 | 근거 | 확인한 곳 (`verify-laptop.sh` 절) |
|---|---|---|---|---|
| CVE-2026-65182 | tomcat-embed-core 11.0.24 | 도달 불가 (확정) | 컨테이너 보안 설정(SecurityConstraint, LoginConfig, @ServletSecurity, auth-method, `addConstraint`, `SecurityCollection`, `setServletSecurity`)이 없다. Spring Boot 내장 Tomcat은 제약을 만들지 않는다(4.0.8·4.1.1 소스 확인) | 6절: 없음 |
| CVE-2026-65905 | tomcat-embed-core 11.0.24 | 도달 불가 (확정) | DigestAuthenticator를 쓰는 코드가 없다. Spring Boot는 web.xml을 읽지 않는다 | 6절: 없음 |
| CVE-2026-68525 | tomcat-embed-core 11.0.24 | 도달 불가 (확정) | FormAuthenticator를 쓰는 코드가 없다. Spring Security formLogin은 별개 구현이다 | 6절: 없음 |
| CVE-2025-14813 | bcprov-jdk18on 1.81 | 도달 불가 (확정) | bcprov는 Spring Security Argon2 경로로만 쓰인다. Argon2 경로의 클래스 폐포에 cipher mode 클래스가 없다(조사 결과). 앱 코드에 BC 참조와 "GOST" 문자열이 없다(10/9 grep, jdeps) | 없음 |
| CVE-2026-8763 | bcprov-jdk18on 1.81 | 도달 불가 (확정) | Argon2 경로에 인증서 검증이 없다. 앱 코드에 BouncyCastleProvider·CertPathValidator 참조가 없다(10/9 grep). bctls가 없어 OkHttp도 BC TLS를 쓰지 않는다. 이미지의 provider 목록은 SUN이 1순위이고 BC가 없으며, 실행 옵션에 `-Djava.security.*`도 없다 | 2절: bctls 없음, 3절: SUN 1순위 |
| CVE-2026-89407 | jackson-core 3.1.5 | 도달 불가 (확정) | 실수형 필드는 응답 record 두 개(`SellerBriefResponse.averageRating`, `SellerProfileResponse.averageRating`)에만 있고, 둘 다 JDBC 행으로 만들어 반환만 한다(`ListingQueryRepository.java:57`, `ReviewService.java:137`). 역직렬화하는 곳이 없다. @RequestBody 타입 31개에는 실수형 필드가 없다. 외부 입력을 `readTree`하는 `CursorCodec`은 `numberValue()`만 써서 문자열→숫자 변환을 타지 않고, `GeminiLlmClient`는 문자열·boolean만 읽는다. JsonNode 숫자 변환(asDouble 등)도 없다 | 7절 + 10/10 소스 확인 |
| CVE-2026-89425 | jackson-core 3.1.5 | 도달 불가 (확정) | Spring MVC는 InputStream/Reader로 읽는다. DataInput API를 쓰는 코드가 없다 | 7절: 없음 |
| CVE-2026-68497 | jackson-databind 3.1.5 | 도달 불가 (확정) | javax.xml.datatype Duration·XMLGregorianCalendar를 쓰는 코드가 없다. 이 역직렬화기는 그 타입을 읽을 때만 실행된다 | 7절: 없음 |
| CVE-2026-91776 | jackson-databind 3.1.5 | 도달 불가 (확정) | @JsonTypeInfo(defaultImpl), default typing, 문제 처리기를 쓰지 않는다 | 7절: 없음 |
| CVE-2026-91777 | jackson-databind 3.1.5 | 도달 불가 (확정) | @JsonIdentityInfo를 쓰지 않는다 | 7절: 없음 |

## 도구 판정과 비교 (2026-10-10 `run-reach.sh`)

| CVE | 도구 판정 | 사람 판정 | 일치 |
|---|---|---|---|
| CVE-2026-65182, 65905, 68525 | 도달 불가 (rule) | 도달 불가 (확정) | 예 |
| CVE-2025-14813, CVE-2026-8763 | 도달 불가 (callgraph) | 도달 불가 (확정) | 예 |
| CVE-2026-89407 | 도달 불가 (rule) | 도달 불가 (확정) | 예 (규칙 개선 후. 개선 전에는 미확인) |
| CVE-2026-89425 | 도달 불가 (callgraph) | 도달 불가 (확정) | 예 |
| CVE-2026-68497, 91776, 91777 | 도달 불가 (rule) | 도달 불가 (확정) | 예 |

- **CVE-2026-89407**은 처음 실행에서 도구가 미확인이었다. `dto.floating.any` 규칙이 응답 전용 타입을 구분하지 못했기 때문이다. 규칙을 "Jackson에 타입을 알려줄 수 있는 자리에 나온 타입"(`dto.floating.tokens`)으로 좁힌 뒤 도달 불가로 일치한다. 자세한 내용은 `WORKLOG.md` 8절에 있다.
- jackson-databind 3개는 호출 그래프상 취약 메서드 도달이 "예"지만, RTA의 가상 호출 과대근사(예: `JSR310StringParsableDeserializer.deserializeWithType → AsArrayTypeDeserializer`)에서 나온 경로다. 판정은 규칙이 정했다.
- Tomcat은 호출 그래프상 패키지 도달이 "아니요"지만, Spring Boot가 Tomcat을 리플렉션으로 띄워 그래프에 잡히지 않을 뿐 실제로는 쓰인다. 판정은 규칙이 정했다.

## 대상 jar 차이

`verify-report.txt` 1절에서 이미지(`sca-test/api:local`)의 `/app/app.jar`는 라이브러리 102개, 레포 bootJar는 185개였다. 이미지에는 bcprov, anthropic-java, AWS SDK 등이 없다. 이미지가 다른 커밋이나 다른 빌드 방식으로 만들어진 것으로 보인다.

- 이 정답지와 도구 판정은 **레포 bootJar** 기준이다.
- 이미지 기준이면 bcprov CVE 2개는 패키지가 없어 해당하지 않는다.
- 원인: Dockerfile이 `build/libs/*.jar`를 복사하는데, 이미지 빌드 시점에 9/21 무렵의 오래된 jar가 남아 있었다(WORKLOG 10-1).
- 현재 bootJar로 `sca-test/api:6583020`을 다시 빌드했다. 이미지 안 jar가 분석한 bootJar와 sha256까지 같아서, 이 정답지는 이 이미지에도 그대로 적용된다.

## 추가 판정 (10/10 저녁·밤)

위 10개 외에 스캐너가 보고한 Java CVE도 취약 함수 데이터를 만들어 판정했다(WORKLOG 10-4, 11-2).

| CVE | 패키지 | 도구 판정 | 사람 판정 | 근거 |
|---|---|---|---|---|
| CVE-2026-13506 | bcprov 1.81 (HIGH) | 도달 불가 (callgraph) | 도달 불가 (잠정) | 앱 코드에 BC 참조 없음(grep 0건). ASN.1 지연 파싱 메서드에 호출 경로 없음. 단 Argon2 클래스 단위 폐포에는 `LazyEncodedSequence`가 있어서 메서드 단위 근거에만 의존한다 |
| CVE-2026-0636 | bcprov 1.81 (MEDIUM) | 도달 불가 (callgraph) | 도달 불가 (확정) | 앱 코드에 BC 참조와 `CertStore.getInstance`가 없다. BC LDAP 저장소를 쓸 방법이 없다 |
| CVE-2026-19032 | jackson-databind 3.1.5 (MEDIUM) | 도달 불가 (rule) | 도달 불가 (확정) | 역직렬화될 수 있는 타입에 `java.nio.file.Path` 필드가 없다 |
| CVE-2026-83557 | jackson-databind 3.1.5 (MEDIUM) | 도달 불가 (rule) | 도달 불가 (확정) | `@JsonTypeInfo`를 쓰지 않는다(verify 7절) |

## Jackson 2 사본 (anthropic-java 내부)

Jackson CVE 7개는 `com.fasterxml.jackson` 2.21.5에서도 나온다. Jackson 2는 anthropic-java SDK만 쓰고, Anthropic API 응답을 SDK 모델로 역직렬화할 때 쓴다. 앱 코드 규칙으로는 판정할 수 없어서 SDK 바이트코드를 직접 검색했다(WORKLOG 11-3). **판정 제안이며, 확정은 사람이 한다.**

| CVE | 제안 | 근거 |
|---|---|---|
| 91776, 83557 | 해당 없음 | SDK에 `@JsonTypeInfo`·`@JsonSubTypes`·default typing·문제 처리기 없음 |
| 91777 | 해당 없음 | `@JsonIdentityInfo` 없음 |
| 89425 | 해당 없음 | `DataInput` 사용 없음 |
| 68497 | 해당 없음 | `javax.xml.datatype` 사용 없음 |
| 19032 | 해당 없음 | `Path`는 요청 빌더·설정 파일 위치에만 있고 응답 모델 필드가 아님 |
| 89407 | 위험 낮음 | 응답 모델에 `Double` 필드가 있다. 다만 입력이 Anthropic API의 TLS 응답이라 공격자가 통제하기 어렵다 |

## 판정 범위 밖

- OS 패키지: CVE-2026-46675 (libpng), CVE-2026-85091 (zlib). Java 호출 그래프로 판정하지 않는다. 베이스 이미지 갱신 또는 `apk upgrade`로 해결된다(WORKLOG 11-4).

## 판정을 고치는 방법

1. 노트북에서 `scripts/verify-laptop.sh`를 실행한다.
2. 각 절의 결과로 위 표의 "사람 판정"을 확정한다. 예를 들어 7절에서 `@JsonIdentityInfo`가 "없음"이면 CVE-2026-91777은 "도달 불가 (확정)"이다.
3. `scripts/run-reach.sh`로 도구 판정을 낸 뒤, 이 표와 비교한다. 다르면 둘 중 어느 쪽이 틀렸는지 근거를 남긴다.

## 업그레이드 기준 (도달 여부와 별개로 일반 유지보수에 넣음)

| 패키지 | 현재 | 최소 수정 버전 | 바꾸는 곳 |
|---|---|---|---|
| tomcat-embed-core | 11.0.24 | 11.0.25 | `ext['tomcat.version']` |
| bcprov-jdk18on | 1.81 | 1.85 (14813·0636은 1.84, 8763·13506은 1.85) | `build.gradle` 의존성 |
| jackson-core, jackson-databind (tools.jackson, 3.x) | 3.1.5 | 3.1.7 | `ext['jackson-bom.version']` |
| jackson-core, jackson-databind (com.fasterxml, 2.x, anthropic-java가 사용) | 2.21.5 | 2.21.7 | `ext['jackson-2-bom.version']` (SDK 업그레이드로는 안 바뀜) |
| libpng, zlib (alpine) | 1.6.58-r1, 1.3.2-r0 | 1.6.59-r0, 1.3.2-r1 | Dockerfile `apk upgrade` |

실험용 clone에서 모두 적용해 이미지 취약점 0개, 테스트 945개 통과를 확인했다. 자세한 내용은 `docs/upgrade-proposal.md`.
