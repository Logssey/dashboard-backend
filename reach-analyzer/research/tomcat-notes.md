# Tomcat CVE 3건 조사 노트 (tomcat-embed-core 11.0.24 → 11.0.25)

`tomcat.json`의 `vulnerable_methods` 항목마다 근거가 되는 diff를 줄여서 남긴다.

## 출처와 방법

- 소스는 `raw.githubusercontent.com/apache/tomcat/<tag>/...`에서 태그 11.0.24와 11.0.25를 받아 로컬에서 diff했다.
  - 받은 파일: `tomcat-src/11.0.24/`, `tomcat-src/11.0.25/`
  - 전체 diff: `tomcat-src/diffs/*.diff`
- 수정 커밋 SHA는 `raw.githubusercontent.com/apache/tomcat-site/trunk/xdocs/security-11.xml`에서 확인했다. 이 파일은 tomcat.apache.org/security-11 페이지의 원본이다.
  - 커밋 시점의 파일도 받아 비교했다: `tomcat-src/commit-<sha>/`
- 공식 설명, CVSS, GHSA는 다음에서 확인했다.
  - opencve, GitLab advisory, averlon: WebFetch로 확인
  - Apache announce 메일(lists.apache.org): WebFetch 요약만 얻었고 원문은 보지 못했다.
- JVM 디스크립터는 11.0.24 시그니처를 그대로 옮긴 stub 클래스를 `javac`로 컴파일한 뒤 `javap -s`로 확인했다.
- 막혀서 쓰지 않은 곳: github.com, osv.dev, nvd, tomcat.apache.org, openwall, lists.apache.org, gitlab.com (curl 기준).
- **수정 버전 주의**: 10.1.58은 수정이 들어갔지만 릴리스되지 않았다.
  - 10.1.59 changelog에 `<section name="Tomcat 10.1.58" rtext="not released">`로 적혀 있다.
  - Apache 메일 요약도 같은 내용이다: 10.1.58 RC 투표가 실패해서 10.1.59로 올려야 한다.
  - 정리하면 실제로 받을 수 있는 수정 버전은 11.0.25, 10.1.59, 9.0.121이다.

---

## CVE-2026-65182: 가장 긴 prefix 제약 선택 오류 (수정 커밋 8bafd79a)

**결함 위치**: `org.apache.catalina.realm.RealmBase#findSecurityConstraints`
- 디스크립터: `(Lorg/apache/catalina/connector/Request;Lorg/apache/catalina/Context;)[Lorg/apache/tomcat/util/descriptor/web/SecurityConstraint;`

```diff
@@ -636,7 +635,8 @@  (RealmBase.findSecurityConstraints, "/*" prefix 매칭 단계)
                 boolean matched = false;
                 int length = -1;
                 for (String pattern : patterns) {
-                    if (pattern.startsWith("/") && pattern.endsWith("/*") && pattern.length() >= longest) {
+                    if (pattern.startsWith("/") && pattern.endsWith("/*") && pattern.length() >= longest &&
+                            pattern.length() >= length) {
                         ...  matched = true; length = pattern.length();
```

**무엇이 잘못됐나**

- 한 `SecurityCollection`(= `<web-resource-collection>`) 안에서는 **마지막으로 매칭된 패턴의 길이**가 `length`에 남는다. 가장 긴 패턴의 길이가 아니다.
- 그래서 `["/level1/level2/level3/*", "/level1/*"]`처럼 긴 패턴이 먼저 나오면, 이 collection의 매칭 길이가 9("/level1/*")로 줄어든다.
- 이 제약 **뒤에** 선언된 다른 제약이 더 긴 prefix(예: `/level1/level2/*`)로 매칭되면, `length > longest`가 되어 앞 제약이 results에서 지워진다.
- 결과적으로 더 제한적인 제약이 빠져서 우회가 생긴다.
- 패턴이 같거나 더 짧은 뒤 제약이 결합되는 경우도 있다. `hasResourcePermission`은 auth-constraint가 없는 제약을 "모두 허용"으로 처리하기 때문에 이것도 우회가 된다.

**수정 커밋에 함께 들어간 테스트** (`TestRealmBase#testOverlappingConstraints`)

```java
outerCollection.addPattern("/level1/level2/level3/*");
outerCollection.addPattern("/level1/*");          // 같은 collection 안에서 긴 패턴이 먼저
outerConstraint.setAuthConstraint(true);          // 빈 auth = deny
innerCollection.addPattern("/level1/level2/*");   // 별도 제약, auth 없음 = allow
...
// Level 3 should be blocked
request = new TesterRequest("/level1/level2/level3/index.jsp");
Assert.assertFalse(mapRealm.hasResourcePermission(request, response, constraints, null));
```

**prefix 단계 시뮬레이션** (11.0.24와 11.0.25 로직을 Python으로 옮겨서 확인)

```
/level1/level2/level3/index.jsp  11.0.24=['inner(allow)']  11.0.25=['outer(deny)']
inner를 먼저 선언한 경우            11.0.24=['outer(deny)']  11.0.25=['outer(deny)']   (순서에 따라 결과가 달라짐)
X=[/a/b/*,/a/*](role) 다음 Y=[/a/*](no auth), /a/b/c  11.0.24=[X,Y]  11.0.25=[X]
패턴이 하나씩인 collection만 있는 경우  차이 없음
```

**도달 조건 근거** (11.0.24)

- 제약이 없으면 vulnerable 루프에 들어가지 않는다.
  ```java
  550  SecurityConstraint[] constraints = context.findConstraints();
  551  if (constraints == null || constraints.length == 0) { ... return null; }
  ```
- `StandardContext` 기본값은 `constraints = new SecurityConstraint[0]`이다 (line 271).
- `@ServletSecurity`와 `setServletSecurity`는 `SecurityConstraint.createConstraints(element, urlPattern)`을 거친다. 이 경로는 collection 하나에 패턴을 **하나만** 넣는다 (`collection.addPatternDecoded(urlPattern)`). 그래서 이것만으로는 취약한 형태가 만들어지지 않는다 (코드에서 추론).
- 같은 파일의 다른 hunk는 이 CVE와 무관하다.
  - `hasRole`이 `wrapper.findSecurityReference`에서 `Context.findRoleMapping`으로 바뀐 것은 CVE-2026-66422(커밋 2c2c510)다. 2c2c510 시점의 RealmBase에는 hasRole 변경만 있고 `>= length`는 없다는 것을 확인했다.
  - 나머지는 javadoc 줄바꿈 정리다.

---

## CVE-2026-65905: DIGEST nonce count 재사용 1회 (수정 커밋 c5f94ad1)

**결함 위치**: `org.apache.catalina.authenticator.DigestAuthenticator$NonceInfo#nonceCountValid`
- 디스크립터: `(J)Z`
- c5f94ad 시점의 파일과 11.0.24의 차이는 아래 2줄뿐이다.

```diff
@@ -804,8 +804,8 @@  (DigestAuthenticator.NonceInfo.nonceCountValid)
     public synchronized boolean nonceCountValid(long nonceCount) {
         if ((count - offset) >= nonceCount || (nonceCount > count - offset + seen.length)) {
             return false;
         }
         int checkIndex = (int) ((nonceCount + offset) % seen.length);
         if (seen[checkIndex]) {
                 return false;
             } else {
                 seen[checkIndex] = true;
-                seen[count % seen.length] = false;
                 count++;
+                seen[count % seen.length] = false;
                 return true;
```

**무엇이 잘못됐나**

- 윈도우 상한값은 `nc = count - offset + W`이고, 이 값의 슬롯은 `count % W`다.
- 11.0.24는 이 슬롯을 `true`로 세운 직후 같은 슬롯을 `false`로 지운다. 그래서 같은 nc를 한 번 더 받아들인다.
- 반대로 새로 윈도우에 들어온 슬롯은 지우지 않는다. 그래서 정상 요청을 잘못 거절하는 일도 생긴다. changelog 문구("incorrect rejection ... upper boundary")가 바로 이 증상이다.

**새 테스트** (`TestDigestAuthenticatorNonceInfo`, 11.0.25에만 있음)
- W=4일 때 `{2, 2} → {true, false}`
- 2는 count=0 시점의 상한값이다.

**같은 로직을 옮긴 시뮬레이션**

```
W=4   [2,2]                 11.0.24=[T,T]  11.0.25=[T,F]   (재사용)
W=100 [1..10, 60, 60]       11.0.24=...T,T 11.0.25=...T,F  (count=10일 때 상한값 60)
W=4   [0,1,2,3,6]           11.0.24=...,F  11.0.25=...,T   (잘못된 거절)
W=100 순차 1..150 후 상한값  11.0.24=F,F    11.0.25=T,F     (순차 클라이언트는 상한값에서 오히려 거절됨)
```

**호출 경로** (변경 없음)

```
AuthenticatorBase.invoke (618: doAuthenticate)
  → DigestAuthenticator.doAuthenticate (356: digestInfo.validate)
  → DigestAuthenticator$DigestInfo.validate (734: info.nonceCountValid(count))
```

**악용 조건** (소스에서 추론)

- nonce는 `remoteAddr:time:key`의 해시다 (409, 696행). 그래서 재전송은 같은 원격 주소에서 와야 한다.
- 그 밖의 조건:
  - nonceValidity(기본 5분) 안이어야 하고, nonce가 캐시(1000개)에 남아 있어야 한다.
  - `validateUri`(기본 true)와 response 해시 때문에 method와 URI가 같아야 한다.
  - nonceCountWindowSize는 기본 100이다.
- Apache는 이 문제를 "windowSize개 요청 전"으로 한정해 설명한다. 내 랜덤 시뮬레이션에서는 nc 순서가 뒤섞이면 그 이후에도 재사용이 가능했다. 이것은 옮긴 로직으로 돌린 결과일 뿐 실제 서버에서는 검증하지 않았다.

---

## CVE-2026-68525: FORM 로그인 후 redirect가 method별 제약을 우회 (수정 커밋 10d048e1)

**11.0.24의 흐름** (`AuthenticatorBase.invoke`)

- 디스크립터: `(Lorg/apache/catalina/connector/Request;Lorg/apache/catalina/connector/Response;)V`

```java
520  boolean authRequired = isContinuationRequired(request);       // FORM: 저장된 요청과 URI가 같으면 true
524  SecurityConstraint[] constraints = realm.findSecurityConstraints(request, this.context); // 로그인 후 redirect된 GET 기준으로 계산
618  if (jaspicProvider == null && !doAuthenticate(request, response) ...  // FORM: restoreRequest()가 method를 POST로, body를 원래 것으로 바꿈
632  if (constraints != null) {                                       // GET 기준 제약(null일 수 있음)을 그대로 사용
636      if (!realm.hasResourcePermission(request, response, constraints, this.context)) {
```

- `FormAuthenticator.isContinuationRequired`(352-367)의 주석에 이 경우가 직접 적혀 있다: "a resource is protected for some HTTP methods but not protected for GET which is used after authentication when redirecting".
- 11.0.24에서 `restoreRequest`는 `request.getCoyoteRequest().setMethod(method)`(641) 뒤에 `true`만 돌려준다. 그래서 method가 바뀌었다는 사실이 invoke로 전달되지 않는다.

**수정 내용**

```diff
 FormAuthenticator
-    protected boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {
+    protected AuthenticationResult doAuthenticateExtended(Request request, HttpServletResponse response)
 ...
-            if (restoreRequest(request, session)) {
+            AuthenticationResult result = restoreRequest(request, session);
 ...
-    protected boolean restoreRequest(Request request, Session session) throws IOException {
+    protected AuthenticationResult restoreRequest(Request request, Session session) throws IOException {
+        boolean methodChanged = !request.getCoyoteRequest().getMethod().equals(method);
         request.getCoyoteRequest().setMethod(method);
-        return true;
+        if (methodChanged) { return AuthenticationResult.PASSED_CONSTRAINTS_NEED_REFRESH; } else { return AuthenticationResult.PASSED; }
+    protected boolean doAuthenticate(...) { throw new UnsupportedOperationException(); }

 AuthenticatorBase.invoke
-            if (jaspicProvider == null && !doAuthenticate(request, response) || ...
+                AuthenticationResult authenticationResult = doAuthenticateExtended(request, response);
+                if (authenticationResult == AuthenticationResult.PASSED_CONSTRAINTS_NEED_REFRESH) {
+                    // Recalculate constraints since the request has changed
+                    constraints = realm.findSecurityConstraints(request, this.context);
+                    disableCaching(constraints, request, response);
+                    if (!checkUserDataConstraints(realm, constraints, request, response)) { return; }
+                }
```

- 커밋 10d048e 시점의 `AuthenticatorBase.java`와 `FormAuthenticator.java`는 11.0.25와 바이트 단위로 같다.
- 수정 여부를 바이트코드로 구분하는 표시:
  - `AuthenticatorBase$AuthenticationResult` 클래스가 있는지
  - `FormAuthenticator.restoreRequest`의 반환 디스크립터가 `Z`에서 `...AuthenticatorBase$AuthenticationResult;`로 바뀌었는지

---

## 기본 Spring Boot 앱의 노출 여부

**확인한 범위**
- Spring Boot v4.0.8과 v4.1.1. 두 버전 모두 `gradle.properties`가 `tomcatVersion=11.0.24`다.
- `TomcatServletWebServerFactory.prepareContext`(v4.0.8 기준 184행, v4.1.1 기준 205행)는 `context.addLifecycleListener(new FixContextListener())`만 추가한다.
  - SecurityConstraint, LoginConfig, Realm, Authenticator는 설정하지 않는다.
  - `ContextConfig`도 붙이지 않는다. 그래서 web.xml을 처리하지 않고, auth-method에 따른 authenticator 자동 설치도 없다.
- 같은 모듈의 `TomcatWebServerFactory`, `TomcatEmbeddedContext`, `TomcatWebServer`, autoconfigure customizer 2개에도 관련 코드가 없다(grep 0건).
  - 다만 spring-boot 레포 전체를 검색한 것은 아니다.

**Tomcat 쪽 동작** (11.0.24)
- `Tomcat.FixContextListener`(1113-1118): `if (context.getLoginConfig() == null) { setLoginConfig(new LoginConfig("NONE",...)); getPipeline().addValve(new NonLoginAuthenticator()); }`
  - 그래서 모든 요청이 `AuthenticatorBase.invoke`를 거친다.
  - `Realm.findSecurityConstraints`(Tomcat.SimpleRealm → RealmBase)도 요청마다 호출되지만, 제약이 0개라 null을 돌려준다(550-556행).
  - 그 뒤 invoke 531-537행에서 바로 다음 valve로 넘어간다.
- DIGEST나 FORM을 쓰려면 앱이 직접 `DigestAuthenticator`/`FormAuthenticator` valve를 넣어야 한다. `ContextConfig.authenticatorConfig()`(337-402)는 임베디드 Spring Boot에서는 실행되지 않기 때문이다.
- 요약: 메서드 단위 도달성만 보면 `AuthenticatorBase.invoke`와 `RealmBase.findSecurityConstraints`가 "도달 가능"으로 잡혀서 오탐이 된다. 취약 분기에 도달하는지는 설정을 봐야 판정할 수 있다.
