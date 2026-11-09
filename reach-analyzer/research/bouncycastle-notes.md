# BouncyCastle CVE 2건 조사 노트 (bcprov-jdk18on 1.81)

`bouncycastle.json`의 근거를 줄여서 남긴다. 각 항목에 **검증**(소스, javap, 로컬 실행으로 확인)과 **추론**(확인한 사실에서 이끌어낸 판단)을 구분해 표시했다.

## 출처와 방법

- **bc-java 소스**: `raw.githubusercontent.com/bcgit/bc-java/<tag>/...`에서 받았다.
  - 태그 이름 형식은 `r1rv81` = 1.81, `r1rv81v1` = 1.81.1, `r1rv80v2` = 1.80.2.
  - 받은 태그: r1rv59, r1rv63, r1rv78v1, r1rv80, r1rv80v1, r1rv80v2, r1rv81, r1rv81v1, r1rv82, r1rv83, r1rv84, r1rv85, r1rv85v2, r1rv86.
  - 수정 커밋 시점의 파일도 받았다: 701686cb, b4257434, 2c28b253.
  - 받은 파일: `bc-src/{gost,nc,prov,tls,pkix,argon2}/`, diff: `bc-src/diffs/`
- **릴리스 노트**: `docs/releasenotes.html @ r1rv85`
  - main 브랜치에서는 404였다.
  - 텍스트로 바꾼 파일: `bc-src/releasenotes/releasenotes-r1rv85.txt`
- **벤더 advisory**: GitHub wiki 원문을 `raw.githubusercontent.com/wiki/bcgit/bc-java/CVE‐2025‐14813.md`에서 받았다. 페이지 이름의 하이픈은 U+2010이다.
  - 저장 위치: `bc-src/wiki/`
- **CVSS, GHSA, 영향 범위**: opencve, db.gcve.eu, GitLab advisory DB를 WebFetch로 확인했다.
- **JVM 디스크립터**: 로컬 `bcprov-jdk18on-1.78.1.jar`에 `javap -p -s -c`를 실행해 확인했다.
  - 관련 소스는 1.78.1과 1.81이 **같다**. 파일별로 diff를 해서 확인했다.
    - `G3413CTRBlockCipher`
    - `asn1.x509.PKIXNameConstraintValidator`
    - `jce.provider.PKIXNameConstraintValidator`
    - `Blake2bDigest`, `Argon2Parameters`
  - `Argon2BytesGenerator`는 입력 검증 코드만 다르고 import 목록은 같다.
- **로컬 재현**: `bc-poc/*.java`를 bcprov 1.78.1과 JDK 21.0.12로 실행했다. 출력은 `bc-poc/*.out.txt`에 있다.
- **막혀서 쓰지 않은 곳** (curl 기준, 우회하지 않았다): github.com, api.github.com, osv.dev, nvd, bouncycastle.org, Maven Central

---

## CVE-2025-14813: GOSTCTR가 255블록을 넘으면 키스트림을 재사용

### 결함 클래스 (검증)

결함은 `org.bouncycastle.crypto.modes.G3413CTRBlockCipher`에 있다. GOST R 34.13-2015 CTR 모드이고, `getAlgorithmName()`은 `"<cipher>/GCTR"`을 돌려준다.

- **GOFBBlockCipher가 아니다**
  - GOFB는 GOST 28147-89의 "GCTR" gamming 모드이고, 이름이 비슷할 뿐이다.
  - r1rv83→r1rv84 사이에 GOFB와 SIC 파일은 바뀌지 않았다.
- **`GCTRBlockCipher`라는 클래스는 없다** (raw에서 404).
- 벤더 wiki 원문: "The GOST-R-3413-2015 CTR implementation in G3413CTRBlockCipher was using a single byte as a counter ... unable to encrypt or decrypt more than 255 blocks."
- GHSA 제목은 "GOST 28147 CTR mode"이지만 본문은 G3413CTRBlockCipher를 가리킨다.

**1.81 소스** (`gost/G3413CTRBlockCipher-r1rv81.java`):

```java
173  protected byte calculateByte(byte in) {
176      if (byteCount == 0) { buf = generateBuf(); }      // CTR을 암호화해 키스트림 생성
181      byte rv = (byte)(buf[byteCount] ^ in);
184      if (byteCount == s) { byteCount = 0; generateCRT(); }
194  private void generateCRT() {
196      CTR[CTR.length - 1]++;                             // 마지막 1바이트만 증가, carry 없음
```

`init`에 대한 메모 (L88-97):
- IV 길이는 반드시 blockSize/2다.
- CTR은 `IV || 00..00`으로 시작한다.
- 따라서 256번째 증가에서 counter가 0으로 돌아가고, block[256]이 block[0]의 키스트림을 다시 쓴다.

### 수정 diff (검증)

r1rv81→r1rv81v1 diff다. r1rv80→r1rv80v2, r1rv83→r1rv84도 같은 내용이고, r1rv81v1 파일은 r1rv84와 같다.

```diff
@@ calculateByte
-            generateCRT();
+            generateCTR();
@@
-    private void generateCRT()
+    private void generateCTR()
     {
-        CTR[CTR.length - 1]++;
+        int start = CTR.length - 1;
+        while (++CTR[start] == 0)
+        {
+            start--;
+            if (start == IV.length - 1)
+            {
+                throw new IllegalStateException("attempt to process too many blocks");
+            }
+        }
     }
```

- 같은 소스가 쓰인 범위
  - r1rv59, r1rv63, r1rv80, r1rv80v1, r1rv81, r1rv82, r1rv83의 파일은 모두 같다. 모두 취약하다.
  - r1rv84, r1rv86, main의 파일은 모두 같다. 모두 수정되어 있다.
- 커밋 `701686cb` 시점의 파일은 r1rv84와 같다.
- 커밋 `b4257434` 시점의 파일에는 루프 안에 `CTR[start]++;`가 한 줄 더 있다.
  - 이렇게 하면 carry가 생길 때 두 번 증가한다.
  - 확인한 어느 릴리스 태그에도 이 형태는 없다.
  - 커밋 순서와 브랜치는 확인하지 못했다. GitHub 커밋 메타데이터가 막혀 있다.

### javap (bcprov 1.78.1)

```
private void generateCRT();                 descriptor: ()V
   0: aload_0; getfield CTR; aload_0; getfield CTR; arraylength; iconst_1; isub; dup2; baload; iconst_1; iadd; i2b; bastore; return
protected byte calculateByte(byte);         descriptor: (B)B     -> invokespecial generateBuf:()[B, invokespecial generateCRT:()V
public int processBlock(byte[], int, byte[], int);  descriptor: ([BI[BI)I  -> invokevirtual processBytes:([BII[BI)I
public <init>(BlockCipher)                  descriptor: (Lorg/bouncycastle/crypto/BlockCipher;)V
public <init>(BlockCipher, int)             descriptor: (Lorg/bouncycastle/crypto/BlockCipher;I)V
StreamBlockCipher.processBytes              descriptor: ([BII[BI)I ; returnByte (B)B ; DefaultMultiBlockCipher.processBlocks ([BII[BI)I
```

**버전 지문** (검증): 취약한 jar에는 `generateCRT()V`가 있고, 수정된 jar에는 `generateCTR()V`가 있다. 메서드 이름이 바뀌었기 때문이다.

### 도달 경로

1. **lightweight API** (검증): `G3413CTRBlockCipher`를 직접 생성하거나 `BufferedBlockCipher`로 감싸서 쓰는 경우.
   - 엔진은 상관없다. GOST3412_2015Engine(Kuznyechik), GOST28147Engine(Magma) 모두 해당한다.
2. **JCE** (검증):
   - 1.81 `GOST3412_2015.java` L66-72에 `super(new BufferedBlockCipher(new G3413CTRBlockCipher(new GOST3412_2015Engine())), true, 64);`가 있다.
   - L119에서 `"Cipher.GOST3412-2015/CTR"`로 등록한다.
   - 1.78.1 jar의 상수 풀을 스캔하면, `G3413CTRBlockCipher`를 참조하는 클래스는 `GOST3412_2015$CTR` 하나뿐이다.
3. **도달하지 않는 경로** (검증)
   - `GOST28147/GOFB`: `BaseBlockCipher` L500-505에서 `GOFBBlockCipher`로 간다.
   - `GOST28147/CTR`: `BaseBlockCipher` L485-498에서 `SICBlockCipher`로 간다.
   - bctls 1.81의 `BcTlsCrypto`와 `JcaTlsCrypto`는 `KUZNYECHIK_CTR_OMAC`, `MAGMA_CTR_OMAC` 스위트에서 `TlsFatalAlert(internal_error)`를 던지거나 `false`를 돌려준다. 즉 TLS 경로는 없다.
4. **"GOSTCTR"라는 JCE 별칭은 없다** (검증): 1.78.1 jar와 1.81 소스를 grep해서 확인했다.

### 로컬 재현 (검증, `bc-poc/GostCtrWrap.out.txt`)

```
lightweight GOST3412_2015/GCTR blockSize=16 keystream block[256]==block[0]: true
lightweight GOST28147/GCTR blockSize=8 keystream block[256]==block[0]: true
JCE GOST3412-2015/CTR/NoPadding (BC) impl=BC keystream block[256]==block[0]: true
JCE GOST28147/CTR/NoPadding (BC, SICBlockCipher) block[256]==block[0]: false
JCE GOST28147/GOFB/NoPadding (BC, GOFBBlockCipher) block[256]==block[0]: false
```

### 버전 (검증)

- **영향 범위** (wiki, CNA, GitLab): 1.59 ≤ v < 1.80.2, 1.81 ≤ v < 1.81.1, 1.82 ≤ v < 1.84
- **수정 버전**: 1.80.2, 1.81.1, 1.84
- **설치된 1.81은 취약하다.**
  - 1.84 릴리스 노트 "2.2.4 Security Fixes"에 `CVE-2025-14813 - GOSTCTR implementation unable to process more than 255 blocks correctly.`가 있다.
- **1.81.1은 CVE-2026-8763을 고치지 않는다.**
  - r1rv81v1의 validator는 r1rv81과 같다.

---

## CVE-2026-8763: rfc822Name, URI 끝의 점(trailing dot)으로 Name Constraints 우회

### 벤더 설명 (wiki 원문)

> In PKIXNameConstraintValidator, the dNSName path strips trailing dots before comparison, but the rfc822Name (isEmailConstrained) and URI (isURIConstrained) paths compare the extracted host with a bare equalsIgnoreCase. A leaf cert with SAN rfc822Name "ceo@bank.com." therefore does not match an excludedSubtrees entry of "bank.com", so checkExcludedEmail never throws and the path validates. This is reachable from the production PKIXCertPathValidatorSpi_8 → RFC3280CertPathUtilities.processCertBC code path.

### 메서드 이름 주의 (검증)

advisory에 나오는 메서드 이름은 1.84에서 리팩터링된 뒤의 이름이다.

| | 1.84+ (advisory) | 1.78.1 ~ 1.83 (설치된 1.81 포함) |
|---|---|---|
| email | `private static isEmailConstrained(String constraint, String email)` | `private boolean emailIsConstrained(String email, String constraint)` (인스턴스 메서드, 인자 순서 반대) |
| URI | `isURIConstrained(String constraint, String uri)` (static) | `isUriConstrained(String uri, String constraint)` |

- 디스크립터는 둘 다 `(Ljava/lang/String;Ljava/lang/String;)Z`이다. 규칙을 만들 때 두 이름을 모두 매칭해야 한다.
- core validator 소스는 r1rv78v1 = r1rv81 = r1rv81v1 = r1rv82 = r1rv83이다. r1rv84에서 리팩터링되었다.

**1.81 소스** (`nc/core-PKIXNameConstraintValidator-r1rv81.java`):

```java
1028 private boolean emailIsConstrained(String email, String constraint) {
1030     String sub = email.substring(email.indexOf('@') + 1);
1032     if (constraint.indexOf('@') != -1) {  if (email.equalsIgnoreCase(constraint)) return true;
                                              if (sub.equalsIgnoreCase(constraint.substring(1))) return true; }
1043     else if (!(constraint.charAt(0) == '.')) { if (sub.equalsIgnoreCase(constraint)) return true; }  // 끝의 점 처리 없음
1051     else if (withinDomain(sub, constraint)) return true;
1059 private boolean withinDomain(String testDomain, String domain)   // Strings.split(testDomain,'.') -> "a.b.c." 는 [a,b,c,""]가 되어 라벨이 어긋남
1801 private boolean isUriConstrained(String uri, String constraint) {
1803     String host = extractHostFromURL(uri);
1807         if (host.equalsIgnoreCase(constraint)) return true;     // 끝의 점 처리 없음
1814     else if (withinDomain(host, constraint)) return true;
```

`Strings.split`(1.81)의 동작:
- `tokenLocation > 0` 조건으로 자른다.
- 그래서 끝에 구분자가 있으면 마지막 원소가 `""`가 된다 (`argon2/Strings-r1rv81.java`).

### 수정 diff (검증)

r1rv84 → 커밋 2c28b253 사이의 diff를 줄였다. 전체는 `diffs/PKIXNameConstraintValidator_r1rv84_to_commit_2c28b253.diff`에 있다.

```diff
@@ isEmailConstrained
         if (atPos > 0)
-            return email.equalsIgnoreCase(constraint);
+            return stripTrailingDot(email).equalsIgnoreCase(stripTrailingDot(constraint));
-        String sub = email.substring(email.indexOf('@') + 1);
+        String sub = stripTrailingDot(email.substring(email.indexOf('@') + 1));
-            return sub.equalsIgnoreCase(constraint.substring(1));
+            return sub.equalsIgnoreCase(stripTrailingDot(constraint.substring(1)));
-        return sub.equalsIgnoreCase(constraint);
+        return sub.equalsIgnoreCase(stripTrailingDot(constraint));
@@ withinDomain
+        testDomain = stripTrailingDot(testDomain);
+        domain = stripTrailingDot(domain);
@@ isDNSConstrained
-        return dns.equalsIgnoreCase(constraint) || withinDomain(dns, constraint);
+        String normDns = stripTrailingDot(dns);
+        String normConstraint = stripTrailingDot(constraint);
+        return normDns.equalsIgnoreCase(normConstraint) || withinDomain(normDns, normConstraint);
+    private static String stripTrailingDot(String s) { ... s.length() > 1 && endsWith('.') -> substring ... }
@@ isURIConstrained
-        String host = extractHostFromURL(uri);
+        String host = stripTrailingDot(extractHostFromURL(uri));
-        return host.equalsIgnoreCase(constraint);
+        return host.equalsIgnoreCase(stripTrailingDot(constraint));
@@ extractHostFromURL  -> RFC 3986 방식으로 다시 작성 (마지막 '@', '?', '#', IPv6 대괄호 처리)
```

- **같은 diff 범위에 다른 강화도 함께 들어 있다**
  - directoryName을 prefix로만 매칭한다. SGP.22 완화 모드는 property 뒤로 옮겼다.
  - `isIPConstrained`에서 IPv4-mapped IPv6를 정규화한다.
  - 1.85 최종본은 '@'가 여러 개인 rfc822Name을 거부한다. 끄려면 `org.bouncycastle.x509.allow_lenient_rfc822_name`을 쓴다.
- **1.85 릴리스 노트** (r1rv85)
  - Security Fixes에 `CVE-2026-8763 - Name Constraints bypass via trailing dot in rfc822Name and URI.`가 있다.
  - 결함 수정 항목: "(2) rfc822Name and uniformResourceIdentifier host comparisons used an exact case-insensitive compare while the dNSName path strips an RFC 1034 root-label trailing dot ... the email and URI host forms now apply the same trailing-dot canonicalisation before comparison."
- **수정 지문**: 수정된 jar의 `asn1.x509.PKIXNameConstraintValidator`에는 `private static stripTrailingDot(Ljava/lang/String;)Ljava/lang/String;`가 있다.

### javap 디스크립터와 호출 관계 (bcprov 1.78.1, `javap -c`로 확인)

```
asn1.x509.PKIXNameConstraintValidator
  public checkPermitted (Lorg/bouncycastle/asn1/x509/GeneralName;)V -> checkPermittedEmail / checkPermittedURI / checkPermittedDNS
  public checkExcluded  (Lorg/bouncycastle/asn1/x509/GeneralName;)V -> checkExcludedEmail / checkExcludedURI / checkExcludedDNS
  private checkPermittedEmail|checkExcludedEmail (Ljava/util/Set;Ljava/lang/String;)V -> emailIsConstrained
  private checkPermittedURI|checkExcludedURI     (Ljava/util/Set;Ljava/lang/String;)V -> isUriConstrained
  private emailIsConstrained (Ljava/lang/String;Ljava/lang/String;)Z -> withinDomain
  private isUriConstrained   (Ljava/lang/String;Ljava/lang/String;)Z -> extractHostFromURL, withinDomain
  private withinDomain       (Ljava/lang/String;Ljava/lang/String;)Z   (DNS, intersect*, union*에서도 호출)
  private static extractHostFromURL (Ljava/lang/String;)Ljava/lang/String;
jce.provider.PKIXNameConstraintValidator  (위임 facade)
  public checkPermitted|checkExcluded (Lorg/bouncycastle/asn1/x509/GeneralName;)V
jce.provider.RFC3280CertPathUtilities
  protected static processCertBC (Ljava/security/cert/CertPath;ILorg/bouncycastle/jce/provider/PKIXNameConstraintValidator;Z)V
     -> checkPermitted/checkExcluded (subject DN의 emailAddress RDN을 rfc822Name으로 검사 L1116-1125, 모든 SAN 검사 L1155-1156)
  protected static prepareNextCertG (...;I;...PKIXNameConstraintValidator;)V -> intersectPermittedSubtree / addExcludedSubtree
jce.provider.PKIXCertPathValidatorSpi_8 / PKIXCertPathValidatorSpi
  public engineValidate (Ljava/security/cert/CertPath;Ljava/security/cert/CertPathParameters;)Ljava/security/cert/CertPathValidatorResult; -> processCertBC, prepareNextCertG
jce.provider.PKIXCertPathBuilderSpi_8
  protected build (Ljava/security/cert/X509Certificate;Lorg/bouncycastle/jcajce/PKIXExtendedBuilderParameters;Ljava/util/List;)Ljava/security/cert/CertPathBuilderResult; -> new PKIXCertPathValidatorSpi_8(Z), engineValidate
  public engineBuild (Ljava/security/cert/CertPathParameters;)Ljava/security/cert/CertPathBuilderResult;
x509.PKIXCertPathReviewer
  private checkNameConstraints ()V  <- protected doChecks ()V <- public isValidCertPath ()Z / getErrors ()[Ljava/util/List;
```

- 1.78.1 jar의 상수 풀을 스캔한 결과
  - `jce.provider.PKIXNameConstraintValidator`를 참조하는 클래스: `PKIXCertPathValidatorSpi`, `PKIXCertPathValidatorSpi_8`, `RFC3280CertPathUtilities`, `PKIXCertPathReviewer`
  - `asn1.x509.PKIXNameConstraintValidator`를 참조하는 클래스: jce facade 하나뿐
- **BC 1.81 validator는 TrustAnchor의 name constraints를 쓰지 않는다** (검증): `PKIXCertPathValidatorSpi(_8)`는 빈 validator를 만들고, `getNameConstraints()`를 참조하지 않는다. 제약은 path 안의 CA 인증서(`prepareNextCertG`)에서만 들어온다.

### Provider 등록과 기본 조회 (검증)

**BouncyCastleProvider 1.81** (L239-246): `PKIXRevocationChecker` 클래스가 있으면(Java 8 이상), 다음처럼 등록한다.
- `CertPathValidator.PKIX`, `CertPathValidator.RFC3280` → `PKIXCertPathValidatorSpi_8`
- `CertPathBuilder.PKIX`, `CertPathBuilder.RFC3280` → `PKIXCertPathBuilderSpi_8`

**JDK 21.0.12** (`javap -c --module java.base sun.security.validator.PKIXValidator`):
- `doValidate`가 `CertPathValidator.getInstance:(Ljava/lang/String;)` with "PKIX"를 호출한다.
- `doBuild`가 `CertPathBuilder.getInstance:(Ljava/lang/String;)` with "PKIX"를 호출한다.
- 즉 provider를 지정하지 않는다. BC가 SUN보다 앞에 등록되어 있으면 SunJSSE의 기본 trust manager도 BC 검증기를 쓴다.

**로컬 확인** (`bc-poc/NcCertPath.out.txt`):

```
default PKIX CertPathValidator provider with BC appended: SUN
default PKIX CertPathValidator provider with BC inserted at 1: BC / CertPathBuilder: BC / X.509 CertificateFactory: BC
```

### BCJSSE (bctls 1.81) (검증)

- `ProvX509TrustManager` L214-235:
  - `helper.createCertificateFactory("X.509").getProvider()`로 provider를 고른다.
  - 그 provider로 `CertPathBuilder.getInstance("PKIX", pkixProvider)`를 호출한다. 실패하면 provider 없이 다시 호출한다.
- `new BouncyCastleJsseProvider()`:
  - config가 "default"이면 `new JcaTlsCryptoProvider()`를 쓰고, helper는 `DefaultJcaJceHelper`다.
  - 따라서 우선순위가 가장 높은 X.509 CertificateFactory provider가 쓰인다. BC가 1순위라면 BC다.

### 로컬 재현 (검증)

**validator 직접 호출** (`bc-poc/NcTrailingDot.out.txt`):

```
rfc822Name  excluded=bank.com            name=user@bank.com        -> REJECTED
rfc822Name  excluded=bank.com            name=user@bank.com.       -> ACCEPTED (not excluded)
rfc822Name  excluded=.bank.com           name=user@mail.bank.com.  -> ACCEPTED (not excluded)
URI         excluded=competitor.example  name=https://competitor.example./ -> ACCEPTED (not excluded)
dNSName     excluded=bank.com            name=www.bank.com.        -> ACCEPTED (not excluded)
```

**CertPathValidator 끝까지** (`bc-poc/NcCertPath.out.txt`):
- 체인은 Root → 제약이 있는 Sub-CA (excluded rfc822Name bank.com, URI competitor.example) → leaf다.

```
SAN rfc822 user@bank.com    BC: REJECTED: Subtree check ... failed.  | SUN: REJECTED: name constraints check failed
SAN rfc822 user@bank.com.   BC: VALID (provider=BC)                  | SUN: VALID (provider=SUN)
SAN uri    https://competitor.example./  BC: VALID (provider=BC)     | SUN: VALID (provider=SUN)
```

- **범위 밖 관찰**: 같은 체인을 OpenJDK 21.0.12의 SUN PKIX 검증기도 통과시켰다.
  - 이 CVE는 BC만 다룬다.
  - 하지만 "BC를 안 쓰면 이 우회 자체가 사라진다"고 볼 수는 없다.

### dNSName 메모 (검증과 추론)

- **검증**
  - 1.81과 1.84 코드의 dNSName 경로(`checkExcludedDNS` → `withinDomain`/`equalsIgnoreCase`)도 끝의 점을 처리하지 않는다. 로컬 테스트에서 우회되었다.
  - 1.85에서 `isDNSConstrained`에 `stripTrailingDot`이 추가되었다.
- **추론**: wiki의 "dNSName path strips trailing dots"는 1.85 개발 중 main 상태를 말한 것으로 보인다. CVE 제목은 rfc822Name과 URI만 적고 있어서, dNSName이 같은 CVE ID에 포함되는지는 불분명하다.

### 버전 (검증)

- **영향 범위**: bcprov-jdk18on < 1.85 (GHSA-9pwp-9qqc-pr26, GitLab: "All versions before 1.85.0")
- **수정 버전**: 1.85
  - r1rv85와 r1rv85v2의 validator는 같고, 둘 다 수정되어 있다.
  - LTS 2.73.12, bc-fips 1.0.2.7 / 2.0.2 / 2.1.3도 수정 버전이다.
- **1.81.x 백포트는 없다.**
  - r1rv81v1의 validator는 r1rv81과 같다.
  - `r1rv81v2` 태그는 404다.
- **bcpkix 1.81** (검증): `org.bouncycastle.pkix.ASN1PKIXNameConstraintValidator`에 같은 로직의 별도 복사본이 있다 (`emailIsConstrained` L1016, `isUriConstrained` L1789).
  - 1.85 노트에 따르면 이 복사본은 제거되었고, core 클래스로 위임하도록 바뀌었다.
  - advisory의 패키지 목록에는 bcpkix가 없다.

---

## Spring Security 7.1.1 `Argon2PasswordEncoder`

### 호출하는 BC API (검증, 태그 7.1.1 소스)

**`Argon2PasswordEncoder`**
- `encodeNonNullPassword` (L111)과 `matchesNonNull` (L130)
  - `new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)`
    `.withSalt([B)` `.withParallelism(I)` `.withMemoryAsKB(I)` `.withIterations(I)` `.build()`
  - `new Argon2BytesGenerator()` `.init(Lorg/bouncycastle/crypto/params/Argon2Parameters;)V`
    `.generateBytes([C[B)I`
- `upgradeEncodingNonNull` (L147): `Argon2Parameters.getMemory()`, `getIterations()`

**`Argon2EncodingUtils`**
- `encode` (L59): `getType`, `getVersion`, `getMemory`, `getIterations`, `getLanes`, `getSalt`
- `decode` (L103): `Builder(int)`, `withVersion(I)`, `withMemoryAsKB`, `withIterations`, `withParallelism`, `withSalt`, `build`
- `Argon2Hash`: `org.bouncycastle.util.Arrays.clone([B)[B`

**Provider 등록 여부**: 다른 BC 사용 클래스 4개(`BouncyCastleAes{,Cbc,Gcm}BytesEncryptor`, `SCryptPasswordEncoder`)를 포함해 `Security.addProvider` / `insertProviderAt` 호출은 없다.

### BC 내부 호출 범위

- **검증**: 1.81 소스 기준 import 목록
  - `Argon2BytesGenerator`: Digest, Blake2bDigest, Argon2Parameters, Arrays, Longs, Pack
  - `Blake2bDigest`: CryptoServicePurpose, CryptoServicesRegistrar, ExtendedDigest, OutputLengthException, Arrays, Longs, Pack, 같은 패키지의 Utils
- **검증**: bcprov 1.78.1에 jdeps `-verbose:class`를 돌려 Argon2 진입 클래스들에서 클래스 단위 전이 폐포를 구했다 (`argon2/argon2-class-closure-1.78.1.txt`).
  - 274개 클래스이고, 실제보다 넓게 잡은 근사다.
  - 폐포 안에 `org.bouncycastle.crypto.modes.*`, `asn1.x509.*`, `jce.*`, `jcajce.*`가 하나도 없다.
  - 리플렉션(`Class.forName` / `loadClass` / `ClassLoader`) 호출도 0건이다.
- **결론 (추론, 근거 강함)**: Argon2 경로로는 두 CVE의 결함 메서드에 도달할 수 없다.
  - 앱의 인자 `(16, 32, 1, 19456, 2)`는 Argon2의 메모리와 반복 횟수만 바꾼다.

---

## OkHttp 4.12.0 (검증, `square/okhttp` 태그 `parent-4.12.0`)

- **BC 참조**
  - `BouncyCastlePlatform.kt`는 `org.bouncycastle.jsse.BCSSLSocket`과 `org.bouncycastle.jsse.provider.BouncyCastleJsseProvider`만 import한다. 둘 다 bctls 클래스다.
  - Android 전용 `android/BouncyCastleSocketAdapter.kt`도 bctls 클래스만 쓴다.
- **플랫폼 선택**: `Platform.kt` L212-216, L230-245
  - `isBouncyCastlePreferred = Security.getProviders()[0].name == "BC"`
    - bcprov의 JCA provider("BC")가 **1순위**여야 한다. "BCJSSE"가 아니다.
  - 그리고 `BouncyCastlePlatform.isSupported`가 참이어야 한다.
    - 이 값은 `Class.forName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider")`가 성공하는지로 정해진다. 즉 bctls가 있어야 한다.
  - `okhttp.platform` 같은 시스템 property는 4.12.0에 없다.
    - 코드가 읽는 property는 `java.vm.name`과 `java.specification.version`뿐이다.
  - 따라서 **bcprov만 있으면 BouncyCastlePlatform은 켜지지 않고 Jdk9Platform이 쓰인다.**
- **BouncyCastlePlatform이 켜진 경우**
  - `platformTrustManager()`는 `TrustManagerFactory.getInstance("PKIX", "BCJSSE")`를 호출한다.
    - BCJSSE도 이름으로 등록되어 있어야 한다. 아니면 `NoSuchProviderException`이 난다 (추론: 동작 실패 모드).
  - 이후 경로는 `ProvX509TrustManager` → `CertPathBuilder("PKIX", BC)` → `PKIXCertPathBuilderSpi_8` → `PKIXCertPathValidatorSpi_8` → `processCertBC`다. CVE-2026-8763의 코드가 실행된다.
- **Jdk9Platform인 경우** (기본)
  - SunJSSE trust manager → `PKIXValidator` → provider를 지정하지 않은 "PKIX" 조회 → SUN
  - BC가 SUN보다 앞에 등록되어 있을 때만 BC로 간다.
- **CVE-2025-14813**: OkHttp는 bcprov의 cipher mode를 직접 쓰지 않는다. bctls 1.81은 GOST CTR_OMAC 스위트를 구현하지 않았다. 따라서 관련이 없다.

---

## 확인하지 못한 것

- 실제 앱 jar(`BOOT-INF/lib`)는 보지 못했다. 다음은 확인되지 않은 상태다.
  - bctls-jdk18on, bcpkix-jdk18on이 있는지
  - "GOST3412-2015/CTR" 문자열 상수가 있는지
  - `BouncyCastleProvider` 등록 코드나 설정이 있는지
- bcprov **1.81** jar 전체에서 `G3413CTRBlockCipher` 참조를 스캔하지 못했다. 1.81 jar를 구할 수 없었다.
  - 1.78.1 jar 스캔과 1.81 JCE 매핑 소스로 대신했다.
  - 1.79~1.82 릴리스 노트에는 GOST CTR 관련 변경이 없다.
- GHSA 원문(github.com/advisories)은 막혀 있었다. GHSA ID는 opencve와 GitLab advisory DB 두 곳에서 일치하는 것을 확인했다.
- 커밋 b4257434와 701686cb의 순서와 브랜치는 확인하지 못했다.
- dNSName 끝의 점 우회가 CVE-2026-8763 범위에 들어가는지는 불분명하다.
- Spring Security의 BC 사용 클래스는 위 6개만 확인했다. 레포 전체를 grep할 수 없었다.
