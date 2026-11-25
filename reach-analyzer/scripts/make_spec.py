#!/usr/bin/env python3
"""Builds the backend's src/main/resources/reach/vuln-functions.json from research/*.json.

The research files hold the full evidence (diffs, sources). The spec keeps only what the
reachability tool needs: package, versions, sink methods, and a short Korean summary.

This is how the first 14 CVEs were made. Newer data is added to the spec directly by
vulndata/vulndata.py, and the L3 regions (`l3`) were written into the spec too. So a re-run keeps
what is only in the spec: the `l3` of each CVE and the CVEs that are not in research/*.json.
"""
import json, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
R = ROOT / "research"
# The dashboard backend serves the same file (API-10) and the analyzer reads it, so there is one copy.
OUT = ROOT.parent / "src" / "main" / "resources" / "reach" / "vuln-functions.json"

SUMMARY_KO = {
    "CVE-2026-65182": "보안 제약(security-constraint) 경로 매칭에서, 같은 컬렉션 안에 긴 경로가 짧은 하위 경로보다 먼저 선언되면 더 엄격한 제약이 밀려나 접근 제어가 우회된다.",
    "CVE-2026-65905": "Tomcat DIGEST 인증의 nonce count 재전송 창 계산 순서가 틀려, 창 상한값의 요청을 한 번 재전송할 수 있다.",
    "CVE-2026-68525": "Tomcat FORM 인증 후 저장된 POST 요청을 복원할 때, GET 기준으로 계산한 보안 제약을 그대로 써서 POST 전용 제약이 우회된다.",
    "CVE-2025-14813": "GOST R 34.13-2015 CTR 모드(G3413CTRBlockCipher)가 카운터의 마지막 1바이트만 증가시켜, 256블록 이후 키스트림이 반복된다.",
    "CVE-2026-8763": "인증서 이름 제약(Name Constraints) 검사에서 rfc822Name·URI 호스트 끝의 점(.)을 정규화하지 않아, 제외 목록(excluded subtree)을 우회할 수 있다.",
    "CVE-2026-89407": "숫자 문자열 검사 정규식(NumberInput.looksLikeValidNumber)의 백트래킹 때문에, 문자열로 들어온 값을 float/double/BigDecimal/Number로 변환할 때 CPU를 과도하게 쓴다(ReDoS).",
    "CVE-2026-89425": "DataInput 기반 파서(UTF8DataInputJsonParser)가 오류 토큰 길이 제한을 적용하지 않아, 매우 긴 오류 메시지를 만든다.",
    "CVE-2026-68497": "javax.xml.datatype Duration·XMLGregorianCalendar 역직렬화에 숫자 길이 제한이 없어, 큰 입력으로 CPU를 과도하게 쓴다.",
    "CVE-2026-91776": "다형성 역직렬화에서 알 수 없는 type id가 기본 구현으로 대체될 때, type id 캐시가 제한 없이 커진다(메모리 고갈).",
    "CVE-2026-91777": "@JsonIdentityInfo를 쓰는 컬렉션·맵에서 전방 참조가 많으면, 참조 해결이 제곱 시간이 걸린다.",
    "CVE-2026-13506": "ASN.1을 지연 파싱(lazyEvaluate)할 때, 지연된 SEQUENCE를 펼칠 때마다 중첩 깊이 제한이 초기화된다. 깊게 중첩된 입력을 끝까지 순회하면 StackOverflowError로 서비스가 멈춘다(DoS).",
    "CVE-2026-0636": "BouncyCastle LDAP 인증서 저장소가 인증서 DN에서 뽑은 값을 이스케이프하지 않고 LDAP 검색 필터에 넣어, 조작한 DN으로 필터를 바꿀 수 있다(LDAP 인젝션).",
    "CVE-2026-19032": "java.nio.file.Path 역직렬화가 입력 URI의 스킴을 제한하지 않아, 외부 JSON이 등록된 아무 FileSystemProvider나 고르고 호출하게 할 수 있다.",
    "CVE-2026-83557": "@JsonTypeInfo의 기본 검증기가 java.lang.Comparable을 위험한 기반 타입으로 보지 않아, Comparable 타입 속성에 거의 모든 클래스(예: 임의 경로의 java.io.File)를 만들 수 있다.",
}

# Methods that run for every request in the container and therefore are NOT good sinks
# (they would mark the CVE reachable even when the vulnerable branch cannot execute).
EXCLUDE_SINKS = {
    ("org.apache.catalina.Realm", "findSecurityConstraints"),
    ("org.apache.catalina.authenticator.AuthenticatorBase", "invoke"),
    ("org.apache.catalina.authenticator.DigestAuthenticator$DigestInfo", "validate"),
    ("org.apache.catalina.authenticator.FormAuthenticator", "isContinuationRequired"),
    ("org.bouncycastle.crypto.StreamBlockCipher", "processBytes"),          # shared by every stream mode
    ("org.bouncycastle.crypto.modes.G3413CTRBlockCipher", "<init>"),        # covered by the 'new' fact
    ("org.bouncycastle.jcajce.provider.symmetric.GOST3412_2015$CTR", "<init>"),
    ("org.bouncycastle.jce.provider.RFC3280CertPathUtilities", "processCertBC"),
    ("org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi_8", "engineValidate"),
    ("org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi_8", "build"),
    ("org.bouncycastle.x509.PKIXCertPathReviewer", "checkNameConstraints"),
    ("org.bouncycastle.asn1.ASN1InputStream", "buildObject"),               # CVE-2026-13506: shared with eager parsing
}

EXTRA_SINKS = {
    # 1.84+ renamed the 1.81 methods; keep both name sets so a newer jar is still matched.
    "CVE-2026-8763": [
        {"class": "org.bouncycastle.asn1.x509.PKIXNameConstraintValidator", "method": "isEmailConstrained", "desc": "(Ljava/lang/String;Ljava/lang/String;)Z", "confidence": "high", "note": "1.84+ name"},
        {"class": "org.bouncycastle.asn1.x509.PKIXNameConstraintValidator", "method": "isURIConstrained", "desc": "(Ljava/lang/String;Ljava/lang/String;)Z", "confidence": "high", "note": "1.84+ name"},
    ],
}

ARTIFACT = {
    "org.apache.tomcat.embed:tomcat-embed-core": "tomcat-embed-core",
    "org.bouncycastle:bcprov-jdk18on": "bcprov-jdk18on",
    "tools.jackson.core:jackson-core": "jackson-core",
    "tools.jackson.core:jackson-databind": "jackson-databind",
}

cves = []
for f in ["tomcat.json", "bouncycastle.json", "jackson.json"]:
    for c in json.loads((R / f).read_text()):
        sinks = []
        for m in c["vulnerable_methods"]:
            if (m["class"], m["method"]) in EXCLUDE_SINKS:
                continue
            sinks.append({k: m.get(k) for k in ("class", "method", "desc", "confidence")})
        sinks += EXTRA_SINKS.get(c["cve"], [])
        group, artifact = c["package"].split(":")
        cves.append({
            "cve": c["cve"],
            "ghsa": c.get("ghsa"),
            "package": {"coordinates": c["package"], "artifact": ARTIFACT[c["package"]],
                        "installed": c["installed_version"], "fixed": c["fixed_versions"]},
            "severity": c.get("severity"),
            "cvss_vector": c.get("cvss_vector"),
            "invocation_kind": c["invocation_kind"],
            "summary_ko": SUMMARY_KO[c["cve"]],
            "summary_en": c["summary"],
            "sinks": sinks,
            "sources": c.get("sources", [])[:6],
        })

# Keep what only the current spec has (see the module docstring)
current = json.loads(OUT.read_text())["cves"] if OUT.exists() else []
by_cve = {c["cve"]: c for c in current}
for c in cves:
    if "l3" in by_cve.get(c["cve"], {}):
        c["l3"] = by_cve[c["cve"]]["l3"]
made = {c["cve"] for c in cves}
cves += [c for c in current if c["cve"] not in made]

out = {
    "schema": "reach-spec/v0",
    "note": "Sink methods were identified by diffing the vulnerable and fixed releases (see data/research/*-notes.md).",
    "generated": "2026-10-10",
    "cves": cves,
}
OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
print(f"wrote {OUT.relative_to(ROOT.parent)} with {len(cves)} CVEs, {sum(len(c['sinks']) for c in cves)} sinks")
for c in cves:
    print(c["cve"], c["package"]["artifact"], [s["class"].split(".")[-1] + "#" + s["method"] for s in c["sinks"]])
