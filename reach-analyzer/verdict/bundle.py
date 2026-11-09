#!/usr/bin/env python3
"""bundle.py — builds the API-13 result bundle from the scanner and analyzer outputs.

    python3 bundle.py --sbom sbom.cdx.json --trivy trivy.json [--grype grype.json] \
        --reach reach-result.json --verdicts verdicts.json \
        --spec vuln-functions.json --rules rules.json [--jar app.jar] \
        [--tool name=value ...] [--stage name=status[:seconds] ...] --out bundle.json.gz

    # the runner failed before analysis: only tools, stages and failure are sent
    python3 bundle.py --failure-code E-L2-FAILED --failure-stage l2 --failure-message "..." \
        [--tool name=value ...] [--stage name=status[:seconds] ...] --out bundle.json.gz

A target without Java code (npm, OS packages only) has no L2 run: leave out --reach and --verdicts and
every match is NOT_ANALYZED. Maven matches without --reach/--verdicts are an error (the L2 step was skipped).

One bundle item per scanner match (purl x CVE). Matches that verdict.py analysed get its verdict and
evidence; the rest are NOT_ANALYZED with the reason (OS package, unsupported ecosystem, another copy of
an analysed CVE, no vuln function data). Field names follow the API spec 3-3, 3-4, 3-5 (API-13 bundle).
An output path ending in .gz is gzip-compressed (API-13 needs Content-Encoding: gzip).
No third-party dependencies (Python 3.8+).
"""
import argparse
import datetime
import gzip
import hashlib
import json
import re
import sys
from urllib.parse import unquote

STATUS_KO = {"REACHABLE": "도달 가능", "UNREACHABLE": "도달 불가", "UNKNOWN": "미확인"}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
STAGES = ("SBOM", "MATCH", "L1", "L2", "REPORT")
STAGE_STATUSES = ("QUEUED", "RUNNING", "SUCCEEDED", "FAILED")
OS_TYPES = ("apk", "deb", "rpm", "alpm", "apkg")
CLAUSES = {"reachable_if": "REACHABLE", "unreachable_if": "UNREACHABLE", "unknown_if": "UNKNOWN", "otherwise": "DEFAULT"}
# results of the call graph, not facts collected from app code (same split as API-09)
CALLGRAPH_NAMES = ("sink", "sink_weak", "sinks_missing", "package", "package_present")
SUMMARY_MAX = 500
EVIDENCE_SUMMARY_MAX = 1000
MAX_PATHS = 3
MAX_LOCATIONS = 20


class BundleError(Exception):
    pass


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cut(text, limit):
    """Server columns count code points; Python str length is code points too."""
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_purl(purl):
    """pkg:maven/org.bouncycastle/bcprov-jdk18on@1.81 -> ('maven', 'org.bouncycastle', 'bcprov-jdk18on', '1.81')"""
    if not purl or not purl.startswith("pkg:"):
        raise BundleError(f"not a purl: {purl}")
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    path, _, version = body.partition("@")
    parts = path.split("/")
    if len(parts) < 2:
        raise BundleError(f"not a purl: {purl}")
    return parts[0].lower(), "/".join(unquote(p) for p in parts[1:-1]), unquote(parts[-1]), unquote(version)


def coordinates(purl):
    """maven purl -> group:artifact, the form vuln-functions.json and verdict.py use"""
    _, namespace, name, _ = parse_purl(purl)
    return f"{namespace}:{name}" if namespace else name


def split_versions(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def unique(values):
    return list(dict.fromkeys(v for v in values if v))


def severity_of(value):
    upper = (value or "UNKNOWN").upper()
    return upper if upper in SEVERITIES else "UNKNOWN"


# ---------------------------------------------------------------- scanner matches

def trivy_matches(data):
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL")
            if not purl:
                print(f"skip {v.get('VulnerabilityID')} {v.get('PkgName')}: Trivy gave no purl", file=sys.stderr)
                continue
            out.append({
                "source": "TRIVY", "purl": purl, "cve": v["VulnerabilityID"], "version": v.get("InstalledVersion"),
                "path": v.get("PkgPath"), "severity": severity_of(v.get("Severity")), "title": v.get("Title"),
                "description": v.get("Description"), "fixed": split_versions(v.get("FixedVersion")),
                "cwe": v.get("CweIDs") or [], "references": v.get("References") or [],
            })
    return out


def grype_matches(data):
    out = []
    for m in data.get("matches") or []:
        vuln, artifact = m.get("vulnerability") or {}, m.get("artifact") or {}
        purl = artifact.get("purl")
        if not purl:
            print(f"skip {vuln.get('id')} {artifact.get('name')}: Grype gave no purl", file=sys.stderr)
            continue
        # Grype reports GitHub advisories as GHSA-…; the Finding key is the CVE when there is one
        vid = vuln.get("id") or ""
        if not vid.startswith("CVE-"):
            vid = next((r["id"] for r in m.get("relatedVulnerabilities") or [] if r.get("id", "").startswith("CVE-")), vid)
        locations = artifact.get("locations") or []
        out.append({
            "source": "GRYPE", "purl": purl, "cve": vid, "version": artifact.get("version"),
            "path": locations[0].get("path") if locations else None, "severity": severity_of(vuln.get("severity")),
            "title": None, "description": vuln.get("description"),
            "fixed": (vuln.get("fix") or {}).get("versions") or [],
            "cwe": unique(c.get("cwe") for c in vuln.get("cwes") or []), "references": vuln.get("urls") or [],
        })
    return out


def merge_matches(matches):
    """One entry per purl x CVE. Trivy values come first; the same package in two paths is one Finding."""
    merged = {}
    for m in matches:
        key = (m["purl"], m["cve"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = dict(m, sources=[m["source"]], severities={m["source"]: m["severity"]})
            continue
        if m["source"] not in cur["sources"]:
            cur["sources"].append(m["source"])
        cur["severities"].setdefault(m["source"], m["severity"])
        for field in ("version", "path", "title", "description"):
            cur[field] = cur[field] or m[field]
        for field in ("fixed", "cwe", "references"):
            cur[field] = unique(cur[field] + m[field])
    return [merged[k] for k in sorted(merged, key=lambda k: (k[1], k[0]))]


# ---------------------------------------------------------------- verdicts

class Context:
    def __init__(self, reach, verdicts, spec, rules):
        self.l2 = reach is not None
        reach = reach or {}
        verdicts = verdicts or {}
        self.reach_by_cve = {c["cve"]: c for c in reach.get("cves", [])}
        self.reach_facts = reach.get("facts", {})
        # how many places the DTO facts looked at (spec 3-5 checkedCount: "tokens 97개에서 필드를 따라갔다")
        self.checked_counts = {"dto.floating": len(reach.get("dto_roots") or []),
                               "dto.floating.tokens": len(reach.get("dto_type_tokens") or [])}
        self.spec_by_cve = {c["cve"]: c for c in spec["cves"]}
        self.rules = rules.get("verdicts", {})
        self.analysed = {}
        for v in verdicts.get("verdicts", []):
            if v.get("status") != "not_analyzed":
                self.analysed[(v["cve"], v["package"])] = v
        # API-10 ids: file order of every sink, starting at 1 (ReachVulnFunctionData)
        self.function_ids = {}
        n = 0
        for c in spec["cves"]:
            for _ in c.get("sinks", []):
                n += 1
                self.function_ids.setdefault(c["cve"], []).append(n)
        self.engine = {k: v for k, v in {
            "reach": reach.get("tool"),
            "rulesVersion": version_of(rules, "reach-rules/"),
            "vulnFunctionsVersion": version_of(spec, "reach-spec/"),
        }.items() if v is not None}


def version_of(data, prefix):
    schema = data.get("schema", "")
    if not schema.startswith(prefix):
        raise BundleError(f"unexpected schema {schema!r}, expected {prefix}…")
    return schema[len(prefix):]


def not_analyzed(reason, summary, ctx, analysed_at):
    return {"status": "NOT_ANALYZED", "notAnalyzedReason": reason, "summary": summary, "evidence": [],
            "analyzedAt": analysed_at, "engine": ctx.engine}


def verdict_for(match, ctx, analysed_at):
    ptype = parse_purl(match["purl"])[0]
    if ptype in OS_TYPES:
        return not_analyzed("OS_PACKAGE", "OS 패키지라 Java 호출 그래프로 판정하지 않았다.", ctx, analysed_at)
    if ptype != "maven":
        return not_analyzed("UNSUPPORTED_ECOSYSTEM", f"{ptype} 패키지는 아직 L2 판정을 지원하지 않는다.", ctx, analysed_at)
    if not ctx.l2:
        raise BundleError(f"{match['purl']} is a maven package but there is no L2 input (--reach, --verdicts)")
    cve, coords = match["cve"], coordinates(match["purl"])
    v = ctx.analysed.get((cve, coords))
    if v is not None:
        return analysed_verdict(v, ctx, analysed_at)
    spec = ctx.spec_by_cve.get(cve)
    if spec is None:
        return not_analyzed("NO_VULN_FUNCTION_DATA", "취약 함수 데이터(vuln-functions.json)가 없어 판정하지 않았다.",
                            ctx, analysed_at)
    spec_coords = spec["package"]["coordinates"]
    if spec_coords == coords:
        # the CVE and package are in the data, so verdict.py must have judged it: the inputs do not belong together
        raise BundleError(f"{cve} {coords} is in vuln-functions.json but not in verdicts.json")
    return not_analyzed("UNANALYZED_COPY",
                        f"같은 CVE가 다른 패키지에서도 나왔다. 취약 함수 데이터와 규칙은 {spec_coords} 기준이라 "
                        f"이 패키지 사본은 판정하지 않았다.", ctx, analysed_at)


def location(fact, where):
    """'Class#method:21' (app code) or 'src/main/webapp/WEB-INF/web.xml:3' (repo file)"""
    m = re.match(r"^(.*):(\d+)$", where or "")
    base, line = (m.group(1), int(m.group(2))) if m else (where, None)
    loc = {"file": base} if fact.startswith("repo.") else {"symbol": base}
    if line is not None:
        loc["line"] = line
    return loc


def fact_present(fact, occ, informational=False):
    first = occ[0].get("detail") if occ else None
    e = {"kind": "FACT", "factId": f"F-{fact}", "value": True,
         "summary": cut(f"F-{fact} 있음 ({len(occ)}곳)" + (f": {first}" if first else ""), EVIDENCE_SUMMARY_MAX)}
    if informational:
        e["informational"] = True
    locs = [location(fact, o.get("where")) for o in occ[:MAX_LOCATIONS] if o.get("where")]
    if locs:
        e["locations"] = locs
    return e


def short_name(method):
    """org.bouncycastle.crypto.modes.G3413CTRBlockCipher#generateCRT()V -> G3413CTRBlockCipher.generateCRT"""
    cls, _, rest = method.partition("#")
    return f"{cls.rsplit('.', 1)[-1]}.{rest.split('(', 1)[0]}"


def path_evidence(steps, target, label, weak):
    names = [s.get("short") or s.get("method") for s in steps]
    return {"kind": "PATH", "path": names, "pathTarget": target, "candidate": True,
            "entryStage": 2 if steps and steps[0].get("via") == "entry:app-method" else 1, "weak": bool(weak),
            "summary": cut(f"{names[0]}에서 {label}까지 후보 경로({len(names)}단계). 가장 짧은 후보이며 실제 경로와 다를 수 있다",
                           EVIDENCE_SUMMARY_MAX)}


def fact_absent(fact, ctx):
    e = {"kind": "FACT", "factId": f"F-{fact}", "value": False, "summary": f"F-{fact} 없음"}
    count = ctx.checked_counts.get(fact)
    if count:
        e["checkedCount"] = count
        e["summary"] = f"F-{fact} 없음 ({count}곳 확인)"
    return e


def analysed_verdict(v, ctx, analysed_at):
    cve = v["cve"]
    r = ctx.reach_by_cve.get(cve)
    if r is None:
        raise BundleError(f"{cve} is in verdicts.json but not in reach-result.json")
    status = v["status"].upper()
    decided = v.get("decided_by", {})
    sinks = r.get("sinks", [])
    reached = sorted((s for s in sinks if s.get("reachable")), key=lambda s: bool(s.get("weak_path_only")))
    pkg = r.get("package", {})

    facts, notes, paths = [], [], []
    seen = set()
    # candidate paths to vuln functions whenever the call graph has them, also when a rule decided
    # (the NOTE below then says why the path does not decide the verdict)
    for s in reached[:MAX_PATHS]:
        if s.get("path"):
            p = path_evidence(s["path"], "VULN_FUNCTION", f"취약 함수 {short_name(s['sink'])}", s.get("weak_path_only"))
            p["vulnFunction"] = s["sink"]
            paths.append(p)
    for e in decided.get("evidence", []):
        name = e["fact"]
        if name in ("sink", "sink_weak"):
            continue
        elif name == "sinks_missing":
            missing = [s["sink"] for s in sinks if not s.get("present_in_jar")]
            notes.append({"kind": "NOTE", "checkedAbsent": missing, "checkedCount": len(sinks),
                          "summary": f"분석한 jar에 취약 함수 {len(sinks)}개 중 {len(missing)}개가 없다(버전 차이일 수 있다)"})
        elif name in ("package", "package_present"):
            notes.append({"kind": "NOTE", "summary": "호출 그래프가 이 패키지의 코드에 닿는다"})
        elif e.get("result") == "없음":
            facts.append(fact_absent(name, ctx))
            seen.add(name)
        else:
            facts.append(fact_present(name, ctx.reach_facts.get(name) or e.get("occurrences") or []))
            seen.add(name)

    sink_checked = False
    for name in v.get("checked_absent", []):
        if name in seen:
            continue
        if name in CALLGRAPH_NAMES:
            sink_checked = sink_checked or name == "sink"
            continue
        facts.append(fact_absent(name, ctx))
        seen.add(name)
    if sink_checked and not reached:
        present = [s["sink"] for s in sinks if s.get("present_in_jar")]
        notes.append({"kind": "NOTE", "checkedAbsent": present, "checkedCount": len(sinks),
                      "summary": f"호출 그래프: 취약 함수 {len(sinks)}개 중 닿는 경로가 있는 것이 없다"})
    for e in v.get("info", []):
        if e["fact"] not in seen:
            facts.append(fact_present(e["fact"], ctx.reach_facts.get(e["fact"]) or e.get("occurrences") or [], True))

    cg = v.get("callgraph", {})
    method = v.get("method", "callgraph").upper()
    if method == "RULE":
        if cg.get("sink_reachable") and status != "REACHABLE":
            notes.append({"kind": "NOTE", "summary": "호출 그래프는 취약 메서드에 닿는다고 보지만 가상 호출을 넓게 잡은 결과다. "
                                                     "이 CVE는 앱이 해당 기능을 쓰는지로 판정했다(규칙)"})
        elif not cg.get("package_reachable"):
            notes.append({"kind": "NOTE", "summary": "프레임워크가 직접 실행하는 코드라 호출 그래프에 잡히지 않을 수 있다. "
                                                     "이 CVE는 앱이 해당 기능을 설정하는지로 판정했다(규칙)"})
    if not paths and pkg.get("reachable") and pkg.get("witness_path"):
        paths.append(path_evidence(pkg["witness_path"], "PACKAGE", f"패키지 {pkg.get('artifact')}", not pkg.get("reachable_strong")))

    rule_id = f"RULE-{cve}" if cve in ctx.rules else None
    evidence = facts + notes
    if rule_id:
        matched = CLAUSES.get(decided.get("clause"), "DEFAULT")
        evidence.append({"kind": "RULE", "ruleId": rule_id, "matchedCondition": matched,
                         "summary": (f"기본값({STATUS_KO.get(status, status)})이 적용됨: 어느 조건에도 맞지 않음" if matched == "DEFAULT"
                                     else f"{STATUS_KO.get(matched, matched)} 조건에 맞음")})
    evidence += paths

    callgraph = {
        "packageReached": bool(pkg.get("reachable")),
        "vulnFunctionPresent": any(s.get("present_in_jar") for s in sinks),
        "vulnFunctionReached": bool(r.get("sink_reachable")),
        "weakOnly": bool(r.get("sink_reachable")) and not r.get("sink_reachable_strong"),
    }
    if reached and reached[0].get("path"):
        callgraph["entryStage"] = 2 if reached[0]["path"][0].get("via") == "entry:app-method" else 1

    out = {"status": status, "method": method, "summary": cut(v.get("why_ko") or STATUS_KO.get(status, status), SUMMARY_MAX),
           "vulnFunctionIds": ctx.function_ids.get(cve, []), "callgraph": callgraph, "evidence": evidence,
           "analyzedAt": analysed_at, "engine": ctx.engine}
    if rule_id:
        out["ruleId"] = rule_id
    return out


# ---------------------------------------------------------------- bundle

def build_items(matches, ctx, analysed_at):
    items = []
    for m in matches:
        _, _, name, version = parse_purl(m["purl"])
        sev = m["severities"]
        severity = sev.get("TRIVY") or sev.get("GRYPE") or "UNKNOWN"
        note = None
        if len(set(sev.values())) > 1:
            note = ", ".join(f"{src.capitalize()} {value}" for src, value in sev.items())
        verdict = verdict_for(m, ctx, analysed_at)
        spec = ctx.spec_by_cve.get(m["cve"])
        vulnerability = {"id": m["cve"], "severity": severity, "severityNote": note, "title": cut(m["title"], 500),
                         "description": m["description"], "fixedVersions": m["fixed"], "cwe": m["cwe"],
                         "references": m["references"]}
        if verdict["status"] != "NOT_ANALYZED" and spec and spec.get("summary_ko"):
            vulnerability["affectedFeature"] = cut(spec["summary_ko"], 500)
        items.append({
            "component": {"purl": m["purl"], "name": name, "version": version or m["version"],
                          "ecosystem": parse_purl(m["purl"])[0], "path": cut(m["path"], 500)},
            "vulnerability": {k: v for k, v in vulnerability.items() if v is not None},
            "sources": m["sources"],
            "verdict": verdict,
        })
    return items


def parse_tools(values):
    tools = {}
    for value in values:
        name, sep, v = value.partition("=")
        if not sep or not name:
            raise BundleError(f"--tool needs name=value: {value}")
        tools[name] = v
    return tools


def parse_stages(values):
    stages = []
    for value in values:
        name, sep, rest = value.partition("=")
        status, _, seconds = rest.partition(":")
        name, status = name.upper(), status.upper()
        if not sep or name not in STAGES or status not in STAGE_STATUSES:
            raise BundleError(f"--stage needs name=status[:seconds] with name in {STAGES}: {value}")
        stage = {"name": name, "status": status}
        if seconds:
            stage["durationSeconds"] = int(seconds)
        stages.append(stage)
    return stages


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(a):
    tools = {}
    stages = parse_stages(a.stage)
    if a.failure_code:
        tools.update(parse_tools(a.tool))
        return {"tools": tools, "stages": stages,
                "failure": {"code": a.failure_code, "stage": (a.failure_stage or "").upper() or None,
                            "message": cut(a.failure_message, 500)}}

    for name in ("sbom", "trivy", "spec", "rules"):
        if not getattr(a, name):
            raise BundleError(f"--{name} is required unless --failure-code is given")
    if bool(a.reach) != bool(a.verdicts):
        raise BundleError("--reach and --verdicts go together (both from the L2 step, or neither)")
    sbom, trivy = load(a.sbom), load(a.trivy)
    reach = load(a.reach) if a.reach else None
    verdicts = load(a.verdicts) if a.verdicts else None
    grype = load(a.grype) if a.grype else None
    spec, rules = load(a.spec), load(a.rules)
    ctx = Context(reach, verdicts, spec, rules)
    analysed_at = a.analyzed_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    matches = trivy_matches(trivy) + (grype_matches(grype) if grype else [])
    items = build_items(merge_matches(matches), ctx, analysed_at)

    tools["trivy"] = (trivy.get("Trivy") or {}).get("Version")
    if grype:
        tools["grype"] = (grype.get("descriptor") or {}).get("version")
    tools.update(ctx.engine)
    tools.update(parse_tools(a.tool))
    index, analysis = (reach or {}).get("index", {}), (reach or {}).get("analysis", {})
    summary = {"appClasses": index.get("app_classes"), "libraryJars": len(index["library_jars"]) if "library_jars" in index else None,
               "reachedMethods": analysis.get("reachable_methods")}
    if a.jar:
        summary["jarSha256"] = sha256_file(a.jar)
    if not stages:
        stages = [{"name": n, "status": "SUCCEEDED"} for n in (("SBOM", "MATCH", "L2", "REPORT") if reach else ("SBOM", "MATCH", "REPORT"))]
    matches_raw = {"trivy": trivy}
    if grype:
        matches_raw["grype"] = grype
    # API-13 needs reachResult as an object even when L2 did not run
    return {"sbom": sbom, "matches": matches_raw, "reachResult": reach if reach is not None else {},
            "tools": {k: v for k, v in tools.items() if v is not None},
            "analysis": {k: v for k, v in summary.items() if v is not None}, "stages": stages, "verdicts": items}


def write(bundle, out):
    data = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if out.endswith(".gz"):
        # mtime=0 keeps the file identical for identical input
        with open(out, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(data)
    else:
        with open(out, "wb") as f:
            f.write(data)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom")
    ap.add_argument("--trivy")
    ap.add_argument("--grype")
    ap.add_argument("--reach", help="analyzer output; leave out with --verdicts when there is no Java code")
    ap.add_argument("--verdicts", help="verdict.py output; leave out with --reach when there is no Java code")
    ap.add_argument("--spec")
    ap.add_argument("--rules")
    ap.add_argument("--jar", help="the analysed bootJar, for analysis.jarSha256")
    ap.add_argument("--tool", action="append", default=[], help="extra or overriding tools entry, name=value")
    ap.add_argument("--stage", action="append", default=[], help="name=status[:seconds]; default: sbom, match, l2, report succeeded")
    ap.add_argument("--analyzed-at", help="ISO-8601 time for every verdict (default: now)")
    ap.add_argument("--failure-code")
    ap.add_argument("--failure-stage")
    ap.add_argument("--failure-message")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        bundle = build(a)
    except (BundleError, OSError, KeyError, json.JSONDecodeError) as e:
        print(f"bundle.py: {e}", file=sys.stderr)
        return 1
    write(bundle, a.out)
    if "verdicts" in bundle:
        counts = {}
        for item in bundle["verdicts"]:
            key = item["verdict"]["status"] + (f" ({item['verdict']['notAnalyzedReason']})" if item["verdict"].get("notAnalyzedReason") else "")
            counts[key] = counts.get(key, 0) + 1
        print(f"wrote {a.out}: {len(bundle['verdicts'])} findings, " + ", ".join(f"{k} {n}" for k, n in sorted(counts.items())),
              file=sys.stderr)
    else:
        print(f"wrote {a.out}: failure bundle ({bundle['failure']['code']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
