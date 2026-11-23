#!/usr/bin/env python3
"""verdict.py — turns reach-result.json (+ optional Trivy JSON and repo checks) into per-CVE verdicts.

    python3 verdict.py --reach reach-result.json --spec ../data/vuln-functions.json \
        --rules ../data/rules.json [--trivy trivy.json ...] [--repo /path/to/repo] [--jar app.jar] \
        --out verdicts.json --md verdicts.md

Config facts (rules.json repo_facts) are read from the source repository and from the config files packed in the app
jar (BOOT-INF/classes, WEB-INF, not the library jars). When neither could be read, a rule that looks at config does not
say unreachable: the config was not seen, so the verdict is unknown.

Status values: reachable / unreachable / unknown (never drop a finding; unknown when unsure).
No third-party dependencies (Python 3.8+).
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import zipfile

CONFIG_UNSEEN_KO = ("이 판정은 앱 설정 파일을 봐야 하는데, 소스 레포도 앱 jar 안의 설정 파일도 읽지 못했다. "
                    "설정이 없다고 볼 수 없어 도달 불가가 아니라 미확인으로 둔다.")
STATUS_KO = {"reachable": "도달 가능", "unreachable": "도달 불가", "unknown": "미확인", "not_analyzed": "분석 대상 아님"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def trivy_findings(paths):
    """CVE -> list of {package, installed, fixed, severity, target} from Trivy JSON reports."""
    out = {}
    for p in paths:
        data = load(p)
        for res in data.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                out.setdefault(v["VulnerabilityID"], []).append({
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "severity": v.get("Severity"),
                    "target": res.get("Target"),
                    "report": os.path.basename(p),
                })
    return out


# the default rule for a CVE without its own rule: a weak path only (Object methods, JDK callbacks) is not enough
# to say reachable, and not enough to rule it out either
DEFAULT_RULE = {"method": "callgraph", "reachable_if": [["sink"]], "unknown_if": [["sinks_missing"], ["sink_weak"]],
                "otherwise": "unreachable"}


def match_config(defs, name, lines, where, found):
    for d in defs:
        if not any(fnmatch.fnmatch(name, pat) for pat in d["files"]):
            continue
        for no, line in enumerate(lines, 1):
            if re.search(d["regex"], line):
                found[d["id"]].append({"where": f"{where}:{no}", "detail": line.strip()[:160]})


def jar_facts(jar, defs, found):
    """The same checks over the config files packed in the app jar. Library jars (BOOT-INF/lib, WEB-INF/lib) are not
    the app's config. Returns whether the jar could be read."""
    if not jar:
        return False
    try:
        with zipfile.ZipFile(jar) as z:
            for info in z.infolist():
                entry = info.filename
                if info.is_dir() or "/lib/" in "/" + entry or entry.endswith((".class", ".jar")):
                    continue
                name = entry.rsplit("/", 1)[-1]
                if not any(fnmatch.fnmatch(name, pat) for d in defs for pat in d["files"]):
                    continue
                text = z.read(info).decode("utf-8", errors="replace")
                match_config(defs, name, text.splitlines(), f"{os.path.basename(jar)}!/{entry}", found)
        return True
    except (OSError, zipfile.BadZipFile):
        return False


def repo_facts(repo, defs, jar=None):
    """Regex checks over configuration files in the source repository and in the app jar.
    Returns (found, sources read): an empty list means no config was seen."""
    found = {d["id"]: [] for d in defs}
    sources = ["jar"] if jar_facts(jar, defs, found) else []
    if not repo or not os.path.isdir(repo):
        return found, sources
    sources.insert(0, "repo")
    skip_dirs = {".git", "node_modules", "build", "target", ".gradle", ".idea", "out"}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            if not any(fnmatch.fnmatch(name, pat) for d in defs for pat in d["files"]):
                continue
            path = os.path.join(root, name)
            if os.path.islink(path):   # a PR checkout is untrusted: do not follow links out of it
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    match_config(defs, name, f.read().splitlines(), os.path.relpath(path, repo), found)
            except OSError:
                pass
    return found, sources


def short_path(steps, limit=8):
    names = [s.get("short") or s.get("note", "") for s in steps]
    if len(names) > limit:
        names = names[:2] + ["…"] + names[-(limit - 3):]
    return " → ".join(names)


def evaluate(rule, facts):
    """Returns (status, satisfied_conditions, clause). All satisfied conditions of the deciding clause are kept as evidence."""
    def holds(cond):
        for f in cond:
            if f.startswith("!"):
                if facts.get(f[1:]):
                    return False
            elif not facts.get(f):
                return False
        return True

    for clause in ("reachable_if", "unreachable_if", "unknown_if"):
        sat = [c for c in rule.get(clause, []) if c and holds(c)]
        if sat:
            return clause.replace("_if", ""), sat, clause
    return rule.get("otherwise", "unknown"), [], "otherwise"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reach", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--trivy", action="append", default=[])
    ap.add_argument("--repo")
    ap.add_argument("--jar", help="the app jar: its packed config files are read like the repository's")
    ap.add_argument("--out", default="verdicts.json")
    ap.add_argument("--md", default="verdicts.md")
    a = ap.parse_args()

    reach = load(a.reach)
    spec = load(a.spec)
    rules = load(a.rules)
    trivy = trivy_findings(a.trivy)
    rfacts, config_sources = repo_facts(a.repo, rules.get("repo_facts", []), a.jar)
    repo_checked = bool(config_sources)

    occurrences = {k: v for k, v in reach.get("facts", {}).items()}
    occurrences.update(rfacts)
    reach_by_cve = {c["cve"]: c for c in reach.get("cves", [])}
    spec_by_cve = {c["cve"]: c for c in spec.get("cves", [])}

    cve_ids = list(spec_by_cve)
    if trivy:  # only what the scanner actually reported, plus anything reported that we have no spec for
        cve_ids = [c for c in spec_by_cve if c in trivy] + sorted(c for c in trivy if c not in spec_by_cve)

    verdicts = []
    for cve in cve_ids:
        s = spec_by_cve.get(cve)
        r = reach_by_cve.get(cve)
        if s is None or r is None:
            rows = {}
            for t in trivy.get(cve) or [{}]:
                rows.setdefault((t.get("package"), t.get("installed")), t)
            for _, t in sorted(rows.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or "")):
                verdicts.append({"cve": cve, "status": "not_analyzed", "package": t.get("package"), "severity": t.get("severity"),
                                 "installed": t.get("installed"), "fixed": t.get("fixed"),
                                 "why_ko": "취약 함수 데이터(vuln-functions.json)가 없어 판정하지 않았다."})
            continue
        facts = {k: bool(v) for k, v in occurrences.items()}
        facts["sink"] = bool(r.get("sink_reachable_strong"))
        facts["sink_weak"] = bool(r.get("sink_reachable")) and not facts["sink"]
        facts["sinks_missing"] = bool(r.get("all_sinks_missing"))
        facts["package"] = bool(r.get("package", {}).get("reachable"))
        facts["package_present"] = bool(r.get("package", {}).get("present"))
        rule = rules["verdicts"].get(cve, DEFAULT_RULE)
        status, conds, clause = evaluate(rule, facts)
        mentioned = sorted({f.lstrip("!") for cl in ("reachable_if", "unreachable_if", "unknown_if") for c in rule.get(cl, []) for f in c})
        # the rule looks at config we could not read: absent config is not evidence, so do not rule it out
        config_unseen = not repo_checked and status == "unreachable" and any(f.startswith("repo.") for f in mentioned)
        if config_unseen:
            status = "unknown"
        cond = [f for c in conds for f in c]
        cond = list(dict.fromkeys(cond))  # unique, keep order

        # evidence: facts that decided the verdict + what was checked and found absent
        decided = []
        for f in cond:
            name = f.lstrip("!")
            if f.startswith("!"):
                decided.append({"fact": name, "result": "없음"})
            elif name in ("sink", "sink_weak"):
                hits = [x for x in r["sinks"] if x.get("reachable")]
                decided.append({"fact": "sink", "result": "도달", "paths": [{"sink": h["sink"], "path": short_path(h["path"])} for h in hits[:3]]})
            elif name in ("sinks_missing", "package", "package_present"):
                decided.append({"fact": name, "result": "예"})
            else:
                decided.append({"fact": name, "result": "있음", "occurrences": occurrences.get(name, [])[:5]})
        checked_absent = [f for f in mentioned if not facts.get(f) and f not in ("sinks_missing", "sink_weak")]
        if not repo_checked:
            checked_absent = [f for f in checked_absent if not f.startswith("repo.")]

        pkg = r.get("package", {})
        coords = s["package"]["coordinates"]
        found = trivy.get(cve) or []
        # the scanner may report the same CVE for several packages (e.g. Jackson 3 and a Jackson 2 copy)
        t = next((x for x in found if x.get("package") == coords), {})
        v = {
            "cve": cve,
            "status": status,
            "status_ko": STATUS_KO[status],
            "method": rule.get("method", "callgraph"),
            "package": s["package"]["coordinates"],
            "installed": t.get("installed") or s["package"]["installed"],
            "fixed": t.get("fixed") or ", ".join(s["package"]["fixed"]),
            "severity": t.get("severity") or s.get("severity"),
            "summary_ko": s.get("summary_ko"),
            "why_ko": (CONFIG_UNSEEN_KO if config_unseen else rule.get("why_ko", {}).get(status, "")),
            "config_unseen": config_unseen,
            "decided_by": {"clause": clause, "conditions": conds, "evidence": decided},
            "checked_absent": checked_absent,
            "info": [{"fact": f, "occurrences": occurrences.get(f, [])[:5]} for f in rule.get("info", []) if occurrences.get(f)],
            "callgraph": {
                "package_reachable": pkg.get("reachable"),
                "package_witness": short_path(pkg.get("witness_path", [])) if pkg.get("witness_path") else None,
                "sink_reachable": r.get("sink_reachable"),
                "sink_reachable_strong": r.get("sink_reachable_strong"),
                "sinks_present_in_jar": [x["sink"] for x in r["sinks"] if x.get("present_in_jar")],
                "sinks_missing_in_jar": [x["sink"] for x in r["sinks"] if not x.get("present_in_jar")],
                "sink_paths": [{"sink": x["sink"], "path": short_path(x["path"])} for x in r["sinks"] if x.get("reachable")][:3],
            },
            "repo_checked": repo_checked,
            "config_sources": config_sources,
        }
        verdicts.append(v)
        # same CVE in a package the spec and rules were not written for: say so instead of hiding it behind this row
        others = {}
        for x in found:
            if x.get("package") != coords:
                others.setdefault((x.get("package"), x.get("installed")), x)
        for (name, installed), x in sorted(others.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or "")):
            verdicts.append({"cve": cve, "status": "not_analyzed", "package": name, "severity": x.get("severity"),
                             "installed": installed, "fixed": x.get("fixed"),
                             "why_ko": f"같은 CVE가 다른 패키지에서도 나왔다. 취약 함수 데이터와 규칙은 {coords} 기준이라 이 패키지는 판정하지 않았다."})

    out = {"tool": "verdict.py 0.2.0", "reach_tool": reach.get("tool"), "app": reach.get("input", {}).get("app"),
           "trivy_reports": a.trivy, "repo": a.repo, "jar": a.jar, "config_sources": config_sources, "verdicts": verdicts}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")

    # markdown report
    counts = {}
    for v in verdicts:
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    lines = ["# 도달 가능성 판정 결과", ""]
    lines.append(f"- 대상: `{out['app']}`")
    lines.append(f"- 판정 도구: {reach.get('tool')} + verdict.py, 설정 확인: {', '.join(config_sources) if config_sources else '아니요'}")
    lines.append("- 요약: " + ", ".join(f"{STATUS_KO[k]} {n}개" for k, n in sorted(counts.items())))
    lines += ["", "| CVE | 패키지 | 심각도 | 판정 | 방식 | 근거 요약 |", "|---|---|---|---|---|---|"]
    for v in verdicts:
        lines.append(f"| {v['cve']} | {v.get('package')} {v.get('installed') or ''} | {v.get('severity') or ''} | **{STATUS_KO[v['status']]}** | {v.get('method', '')} | {v.get('why_ko', '')[:90]}… |")
    for v in verdicts:
        if v["status"] == "not_analyzed":
            continue
        lines += ["", f"## {v['cve']} — {STATUS_KO[v['status']]}", "", f"- 취약점: {v['summary_ko']}", f"- 수정 버전: {v['fixed']}",
                  f"- 판정 이유: {v['why_ko']}"]
        ev = v["decided_by"]
        if ev["conditions"]:
            lines.append(f"- 결정 조건 ({ev['clause']}): " + " / ".join("`" + " AND ".join(c) + "`" for c in ev["conditions"]))
            # facts found in app code point at real lines; call-graph paths come last because they may be over-approximated
            for e in sorted(ev["evidence"], key=lambda e: 1 if e.get("paths") else 0):
                if e.get("occurrences"):
                    for o in e["occurrences"][:3]:
                        lines.append(f"  - `{e['fact']}`: {o.get('where')} — {o.get('detail', '')}")
                elif e.get("paths"):
                    lines.append("  - `sink` 호출 경로 (가장 짧은 후보 경로다. 가상 호출을 넓게 잡아 실제 경로와 다를 수 있다):")
                    for p in e["paths"]:
                        lines.append(f"    - {p['sink']}: {p['path']}")
                else:
                    lines.append(f"  - `{e['fact']}`: {e['result']}")
        if v["checked_absent"]:
            lines.append(f"- 확인했지만 없던 것: {', '.join('`' + x + '`' for x in v['checked_absent'])}")
        if v["info"]:
            lines.append("- 참고 (판정에 쓰지 않음):")
            for e in v["info"]:
                for o in e["occurrences"][:3]:
                    lines.append(f"  - `{e['fact']}`: {o.get('where')} — {o.get('detail', '')}")
        cg = v["callgraph"]
        lines.append(f"- 호출 그래프: 패키지 도달 {'예' if cg['package_reachable'] else '아니요'}"
                     + (f" ({cg['package_witness']})" if cg.get("package_witness") else "")
                     + f", 취약 메서드 도달 {'예' if cg['sink_reachable'] else '아니요'}")
        if v.get("method") == "rule":
            if cg["sink_reachable"] and v["status"] != "reachable":
                lines.append("  - 참고: 취약 메서드 도달 \"예\"는 가상 호출을 넓게 잡은 결과다. 이 CVE는 앱이 해당 기능을 쓰는지로 판정했다(규칙).")
            elif not cg["package_reachable"]:
                lines.append("  - 참고: 프레임워크가 직접 실행하는 코드라 호출 그래프에 잡히지 않을 수 있다. 이 CVE는 앱이 해당 기능을 설정하는지로 판정했다(규칙).")
        if cg["sink_paths"]:
            lines.append("  - 후보 경로 (실제 경로와 다를 수 있다):")
        for sp in cg["sink_paths"]:
            lines.append(f"    - {sp['sink']}: {sp['path']}")
        if cg["sinks_missing_in_jar"]:
            lines.append(f"  - jar에 없는 메서드(버전 차이 가능): {', '.join(cg['sinks_missing_in_jar'][:4])}")
    with open(a.md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    for v in verdicts:
        print(f"{v['cve']:16} {STATUS_KO[v['status']]:8} {v.get('method', ''):9} {v.get('package') or ''}")
    print(f"wrote {a.out}, {a.md}", file=sys.stderr)


if __name__ == "__main__":
    main()
