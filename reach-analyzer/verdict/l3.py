#!/usr/bin/env python3
"""l3.py — how far did a real run get towards the vulnerable code? (L3, PRD FR-14)

    python3 l3.py --spec vuln-functions.json --sbom sbom.cdx.json \
        (--segments xml-dir/ | --jacoco one.xml) [--reach reach-result.json] \
        [--scope 'tools.jackson.*:org.apache.*'] --out l3-result.json

The reports come from running the app (same image) with the JaCoCo agent and a request scenario
(deploy/reach/ci/l3-run.sh). The run is cut into segments: "startup" (until the app is ready) and one per
scenario step ("001", "002", …), each a JaCoCo XML report <id>.xml in --segments. That is how a result
says in which requests the code ran. --jacoco is one report of a whole run (segment "all").

L3 is evidence next to the L2 verdict; it never changes it. It looks at every CVE of vuln-functions.json whose
package is in the SBOM, whatever L2 said. Each CVE may carry

    "l3": {"version": "3.1.5",                      # library version the line numbers belong to
           "regions": [{"class": "...", "method": "...", "desc": "...", "source": "pkg/Name.java",
                        "lines": [[626, 627]]}],    # no "lines": the whole method (jars without line numbers)
           "note": "..."}

Per CVE, `reached` says how far the run got:

    REGION        a vulnerable region ran (the library version is the one the regions were written for)
    FUNCTION      a vulnerable function (a sink method) ran, but no region: regionsChecked tells whether the
                  regions were looked at and did not run (true) or could not be checked (false: another
                  library version, no region data, a class without line numbers)
    NONE          everything could be checked and nothing ran
    NOT_RECORDED  nothing ran and something could not be checked: a class outside the agent's recording
                  scope (--scope) or not in the report (no class file was given, e.g. a JDK class; JDK
                  classes loaded before the agent starts are never recorded)

with the evidence: `during` (the segments in which that level was reached; startupOnly when it was only
while the app started), `functions` and `regions` (each with its own `during`), and `paths`: for every
call path L2 found to a sink (--reach), how many steps ran from the entry without a gap (reachedStep of `of`). A region that could not be checked says why
(unchecked: OTHER_VERSION, OUT_OF_SCOPE, NO_CLASS_FILE, NO_METHOD, NO_LINE_NUMBERS).
NONE only says the scenario did not run the code; it is not evidence of UNREACHABLE.
No third-party dependencies (Python 3.8+).
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

from bundle import BundleError, coordinates

TOOL = "reach-l3 0.2.0"
LEVELS = ("REGION", "FUNCTION", "NONE", "NOT_RECORDED")
STARTUP = "startup"


class L3Error(Exception):
    pass


# ---------------------------------------------------------------- JaCoCo report

class Coverage:
    """Executed lines per source file and executed methods, from a JaCoCo XML report."""

    def __init__(self):
        self.lines = {}     # "pkg/Name.java" -> {line number: covered instructions}
        self.methods = {}   # ("pkg/Class$Inner", name, desc) -> covered instructions
        self.classes = set()

    @classmethod
    def parse(cls, source):
        cov = cls()
        root = ET.parse(source).getroot()
        if root.tag != "report":
            raise L3Error("not a JaCoCo XML report")
        for package in root.iter("package"):
            pkg = package.get("name", "")
            for klass in package.findall("class"):
                name = klass.get("name")
                cov.classes.add(name)
                for method in klass.findall("method"):
                    covered = 0
                    for counter in method.findall("counter"):
                        if counter.get("type") == "INSTRUCTION":
                            covered = int(counter.get("covered", "0"))
                    cov.methods[(name, method.get("name"), method.get("desc"))] = covered
            for sourcefile in package.findall("sourcefile"):
                path = f"{pkg}/{sourcefile.get('name')}" if pkg else sourcefile.get("name")
                cov.lines[path] = {int(line.get("nr")): int(line.get("ci", "0")) for line in sourcefile.findall("line")}
        return cov

    def has_class(self, class_name):
        return class_name.replace(".", "/") in self.classes

    def has_method(self, class_name, method, desc=None):
        internal = class_name.replace(".", "/")
        return any(c == internal and m == method and (desc is None or d == desc) for c, m, d in self.methods)

    def method_ran(self, class_name, method, desc=None):
        internal = class_name.replace(".", "/")
        return any(covered > 0 for (c, m, d), covered in self.methods.items()
                   if c == internal and m == method and (desc is None or d == desc))

    def has_lines(self, source):
        return bool(self.lines.get(source))

    def lines_ran(self, source, ranges):
        file_lines = self.lines.get(source, {})
        return [n for lo, hi in ranges for n in range(lo, hi + 1) if file_lines.get(n, 0) > 0]


class Run:
    """The segments of one run, in order: [(id, Coverage)]. The class files are the same in all of them."""

    def __init__(self, segments):
        if not segments:
            raise L3Error("no report")
        self.segments = segments
        self.any = segments[0][1]      # which classes, methods and line tables exist

    @classmethod
    def load(cls, directory):
        ids = [n[:-len(".xml")] for n in os.listdir(directory) if n.endswith(".xml")]
        ids.sort(key=lambda i: (i != STARTUP, i))
        return cls([(i, Coverage.parse(os.path.join(directory, i + ".xml"))) for i in ids])

    def ids(self):
        return [i for i, _ in self.segments]

    def method_during(self, class_name, method, desc=None):
        return [i for i, cov in self.segments if cov.method_ran(class_name, method, desc)]

    def lines_during(self, source, ranges):
        """(executed lines of the whole run, the segments in which one of them ran)"""
        lines, during = set(), []
        for i, cov in self.segments:
            ran = cov.lines_ran(source, ranges)
            if ran:
                lines.update(ran)
                during.append(i)
        return sorted(lines), during


# ---------------------------------------------------------------- recording scope

def scope_matcher(scope):
    """JaCoCo agent includes syntax: class names with '.', '*' and '?' wildcards, ':' between patterns."""
    patterns = [p for p in (scope or "*").split(":") if p]
    regex = [re.compile("".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in p) + r"\Z")
             for p in patterns]
    return lambda class_name: any(r.match(class_name) for r in regex)


# ---------------------------------------------------------------- SBOM

def sbom_versions(sbom):
    """group:artifact -> set of versions, from the maven components of a CycloneDX SBOM"""
    out = {}
    stack = list(sbom.get("components") or [])
    while stack:
        comp = stack.pop()
        stack.extend(comp.get("components") or [])
        purl = comp.get("purl") or ""
        if not purl.startswith("pkg:maven/"):
            continue
        try:
            coords = coordinates(purl)
        except BundleError:
            continue
        version = comp.get("version") or purl.split("@", 1)[-1].split("?", 1)[0]
        out.setdefault(coords, set()).add(version)
    return out


# ---------------------------------------------------------------- L2 call paths

def path_method(pretty):
    """'com.a.B$C.name(Ljava/lang/String;)V' (analyzer path step) -> (class, method, desc)"""
    head, paren, tail = pretty.partition("(")
    class_name, _, method = head.rpartition(".")
    return (class_name, method, paren + tail) if class_name and paren else None


def l2_paths(reach):
    """CVE id -> [(sink label, [step method strings])] for the sinks L2 found a call path to"""
    out = {}
    for cve in (reach or {}).get("cves", []):
        for sink in cve.get("sinks") or []:
            steps = [s["method"] for s in sink.get("path") or [] if s.get("method")]
            if steps:
                out.setdefault(cve.get("cve"), []).append((sink.get("sink"), steps))
    return out


def path_result(run, recorded, target, steps):
    """How far along an L2 call path the run got: reachedStep is the number of steps that ran from the entry
    without a gap. A later step that ran on its own (a shared library method reached another way) does not
    count. executed is None when a step cannot be judged (a JDK callback, a bridge method); it is not a gap.
    The steps are listed only when the entry ran."""
    results = []
    for pretty in steps:
        ref = path_method(pretty)
        executed = None
        if ref and not unchecked(run.any, recorded, *ref):
            executed = bool(run.method_during(*ref))
        results.append({"method": pretty, "executed": executed})
    depth = 0
    for n, step in enumerate(results, 1):
        if step["executed"] is False:
            break
        if step["executed"]:
            depth = n
    out = {"target": target, "reachedStep": depth, "of": len(steps)}
    if depth:
        out["steps"] = results
    return out


# ---------------------------------------------------------------- matching

def label(class_name, method, desc):
    return f"{class_name}#{method}{desc or ''}"


def unchecked(cov, recorded, class_name, method, desc, source=None):
    """Why this method (or its lines) cannot be judged from the report; None when it can."""
    if not recorded(class_name):
        return "OUT_OF_SCOPE"
    if not cov.has_class(class_name):
        return "NO_CLASS_FILE"
    if not cov.has_method(class_name, method, desc):
        return "NO_METHOD"
    if source is not None and not cov.has_lines(source):
        return "NO_LINE_NUMBERS"
    return None


def merged(lists, order):
    seen = {i for one in lists for i in one}
    return [i for i in order if i in seen]


def match_cve(cve, versions, run, recorded, paths=()):
    l3 = cve.get("l3") or {}
    regions = l3.get("regions") or []
    data_version = l3.get("version")
    sinks = cve.get("sinks") or []
    order = run.ids()

    same_version = data_version is not None and versions == {data_version}
    region_results = []
    for r in regions:
        result = {"class": r["class"], "method": r["method"]}
        # the regions (line numbers) belong to one library version
        why = "OTHER_VERSION" if not same_version else unchecked(
            run.any, recorded, r["class"], r["method"], r.get("desc"), r["source"] if "lines" in r else None)
        if "lines" in r:
            ran, during = ([], []) if why else run.lines_during(r["source"], r["lines"])
            result.update(lines=r["lines"], executedLines=ran)
        else:
            during = [] if why else run.method_during(r["class"], r["method"], r.get("desc"))
            result["wholeMethod"] = True
        result.update(executed=bool(during), during=during)
        if why:
            result["unchecked"] = why
        region_results.append(result)

    # the vulnerable functions: the sink methods, and the methods of the regions (a sink even when the list misses it)
    methods = {(s["class"], s["method"], s.get("desc")): None for s in sinks}
    methods.update({(r["class"], r["method"], r.get("desc")): None for r in regions})
    functions, functions_unchecked = [], []
    for class_name, method, desc in methods:
        during = run.method_during(class_name, method, desc) if recorded(class_name) else []
        if during:
            functions.append({"function": label(class_name, method, desc), "during": during})
        elif unchecked(run.any, recorded, class_name, method, desc):
            functions_unchecked.append(label(class_name, method, desc))

    regions_checked = bool(regions) and not any("unchecked" in r for r in region_results)
    if any(r["executed"] for r in region_results):
        reached = "REGION"
        during = merged([r["during"] for r in region_results], order)
    elif functions:
        reached = "FUNCTION"
        during = merged([f["during"] for f in functions], order)
    elif regions_checked or (methods and not functions_unchecked):
        reached, during = "NONE", []
    else:
        reached, during = "NOT_RECORDED", []

    out = {"cve": cve["cve"], "coordinates": cve["package"]["coordinates"], "reached": reached, "during": during,
           "startupOnly": during == [STARTUP],
           "installedVersions": sorted(versions), "regionVersion": data_version,
           "regionsChecked": regions_checked, "regions": region_results, "functions": functions}
    if functions_unchecked:
        out["functionsUnchecked"] = functions_unchecked
    if paths:
        out["paths"] = [path_result(run, recorded, target, steps) for target, steps in paths]
    if l3.get("note"):
        out["note"] = l3["note"]
    return out


def match(spec, sbom, run, scope=None, reach=None):
    recorded = scope_matcher(scope)
    versions = sbom_versions(sbom)
    paths = l2_paths(reach)
    results = [match_cve(c, versions[c["package"]["coordinates"]], run, recorded, paths.get(c["cve"], ()))
               for c in spec.get("cves", []) if c["package"]["coordinates"] in versions]
    counts = {level: sum(1 for r in results if r["reached"] == level) for level in LEVELS}
    return {"tool": TOOL, "scope": scope or "*", "segments": run.ids(), "counts": counts, "cves": results}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--segments", help="folder of JaCoCo XML reports, one per segment (<id>.xml)")
    group.add_argument("--jacoco", help="one JaCoCo XML report of a whole run")
    ap.add_argument("--sbom", required=True, help="CycloneDX JSON (library versions)")
    ap.add_argument("--reach", help="analyzer output (reach-result.json): which steps of its call paths ran")
    ap.add_argument("--scope", help="the agent's includes (default: everything)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.spec, encoding="utf-8") as f:
            spec = json.load(f)
        with open(a.sbom, encoding="utf-8") as f:
            sbom = json.load(f)
        reach = None
        if a.reach:
            with open(a.reach, encoding="utf-8") as f:
                reach = json.load(f)
        run = Run.load(a.segments) if a.segments else Run([("all", Coverage.parse(a.jacoco))])
        result = match(spec, sbom, run, a.scope, reach)
    except (OSError, ValueError, ET.ParseError, L3Error) as e:
        print(f"l3.py: {e}", file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"wrote {a.out}: " + ", ".join(f"{k} {v}" for k, v in result["counts"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
