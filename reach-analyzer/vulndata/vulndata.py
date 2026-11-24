#!/usr/bin/env python3
"""vulndata.py — makes verdict data (vuln-functions.json) for a CVE the tool has no data for yet.

    python3 vulndata.py prepare --cve CVE-2026-65637 --coordinates org.apache.tomcat.embed:tomcat-embed-core \
        --installed 11.0.24 --out bundles/CVE-2026-65637
    #   an AI writes bundles/CVE-2026-65637/draft.json from the bundle (PROMPT.md says how)
    python3 vulndata.py check bundles/CVE-2026-65637            # writes REVIEW.md; exit 1 when the draft is wrong
    python3 vulndata.py apply bundles/CVE-2026-65637 --reviewed-by NAME

prepare collects what is needed to find the vulnerable functions, without deciding anything:
the advisory (GitHub Advisory Database; an unreviewed one has no package, then the affected versions come from the
CVE record and --coordinates names the Maven package), the installed and the fixed release from Maven Central, the methods
whose code the fix changed (MethodDiff in reach-analyzer.jar), the fix commits the advisory links, and for
each changed method the source lines the fix touched (candidates for the L3 vulnerable region).

The draft is a CANDIDATE. check compares it with the jars (every function and line it names must exist) and
writes REVIEW.md, the page a person reads before the data goes in. apply refuses a draft that fails check and
records who reviewed it (PRD NFR-04: an AI proposes, a person confirms).

Only the Python standard library is used. Network: api.github.com, github.com (fix commits), cveawg.mitre.org
(CVE records) and repo1.maven.org. GITHUB_TOKEN, when set, is sent to api.github.com only (a higher rate limit).
"""
import argparse
import datetime
import difflib
import functools
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

TOOL = "reach-vulndata 0.1.0"
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent                                   # reach-analyzer/
SPEC = ROOT.parent / "src" / "main" / "resources" / "reach" / "vuln-functions.json"
RULES = ROOT.parent / "src" / "main" / "resources" / "reach" / "rules.json"
ANALYZER_JAR = ROOT / "build" / "libs" / "reach-analyzer.jar"
RECORDS = ROOT / "research" / "vulndata"
MAVEN = "https://repo1.maven.org/maven2"
ADVISORIES = "https://api.github.com/advisories"
CVE_RECORDS = "https://cveawg.mitre.org/api/cve"

KINDS = ("app_calls_library", "framework_calls_library", "framework_invokes", "both")
# Kinds where a framework runs the code: the call graph alone cannot decide, so rules.json needs a rule
NEEDS_RULE = ("framework_calls_library", "framework_invokes", "both")
CONFIDENCE = ("high", "medium", "low")
ENTRY_KEYS = ("cve", "ghsa", "package", "severity", "cvss_vector", "invocation_kind", "summary_ko", "summary_en",
              "sinks", "sources", "l3")
SINK_KEYS = ("class", "method", "desc", "confidence", "note")
REGION_KEYS = ("class", "method", "desc", "source", "lines")
REVIEW_KEYS = ("trigger_conditions", "rule_hint", "overreach_risks", "open_questions")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
GHSA_RE = re.compile(r"GHSA(-[0-9a-z]{4}){3}")
COORD_RE = re.compile(r"[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*")
COMMIT_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)/commit/([0-9a-f]{7,40})")
CANDIDATE_LIMIT = 400
SOURCE_FILE_LIMIT = 60
PATCH_LIMIT = 120_000


class Stop(Exception):
    """A message for the person running the tool (no stack trace)."""


def log(message):
    print(f"[vulndata] {message}", file=sys.stderr)


# ---------------------------------------------------------------------------------------------------------
# versions

def version_tokens(version):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"[.\-+_]", version) if t != ""]


def compare_versions(a, b):
    """Maven-like order, enough for release versions: numbers by value, and 1.0-RC1 < 1.0 < 1.0.1."""
    x, y = version_tokens(a), version_tokens(b)
    for i in range(max(len(x), len(y))):
        if i >= len(x) or i >= len(y):
            rest = (x if i < len(x) else y)[i:]
            longer = 1 if i < len(x) else -1
            if isinstance(rest[0], str):
                return -longer                      # a qualifier (rc1, m2) comes before the plain release
            return longer if any(t != 0 for t in rest if isinstance(t, int)) else 0
        p, q = x[i], y[i]
        if p == q:
            continue
        if isinstance(p, int) and isinstance(q, int):
            return -1 if p < q else 1
        if isinstance(p, int) != isinstance(q, int):
            return 1 if isinstance(p, int) else -1  # 1.0.1 > 1.0-rc1
        return -1 if p < q else 1
    return 0


def parse_range(text):
    """'>= 11.0.20, < 11.0.25' -> [('>=', '11.0.20'), ('<', '11.0.25')]"""
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(>=|<=|>|<|=)\s*(\S+)", part)
        if not m:
            raise Stop(f"cannot read the version range {text!r}")
        out.append((m.group(1), m.group(2)))
    return out


def in_range(version, text):
    for op, bound in parse_range(text):
        c = compare_versions(version, bound)
        ok = {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0, "=": c == 0}[op]
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------------------------------------
# network and files

def http_get(url, accept=None):
    request = urllib.request.Request(url, headers={"User-Agent": "reach-vulndata"})
    if accept:
        request.add_header("Accept", accept)
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def fetch(url, path):
    """Downloads once (the bundle's cache/ keeps it). Returns False when the server has no such file."""
    path = pathlib.Path(path)
    if path.exists():
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = http_get(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise Stop(f"{url}: HTTP {e.code}")
    except urllib.error.URLError as e:
        raise Stop(f"{url}: {e.reason}")
    part = path.with_name(path.name + ".part")
    part.write_bytes(data)
    part.replace(path)
    return True


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def maven_url(group, artifact, version, classifier=None):
    name = f"{artifact}-{version}" + (f"-{classifier}" if classifier else "") + ".jar"
    return f"{MAVEN}/{group.replace('.', '/')}/{artifact}/{version}/{name}"


def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    pathlib.Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_tsv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\t".join(header) + "\n")
        for row in rows:
            f.write("\t".join(row) + "\n")


def read_tsv(path):
    lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


# ---------------------------------------------------------------------------------------------------------
# the advisory

def load_advisory(cve, ghsa):
    if ghsa:
        data = json.loads(http_get(f"{ADVISORIES}/{ghsa}", "application/vnd.github+json"))
    else:
        found = json.loads(http_get(f"{ADVISORIES}?cve_id={cve}", "application/vnd.github+json"))
        if not found:   # not reviewed yet: no package in it, the CVE record gives the versions (from_cve_record)
            found = json.loads(http_get(f"{ADVISORIES}?cve_id={cve}&type=unreviewed", "application/vnd.github+json"))
        if not found:
            raise Stop(f"no advisory for {cve} in the GitHub Advisory Database; pass --ghsa if it has another id")
        if len(found) > 1:
            ids = ", ".join(a["ghsa_id"] for a in found)
            raise Stop(f"{cve} has more than one advisory ({ids}); pass --ghsa")
        data = found[0]
    return data


def maven_rows(advisory):
    return [r for r in advisory.get("vulnerabilities") or []
            if ((r.get("package") or {}).get("ecosystem") or "").lower() == "maven"]


def record_cvss(record):
    """(severity, vector) of the CVE record: the CNA's CVSS first, then an ADP's (CISA adds one to many records)."""
    containers = record.get("containers") or {}
    for holder in [containers.get("cna") or {}] + list(containers.get("adp") or []):
        for metric in holder.get("metrics") or []:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                cvss = metric.get(key)
                if cvss and cvss.get("baseSeverity"):
                    return cvss["baseSeverity"].upper(), cvss.get("vectorString")
    return None, None


def from_cve_record(advisory, record, coordinates):
    """An advisory without a Maven package (unreviewed in the GitHub database) completed from the CVE record: every
    affected version range of the record becomes a row for --coordinates. A range that ends at 'lessThan' is fixed in
    that version; one that ends at 'lessThanOrEqual' has no fixed version yet (prepare asks Maven Central).
    The CVSS of the record fills a severity the advisory does not have."""
    rows = []
    for affected in ((record.get("containers") or {}).get("cna") or {}).get("affected") or []:
        for v in affected.get("versions") or []:
            if v.get("status") != "affected":
                continue
            start, below, upto = v.get("version"), v.get("lessThan"), v.get("lessThanOrEqual")
            bounds = [f">= {start}"] if start and start not in ("0", "*") else []
            if below and below != "*":
                bounds.append(f"< {below}")
            elif upto and upto != "*":
                bounds.append(f"<= {upto}")
            elif start:
                bounds = [f"= {start}"]
            if bounds:
                rows.append({"package": {"ecosystem": "maven", "name": coordinates},
                             "vulnerable_version_range": ", ".join(bounds),
                             "first_patched_version": below if below and below != "*" else None})
    if not rows:
        raise Stop("the CVE record lists no affected version range; pass --fixed")
    out = dict(advisory, vulnerabilities=rows, package_source=f"CVE record ({CVE_RECORDS}/{record_id(record)})")
    severity, vector = record_cvss(record)
    if severity and (advisory.get("severity") or "unknown").lower() == "unknown":
        out["severity"] = severity.lower()
    if vector and not cvss_vector(advisory):
        out["cvss"] = {"vector_string": vector}
    return out


def record_id(record):
    return (record.get("cveMetadata") or {}).get("cveId") or "?"


def next_release(versions, after):
    """The first release after `after` on the same line (every number but the last the same: 11.0.25 -> 11.0.x,
    1.1 -> 1.x; no qualifier such as -M1): the version that fixed a range ending at 'lessThanOrEqual after'."""
    tokens = version_tokens(after)
    line = tokens[:max(1, len(tokens) - 1)]
    later = [v for v in versions if VERSION_RE.fullmatch(v) and all(isinstance(t, int) for t in version_tokens(v))
             and version_tokens(v)[:len(line)] == line and compare_versions(v, after) > 0]
    return min(later, key=functools.cmp_to_key(compare_versions)) if later else None


def maven_versions(group, artifact):
    text = http_get(f"{MAVEN}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml").decode("utf-8", "replace")
    return re.findall(r"<version>([^<]+)</version>", text)


def complete_fixed(advisory, coordinates):
    """Fills the fixed version of rows ending at '<= x' with the next release after x on Maven Central."""
    group, artifact = coordinates.split(":")
    versions = None
    for row in advisory["vulnerabilities"]:
        if patched(row):
            continue
        upto = [bound for op, bound in parse_range(row["vulnerable_version_range"]) if op == "<="]
        if not upto:
            continue
        versions = versions if versions is not None else maven_versions(group, artifact)
        row["first_patched_version"] = next_release(versions, upto[0])
    return advisory


def patched(row):
    value = row.get("first_patched_version")
    if isinstance(value, dict):
        value = value.get("identifier")
    return value or None


def choose_package(advisory, coordinates, installed, fixed_override=None):
    """-> (coordinates, fixed versions of every branch, the fixed version to compare the installed one with)"""
    rows = maven_rows(advisory)
    names = sorted({r["package"]["name"] for r in rows})
    if not names:
        raise Stop("the advisory lists no Maven package (only Java libraries are supported); "
                   "pass --coordinates group:artifact to read the affected versions from the CVE record")
    if not coordinates:
        if len(names) > 1:
            raise Stop("the advisory lists several packages; pass --coordinates: " + ", ".join(names))
        coordinates = names[0]
    mine = [r for r in rows if r["package"]["name"] == coordinates]
    if not mine:
        raise Stop(f"{coordinates} is not in the advisory: " + ", ".join(names))
    fixed = []
    for r in mine:
        if patched(r) and patched(r) not in fixed:
            fixed.append(patched(r))
    if fixed_override:
        return coordinates, with_version(fixed, fixed_override), fixed_override
    hit = [r for r in mine if in_range(installed, r.get("vulnerable_version_range"))]
    if not hit:
        ranges = "; ".join(r.get("vulnerable_version_range") or "?" for r in mine)
        raise Stop(f"{coordinates} {installed} is not in a vulnerable range of the advisory ({ranges}); "
                   "check --installed, or pass --fixed to compare anyway")
    row = hit[0]
    target = patched(row)
    # '< 1.81.1' with first patched 1.84: the closest fixed release gives the smallest diff, when it was published
    uppers = [bound for op, bound in parse_range(row.get("vulnerable_version_range")) if op == "<"]
    if uppers and uppers[0] != target:
        group, artifact = coordinates.split(":")
        if url_exists(maven_url(group, artifact, uppers[0])):
            log(f"comparing with {uppers[0]} (the end of the vulnerable range) instead of {target}")
            target = uppers[0]
    if not target:
        raise Stop(f"the advisory names no fixed version for {coordinates} {installed}; pass --fixed")
    return coordinates, with_version(fixed, target), target


def with_version(fixed, version):
    """The release compared with is a fixed release too, also when the advisory names a later one."""
    return fixed if version in fixed else [version] + fixed


def url_exists(url):
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "reach-vulndata"})
    try:
        with urllib.request.urlopen(request, timeout=30):
            return True
    except (urllib.error.HTTPError, urllib.error.URLError):
        return False


def fix_commits(advisory):
    out, seen = [], set()
    for ref in advisory.get("references") or []:
        m = COMMIT_RE.fullmatch(ref.strip()) if isinstance(ref, str) else None
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            out.append({"repository": m.group(1), "sha": m.group(2), "url": m.group(0)})
    return out


def cvss_vector(advisory):
    for holder in (advisory.get("cvss") or {}, ((advisory.get("cvss_severities") or {}).get("cvss_v3") or {}),
                   ((advisory.get("cvss_severities") or {}).get("cvss_v4") or {})):
        if holder.get("vector_string"):
            return holder["vector_string"]
    return None


# ---------------------------------------------------------------------------------------------------------
# what the fix changed

def java_files_of_patch(text):
    """Paths of the non-test Java files a patch touches."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^diff --git a/(\S+\.java) b/", line)
        if m and not is_test_path(m.group(1)) and m.group(1) not in out:
            out.append(m.group(1))
    return out


def is_test_path(path):
    return bool(re.search(r"(^|/)(test|tests|src/test|testFixtures|jmh)(/|$)", path))


def class_of_path(path):
    """core/src/main/java/org/x/Y.java or java/org/x/Y.java -> org.x.Y"""
    m = re.search(r"(?:^|/)(?:src/main/java|java)/(.+)\.java$", path)
    name = m.group(1) if m else path[:-len(".java")]
    return name.replace("/", ".")


def java_hunks(text):
    """The patch without tests and non-Java files."""
    out, keep = [], False
    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            m = re.match(r"^diff --git a/(\S+) b/", line)
            keep = bool(m) and m.group(1).endswith(".java") and not is_test_path(m.group(1))
        if keep:
            out.append(line)
    return "".join(out)


def outer(cls):
    return cls.split("$")[0]


def simple(cls):
    return outer(cls).rsplit(".", 1)[-1]


def package(cls):
    return cls.rsplit(".", 1)[0] if "." in cls else ""


def match_of(cls, touched):
    """How a changed method relates to the fix commits: class (same class), name (same simple name, for a
    library whose packages were moved or shaded), package (same package), or '-'."""
    if not touched:
        return "-"
    if outer(cls) in touched:
        return "class"
    if simple(cls) in {simple(t) for t in touched}:
        return "name"
    if package(cls) in {package(t) for t in touched}:
        return "package"
    return "-"


def parse_lines(text):
    """'548,550-553' -> {548, 550, 551, 552, 553}"""
    out = set()
    if not text or text == "-":
        return out
    for part in text.split(","):
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def format_lines(numbers):
    out = []
    for n in sorted(numbers):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in out) or "-"


def ranges_of(numbers):
    """{639, 641, 642} -> [[639, 639], [641, 642]] (the form of l3.regions[].lines)"""
    return [[int(p.partition("-")[0]), int(p.partition("-")[2] or p.partition("-")[0])]
            for p in format_lines(numbers).split(",") if p != "-"]


def changed_source_lines(before, after):
    """1-based lines of `before` that the fix replaced or deleted. An insertion marks the lines around it."""
    out = set()
    for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            out.update(range(i1 + 1, i2 + 1))
        elif tag == "insert":
            out.update(n for n in (i1, i1 + 1) if 1 <= n <= len(before))
    return out


def source_path(cls):
    return outer(cls).replace(".", "/") + ".java"


def read_source(sources_jar, path):
    if not sources_jar or not pathlib.Path(sources_jar).exists():
        return None
    with zipfile.ZipFile(sources_jar) as z:
        try:
            return z.read(path).decode("utf-8", "replace").splitlines()
        except KeyError:
            return None


def run_method_diff(analyzer_jar, *args):
    if not pathlib.Path(analyzer_jar).exists():
        raise Stop(f"{analyzer_jar} not found; build it with ./gradlew :reach-analyzer:jar")
    done = subprocess.run(["java", "-cp", str(analyzer_jar), "com.logssey.reach.analyzer.MethodDiff", *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8")
    if done.returncode != 0:
        raise Stop("MethodDiff failed: " + done.stderr.strip()[-400:])
    return [line.split("\t") for line in done.stdout.splitlines() if line]


# ---------------------------------------------------------------------------------------------------------
# prepare

def prepare(a):
    if not (a.cve or a.ghsa):
        raise Stop("pass --cve or --ghsa")
    for value, pattern, name in ((a.cve, CVE_RE, "--cve"), (a.ghsa, GHSA_RE, "--ghsa"), (a.coordinates, COORD_RE,
                                 "--coordinates"), (a.installed, VERSION_RE, "--installed"), (a.fixed, VERSION_RE,
                                 "--fixed")):
        if value and not pattern.fullmatch(value):
            raise Stop(f"{name} {value!r} is not valid")
    out = pathlib.Path(a.out)
    cache = out / "cache"
    cache.mkdir(parents=True, exist_ok=True)

    extra_commits = []
    for url in a.commit or []:
        m = COMMIT_RE.fullmatch(url.strip())
        if not m:
            raise Stop(f"--commit {url!r} is not a https://github.com/<owner>/<repo>/commit/<sha> link")
        extra_commits.append({"repository": m.group(1), "sha": m.group(2), "url": m.group(0)})

    advisory = load_advisory(a.cve, a.ghsa)
    cve = advisory.get("cve_id") or a.cve
    if not cve or not CVE_RE.fullmatch(cve):
        raise Stop("the advisory has no CVE id; verdict data is keyed by CVE")
    if not maven_rows(advisory) and a.coordinates:
        record = json.loads(http_get(f"{CVE_RECORDS}/{cve}"))
        write_json(out / "cve-record.json", record)
        advisory = from_cve_record(advisory, record, a.coordinates)
        if not a.fixed:
            complete_fixed(advisory, a.coordinates)
        log(f"{cve}: the advisory has no package, the affected versions come from the CVE record")
    write_json(out / "advisory.json", advisory)
    coordinates, fixed, target = choose_package(advisory, a.coordinates, a.installed, a.fixed)
    # these come from the advisory and go into URLs and file names
    if not COORD_RE.fullmatch(coordinates) or not all(VERSION_RE.fullmatch(v) for v in [target, *fixed]):
        raise Stop(f"the advisory has a package name or version this tool cannot use: {coordinates} {fixed}")
    if not GHSA_RE.fullmatch(advisory.get("ghsa_id") or ""):
        raise Stop("the advisory has no GHSA id")
    group, artifact = coordinates.split(":")
    log(f"{cve} {advisory['ghsa_id']}  {coordinates} {a.installed} -> {target}")

    jars = {}
    for label, version in (("installed", a.installed), ("fixed", target)):
        jar = cache / f"{artifact}-{version}.jar"
        url = maven_url(group, artifact, version)
        if not fetch(url, jar):
            raise Stop(f"{url} not found on Maven Central")
        sources = cache / f"{artifact}-{version}-sources.jar"
        has_sources = fetch(maven_url(group, artifact, version, "sources"), sources)
        jars[label] = {"version": version, "url": url, "sha256": sha256(jar), "jar": jar,
                       "sources": sources if has_sources else None}
    if not all(j["sources"] for j in jars.values()):
        log("WARNING: no sources jar on Maven Central; fix lines and source files are left out")

    diff = run_method_diff(a.analyzer_jar, jars["installed"]["jar"], jars["fixed"]["jar"])
    methods = run_method_diff(a.analyzer_jar, "--list", jars["installed"]["jar"])
    write_tsv(out / "method-diff.tsv", ("status", "class", "method", "desc", "lines"), diff)
    write_tsv(out / "methods-installed.tsv", ("class", "method", "desc", "lines"), methods)

    commits = fix_commits(advisory)
    commits += [c for c in extra_commits if c["sha"] not in {k["sha"] for k in commits}]
    patch_text, touched = "", set()
    for commit in commits:
        path = cache / f"{commit['sha'][:12]}.patch"
        if not fetch(commit["url"] + ".patch", path):
            log(f"WARNING: {commit['url']} could not be downloaded")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        commit["files"] = java_files_of_patch(text)
        touched.update(class_of_path(p) for p in commit["files"])
        patch_text += java_hunks(text)
    if not commits:
        log("WARNING: the advisory links no fix commit; every changed method is a candidate")
    elif not touched:
        log("WARNING: the fix commits touch no Java source (a data-only fix?); every changed method is a candidate")

    # candidates: changed and removed methods of the installed release, near the classes the fix commits touched
    order = {"class": 0, "name": 1, "package": 2, "-": 3}
    rows = [(status, cls, method, desc, lines, match_of(cls, touched))
            for status, cls, method, desc, lines in diff if status != "ADDED"]
    picked = [r for r in rows if not touched or r[5] != "-"]
    if touched and not picked:
        # the fix commits are for another line of the library (renamed packages), so they narrow nothing
        log("WARNING: no changed method is near the classes of the fix commits; every changed method is a candidate")
        picked = rows
    picked = sorted(picked, key=lambda r: (order[r[5]], r[1], r[2], r[3]))
    dropped = max(0, len(picked) - CANDIDATE_LIMIT)
    if dropped:
        log(f"WARNING: {len(picked)} candidates; the last {dropped} are left out of candidates.tsv "
            "(all changed methods are in method-diff.tsv)")
    picked = picked[:CANDIDATE_LIMIT]

    changed_by_file, written = {}, 0
    out_rows = []
    for status, cls, method, desc, lines, match in picked:
        path = source_path(cls)
        if path not in changed_by_file:
            before = read_source(jars["installed"]["sources"], path)
            after = read_source(jars["fixed"]["sources"], path)
            if before is None:
                changed_by_file[path] = None
            else:
                changed_by_file[path] = (set(range(1, len(before) + 1)) if after is None
                                         else changed_source_lines(before, after))
                if written < SOURCE_FILE_LIMIT:
                    written += 1
                    for label, text in (("installed", before), ("fixed", after)):
                        if text is not None:
                            target_file = out / "source" / label / path
                            target_file.parent.mkdir(parents=True, exist_ok=True)
                            target_file.write_text("\n".join(text) + "\n", encoding="utf-8")
        changed = changed_by_file[path]
        fix_lines = "-" if changed is None else format_lines(parse_lines(lines) & changed)
        out_rows.append((status, cls, method, desc, match, lines, fix_lines))
    write_tsv(out / "candidates.tsv", ("status", "class", "method", "desc", "match", "lines", "fix_lines"), out_rows)
    write_json(out / "changed-lines.json",
               {path: ranges_of(lines) for path, lines in sorted(changed_by_file.items()) if lines is not None})

    if len(patch_text) > PATCH_LIMIT:
        log(f"WARNING: the fix commits are {len(patch_text)} characters; fix-commits.diff keeps the first {PATCH_LIMIT}")
        patch_text = patch_text[:PATCH_LIMIT] + "\n... (truncated; the whole patches are in cache/)\n"
    (out / "fix-commits.diff").write_text(patch_text or "(no fix commit with Java source is linked in the advisory)\n",
                                          encoding="utf-8")

    severity = (advisory.get("severity") or "").upper() or None
    meta = {
        "tool": TOOL, "cve": cve, "ghsa": advisory["ghsa_id"],
        "package": {"coordinates": coordinates, "artifact": artifact, "installed": a.installed, "fixed": fixed},
        "comparedWith": target, "severity": severity, "cvss_vector": cvss_vector(advisory),
        "jars": {k: {"version": v["version"], "url": v["url"], "sha256": v["sha256"], "sources": bool(v["sources"])}
                 for k, v in jars.items()},
        "fixCommits": commits,
        "counts": {"methodsInstalled": len(methods), "changed": len(rows), "candidates": len(out_rows),
                   "candidatesDropped": dropped},
    }
    write_json(out / "meta.json", meta)
    write_advisory_md(out / "advisory.md", advisory, meta)
    write_json(out / "draft.template.json", template(meta, advisory))
    shutil.copyfile(HERE / "PROMPT.md", out / "PROMPT.md")
    log(f"{len(methods)} methods, {len(rows)} changed or removed, {len(out_rows)} candidates -> {out}")
    log(f"next: have an AI follow {out / 'PROMPT.md'} and write {out / 'draft.json'}, then: vulndata.py check {out}")


def write_advisory_md(path, advisory, meta):
    p = meta["package"]
    text = [f"# {meta['ghsa']} / {meta['cve']}", "",
            f"package: {p['coordinates']}", f"installed (vulnerable): {p['installed']}",
            f"fixed releases: {', '.join(p['fixed']) or '-'}", f"compared with: {meta['comparedWith']}",
            f"severity: {meta['severity']}  {meta['cvss_vector'] or ''}",
            f"versions from: {advisory.get('package_source') or 'the advisory'}", "",
            "## summary", advisory.get("summary") or "", "",
            "## description", (advisory.get("description") or "")[:8000], "",
            "## affected", *[f"- {r['package']['name']}  {r.get('vulnerable_version_range')}  "
                             f"(first patched {patched(r)})" for r in advisory.get("vulnerabilities") or []], "",
            "## references", *[f"- {r}" for r in advisory.get("references") or []], ""]
    pathlib.Path(path).write_text("\n".join(text), encoding="utf-8")


def template(meta, advisory):
    sources = [advisory.get("html_url")] + [c["url"] for c in meta["fixCommits"]]
    return {
        "entry": {
            "cve": meta["cve"], "ghsa": meta["ghsa"], "package": meta["package"],
            "severity": meta["severity"], "cvss_vector": meta["cvss_vector"],
            "invocation_kind": "", "summary_ko": "", "summary_en": "",
            "sinks": [{"class": "", "method": "", "desc": "", "confidence": "high"}],
            "sources": [s for s in sources if s],
            "l3": {"version": meta["package"]["installed"],
                   "regions": [{"class": "", "method": "", "desc": "", "source": "", "lines": [[0, 0]]}],
                   "note": ""},
        },
        "review": {"trigger_conditions": [], "rule_hint": "", "overreach_risks": [], "open_questions": []},
    }


# ---------------------------------------------------------------------------------------------------------
# check

class Findings:
    def __init__(self):
        self.errors, self.warnings = [], []

    def error(self, message):
        self.errors.append(message)

    def warn(self, message):
        self.warnings.append(message)


def load_bundle(bundle):
    bundle = pathlib.Path(bundle)
    for name in ("meta.json", "methods-installed.tsv", "method-diff.tsv"):
        if not (bundle / name).exists():
            raise Stop(f"{bundle / name} not found; is this a bundle made by prepare?")
    if not (bundle / "draft.json").exists():
        raise Stop(f"{bundle / 'draft.json'} not found; the draft is written from the bundle (see PROMPT.md)")
    try:
        draft = read_json(bundle / "draft.json")
    except json.JSONDecodeError as e:
        raise Stop(f"draft.json is not JSON: {e}")
    methods = {}
    for row in read_tsv(bundle / "methods-installed.tsv"):
        methods[(row["class"], row["method"], row["desc"])] = parse_lines(row["lines"])
    changed = {(r["class"], r["method"], r["desc"]): r["status"] for r in read_tsv(bundle / "method-diff.tsv")}
    changed_lines = {}
    if (bundle / "changed-lines.json").exists():
        for path, ranges in read_json(bundle / "changed-lines.json").items():
            changed_lines[path] = {n for lo, hi in ranges for n in range(lo, hi + 1)}
    return {"dir": bundle, "meta": read_json(bundle / "meta.json"), "draft": draft, "methods": methods,
            "changed": changed, "changedLines": changed_lines}


def text_of(value):
    return value.strip() if isinstance(value, str) else ""


def check_draft(b, rules=None):
    """-> Findings. Errors are things that are wrong whatever a reviewer thinks; warnings are for the reviewer."""
    f, meta, draft = Findings(), b["meta"], b["draft"]
    entry = draft.get("entry") if isinstance(draft, dict) else None
    if not isinstance(entry, dict):
        f.error("draft.json needs an object 'entry'")
        return f
    for key in entry:
        if key not in ENTRY_KEYS:
            f.error(f"entry.{key} is not a field of vuln-functions.json")
    for key in ("cve", "ghsa", "severity", "cvss_vector"):
        if entry.get(key) != meta.get(key):
            f.error(f"entry.{key} must stay {meta.get(key)!r} (from the advisory)")
    if entry.get("package") != meta["package"]:
        f.error("entry.package must stay as prepare wrote it")
    if entry.get("invocation_kind") not in KINDS:
        f.error("entry.invocation_kind must be one of " + ", ".join(KINDS))
    for key in ("summary_ko", "summary_en"):
        if not text_of(entry.get(key)):
            f.error(f"entry.{key} is empty")
    if text_of(entry.get("summary_ko")) and not re.search(r"[가-힣]", entry["summary_ko"]):
        f.error("entry.summary_ko must be Korean (the dashboard shows it)")
    sources = entry.get("sources")
    if not isinstance(sources, list) or not sources or not all(text_of(s) for s in sources):
        f.error("entry.sources must be a list of URLs (the advisory and the fix commits at least)")
    elif meta["fixCommits"] and not any(COMMIT_RE.fullmatch(s) for s in sources):
        f.warn("entry.sources에 수정 커밋 URL이 없다(화면의 '수정 커밋'이 비게 된다)")

    methods, changed = b["methods"], b["changed"]
    classes = {k[0] for k in methods}

    def locate(item, where):
        """The method an item names, or None after reporting why not."""
        if not isinstance(item, dict):
            f.error(f"{where} must be an object")
            return None
        cls, method, desc = text_of(item.get("class")), text_of(item.get("method")), text_of(item.get("desc"))
        if not (cls and method and desc):
            f.error(f"{where} needs class, method and desc")
            return None
        key = (cls, method, desc)
        if key in methods:
            return key
        if cls not in classes:
            f.error(f"{where}: class {cls} is not in {meta['package']['artifact']} {meta['package']['installed']}")
        else:
            same = sorted(k[2] for k in methods if k[0] == cls and k[1] == method)
            f.error(f"{where}: {cls}.{method}{desc} is not in the installed jar"
                    + (f" (descriptors of that name: {', '.join(same)})" if same else " (no method of that name)"))
        return None

    sinks = entry.get("sinks")
    sink_keys = []
    if not isinstance(sinks, list) or not sinks:
        f.error("entry.sinks must list at least one method (the dashboard refuses a CVE without sinks)")
        sinks = []
    for i, sink in enumerate(sinks):
        where = f"sinks[{i}]"
        if isinstance(sink, dict):
            for key in sink:
                if key not in SINK_KEYS:
                    f.error(f"{where}.{key} is not a sink field")
            if sink.get("confidence") not in CONFIDENCE:
                f.error(f"{where}.confidence must be one of " + ", ".join(CONFIDENCE))
        key = locate(sink, where)
        if key is None:
            continue
        if key in sink_keys:
            f.error(f"{where} repeats {key[0]}.{key[1]}")
        sink_keys.append(key)
        if key not in changed:
            f.warn(f"{where} {short(key)}: 수정에서 바뀌지 않은 메서드다(고쳐진 메서드를 부르는 쪽인지 확인)")
    if sink_keys and not any(k in changed for k in sink_keys):
        f.warn("sink 중에 수정에서 바뀐 메서드가 하나도 없다")

    l3 = entry.get("l3")
    if l3 is None:
        f.warn("entry.l3가 없다(L3는 이 CVE를 '기록 안 됨'으로만 보인다)")
    elif not isinstance(l3, dict) or not isinstance(l3.get("regions"), list):
        f.error("entry.l3 needs version and a list regions")
    else:
        for key in l3:
            if key not in ("version", "regions", "note"):
                f.error(f"l3.{key} is not an l3 field")
        if l3.get("version") != meta["package"]["installed"]:
            f.error(f"l3.version must be the installed version {meta['package']['installed']} (line numbers are its)")
        if not l3["regions"] and not text_of(l3.get("note")):
            f.error("l3.regions is empty: l3.note must say why execution cannot show the vulnerable code")
        for i, region in enumerate(l3["regions"]):
            where = f"l3.regions[{i}]"
            if isinstance(region, dict):
                for key in region:
                    if key not in REGION_KEYS:
                        f.error(f"{where}.{key} is not a region field")
            key = locate(region, where)
            if key is None:
                continue
            if region.get("source") != source_path(key[0]):
                f.error(f"{where}.source must be {source_path(key[0])}")
            lines, own = region.get("lines"), methods[key]
            if lines is None:
                if own:
                    f.warn(f"{where} {short(key)}: 줄 없이 메서드 전체를 구간으로 잡았다(줄 번호가 있는 jar다)")
                continue
            if (not isinstance(lines, list) or not lines or not all(
                    isinstance(r, list) and len(r) == 2 and all(type(n) is int for n in r) and 0 < r[0] <= r[1]
                    for r in lines)):
                f.error(f"{where}.lines must be [[first, last], …] with first <= last")
                continue
            if not own:
                f.error(f"{where} {short(key)}: the jar has no line numbers for it; leave lines out (whole method)")
                continue
            wanted = {n for lo, hi in lines for n in range(lo, hi + 1)}
            if not wanted & own:
                f.error(f"{where} {short(key)}: no code on lines {format_lines(wanted)} "
                        f"(the method's lines: {format_lines(own)})")
                continue
            # a range may hold braces and comments, but a range with no code at all can never be seen executed
            empty = [f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in lines if not set(range(lo, hi + 1)) & own]
            if empty:
                f.warn(f"{where} {short(key)}: {', '.join(empty)}줄 범위에는 실행되는 코드가 없다"
                       "(선언·빈 줄·주석). 그 범위는 빼는 것이 맞다")
            fix = b["changedLines"].get(region.get("source"))
            if fix is not None and not (wanted & fix):
                f.warn(f"{where} {short(key)}: 수정에서 바뀐 줄과 겹치지 않는다(바뀐 줄 {format_lines(own & fix)})")
            if key not in changed:
                f.warn(f"{where} {short(key)}: 수정에서 바뀌지 않은 메서드다")

    review = draft.get("review")
    if not isinstance(review, dict):
        f.error("draft.json needs an object 'review' (what a person must check)")
    else:
        for key in review:
            if key not in REVIEW_KEYS:
                f.error(f"review.{key} is not a review field")
        if not review.get("trigger_conditions"):
            f.error("review.trigger_conditions is empty: say what must be true for the code to be vulnerable")

    if entry.get("invocation_kind") in NEEDS_RULE:
        has_rule = bool(rules) and entry.get("cve") in (rules.get("verdicts") or {})
        if not has_rule:
            f.warn(f"invocation_kind={entry.get('invocation_kind')}인데 rules.json에 이 CVE의 규칙이 없다. "
                   "규칙이 없으면 호출 그래프만 보고 '도달 불가'가 나올 수 있다. 규칙을 같은 PR에서 쓴다")
    return f


def short(key):
    return f"{key[0].rsplit('.', 1)[-1]}.{key[1]}"


def review_md(b, findings):
    meta, draft = b["meta"], b["draft"]
    entry = draft.get("entry") if isinstance(draft.get("entry"), dict) else {}
    review = draft.get("review") if isinstance(draft.get("review"), dict) else {}
    p = meta["package"]
    out = [f"# {meta['cve']} 판정 데이터 초안 검토", "",
           f"- 패키지: `{p['coordinates']}` {p['installed']} (수정 {', '.join(p['fixed']) or '-'}, "
           f"비교한 버전 {meta['comparedWith']})",
           f"- 심각도: {meta['severity']}  {meta['cvss_vector'] or ''}",
           f"- 권고문: https://github.com/advisories/{meta['ghsa']}",
           f"- 수정에서 바뀐 메서드 {meta['counts']['changed']}개 중 후보 {meta['counts']['candidates']}개"
           f"(`candidates.tsv`), 수정 커밋 {len(meta['fixCommits'])}개(`fix-commits.diff`)",
           f"- 호출 방식: `{entry.get('invocation_kind')}`", "",
           "이 초안은 AI가 만든 **후보**다. 아래를 사람이 확인한 뒤 `apply`한다(NFR-04).", ""]

    out += ["## 자동 검사", ""]
    if not findings.errors and not findings.warnings:
        out.append("문제 없음.")
    out += [f"- **오류** {m}" for m in findings.errors]
    out += [f"- 확인 {m}" for m in findings.warnings]
    out.append("")

    out += ["## 요약", "", text_of(entry.get("summary_ko")) or "(없음)", "", text_of(entry.get("summary_en")), ""]

    out += ["## 취약 함수 (sink)", "", "| 메서드 | 수정에서 | 줄 | 확신 | 메모 |", "|---|---|---|---|---|"]
    for sink in entry.get("sinks") or []:
        if not isinstance(sink, dict):
            continue
        key = (text_of(sink.get("class")), text_of(sink.get("method")), text_of(sink.get("desc")))
        state = {"CHANGED": "바뀜", "REMOVED": "지워짐"}.get(b["changed"].get(key), "안 바뀜")
        if key not in b["methods"]:
            state = "jar에 없음"
        out.append(f"| `{key[0]}.{key[1]}` `{key[2]}` | {state} | {format_lines(b['methods'].get(key, set()))} "
                   f"| {sink.get('confidence') or ''} | {text_of(sink.get('note'))} |")
    out.append("")

    l3 = entry.get("l3") if isinstance(entry.get("l3"), dict) else {}
    out += ["## 취약 구간 (L3)", ""]
    if text_of(l3.get("note")):
        out += [text_of(l3.get("note")), ""]
    for region in l3.get("regions") or []:
        if not isinstance(region, dict):
            continue
        lines = region.get("lines")
        valid = isinstance(lines, list) and all(isinstance(r, list) and len(r) == 2 for r in lines)
        label = format_lines({n for lo, hi in lines for n in range(lo, hi + 1)}) if valid and lines else "메서드 전체"
        out += [f"### `{region.get('class')}.{region.get('method')}` {label}", ""]
        source = b["dir"] / "source" / "installed" / str(region.get("source"))
        if valid and lines and source.is_file():
            text = source.read_text(encoding="utf-8").splitlines()
            fix = b["changedLines"].get(region.get("source"), set())
            out.append("```java")
            for lo, hi in lines:
                for n in range(max(1, lo - 2), min(len(text), hi + 2) + 1):
                    mark = ">" if lo <= n <= hi else " "
                    out.append(f"{mark}{'*' if n in fix else ' '}{n:5} | {text[n - 1].rstrip()[:150]}")
                out.append("")
            out += ["```", "", "`>` 구간, `*` 수정에서 바뀐 줄", ""]
    if not l3.get("regions"):
        out += ["(구간 없음)", ""]

    titles = (("trigger_conditions", "취약해지는 조건"), ("rule_hint", "규칙 제안 (rules.json)"),
              ("overreach_risks", "과탐 위험"), ("open_questions", "AI가 확신하지 못한 것"))
    for key, title in titles:
        value = review.get(key)
        if not value:
            continue
        out += [f"## {title}", ""]
        out += [f"- {v}" for v in value] if isinstance(value, list) else [str(value)]
        out.append("")

    out += ["## 사람이 확인할 것", "",
            "- [ ] 취약 함수가 실제로 취약한 코드인가(`fix-commits.diff`, `source/installed`와 `source/fixed` 비교)",
            "- [ ] 모든 요청에서 실행되는 공용 메서드가 sink에 들어가지 않았는가(들어가면 항상 '도달 가능')",
            "- [ ] 취약 구간이 취약한 줄만 잡는가(구간이 넓으면 실행됐다는 근거가 약해진다)",
            "- [ ] 호출 방식이 맞는가. 프레임워크가 실행하는 코드면 `rules.json` 규칙을 쓴다",
            "- [ ] 규칙에 L3 한도 `l3`(region·function·why_ko)를 썼는가: 조건을 갖추지 않은 앱에서도 이 구간·함수가 실행되면 none(없으면 서버가 뜨지 않는다)",
            "- [ ] 요약(한국어)이 권고문과 맞는가", ""]
    return "\n".join(out)


def check(a):
    b = load_bundle(a.bundle)
    rules = read_json(a.rules) if pathlib.Path(a.rules).exists() else None
    findings = check_draft(b, rules)
    (b["dir"] / "REVIEW.md").write_text(review_md(b, findings), encoding="utf-8")
    for m in findings.errors:
        log(f"ERROR {m}")
    for m in findings.warnings:
        log(f"check {m}")
    log(f"{len(findings.errors)} errors, {len(findings.warnings)} to check -> {b['dir'] / 'REVIEW.md'}")
    return 1 if findings.errors else 0


# ---------------------------------------------------------------------------------------------------------
# apply

def ordered_entry(entry):
    out = {k: entry[k] for k in ENTRY_KEYS if k in entry}
    out["sinks"] = [{k: s[k] for k in SINK_KEYS if s.get(k) not in (None, "")} for s in entry["sinks"]]
    if "l3" in out:
        l3 = {"version": entry["l3"]["version"],
              "regions": [{k: r[k] for k in REGION_KEYS if r.get(k) is not None} for r in entry["l3"]["regions"]]}
        if text_of(entry["l3"].get("note")):
            l3["note"] = entry["l3"]["note"].strip()
        out["l3"] = l3
    return out


def apply_entry(spec, entry, replace=False):
    """Puts the entry into the parsed vuln-functions.json. A CVE that is already there needs replace."""
    at = [i for i, c in enumerate(spec["cves"]) if c.get("cve") == entry["cve"]]
    if at and not replace:
        raise Stop(f"{entry['cve']} is already in the data; pass --replace to overwrite it")
    if at:
        spec["cves"][at[0]] = entry
    else:
        spec["cves"].append(entry)
    return spec


def apply(a):
    b = load_bundle(a.bundle)
    rules = read_json(a.rules) if pathlib.Path(a.rules).exists() else None
    findings = check_draft(b, rules)
    if findings.errors:
        for m in findings.errors:
            log(f"ERROR {m}")
        raise Stop("the draft fails check; nothing was written")
    reviewer = a.reviewed_by.strip()
    if not reviewer:
        raise Stop("--reviewed-by needs the name of the person who checked REVIEW.md")
    entry = ordered_entry(b["draft"]["entry"])
    spec_path = pathlib.Path(a.spec)
    spec = apply_entry(read_json(spec_path), entry, a.replace)
    write_json(spec_path, spec)

    record = {"tool": b["meta"]["tool"], "cve": entry["cve"], "reviewedBy": reviewer,
              "appliedAt": datetime.date.today().isoformat(), "draftedBy": "AI draft, reviewed by a person",
              "package": b["meta"]["package"], "comparedWith": b["meta"]["comparedWith"], "jars": b["meta"]["jars"],
              "fixCommits": [c["url"] for c in b["meta"]["fixCommits"]], "counts": b["meta"]["counts"],
              "review": b["draft"].get("review") or {}, "checkWarnings": findings.warnings}
    records = pathlib.Path(a.records)
    records.mkdir(parents=True, exist_ok=True)
    write_json(records / f"{entry['cve']}.json", record)
    log(f"{entry['cve']} -> {spec_path} ({len(spec['cves'])} CVEs), record {records / (entry['cve'] + '.json')}")
    if entry["invocation_kind"] in NEEDS_RULE and not (rules and entry["cve"] in (rules.get("verdicts") or {})):
        log(f"NEXT: write the rule for {entry['cve']} in rules.json (invocation_kind={entry['invocation_kind']}), "
            "with its L3 limits \"l3\" (region, function, why_ko; the server does not start without them); "
            "ReachRuleServiceTest lists the facts of rules.json")
    log("NEXT: ./gradlew :reach-analyzer:fixtureTest :reach-analyzer:verdictTest and :test --tests "
        "'com.logssey.reach.rule.*'; then run the analyzer on the service jar and read the verdict")
    return 0


# ---------------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("prepare", help="collect the advisory, the jars, the changed methods and the fix commits")
    p.add_argument("--cve")
    p.add_argument("--ghsa")
    p.add_argument("--coordinates", help="group:artifact, when the advisory lists several packages")
    p.add_argument("--installed", required=True, help="the vulnerable version the service runs (from the SBOM)")
    p.add_argument("--fixed", help="the fixed version to compare with (default: from the advisory)")
    p.add_argument("--commit", action="append", default=[],
                   help="a fix commit (https://github.com/<owner>/<repo>/commit/<sha>) the advisory does not link; "
                        "repeat for several (e.g. from the project's security page)")
    p.add_argument("--out", required=True, help="the bundle directory")
    p.add_argument("--analyzer-jar", default=str(ANALYZER_JAR))
    p.set_defaults(run=prepare)

    p = sub.add_parser("check", help="compare draft.json with the jars and write REVIEW.md")
    p.add_argument("bundle")
    p.add_argument("--rules", default=str(RULES))
    p.set_defaults(run=check)

    p = sub.add_parser("apply", help="put a reviewed draft into vuln-functions.json")
    p.add_argument("bundle")
    p.add_argument("--reviewed-by", required=True, help="the person who checked REVIEW.md")
    p.add_argument("--replace", action="store_true", help="overwrite a CVE that is already in the data")
    p.add_argument("--spec", default=str(SPEC))
    p.add_argument("--rules", default=str(RULES))
    p.add_argument("--records", default=str(RECORDS))
    p.set_defaults(run=apply)

    a = ap.parse_args(argv)
    try:
        return a.run(a) or 0
    except Stop as e:
        log(f"ERROR {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
