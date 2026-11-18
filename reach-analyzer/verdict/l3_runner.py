#!/usr/bin/env python3
"""l3_runner.py — helpers for the L3 run (deploy/reach/ci/l3-run.sh): the scenario, the class files, the scope.

    python3 l3_runner.py validate scenario.json
    python3 l3_runner.py env scenario.json (--service NAME | --app)       # docker --env-file lines
    python3 l3_runner.py scope --jar app.jar                              # the agent includes
    python3 l3_runner.py run scenario.json --base-url http://127.0.0.1:PORT --out steps.json \
        [--dump-to segments/ --jacoco-cli jacococli.jar --agent 127.0.0.1:PORT]
    python3 l3_runner.py classes --jar app.jar --out classes/ [--java-release 21] \
        [--spec vuln-functions.json] [--reach reach-result.json]

The scenario lives in the service repo (.reach/l3-scenario.json) and is DATA: requests to send to the app,
never commands for the runner. Services (database, cache) and the app get only the environment written in it
plus generated throwaway secrets. Logs show the step name, the method, the path as written (before
substitution) and the status; never a request or response body, a header or a saved value (service repos
can be public). No string of the scenario may hold a control character, and log lines are written so that
they cannot start a GitHub workflow command. Requests go to the app only: redirects are not followed.

    {"schema": "reach-l3-scenario/v1", "version": "2026-11-18.1",
     "services": [{"name": "db", "image": "postgres:18.6-alpine", "env": {"POSTGRES_PASSWORD": "l3"},
                   "ready": ["pg_isready", "-U", "postgres"]}],
     "app": {"port": 8080, "env": {"SPRING_PROFILES_ACTIVE": "local"}, "generate": ["JWT_SECRET"],
             "ready": {"path": "/api/v1/categories", "status": 200}, "startTimeoutSeconds": 180},
     "steps": [{"name": "signup", "request": "POST /api/v1/auth/signup", "json": {"nickname": "l3"},
                "expect": 200, "save": {"token": "accessToken"}},
               {"name": "listing", "request": "POST /api/v1/listings", "repeat": 3,
                "headers": {"Authorization": "Bearer ${token}"}, "json": {"title": "item ${i}"}}]}

${name} is a saved value (or ${i}, the 1-based repeat index). A string that is only "${name}" keeps the
saved value's JSON type; in the path the value is URL-encoded. save paths are dot-separated keys and list
indexes ("items.0.listingId"). A step whose value is missing is SKIPPED; a failed step does not stop the run.

The class files are the ones the app runs, for `jacococli report --classfiles`: BOOT-INF/classes and
BOOT-INF/lib/*.jar of a Spring Boot jar (a plain jar as is), in class path order (first wins, like the
class loader), with multi-release jar versions up to --java-release. --spec and --reach keep only the
classes of the source files the L3 data names and of the methods on the call paths L2 found (a small
report; without both, every class). The recording scope is java.util.* and every top-level package of
the app and its libraries except java, javax, jdk and sun (JDK classes need inclbootstrapclasses, and
all of them stop the JVM).

`run --dump-to` cuts the execution data into segments so a result can say in which request code ran: the agent
(output=tcpserver) is read and reset when the run starts ("startup": everything until the app was ready,
readiness requests included) and after every step ("001", "002", …; a repeated step is one segment). Work the
app does in the background after a request can land in the next segment. The app is untrusted, so a segment
must be a regular file of at most 64 MB that starts like JaCoCo execution data.

`classes` writes the class files for the reports. `scope` prints the agent includes of a jar.
No third-party dependencies (Python 3.8+).
"""
import argparse
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SCHEMA = "reach-l3-scenario/v1"
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,199}(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# the runner sets the agent; the scenario may not replace or add JVM options
RESERVED_ENV = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS", "CLASSPATH")
SCOPE_SKIP = ("java", "javax", "jdk", "sun")
MAX_SERVICES, MAX_STEPS, MAX_REPEAT = 5, 300, 200
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
HEADER_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
PACKAGE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PATH_SAFE = "/?&=%:@!$'()*+,;~-._[]"
MAX_RESPONSE = 1 << 20          # bytes of a response read for save
MAX_EXEC = 64 << 20
EXEC_MAGIC = b"\x01\xc0\xc0"    # JaCoCo execution data: header block, magic number
STARTUP = "startup"
AGENT_PORT = 36300              # the agent's tcpserver in the app container (l3-run.sh)
OFF = ("", "0", "false", "off", "no")


def is_text(value, limit):
    """a string without control characters (they could forge log lines and env-file entries)"""
    return isinstance(value, str) and len(value) <= limit and not CONTROL_RE.search(value)


def is_int(value):
    return type(value) is int


def safe(text):
    """for a log line: no control characters, nothing GitHub Actions reads as a workflow command"""
    return CONTROL_RE.sub(" ", str(text)).replace("::", ": :").replace("##[", "## [")


class ScenarioError(Exception):
    pass


# ---------------------------------------------------------------- scenario

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _env_errors(env, where):
    errors = []
    if not isinstance(env, dict):
        return [f"{where}.env must be an object"]
    for k, v in env.items():
        if not isinstance(k, str) or not ENV_RE.fullmatch(k):
            errors.append(f"{where}.env: bad name {k!r}")
            continue
        if k.upper() in RESERVED_ENV:
            errors.append(f"{where}.env: {k} is set by the runner")
        if not is_text(v, 1000):
            errors.append(f"{where}.env.{k}: a one-line string of at most 1000 characters")
    return errors


def validate(sc):
    """Returns a list of problems (empty when the scenario is usable)."""
    if not isinstance(sc, dict):
        return ["the scenario must be a JSON object"]
    errors = []
    if sc.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if not is_text(sc.get("version"), 64) or not sc["version"]:
        errors.append("version: a string of 1 to 64 characters")

    services = sc.get("services", [])
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        errors.append(f"services: a list of at most {MAX_SERVICES}")
        services = []
    names = set()
    for n, s in enumerate(services):
        where = f"services[{n}]"
        if not isinstance(s, dict):
            errors.append(f"{where} must be an object")
            continue
        name = s.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in names or name == "app":
            errors.append(f"{where}.name: unique, lower case letters, digits and '-', not 'app'")
        else:
            names.add(name)
        if not isinstance(s.get("image"), str) or not IMAGE_RE.fullmatch(s["image"]):
            errors.append(f"{where}.image: an image reference")
        errors += _env_errors(s.get("env", {}), where)
        ready = s.get("ready")
        if ready is not None and (not isinstance(ready, list) or not ready
                                  or not all(is_text(x, 200) for x in ready)):
            errors.append(f"{where}.ready: a command as a list of strings")

    app = sc.get("app")
    if not isinstance(app, dict):
        errors.append("app must be an object")
        app = {}
    if not is_int(app.get("port")) or not 0 < app["port"] < 65536 or app["port"] == AGENT_PORT:
        errors.append(f"app.port: the port the app listens on (not {AGENT_PORT}, the agent's)")
    errors += _env_errors(app.get("env", {}), "app")
    gen = app.get("generate", [])
    if not isinstance(gen, list) or not all(isinstance(g, str) and ENV_RE.fullmatch(g) and g.upper() not in RESERVED_ENV for g in gen):
        errors.append("app.generate: names of variables to fill with random values")
    ready = app.get("ready")
    if (not isinstance(ready, dict) or not is_text(ready.get("path"), 500) or not ready["path"].startswith("/")
            or " " in ready["path"]):
        errors.append("app.ready.path: a path starting with /")
    elif not is_int(ready.get("status", 200)) or not 100 <= ready.get("status", 200) <= 599:
        errors.append("app.ready.status: a status code")
    timeout = app.get("startTimeoutSeconds", 180)
    if not is_int(timeout) or not 10 <= timeout <= 600:
        errors.append("app.startTimeoutSeconds: 10 to 600")

    steps = sc.get("steps")
    if not isinstance(steps, list) or not 0 < len(steps) <= MAX_STEPS:
        errors.append(f"steps: a list of 1 to {MAX_STEPS}")
        steps = []
    for n, st in enumerate(steps):
        where = f"steps[{n}]"
        if not isinstance(st, dict):
            errors.append(f"{where} must be an object")
            continue
        if not is_text(st.get("name"), 60) or not st["name"]:
            errors.append(f"{where}.name: a string of 1 to 60 characters")
        method, _, path = st["request"].partition(" ") if is_text(st.get("request"), 2000) else ("", "", "")
        if method not in METHODS or not path.startswith("/") or " " in path:
            errors.append(f"{where}.request: '<{'|'.join(METHODS)}> /path'")
        if "json" in st and "body" in st:
            errors.append(f"{where}: json or body, not both")
        if "body" in st and not isinstance(st["body"], str):
            errors.append(f"{where}.body: a string")
        headers = st.get("headers", {})
        if not isinstance(headers, dict) or not all(isinstance(k, str) and HEADER_RE.fullmatch(k) and is_text(v, 2000)
                                                    for k, v in headers.items()):
            errors.append(f"{where}.headers: header names of letters, digits and '-', one-line string values")
        repeat = st.get("repeat", 1)
        if not is_int(repeat) or not 1 <= repeat <= MAX_REPEAT:
            errors.append(f"{where}.repeat: 1 to {MAX_REPEAT}")
        expect = st.get("expect")
        if expect is not None and not (is_int(expect) or (isinstance(expect, list) and expect and all(is_int(x) for x in expect))):
            errors.append(f"{where}.expect: a status or a list of statuses")
        save = st.get("save", {})
        if not isinstance(save, dict) or not all(isinstance(k, str) and VAR_RE.fullmatch("${" + k + "}") and is_text(v, 200) for k, v in save.items()):
            errors.append(f"{where}.save: variable name -> dot path")
    return errors


def env_lines(sc, service=None):
    """KEY=VALUE lines for docker --env-file. The app also gets the generated values."""
    if service is None:
        app = sc["app"]
        env = dict(app.get("env", {}))
        for name in app.get("generate", []):
            env[name] = secrets.token_urlsafe(48)
    else:
        found = [s for s in sc.get("services", []) if s["name"] == service]
        if not found:
            raise ScenarioError(f"no service {service}")
        env = found[0].get("env", {})
    return [f"{k}={v}" for k, v in env.items()]


# ---------------------------------------------------------------- running the steps

class Missing(Exception):
    pass


def substitute(value, variables, quote=False):
    if isinstance(value, str):
        whole = VAR_RE.fullmatch(value)
        if whole and not quote:
            if whole.group(1) not in variables:
                raise Missing(whole.group(1))
            return variables[whole.group(1)]

        def one(m):
            if m.group(1) not in variables:
                raise Missing(m.group(1))
            v = variables[m.group(1)]
            v = v if isinstance(v, str) else json.dumps(v)
            return urllib.parse.quote(v, safe="") if quote else v
        return VAR_RE.sub(one, value)
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    return value


def pick(data, path):
    for part in path.split(".") if path else []:
        if isinstance(data, list) and re.fullmatch(r"\d+", part) and int(part) < len(data):
            data = data[int(part)]
        elif isinstance(data, dict) and part in data:
            data = data[part]
        else:
            return None
    return data


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Requests go to the app only: a 3xx is the answer, not a new request (its headers would go along)"""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def send(base_url, method, path, headers, body, timeout=15):
    """(status, body) of one request; (None, b"") when it could not be sent or read"""
    try:
        url = base_url.rstrip("/") + urllib.parse.quote(path, safe=PATH_SAFE)
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.read(MAX_RESPONSE)
        except urllib.error.HTTPError as e:
            return e.code, e.read(MAX_RESPONSE)
    except Exception:   # nothing about a request may stop the run or reach the log (the text can hold values)
        return None, b""


def config_keys(sc):
    """The app's settings for the evidence (FR-14): names and whether they are on, never values."""
    app = sc["app"]
    keys = [{"name": k, "enabled": v.strip().lower() not in OFF} for k, v in app.get("env", {}).items()]
    return keys + [{"name": k, "enabled": True} for k in app.get("generate", []) if k not in app.get("env", {})]


def run(sc, base_url, log=print, sender=send, cut=None):
    """Sends the steps. cut(segment id) is called when the run starts and after every step."""
    variables, results = {}, []
    if cut:
        cut(STARTUP)
    for number, st in enumerate(sc["steps"], 1):
        method, _, path = st["request"].partition(" ")
        expect = st.get("expect")
        expect = None if expect is None else ([expect] if isinstance(expect, int) else expect)
        summary = {"segment": f"{number:03d}", "name": st["name"], "method": method, "path": path,
                   "count": 0, "ok": 0, "failed": 0, "skipped": 0, "statuses": {}}
        started = time.monotonic()
        for i in range(1, st.get("repeat", 1) + 1):
            summary["count"] += 1
            scope = dict(variables, i=i)
            try:
                url = substitute(path, scope, quote=True)
                headers = {}
                for k, v in st.get("headers", {}).items():
                    v = substitute(v, scope)
                    v = v if isinstance(v, str) else json.dumps(v)
                    if CONTROL_RE.search(v):     # a saved value that cannot be a header; never shown
                        raise Missing(VAR_RE.search(st["headers"][k]).group(1))
                    headers[k] = v
                body = None
                if "json" in st:
                    body = json.dumps(substitute(st["json"], scope)).encode()
                    headers.setdefault("Content-Type", "application/json")
                elif "body" in st:
                    text = substitute(st["body"], scope)
                    body = (text if isinstance(text, str) else json.dumps(text)).encode()
            except Missing as e:
                summary["skipped"] += 1
                summary.setdefault("missing", e.args[0])
                continue
            try:
                status, payload = sender(base_url, method, url, headers, body)
            except Exception:
                status, payload = None, b""
            key = str(status) if status is not None else "error"
            summary["statuses"][key] = summary["statuses"].get(key, 0) + 1
            good = status is not None and (status in expect if expect else 200 <= status < 300)
            if not good:
                summary["failed"] += 1
                continue
            summary["ok"] += 1
            if st.get("save"):
                try:
                    data = json.loads(payload or b"null")
                except ValueError:
                    data = None
                for name, where in st["save"].items():
                    v = pick(data, where)
                    if v is not None:
                        variables[name] = v
        summary["ms"] = int((time.monotonic() - started) * 1000)
        statuses = ", ".join(f"{k} x{v}" for k, v in sorted(summary["statuses"].items()))
        extra = f", skipped {summary['skipped']} (missing ${{{summary['missing']}}})" if summary["skipped"] else ""
        log(safe(f"[l3] {st['name']}: {method} {path} -> {statuses or '-'}{extra} ({summary['ms']}ms)"))
        results.append(summary)
        if cut:
            cut(summary["segment"])
    counts = {k: sum(r[k] for r in results) for k in ("count", "ok", "failed", "skipped")}
    return {"scenario": sc["version"], "configKeys": config_keys(sc), "requests": counts, "steps": results}


# ---------------------------------------------------------------- execution data, one file per segment

def check_segment(path):
    """The agent of an untrusted app sent this: a regular file, not huge, that starts like JaCoCo data."""
    try:
        info = os.lstat(path)
    except OSError:
        raise ScenarioError("no execution data")
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EXEC:
        raise ScenarioError("the execution data is not a regular file of a usable size")
    with open(path, "rb") as f:
        if f.read(len(EXEC_MAGIC)) != EXEC_MAGIC:
            raise ScenarioError("the file is not JaCoCo execution data")
    return info.st_size


def dumper(cli, address, directory, java="java"):
    """cut(segment): read the agent's execution data into <directory>/<segment>.exec and reset it"""
    host, _, port = address.rpartition(":")
    os.makedirs(directory, exist_ok=True)

    def cut(segment):
        path = os.path.join(directory, segment + ".exec")
        try:
            done = subprocess.run([java, "-jar", cli, "dump", "--address", host, "--port", port, "--destfile", path,
                                   "--reset", "--retry", "3", "--quiet"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            raise ScenarioError(f"could not read the execution data of segment {segment}")
        if done.returncode != 0:
            raise ScenarioError(f"could not read the execution data of segment {segment}")
        check_segment(path)
    return cut


# ---------------------------------------------------------------- class files and scope

def _classpath(fat, names):
    """BOOT-INF/lib jars in the order the launcher uses (classpath.idx), else sorted"""
    libs = sorted(n for n in names if n.startswith("BOOT-INF/lib/") and n.endswith(".jar"))
    if "BOOT-INF/classpath.idx" not in names:
        return libs
    listed = re.findall(r'"([^"]+)"', fat.read("BOOT-INF/classpath.idx").decode("utf-8", "replace"))
    listed = [n if n.startswith("BOOT-INF/") else "BOOT-INF/lib/" + n for n in listed]
    return [n for n in listed if n in names] + [n for n in libs if n not in listed]


def _jar_classes(zf, prefix, release):
    """class path -> bytes of one archive (entries under prefix), multi-release versions up to release"""
    names = zf.namelist()
    multi = False
    if prefix == "" and "META-INF/MANIFEST.MF" in names:
        multi = re.search(rb"(?im)^Multi-Release:\s*true", zf.read("META-INF/MANIFEST.MF")) is not None
    out = {}
    for n in names:
        if n.startswith(prefix) and n.endswith(".class") and not n.startswith(prefix + "META-INF/"):
            rel = n[len(prefix):]
            if rel.endswith("module-info.class"):
                continue
            out[rel] = n
    if multi:
        versioned = {}
        for n in names:
            m = re.match(r"META-INF/versions/(\d+)/(.+\.class)$", n)
            if m and int(m.group(1)) <= release and not m.group(2).endswith("module-info.class"):
                versioned.setdefault(m.group(2), []).append((int(m.group(1)), n))
        for rel, options in versioned.items():
            out[rel] = max(options)[1]
    return {rel: zf.read(entry) for rel, entry in out.items()}


def spec_sources(spec):
    """outer class paths ("pkg/Outer") of every class the L3 data names (regions and sinks)"""
    out = set()
    for cve in spec.get("cves", []):
        classes = [r["class"] for r in (cve.get("l3") or {}).get("regions") or []]
        classes += [s["class"] for s in cve.get("sinks") or []]
        out.update(c.split("$")[0].replace(".", "/") for c in classes)
    return out


def reach_sources(reach):
    """outer class paths of the methods on the call paths L2 found (reach-result.json sinks[].path)"""
    out = set()
    for cve in (reach or {}).get("cves", []):
        for sink in cve.get("sinks") or []:
            for step in sink.get("path") or []:
                owner = (step.get("method") or "").partition("(")[0].rpartition(".")[0]
                if owner:
                    out.add(owner.split("$")[0].replace(".", "/"))
    return out


def write_classes(jar, out_dir, release=21, only=None):
    """Writes the class files and returns (top-level packages, written, duplicates skipped).
    out_dir None: nothing is written (only the packages are wanted)."""
    roots, written, duplicates = set(), 0, 0
    seen = set()

    base = None
    if out_dir is not None:
        os.makedirs(out_dir, exist_ok=True)   # also when nothing is written: the report then has no class
        base = os.path.realpath(out_dir)

    def keep(rel, data):
        nonlocal written, duplicates
        parts = rel.split("/")
        if any(part in ("", ".", "..") or "\\" in part or CONTROL_RE.search(part) for part in parts):
            return                        # not a class name; would leave --out
        if len(parts) > 1 and PACKAGE_RE.fullmatch(parts[0]):
            roots.add(parts[0])           # goes into the agent options: package names only
        if rel in seen:
            duplicates += 1
            return
        seen.add(rel)
        if base is None or (only is not None and rel[:-len(".class")].split("$")[0] not in only):
            return
        path = os.path.realpath(os.path.join(base, rel))
        if os.path.commonpath([base, path]) != base:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        written += 1

    with zipfile.ZipFile(jar) as fat:
        names = set(fat.namelist())
        if any(n.startswith("BOOT-INF/") for n in names):
            for rel, data in _jar_classes(fat, "BOOT-INF/classes/", release).items():
                keep(rel, data)
            for lib in _classpath(fat, names):
                with zipfile.ZipFile(io.BytesIO(fat.read(lib))) as zf:
                    for rel, data in _jar_classes(zf, "", release).items():
                        keep(rel, data)
        else:
            for rel, data in _jar_classes(fat, "", release).items():
                keep(rel, data)
    return roots, written, duplicates


def scope_of(roots):
    return ":".join(["java.util.*"] + [f"{r}.*" for r in sorted(roots) if r not in SCOPE_SKIP])


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("scenario")
    e = sub.add_parser("env")
    e.add_argument("scenario")
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--service")
    g.add_argument("--app", action="store_true")
    c = sub.add_parser("classes")
    c.add_argument("--jar", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--java-release", type=int, default=21)
    c.add_argument("--spec", help="keep the classes of the source files this L3 data names")
    c.add_argument("--reach", help="keep the classes on the call paths of this analyzer output")
    p = sub.add_parser("scope")
    p.add_argument("--jar", required=True)
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("--base-url", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--dump-to", help="folder for the execution data, one file per segment")
    r.add_argument("--jacoco-cli", help="jacococli.jar (with --dump-to)")
    r.add_argument("--agent", help="host:port of the agent's tcpserver (with --dump-to)")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "classes":
            only = None
            if a.spec or a.reach:
                only = (spec_sources(load(a.spec)) if a.spec else set()) | (reach_sources(load(a.reach)) if a.reach else set())
            _, written, duplicates = write_classes(a.jar, a.out, a.java_release, only)
            print(f"l3_runner: {written} class files in {a.out}, {duplicates} later duplicates skipped", file=sys.stderr)
            return 0
        if a.cmd == "scope":
            print(scope_of(write_classes(a.jar, None)[0]))
            return 0
        sc = load(a.scenario)
        problems = validate(sc)
        if problems:
            for p in problems:
                print(safe(f"l3_runner: {a.scenario}: {p}"), file=sys.stderr)
            return 1
        if a.cmd == "validate":
            print(safe(f"l3_runner: {a.scenario}: scenario {sc['version']}, {len(sc['steps'])} steps"), file=sys.stderr)
        elif a.cmd == "env":
            print("\n".join(env_lines(sc, None if a.app else a.service)))
        elif a.cmd == "run":
            cut = None
            if a.dump_to:
                if not a.jacoco_cli or not a.agent:
                    raise ScenarioError("--dump-to needs --jacoco-cli and --agent")
                cut = dumper(a.jacoco_cli, a.agent, a.dump_to)
            result = run(sc, a.base_url, log=lambda m: print(m, file=sys.stderr), cut=cut)
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            q = result["requests"]
            print(f"l3_runner: {q['count']} requests, ok {q['ok']}, failed {q['failed']}, skipped {q['skipped']}", file=sys.stderr)
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, ScenarioError) as err:
        print(safe(f"l3_runner: {err}"), file=sys.stderr)
        return 1
    except Exception as err:   # the message may hold scenario or response values: only its kind
        print(f"l3_runner: {type(err).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
