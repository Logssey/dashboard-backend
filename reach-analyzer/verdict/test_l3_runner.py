"""Tests for l3_runner.py.  python3 -m unittest discover -s reach-analyzer/verdict"""
import copy
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

import l3_runner

SCENARIO = {
    "schema": "reach-l3-scenario/v1", "version": "1",
    "services": [{"name": "db", "image": "postgres:18.6-alpine", "env": {"POSTGRES_PASSWORD": "l3"},
                  "ready": ["pg_isready", "-h", "127.0.0.1"]}],
    "app": {"port": 8080, "env": {"SPRING_PROFILES_ACTIVE": "local"}, "generate": ["JWT_SECRET"],
            "ready": {"path": "/health"}},
    "steps": [
        {"name": "login", "request": "POST /login", "json": {"user": "l3"}, "save": {"token": "data.token", "id": "items.0.id"}},
        {"name": "create", "request": "POST /items", "repeat": 3, "headers": {"Authorization": "Bearer ${token}"},
         "json": {"title": "item ${i}", "owner": "${id}"}},
        {"name": "search", "request": "GET /items?q=${token}"},
        {"name": "needs a missing value", "request": "GET /items/${nothing}"},
        {"name": "denied", "request": "GET /admin", "expect": [403]},
    ],
}


class FakeApp:
    """Records the requests; answers like a tiny app"""

    def __init__(self):
        self.requests = []

    def __call__(self, base_url, method, path, headers, body, timeout=30):
        self.requests.append((method, path, headers, json.loads(body) if body else None))
        if path == "/login":
            return 200, json.dumps({"data": {"token": "t/1 2"}, "items": [{"id": 7}]}).encode()
        if path == "/admin":
            return 500, b"secret stack trace"
        return 201 if method == "POST" else 200, b"{}"


class ValidateTest(unittest.TestCase):

    def broken(self, change):
        sc = copy.deepcopy(SCENARIO)
        change(sc)
        return l3_runner.validate(sc)

    def test_the_example_is_valid(self):
        self.assertEqual(l3_runner.validate(SCENARIO), [])

    def test_the_runner_owns_the_jvm_options(self):
        problems = self.broken(lambda sc: sc["app"]["env"].update(JAVA_TOOL_OPTIONS="-javaagent:/x.jar"))
        self.assertTrue(any("set by the runner" in p for p in problems))
        self.assertTrue(self.broken(lambda sc: sc["app"].update(generate=["_JAVA_OPTIONS"])))

    def test_env_values_are_one_line(self):
        self.assertTrue(self.broken(lambda sc: sc["services"][0]["env"].update(X="a\nB=c")))
        self.assertTrue(self.broken(lambda sc: sc["app"]["env"].update(X=1)))

    def test_requests_images_and_names(self):
        self.assertTrue(self.broken(lambda sc: sc["steps"][0].update(request="FETCH /login")))
        self.assertTrue(self.broken(lambda sc: sc["steps"][0].update(request="GET login")))
        self.assertTrue(self.broken(lambda sc: sc["services"][0].update(image="postgres; rm -rf /")))
        self.assertTrue(self.broken(lambda sc: sc["services"][0].update(name="app")))
        self.assertTrue(self.broken(lambda sc: sc["steps"][1].update(repeat=1000)))
        self.assertTrue(self.broken(lambda sc: sc.update(schema="other")))
        self.assertEqual(l3_runner.validate([]), ["the scenario must be a JSON object"])

    def test_no_string_can_forge_a_log_line_or_an_env_entry(self):
        command = "x\n::set-output name=xml::/etc/passwd"
        self.assertTrue(self.broken(lambda sc: sc["steps"][0].update(name=command)))
        self.assertTrue(self.broken(lambda sc: sc["steps"][0].update(request="GET /a\n::warning::x")))
        self.assertTrue(self.broken(lambda sc: sc["steps"][0].update(request="GET /a\tb")))
        self.assertTrue(self.broken(lambda sc: sc.update(version=command)))
        self.assertTrue(self.broken(lambda sc: sc["app"]["ready"].update(path="/h\n::set-output name=run::/x")))
        self.assertTrue(self.broken(lambda sc: sc["app"]["env"].update({"FOO\n": "x"})))      # "$" also matches before \n
        self.assertTrue(self.broken(lambda sc: sc["steps"][1]["headers"].update({"X\r\nY": "1"})))
        self.assertTrue(self.broken(lambda sc: sc["steps"][1]["headers"].update(Authorization="a\nb")))
        self.assertEqual(l3_runner.safe("a\n::error::x ##[set-output name=a;]b"), "a : :error: :x ## [set-output name=a;]b")

    def test_types_are_strict(self):
        self.assertTrue(self.broken(lambda sc: sc["app"].update(port=True)))
        self.assertTrue(self.broken(lambda sc: sc["app"].update(port=l3_runner.AGENT_PORT)))
        self.assertTrue(self.broken(lambda sc: sc["app"]["ready"].update(status=True)))
        self.assertTrue(self.broken(lambda sc: sc["services"][0].update(name=["db"])))
        self.assertTrue(self.broken(lambda sc: sc["steps"][1].update(repeat=True)))

    def test_env_lines(self):
        app = l3_runner.env_lines(SCENARIO)
        self.assertIn("SPRING_PROFILES_ACTIVE=local", app)
        secret = [line for line in app if line.startswith("JWT_SECRET=")][0]
        self.assertGreater(len(secret), 50)
        self.assertNotEqual(secret, [line for line in l3_runner.env_lines(SCENARIO) if line.startswith("JWT_SECRET=")][0])
        self.assertEqual(l3_runner.env_lines(SCENARIO, "db"), ["POSTGRES_PASSWORD=l3"])
        with self.assertRaises(l3_runner.ScenarioError):
            l3_runner.env_lines(SCENARIO, "cache")


class RunTest(unittest.TestCase):

    def setUp(self):
        self.app, self.lines = FakeApp(), []
        self.result = l3_runner.run(SCENARIO, "http://127.0.0.1:1", log=self.lines.append, sender=self.app)
        self.steps = {s["name"]: s for s in self.result["steps"]}

    def test_saved_values_are_substituted(self):
        create = [r for r in self.app.requests if r[1] == "/items"]
        self.assertEqual(len(create), 3)
        self.assertEqual(create[2][2]["Authorization"], "Bearer t/1 2")
        self.assertEqual(create[2][2]["Content-Type"], "application/json")
        # "${id}" alone keeps the number; ${i} counts from 1
        self.assertEqual(create[2][3], {"title": "item 3", "owner": 7})

    def test_values_in_the_path_are_url_encoded(self):
        self.assertIn(("GET", "/items?q=t%2F1%202"), [(r[0], r[1]) for r in self.app.requests])

    def test_missing_values_skip_and_failures_do_not_stop(self):
        self.assertEqual(self.steps["needs a missing value"]["skipped"], 1)
        self.assertEqual(self.steps["denied"]["failed"], 1)          # 500, expected 403
        self.assertEqual(self.result["requests"], {"count": 7, "ok": 5, "failed": 1, "skipped": 1})

    def test_logs_never_show_values_or_bodies(self):
        text = "\n".join(self.lines)
        for secret in ("t/1 2", "t%2F1", "secret stack trace", "item 3", '"user"'):
            self.assertNotIn(secret, text)
        self.assertIn("GET /items?q=${token} -> 200 x1", text)
        self.assertIn("missing ${nothing}", text)

    def test_a_request_that_cannot_be_sent_does_not_stop_the_run(self):
        def sender(base_url, method, path, headers, body, timeout=30):
            if path == "/login":
                return 200, json.dumps({"data": {"token": "SAVED-TOKEN\nX: 1"}, "items": [{"id": {"a": 1}}]}).encode()
            if path == "/admin":
                raise RuntimeError("boom SAVED-TOKEN")
            return 200, b"{}"
        lines = []
        result = l3_runner.run(SCENARIO, "http://127.0.0.1:1", log=lines.append, sender=sender)
        steps = {s["name"]: s for s in result["steps"]}
        self.assertEqual(steps["create"]["skipped"], 3)            # the saved value cannot be a header
        self.assertEqual(steps["denied"]["statuses"], {"error": 1})
        self.assertEqual(steps["search"]["ok"], 1)                  # later steps still run
        self.assertNotIn("SAVED-TOKEN", "\n".join(lines))

    def test_pick(self):
        data = {"a": [{"b": 1}], "c": None}
        self.assertEqual(l3_runner.pick(data, "a.0.b"), 1)
        self.assertIsNone(l3_runner.pick(data, "a.1.b"))
        self.assertIsNone(l3_runner.pick(data, "x"))
        self.assertEqual(l3_runner.pick([5], "0"), 5)


class Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        Handler.seen.append((self.path, self.headers.get("Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/elsewhere")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")


class SendTest(unittest.TestCase):
    """send() against a real socket"""

    def setUp(self):
        Handler.seen = []
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def test_redirects_are_not_followed(self):
        status, _ = l3_runner.send(self.base, "GET", "/redirect", {"Authorization": "Bearer t"}, None)
        self.assertEqual(status, 302)
        self.assertEqual([path for path, _ in Handler.seen], ["/redirect"])     # the token went nowhere else

    def test_paths_are_encoded_and_errors_are_a_status(self):
        self.assertEqual(l3_runner.send(self.base, "GET", "/s?q=\uac00\ubc29&x=a%2Fb", {}, None)[0], 200)
        self.assertEqual(Handler.seen[-1][0], "/s?q=%EA%B0%80%EB%B0%A9&x=a%2Fb")
        self.assertEqual(l3_runner.send(self.base, "GET", "/a", {"X": "bad\nvalue"}, None), (None, b""))
        self.assertEqual(l3_runner.send("http://127.0.0.1:1", "GET", "/a", {}, None), (None, b""))


class SegmentTest(unittest.TestCase):
    """the execution data comes from the agent of an untrusted app, cut into one file per segment"""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_the_run_is_cut_at_the_start_and_after_every_step(self):
        cuts = []
        result = l3_runner.run(SCENARIO, "http://127.0.0.1:1", log=lambda m: None, sender=FakeApp(), cut=cuts.append)
        self.assertEqual(cuts, ["startup", "001", "002", "003", "004", "005"])      # a repeated step is one segment
        self.assertEqual([s["segment"] for s in result["steps"]], cuts[1:])

    def test_setting_names_without_values(self):
        sc = copy.deepcopy(SCENARIO)
        sc["app"]["env"].update(KAKAO_STUB="true", MAIL_ENABLED="false", DB_PASSWORD="hunter2")
        keys = {k["name"]: k["enabled"] for k in l3_runner.run(sc, "http://x", log=lambda m: None, sender=FakeApp())["configKeys"]}
        self.assertEqual(keys, {"SPRING_PROFILES_ACTIVE": True, "KAKAO_STUB": True, "MAIL_ENABLED": False,
                                "DB_PASSWORD": True, "JWT_SECRET": True})
        self.assertNotIn("hunter2", json.dumps(l3_runner.config_keys(sc)))

    def fake_java(self, script):
        path = os.path.join(self.dir.name, "java")
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n" + script)
        os.chmod(path, 0o755)
        return path

    def test_the_dump_is_checked(self):
        out = os.path.join(self.dir.name, "segments")
        # the arguments: -jar cli dump --address H --port P --destfile FILE --reset ...
        good = self.fake_java('printf "\\001\\300\\300\\020\\007data" > "$9"\n')
        l3_runner.dumper("cli.jar", "127.0.0.1:6300", out, java=good)("startup")
        with open(os.path.join(out, "startup.exec"), "rb") as f:
            self.assertEqual(f.read(), b"\x01\xc0\xc0\x10\x07data")
        for script in ('echo not-jacoco > "$9"\n', "exit 1\n", "exit 0\n"):
            with self.assertRaises(l3_runner.ScenarioError):
                l3_runner.dumper("cli.jar", "127.0.0.1:6300", out, java=self.fake_java(script))("001")
        with self.assertRaises(l3_runner.ScenarioError):
            l3_runner.dumper("cli.jar", "127.0.0.1:6300", out, java=os.path.join(self.dir.name, "missing"))("002")

    def test_a_segment_must_be_a_regular_jacoco_file(self):
        target = os.path.join(self.dir.name, "config.json")
        with open(target, "wb") as f:
            f.write(b"\x01\xc0\xc0 right start, but reached through a link")
        link = os.path.join(self.dir.name, "seg.exec")
        os.symlink(target, link)
        with self.assertRaises(l3_runner.ScenarioError):
            l3_runner.check_segment(link)
        self.assertEqual(l3_runner.check_segment(target), 43)


def jar_bytes(entries, manifest=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if manifest:
            z.writestr("META-INF/MANIFEST.MF", manifest)
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class ClassesTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        crypto = jar_bytes({"org/bc/Key.class": b"base", "org/bc/Key$Inner.class": b"inner",
                            "META-INF/versions/9/org/bc/Key.class": b"v9",
                            "META-INF/versions/25/org/bc/Key.class": b"v25",
                            "META-INF/versions/9/module-info.class": b"m"},
                           manifest="Manifest-Version: 1.0\r\nMulti-Release: true\r\n")
        first = jar_bytes({"com/fasterxml/Dup.class": b"first", "module-info.class": b"m"})
        second = jar_bytes({"com/fasterxml/Dup.class": b"second", "javax/annotation/X.class": b"x"})
        self.jar = os.path.join(self.dir.name, "app.jar")
        with zipfile.ZipFile(self.jar, "w") as z:
            z.writestr("BOOT-INF/classes/com/app/Main.class", b"app")
            z.writestr("BOOT-INF/lib/a-second.jar", second)
            z.writestr("BOOT-INF/lib/b-first.jar", first)
            z.writestr("BOOT-INF/lib/crypto.jar", crypto)
            z.writestr("BOOT-INF/classpath.idx", '- "BOOT-INF/lib/b-first.jar"\n- "BOOT-INF/lib/a-second.jar"\n'
                                                 '- "BOOT-INF/lib/crypto.jar"\n')
            z.writestr("org/springframework/boot/loader/Launcher.class", b"loader")

    def read(self, out, rel):
        with open(os.path.join(out, rel), "rb") as f:
            return f.read()

    def test_class_path_order_and_multi_release(self):
        out = os.path.join(self.dir.name, "c")
        roots, written, duplicates = l3_runner.write_classes(self.jar, out, release=21)
        self.assertEqual(self.read(out, "com/fasterxml/Dup.class"), b"first")      # classpath.idx order wins
        self.assertEqual(duplicates, 1)
        self.assertEqual(self.read(out, "org/bc/Key.class"), b"v9")               # newest version <= 21
        self.assertFalse(os.path.exists(os.path.join(out, "module-info.class")))
        self.assertFalse(os.path.exists(os.path.join(out, "org/springframework")))  # the loader is not the app
        self.assertEqual(written, 5)
        self.assertEqual(l3_runner.scope_of(roots), "java.util.*:com.*:org.*")    # javax needs the JDK's loader
        # the scope alone: nothing is written
        self.assertEqual(l3_runner.write_classes(self.jar, None)[:2], (roots, 0))

    def test_the_classes_on_the_l2_call_paths(self):
        reach = {"cves": [{"cve": "CVE-1", "sinks": [
            {"sink": "org.bc.Key#m", "path": [{"method": "com.app.Main.handle(Ljava/lang/String;)V"},
                                              {"note": "... 2 steps omitted ..."},
                                              {"method": "com.fasterxml.Dup$Inner.run()V"}]},
            {"sink": "org.bc.Key#other", "reachable": False}]}]}
        self.assertEqual(l3_runner.reach_sources(reach), {"com/app/Main", "com/fasterxml/Dup"})
        out = os.path.join(self.dir.name, "r")
        self.assertEqual(l3_runner.write_classes(self.jar, out, only=l3_runner.reach_sources(reach))[1], 2)

    def test_only_the_source_files_the_data_names(self):
        out = os.path.join(self.dir.name, "s")
        spec = {"cves": [{"sinks": [{"class": "org.bc.Key$Inner", "method": "m"}], "l3": {"regions": []}}]}
        _, written, _ = l3_runner.write_classes(self.jar, out, only=l3_runner.spec_sources(spec))
        self.assertEqual(sorted(os.listdir(os.path.join(out, "org/bc"))), ["Key$Inner.class", "Key.class"])
        self.assertEqual(written, 2)

    def test_entry_names_cannot_leave_the_folder_or_the_agent_options(self):
        jar = os.path.join(self.dir.name, "evil.jar")
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("BOOT-INF/classes/org/bc/Key$/../../../../../escaped/Evil.class", b"x")
            z.writestr("BOOT-INF/classes/a -Dfoo=bar b/C.class", b"x")
            z.writestr("BOOT-INF/classes/ok/Fine.class", b"x")
        out = os.path.join(self.dir.name, "deep", "out")
        roots, written, _ = l3_runner.write_classes(jar, out, only={"org/bc/Key", "ok/Fine", "a -Dfoo=bar b/C"})
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "escaped")))
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "deep", "escaped")))
        self.assertEqual(l3_runner.scope_of(roots), "java.util.*:ok.*")
        self.assertEqual(written, 2)

    def test_no_class_of_the_data_still_gives_a_folder(self):
        out = os.path.join(self.dir.name, "none")
        self.assertEqual(l3_runner.write_classes(self.jar, out, only=set())[1], 0)
        self.assertTrue(os.path.isdir(out))          # jacococli needs the folder; the report is then empty

    def test_cli(self):
        path = os.path.join(self.dir.name, "sc.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(SCENARIO, f)
        self.assertEqual(l3_runner.main(["validate", path]), 0)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"schema": "x"}, f)
        self.assertEqual(l3_runner.main(["validate", path]), 1)
        self.assertEqual(l3_runner.main(["classes", "--jar", path, "--out", os.path.join(self.dir.name, "x")]), 1)
        self.assertEqual(l3_runner.main(["scope", "--jar", self.jar]), 0)
        self.assertEqual(l3_runner.main(["run", path, "--base-url", "http://127.0.0.1:1", "--out", path + ".out"]), 1)


if __name__ == "__main__":
    unittest.main()
