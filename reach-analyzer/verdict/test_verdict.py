"""Tests for verdict.py: config facts from the repo and the app jar, unseen config, the default rule.
python3 -m unittest discover -s reach-analyzer/verdict"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

import bundle

HERE = os.path.dirname(os.path.abspath(__file__))

CONF = "CVE-2026-3000"     # a rule that looks at config (like Tomcat HTTP/2, CVE-2026-65637)
PLAIN = "CVE-2026-4000"    # no rule of its own: the default rule


def spec():
    return {"schema": "reach-spec/v0", "cves": [
        {"cve": CONF, "package": {"coordinates": "org.example:server", "installed": "1", "fixed": ["2"]},
         "summary_ko": "설정에 따라 열리는 문제", "sinks": [{"class": "org.example.server.H2", "method": "open"}]},
        {"cve": PLAIN, "package": {"coordinates": "org.example:lib", "installed": "1", "fixed": ["2"]},
         "summary_ko": "라이브러리 문제", "sinks": [{"class": "org.example.lib.Codec", "method": "decode"}]},
    ]}


def rules():
    return {"schema": "reach-rules/v0",
            "repo_facts": [{"id": "repo.http2", "files": ["*.properties", "*.yml"], "regex": r"server\.http2\.enabled\s*[=:]\s*true"}],
            "verdicts": {CONF: {"method": "rule", "reachable_if": [["repo.http2"]], "otherwise": "unreachable",
                                "why_ko": {"reachable": "HTTP/2를 켰다", "unreachable": "HTTP/2를 켜지 않았다"}}}}


def reach(strong=False, weak=False):
    path = [{"method": "com.app.Api.handle()V", "short": "Api.handle", "via": "entry:spring"}]
    return {"tool": "reach test", "facts": {}, "cves": [
        {"cve": CONF, "sink_reachable": False, "sink_reachable_strong": False, "package": {"reachable": False},
         "sinks": [{"sink": "org.example.server.H2#open()V", "present_in_jar": True, "reachable": False}]},
        {"cve": PLAIN, "sink_reachable": strong or weak, "sink_reachable_strong": strong, "package": {"reachable": True},
         "sinks": [{"sink": "org.example.lib.Codec#decode()V", "present_in_jar": True, "reachable": strong or weak,
                    "weak_path_only": weak and not strong, "path": path}]},
    ]}


class VerdictTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def json(self, name, data):
        with open(self.path(name), "w", encoding="utf-8") as f:
            json.dump(data, f)
        return self.path(name)

    def jar(self, entries):
        with zipfile.ZipFile(self.path("app.jar"), "w") as z:
            for name, text in entries.items():
                z.writestr(name, text)
        return self.path("app.jar")

    def run_verdict(self, repo=None, jar=None, reach_data=None):
        args = [sys.executable, "-B", os.path.join(HERE, "verdict.py"),
                "--reach", self.json("reach.json", reach_data or reach()), "--spec", self.json("spec.json", spec()),
                "--rules", self.json("rules.json", rules()), "--out", self.path("verdicts.json"), "--md", self.path("v.md")]
        if repo:
            args += ["--repo", repo]
        if jar:
            args += ["--jar", jar]
        subprocess.run(args, check=True, capture_output=True)
        with open(self.path("verdicts.json"), encoding="utf-8") as f:
            out = json.load(f)
        return out, {v["cve"]: v for v in out["verdicts"]}

    def test_a_cve_in_the_data_is_judged_when_only_grype_reports_it(self):
        # Trivy reports only PLAIN. Grype finds CONF too (bundle.py merges both): CONF needs a verdict, or the bundle fails
        trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": PLAIN, "PkgName": "lib", "InstalledVersion": "1",
                                                     "PkgIdentifier": {"PURL": "pkg:maven/org.example/lib@1"},
                                                     "Severity": "HIGH"}]}]}
        args = [sys.executable, "-B", os.path.join(HERE, "verdict.py"),
                "--reach", self.json("reach.json", reach()), "--spec", self.json("spec.json", spec()),
                "--rules", self.json("rules.json", rules()), "--trivy", self.json("trivy.json", trivy),
                "--out", self.path("verdicts.json"), "--md", self.path("v.md")]
        subprocess.run(args, check=True, capture_output=True)
        with open(self.path("verdicts.json"), encoding="utf-8") as f:
            cves = {v["cve"] for v in json.load(f)["verdicts"]}
        self.assertEqual(cves, {CONF, PLAIN})

    def test_config_that_was_never_read_is_not_evidence_of_absence(self):
        out, v = self.run_verdict()
        self.assertEqual(out["config_sources"], [])
        self.assertEqual(v[CONF]["status"], "unknown")
        self.assertTrue(v[CONF]["config_unseen"])
        self.assertIn("읽지 못했다", v[CONF]["why_ko"])
        self.assertNotIn("repo.http2", v[CONF]["checked_absent"])
        # a CVE whose rule does not look at config is not touched
        self.assertFalse(v[PLAIN]["config_unseen"])

    def test_the_app_jar_config_counts_when_there_is_no_repo(self):
        jar = self.jar({"BOOT-INF/classes/application.properties": "server.port=8080\nserver.http2.enabled=true\n",
                        "BOOT-INF/classes/com/app/Api.class": "x"})
        out, v = self.run_verdict(jar=jar)
        self.assertEqual(out["config_sources"], ["jar"])
        self.assertEqual(v[CONF]["status"], "reachable")
        where = v[CONF]["decided_by"]["evidence"][0]["occurrences"][0]["where"]
        self.assertEqual(where, "app.jar!/BOOT-INF/classes/application.properties:2")

        # read but absent: now unreachable is backed by what was checked
        jar = self.jar({"BOOT-INF/classes/application.properties": "server.port=8080\n",
                        # a library's own config is not the app's
                        "BOOT-INF/lib/dep/application.properties": "server.http2.enabled=true\n"})
        out, v = self.run_verdict(jar=jar)
        self.assertEqual(v[CONF]["status"], "unreachable")
        self.assertFalse(v[CONF]["config_unseen"])
        self.assertIn("repo.http2", v[CONF]["checked_absent"])

    def test_repo_and_jar_are_both_read_and_links_are_not_followed(self):
        repo = self.path("repo")
        os.makedirs(os.path.join(repo, "src"))
        outside = self.path("outside.yml")
        with open(outside, "w") as f:
            f.write("server.http2.enabled: true\n")
        os.symlink(outside, os.path.join(repo, "src", "application.yml"))
        jar = self.jar({"BOOT-INF/classes/application.properties": "server.port=8080\n"})
        out, v = self.run_verdict(repo=repo, jar=jar)
        self.assertEqual(out["config_sources"], ["repo", "jar"])
        self.assertEqual(v[CONF]["status"], "unreachable")

        with open(os.path.join(repo, "src", "application.properties"), "w") as f:
            f.write("server.http2.enabled=true\n")
        out, v = self.run_verdict(repo=repo, jar=jar)
        self.assertEqual(v[CONF]["status"], "reachable")

    def test_the_default_rule_does_not_rule_out_a_weak_path(self):
        _, v = self.run_verdict(reach_data=reach(weak=True))
        self.assertEqual(v[PLAIN]["status"], "unknown")
        self.assertEqual(v[PLAIN]["decided_by"]["clause"], "unknown_if")
        _, v = self.run_verdict(reach_data=reach(strong=True))
        self.assertEqual(v[PLAIN]["status"], "reachable")
        _, v = self.run_verdict(reach_data=reach())
        self.assertEqual(v[PLAIN]["status"], "unreachable")

    def test_the_bundle_says_why_an_unseen_config_is_unknown(self):
        _, v = self.run_verdict()
        ctx = bundle.Context(reach(), {"verdicts": list(v.values())}, spec(), rules())
        out = bundle.analysed_verdict(v[CONF], ctx, "2026-11-23T00:00:00Z")
        self.assertEqual(out["status"], "UNKNOWN")
        rule = next(e for e in out["evidence"] if e["kind"] == "RULE")
        self.assertEqual(rule["matchedCondition"], "UNKNOWN")
        self.assertTrue(any(e["kind"] == "NOTE" and "설정 파일" in e["summary"] for e in out["evidence"]))


if __name__ == "__main__":
    unittest.main()
