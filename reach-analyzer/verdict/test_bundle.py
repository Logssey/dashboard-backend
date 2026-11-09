"""Tests for bundle.py.  python3 -m unittest discover -s reach-analyzer/verdict"""
import gzip
import json
import os
import tempfile
import unittest

import bundle

SINK_A = "org.example.lib.Codec#decode([B)V"
SINK_B = "org.example.lib.Codec#encode([B)V"


def spec():
    return {"schema": "reach-spec/v0", "cves": [
        {"cve": "CVE-2026-1000", "package": {"coordinates": "org.example:lib"}, "summary_ko": "디코더 문제",
         "sinks": [{"class": "org.example.lib.Codec", "method": "decode"}, {"class": "org.example.lib.Codec", "method": "encode"}]},
        {"cve": "CVE-2026-2000", "package": {"coordinates": "org.example:other"}, "summary_ko": "설정 문제",
         "sinks": [{"class": "org.example.other.Conf", "method": "load"}]},
    ]}


def rules():
    return {"schema": "reach-rules/v0", "verdicts": {
        "CVE-2026-1000": {"method": "callgraph"},
        "CVE-2026-2000": {"method": "rule"},
    }}


def reach():
    path = [{"method": "com.app.Api.handle()V", "short": "Api.handle", "via": "entry:app-method"},
            {"method": "org.example.lib.Codec.decode([B)V", "short": "Codec.decode", "via": "virtual"}]
    return {"tool": "reach 0.1.0", "facts": {"app.uses": [{"where": "com.app.Api#handle:12", "detail": "new Codec"}]},
            "dto_roots": [{}, {}], "dto_type_tokens": [{}, {}, {}],
            "index": {"app_classes": 3, "library_jars": {"lib.jar": 10}}, "analysis": {"reachable_methods": 42},
            "cves": [
                {"cve": "CVE-2026-1000", "sink_reachable": True, "sink_reachable_strong": True,
                 "package": {"reachable": True, "reachable_strong": True},
                 "sinks": [{"sink": SINK_A, "present_in_jar": True, "reachable": True, "weak_path_only": False, "path": path},
                           {"sink": SINK_B, "present_in_jar": True, "reachable": False}]},
                {"cve": "CVE-2026-2000", "sink_reachable": False, "sink_reachable_strong": False,
                 "package": {"reachable": False},
                 "sinks": [{"sink": "org.example.other.Conf#load()V", "present_in_jar": True, "reachable": False}]},
            ]}


def verdicts():
    return {"verdicts": [
        {"cve": "CVE-2026-1000", "status": "reachable", "method": "callgraph", "package": "org.example:lib",
         "why_ko": "앱 코드가 디코더를 부른다",
         "decided_by": {"clause": "reachable_if", "conditions": [["sink"]], "evidence": [{"fact": "sink", "result": "도달"}]},
         "checked_absent": [], "info": [], "callgraph": {"sink_reachable": True, "package_reachable": True}},
        {"cve": "CVE-2026-2000", "status": "unreachable", "method": "rule", "package": "org.example:other",
         "why_ko": "설정을 쓰지 않는다",
         "decided_by": {"clause": "otherwise", "conditions": [], "evidence": []},
         "checked_absent": ["dto.floating.tokens", "repo.conf", "sink"], "info": [],
         "callgraph": {"sink_reachable": False, "package_reachable": False}},
        {"cve": "CVE-2026-9999", "status": "not_analyzed", "package": "org.example:lib"},
    ]}


def trivy_vuln(cve, purl, severity="HIGH", path="app.jar/BOOT-INF/lib/x.jar", fixed="1.2.0, 2.0.1"):
    return {"VulnerabilityID": cve, "PkgName": "x", "InstalledVersion": purl.rsplit("@", 1)[-1], "PkgPath": path,
            "PkgIdentifier": {"PURL": purl}, "Severity": severity, "Title": f"{cve} title", "Description": "desc",
            "FixedVersion": fixed, "CweIDs": ["CWE-400"], "References": ["https://example.com/a"]}


def trivy(*vulns):
    return {"Trivy": {"Version": "0.75.0"}, "Results": [{"Target": "Java", "Vulnerabilities": list(vulns)}]}


LIB = "pkg:maven/org.example/lib@1.0.0"
OTHER = "pkg:maven/org.example/other@3.0.0"
COPY = "pkg:maven/com.legacy/lib@0.9"


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def file(self, name, data):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def run_bundle(self, trivy_data, grype_data=None, extra=(), verdict_data=None):
        args = ["--sbom", self.file("sbom.json", {"bomFormat": "CycloneDX", "components": []}),
                "--trivy", self.file("trivy.json", trivy_data),
                "--reach", self.file("reach.json", reach()),
                "--verdicts", self.file("verdicts.json", verdict_data or verdicts()),
                "--spec", self.file("spec.json", spec()), "--rules", self.file("rules.json", rules()),
                "--analyzed-at", "2026-11-09T00:00:00Z", "--out", os.path.join(self.dir.name, "out.json"), *extra]
        if grype_data is not None:
            args += ["--grype", self.file("grype.json", grype_data)]
        self.assertEqual(bundle.main(args), 0)
        with open(os.path.join(self.dir.name, "out.json"), encoding="utf-8") as f:
            return json.load(f)

    def item(self, b, cve, purl):
        return next(i for i in b["verdicts"] if i["vulnerability"]["id"] == cve and i["component"]["purl"] == purl)

    def test_not_analyzed_reasons(self):
        b = self.run_bundle(trivy(
            trivy_vuln("CVE-2026-1000", LIB), trivy_vuln("CVE-2026-1000", COPY), trivy_vuln("CVE-2026-3000", LIB),
            trivy_vuln("CVE-2026-4000", "pkg:apk/alpine/zlib@1.3.2-r0"), trivy_vuln("CVE-2026-5000", "pkg:npm/left-pad@1.0.0")))
        reasons = {(i["vulnerability"]["id"], i["component"]["purl"]): i["verdict"].get("notAnalyzedReason") for i in b["verdicts"]}
        self.assertEqual(reasons, {
            ("CVE-2026-1000", LIB): None,
            ("CVE-2026-1000", COPY): "UNANALYZED_COPY",
            ("CVE-2026-3000", LIB): "NO_VULN_FUNCTION_DATA",
            ("CVE-2026-4000", "pkg:apk/alpine/zlib@1.3.2-r0"): "OS_PACKAGE",
            ("CVE-2026-5000", "pkg:npm/left-pad@1.0.0"): "UNSUPPORTED_ECOSYSTEM",
        })
        for i in b["verdicts"]:
            v = i["verdict"]
            if v["status"] == "NOT_ANALYZED":
                self.assertNotIn("method", v)
                self.assertTrue(v["summary"])
                self.assertNotIn("affectedFeature", i["vulnerability"])

    def test_component_and_vulnerability_fields(self):
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-1000", LIB)))
        i = self.item(b, "CVE-2026-1000", LIB)
        self.assertEqual(i["component"], {"purl": LIB, "name": "lib", "version": "1.0.0", "ecosystem": "maven",
                                          "path": "app.jar/BOOT-INF/lib/x.jar"})
        self.assertEqual(i["vulnerability"]["fixedVersions"], ["1.2.0", "2.0.1"])
        self.assertEqual(i["vulnerability"]["affectedFeature"], "디코더 문제")
        self.assertEqual(i["sources"], ["TRIVY"])

    def test_same_package_in_two_paths_is_one_finding(self):
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-1000", LIB, path="a.jar"), trivy_vuln("CVE-2026-1000", LIB, path="b.jar")))
        self.assertEqual(len(b["verdicts"]), 1)
        self.assertEqual(b["verdicts"][0]["component"]["path"], "a.jar")

    def test_grype_ghsa_merges_with_trivy_cve(self):
        grype = {"descriptor": {"version": "0.121.2"}, "matches": [{
            "vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "severity": "Medium", "fix": {"versions": ["1.2.0"]},
                              "cwes": [{"cwe": "CWE-20"}], "urls": ["https://example.com/b"]},
            "relatedVulnerabilities": [{"id": "CVE-2026-1000"}],
            "artifact": {"purl": LIB, "version": "1.0.0"}}]}
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-1000", LIB)), grype)
        self.assertEqual(len(b["verdicts"]), 1)
        i = b["verdicts"][0]
        self.assertEqual(i["sources"], ["TRIVY", "GRYPE"])
        self.assertEqual(i["vulnerability"]["severity"], "HIGH")
        self.assertEqual(i["vulnerability"]["severityNote"], "Trivy HIGH, Grype MEDIUM")
        self.assertEqual(i["vulnerability"]["cwe"], ["CWE-400", "CWE-20"])
        self.assertEqual(b["tools"]["grype"], "0.121.2")

    def test_callgraph_verdict(self):
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-1000", LIB)))
        v = self.item(b, "CVE-2026-1000", LIB)["verdict"]
        self.assertEqual((v["status"], v["method"], v["ruleId"]), ("REACHABLE", "CALLGRAPH", "RULE-CVE-2026-1000"))
        self.assertEqual(v["vulnFunctionIds"], [1, 2])
        self.assertEqual(v["callgraph"], {"packageReached": True, "vulnFunctionPresent": True, "vulnFunctionReached": True,
                                          "weakOnly": False, "entryStage": 2})
        self.assertEqual(v["engine"], {"reach": "reach 0.1.0", "rulesVersion": "v0", "vulnFunctionsVersion": "v0"})
        kinds = [e["kind"] for e in v["evidence"]]
        self.assertEqual(kinds, ["RULE", "PATH"])
        path = v["evidence"][1]
        self.assertEqual((path["path"], path["pathTarget"], path["entryStage"], path["vulnFunction"]),
                         (["Api.handle", "Codec.decode"], "VULN_FUNCTION", 2, SINK_A))
        self.assertEqual(v["evidence"][0]["matchedCondition"], "REACHABLE")

    def test_unreachable_by_default_still_has_evidence(self):
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-2000", OTHER)))
        v = self.item(b, "CVE-2026-2000", OTHER)["verdict"]
        self.assertEqual((v["status"], v["method"]), ("UNREACHABLE", "RULE"))
        facts = [e for e in v["evidence"] if e["kind"] == "FACT"]
        self.assertEqual([(e["factId"], e["value"]) for e in facts],
                         [("F-dto.floating.tokens", False), ("F-repo.conf", False)])
        self.assertEqual(facts[0]["checkedCount"], 3)
        note = next(e for e in v["evidence"] if e["kind"] == "NOTE" and "checkedAbsent" in e)
        self.assertEqual(note["checkedAbsent"], ["org.example.other.Conf#load()V"])
        rule = next(e for e in v["evidence"] if e["kind"] == "RULE")
        self.assertEqual(rule["matchedCondition"], "DEFAULT")
        self.assertEqual(v["evidence"][-1]["kind"], "RULE")   # facts and notes first, no path here

    def test_inconsistent_inputs_fail(self):
        data = verdicts()
        data["verdicts"] = data["verdicts"][1:]   # CVE-2026-1000 on its own package missing from verdicts.json
        args = ["--sbom", self.file("s.json", {}), "--trivy", self.file("t.json", trivy(trivy_vuln("CVE-2026-1000", LIB))),
                "--reach", self.file("r.json", reach()), "--verdicts", self.file("v.json", data),
                "--spec", self.file("sp.json", spec()), "--rules", self.file("ru.json", rules()),
                "--out", os.path.join(self.dir.name, "x.json")]
        self.assertEqual(bundle.main(args), 1)
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "x.json")))

    def test_bundle_fields_and_stages(self):
        b = self.run_bundle(trivy(trivy_vuln("CVE-2026-1000", LIB)),
                            extra=["--stage", "sbom=succeeded:9", "--stage", "l2=succeeded", "--tool", "cdxgen=11.10.0"])
        self.assertEqual(set(b), {"sbom", "matches", "reachResult", "tools", "analysis", "stages", "verdicts"})
        self.assertEqual(b["stages"], [{"name": "SBOM", "status": "SUCCEEDED", "durationSeconds": 9},
                                       {"name": "L2", "status": "SUCCEEDED"}])
        self.assertEqual(b["tools"]["cdxgen"], "11.10.0")
        self.assertEqual(b["analysis"], {"appClasses": 3, "libraryJars": 1, "reachedMethods": 42})
        self.assertEqual(b["matches"]["trivy"]["Trivy"]["Version"], "0.75.0")

    def test_failure_bundle_is_gzip(self):
        out = os.path.join(self.dir.name, "fail.json.gz")
        code = bundle.main(["--failure-code", "E-L2-FAILED", "--failure-stage", "l2", "--failure-message", "out of memory",
                            "--stage", "sbom=succeeded", "--stage", "l2=failed", "--tool", "reach=reach 0.1.0", "--out", out])
        self.assertEqual(code, 0)
        with gzip.open(out, "rt", encoding="utf-8") as f:
            b = json.load(f)
        self.assertEqual(b["failure"], {"code": "E-L2-FAILED", "stage": "L2", "message": "out of memory"})
        self.assertNotIn("verdicts", b)

    def test_bad_stage_is_rejected(self):
        out = os.path.join(self.dir.name, "y.json")
        self.assertEqual(bundle.main(["--failure-code", "E", "--stage", "deploy=succeeded", "--out", out]), 1)

    def no_l2_args(self, trivy_data, out):
        return ["--sbom", self.file("s.json", {"bomFormat": "CycloneDX"}), "--trivy", self.file("t.json", trivy_data),
                "--spec", self.file("sp.json", spec()), "--rules", self.file("ru.json", rules()), "--out", out]

    def test_target_without_java_needs_no_l2_input(self):
        out = os.path.join(self.dir.name, "npm.json")
        code = bundle.main(self.no_l2_args(trivy(trivy_vuln("CVE-2026-5000", "pkg:npm/left-pad@1.0.0"),
                                                 trivy_vuln("CVE-2026-4000", "pkg:apk/alpine/zlib@1.3.2-r0")), out))
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as f:
            b = json.load(f)
        self.assertEqual([i["verdict"]["notAnalyzedReason"] for i in b["verdicts"]], ["OS_PACKAGE", "UNSUPPORTED_ECOSYSTEM"])
        self.assertEqual(b["reachResult"], {})
        self.assertEqual([s["name"] for s in b["stages"]], ["SBOM", "MATCH", "REPORT"])
        self.assertNotIn("reach", b["verdicts"][0]["verdict"]["engine"])

    def test_maven_match_without_l2_input_fails(self):
        out = os.path.join(self.dir.name, "m.json")
        self.assertEqual(bundle.main(self.no_l2_args(trivy(trivy_vuln("CVE-2026-1000", LIB)), out)), 1)
        self.assertFalse(os.path.exists(out))

    def test_reach_without_verdicts_fails(self):
        out = os.path.join(self.dir.name, "r.json")
        args = self.no_l2_args(trivy(), out) + ["--reach", self.file("reach.json", reach())]
        self.assertEqual(bundle.main(args), 1)

if __name__ == "__main__":
    unittest.main()
