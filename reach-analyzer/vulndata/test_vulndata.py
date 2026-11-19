"""Unit tests of vulndata.py. No network: the advisory, Maven Central and MethodDiff are replaced.

    python3 -B -m unittest discover -s . -v          (./gradlew :reach-analyzer:vulndataTest)

MethodDiff itself is tested against two small jars compiled here, when REACH_JAR (reach-analyzer.jar) and
javac are available.
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock

import vulndata as V

CLS = "org.example.codec.Decoder"
DESC = "(Ljava/lang/String;)I"
COMMIT = "https://github.com/example/lib/commit/0123456789abcdef0123456789abcdef01234567"

BEFORE = """package org.example.codec;

public class Decoder {
    public int decode(String text) {
        int n = text.length();
        return parse(text, n);
    }

    int parse(String text, int n) {
        return n;
    }
}
""".splitlines()

AFTER = """package org.example.codec;

public class Decoder {
    public int decode(String text) {
        int n = text.length();
        if (n > 100) throw new IllegalArgumentException();
        return parse(text, n);
    }

    int parse(String text, int n) {
        return n;
    }
}
""".splitlines()

PATCH = """From 0123456789abcdef Mon Sep 17 00:00:00 2001
Subject: [PATCH] limit the input

diff --git a/core/src/main/java/org/example/codec/Decoder.java b/core/src/main/java/org/example/codec/Decoder.java
--- a/core/src/main/java/org/example/codec/Decoder.java
+++ b/core/src/main/java/org/example/codec/Decoder.java
@@ -5,2 +5,3 @@
         int n = text.length();
+        if (n > 100) throw new IllegalArgumentException();
         return parse(text, n);
diff --git a/core/src/test/java/org/example/codec/DecoderTest.java b/core/src/test/java/org/example/codec/DecoderTest.java
--- a/core/src/test/java/org/example/codec/DecoderTest.java
+++ b/core/src/test/java/org/example/codec/DecoderTest.java
@@ -1 +1,2 @@
+// test
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
+note
"""


def advisory(**over):
    data = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2099-12345", "severity": "high",
        "summary": "Decoder reads input of any length", "description": "A long input is not rejected.",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
        "references": [COMMIT, "https://example.org/notes", COMMIT],
        "vulnerabilities": [
            {"package": {"ecosystem": "maven", "name": "org.example:lib"},
             "vulnerable_version_range": ">= 1.0, < 1.2", "first_patched_version": "1.2"},
            {"package": {"ecosystem": "maven", "name": "org.example:lib"},
             "vulnerable_version_range": ">= 2.0, < 2.0.3", "first_patched_version": "2.1"},
        ],
    }
    data.update(over)
    return data


def quiet(function, *args, **kwargs):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        result = function(*args, **kwargs)
    return result, err.getvalue()


class Versions(unittest.TestCase):

    def test_order(self):
        ordered = ["1.0-RC1", "1.0", "1.0.1", "1.2", "1.10", "1.81", "1.81.1", "1.84", "11.0.24", "11.0.25"]
        for i, a in enumerate(ordered):
            for j, b in enumerate(ordered):
                self.assertEqual(V.compare_versions(a, b), (i > j) - (i < j), (a, b))

    def test_trailing_zero_is_the_same_release(self):
        self.assertEqual(V.compare_versions("1.0", "1.0.0"), 0)

    def test_range(self):
        self.assertTrue(V.in_range("11.0.24", ">= 11.0.20, < 11.0.25"))
        self.assertFalse(V.in_range("11.0.25", ">= 11.0.20, < 11.0.25"))
        self.assertTrue(V.in_range("10.1.57", ">= 10.1.53, <= 10.1.57"))
        self.assertTrue(V.in_range("1.81", ">= 1.81, < 1.81.1"))
        self.assertTrue(V.in_range("3.0", "= 3.0"))

    def test_unreadable_range_stops(self):
        with self.assertRaises(V.Stop):
            V.in_range("1.0", "~> 1.0")


class Advisory(unittest.TestCase):

    def test_picks_the_branch_of_the_installed_version(self):
        with mock.patch.object(V, "url_exists", return_value=False):
            got = V.choose_package(advisory(), None, "1.1")
        self.assertEqual(got, ("org.example:lib", ["1.2", "2.1"], "1.2"))

    def test_end_of_the_range_is_compared_when_it_was_released(self):
        # '< 2.0.3' but first patched 2.1: 2.0.3 is the closest fixed release
        with mock.patch.object(V, "url_exists", return_value=True) as exists:
            (coordinates, fixed, target), _ = quiet(V.choose_package, advisory(), "org.example:lib", "2.0.1")
        self.assertEqual((fixed, target), (["2.0.3", "1.2", "2.1"], "2.0.3"))
        self.assertIn("/org/example/lib/2.0.3/lib-2.0.3.jar", exists.call_args[0][0])
        with mock.patch.object(V, "url_exists", return_value=False):
            self.assertEqual(V.choose_package(advisory(), "org.example:lib", "2.0.1")[2], "2.1")

    def test_installed_version_outside_the_ranges_stops(self):
        with self.assertRaisesRegex(V.Stop, "not in a vulnerable range"):
            V.choose_package(advisory(), None, "1.5")

    def test_fixed_override(self):
        self.assertEqual(V.choose_package(advisory(), None, "1.5", "1.6"), ("org.example:lib", ["1.6", "1.2", "2.1"], "1.6"))

    def test_several_packages_need_coordinates(self):
        rows = advisory()["vulnerabilities"] + [{"package": {"ecosystem": "maven", "name": "org.example:other"},
                                                 "vulnerable_version_range": "< 9", "first_patched_version": "9"}]
        with self.assertRaisesRegex(V.Stop, "org.example:lib, org.example:other"):
            V.choose_package(advisory(vulnerabilities=rows), None, "1.1")
        with self.assertRaisesRegex(V.Stop, "is not in the advisory"):
            V.choose_package(advisory(), "org.example:missing", "1.1")

    def test_other_ecosystems_are_not_supported(self):
        rows = [{"package": {"ecosystem": "npm", "name": "lib"}, "vulnerable_version_range": "< 2",
                 "first_patched_version": "2"}]
        with self.assertRaisesRegex(V.Stop, "no Maven package"):
            V.choose_package(advisory(vulnerabilities=rows), None, "1.0")

    def test_fix_commits_are_the_github_commit_references_once(self):
        got = V.fix_commits(advisory(references=[COMMIT, COMMIT, "https://github.com/example/lib/pull/7",
                                                 "https://evil.example/x/y/commit/0123456", None]))
        self.assertEqual(got, [{"repository": "example/lib", "sha": COMMIT.rsplit("/", 1)[1], "url": COMMIT}])

    def test_cvss_vector(self):
        self.assertTrue(V.cvss_vector(advisory()).startswith("CVSS:3.1/"))
        self.assertEqual(V.cvss_vector(advisory(cvss=None, cvss_severities={"cvss_v3": {"vector_string": "V3"}})), "V3")
        self.assertIsNone(V.cvss_vector(advisory(cvss=None)))


class Patch(unittest.TestCase):

    def test_java_files_without_tests(self):
        self.assertEqual(V.java_files_of_patch(PATCH), ["core/src/main/java/org/example/codec/Decoder.java"])
        hunks = V.java_hunks(PATCH)
        self.assertIn("if (n > 100)", hunks)
        self.assertNotIn("DecoderTest", hunks)
        self.assertNotIn("README", hunks)

    def test_class_of_path(self):
        for path, cls in (("core/src/main/java/org/example/codec/Decoder.java", CLS),
                          ("java/org/apache/coyote/http2/Stream.java", "org.apache.coyote.http2.Stream"),
                          ("src/main/java/tools/jackson/core/io/NumberInput.java", "tools.jackson.core.io.NumberInput")):
            self.assertEqual(V.class_of_path(path), cls)

    def test_match(self):
        touched = {CLS}
        self.assertEqual(V.match_of(CLS + "$Inner", touched), "class")
        self.assertEqual(V.match_of("shaded.codec.Decoder", touched), "name")
        self.assertEqual(V.match_of("org.example.codec.Other", touched), "package")
        self.assertEqual(V.match_of("org.example.io.Reader", touched), "-")
        self.assertEqual(V.match_of(CLS, set()), "-")


class Lines(unittest.TestCase):

    def test_ranges(self):
        numbers = {548, 550, 551, 552, 553, 600}
        self.assertEqual(V.format_lines(numbers), "548,550-553,600")
        self.assertEqual(V.parse_lines("548,550-553,600"), numbers)
        self.assertEqual(V.ranges_of(numbers), [[548, 548], [550, 553], [600, 600]])
        self.assertEqual(V.parse_lines("-"), set())
        self.assertEqual(V.format_lines(set()), "-")

    def test_changed_lines(self):
        self.assertEqual(V.changed_source_lines(["a", "b", "c"], ["a", "B", "c"]), {2})          # replaced
        self.assertEqual(V.changed_source_lines(["a", "b", "c"], ["a", "c"]), {2})               # deleted
        self.assertEqual(V.changed_source_lines(["a", "b", "c"], ["a", "x", "b", "c"]), {1, 2})  # inserted between
        self.assertEqual(V.changed_source_lines(["a"], ["x", "a"]), {1})                         # inserted on top
        self.assertEqual(V.changed_source_lines(BEFORE, AFTER), {5, 6})


class Bundle(unittest.TestCase):
    """prepare with the network and MethodDiff replaced, then check and apply on that bundle."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bundle = self.tmp / "bundle"
        self.rules = self.tmp / "rules.json"
        self.rules.write_text(json.dumps({"verdicts": {}}))
        self.spec = self.tmp / "vuln-functions.json"
        V.write_json(self.spec, {"schema": "reach-spec/v0", "cves": [{"cve": "CVE-2000-0001", "sinks": []}]})
        self.prepare()

    def fetch(self, url, path):
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if url.endswith(".patch"):
            path.write_text(PATCH)
        elif url.endswith("-sources.jar"):
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("org/example/codec/Decoder.java", "\n".join(AFTER if "1.2" in url else BEFORE))
        else:
            path.write_bytes(b"jar of " + url.encode())
        return True

    @staticmethod
    def method_diff(_jar, *args):
        if args[0] == "--list":
            return [[CLS, "<init>", "()V", "3"], [CLS, "decode", DESC, "5-6"],
                    [CLS, "parse", "(Ljava/lang/String;I)I", "10"], ["org.example.io.Reader", "read", "()I", "-"]]
        return [["CHANGED", CLS, "decode", DESC, "5-6"], ["ADDED", CLS, "limit", "()I", "20"],
                ["REMOVED", "org.example.codec.Old", "run", "()V", "7"], ["CHANGED", "org.example.io.Reader", "read", "()I", "-"]]

    def prepare(self, **over):
        argv = ["prepare", "--cve", "CVE-2099-12345", "--installed", "1.1", "--out", str(self.bundle)]
        with mock.patch.object(V, "load_advisory", return_value=advisory(**over)), \
                mock.patch.object(V, "fetch", side_effect=self.fetch), \
                mock.patch.object(V, "url_exists", return_value=False), \
                mock.patch.object(V, "run_method_diff", side_effect=self.method_diff):
            return quiet(V.main, argv)

    def draft(self, **entry_over):
        draft = V.read_json(self.bundle / "draft.template.json")
        draft["entry"].update(
            invocation_kind="app_calls_library", summary_ko="입력 길이를 확인하지 않는다.", summary_en="No length limit.",
            sinks=[{"class": CLS, "method": "decode", "desc": DESC, "confidence": "high"}])
        draft["entry"]["l3"] = {"version": "1.1", "note": "The unchecked parse call.", "regions": [
            {"class": CLS, "method": "decode", "desc": DESC, "source": "org/example/codec/Decoder.java", "lines": [[6, 6]]}]}
        draft["entry"].update(entry_over)
        draft["review"]["trigger_conditions"] = ["100자를 넘는 입력을 decode에 넘긴다"]
        return draft

    def findings(self, draft, rules=None):
        V.write_json(self.bundle / "draft.json", draft)
        return V.check_draft(V.load_bundle(self.bundle), rules)

    # prepare

    def test_prepare_writes_the_bundle(self):
        meta = V.read_json(self.bundle / "meta.json")
        self.assertEqual(meta["package"], {"coordinates": "org.example:lib", "artifact": "lib", "installed": "1.1",
                                           "fixed": ["1.2", "2.1"]})
        self.assertEqual((meta["cve"], meta["comparedWith"], meta["severity"]), ("CVE-2099-12345", "1.2", "HIGH"))
        self.assertEqual(meta["counts"], {"methodsInstalled": 4, "changed": 3, "candidates": 2, "candidatesDropped": 0})
        self.assertEqual(meta["fixCommits"][0]["files"], ["core/src/main/java/org/example/codec/Decoder.java"])
        self.assertEqual(len(meta["jars"]["installed"]["sha256"]), 64)
        rows = V.read_tsv(self.bundle / "candidates.tsv")
        # the changed method of the class the commit touches first, with the lines the fix touched; ADDED is not listed
        self.assertEqual([(r["status"], r["class"], r["method"], r["match"], r["lines"], r["fix_lines"]) for r in rows],
                         [("CHANGED", CLS, "decode", "class", "5-6", "5-6"),
                          ("REMOVED", "org.example.codec.Old", "run", "package", "7", "-")])
        self.assertEqual(V.read_json(self.bundle / "changed-lines.json"), {"org/example/codec/Decoder.java": [[5, 6]]})
        self.assertIn("int parse", (self.bundle / "source/installed/org/example/codec/Decoder.java").read_text())
        self.assertIn("n > 100", (self.bundle / "source/fixed/org/example/codec/Decoder.java").read_text())
        self.assertIn("if (n > 100)", (self.bundle / "fix-commits.diff").read_text())
        self.assertTrue((self.bundle / "PROMPT.md").read_text().startswith("# Drafting"))
        template = V.read_json(self.bundle / "draft.template.json")
        self.assertEqual(template["entry"]["sources"], [advisory()["html_url"], COMMIT])
        self.assertEqual(list(template["entry"]), list(V.ENTRY_KEYS))

    def test_without_a_fix_commit_every_changed_method_is_a_candidate(self):
        _, err = self.prepare(references=["https://example.org/notes"])
        self.assertIn("links no fix commit", err)
        self.assertEqual([r["match"] for r in V.read_tsv(self.bundle / "candidates.tsv")], ["-", "-", "-"])

    def test_names_from_the_advisory_are_checked_before_use(self):
        rows = [{"package": {"ecosystem": "maven", "name": "org.example:lib"}, "vulnerable_version_range": "< 1.2",
                 "first_patched_version": "1.2/../../x"}]
        shutil.rmtree(self.bundle)
        code, err = self.prepare(vulnerabilities=rows)
        self.assertEqual(code, 1)
        self.assertIn("cannot use", err)
        self.assertEqual(list((self.bundle / "cache").iterdir()), [])     # nothing was downloaded

    def test_bad_arguments_stop_before_the_network(self):
        with mock.patch.object(V, "load_advisory", side_effect=AssertionError("called")):
            for argv in (["prepare", "--installed", "1.1", "--out", str(self.bundle)],
                         ["prepare", "--cve", "CVE-1", "--installed", "1.1", "--out", str(self.bundle)],
                         ["prepare", "--cve", "CVE-2099-12345", "--installed", "../1", "--out", str(self.bundle)],
                         ["prepare", "--cve", "CVE-2099-12345", "--coordinates", "a/b:c", "--installed", "1.1",
                          "--out", str(self.bundle)]):
                code, err = quiet(V.main, argv)
                self.assertEqual(code, 1, argv)
                self.assertIn("ERROR", err)

    # check

    def test_a_correct_draft_has_no_findings(self):
        f = self.findings(self.draft())
        self.assertEqual((f.errors, f.warnings), ([], []))

    def test_methods_that_do_not_exist_are_errors(self):
        draft = self.draft(sinks=[
            {"class": CLS, "method": "decode", "desc": "(Ljava/lang/Object;)I", "confidence": "high"},
            {"class": CLS, "method": "decodeAll", "desc": "()V", "confidence": "high"},
            {"class": "org.example.codec.Missing", "method": "run", "desc": "()V", "confidence": "high"},
            {"class": CLS, "method": "", "desc": "()V", "confidence": "high"}])
        errors = "\n".join(self.findings(draft).errors)
        self.assertIn(f"sinks[0]: {CLS}.decode(Ljava/lang/Object;)I is not in the installed jar "
                      f"(descriptors of that name: {DESC})", errors)
        self.assertIn("sinks[1]", errors)
        self.assertIn("(no method of that name)", errors)
        self.assertIn("sinks[2]: class org.example.codec.Missing is not in lib 1.1", errors)
        self.assertIn("sinks[3] needs class, method and desc", errors)

    def test_fields_from_the_advisory_must_stay(self):
        draft = self.draft(severity="LOW", cve="CVE-2099-99999")
        draft["entry"]["package"] = dict(draft["entry"]["package"], installed="1.0")
        errors = "\n".join(self.findings(draft).errors)
        for part in ("entry.severity must stay 'HIGH'", "entry.cve must stay", "entry.package must stay"):
            self.assertIn(part, errors)

    def test_entry_fields(self):
        draft = self.draft(invocation_kind="direct", summary_ko="No Korean here", sources=[], extra=1)
        draft["entry"]["sinks"][0]["confidence"] = "sure"
        draft["entry"]["sinks"][0]["rank"] = 1
        errors = "\n".join(self.findings(draft).errors)
        for part in ("invocation_kind must be one of", "summary_ko must be Korean", "entry.sources must be a list",
                     "entry.extra is not a field", "sinks[0].confidence", "sinks[0].rank is not a sink field"):
            self.assertIn(part, errors)
        self.assertIn("at least one method", "\n".join(self.findings(self.draft(sinks=[])).errors))

    def test_a_sink_the_fix_did_not_change_is_for_the_reviewer(self):
        draft = self.draft(sinks=[{"class": CLS, "method": "parse", "desc": "(Ljava/lang/String;I)I", "confidence": "medium"}])
        f = self.findings(draft)
        self.assertEqual(f.errors, [])
        self.assertEqual(len([w for w in f.warnings if "바뀌지 않은 메서드" in w]), 1)
        self.assertEqual(len([w for w in f.warnings if "하나도 없다" in w]), 1)

    def region(self, **over):
        region = {"class": CLS, "method": "decode", "desc": DESC, "source": "org/example/codec/Decoder.java", "lines": [[6, 6]]}
        region.update(over)
        return self.draft(l3={"version": "1.1", "regions": [region], "note": "n"})

    def test_region_lines(self):
        self.assertIn("no code on lines 8-9", "\n".join(self.findings(self.region(lines=[[8, 9]])).errors))
        self.assertIn("lines must be", "\n".join(self.findings(self.region(lines=[[6, 5]])).errors))
        self.assertIn("lines must be", "\n".join(self.findings(self.region(lines=[[True, 6]])).errors))
        self.assertIn("source must be org/example/codec/Decoder.java",
                      "\n".join(self.findings(self.region(source="Decoder.java")).errors))
        f = self.findings(self.region(lines=[[4, 4], [6, 7]]))      # 4: the declaration; 7: the closing brace
        self.assertEqual(f.errors, [])
        self.assertEqual(len(f.warnings), 1)
        self.assertIn("4줄 범위에는 실행되는 코드가 없다", f.warnings[0])

    def test_region_without_lines(self):
        whole = self.region()
        del whole["entry"]["l3"]["regions"][0]["lines"]
        f = self.findings(whole)
        self.assertEqual(f.errors, [])
        self.assertIn("메서드 전체", f.warnings[0])
        no_numbers = self.region(**{"class": "org.example.io.Reader", "method": "read", "desc": "()I",
                                    "source": "org/example/io/Reader.java"})
        self.assertIn("no line numbers", "\n".join(self.findings(no_numbers).errors))
        del no_numbers["entry"]["l3"]["regions"][0]["lines"]
        self.assertEqual(self.findings(no_numbers).errors, [])

    def test_region_away_from_the_fix_is_for_the_reviewer(self):
        f = self.findings(self.region(method="parse", desc="(Ljava/lang/String;I)I", lines=[[10, 10]]))
        self.assertEqual(f.errors, [])
        self.assertTrue(any("바뀐 줄과 겹치지 않는다" in w for w in f.warnings))

    def test_l3_shape(self):
        self.assertIn("l3.version must be the installed version 1.1",
                      "\n".join(self.findings(self.draft(l3={"version": "1.2", "regions": [], "note": "n"})).errors))
        self.assertIn("l3.note must say why",
                      "\n".join(self.findings(self.draft(l3={"version": "1.1", "regions": []})).errors))
        self.assertEqual(self.findings(self.draft(l3={"version": "1.1", "regions": [], "note": "data only"})).errors, [])
        draft = self.draft()
        del draft["entry"]["l3"]
        f = self.findings(draft)
        self.assertEqual(f.errors, [])
        self.assertIn("entry.l3가 없다", f.warnings[0])

    def test_review_is_required(self):
        draft = self.draft()
        draft["review"]["trigger_conditions"] = []
        self.assertIn("trigger_conditions is empty", "\n".join(self.findings(draft).errors))
        draft["review"] = None
        self.assertIn("needs an object 'review'", "\n".join(self.findings(draft).errors))

    def test_a_framework_kind_without_a_rule_is_flagged(self):
        draft = self.draft(invocation_kind="framework_invokes")
        self.assertTrue(any("rules.json" in w for w in self.findings(draft, {"verdicts": {}}).warnings))
        self.assertEqual(self.findings(draft, {"verdicts": {"CVE-2099-12345": {"method": "rule"}}}).warnings, [])

    def test_check_command_writes_the_review_page(self):
        V.write_json(self.bundle / "draft.json", self.draft())
        code, _ = quiet(V.main, ["check", str(self.bundle), "--rules", str(self.rules)])
        self.assertEqual(code, 0)
        page = (self.bundle / "REVIEW.md").read_text()
        self.assertIn("# CVE-2099-12345 판정 데이터 초안 검토", page)
        self.assertIn(f"| `{CLS}.decode` `{DESC}` | 바뀜 | 5-6 | high |", page)
        self.assertIn(">*    6 |         return parse(text, n);", page)     # the region line, changed by the fix
        self.assertIn(" *    5 |         int n = text.length();", page)     # context
        self.assertIn("- 100자를 넘는 입력을 decode에 넘긴다", page)
        V.write_json(self.bundle / "draft.json", self.draft(sinks=[]))
        code, err = quiet(V.main, ["check", str(self.bundle), "--rules", str(self.rules)])
        self.assertEqual(code, 1)
        self.assertIn("- **오류** entry.sinks", (self.bundle / "REVIEW.md").read_text())

    def test_check_needs_a_draft(self):
        code, err = quiet(V.main, ["check", str(self.bundle)])
        self.assertEqual(code, 1)
        self.assertIn("draft.json not found", err)
        (self.bundle / "draft.json").write_text("{not json")
        self.assertIn("not JSON", quiet(V.main, ["check", str(self.bundle)])[1])

    # apply

    def apply(self, *extra):
        return quiet(V.main, ["apply", str(self.bundle), "--spec", str(self.spec), "--rules", str(self.rules),
                              "--records", str(self.tmp / "records"), *extra])

    def test_apply_adds_the_entry_and_records_the_reviewer(self):
        draft = self.draft()
        draft["entry"]["sinks"][0]["note"] = ""
        V.write_json(self.bundle / "draft.json", draft)
        code, _ = self.apply("--reviewed-by", "jinseob")
        self.assertEqual(code, 0)
        spec = V.read_json(self.spec)
        self.assertEqual([c["cve"] for c in spec["cves"]], ["CVE-2000-0001", "CVE-2099-12345"])
        entry = spec["cves"][1]
        self.assertEqual(list(entry), list(V.ENTRY_KEYS))
        self.assertEqual(entry["sinks"], [{"class": CLS, "method": "decode", "desc": DESC, "confidence": "high"}])
        self.assertEqual(entry["l3"]["regions"][0]["lines"], [[6, 6]])
        record = V.read_json(self.tmp / "records" / "CVE-2099-12345.json")
        self.assertEqual((record["reviewedBy"], record["comparedWith"], record["fixCommits"]), ("jinseob", "1.2", [COMMIT]))
        self.assertEqual(record["review"]["trigger_conditions"], ["100자를 넘는 입력을 decode에 넘긴다"])

    def test_apply_does_not_overwrite_without_replace(self):
        V.write_json(self.bundle / "draft.json", self.draft())
        self.assertEqual(self.apply("--reviewed-by", "a")[0], 0)
        code, err = self.apply("--reviewed-by", "a")
        self.assertEqual(code, 1)
        self.assertIn("--replace", err)
        V.write_json(self.bundle / "draft.json", self.draft(summary_en="Changed."))
        self.assertEqual(self.apply("--reviewed-by", "a", "--replace")[0], 0)
        spec = V.read_json(self.spec)
        self.assertEqual(len(spec["cves"]), 2)
        self.assertEqual(spec["cves"][1]["summary_en"], "Changed.")

    def test_apply_refuses_a_draft_that_fails_check(self):
        before = self.spec.read_text()
        V.write_json(self.bundle / "draft.json", self.draft(sinks=[]))
        code, err = self.apply("--reviewed-by", "a")
        self.assertEqual(code, 1)
        self.assertIn("nothing was written", err)
        self.assertEqual(self.spec.read_text(), before)
        V.write_json(self.bundle / "draft.json", self.draft())
        self.assertEqual(self.apply("--reviewed-by", "  ")[0], 1)
        self.assertEqual(self.spec.read_text(), before)


class RealData(unittest.TestCase):

    def test_writing_keeps_the_format_of_the_data_file(self):
        # apply rewrites the whole file: a different format would show every line as changed in the PR
        text = V.SPEC.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            V.write_json(pathlib.Path(tmp) / "out.json", json.loads(text))
            self.assertEqual((pathlib.Path(tmp) / "out.json").read_text(encoding="utf-8"), text)

    def test_the_data_uses_only_known_fields(self):
        spec = V.read_json(V.SPEC)
        for c in spec["cves"]:
            self.assertLessEqual(set(c), set(V.ENTRY_KEYS), c["cve"])
            self.assertIn(c["invocation_kind"], V.KINDS)
            for s in c["sinks"]:
                self.assertLessEqual(set(s), set(V.SINK_KEYS), c["cve"])
            for r in c.get("l3", {}).get("regions", []):
                self.assertLessEqual(set(r), set(V.REGION_KEYS), c["cve"])


JAVA_OLD = """package demo;
public class Calc {
    public int add(int a, int b) {
        return a + b;
    }
    public int twice(int a) {
        return a * 2;
    }
    public int gone() { return 1; }
}
"""
# add: the code changed. twice: only moved down two lines. gone: removed. fresh: added.
JAVA_NEW = """package demo;
public class Calc {
    public int add(int a, int b) {
        if (a < 0) return 0;
        return a + b;
    }

    public int twice(int a) {
        return a * 2;
    }
    public int fresh() { return 2; }
}
"""


@unittest.skipUnless(os.environ.get("REACH_JAR") and shutil.which("javac") and shutil.which("jar"),
                     "needs REACH_JAR (reach-analyzer.jar), javac and jar")
class MethodDiffJar(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.jars = {}
        for name, source in (("old", JAVA_OLD), ("new", JAVA_NEW)):
            src = cls.tmp / name / "demo"
            src.mkdir(parents=True)
            (src / "Calc.java").write_text(source)
            subprocess.run(["javac", "-g", "-d", str(cls.tmp / name / "classes"), str(src / "Calc.java")], check=True)
            cls.jars[name] = cls.tmp / f"{name}.jar"
            subprocess.run(["jar", "cf", str(cls.jars[name]), "-C", str(cls.tmp / name / "classes"), "."], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_changed_removed_added(self):
        rows = V.run_method_diff(os.environ["REACH_JAR"], self.jars["old"], self.jars["new"])
        self.assertEqual(rows, [["CHANGED", "demo.Calc", "add", "(II)I", "4"],
                                ["ADDED", "demo.Calc", "fresh", "()I", "11"],
                                ["REMOVED", "demo.Calc", "gone", "()I", "9"]])

    def test_list(self):
        rows = V.run_method_diff(os.environ["REACH_JAR"], "--list", self.jars["old"])
        self.assertEqual(rows, [["demo.Calc", "<init>", "()V", "2"], ["demo.Calc", "add", "(II)I", "4"],
                                ["demo.Calc", "gone", "()I", "9"], ["demo.Calc", "twice", "(I)I", "7"]])

    def test_missing_analyzer_jar_stops(self):
        with self.assertRaisesRegex(V.Stop, "build it with"):
            V.run_method_diff(self.tmp / "none.jar", "--list", self.jars["old"])


if __name__ == "__main__":
    unittest.main()
