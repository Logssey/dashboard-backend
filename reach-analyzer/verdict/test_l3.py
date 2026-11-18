"""Tests for l3.py.  python3 -m unittest discover -s reach-analyzer/verdict"""
import io
import json
import os
import tempfile
import unittest

import l3

HEAD = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="l3">
  <package name="org/example/lib">"""
TAIL = """  </package>
</report>
"""


def report(check=(6, 3, 3, 0), unused=0, inner=5, decode=9, handle=0):
    """One segment. check: covered instructions of the method and of lines 10, 11, 12."""
    return f"""{HEAD}
    <class name="org/example/lib/Parser" sourcefilename="Parser.java">
      <method name="check" desc="(Ljava/lang/String;)Z" line="10">
        <counter type="INSTRUCTION" missed="4" covered="{check[0]}"/>
      </method>
      <method name="unused" desc="()V" line="30">
        <counter type="INSTRUCTION" missed="3" covered="{unused}"/>
      </method>
    </class>
    <class name="org/example/lib/Parser$Inner" sourcefilename="Parser.java">
      <method name="loop" desc="()V" line="40">
        <counter type="INSTRUCTION" missed="0" covered="{inner}"/>
      </method>
    </class>
    <class name="org/example/lib/NoLines">
      <method name="decode" desc="([B)V">
        <counter type="INSTRUCTION" missed="0" covered="{decode}"/>
      </method>
    </class>
    <class name="org/example/lib/Handler" sourcefilename="Handler.java">
      <method name="handle" desc="()V" line="5">
        <counter type="INSTRUCTION" missed="0" covered="{handle}"/>
      </method>
    </class>
    <sourcefile name="Parser.java">
      <line nr="10" mi="0" ci="{check[1]}" mb="0" cb="0"/>
      <line nr="11" mi="0" ci="{check[2]}" mb="0" cb="0"/>
      <line nr="12" mi="4" ci="{check[3]}" mb="0" cb="0"/>
      <line nr="30" mi="3" ci="{unused}" mb="0" cb="0"/>
      <line nr="41" mi="0" ci="{inner}" mb="0" cb="0"/>
    </sourcefile>
    <sourcefile name="Handler.java">
      <line nr="5" mi="0" ci="{handle}" mb="0" cb="0"/>
    </sourcefile>
{TAIL}"""


IDLE = dict(check=(0, 0, 0, 0), unused=0, inner=0, decode=0, handle=0)


def cve(cve_id, coords, regions=None, version="1.0", sinks=None, note=None):
    entry = {"cve": cve_id, "package": {"coordinates": coords, "installed": version},
             "sinks": sinks if sinks is not None else [{"class": "org.example.lib.Parser", "method": "check"}]}
    if regions is not None:
        entry["l3"] = {"version": version, "regions": regions}
        if note:
            entry["l3"]["note"] = note
    return entry


def region(cls="org.example.lib.Parser", method="check", lines=None, source="org/example/lib/Parser.java", desc=None):
    r = {"class": cls, "method": method, "desc": desc, "source": source}
    if lines is not None:
        r["lines"] = lines
    return r


def sbom(*components):
    return {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": c.split(":")[1].split("@")[0], "version": c.split("@")[1],
         "purl": "pkg:maven/" + c.split(":")[0] + "/" + c.split(":")[1]} for c in components]}


def one(text=None):
    return l3.Run([("all", l3.Coverage.parse(io.StringIO(text or report())))])


def run(cves, components=("org.example:lib@1.0",), scope=None, segments=None, reach=None):
    spec = {"schema": "reach-spec/v0", "cves": cves}
    return {c["cve"]: c for c in l3.match(spec, sbom(*components), segments or one(), scope, reach)["cves"]}


class MatchTest(unittest.TestCase):

    def test_a_region_line_that_ran_reaches_the_region(self):
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 12]])])])["CVE-1"]
        self.assertEqual(r["reached"], "REGION")
        self.assertEqual(r["regions"][0]["executedLines"], [11])
        self.assertTrue(r["regionsChecked"])

    def test_the_function_ran_but_not_the_region(self):
        # like Tomcat findSecurityConstraints: every request runs the method, not the vulnerable comparison
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[12, 12]])])])["CVE-1"]
        self.assertEqual(r["reached"], "FUNCTION")
        self.assertTrue(r["regionsChecked"])                       # looked at, and it did not run
        self.assertEqual([f["function"] for f in r["functions"]], ["org.example.lib.Parser#check"])

    def test_inner_class_lines_are_in_the_outer_source_file(self):
        r = run([cve("CVE-1", "org.example:lib", [region(cls="org.example.lib.Parser$Inner", method="loop", lines=[[41, 41]])])])
        self.assertEqual(r["CVE-1"]["reached"], "REGION")

    def test_whole_method_region_for_jars_without_line_numbers(self):
        hit = run([cve("CVE-1", "org.example:lib", [region(cls="org.example.lib.NoLines", method="decode", source="org/example/lib/NoLines.java")])])
        miss = run([cve("CVE-2", "org.example:lib", [region(method="unused")], sinks=[])])
        self.assertEqual(hit["CVE-1"]["reached"], "REGION")
        self.assertTrue(hit["CVE-1"]["regions"][0]["wholeMethod"])
        self.assertEqual(miss["CVE-2"]["reached"], "NONE")

    def test_another_library_version_only_reaches_the_function(self):
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])], components=("org.example:lib@1.1",))["CVE-1"]
        self.assertEqual(r["reached"], "FUNCTION")
        self.assertFalse(r["regionsChecked"])
        self.assertEqual(r["installedVersions"], ["1.1"])
        # the line numbers belong to 1.0: no lines are reported for 1.1
        self.assertEqual(r["regions"][0], {"class": "org.example.lib.Parser", "method": "check", "lines": [[11, 11]],
                                           "executedLines": [], "executed": False, "during": [], "unchecked": "OTHER_VERSION"})

    def test_two_versions_in_the_app_do_not_check_lines(self):
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])],
                components=("org.example:lib@1.0", "org.example:lib@1.1"))["CVE-1"]
        self.assertEqual(r["reached"], "FUNCTION")

    def test_no_region_data_falls_back_to_the_functions(self):
        ran = run([cve("CVE-1", "org.example:lib", [], note="data-only fix")])["CVE-1"]
        none = run([cve("CVE-2", "org.example:lib", None, sinks=[{"class": "org.example.lib.Parser", "method": "unused"}])])["CVE-2"]
        self.assertEqual(ran["reached"], "FUNCTION")
        self.assertFalse(ran["regionsChecked"])
        self.assertEqual(ran["note"], "data-only fix")
        self.assertEqual(none["reached"], "NONE")

    def test_classes_outside_the_recording_scope(self):
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])], scope="com.other.*:tools.jackson.*")["CVE-1"]
        self.assertEqual(r["reached"], "NOT_RECORDED")
        self.assertEqual(run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])],
                             scope="org.example.lib.Pars?r")["CVE-1"]["reached"], "REGION")

    def test_the_descriptor_picks_the_overload(self):
        r = region(cls="org.example.lib.NoLines", method="decode", source="org/example/lib/NoLines.java")
        sink = [{"class": "org.example.lib.NoLines", "method": "decode", "desc": "([B)V"}]
        hit = run([cve("CVE-1", "org.example:lib", [dict(r, desc="([B)V")], sinks=sink)])["CVE-1"]
        self.assertEqual(hit["reached"], "REGION")
        # an overload the report does not have: nothing to judge by, and no other method stands in for it
        other = [{"class": "org.example.lib.NoLines", "method": "decode", "desc": "(Ljava/lang/String;)V"}]
        miss = run([cve("CVE-2", "org.example:lib", [dict(r, desc="(Ljava/lang/String;)V")], sinks=other)])["CVE-2"]
        self.assertEqual(miss["reached"], "NOT_RECORDED")
        self.assertEqual(miss["regions"][0]["unchecked"], "NO_METHOD")
        self.assertFalse(miss["regionsChecked"])

    def test_a_class_that_is_not_in_the_report_is_not_judged(self):
        # no class file was given for it (a JDK class, or a jar that is not the one that ran)
        gone = [{"class": "java.util.Base64$Decoder", "method": "decode"}]
        r = run([cve("CVE-1", "org.example:lib", [region(cls="java.util.Base64$Decoder", method="decode", lines=[[5, 9]],
                                                         source="java/util/Base64.java")], sinks=gone)],
                scope="java.util.*:org.*")["CVE-1"]
        self.assertEqual(r["reached"], "NOT_RECORDED")
        self.assertEqual(r["regions"][0]["unchecked"], "NO_CLASS_FILE")
        self.assertEqual(r["functionsUnchecked"], ["java.util.Base64$Decoder#decode"])

    def test_lines_of_a_class_without_line_numbers_fall_back_to_the_function(self):
        sink = [{"class": "org.example.lib.NoLines", "method": "decode"}]
        r = run([cve("CVE-1", "org.example:lib", [region(cls="org.example.lib.NoLines", method="decode", lines=[[3, 4]],
                                                         source="org/example/lib/NoLines.java")], sinks=sink)])["CVE-1"]
        self.assertEqual(r["reached"], "FUNCTION")
        self.assertEqual(r["regions"][0]["unchecked"], "NO_LINE_NUMBERS")
        self.assertFalse(r["regionsChecked"])

    def test_one_region_out_of_scope_is_not_a_clean_none(self):
        regions = [region(method="unused", lines=[[30, 30]]),
                   region(cls="org.other.Far", method="run", lines=[[1, 2]], source="org/other/Far.java")]
        r = run([cve("CVE-1", "org.example:lib", regions, sinks=[])], scope="org.example.*")["CVE-1"]
        self.assertEqual(r["reached"], "NOT_RECORDED")
        self.assertEqual([x.get("unchecked") for x in r["regions"]], [None, "OUT_OF_SCOPE"])

    def test_cves_of_packages_not_in_the_sbom_are_left_out(self):
        self.assertEqual(set(run([cve("CVE-1", "org.example:lib", []), cve("CVE-2", "org.other:x", [])])), {"CVE-1"})

    def test_counts_and_nested_sbom_components(self):
        spec = {"schema": "reach-spec/v0", "cves": [cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])]}
        nested = {"components": [{"purl": "pkg:maven/com.app/app@1", "components": [
            {"purl": "pkg:maven/org.example/lib@1.0", "version": "1.0"}]}]}
        out = l3.match(spec, nested, one())
        self.assertEqual(out["counts"], {"REGION": 1, "FUNCTION": 0, "NONE": 0, "NOT_RECORDED": 0})
        self.assertEqual(out["scope"], "*")
        self.assertEqual(out["segments"], ["all"])


class SegmentTest(unittest.TestCase):
    """In which part of the run the code ran"""

    def segments(self, *parts):
        return l3.Run([(i, l3.Coverage.parse(io.StringIO(report(**dict(IDLE, **kw))))) for i, kw in parts])

    def test_the_requests_that_reached_each_level(self):
        run_ = self.segments(("startup", {}), ("001", dict(check=(6, 3, 0, 0))), ("002", {}),
                             ("003", dict(check=(6, 3, 3, 0))))
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])], segments=run_)["CVE-1"]
        self.assertEqual(r["reached"], "REGION")
        self.assertEqual(r["during"], ["003"])                              # the region: only the third step
        self.assertEqual(r["functions"][0]["during"], ["001", "003"])       # the function: also the first
        self.assertFalse(r["startupOnly"])

    def test_code_that_ran_only_while_the_app_started(self):
        run_ = self.segments(("startup", dict(check=(6, 3, 3, 0))), ("001", {}))
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])], segments=run_)["CVE-1"]
        self.assertEqual((r["reached"], r["during"], r["startupOnly"]), ("REGION", ["startup"], True))

    def test_executed_lines_are_the_union(self):
        run_ = self.segments(("startup", {}), ("001", dict(check=(3, 3, 0, 0))), ("002", dict(check=(3, 0, 3, 0))))
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[10, 12]])])], segments=run_)["CVE-1"]
        self.assertEqual(r["regions"][0]["executedLines"], [10, 11])
        self.assertEqual(r["regions"][0]["during"], ["001", "002"])

    def test_how_far_along_an_l2_path_the_run_got(self):
        def steps(*methods):
            return [{"method": m} if "(" in m else {"note": m} for m in methods]
        reach = {"cves": [{"cve": "CVE-1", "sinks": [
            {"sink": "org.example.lib.Parser#check", "reachable": True, "path": steps(
                "org.example.lib.Handler.handle()V",
                "java.util.ArrayList.forEach(Ljava/util/function/Consumer;)V",       # no class file: unknown, no gap
                "... 2 steps omitted ...",
                "org.example.lib.Parser$Inner.loop()V",
                "org.example.lib.Parser.check(Ljava/lang/String;)Z")},
            # the entry did not run; a later step did, reached some other way: that is not progress on this path
            {"sink": "org.example.lib.NoLines#decode", "reachable": True, "path": steps(
                "org.example.lib.Parser.unused()V", "org.example.lib.Parser$Inner.loop()V",
                "org.example.lib.NoLines.decode([B)V")},
            {"sink": "org.example.lib.Parser#unused", "reachable": False}]}]}
        run_ = self.segments(("startup", {}), ("001", dict(handle=4, inner=5)))
        r = run([cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])], segments=run_, reach=reach)["CVE-1"]
        self.assertEqual(r["reached"], "NONE")
        first, second = r["paths"]
        self.assertEqual([s["executed"] for s in first["steps"]], [True, None, True, False])
        self.assertEqual((first["reachedStep"], first["of"], first["target"]), (3, 4, "org.example.lib.Parser#check"))
        self.assertEqual(second, {"target": "org.example.lib.NoLines#decode", "reachedStep": 0, "of": 3})
        self.assertNotIn("paths", run([cve("CVE-1", "org.example:lib", [])], segments=run_)["CVE-1"])

    def test_segments_are_read_from_a_folder_startup_first(self):
        with tempfile.TemporaryDirectory() as d:
            for name, kw in (("002", {}), ("startup", {}), ("001", dict(check=(6, 3, 3, 0)))):
                write(os.path.join(d, name + ".xml"), report(**dict(IDLE, **kw)))
            write(os.path.join(d, "notes.txt"), "ignored")
            loaded = l3.Run.load(d)
        self.assertEqual(loaded.ids(), ["startup", "001", "002"])
        self.assertEqual(loaded.method_during("org.example.lib.Parser", "check"), ["001"])


def write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data if isinstance(data, str) else json.dumps(data))


class CliTest(unittest.TestCase):

    def test_writes_the_result(self):
        with tempfile.TemporaryDirectory() as d:
            paths = {n: os.path.join(d, n) for n in ("spec.json", "report.xml", "sbom.json", "out.json", "seg")}
            write(paths["spec.json"], {"schema": "reach-spec/v0", "cves": [cve("CVE-1", "org.example:lib", [region(lines=[[11, 11]])])]})
            write(paths["report.xml"], report())
            write(paths["sbom.json"], sbom("org.example:lib@1.0"))
            self.assertEqual(l3.main(["--spec", paths["spec.json"], "--jacoco", paths["report.xml"],
                                      "--sbom", paths["sbom.json"], "--out", paths["out.json"]]), 0)
            with open(paths["out.json"], encoding="utf-8") as f:
                self.assertEqual(json.load(f)["cves"][0]["reached"], "REGION")
            os.mkdir(paths["seg"])
            write(os.path.join(paths["seg"], "startup.xml"), report(**IDLE))
            write(os.path.join(paths["seg"], "001.xml"), report())
            self.assertEqual(l3.main(["--spec", paths["spec.json"], "--segments", paths["seg"],
                                      "--sbom", paths["sbom.json"], "--out", paths["out.json"]]), 0)
            with open(paths["out.json"], encoding="utf-8") as f:
                self.assertEqual(json.load(f)["cves"][0]["during"], ["001"])

    def test_not_a_jacoco_report_and_an_empty_folder(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "x.xml")
            write(bad, "<html/>")
            spec = os.path.join(d, "s.json")
            write(spec, {"cves": []})
            self.assertEqual(l3.main(["--spec", spec, "--jacoco", bad, "--sbom", spec, "--out", os.path.join(d, "o")]), 1)
            os.mkdir(os.path.join(d, "empty"))
            self.assertEqual(l3.main(["--spec", spec, "--segments", os.path.join(d, "empty"), "--sbom", spec,
                                      "--out", os.path.join(d, "o")]), 1)


class DataTest(unittest.TestCase):
    """The L3 regions in the real vuln-functions.json are well formed."""

    def test_regions_of_the_shipped_data(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "src", "main", "resources", "reach", "vuln-functions.json")
        with open(path, encoding="utf-8") as f:
            spec = json.load(f)
        for c in spec["cves"]:
            data = c.get("l3")
            self.assertIsNotNone(data, c["cve"])
            self.assertEqual(data["version"], c["package"]["installed"], c["cve"])
            if not data["regions"]:
                self.assertTrue(data.get("note"), f"{c['cve']}: no region needs a note")
            for r in data["regions"]:
                self.assertEqual(r["source"], r["class"].split("$")[0].replace(".", "/") + ".java", c["cve"])
                self.assertTrue(r["desc"].startswith("("), c["cve"])
                for lo, hi in r.get("lines", []):
                    self.assertLessEqual(lo, hi, c["cve"])


if __name__ == "__main__":
    unittest.main()
