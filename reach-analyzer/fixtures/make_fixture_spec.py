#!/usr/bin/env python3
"""Test spec: same as the backend's reach/vuln-functions.json but Jackson sinks use the 2.x names (fixtures bundle jackson 2.16.1)."""
import json, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
spec = json.loads((root.parent / "src/main/resources/reach/vuln-functions.json").read_text())
research = {c["cve"]: c for c in json.loads((root / "research/jackson.json").read_text())}
for c in spec["cves"]:
    if c["cve"] in research:
        eq = research[c["cve"]].get("jackson2_equivalent") or {}
        c["sinks"] = [{"class": m["class"], "method": m["method"], "desc": m.get("desc"), "confidence": "fixture"} for m in eq.get("methods", [])]
spec["note"] = "TEST ONLY: Jackson sinks replaced by Jackson 2.x equivalents for the fixture jars."
(root / "fixtures/spec-fixture.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n")
print("wrote fixtures/spec-fixture.json")
