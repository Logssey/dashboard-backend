#!/usr/bin/env bash
# Builds the fixtures, runs the analyzer + verdict.py, and compares with expected.json.
#   ./gradlew :reach-analyzer:fixtureTest     (sets REACH_JAR, FIXTURE_LIBS, FIXTURE_BUILD)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
REACH_JAR="${REACH_JAR:-$HERE/../build/libs/reach-analyzer.jar}"
RULES="$HERE/../../src/main/resources/reach/rules.json"
VERDICT="$HERE/../verdict/verdict.py"
B="${FIXTURE_BUILD:-$HERE/../build/fixtures}"
[ -f "$REACH_JAR" ] || { echo "analyzer jar not found: $REACH_JAR (run ./gradlew :reach-analyzer:jar)"; exit 1; }
mkdir -p "$B"
FIXTURE_BUILD="$B" bash ./build-fixtures.sh > "$B/build-fixtures.log" 2>&1 || { cat "$B/build-fixtures.log"; exit 1; }
python3 make_fixture_spec.py >/dev/null
fail=0
for app in app-like app-positive app-tokens app-indirect app-blindspots; do
  java -jar "$REACH_JAR" --app "$B/$app.jar" --spec spec-fixture.json --rules "$RULES" \
       --out "$B/$app.reach.json" 2> "$B/$app.reach.log"
  python3 "$VERDICT" --reach "$B/$app.reach.json" --spec spec-fixture.json --rules "$RULES" \
       --repo "fixture-src/$app" --out "$B/$app.verdicts.json" --md "$B/$app.verdicts.md" > /dev/null 2>&1
  python3 - "$app" "$B" <<'PY' || fail=1
import json, sys
app, build = sys.argv[1], sys.argv[2]
exp = json.load(open("expected.json"))[app]
got = {v["cve"]: v["status"] for v in json.load(open(f"{build}/{app}.verdicts.json"))["verdicts"]}
bad = [(c, e, got.get(c)) for c, e in exp.items() if got.get(c) != e]
for c, e, g in bad:
    print(f"  FAIL {app} {c}: expected {e}, got {g}")
print(f"{app}: {len(exp) - len(bad)}/{len(exp)} as expected")
sys.exit(1 if bad else 0)
PY
done
exit $fail
