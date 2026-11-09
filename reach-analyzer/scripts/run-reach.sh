#!/usr/bin/env bash
# 서비스 레포에 판정 도구를 돌린다: bootJar 빌드 → 분석기(호출 그래프·사실 수집) → verdict.py(판정)
#
#   REPO=<서비스 레포 경로> OUT=<결과 폴더> bash reach-analyzer/scripts/run-reach.sh
#
# 선택: JAR=<이미 빌드한 bootJar>, TRIVY_DIR=<Trivy JSON 보고서 폴더>(있으면 스캐너가 찾은 CVE만 판정)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$(cd "$HERE/.." && pwd)"
DATA="$BACKEND/src/main/resources/reach"
ANALYZER="$HERE/build/libs/reach-analyzer.jar"
: "${REPO:?REPO=<서비스 레포 경로>를 지정한다}"
OUT="${OUT:-$PWD/reach-out}"
mkdir -p "$OUT"

if [ ! -f "$ANALYZER" ]; then
  echo "[0/3] 분석기 빌드"
  (cd "$BACKEND" && bash ./gradlew -q :reach-analyzer:jar)
fi

if [ -z "${JAR:-}" ]; then
  echo "[1/3] bootJar 빌드: $REPO"
  (cd "$REPO" && bash ./gradlew bootJar -x test -q)
  JAR=$(ls "$REPO"/build/libs/*.jar | grep -v plain | head -1)
fi
echo "      대상 jar: $JAR"

echo "[2/3] 호출 그래프 분석"
java -Xmx3g -jar "$ANALYZER" --app "$JAR" \
  --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" \
  --out "$OUT/reach-result.json"

echo "[3/3] 판정 (verdict)"
TRIVY_ARGS=()
if [ -n "${TRIVY_DIR:-}" ]; then
  for f in "$TRIVY_DIR"/*.json; do
    [ -f "$f" ] && jq -e '.Results' "$f" >/dev/null 2>&1 && TRIVY_ARGS+=(--trivy "$f")
  done
fi
python3 "$HERE/verdict/verdict.py" --reach "$OUT/reach-result.json" \
  --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" \
  "${TRIVY_ARGS[@]}" --repo "$REPO" \
  --out "$OUT/verdicts.json" --md "$OUT/verdicts.md"

echo
echo "결과: $OUT/verdicts.md (사람이 읽는 보고서), $OUT/verdicts.json, $OUT/reach-result.json"
