#!/usr/bin/env bash
# Reach CI scan for one service build: register a check (API-12), scan and analyse, upload the
# result bundle (API-13), wait for the gate and exit with its exit code.
#
#   MODE=PR REPOSITORY=service-backend COMMIT=<40-char sha> JAR=build/libs/app.jar \
#   REACH_URL=https://<dashboard> bash deploy/reach/ci/reach-scan.sh
#
# MODE=MANUAL scans for a check the dashboard already created (API-01 dispatches the workflow with its id):
# no registration, the same steps and upload.
#
# Steps: SBOM (Trivy) -> match (Trivy, Grype if installed) -> L2 (reach-analyzer + verdict.py)
#        -> bundle.py -> API-13. A failed step after the check is registered uploads a failure bundle,
#        so the scan ends FAILED on the dashboard instead of staying QUEUED.
#
# Required: MODE (PR | IMAGE_BUILD | MANUAL), JAR, REACH_URL. REPOSITORY and COMMIT for PR and IMAGE_BUILD
# MODE=PR: PR_NUMBER (optional BASE_REF, HEAD_REF). Target is the repo at COMMIT; the SBOM comes from JAR.
# MODE=IMAGE_BUILD: IMAGE_REPOSITORY (e.g. logssey/reused-api), IMAGE_DIGEST (sha256:...), IMAGE_REF
#   (what `trivy image` pulls, e.g. <registry>/<repo>@<digest>). JAR is the app jar copied out of that image.
# MODE=MANUAL: CHECK_ID (the dashboard's check), TARGET_TYPE (REPO: SBOM from JAR | IMAGE: SBOM from IMAGE_REF).
# Optional: APP (app code; when empty the dashboard picks it from its logssey.reach.apps), POLICY (REPORT_ONLY | GATE, default REPORT_ONLY), SOURCE (service repo checkout,
#   gives verdict.py the config files), OUT (./reach-out), WAIT_SECONDS (300), REACH_UI_URL (link in the summary),
#   REACH_HOME (dashboard-backend checkout; default: this script's repo), ANALYZER (reach-analyzer.jar path).
# Auth: in GitHub Actions a fresh OIDC token (aud logssey-reach) is fetched for every call
#   (needs `permissions: id-token: write`). Otherwise REACH_TOKEN is sent as a bearer token.
#   REACH_CURL_OPTS adds raw curl arguments (local checks only: session cookie and CSRF header).
# Needs: bash, curl, jq, java 21, python3, trivy. grype is used when installed.
set -Eeuo pipefail

: "${MODE:?MODE=PR, IMAGE_BUILD or MANUAL}"
if [ "$MODE" != MANUAL ]; then
  : "${REPOSITORY:?REPOSITORY=<repository name, e.g. service-backend>}"
  : "${COMMIT:?COMMIT=<40-character commit sha>}"
fi
: "${JAR:?JAR=<bootJar to analyse>}"
: "${REACH_URL:?REACH_URL=<dashboard base URL>}"
APP="${APP:-}"
POLICY="${POLICY:-REPORT_ONLY}"
OUT="${OUT:-$PWD/reach-out}"
WAIT_SECONDS="${WAIT_SECONDS:-300}"
REACH_HOME="${REACH_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
DATA="$REACH_HOME/src/main/resources/reach"
VERDICT="$REACH_HOME/reach-analyzer/verdict"
ANALYZER="${ANALYZER:-$REACH_HOME/reach-analyzer/build/libs/reach-analyzer.jar}"
REACH_URL="${REACH_URL%/}"

# SBOM source: the jar (repo target) or the image
case "$MODE" in
  PR) : "${PR_NUMBER:?PR_NUMBER is required for MODE=PR}"; SBOM_FROM=jar ;;
  IMAGE_BUILD)
    : "${IMAGE_REPOSITORY:?IMAGE_REPOSITORY is required for MODE=IMAGE_BUILD}"
    : "${IMAGE_DIGEST:?IMAGE_DIGEST is required for MODE=IMAGE_BUILD}"
    : "${IMAGE_REF:?IMAGE_REF is required for MODE=IMAGE_BUILD}"
    SBOM_FROM=image ;;
  MANUAL)
    [[ "${CHECK_ID:-}" =~ ^[0-9]+$ ]] || { echo "CHECK_ID must be the dashboard check id: ${CHECK_ID:-}" >&2; exit 2; }
    case "${TARGET_TYPE:-}" in
      REPO) SBOM_FROM=jar ;;
      IMAGE) : "${IMAGE_REF:?IMAGE_REF is required for TARGET_TYPE=IMAGE}"; SBOM_FROM=image ;;
      *) echo "TARGET_TYPE must be REPO or IMAGE: ${TARGET_TYPE:-}" >&2; exit 2 ;;
    esac ;;
  *) echo "MODE must be PR, IMAGE_BUILD or MANUAL: $MODE" >&2; exit 2 ;;
esac
if [ "$MODE" != MANUAL ]; then
  [ "${#COMMIT}" -eq 40 ] || { echo "COMMIT must be the full 40-character sha: $COMMIT" >&2; exit 2; }
fi
[ -f "$JAR" ] || { echo "JAR not found: $JAR" >&2; exit 2; }
[ -f "$ANALYZER" ] || { echo "analyzer jar not found: $ANALYZER (./gradlew :reach-analyzer:jar)" >&2; exit 2; }
mkdir -p "$OUT"

log() { echo "[reach] $*" >&2; }
summary() { if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$*" >> "$GITHUB_STEP_SUMMARY"; else echo "$*"; fi; }

# ---- dashboard API ----

AUTH=()
set_auth() {
  AUTH=()
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    local token
    token=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=logssey-reach" | jq -r .value)
    echo "::add-mask::$token"
    AUTH=(-H "Authorization: Bearer $token")
  elif [ -n "${REACH_TOKEN:-}" ]; then
    AUTH=(-H "Authorization: Bearer $REACH_TOKEN")
  fi
  if [ -n "${REACH_CURL_OPTS:-}" ]; then
    local extra
    read -r -a extra <<< "$REACH_CURL_OPTS"
    AUTH+=("${extra[@]}")
  fi
}

# api METHOD PATH [curl args...] -> sets HTTP (status) and BODY
api() {
  local method=$1 path=$2 response
  shift 2
  set_auth
  response=$(curl -sS -X "$method" "${AUTH[@]}" -w $'\n%{http_code}' "$@" "$REACH_URL$path")
  HTTP=${response##*$'\n'}
  BODY=${response%$'\n'*}
}

# ---- 1. register the check (API-12) ----

if [ "$MODE" = MANUAL ]; then
  log "check $CHECK_ID was created by the dashboard (API-01)"
elif [ "$MODE" = PR ]; then
  KEY="$REPOSITORY-pr-$PR_NUMBER-${COMMIT:0:12}"
  REQUEST=$(jq -n --arg repo "$REPOSITORY" --arg commit "$COMMIT" --arg app "$APP" --arg policy "$POLICY" \
    --argjson number "$PR_NUMBER" --arg base "${BASE_REF:-}" --arg head "${HEAD_REF:-}" '
    {mode: "PR", repository: $repo, headCommit: $commit,
     pullRequest: ({number: $number} + (if $base != "" then {baseRef: $base} else {} end)
                                     + (if $head != "" then {headRef: $head} else {} end)),
     target: ({type: "REPO", repo: {name: $repo, commit: $commit}} + (if $app != "" then {app: $app} else {} end)),
     policy: $policy}')
else
  KEY="$REPOSITORY-image-${IMAGE_DIGEST#sha256:}"
  REQUEST=$(jq -n --arg repo "$REPOSITORY" --arg commit "$COMMIT" --arg app "$APP" --arg policy "$POLICY" \
    --arg image "$IMAGE_REPOSITORY" --arg digest "$IMAGE_DIGEST" '
    {mode: "IMAGE_BUILD", repository: $repo, headCommit: $commit,
     target: ({type: "IMAGE", image: {repository: $image, digest: $digest}} + (if $app != "" then {app: $app} else {} end)),
     policy: $policy}')
fi

if [ "$MODE" != MANUAL ]; then
  KEY="${KEY:0:64}"
  api POST /api/v1/reach/ci/checks -H 'Content-Type: application/json' -H "Idempotency-Key: $KEY" -d "$REQUEST"
  if [ "$HTTP" != 202 ]; then
    log "API-12 register failed: HTTP $HTTP $BODY"
    exit 1
  fi
  CHECK_ID=$(jq -r .id <<< "$BODY")
  log "check $CHECK_ID registered (scan $(jq -r .scanId <<< "$BODY"), key $KEY)"
fi

# the same key (a re-run of the same build) returns the existing check; report it instead of uploading twice.
# MANUAL: a re-run of the dispatched workflow finds the check already finished
api GET "/api/v1/reach/ci/checks/$CHECK_ID"
if [ "$HTTP" != 200 ]; then
  log "API-12 read failed: HTTP $HTTP $BODY"
  exit 1
fi
ALREADY=$(jq -r .scanStatus <<< "$BODY")

# ---- 2. scan and analyse ----

STAGES=()
TOOLS=()
CURRENT=""
UPLOADED=""

upload() {
  api PUT "/api/v1/reach/ci/checks/$CHECK_ID/results" \
    -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary "@$1"
  UPLOADED=1
  if [ "$HTTP" != 202 ] && [ "$HTTP" != 200 ]; then
    log "API-13 upload failed: HTTP $HTTP $BODY"
    return 1
  fi
}

on_error() {
  local rc=$?
  trap - ERR
  if [ -n "${CHECK_ID:-}" ] && [ -z "$UPLOADED" ] && [ -n "$CURRENT" ]; then
    log "step $CURRENT failed (exit $rc); uploading a failure bundle"
    python3 "$VERDICT/bundle.py" --failure-code ANALYSIS_FAILED --failure-stage "$CURRENT" \
      --failure-message "runner step $CURRENT failed (exit $rc), see the workflow log" \
      "${TOOLS[@]}" "${STAGES[@]}" --stage "$CURRENT=failed" --out "$OUT/failure.json.gz" \
      && upload "$OUT/failure.json.gz" || log "failure bundle upload failed too"
  fi
  exit "$rc"
}

stage() {
  local name=$1 started=$SECONDS
  shift
  CURRENT=$name
  "$@"
  STAGES+=(--stage "$name=succeeded:$((SECONDS - started))")
  CURRENT=""
}

sbom() {
  if [ "$SBOM_FROM" = jar ]; then
    # trivy fs reads only lock files (none in a Gradle repo); rootfs reads the jars
    local dir="$OUT/jar"
    mkdir -p "$dir"
    cp "$JAR" "$dir/"
    trivy rootfs --quiet --format cyclonedx -o "$OUT/sbom.cdx.json" "$dir"
  else
    trivy image --quiet --format cyclonedx -o "$OUT/sbom.cdx.json" "$IMAGE_REF"
  fi
}

match() {
  trivy sbom --quiet --format json -o "$OUT/trivy.json" "$OUT/sbom.cdx.json"
  if command -v grype > /dev/null; then
    grype "sbom:$OUT/sbom.cdx.json" -o json --file "$OUT/grype.json" -q
  fi
}

l2() {
  java -Xmx3g -jar "$ANALYZER" --app "$JAR" \
    --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" --out "$OUT/reach-result.json"
  local repo_args=()
  [ -n "${SOURCE:-}" ] && repo_args=(--repo "$SOURCE")
  python3 "$VERDICT/verdict.py" --reach "$OUT/reach-result.json" \
    --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" \
    --trivy "$OUT/trivy.json" "${repo_args[@]}" --out "$OUT/verdicts.json" --md "$OUT/verdicts.md"
}

report() {
  local grype_args=()
  [ -f "$OUT/grype.json" ] && grype_args=(--grype "$OUT/grype.json")
  python3 "$VERDICT/bundle.py" --sbom "$OUT/sbom.cdx.json" --trivy "$OUT/trivy.json" "${grype_args[@]}" \
    --reach "$OUT/reach-result.json" --verdicts "$OUT/verdicts.json" \
    --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" --jar "$JAR" \
    "${TOOLS[@]}" "${STAGES[@]}" --stage "report=succeeded" --out "$OUT/bundle.json.gz"
}

if [ "$ALREADY" = QUEUED ]; then
  trap on_error ERR
  db_updated=$(trivy version --format json 2> /dev/null | jq -r '.VulnerabilityDB.UpdatedAt // empty' || true)
  [ -n "$db_updated" ] && TOOLS+=(--tool "trivyDbUpdatedAt=$db_updated")
  stage sbom sbom
  stage match match
  stage l2 l2
  stage report report
  CURRENT=report
  upload "$OUT/bundle.json.gz"
  trap - ERR
else
  log "check $CHECK_ID is already $ALREADY (re-run of the same build); not uploading again"
fi

# ---- 3. wait for the gate ----

deadline=$((SECONDS + WAIT_SECONDS))
while :; do
  api GET "/api/v1/reach/ci/checks/$CHECK_ID"
  status=$(jq -r .scanStatus <<< "$BODY")
  { [ "$status" = SUCCEEDED ] || [ "$status" = FAILED ]; } && break
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "check $CHECK_ID still $status after ${WAIT_SECONDS}s"
    exit 1
  fi
  sleep 5
done
echo "$BODY" | jq . > "$OUT/check.json"

link="${REACH_UI_URL:+${REACH_UI_URL%/}/vulnerabilities/scans?tab=ci&check=$CHECK_ID}"
summary "### Reach ($MODE, $POLICY)"
if [ "$status" = FAILED ]; then
  summary "Scan failed on the dashboard. Check $CHECK_ID${link:+ ($link)}."
  exit 1
fi
summary "$(jq -r '"Gate **\(.gate.result)** · new findings \(.gate.newFindings.total) (REACHABLE \(.gate.newFindings.byStatus.REACHABLE // 0), UNKNOWN \(.gate.newFindings.byStatus.UNKNOWN // 0), UNREACHABLE \(.gate.newFindings.byStatus.UNREACHABLE // 0), NOT_ANALYZED \(.gate.newFindings.byStatus.NOT_ANALYZED // 0))"' <<< "$BODY")"
summary "$(jq -r '.gate.reasons[]? | "- \(.condition) \(.count): \(.summary)"' <<< "$BODY")"
[ -n "$link" ] && summary "Dashboard: $link"
exit "$(jq -r '.gate.exitCode // 0' <<< "$BODY")"
