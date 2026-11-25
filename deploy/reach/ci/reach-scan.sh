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
#        -> L3 evidence (only with L3_SEGMENTS) -> bundle.py -> API-13. A failed step after the check is registered uploads a failure bundle,
#        so the scan ends FAILED on the dashboard instead of staying QUEUED.
#
# Required: MODE (PR | IMAGE_BUILD | MANUAL), REACH_URL. REPOSITORY and COMMIT for PR and IMAGE_BUILD
# JAR: the Java app jar (bootJar) to analyse (L2). Leave it empty for a target without one (a Node image,
#   a repo path without a Gradle build): then L2 is skipped and every finding is NOT_ANALYZED with its reason.
#   A repo target without JAR needs FS_DIR, the checked-out path whose lock files give the SBOM (trivy fs).
# MODE=PR: PR_NUMBER (optional BASE_REF, HEAD_REF). Target is the repo at COMMIT; the SBOM comes from JAR (or FS_DIR).
# MODE=IMAGE_BUILD: IMAGE_REPOSITORY (e.g. logssey/reused-api), IMAGE_DIGEST (sha256:...), IMAGE_REF
#   (what `trivy image` pulls, e.g. <registry>/<repo>@<digest>). JAR is the app jar copied out of that image.
# MODE=MANUAL: CHECK_ID (the dashboard's check), TARGET_TYPE (REPO: SBOM from JAR or FS_DIR | IMAGE: SBOM from IMAGE_REF).
#   RESCAN_OF (optional, a rescan: API-01 rescanOf or the dashboard's daily rescan): the SBOM the dashboard stored
#   for that scan is matched again instead of making one. Without a stored SBOM (a scan from before SBOMs were
#   kept) the SBOM is made as usual. JAR (L2) is still needed.
# L3 (optional, FR-14): L3_SEGMENTS (the execution data of l3-run.sh, one file per segment) and L3_RUN (its
#   run.json), with JAR and JACOCO_HOME (jacococli.jar): after L2 the segments become JaCoCo reports of the classes
#   the L3 data and the L2 call paths name, verdict/l3.py says how far the run got per CVE and in which requests,
#   and that goes into the bundle as its l3 object. It is evidence next to the L2 verdict; this script never changes
#   the verdict. The dashboard raises it when it takes the bundle, only as far as the CVE's rule allows (rules.json l3).
#   The segments of a fresh run are also sent as the bundle's l3Record: the dashboard keeps them, and a rescan
#   (MANUAL with RESCAN_OF) gets them back (GET …/l3-record) and matches them again with today's data instead of
#   running the app. Without a kept record a rescan has no L3.
#   L3_ERROR (a message) when the L3 run failed. A failed L3 step is logged and sent as an L3 error; it never
#   fails the scan.
# Optional: APP (app code; when empty the dashboard picks it from its logssey.reach.apps), POLICY (REPORT_ONLY | GATE, default REPORT_ONLY; only PR checks are gated, an image build is always REPORT_ONLY), SOURCE (service repo checkout,
#   gives verdict.py the config files), OUT (./reach-out), WAIT_SECONDS (300), REACH_UI_URL (link in the summary),
#   REACH_HOME (dashboard-backend checkout; default: this script's repo), ANALYZER (reach-analyzer.jar path).
# Auth: in GitHub Actions a fresh OIDC token (aud logssey-reach) is fetched for every call
#   (needs `permissions: id-token: write`). Otherwise REACH_TOKEN is sent as a bearer token.
#   REACH_CURL_OPTS adds raw curl arguments (local checks only: session cookie and CSRF header).
# Needs: bash, curl, jq, python3, trivy (java 21 when JAR is given). grype is used when installed.
set -Eeuo pipefail

: "${MODE:?MODE=PR, IMAGE_BUILD or MANUAL}"
if [ "$MODE" != MANUAL ]; then
  : "${REPOSITORY:?REPOSITORY=<repository name, e.g. service-backend>}"
  : "${COMMIT:?COMMIT=<40-character commit sha>}"
fi
JAR="${JAR:-}"
FS_DIR="${FS_DIR:-}"
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
  PR) : "${PR_NUMBER:?PR_NUMBER is required for MODE=PR}"; SBOM_FROM=repo ;;
  IMAGE_BUILD)
    : "${IMAGE_REPOSITORY:?IMAGE_REPOSITORY is required for MODE=IMAGE_BUILD}"
    : "${IMAGE_DIGEST:?IMAGE_DIGEST is required for MODE=IMAGE_BUILD}"
    : "${IMAGE_REF:?IMAGE_REF is required for MODE=IMAGE_BUILD}"
    SBOM_FROM=image ;;
  MANUAL)
    [[ "${CHECK_ID:-}" =~ ^[0-9]+$ ]] || { echo "CHECK_ID must be the dashboard check id: ${CHECK_ID:-}" >&2; exit 2; }
    [[ "${RESCAN_OF:-}" =~ ^[0-9]*$ ]] || { echo "RESCAN_OF must be a scan id: $RESCAN_OF" >&2; exit 2; }
    case "${TARGET_TYPE:-}" in
      REPO) SBOM_FROM=repo ;;
      IMAGE) : "${IMAGE_REF:?IMAGE_REF is required for TARGET_TYPE=IMAGE}"; SBOM_FROM=image ;;
      *) echo "TARGET_TYPE must be REPO or IMAGE: ${TARGET_TYPE:-}" >&2; exit 2 ;;
    esac ;;
  *) echo "MODE must be PR, IMAGE_BUILD or MANUAL: $MODE" >&2; exit 2 ;;
esac
if [ "$MODE" != MANUAL ]; then
  [ "${#COMMIT}" -eq 40 ] || { echo "COMMIT must be the full 40-character sha: $COMMIT" >&2; exit 2; }
fi
if [ -n "$JAR" ]; then
  [ -f "$JAR" ] || { echo "JAR not found: $JAR" >&2; exit 2; }
  [ -f "$ANALYZER" ] || { echo "analyzer jar not found: $ANALYZER (./gradlew :reach-analyzer:jar)" >&2; exit 2; }
  [ "$SBOM_FROM" = repo ] && SBOM_FROM=jar
elif [ "$SBOM_FROM" = repo ]; then
  [ -d "$FS_DIR" ] || { echo "a repo target needs JAR (Java) or FS_DIR (lock files): FS_DIR=$FS_DIR" >&2; exit 2; }
  SBOM_FROM=dir
fi
mkdir -p "$OUT"

log() { echo "[reach] $*" >&2; }
summary() { if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$*" >> "$GITHUB_STEP_SUMMARY"; else echo "$*"; fi; }

# ---- dashboard API ----

# Every call to the dashboard retries a dropped connection, a timeout and 408/429/5xx (curl --retry), so one restart of
# the dashboard (a deploy) does not fail the check. Creating a check is safe to retry (Idempotency-Key); an upload the
# dashboard did store before the reply was lost comes back 409 and is checked below (upload)
CURL_RETRY=(--connect-timeout 10 --max-time "${REACH_CURL_MAX_TIME:-300}" --retry 4 --retry-delay 5 --retry-connrefused)

AUTH=()
set_auth() {
  AUTH=()
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    local token
    token=$(curl -sSf "${CURL_RETRY[@]}" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
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
  response=$(curl -sS "${CURL_RETRY[@]}" -X "$method" "${AUTH[@]}" -w $'\n%{http_code}' "$@" "$REACH_URL$path")
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
  # the gate is for PRs (API spec 6-2): an image build has no baseline, so GATE would fail it on findings already in production
  REQUEST=$(jq -n --arg repo "$REPOSITORY" --arg commit "$COMMIT" --arg app "$APP" --arg policy REPORT_ONLY \
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
# A check that FAILED is not returned: the dashboard opens a new one for the key, so a re-run scans again (API spec 2-7).
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

# tools.reachRef: the dashboard-backend commit whose analyzer, judgement data (vuln-functions.json, rules.json) and
# scripts made this result (NFR-04: the same input with the same commit gives the same verdicts). In CI it is the
# REACH_REF checkout; a local run with changes in those paths gets "-dirty"
reach_ref() {
  local ref
  if ref=$(git -C "$REACH_HOME" rev-parse --verify -q HEAD 2>/dev/null); then
    [ -z "$(git -C "$REACH_HOME" status --porcelain -- src/main/resources/reach reach-analyzer deploy/reach 2>/dev/null)" ] \
      || ref="$ref-dirty"
  else
    ref="${REACH_REF:-}"
  fi
  [[ "$ref" =~ ^[0-9a-f]{40}(-dirty)?$ ]] && echo "$ref"
  return 0
}
REACH_COMMIT=$(reach_ref)
[ -n "$REACH_COMMIT" ] && TOOLS+=(--tool "reachRef=$REACH_COMMIT")
UPLOADED=""

# UPLOADED is set only when the dashboard took the bundle: after a failed upload (e.g. 502 while it restarts) the
# failure bundle still goes up, so the scan does not stay QUEUED
upload() {
  api PUT "/api/v1/reach/ci/checks/$CHECK_ID/results" \
    -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary "@$1"
  if [ "$HTTP" = 202 ] || [ "$HTTP" = 200 ]; then
    UPLOADED=1
    return 0
  fi
  if [ "$HTTP" = 409 ]; then
    # a retried upload: the first attempt may have been stored before its reply was lost
    local refused="$BODY"
    api GET "/api/v1/reach/ci/checks/$CHECK_ID"
    if [ "$HTTP" = 200 ] && [ "$(jq -r .scanStatus <<< "$BODY")" = SUCCEEDED ]; then
      log "API-13 said 409 but the check already SUCCEEDED (an earlier attempt was stored)"
      UPLOADED=1
      return 0
    fi
    BODY="$refused"
    HTTP=409
  fi
  log "API-13 upload failed: HTTP $HTTP $BODY"
  return 1
}

# A failure bundle for the step that was running, so the scan ends FAILED with a reason instead of staying QUEUED
fail_bundle() {
  local code=$1 message=$2
  if [ -n "${CHECK_ID:-}" ] && [ -z "$UPLOADED" ] && [ -n "$CURRENT" ]; then
    log "step $CURRENT: $message; uploading a failure bundle"
    python3 "$VERDICT/bundle.py" --failure-code "$code" --failure-stage "$CURRENT" \
      --failure-message "runner step $CURRENT: $message, see the workflow log" \
      "${TOOLS[@]}" "${STAGES[@]}" --stage "$CURRENT=failed" --out "$OUT/failure.json.gz" \
      && upload "$OUT/failure.json.gz" || log "failure bundle upload failed too"
  fi
}

on_error() {
  local rc=$?
  trap - ERR TERM INT
  fail_bundle ANALYSIS_FAILED "failed (exit $rc)"
  exit "$rc"
}

# The job was cancelled or hit timeout-minutes: GitHub sends SIGINT, then SIGTERM. The ERR trap does not run then
on_signal() {
  trap - ERR TERM INT
  fail_bundle RUNNER_CANCELLED "cancelled or timed out"
  exit 143
}

stage() {
  local name=$1 started=$SECONDS
  shift
  CURRENT=$name
  "$@"
  STAGES+=(--stage "$name=succeeded:$((SECONDS - started))")
  CURRENT=""
}

# a rescan: the SBOM the dashboard stored for RESCAN_OF (gzip). Fails (1) when there is none (404)
stored_sbom() {
  [ "$MODE" = MANUAL ] && [ -n "${RESCAN_OF:-}" ] || return 1
  set_auth
  local code
  code=$(curl -sS "${CURL_RETRY[@]}" "${AUTH[@]}" -o "$OUT/stored-sbom.json.gz" -w '%{http_code}' \
    "$REACH_URL/api/v1/reach/ci/checks/$CHECK_ID/sbom") || return 1
  if [ "$code" != 200 ]; then
    log "no stored SBOM for scan $RESCAN_OF (HTTP $code); making the SBOM"
    return 1
  fi
  gzip -dc "$OUT/stored-sbom.json.gz" > "$OUT/sbom.cdx.json" || return 1
  log "rescan of scan $RESCAN_OF: matching its stored SBOM again"
  TOOLS+=(--tool "sbomSource=stored:scan-$RESCAN_OF")
}

sbom() {
  if stored_sbom; then
    return 0
  elif [ "$SBOM_FROM" = jar ]; then
    # trivy fs reads only lock files (none in a Gradle repo); rootfs reads the jars
    local dir="$OUT/jar"
    mkdir -p "$dir"
    cp "$JAR" "$dir/"
    trivy rootfs --quiet --format cyclonedx -o "$OUT/sbom.cdx.json" "$dir"
  elif [ "$SBOM_FROM" = dir ]; then
    # no Java build at this path: the lock files (package-lock.json, …) list the packages
    trivy fs --quiet --format cyclonedx -o "$OUT/sbom.cdx.json" "$FS_DIR"
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

# L3 (FR-14): reports of the run's segments, then how far the run got per CVE. Never stops the scan: the caller
# checks the status
l3_evidence() {
  local cli="${JACOCO_HOME:-}/jacococli.jar" release scope seg id reach_args=()
  [ -n "$JAR" ] && [ -f "$cli" ] && [ -f "${L3_RUN:-}" ] || { log "L3 needs JAR, JACOCO_HOME and L3_RUN"; return 1; }
  release=$(jq -r '.javaRelease // 21' "$L3_RUN") || return 1
  scope=$(jq -r '.scope // "*"' "$L3_RUN") || return 1
  [ -f "$OUT/reach-result.json" ] && reach_args=(--reach "$OUT/reach-result.json")
  rm -rf "$OUT/l3-classes" "$OUT/l3-xml"
  mkdir -p "$OUT/l3-xml"
  python3 "$VERDICT/l3_runner.py" classes --jar "$JAR" --out "$OUT/l3-classes" --java-release "$release" \
    --spec "$DATA/vuln-functions.json" "${reach_args[@]}" || return 1
  for seg in "$L3_SEGMENTS"/*.exec; do
    id=$(basename "$seg" .exec)
    java -jar "$cli" report "$seg" --classfiles "$OUT/l3-classes" --xml "$OUT/l3-xml/$id.xml" \
      > "$OUT/l3-report.log" 2>&1 || { log "the JaCoCo report of segment $id failed"; return 1; }
    # a class file that is not the one that ran has no coverage at all: that would read as "did not run"
    if grep -q 'does not match' "$OUT/l3-report.log"; then
      log "the class files of the jar are not the ones that ran (segment $id); no L3 result"
      return 1
    fi
  done
  python3 "$VERDICT/l3.py" --spec "$DATA/vuln-functions.json" --segments "$OUT/l3-xml" --sbom "$OUT/sbom.cdx.json" \
    --scope "$scope" "${reach_args[@]}" --out "$OUT/l3-match.json" || return 1
  # rematch: not a new observation; the kept record of an earlier run matched again in this scan
  jq -s --argjson rematch "${L3_REMATCH:-false}" '.[0] + {run: (.[1] + (if $rematch then {rematch: true} else {} end))}' \
    "$OUT/l3-match.json" "$L3_RUN" > "$OUT/l3-result.json" || return 1
}

# a rescan: the execution record the dashboard kept for this image (tar.xz). Fails (1) when there is none (404)
stored_l3() {
  [ "$MODE" = MANUAL ] && [ -n "${RESCAN_OF:-}" ] && [ -n "$JAR" ] || return 1
  set_auth
  local code
  code=$(curl -sS "${CURL_RETRY[@]}" "${AUTH[@]}" -o "$OUT/stored-l3-record.tar.xz" -w '%{http_code}' \
    "$REACH_URL/api/v1/reach/ci/checks/$CHECK_ID/l3-record") || return 1
  if [ "$code" != 200 ]; then
    log "no kept L3 record for this image (HTTP $code); the rescan has no L3"
    return 1
  fi
  rm -rf "$OUT/l3-stored"
  python3 "$VERDICT/l3_runner.py" unpack --record "$OUT/stored-l3-record.tar.xz" --out "$OUT/l3-stored" || return 1
  log "rescan: matching the kept L3 record of this image again (the app is not run)"
  L3_SEGMENTS="$OUT/l3-stored/segments"
  L3_RUN="$OUT/l3-stored/run.json"
  L3_REMATCH=true
}

l2() {
  java -Xmx3g -jar "$ANALYZER" --app "$JAR" \
    --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" --out "$OUT/reach-result.json"
  local repo_args=()
  [ -n "${SOURCE:-}" ] && repo_args=(--repo "$SOURCE")
  # the jar's own config files are read too: an image without its source commit (no pr-<sha> tag) still has them
  python3 "$VERDICT/verdict.py" --reach "$OUT/reach-result.json" \
    --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" \
    --trivy "$OUT/trivy.json" "${repo_args[@]}" --jar "$JAR" --out "$OUT/verdicts.json" --md "$OUT/verdicts.md"
}

report() {
  local grype_args=() l2_args=(--no-l2)
  [ -f "$OUT/grype.json" ] && grype_args=(--grype "$OUT/grype.json")
  [ -n "$JAR" ] && l2_args=(--reach "$OUT/reach-result.json" --verdicts "$OUT/verdicts.json" --jar "$JAR")
  python3 "$VERDICT/bundle.py" --sbom "$OUT/sbom.cdx.json" --trivy "$OUT/trivy.json" "${grype_args[@]}" \
    "${l2_args[@]}" "${L3_ARGS[@]}" --spec "$DATA/vuln-functions.json" --rules "$DATA/rules.json" \
    "${TOOLS[@]}" "${STAGES[@]}" --stage "report=succeeded" --out "$OUT/bundle.json.gz"
}

if [ "$ALREADY" = QUEUED ]; then
  trap on_error ERR
  trap on_signal TERM INT
  db_updated=$(trivy version --format json 2> /dev/null | jq -r '.VulnerabilityDB.UpdatedAt // empty' || true)
  [ -n "$db_updated" ] && TOOLS+=(--tool "trivyDbUpdatedAt=$db_updated")
  stage sbom sbom
  stage match match
  if [ -n "$JAR" ]; then
    stage l2 l2
  else
    log "no app jar: L2 skipped, findings are NOT_ANALYZED with their reason"
  fi
  L3_ARGS=()
  rm -f "$OUT/l3-match.json" "$OUT/l3-result.json"
  if [ -z "${L3_SEGMENTS:-}" ] && [ -z "${L3_ERROR:-}" ]; then
    stored_l3 || true
  fi
  if [ -n "${L3_SEGMENTS:-}" ]; then
    if l3_evidence; then
      L3_ARGS=(--l3 "$OUT/l3-result.json")
      log "L3: $(jq -c .counts "$OUT/l3-result.json")"
      # a fresh run: the dashboard keeps its record for rescans. A failed pack only loses that
      if [ "${L3_REMATCH:-false}" != true ]; then
        if python3 "$VERDICT/l3_runner.py" pack --segments "$L3_SEGMENTS" --run "$L3_RUN" --out "$OUT/l3-record.tar.xz"; then
          L3_ARGS+=(--l3-record "$OUT/l3-record.tar.xz")
        else
          log "the L3 record was not packed; rescans of this image will have no L3"
        fi
      fi
    else
      log "L3 evidence failed; the scan goes on without it"
      rm -f "$OUT/l3-result.json"
      L3_ARGS=(--l3-error "L3 evidence failed on the runner, see the workflow log")
    fi
  elif [ -n "${L3_ERROR:-}" ]; then
    L3_ARGS=(--l3-error "$L3_ERROR")
  fi
  stage report report
  CURRENT=report
  upload "$OUT/bundle.json.gz"
  trap - ERR TERM INT
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
summary "### Reach ($MODE, $(jq -r '.policy // "REPORT_ONLY"' <<< "$BODY"))"
if [ "$status" = FAILED ]; then
  summary "Scan failed on the dashboard. Check $CHECK_ID${link:+ ($link)}."
  exit 1
fi
summary "$(jq -r '"Gate **\(.gate.result)** · new findings \(.gate.newFindings.total) (REACHABLE \(.gate.newFindings.byStatus.REACHABLE // 0), UNKNOWN \(.gate.newFindings.byStatus.UNKNOWN // 0), UNREACHABLE \(.gate.newFindings.byStatus.UNREACHABLE // 0), NOT_ANALYZED \(.gate.newFindings.byStatus.NOT_ANALYZED // 0))"' <<< "$BODY")"
summary "$(jq -r 'if .baselineScanId then "Compared with scan \(.baselineScanId) (for a PR: the image running in production); findings already there are not new"
                  else "No baseline scan: every finding counts as new" end' <<< "$BODY")"
summary "$(jq -r '.gate.reasons[]? | "- \(.condition) \(.count): \(.summary)"' <<< "$BODY")"
[ -n "$link" ] && summary "Dashboard: $link"
exit "$(jq -r '.gate.exitCode // 0' <<< "$BODY")"
