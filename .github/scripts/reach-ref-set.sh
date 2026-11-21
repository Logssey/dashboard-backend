#!/usr/bin/env bash
# Moves the repository variable REACH_REF of the service repos to the commit the dashboard was just deployed from.
# The Reach scans of those repos (deploy/reach/ci/reach.yml) run the analyzer, judgement data and scripts of that
# commit, so new rules reach the scans without anyone editing the variable.
#
#   GH_TOKEN=<token that can read and write Actions variables of the repos> COMMIT=<40-character commit> \
#   REPOSITORIES=service-backend[,other-repo] bash .github/scripts/reach-ref-set.sh
#
# Run inside a full clone of dashboard-backend (fetch-depth 0): the variable only moves forward. When it holds a
# commit that COMMIT does not contain (an older run was run again after a newer deploy), it is left as it is.
# The variable has to exist: it is created once by hand (deploy/reach/ci/README.md).
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is not set}" "${COMMIT:?COMMIT is not set}" "${REPOSITORIES:?REPOSITORIES is not set}"
OWNER=${OWNER:-Logssey}
API=${GITHUB_API_URL:-https://api.github.com}
SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}

[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "::error::COMMIT is not a 40-character commit: $COMMIT"; exit 2; }

body=$(mktemp)
trap 'rm -f "$body"' EXIT
call() {   # method url [json] -> prints the HTTP status, leaves the response in $body
  curl -sS --retry 3 -o "$body" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' ${3:+-d "$3"} "$2"
}

failed=0
for repo in ${REPOSITORIES//,/ }; do
  if ! [[ $repo =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::bad repository name: $repo"; failed=1; continue
  fi
  url="$API/repos/$OWNER/$repo/actions/variables/REACH_REF"
  code=$(call GET "$url") || code=000
  if [ "$code" != 200 ]; then
    echo "::error::$OWNER/$repo: cannot read the variable REACH_REF (HTTP $code). It has to exist, and the app needs the Variables permission on that repo"
    failed=1; continue
  fi
  current=$(jq -r '.value // ""' "$body")
  if [ "$current" = "$COMMIT" ]; then
    echo "$OWNER/$repo: REACH_REF is already $COMMIT" | tee -a "$SUMMARY"; continue
  fi
  if [[ $current =~ ^[0-9a-f]{40}$ ]] && git cat-file -e "$current^{commit}" 2> /dev/null \
      && ! git merge-base --is-ancestor "$current" "$COMMIT"; then
    echo "::notice::$OWNER/$repo: REACH_REF stays $current; $COMMIT does not contain it (an older run after a newer deploy?)"
    echo "$OWNER/$repo: REACH_REF stays $current (newer than $COMMIT)" >> "$SUMMARY"
    continue
  fi
  code=$(call PATCH "$url" "{\"name\":\"REACH_REF\",\"value\":\"$COMMIT\"}") || code=000
  if [ "$code" != 204 ]; then
    echo "::error::$OWNER/$repo: could not set REACH_REF (HTTP $code)"; failed=1; continue
  fi
  echo "$OWNER/$repo: REACH_REF ${current:-(empty)} -> $COMMIT" | tee -a "$SUMMARY"
done
exit "$failed"
