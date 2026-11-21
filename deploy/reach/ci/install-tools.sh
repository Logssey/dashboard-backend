#!/usr/bin/env bash
# Installs the scanners reach-scan.sh uses, pinned by version and SHA-256 (same pattern as infrastructure iac-gate).
#
#   bash deploy/reach/ci/install-tools.sh [<bin dir>]     # default: $RUNNER_TEMP/reach-bin or ./reach-bin
#
# In GitHub Actions the bin dir is added to GITHUB_PATH. Bump a version together with its checksum
# (from the release's checksums file) and note it in the PR.
set -euo pipefail

TRIVY_VERSION="0.75.0"
TRIVY_SHA256="c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"
GRYPE_VERSION="0.121.2"
GRYPE_SHA256="9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12"
# L3 (l3-run.sh): agent and CLI from Maven Central. SHA-1 matches the .sha1 file next to each jar
JACOCO_VERSION="0.8.13"
JACOCO_AGENT_SHA256="47e700ccb0fdb9e27c5241353f8161938f4e53c3561dd35e063c5fe88dc3349b"
JACOCO_CLI_SHA256="8f748683833d4dc4d72cea5d6b43f49344687b831e0582c97bcb9b984e3de0a3"

BIN="${1:-${RUNNER_TEMP:-$PWD}/reach-bin}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$BIN"

fetch() {   # url sha256 file
  # a release host sometimes answers 404 or 5xx for a moment: try again before giving up, and say which URL it was
  if ! curl -sSfL --retry 4 --retry-delay 5 --retry-all-errors -o "$WORK/$3" "$1"; then
    echo "install-tools: could not download $1" >&2
    return 1
  fi
  if ! echo "$2  $WORK/$3" | sha256sum -c --quiet -; then
    echo "install-tools: checksum mismatch for $1" >&2
    return 1
  fi
}

fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
  "$TRIVY_SHA256" trivy.tar.gz
tar -xzf "$WORK/trivy.tar.gz" -C "$BIN" trivy

fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
  "$GRYPE_SHA256" grype.tar.gz
tar -xzf "$WORK/grype.tar.gz" -C "$BIN" grype

# its own folder: l3-run.sh mounts it read-only into the app container
maven="https://repo1.maven.org/maven2/org/jacoco"
mkdir -p "$BIN/jacoco"
fetch "$maven/org.jacoco.agent/$JACOCO_VERSION/org.jacoco.agent-$JACOCO_VERSION-runtime.jar" "$JACOCO_AGENT_SHA256" jacocoagent.jar
fetch "$maven/org.jacoco.cli/$JACOCO_VERSION/org.jacoco.cli-$JACOCO_VERSION-nodeps.jar" "$JACOCO_CLI_SHA256" jacococli.jar
cp "$WORK/jacocoagent.jar" "$WORK/jacococli.jar" "$BIN/jacoco/"

[ -n "${GITHUB_PATH:-}" ] && echo "$BIN" >> "$GITHUB_PATH"
[ -n "${GITHUB_ENV:-}" ] && echo "JACOCO_HOME=$BIN/jacoco" >> "$GITHUB_ENV"
"$BIN/trivy" --version | head -1
"$BIN/grype" version | grep '^Version'
echo "jacoco $JACOCO_VERSION ($BIN/jacoco)"
