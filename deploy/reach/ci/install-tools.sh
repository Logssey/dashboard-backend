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

BIN="${1:-${RUNNER_TEMP:-$PWD}/reach-bin}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$BIN"

fetch() {   # url sha256 file
  curl -sSfLo "$WORK/$3" "$1"
  echo "$2  $WORK/$3" | sha256sum -c --quiet -
}

fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
  "$TRIVY_SHA256" trivy.tar.gz
tar -xzf "$WORK/trivy.tar.gz" -C "$BIN" trivy

fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
  "$GRYPE_SHA256" grype.tar.gz
tar -xzf "$WORK/grype.tar.gz" -C "$BIN" grype

[ -n "${GITHUB_PATH:-}" ] && echo "$BIN" >> "$GITHUB_PATH"
"$BIN/trivy" --version | head -1
"$BIN/grype" version | grep '^Version'
