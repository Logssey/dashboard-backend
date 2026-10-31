#!/bin/sh
set -eu
# Official v8.30.1 release checksums, fixed here rather than trusting a downloaded
# mutable checksum file. No source content is handled during image construction.
case "${1:-}" in
  amd64) release_arch=x64; checksum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  arm64) release_arch=arm64; checksum=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
  *) echo 'Unsupported Gitleaks architecture' >&2; exit 1 ;;
esac
output_dir="${2:?Output directory required}"
mkdir -p "$output_dir"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-time 120 --retry 2 \
  "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${release_arch}.tar.gz" \
  --output "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$output_dir" gitleaks LICENSE
chmod 0555 "$output_dir/gitleaks"
test "$("$output_dir/gitleaks" version)" = '8.30.1'
