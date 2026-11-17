#!/usr/bin/env bash
# Deterministically derives a review baseline from the exact Prowler source used by the Worker.
# It never uploads or attaches policies. Review the output before using it in any account.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <prowler-5.46.0-source-dir> <output-json> [account-id] [region]" >&2
  exit 2
fi

source_dir=$(cd "$1" && pwd)
output_file=$2
account_id=${3:-}
region=${4:-}
expected_commit=91b86777ce86e2cc2f17f818df21fe3bae7b0677

actual_commit=$(git -C "$source_dir" rev-parse HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "Prowler source must be commit $expected_commit" >&2
  exit 3
fi

if ! command -v uvx >/dev/null 2>&1; then
  echo "uvx is required: https://docs.astral.sh/uv/" >&2
  exit 4
fi

source_files=()
while IFS= read -r source_file; do
  source_files+=("$source_file")
done < <(find "$source_dir/prowler/providers/aws" -type f -name '*.py' -print | LC_ALL=C sort)
if [ "${#source_files[@]}" -eq 0 ]; then
  echo "No Prowler AWS Python source files found" >&2
  exit 5
fi

arguments=(iam-policy-autopilot@0.4.0 generate-policies "${source_files[@]}" --language python --pretty)
if [ -n "$account_id" ]; then arguments+=(--account "$account_id"); fi
if [ -n "$region" ]; then arguments+=(--region "$region"); fi

umask 077
mkdir -p "$(dirname "$output_file")"
uvx "${arguments[@]}" > "$output_file"
chmod 600 "$output_file"
echo "Generated review baseline: $output_file"
