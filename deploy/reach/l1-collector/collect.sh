#!/bin/sh
# Reach L1 collector: list the running pods of each namespace and PUT their workloads to the dashboard (README).
# Exit 2: missing settings. Exit 1: at least one namespace was not sent (the Job fails and retries).
set -eu
set -o pipefail
: "${NAMESPACES:?}" "${CLUSTER:?}" "${REACH_URL:?}"
SA=/var/run/secrets/kubernetes.io/serviceaccount
REACH_TOKEN=/var/run/secrets/reach/token
CURL="curl -sS --connect-timeout 10 --max-time 60"
failed="" count=0
for ns in $(echo "$NAMESPACES" | tr ',' ' '); do
  count=$((count + 1))
  # Build the whole body first, so a failed pod list never sends an empty upload
  if ! pods=$($CURL -f --cacert "$SA/ca.crt" -H "Authorization: Bearer $(cat "$SA/token")" \
        "https://kubernetes.default.svc/api/v1/namespaces/$ns/pods"); then
    echo "failed namespace=$ns: cannot list pods" >&2
    failed="$failed $ns"
    continue
  fi
  if ! body=$(printf '%s' "$pods" | jq --arg cluster "$CLUSTER" --arg ns "$ns" -f /app/inventory.jq); then
    echo "failed namespace=$ns: cannot read the pod list" >&2
    failed="$failed $ns"
    continue
  fi
  if response=$(printf '%s' "$body" | $CURL --fail-with-body -X PUT \
        -H "Authorization: Bearer $(cat "$REACH_TOKEN")" -H 'Content-Type: application/json' \
        --data-binary @- "$REACH_URL/api/v1/reach/l1/workloads"); then
    echo "sent namespace=$ns"
  else
    echo "failed namespace=$ns: $(printf '%s' "$response" | head -c 300)" >&2
    failed="$failed $ns"
  fi
done
[ "$count" -gt 0 ] || { echo "NAMESPACES has no namespace" >&2; exit 2; }
[ -z "$failed" ] || { echo "failed namespaces:$failed" >&2; exit 1; }
