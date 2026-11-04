#!/bin/sh
set -eu
set -o pipefail
: "${NAMESPACES:?}" "${CLUSTER:?}" "${REACH_URL:?}"
SA=/var/run/secrets/kubernetes.io/serviceaccount
failed=""
for ns in $(echo "$NAMESPACES" | tr ',' ' '); do
  if curl -sSf --cacert "$SA/ca.crt" -H "Authorization: Bearer $(cat "$SA/token")" \
          "https://kubernetes.default.svc/api/v1/namespaces/$ns/pods" \
     | jq --arg cluster "$CLUSTER" --arg ns "$ns" -f /app/inventory.jq \
     | curl -sSf -X PUT -H "Authorization: Bearer $(cat /var/run/secrets/reach/token)" \
            -H 'Content-Type: application/json' --data-binary @- \
            "$REACH_URL/internal/v1/reach/l1/workloads" >/dev/null; then
    echo "sent namespace=$ns"
  else
    echo "failed namespace=$ns" >&2
    failed="$failed $ns"
  fi
done
[ -z "$failed" ] || { echo "failed namespaces:$failed" >&2; exit 1; }
