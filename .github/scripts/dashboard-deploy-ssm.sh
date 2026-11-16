#!/usr/bin/env bash
# Run /opt/logssey/deploy.sh <service> <digest> on the dashboard host through the SSM document and wait for it.
# Used by .github/workflows/dashboard-deploy.yml. Needs AWS credentials, INSTANCE_ID, DEPLOY_DOCUMENT.
set -euo pipefail
service=$1 digest=$2
: "${INSTANCE_ID:?}" "${DEPLOY_DOCUMENT:?}"

command_id=$(aws ssm send-command --instance-ids "$INSTANCE_ID" --document-name "$DEPLOY_DOCUMENT" \
  --parameters "{\"service\":[\"$service\"],\"digest\":[\"$digest\"]}" \
  --comment "${GITHUB_REPOSITORY#*/} ${GITHUB_SHA::12} run $GITHUB_RUN_ID" \
  --query Command.CommandId --output text)
echo "SSM command $command_id ($service)"
# deploy.sh waits for another deploy, dumps the database and checks health for up to 5 minutes;
# the document stops it after 15 minutes
status=Pending
for _ in $(seq 1 96); do
  sleep 10
  status=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$INSTANCE_ID" \
    --query Status --output text 2> /dev/null || echo Pending)
  case $status in Pending|InProgress|Delayed) ;; *) break ;; esac
done
for stream in StandardOutputContent StandardErrorContent; do
  echo "--- $stream"
  aws ssm get-command-invocation --command-id "$command_id" --instance-id "$INSTANCE_ID" \
    --query "$stream" --output text || true
done
echo "Deploy $service: $status (SSM command \`$command_id\`)" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
if [ "$status" != Success ]; then
  echo "::error::Deploy $service $status. If the output says 'rolled back', the previous image is running."
  exit 1
fi
