#!/bin/sh
# Synthetic, isolated smoke test. No source scopes or live provider credentials.
set -eu
task_prefix="logssey-secret-ci-$$"
task_dir="$(mktemp -d)"
task_network="$task_prefix-network"
task_db="$task_prefix-db"
task_api="$task_prefix-api"
task_worker="$task_prefix-worker"
cleanup() {
  docker rm -f "$task_api" "$task_worker" "$task_db" >/dev/null 2>&1 || true
  docker network rm "$task_network" >/dev/null 2>&1 || true
  # CI runner temporary files contain synthetic values only and expire with the runner.
}
trap cleanup EXIT INT TERM
mkdir "$task_dir/api-secrets" "$task_dir/worker-secrets"
printf '%s' 'isolated-ci-database' > "$task_dir/api-secrets/spring.datasource.password"
printf '%s' 'isolated-ci-database' > "$task_dir/worker-secrets/spring.datasource.password"
printf '%s' 'isolated-ci-login' > "$task_dir/api-secrets/logssey.admin.password"
cat > "$task_dir/api.properties" <<EOF
spring.datasource.url=jdbc:postgresql://$task_db:5432/secret_ci
spring.datasource.username=secret_ci
spring.flyway.enabled=true
logssey.admin.login-id=secret-ci
logssey.admin.display-name=Isolated CI
logssey.secret.bootstrap-security-login-id=secret-ci
logssey.notion.collector.token=
logssey.credential.fingerprint-secret=
logssey.runtime.collector-token=
logssey.secret.github.enabled=false
logssey.secret.aws.content.enabled=false
logssey.secret.validation.aws.enabled=false
logssey.secret.validation.github.enabled=false
logssey.secret.guide.groq.enabled=false
EOF
cat > "$task_dir/worker.properties" <<EOF
spring.datasource.url=jdbc:postgresql://$task_db:5432/secret_ci
spring.datasource.username=secret_ci
spring.flyway.enabled=false
logssey.secret.scheduler.enabled=false
logssey.secret.executor.enabled=false
logssey.secret.github.enabled=false
logssey.secret.aws.collection.enabled=false
logssey.secret.aws.content.enabled=false
logssey.secret.validation.aws.enabled=false
logssey.secret.validation.github.enabled=false
logssey.secret.permissions.enabled=false
EOF
# UID10001 may read the synthetic mounted configuration; no host credential directory is used.
chmod 755 "$task_dir" "$task_dir/api-secrets" "$task_dir/worker-secrets"
chmod 644 "$task_dir/"*.properties "$task_dir/api-secrets/"* "$task_dir/worker-secrets/"*
docker network create --internal "$task_network" >/dev/null
docker run -d --name "$task_db" --network "$task_network" \
  -e POSTGRES_USER=secret_ci -e POSTGRES_DB=secret_ci -e POSTGRES_PASSWORD=isolated-ci-database \
  postgres:18.6 >/dev/null
for task_attempt in $(seq 1 60); do
  if docker exec "$task_db" pg_isready -U secret_ci -d secret_ci >/dev/null 2>&1; then break; fi
  if [ "$task_attempt" = 60 ]; then echo 'POSTGRES_NOT_READY'; exit 1; fi
  sleep 1
done
docker run -d --name "$task_api" --network "$task_network" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=0700 \
  -p 127.0.0.1::8080 \
  -v "$task_dir/api.properties:/run/config/application.properties:ro" \
  -v "$task_dir/api-secrets:/run/secrets:ro" logssey-secret-api:ci >/dev/null
task_port="$(docker port "$task_api" 8080/tcp | sed 's/.*://')"
python3 deploy/verify-http.py "http://127.0.0.1:$task_port"
docker run --rm --network none --read-only --entrypoint /usr/local/bin/gitleaks \
  logssey-secret-worker:ci version | grep -Fx '8.30.1'
docker run -d --name "$task_worker" --network "$task_network" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=0700 \
  -v "$task_dir/worker.properties:/run/config/application.properties:ro" \
  -v "$task_dir/worker-secrets:/run/secrets:ro" logssey-secret-worker:ci >/dev/null
for task_attempt in $(seq 1 45); do
  if docker logs "$task_worker" 2>&1 | grep -q 'Started SecretWorkerApplication'; then break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$task_worker")" != true ] || [ "$task_attempt" = 45 ]; then
    echo 'WORKER_NOT_READY'; exit 1
  fi
  sleep 1
done
echo 'ISOLATED_API_AND_WORKER_IMAGES_PASSED'
