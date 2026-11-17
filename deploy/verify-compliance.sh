#!/bin/sh
# Credential-free E2E. A synthetic executable replaces Prowler, so no AWS account is contacted.
set -eu

task_prefix="logssey-compliance-ci-$$"
task_dir="$(mktemp -d)"
task_network="$task_prefix-network"
task_db="$task_prefix-db"
task_api="$task_prefix-api"
task_worker="$task_prefix-worker"
task_sts="$task_prefix-sts"

cleanup() {
  task_exit=$?
  if [ "$task_exit" != 0 ]; then
    docker logs "$task_api" 2>&1 | tail -60 || true
    docker logs "$task_worker" 2>&1 | tail -60 || true
  fi
  docker rm -f "$task_api" "$task_worker" "$task_sts" "$task_db" >/dev/null 2>&1 || true
  docker network rm "$task_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir "$task_dir/api-secrets" "$task_dir/worker-secrets"
printf '%s' 'isolated-ci-database' > "$task_dir/api-secrets/spring.datasource.password"
printf '%s' 'isolated-ci-login' > "$task_dir/api-secrets/logssey.admin.password"
printf '%s' '0123456789abcdef0123456789abcdef' > "$task_dir/api-secrets/logssey.compliance.worker-token"
printf '%s' '0123456789abcdef0123456789abcdef' > "$task_dir/worker-secrets/logssey.compliance-worker.token"

cat > "$task_dir/api.properties" <<EOF
spring.datasource.url=jdbc:postgresql://$task_db:5432/compliance_ci
spring.datasource.username=compliance_ci
spring.flyway.enabled=true
logssey.admin.login-id=compliance-ci
logssey.admin.display-name=Compliance CI
logssey.runtime.collector-token=
logssey.compliance.target-key=synthetic-service
logssey.compliance.target-name=Synthetic Service
logssey.compliance.execution-enabled=true
logssey.compliance.connection-tests-enabled=true
logssey.compliance.worker-lease-seconds=60
logssey.compliance.worker-retry-delay-seconds=1
EOF

cat > "$task_dir/worker.properties" <<EOF
logssey.compliance-worker.enabled=true
logssey.compliance-worker.api-base-url=http://$task_api:8080
logssey.compliance-worker.worker-id=synthetic-worker
logssey.compliance-worker.poll-delay=1s
logssey.compliance-worker.heartbeat-delay=10s
logssey.compliance-worker.scan-timeout=30s
logssey.compliance-worker.prowler-executable=/opt/logssey/fake-prowler
logssey.compliance-worker.aws-region=ap-northeast-1
logssey.compliance-worker.sts-endpoint=http://$task_sts:8080
EOF

cat > "$task_dir/fake-sts.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0"))).decode()
        action = parse_qs(body).get("Action", [""])[0]
        if action == "AssumeRole":
            payload = """<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult><Credentials><AccessKeyId>ASIASYNTHETIC123456</AccessKeyId><SecretAccessKey>synthetic-secret-access-key-000000000000000</SecretAccessKey><SessionToken>synthetic-session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::000000000000:assumed-role/LogsseyProwlerScan/logssey-ci</Arn><AssumedRoleId>synthetic:logssey-ci</AssumedRoleId></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000001</RequestId></ResponseMetadata></AssumeRoleResponse>"""
        elif action == "GetCallerIdentity":
            payload = """<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>arn:aws:sts::000000000000:assumed-role/LogsseyProwlerScan/logssey-ci</Arn><UserId>synthetic:logssey-ci</UserId><Account>000000000000</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000002</RequestId></ResponseMetadata></GetCallerIdentityResponse>"""
        else:
            self.send_error(400)
            return
        encoded = payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
    def log_message(self, *_):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY

cat > "$task_dir/fake-prowler" <<'EOF'
#!/bin/sh
set -eu
output=''
filename='result'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-directory) output="$2"; shift 2 ;;
    --output-filename) filename="$2"; shift 2 ;;
    *) shift ;;
  esac
done
test -n "$output"
cat > "$output/$filename.ocsf.json" <<'JSON'
[{
  "metadata":{"event_code":"securityhub_enabled","product":{"name":"Prowler","version":"5.46.0"}},
  "status_code":"FAIL",
  "finding_info":{"uid":"aws:securityhub:000000000000","title":"Synthetic Security Hub finding"},
  "cloud":{"provider":"aws"},
  "resources":[{"uid":"000000000000","name":"000000000000","region":"ap-northeast-2"}],
  "severity":"High",
  "time_dt":"2026-11-16T01:00:00Z"
}]
JSON
EOF

chmod 755 "$task_dir" "$task_dir/api-secrets" "$task_dir/worker-secrets" "$task_dir/fake-prowler"
chmod 644 "$task_dir/"*.properties "$task_dir/api-secrets/"* "$task_dir/worker-secrets/"*

docker network create --internal "$task_network" >/dev/null
docker run -d --name "$task_sts" --network "$task_network" --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$task_dir/fake-sts.py:/fake-sts.py:ro" \
  python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8 \
  python -B /fake-sts.py >/dev/null
docker run -d --name "$task_db" --network "$task_network" \
  -e POSTGRES_USER=compliance_ci -e POSTGRES_DB=compliance_ci -e POSTGRES_PASSWORD=isolated-ci-database \
  postgres:18.6 >/dev/null
for task_attempt in $(seq 1 60); do
  if docker exec "$task_db" pg_isready -U compliance_ci -d compliance_ci >/dev/null 2>&1; then break; fi
  if [ "$task_attempt" = 60 ]; then echo 'POSTGRES_NOT_READY'; exit 1; fi
  sleep 1
done

docker run -d --name "$task_api" --network "$task_network" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=0700 \
  -v "$task_dir/api.properties:/run/config/application.properties:ro" \
  -v "$task_dir/api-secrets:/run/secrets:ro" logssey-dashboard-api:ci >/dev/null

docker run -d --name "$task_worker" --network "$task_network" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,uid=1000,gid=1000,mode=0700 \
  -v "$task_dir/worker.properties:/run/config/application.properties:ro" \
  -v "$task_dir/worker-secrets:/run/secrets:ro" \
  -v "$task_dir/fake-prowler:/opt/logssey/fake-prowler:ro" \
  -e AWS_ACCESS_KEY_ID=synthetic-base-key -e AWS_SECRET_ACCESS_KEY=synthetic-base-secret \
  logssey-compliance-worker:ci >/dev/null

docker run --rm --network "container:$task_api" --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD/deploy/verify-compliance.py:/verify-compliance.py:ro" \
  python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8 \
  python -B /verify-compliance.py http://127.0.0.1:8080
