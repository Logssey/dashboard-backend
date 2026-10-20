#!/usr/bin/env bash
# ─────────────────────────────────────────────
# IaC 보안 로컬 데모: CI 와 Cartography CronJob 이 할 호출을 대신 한다.
#
#   1. prod 레포·데이터 등급 등록 (register-prod-assets.sql)
#   2. 수집 끝 기록 → 워커가 그래프 보강·열린 경로 계산 (ENRICH_GRAPH)
#   3. PR 3개 등록 + 실제 CI plan fixture 업로드 → 워커가 경로 분석 (ANALYZE_RUN)
#        #58  tfstate 거부 정책 삭제 → 차단
#        #60  IMDSv2 강제          → 경로 감소
#        #61  변경 없음             → 통과
#   4. main 매일 점검 + DNS 콘솔 변경 fixture 업로드 → 워커가 드리프트 점검 (CHECK_DRIFT) → 높음 1건
#
# 먼저 띄울 것 (README.md): compose DB, API(bootRun), 로컬 Neo4j, iac-worker
# 실행: dashboard-backend 에서 bash iac-worker/local/demo.sh
# ─────────────────────────────────────────────

set -euo pipefail

cd "$(dirname "$0")/../.."
# .env 는 셸 문법이 아닐 수 있어(따옴표 없는 공백 등) 필요한 값만 읽는다
env_value() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }
DB_NAME=$(env_value DB_NAME)
DB_USERNAME=$(env_value DB_USERNAME)
ADMIN_LOGIN_ID=$(env_value ADMIN_LOGIN_ID)
ADMIN_PASSWORD=$(env_value ADMIN_PASSWORD)

API="${API:-http://localhost:8080}"
PLANS=iac-worker/src/test/resources/plans
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

csrf() { awk '$6 == "XSRF-TOKEN" {print $7}' "$JAR" | tail -1; }
call() {
  local method=$1 path=$2; shift 2
  curl -sS -b "$JAR" -c "$JAR" -X "$method" -H "X-XSRF-TOKEN: $(csrf)" "$@" "$API$path"
}

echo "== 1. 레포·데이터 등급 등록"
docker compose exec -T db psql -q -U "$DB_USERNAME" -d "$DB_NAME" < iac-worker/local/register-prod-assets.sql

echo "== 로그인 ($ADMIN_LOGIN_ID)"
curl -sS -c "$JAR" -o /dev/null "$API/api/v1/auth/me" || true
call POST /api/v1/auth/login -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg id "$ADMIN_LOGIN_ID" --arg pw "$ADMIN_PASSWORD" '{loginId: $id, password: $pw}')" -o /dev/null -w '%{http_code}\n'
curl -sS -b "$JAR" -c "$JAR" -o /dev/null "$API/api/v1/auth/me"

echo "== 2. 수집 끝 기록 → 그래프 보강"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
call POST /api/v1/iac/jobs/collect-graph/runs -H 'Content-Type: application/json' \
  -d "{\"status\":\"SUCCEEDED\",\"startedAt\":\"$now\",\"finishedAt\":\"$now\",\"stats\":{}}"; echo
for _ in $(seq 1 30); do
  checked=$(call GET /api/v1/iac/summary | jq -r '.lastFullCheckAt // empty')
  [ -n "$checked" ] && break
  sleep 2
done
call GET /api/v1/iac/summary | jq -c '{metrics, severityCounts}'

echo "== 3. PR 등록 + plan 업로드"
for pr in 58:58 60:imdsv2 61:nochange; do
  number=${pr%%:*}; plan=${pr#*:}
  sha=$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')
  run=$(call POST /api/v1/iac/runs -H 'Content-Type: application/json' \
    -d "{\"repo\":\"Logssey/infrastructure\",\"prNumber\":$number,\"headSha\":\"$sha\",\"gate\":{\"status\":\"PASSED\",\"findings\":[]}}" | jq -r .runId)
  call PUT "/api/v1/iac/runs/$run/plan" -H 'Content-Type: application/gzip' --data-binary "@$PLANS/$plan.json.gz" | jq -c .
done

echo "== 결과"
for number in 58 60 61; do
  for _ in $(seq 1 30); do
    status=$(call GET "/api/v1/iac/prs/$number" | jq -r .status)
    [ "$status" = DONE ] || [ "$status" = ERROR ] && break
    sleep 2
  done
  call GET "/api/v1/iac/prs/$number" | jq -c '{number, status, verdict, highestSeverity, changes: (.paths | length), resources}'
done

echo "== 4. main 점검 (드리프트)"
sha=$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')
run=$(call POST /api/v1/iac/runs -H 'Content-Type: application/json' \
  -d "{\"repo\":\"Logssey/infrastructure\",\"headSha\":\"$sha\",\"trigger\":\"PUSH\",\"gate\":{\"status\":\"PASSED\",\"findings\":[]}}" | jq -r .runId)
call PUT "/api/v1/iac/runs/$run/plan" -H 'Content-Type: application/gzip' --data-binary "@$PLANS/drift-dns.json.gz" | jq -c .
for _ in $(seq 1 30); do
  [ "$(call GET "/api/v1/iac/runs/$run" | jq -r .status)" = DONE ] && break
  sleep 2
done
call GET /api/v1/iac/drifts | jq -c '.[] | {ruleId, severity, address, attributes}'
