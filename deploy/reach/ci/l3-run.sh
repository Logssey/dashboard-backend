#!/usr/bin/env bash
# L3 run (PRD FR-14): starts the scanned image with the JaCoCo agent next to the services its scenario lists
# (database, cache), sends the scenario's requests and keeps what ran, cut into segments: "startup" and one per
# scenario step. It only records. reach-scan.sh turns the segments into reports and matches them after L2
# (verdict/l3.py); a rescan can match the same segments again without running the app.
#
#   IMAGE_REF=<registry>/<repo>@sha256:<digest> JAR=image-jar/app.jar SCENARIO=service/.reach/l3-scenario.json \
#   JACOCO_HOME=<dir with jacocoagent.jar, jacococli.jar> OUT=reach-out/l3 bash deploy/reach/ci/l3-run.sh
#
# JAR is the app jar copied out of the same image; its package names give the recording scope: java.util.* and
# every package of the app and its libraries (l3_runner.py scope).
# The scenario (verdict/l3_runner.py) is data from the service repo: services, app environment, requests.
# The containers get only that environment and generated throwaway secrets, never a runner secret; they run on
# their own Docker network, and only the app port and the agent port are published, on 127.0.0.1.
# The image and the scenario are untrusted (a PR builds them): nothing the containers write is read from disk
# (the agent is read over its port by jacococli), and their log lines are printed so that they cannot start a
# workflow command.
#
# Writes OUT/segments/<id>.exec (execution data), OUT/steps.json (per step: statuses only) and OUT/run.json
# (the evidence of the run: image, scenario version, setting names, requests, time, scope).
# In GitHub Actions also the step outputs segments and run. A failed run leaves no segments and no run.json.
# Needs: bash, docker, curl, jq, python3, java 21.
set -Eeuo pipefail

: "${IMAGE_REF:?IMAGE_REF=<image reference to run>}"
: "${JAR:?JAR=<app jar copied out of that image>}"
: "${SCENARIO:?SCENARIO=<the service repo scenario, .reach/l3-scenario.json>}"
: "${JACOCO_HOME:?JACOCO_HOME=<dir with jacocoagent.jar and jacococli.jar, see install-tools.sh>}"
OUT="${OUT:-$PWD/reach-out/l3}"
REACH_HOME="${REACH_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
RUNNER="$REACH_HOME/reach-analyzer/verdict/l3_runner.py"
AGENT_PORT=36300   # l3_runner.py AGENT_PORT

# untrusted text for the (public) log: no control characters, no GitHub workflow command
plain() { LC_ALL=C tr -d '\000-\010\013-\037\177' | sed -e 's/::/: :/g' -e 's/##\[/## [/g'; }
log() { echo "[l3] $*" | plain >&2; }
started=$SECONDS
RUN="reach-l3-$$-$RANDOM"
WORK="$(mktemp -d)"
DONE=""
cleanup() {
  docker ps -aq --filter "label=reach-l3=$RUN" | xargs -r docker rm -f > /dev/null 2>&1 || true
  docker network rm "$RUN" > /dev/null 2>&1 || true
  rm -rf "$WORK"
  # a failed run leaves nothing a later step could upload or match
  [ -n "$DONE" ] || rm -rf "$OUT/segments" "$OUT/run.json"
}
trap cleanup EXIT

[ -f "$JAR" ] || { log "JAR not found: $JAR"; exit 2; }
for f in jacocoagent.jar jacococli.jar; do
  [ -f "$JACOCO_HOME/$f" ] || { log "$f not in JACOCO_HOME=$JACOCO_HOME"; exit 2; }
done
python3 "$RUNNER" validate "$SCENARIO"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rm -rf "$OUT/segments" "$OUT/steps.json" "$OUT/run.json"

# ---- recording scope; the Java release picks the classes of multi-release jars when the reports are made
# (temurin images set JAVA_VERSION=jdk-21.0.x+y)
release=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE_REF" \
  | sed -n 's/^JAVA_VERSION=[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -1)
release=${release:-21}
scope=$(python3 "$RUNNER" scope --jar "$JAR")
log "Java $release, recording $scope"

# ---- services
docker network create --label "reach-l3=$RUN" "$RUN" > /dev/null
mapfile -t services < <(jq -r '.services[]?.name' "$SCENARIO")
for svc in "${services[@]}"; do
  image=$(jq -r --arg n "$svc" '.services[] | select(.name == $n) | .image' "$SCENARIO")
  python3 "$RUNNER" env "$SCENARIO" --service "$svc" > "$WORK/$svc.env"
  docker run -d --name "$RUN-$svc" --network "$RUN" --network-alias "$svc" --label "reach-l3=$RUN" \
    --env-file "$WORK/$svc.env" "$image" > /dev/null
  log "service $svc ($image)"
done
for svc in "${services[@]}"; do
  mapfile -t ready < <(jq -r --arg n "$svc" '.services[] | select(.name == $n) | .ready[]?' "$SCENARIO")
  [ "${#ready[@]}" -gt 0 ] || continue
  for _ in $(seq 1 60); do
    docker exec "$RUN-$svc" "${ready[@]}" > /dev/null 2>&1 && continue 2
    sleep 2
  done
  log "service $svc did not become ready"
  exit 1
done

# ---- the app with the agent
port=$(jq -r '.app.port' "$SCENARIO")
ready_path=$(jq -r '.app.ready.path' "$SCENARIO")
ready_status=$(jq -r '.app.ready.status // 200' "$SCENARIO")
timeout=$(jq -r '.app.startTimeoutSeconds // 180' "$SCENARIO")
python3 "$RUNNER" env "$SCENARIO" --app > "$WORK/app.env"   # generated secrets: only here, removed on exit
agent="-javaagent:/reach-jacoco/jacocoagent.jar=output=tcpserver,address=*,port=$AGENT_PORT"
agent+=",inclbootstrapclasses=true,includes=$scope"
observed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
app_started=$SECONDS
docker run -d --name "$RUN-app" --network "$RUN" --label "reach-l3=$RUN" \
  -p "127.0.0.1::$port" -p "127.0.0.1::$AGENT_PORT" -v "$JACOCO_HOME:/reach-jacoco:ro" \
  --env-file "$WORK/app.env" -e "JAVA_TOOL_OPTIONS=$agent" "$IMAGE_REF" > /dev/null
host_port=$(docker port "$RUN-app" "$port/tcp" | head -1 | sed 's/.*://')
agent_port=$(docker port "$RUN-app" "$AGENT_PORT/tcp" | head -1 | sed 's/.*://')
base="http://127.0.0.1:$host_port"
code=000
while [ $((SECONDS - app_started)) -lt "$timeout" ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$base$ready_path" || true)
  [ "$code" = "$ready_status" ] && break
  if [ "$(docker inspect -f '{{.State.Running}}' "$RUN-app")" != true ]; then
    break
  fi
  sleep 2
done
if [ "$code" != "$ready_status" ]; then
  # startup log of a throwaway app with the scenario's environment; no runner secret is in it
  log "app not ready ($ready_path answered $code); last log lines:"
  docker logs --tail 40 "$RUN-app" 2>&1 | plain | cut -c1-300 >&2 || true
  exit 1
fi
start_seconds=$((SECONDS - app_started))
log "app ready in ${start_seconds}s"

# ---- scenario: the agent is read and reset when it starts ("startup") and after every step
python3 "$RUNNER" run "$SCENARIO" --base-url "$base" --out "$OUT/steps.json" \
  --dump-to "$OUT/segments" --jacoco-cli "$JACOCO_HOME/jacococli.jar" --agent "127.0.0.1:$agent_port"
docker stop -t 20 "$RUN-app" > /dev/null || true

digest="${IMAGE_REF##*@}"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || digest=""
jq -n --arg observed "$observed_at" --arg digest "$digest" --arg scope "$scope" \
  --argjson release "$release" --argjson start "$start_seconds" --argjson seconds "$((SECONDS - started))" \
  --arg jacoco "$(java -jar "$JACOCO_HOME/jacococli.jar" version 2> /dev/null | head -1)" \
  --slurpfile steps "$OUT/steps.json" '
  {observationMethod: "COVERAGE", observedAt: $observed, scenario: $steps[0].scenario,
   build: (if $digest != "" then {imageDigest: $digest} else {} end),
   configKeys: $steps[0].configKeys,
   invocations: [$steps[0].steps[] | {segment, name, request: (.method + " " + .path), count, ok, failed, skipped}],
   requests: $steps[0].requests, scope: $scope, javaRelease: $release, jacoco: $jacoco,
   appStartSeconds: $start, durationSeconds: $seconds}' > "$OUT/run.json"
log "done in $((SECONDS - started))s: $(jq -c .requests "$OUT/run.json"), $(find "$OUT/segments" -name '*.exec' | wc -l) segments"

DONE=1
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "segments=$OUT/segments"; echo "run=$OUT/run.json"; } >> "$GITHUB_OUTPUT"
fi
