#!/usr/bin/env python3
"""Add the disabled Compliance Worker to an existing single-host dashboard deployment.

The script never starts or recreates a container. It backs up every existing file,
writes a shared token without printing it, and validates the resulting Compose and
deploy-script syntax before returning.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import secrets
import shutil
import subprocess
from pathlib import Path


REPOSITORY = "794386801311.dkr.ecr.ap-northeast-1.amazonaws.com/logssey/dashboard-compliance-worker"
PLACEHOLDER_IMAGE = f"{REPOSITORY}@sha256:{'0' * 64}"

COMPOSE_SERVICE = """  # Compliance worker: isolated, no web port, and disabled until workload identity approval.
  compliance-worker:
    image: ${COMPLIANCE_WORKER_IMAGE:?Set COMPLIANCE_WORKER_IMAGE in .env}
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    init: true
    restart: unless-stopped
    stop_grace_period: 45s
    mem_limit: 1g
    cpus: 0.75
    oom_score_adj: 500
    pids_limit: 192
    depends_on: [api]
    network_mode: host
    volumes:
      - type: bind
        source: ./compliance-worker.properties
        target: /run/config/application.properties
        read_only: true
      - type: bind
        source: ./secrets/compliance-worker
        target: /run/secrets
        read_only: true
    tmpfs: ["/tmp:rw,noexec,nosuid,size=192m,uid=1000,gid=1000,mode=0700"]
    logging:
      driver: json-file
      options: {max-size: 10m, max-file: "3"}

"""

WORKER_PROPERTIES = """spring.main.web-application-type=none
logssey.compliance-worker.enabled=false
logssey.compliance-worker.api-base-url=http://127.0.0.1:8080
logssey.compliance-worker.worker-id=dashboard-compliance-worker-1
logssey.compliance-worker.poll-delay=10s
logssey.compliance-worker.heartbeat-delay=60s
logssey.compliance-worker.scan-timeout=45m
logssey.compliance-worker.prowler-executable=prowler
logssey.compliance-worker.aws-region=ap-northeast-1
logging.level.software.amazon.awssdk=OFF
logging.level.org.apache.hc.client5.http.wire=OFF
"""


def replace_once(text: str, needle: str, replacement: str, label: str) -> str:
    if needle not in text:
        raise RuntimeError(f"{label}: expected anchor was not found")
    return text.replace(needle, replacement, 1)


def set_property(text: str, key: str, value: str) -> str:
    lines = text.splitlines()
    replacement = f"{key}={value}"
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = replacement
            return "\n".join(lines) + "\n"
    return text.rstrip() + "\n" + replacement + "\n"


def backup(path: Path, stamp: str) -> None:
    target = path.with_name(f"{path.name}.bak-compliance-{stamp}")
    if not target.exists():
        shutil.copy2(path, target)


def atomic_write(path: Path, content: str, mode: int, uid: int, gid: int) -> None:
    temporary = path.with_name(f".{path.name}.compliance-tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, mode)
    os.chown(temporary, uid, gid)
    os.replace(temporary, path)


def install_token(root: Path) -> None:
    api_token = root / "secrets/api/logssey.compliance.worker-token"
    worker_dir = root / "secrets/compliance-worker"
    worker_token = worker_dir / "logssey.compliance-worker.token"
    worker_dir.mkdir(mode=0o500, parents=True, exist_ok=True)
    os.chown(worker_dir, 1000, 1000)
    os.chmod(worker_dir, 0o500)
    token = api_token.read_text(encoding="utf-8").strip() if api_token.exists() else secrets.token_hex(32)
    if len(token) < 32:
        raise RuntimeError("existing Compliance Worker token is too short")
    atomic_write(api_token, token, 0o400, 10001, 10001)
    atomic_write(worker_token, token, 0o400, 1000, 1000)


def service_range(lines: list[str], service: str) -> tuple[int, int]:
    marker = f"  {service}:"
    start = next((index for index, line in enumerate(lines) if line == marker), None)
    if start is None:
        raise RuntimeError(f"compose: {service} service was not found")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  ")
            and not lines[index].startswith("    ")
            and lines[index].strip()
            and not lines[index].lstrip().startswith("#")
        ),
        len(lines),
    )
    return start, end


def patch_compose(text: str) -> str:
    lines = text.splitlines()
    api_start, api_end = service_range(lines, "api")
    if not any(line.strip().startswith("ports:") for line in lines[api_start:api_end]):
        insert_at = next((index for index in range(api_start + 1, api_end)
                          if lines[index].strip().startswith("volumes:")), api_end)
        lines.insert(insert_at, '    ports: ["127.0.0.1:8080:8080"]')
    try:
        worker_start, worker_end = service_range(lines, "compliance-worker")
    except RuntimeError:
        insertion = COMPOSE_SERVICE.rstrip().splitlines()
        top_level = next(
            (index for index in range(1, len(lines)) if lines[index] and not lines[index].startswith(" ")),
            len(lines),
        )
        lines[top_level:top_level] = [""] + insertion
        return "\n".join(lines).rstrip() + "\n"

    worker = lines[worker_start:worker_end]
    worker = [line for line in worker if line.strip() != "networks: [backend]"]
    if not any(line.strip().startswith("network_mode:") for line in worker):
        depends_on = next(
            (index for index, line in enumerate(worker) if line.strip().startswith("depends_on:")),
            0,
        )
        worker.insert(depends_on + 1, "    network_mode: host")
    lines[worker_start:worker_end] = worker
    return "\n".join(lines).rstrip() + "\n"


def patch_deploy_script(text: str) -> str:
    if "compliance-worker) var=COMPLIANCE_WORKER_IMAGE" in text:
        return text
    text = replace_once(
        text,
        "WORKER_SETTLE=${LOGSSEY_WORKER_SETTLE:-60}\n",
        "WORKER_SETTLE=${LOGSSEY_WORKER_SETTLE:-60}\nCOMPLIANCE_WORKER_SETTLE=${LOGSSEY_COMPLIANCE_WORKER_SETTLE:-20}\n",
        "deploy settle settings",
    )
    text = replace_once(
        text,
        "  worker) var=WORKER_IMAGE container=secret-worker ;;\n",
        "  worker) var=WORKER_IMAGE container=secret-worker ;;\n"
        "  compliance-worker) var=COMPLIANCE_WORKER_IMAGE container=compliance-worker ;;\n",
        "deploy service case",
    )
    text = text.replace("api|frontend|worker sha256:<digest>", "api|frontend|worker|compliance-worker sha256:<digest>")
    text = replace_once(
        text,
        "  if [ \"$service\" = worker ]; then worker_healthy; return; fi\n",
        "  if [ \"$service\" = worker ]; then worker_healthy; return; fi\n"
        "  if [ \"$service\" = compliance-worker ]; then\n"
        "    sleep \"$COMPLIANCE_WORKER_SETTLE\"\n"
        "    local id state\n"
        "    id=$(docker compose ps -q \"$container\") && [ -n \"$id\" ] || return 1\n"
        "    state=$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' \"$id\") || return 1\n"
        "    echo \"compliance worker after ${COMPLIANCE_WORKER_SETTLE}s: running/restarts = $state\"\n"
        "    [ \"$state\" = \"true 0\" ]\n"
        "    return\n"
        "  fi\n",
        "deploy health function",
    )
    text = replace_once(
        text,
        "if recreate && healthy; then\n  record rolled-back\n",
        "if [ \"$service\" = compliance-worker ] && [[ \"$current\" =~ @sha256:0{64}$ ]]; then\n"
        "  docker compose rm -sf \"$container\" >/dev/null 2>&1 || true\n"
        "  record rolled-back\n"
        "  echo \"removed failed initial compliance worker; existing services were not changed\" >&2\n"
        "  exit 1\n"
        "fi\n"
        "if recreate && healthy; then\n  record rolled-back\n",
        "deploy rollback",
    )
    return text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=os.environ.get("LOGSSEY_DIR", "/opt/logssey"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    root = Path(args.root).resolve()
    compose = root / "compose.yaml"
    deploy = root / "deploy.sh"
    api_properties = root / "api.properties"
    env_file = root / ".env"
    for path in (compose, deploy, api_properties, env_file):
        if not path.is_file():
            raise RuntimeError(f"missing required file: {path}")

    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    for path in (compose, deploy, api_properties, env_file):
        backup(path, stamp)

    install_token(root)
    api_text = api_properties.read_text(encoding="utf-8")
    api_text = set_property(api_text, "logssey.compliance.target-key", "reused")
    api_text = set_property(api_text, "logssey.compliance.target-name", "Re:Used")
    api_text = set_property(api_text, "logssey.compliance.execution-enabled", "false")
    api_text = set_property(api_text, "logssey.compliance.connection-tests-enabled", "false")
    api_text = set_property(api_text, "logssey.compliance.worker-lease-seconds", "900")
    api_text = set_property(api_text, "logssey.compliance.worker-retry-delay-seconds", "30")
    atomic_write(api_properties, api_text, 0o644, 0, 0)
    atomic_write(root / "compliance-worker.properties", WORKER_PROPERTIES, 0o444, 0, 0)

    env_text = env_file.read_text(encoding="utf-8")
    env_text = set_property(env_text, "COMPLIANCE_WORKER_IMAGE", PLACEHOLDER_IMAGE)
    atomic_write(env_file, env_text, 0o600, 0, 0)
    atomic_write(compose, patch_compose(compose.read_text(encoding="utf-8")), 0o644, 0, 0)
    atomic_write(deploy, patch_deploy_script(deploy.read_text(encoding="utf-8")), 0o755, 0, 0)

    subprocess.run(["bash", "-n", str(deploy)], check=True)
    subprocess.run(["docker", "compose", "-f", str(compose), "config", "--quiet"], cwd=root, check=True)
    print("Compliance Worker host configuration prepared; execution remains disabled.")


if __name__ == "__main__":
    main()
