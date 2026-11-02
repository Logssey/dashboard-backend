"""Encrypted logical backup and isolated restore drill. No production database is overwritten.

Connection secrets live in a libpq service/password file, never command arguments.
age is an independently installed, reviewed executable. No plaintext dump is written.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone

import psycopg
from psycopg import sql

TABLES = ("secret_jobs", "secret_scan_runs", "secret_credential_sets", "secret_occurrences",
          "secret_response_cases", "secret_audit_events", "secret_risk_evidence",
          "secret_severity_assessments", "flyway_schema_history", "dashboard_users", "assets")
OPTIONAL_TABLES = ("secret_credential_identities", "secret_permission_requests", "secret_permission_observations",
                   "secret_permission_decisions", "secret_worker_heartbeats", "secret_operations_alerts", "secret_operations_alert_events")
REPOSITORY = Path(__file__).resolve().parent.parent
CHECK_CONTEXT = b"logssey-secret-recovery-key-check-v1"


def fail(code):
    raise ValueError(code)


def external(path):
    value = Path(path).resolve()
    if value == REPOSITORY or REPOSITORY in value.parents:
        fail("EXTERNAL_PATH_REQUIRED")
    # Worktrees use a .git file; regular repositories use a directory. Check all
    # resolved ancestors so sibling repos, new child paths and symlinks fail closed.
    for parent in (value, *value.parents):
        marker = parent / ".git"
        if marker.exists() or marker.is_symlink():
            fail("EXTERNAL_PATH_REQUIRED")
    return value


def load_config(path):
    cfg = json.loads(external(path).read_text(encoding="utf-8-sig"))
    for field in ("service_file", "output_dir", "age", "recipient_file", "approved_key_checks_file"):
        cfg[field] = str(external(cfg[field]))
    for name in ("source_service", "restore_admin_service"):
        if name in cfg and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", cfg[name]):
            fail("SERVICE_NAME_INVALID")
    if not cfg.get("keys"):
        fail("HMAC_RECOVERY_KEYS_REQUIRED")
    for key in cfg["keys"]:
        if key.get("kind") not in ("fingerprint", "metadata") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", key.get("version", "")):
            fail("KEY_MANIFEST_INVALID")
        key["file"] = str(external(key["file"]))
    os.environ["PGSERVICEFILE"] = cfg["service_file"]
    return cfg


def connect(service, dbname=None):
    return psycopg.connect("service=" + service, dbname=dbname, connect_timeout=10) if dbname else psycopg.connect("service=" + service, connect_timeout=10)


def key_bundle(cfg):
    baseline = approved_key_checks(cfg)
    result = []
    seen = set()
    for item in cfg["keys"]:
        key = (item["kind"], item["version"])
        if key in seen:
            fail("DUPLICATE_KEY_VERSION")
        seen.add(key)
        encoded = Path(item["file"]).read_bytes().strip()
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError:
            fail("KEY_MATERIAL_INVALID")
        if len(decoded) < 32:
            fail("KEY_MATERIAL_INVALID")
        check = hmac.new(decoded, CHECK_CONTEXT, hashlib.sha256).hexdigest()
        if key not in baseline or not hmac.compare_digest(check, baseline[key]):
            fail("RUNTIME_KEY_BASELINE_MISMATCH")
        result.append({"kind": key[0], "version": key[1], "encoded": encoded, "check": check})
    return result


def approved_key_checks(cfg):
    value = json.loads(external(cfg["approved_key_checks_file"]).read_text(encoding="utf-8-sig"))
    if value.get("format") != "logssey-approved-runtime-keys-v1" or not value.get("approvalRef"):
        fail("APPROVED_RUNTIME_BASELINE_REQUIRED")
    result = {}
    for key in value.get("keys", []):
        if key.get("kind") not in ("fingerprint", "metadata") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", key.get("version", "")) or not re.fullmatch(r"[0-9a-f]{64}", key.get("check", "")):
            fail("RUNTIME_KEY_BASELINE_INVALID")
        identity = key["kind"], key["version"]
        if identity in result:
            fail("RUNTIME_KEY_BASELINE_INVALID")
        result[identity] = key["check"]
    if not result:
        fail("APPROVED_RUNTIME_BASELINE_REQUIRED")
    return result


def db_manifest(db):
    present = tuple(t for t in OPTIONAL_TABLES if db.execute("SELECT to_regclass(%s)", ("public."+t,)).fetchone()[0] is not None)
    counts = {table: db.execute(sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(table))).fetchone()[0] for table in TABLES + present}
    fingerprint = [r[0] for r in db.execute("SELECT DISTINCT fingerprint_key_version FROM secret_credential_sets WHERE fingerprint_key_version IS NOT NULL ORDER BY 1")]
    metadata = [r[0] for r in db.execute("SELECT DISTINCT split_part(external_key_ref,':',2) FROM secret_credential_sets WHERE external_key_ref LIKE 'hmac:%' ORDER BY 1")]
    return {"counts": counts, "fingerprintVersions": fingerprint, "metadataVersions": metadata}


def pipeline(first, second, outfile=None, timeout=1800):
    # Stderr may quote connection settings or database content: report safe codes only.
    source = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    sink = None
    try:
        sink = subprocess.Popen(second, stdin=source.stdout, stdout=outfile or subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        source.stdout.close()
        if sink.wait(timeout=timeout) != 0 or source.wait(timeout=timeout) != 0:
            fail("BACKUP_RESTORE_COMMAND_FAILED")
    finally:
        for proc in (source, sink):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()


def encrypt_bytes(cfg, value, path):
    with path.open("xb") as output:
        completed = subprocess.run([cfg["age"], "--encrypt", "--recipients-file", cfg["recipient_file"]],
                                   input=value, stdout=output, stderr=subprocess.DEVNULL, timeout=60)
    if completed.returncode:
        fail("RECOVERY_BUNDLE_ENCRYPTION_FAILED")


def backup(cfg):
    keys = key_bundle(cfg)
    folder = external(cfg["output_dir"])
    folder.mkdir(parents=True, exist_ok=True)
    bundle = folder / ("backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12])
    bundle.mkdir(mode=0o700)
    captured = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    with connect(cfg["source_service"]) as db:
        db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        snapshot = db.execute("SELECT pg_export_snapshot()").fetchone()[0]
        manifest = db_manifest(db)
        for kind, field in (("fingerprint", "fingerprintVersions"), ("metadata", "metadataVersions")):
            if not set(manifest[field]).issubset({k["version"] for k in keys if k["kind"] == kind}):
                fail("RECOVERY_KEY_VERSION_MISSING")
        dump = bundle / "database.dump.age"
        with dump.open("xb") as output:
            pipeline([cfg["pg_dump"], "--dbname=service=" + cfg["source_service"], "--format=custom", "--snapshot=" + snapshot],
                     [cfg["age"], "--encrypt", "--recipients-file", cfg["recipient_file"]], output)
    manifest.update({"format": "logssey-secret-recovery-v1", "capturedAt": captured,
                     "databaseCiphertextSHA256": file_hash(dump),
                     "keys": [{k: item[k] for k in ("kind", "version", "check")} for item in keys]})
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        add_member(archive, "manifest.json", json.dumps(manifest).encode())
        for key in keys:
            add_member(archive, "keys/" + key["kind"] + "-" + key["version"] + ".b64", key["encoded"])
    encrypt_bytes(cfg, stream.getvalue(), bundle / "recovery-keys.tar.age")
    summary = {"status": "PASSED", "bundle": bundle.name, "capturedAt": captured,
               "backupSeconds": round(time.monotonic() - started, 3), "encryption": "age", "plaintextDumpWritten": False}
    (bundle / "complete.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def add_member(archive, name, content):
    item = tarfile.TarInfo(name)
    item.size, item.mode = len(content), 0o600
    archive.addfile(item, io.BytesIO(content))


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def decrypt_bundle(cfg, folder):
    if not (folder / "complete.json").is_file():
        fail("INCOMPLETE_BACKUP")
    result = subprocess.run([cfg["age"], "--decrypt", "--identity", str(external(cfg["identity_file"])), str(folder / "recovery-keys.tar.age")],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        fail("RECOVERY_BUNDLE_UNAVAILABLE")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        members = archive.getmembers()
        if any(not m.isfile() or not re.fullmatch(r"manifest\.json|keys/(fingerprint|metadata)-[A-Za-z0-9_.-]{1,40}\.b64", m.name) or m.size > 65536 for m in members):
            fail("RECOVERY_BUNDLE_INVALID")
        manifest = json.load(archive.extractfile("manifest.json"))
        if manifest.get("format") != "logssey-secret-recovery-v1" or file_hash(folder / "database.dump.age") != manifest["databaseCiphertextSHA256"]:
            fail("BACKUP_INTEGRITY_FAILED")
        available = dict(cfg)
        available["keys"] = [k for k in cfg["keys"] if Path(k["file"]).is_file()]
        current = {(k["kind"], k["version"]): k for k in key_bundle(available)}
        approved = approved_key_checks(cfg)
        recovered = []
        for key in manifest["keys"]:
            encoded = archive.extractfile("keys/" + key["kind"] + "-" + key["version"] + ".b64").read()
            actual = hmac.new(base64.b64decode(encoded, validate=True), CHECK_CONTEXT, hashlib.sha256).hexdigest()
            known = current.get((key["kind"], key["version"]))
            trusted = approved.get((key["kind"], key["version"]))
            if not trusted or not hmac.compare_digest(actual, trusted) or not hmac.compare_digest(actual, key["check"]) or known and not hmac.compare_digest(actual, known["check"]):
                fail("RECOVERY_KEY_MATERIAL_MISMATCH")
            recovered.append((key["kind"] + "-" + key["version"] + ".b64", encoded))
    return manifest, recovered


def restore_drill(cfg, bundle_name):
    if not re.fullmatch(r"backup-[A-Za-z0-9-]{1,100}", bundle_name):
        fail("BACKUP_NAME_INVALID")
    folder = external(cfg["output_dir"]) / bundle_name
    manifest, recovered_keys = decrypt_bundle(cfg, folder)
    started = time.monotonic()
    service = cfg["restore_admin_service"]
    with connect(service) as admin:
        identity = admin.execute("SELECT current_database(),current_setting('logssey.restore_admin',true)").fetchone()
        if not identity[0].startswith("secret_restore_admin") or identity[1] != "enabled":
            fail("RESTORE_ADMIN_MARKER_REQUIRED")
        if admin.info.host not in cfg.get("allowed_restore_hosts", ["127.0.0.1", "localhost"]):
            fail("RESTORE_HOST_NOT_APPROVED")
        count = admin.execute("SELECT count(*) FROM pg_database WHERE starts_with(datname,'secret_restore_') AND NOT starts_with(datname,'secret_restore_admin')").fetchone()[0]
        if count >= int(cfg.get("max_retained_drills", 2)):
            fail("RESTORE_DRILL_CAPACITY_REQUIRES_OPERATOR")
        name = "secret_restore_" + uuid.uuid4().hex
        admin.commit()
        admin.autocommit = True
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
        admin.execute(sql.SQL("ALTER DATABASE {} SET logssey.restore_drill='enabled'").format(sql.Identifier(name)))
    with connect(service, name) as target:
        if target.execute("SELECT count(*) FROM pg_tables WHERE schemaname='public'").fetchone()[0] != 0:
            fail("RESTORE_TARGET_NOT_EMPTY")
    pipeline([cfg["age"], "--decrypt", "--identity", str(external(cfg["identity_file"])), str(folder / "database.dump.age")],
             [cfg["pg_restore"], "--dbname=service=" + service + " dbname=" + name, "--no-owner", "--no-privileges", "--exit-on-error", "--single-transaction"])
    with connect(service, name) as target:
        restored = db_manifest(target)
        if any(restored["counts"].get(table) != count for table,count in manifest["counts"].items()) or any(restored.get(k) != manifest.get(k) for k in ("fingerprintVersions", "metadataVersions")):
            fail("RESTORE_MANIFEST_MISMATCH")
        if target.execute("SELECT count(*) FROM pg_constraint WHERE contype='f' AND NOT convalidated").fetchone()[0]:
            fail("RESTORE_FOREIGN_KEY_INVALID")
    key_dir = external(cfg["restore_keys_dir"]) / name
    key_dir.mkdir(parents=True, mode=0o700)
    for filename, content in recovered_keys:
        fd = os.open(key_dir / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
    seconds = time.monotonic() - started
    result = {"status": "PASSED", "restoredDatabase": name, "backupCapturedAt": manifest["capturedAt"],
              "restoreSeconds": round(seconds, 3), "countsVerified": True, "keyMaterialVersionsVerified": True,
              "foreignKeysVerified": True, "plaintextDumpWritten": False, "productionDatabaseOverwritten": False}
    result["recoveryKeyFilesWritten"] = len(recovered_keys)
    result["verifiedTables"] = sorted(manifest["counts"])
    result["backupAgeSeconds"] = round((datetime.now(timezone.utc) - datetime.fromisoformat(manifest["capturedAt"])).total_seconds(), 3)
    result["rpoTargetSeconds"] = int(cfg["rpo_seconds"]) if cfg.get("rpo_seconds") else None
    result["rtoTargetSeconds"] = int(cfg["rto_seconds"]) if cfg.get("rto_seconds") else None
    result["rpoStatus"] = "WITHIN_TARGET" if cfg.get("rpo_seconds") else "NOT_CONFIGURED"
    result["rtoStatus"] = "WITHIN_TARGET" if cfg.get("rto_seconds") else "NOT_CONFIGURED"
    if cfg.get("rto_seconds") and seconds > int(cfg["rto_seconds"]):
        result["status"] = "RTO_EXCEEDED"
        result["rtoStatus"] = "EXCEEDED"
    if cfg.get("rpo_seconds") and result["backupAgeSeconds"] > int(cfg["rpo_seconds"]):
        result["status"] = "RPO_EXCEEDED"
        result["rpoStatus"] = "EXCEEDED"
    (folder / ("restore-" + name + ".json")).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def tick(cfg):
    interval = int(cfg.get("backup_interval_seconds", 0))
    restore_interval = int(cfg.get("restore_interval_seconds", 0))
    if interval < 60 or restore_interval < 60:
        fail("EXPLICIT_BACKUP_AND_DRILL_INTERVALS_REQUIRED")
    if cfg.get("rpo_seconds") and interval > int(cfg["rpo_seconds"]):
        fail("BACKUP_INTERVAL_EXCEEDS_RPO")
    root = external(cfg["output_dir"])
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / "schedule-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    with connect(cfg["source_service"]) as lock:
        if not lock.execute("SELECT pg_try_advisory_lock(731044207014::bigint)").fetchone()[0]:
            return {"status": "PASSED", "reasonCode": "ALREADY_RUNNING"}
        try:
            now = time.time()
            if now - state.get("lastBackupEpoch", 0) >= interval:
                state["backup"] = backup(cfg)
                state["lastBackupEpoch"] = now
                state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            if now - state.get("lastRestoreEpoch", 0) >= restore_interval:
                if not state.get("backup", {}).get("bundle"):
                    fail("NO_COMPLETED_BACKUP")
                state["restore"] = restore_drill(cfg, state["backup"]["bundle"])
                if state["restore"]["status"] != "PASSED":
                    fail(state["restore"]["status"])
                state["lastRestoreEpoch"] = now
            state["status"] = "PASSED"
            state.pop("reasonCode", None)
        except Exception as error:
            state["status"] = "FAILED"
            state["reasonCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z0-9_]{1,100}", str(error)) else "RECOVERY_OPERATION_FAILED"
            raise
        finally:
            state["observedAt"] = datetime.now(timezone.utc).isoformat()
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return {"status": state["status"], "scheduledBackup": True, "scheduledRestoreDrill": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "restore-drill", "tick"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--bundle")
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
        result = backup(cfg) if args.action == "backup" else restore_drill(cfg, args.bundle or "") if args.action == "restore-drill" else tick(cfg)
        print(json.dumps(result))
        return 0 if result["status"] == "PASSED" else 1
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z0-9_]{1,100}", str(error)) else "RECOVERY_OPERATION_FAILED"
        print(json.dumps({"status": "FAILED", "reasonCode": code}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
