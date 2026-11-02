"""Produce a non-secret key check from an actual deployed key mount.

This output is not an approval. An operator must verify legacy provenance and keep
the approved baseline separately from editable backup configuration.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--key-file", required=True)
parser.add_argument("--kind", required=True, choices=("fingerprint", "metadata"))
parser.add_argument("--version", required=True)
args = parser.parse_args()
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", args.version):
    raise SystemExit("KEY_VERSION_INVALID")
try:
    path = Path(args.key_file).resolve()
    if any((parent / ".git").exists() or (parent / ".git").is_symlink() for parent in (path, *path.parents)):
        raise SystemExit("KEY_PATH_INSIDE_GIT")
    key = base64.b64decode(path.read_bytes().strip(), validate=True)
    if len(key) < 32:
        raise ValueError()
except (OSError, ValueError):
    raise SystemExit("KEY_MATERIAL_INVALID")
print(json.dumps({"kind": args.kind, "version": args.version,
                  "check": hmac.new(key, b"logssey-secret-recovery-key-check-v1", hashlib.sha256).hexdigest()}))
