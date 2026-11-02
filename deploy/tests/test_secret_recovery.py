import importlib.util
import tempfile
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery", root / "secret_recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
grants_spec = importlib.util.spec_from_file_location("grants", root / "render_secret_worker_grants.py")
grants = importlib.util.module_from_spec(grants_spec)
grants_spec.loader.exec_module(grants)


class RecoverySafetyTest(unittest.TestCase):
    def test_secret_config_and_outputs_cannot_reside_in_repository(self):
        with self.assertRaisesRegex(ValueError, "EXTERNAL_PATH_REQUIRED"):
            recovery.external(root / "local-secret.json")

    def test_other_repository_and_worktree_new_child_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "other-repo"
            repo.mkdir()
            (repo / ".git").mkdir()
            with self.assertRaisesRegex(ValueError, "EXTERNAL_PATH_REQUIRED"):
                recovery.external(repo / "not-created" / "restored-key.b64")
            worktree = Path(folder) / "worktree"
            worktree.mkdir()
            (worktree / ".git").write_text("gitdir: elsewhere")
            with self.assertRaisesRegex(ValueError, "EXTERNAL_PATH_REQUIRED"):
                recovery.external(worktree / "new-output")

    def test_symlink_into_a_git_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "repository"
            repo.mkdir()
            (repo / ".git").mkdir()
            link = Path(folder) / "outside-looking-link"
            try:
                link.symlink_to(repo, target_is_directory=True)
            except OSError:
                self.skipTest("Host does not permit test symlink creation")
            with self.assertRaisesRegex(ValueError, "EXTERNAL_PATH_REQUIRED"):
                recovery.external(link / "future-output")

    def test_same_key_version_requires_the_same_material_and_long_random_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.b64"
            import base64
            path.write_bytes(base64.b64encode(b"a" * 32))
            import json, hmac, hashlib
            baseline = Path(folder) / "baseline.json"
            baseline.write_text(json.dumps({"format": "logssey-approved-runtime-keys-v1", "approvalRef": "TICKET:OPS-101", "keys": [{"kind": "fingerprint", "version": "test-v1", "check": hmac.new(b"a" * 32,recovery.CHECK_CONTEXT,hashlib.sha256).hexdigest()}]}))
            cfg = {"approved_key_checks_file": str(baseline), "keys": [{"kind": "fingerprint", "version": "test-v1", "file": str(path)}]}
            first = recovery.key_bundle(cfg)[0]["check"]
            path.write_bytes(base64.b64encode(b"b" * 32))
            with self.assertRaisesRegex(ValueError, "RUNTIME_KEY_BASELINE_MISMATCH"):
                recovery.key_bundle(cfg)
            path.write_bytes(base64.b64encode(b"short"))
            with self.assertRaisesRegex(ValueError, "KEY_MATERIAL_INVALID"):
                recovery.key_bundle(cfg)

    def test_scheduler_requires_explicit_backup_and_restore_intervals(self):
        with self.assertRaisesRegex(ValueError, "EXPLICIT_BACKUP_AND_DRILL_INTERVALS_REQUIRED"):
            recovery.tick({"backup_interval_seconds": 0, "restore_interval_seconds": 0})

    def test_grants_render_only_cannot_inject_role_or_grant_policy_writes(self):
        with self.assertRaisesRegex(ValueError, "ROLE_NAME_INVALID"):
            grants.render('worker"; DROP SCHEMA public; --')
        text = grants.render("fixture_worker")
        self.assertIn("REVOKE UPDATE,DELETE,TRUNCATE ON secret_audit_events", text)
        self.assertNotIn("GRANT ALL", text)
        self.assertNotIn("CREATE ROLE", text)


if __name__ == "__main__":
    unittest.main()
