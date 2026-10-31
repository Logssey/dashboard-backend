"""Render a reviewed worker role baseline. Does not connect to or change a database.

DBA must use a dedicated non-owner role and inspect inherited/PUBLIC privileges.
API grants remain a shared-CNAPP responsibility, not a Secret-only blanket grant.
"""
import argparse
import re

INSERT = "secret_aws_access_key_observations secret_credential_identities secret_credential_sets secret_findings secret_fixture_match_evidence secret_jobs secret_occurrences secret_operations_alert_events secret_operations_alerts secret_permission_observations secret_risk_evidence secret_run_scopes secret_scan_runs secret_severity_assessments secret_snapshot_retirements secret_test_fixture_attestations secret_tool_runs secret_validation_attempts secret_worker_heartbeats".split()
UPDATE = "secret_aws_access_key_observations secret_case_revalidations secret_credential_sets secret_fixture_match_evidence secret_jobs secret_occurrences secret_operations_alerts secret_run_scopes secret_scan_runs secret_tool_runs secret_validation_attempts secret_worker_heartbeats".split()
DELETE = "secret_findings secret_query_snapshots secret_snapshot_retirements".split()


def render(role):
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise ValueError("ROLE_NAME_INVALID")
    quoted = '"' + role + '"'
    lines = ["-- REVIEW ONLY: execute as DBA after schema migration; no role/password creation.",
             "BEGIN;", f"GRANT USAGE ON SCHEMA public TO {quoted};",
             f"GRANT SELECT ON TABLE assets TO {quoted};"]
    # Include current Secret views and tables, never other CNAPP domains.
    lines += ["DO $grant$ DECLARE r record; BEGIN",
              "FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','v','p') AND starts_with(c.relname,'secret_') LOOP",
              "EXECUTE format('GRANT SELECT ON TABLE public.%I TO %I',r.relname,'" + role + "'); END LOOP;",
              "FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' AND starts_with(c.relname,'secret_') LOOP",
              "EXECUTE format('GRANT USAGE,SELECT ON SEQUENCE public.%I TO %I',r.relname,'" + role + "'); END LOOP; END $grant$;"]
    for operation, tables in (("INSERT", INSERT), ("UPDATE", UPDATE), ("DELETE", DELETE)):
        optional = {"secret_credential_identities", "secret_permission_observations"}
        lines.append(f"GRANT {operation} ON TABLE " + ",".join(t for t in tables if t not in optional) + f" TO {quoted};")
        for table in sorted(set(tables) & optional):
            lines.append("DO $optional$ BEGIN IF to_regclass('public." + table + "') IS NOT NULL THEN EXECUTE 'GRANT " + operation + " ON public." + table + " TO " + quoted + "'; END IF; END $optional$;")
    lines += [f"GRANT UPDATE(next_due_at,last_collection_success_at) ON secret_connections TO {quoted};",
              f"REVOKE UPDATE,DELETE,TRUNCATE ON secret_audit_events,secret_risk_evidence,secret_severity_assessments,secret_operations_alert_events FROM {quoted};",
              f"REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON secret_role_grants,secret_severity_policies,secret_severity_rules,secret_connection_scopes FROM {quoted};",
              "COMMIT;", "-- Check effective privileges, memberships, ownership and PUBLIC grants separately."]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-role", required=True)
    args = parser.parse_args()
    print(render(args.worker_role))
