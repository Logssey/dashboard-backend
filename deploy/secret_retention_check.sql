-- Dry-run only. No run, finding, credential, evidence or audit row is deleted.
BEGIN TRANSACTION READ ONLY;
SELECT false AS ledger_purge_enabled,
       (SELECT count(*) FROM secret_query_snapshots WHERE expires_at<=clock_timestamp()) AS expired_temporary_snapshots,
       (SELECT count(*) FROM secret_query_snapshots WHERE expires_at>clock_timestamp()) AS active_temporary_snapshots,
       (SELECT count(*) FROM secret_audit_events) AS audit_rows_retained,
       (SELECT count(*) FROM secret_severity_assessments) AS assessment_rows_retained,
       (SELECT count(*) FROM secret_risk_evidence) AS risk_evidence_rows_retained;
-- A source/run can remain pinned by historical facts even after a case is closed.
SELECT conrelid::regclass AS referencing_table,confrelid::regclass AS referenced_table,
       conname,confdeltype AS on_delete_action
FROM pg_constraint WHERE contype='f' AND confrelid IN(
  'secret_jobs'::regclass,'secret_scan_runs'::regclass,'secret_occurrences'::regclass,
  'secret_risk_evidence'::regclass,'secret_severity_assessments'::regclass,
  'secret_command_idempotency'::regclass)
ORDER BY referenced_table::text,referencing_table::text,conname;
SELECT event_object_table,trigger_name,event_manipulation
FROM information_schema.triggers WHERE event_object_table IN(
  'secret_audit_events','secret_risk_evidence','secret_severity_assessments','secret_operations_alert_events')
ORDER BY event_object_table,trigger_name,event_manipulation;
COMMIT;
