-- Extend the existing investigation model rather than creating a second task queue.
ALTER TABLE secret_investigation_tasks
 ADD COLUMN requested_by_user_id BIGINT REFERENCES dashboard_users,
 ADD COLUMN scope_origin_decision_id BIGINT REFERENCES secret_scope_origin_decisions(decision_id),
 ADD COLUMN policy_binding_id BIGINT REFERENCES secret_scope_policy_bindings(binding_id),
 ADD COLUMN accepted_evidence_history_id BIGINT REFERENCES secret_investigation_history(history_id);
DO $$ DECLARE c RECORD; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='secret_investigation_tasks'::regclass AND contype='c'
  AND (pg_get_expr(conbin,conrelid) LIKE '%resolving_decision_id%'
    OR (pg_get_expr(conbin,conrelid) LIKE '%creation_source%' AND pg_get_expr(conbin,conrelid) NOT LIKE '%human_follow_up_required%'))
 LOOP EXECUTE format('ALTER TABLE secret_investigation_tasks DROP CONSTRAINT %I',c.conname); END LOOP;
END $$;
ALTER TABLE secret_investigation_tasks
 ADD CONSTRAINT ck_secret_investigation_creation CHECK(creation_source IN ('HUMAN_MORE_INFO','AUTO_TEST_ALERT','SCOPE_RESTORE','HUMAN_HANDOFF')),
 ADD CONSTRAINT ck_secret_investigation_closure CHECK(
  (status='OPEN' AND closed_at IS NULL) OR (status='CLOSED' AND closed_at IS NOT NULL
    AND num_nonnulls(resolving_decision_id,restored_run_scope_id,scope_origin_decision_id,policy_binding_id,accepted_evidence_history_id)=1));
DO $$ DECLARE expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO expression FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('
   ||expression||') OR event_type IN (''INVESTIGATION_REQUESTED'',''INVESTIGATION_EVIDENCE_ACCEPTED''))';
END $$;
