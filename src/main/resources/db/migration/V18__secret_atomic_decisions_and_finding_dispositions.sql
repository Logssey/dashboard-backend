-- One immutable decision ID domain for exposure, investigation and Finding corrections.
ALTER TABLE secret_exposure_assessments
    DROP CONSTRAINT secret_exposure_assessments_decision_check,
    DROP CONSTRAINT secret_exposure_assessments_scope_origin_check,
    DROP CONSTRAINT ck_secret_exposure_assessment_reason,
    ALTER COLUMN finding_id DROP NOT NULL,
    ALTER COLUMN finding_rule_id DROP NOT NULL,
    ALTER COLUMN finding_run_id DROP NOT NULL,
    ALTER COLUMN actor_user_id DROP NOT NULL,
    ALTER COLUMN reason_code TYPE VARCHAR(80),
    ADD COLUMN finding_rule_version VARCHAR(100),
    ADD COLUMN scope_version BIGINT,
    ADD COLUMN scope_revision BIGINT,
    ADD COLUMN policy_id BIGINT,
    ADD COLUMN policy_version BIGINT,
    ADD COLUMN policy_binding_id BIGINT REFERENCES secret_scope_policy_bindings(binding_id),
    ADD COLUMN policy_result VARCHAR(10),
    ADD COLUMN decision_source VARCHAR(20) NOT NULL DEFAULT 'HUMAN',
    ADD COLUMN evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN observed_at TIMESTAMPTZ,
    ADD COLUMN automatic_policy_version BIGINT,
    ADD CONSTRAINT ck_secret_decision_type CHECK(decision IN ('NORMAL','ABNORMAL','FALSE_POSITIVE','NEEDS_MORE_INFO')),
    ADD CONSTRAINT ck_secret_decision_origin CHECK(scope_origin IN ('UNCLASSIFIED','TEST','PRODUCTION')),
    ADD CONSTRAINT ck_secret_decision_source CHECK(decision_source IN ('HUMAN','POLICY')),
    ADD CONSTRAINT ck_secret_decision_actor CHECK((decision_source='HUMAN' AND actor_user_id IS NOT NULL)
        OR (decision_source='POLICY' AND actor_user_id IS NULL AND decision='NORMAL' AND automatic_policy_version IS NOT NULL)),
    ADD CONSTRAINT ck_secret_decision_evidence CHECK(jsonb_typeof(evidence_refs)='array'),
    ADD CONSTRAINT ck_secret_decision_policy_result CHECK(policy_result IS NULL OR policy_result IN ('ALLOWED','DENIED','UNKNOWN')),
    ADD CONSTRAINT fk_secret_decision_policy FOREIGN KEY(policy_id,policy_version) REFERENCES secret_storage_policies(policy_id,version);
-- Legacy assessments intentionally retain NULL evidence versions: never invent historical proof.
ALTER TABLE secret_response_cases ADD COLUMN opening_decision_id BIGINT REFERENCES secret_exposure_assessments(assessment_id);
ALTER TABLE secret_case_occurrences ADD COLUMN linked_decision_id BIGINT REFERENCES secret_exposure_assessments(assessment_id);

CREATE TABLE secret_finding_dispositions (
    disposition_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_id BIGINT NOT NULL UNIQUE REFERENCES secret_exposure_assessments(assessment_id),
    finding_id BIGINT NOT NULL, occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,
    scope_revision BIGINT NOT NULL, scope_origin_version BIGINT NOT NULL,scope_fingerprint VARCHAR(32) NOT NULL,
    source_object_digest BYTEA NOT NULL CHECK(octet_length(source_object_digest)=32),
    location_digest BYTEA NOT NULL CHECK(octet_length(location_digest)=32),
    object_version VARCHAR(200),rule_id VARCHAR(120) NOT NULL,rule_version VARCHAR(100) NOT NULL,
    engine VARCHAR(20) NOT NULL,engine_version VARCHAR(100) NOT NULL,config_hash VARCHAR(100) NOT NULL,
    protected_evidence_identity BYTEA,identity_key_version VARCHAR(40),issuer VARCHAR(40) NOT NULL,credential_type VARCHAR(80) NOT NULL,
    reason_code VARCHAR(80) NOT NULL CHECK(reason_code IN ('NOT_A_CREDENTIAL','DOCUMENTED_PLACEHOLDER')),
    decision_source VARCHAR(30) NOT NULL CHECK(decision_source IN ('HUMAN','EXACT_EVIDENCE_REUSE')),
    reused_from_disposition_id BIGINT REFERENCES secret_finding_dispositions,
    reviewed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),reuse_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,is_current BOOLEAN NOT NULL DEFAULT true,
    CHECK(reuse_expires_at>created_at AND reuse_expires_at<=created_at+interval '30 days'),
    CHECK((decision_source='HUMAN' AND reused_from_disposition_id IS NULL)
        OR (decision_source='EXACT_EVIDENCE_REUSE' AND reused_from_disposition_id IS NOT NULL)),
    CHECK((protected_evidence_identity IS NULL AND identity_key_version IS NULL)
        OR (protected_evidence_identity IS NOT NULL AND identity_key_version IS NOT NULL))
);
CREATE UNIQUE INDEX uq_secret_current_finding_disposition ON secret_finding_dispositions(finding_id) WHERE is_current;
CREATE INDEX idx_secret_finding_disposition_reuse ON secret_finding_dispositions(scope_id,scope_revision,object_version,reuse_expires_at)
    WHERE is_current AND revoked_at IS NULL AND decision_source='HUMAN';
-- Compatibility for investigation/alert readers; there is only one persistent correction source.
CREATE VIEW secret_finding_corrections AS SELECT disposition_id AS correction_id,decision_id,finding_id,
    occurrence_id,created_at,created_at AS corrected_at,reuse_expires_at AS expires_at,revoked_at
    FROM secret_finding_dispositions WHERE is_current;

CREATE VIEW secret_current_raw_findings AS
SELECT f.finding_id,f.occurrence_id,f.run_id,f.rule_id,f.rule_version,f.detected_at
FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
WHERE o.presence_status='PRESENT' AND s.enabled AND o.last_seen_run_id=f.run_id
 AND f.run_id=(SELECT so.run_id FROM secret_scope_outcomes so WHERE so.scope_id=o.scope_id
    AND so.scope_revision=s.revision AND so.scope_outcome='SUCCEEDED' AND so.job_status='SUCCEEDED'
    ORDER BY so.finished_at DESC NULLS LAST,so.run_id DESC LIMIT 1);

CREATE OR REPLACE VIEW secret_current_valid_findings AS
SELECT f.finding_id,f.occurrence_id,f.run_id,f.rule_id,f.rule_version,f.detected_at
FROM secret_current_raw_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
WHERE EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=o.credential_set_id)
 OR NOT EXISTS(SELECT 1 FROM secret_finding_dispositions d WHERE d.finding_id=f.finding_id
    AND d.occurrence_id=f.occurrence_id AND d.is_current AND d.revoked_at IS NULL AND d.reuse_expires_at>now()
    AND (d.reused_from_disposition_id IS NULL OR EXISTS(SELECT 1 FROM secret_finding_dispositions original
        WHERE original.disposition_id=d.reused_from_disposition_id AND original.revoked_at IS NULL AND original.is_current
          AND original.reuse_expires_at>now())));

-- Exact evidence can be reused only within its original approval lifetime and live reviewer grant.
CREATE VIEW secret_exact_finding_reuse_candidates AS
SELECT DISTINCT ON(f.finding_id) f.finding_id,f.occurrence_id,d.disposition_id
FROM secret_current_raw_findings f JOIN secret_findings finding ON finding.finding_id=f.finding_id
JOIN secret_tool_runs tool ON tool.tool_run_id=finding.tool_run_id
JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
JOIN secret_finding_dispositions d ON d.scope_id=s.scope_id AND d.scope_revision=s.revision
 AND d.scope_origin_version=s.response_origin_version AND d.object_version=o.latest_object_version
 AND d.scope_fingerprint=md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text)
 AND d.source_object_digest=sha256(convert_to(o.source_object_ref,'UTF8'))
 AND d.location_digest=sha256(convert_to(o.location_key,'UTF8'))
 AND d.rule_id=f.rule_id AND d.rule_version=f.rule_version AND d.engine=tool.engine
 AND d.engine_version=tool.engine_version AND d.config_hash=tool.config_hash
 AND d.identity_key_version=c.fingerprint_key_version
 AND d.issuer=c.issuer AND d.credential_type=c.credential_type
 AND d.protected_evidence_identity=coalesce(c.fingerprint,c.candidate_locator)
WHERE d.decision_source='HUMAN' AND d.is_current AND d.revoked_at IS NULL AND d.reuse_expires_at>now()
 AND o.latest_object_version IS NOT NULL AND s.response_origin<>'UNCLASSIFIED'
 AND EXISTS(SELECT 1 FROM secret_scope_origin_decisions od WHERE od.scope_id=s.scope_id
    AND od.version=s.response_origin_version AND od.decision='APPROVED')
 AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=d.reviewed_by_user_id AND g.role='SECURITY'
    AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=o.connection_id))
 AND NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=c.credential_set_id)
 AND NOT EXISTS(SELECT 1 FROM secret_scope_outcomes failure WHERE failure.scope_id=o.scope_id
    AND failure.scope_revision=s.revision AND failure.scope_outcome IN ('PARTIAL','FAILED','SKIPPED','UNKNOWN')
    AND failure.requested_at>o.last_seen_at)
 AND NOT EXISTS(SELECT 1 FROM secret_finding_dispositions already WHERE already.finding_id=f.finding_id
    AND already.is_current AND already.revoked_at IS NULL AND already.reuse_expires_at>now())
ORDER BY f.finding_id,d.created_at DESC,d.disposition_id DESC;

ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK(event_type IN (
 'CASE_OPENED','ASSIGNMENT_CHANGED','REVIEW_RECORDED','RESPONSE_STARTED','CHECKLIST_CHANGED',
 'ACTION_RECORDED','REVALIDATION_REQUESTED','REVALIDATION_REOPENED','CASE_RESOLVED','MANUAL_SCAN_REGISTERED',
 'POLICY_DRAFTED','POLICY_APPROVED','POLICY_RETIRED','CLASSIFICATION_PROPOSED','CLASSIFICATION_APPROVED',
 'CLASSIFICATION_REJECTED','INVESTIGATION_ASSIGNED','INVESTIGATION_EVIDENCE_ADDED','INVESTIGATION_CLOSED',
 'FIXTURE_ATTESTED','CROSS_ALERT_ACKNOWLEDGED','CROSS_ALERT_ASSIGNED','CROSS_ALERT_CLOSED','TRIAGE_DECIDED','CASE_LINKED',
 'FINDING_CORRECTION_REUSED','POLICY_NORMAL_APPLIED','FINDING_CORRECTION_REVOKED'));
ALTER TABLE secret_case_stage_history DROP CONSTRAINT ck_secret_case_stage_reason;
ALTER TABLE secret_case_stage_history ADD CONSTRAINT ck_secret_case_stage_reason CHECK(reason_code IN (
 'RESPONSE_STARTED','EXTERNAL_ACTION_RECORDED','REVALIDATION_PRESENT','POST_ACTION_REVALIDATION','NEW_ABNORMAL_LOCATION'));

-- Called by the worker before fixture reconciliation and after a source/policy approval.
-- The governance lock also serializes this against policy retirement and human decisions.
CREATE FUNCTION secret_apply_storage_policy_defaults(target_run BIGINT DEFAULT NULL) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE candidate RECORD; basis RECORD; original RECORD; new_decision BIGINT; total BIGINT:=0; new_version BIGINT;
BEGIN
 PERFORM pg_advisory_xact_lock(6197611306);
 FOR candidate IN SELECT reuse.* FROM secret_exact_finding_reuse_candidates reuse
   JOIN secret_current_raw_findings raw ON raw.finding_id=reuse.finding_id
   WHERE (target_run IS NULL OR raw.run_id=target_run)
    AND NOT EXISTS(SELECT 1 FROM secret_current_raw_findings independent
      WHERE independent.occurrence_id=reuse.occurrence_id
       AND NOT EXISTS(SELECT 1 FROM secret_exact_finding_reuse_candidates match WHERE match.finding_id=independent.finding_id)
       AND NOT EXISTS(SELECT 1 FROM secret_finding_dispositions done WHERE done.finding_id=independent.finding_id
          AND done.is_current AND done.revoked_at IS NULL AND done.reuse_expires_at>now()))
   ORDER BY reuse.occurrence_id,reuse.finding_id
 LOOP
  SELECT o.*,s.response_origin,s.response_origin_version,s.revision INTO basis FROM secret_occurrences o
    JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE o.occurrence_id=candidate.occurrence_id FOR UPDATE OF o;
  SELECT * INTO original FROM secret_finding_dispositions WHERE disposition_id=candidate.disposition_id;
  IF original.reuse_expires_at<=clock_timestamp() THEN CONTINUE; END IF;
  new_version:=basis.exposure_assessment_version+1;
  INSERT INTO secret_exposure_assessments(occurrence_id,finding_id,finding_rule_id,finding_run_id,finding_rule_version,
    from_status,decision,reason_code,scope_origin,scope_version,scope_revision,actor_user_id,version,evidence_refs,observed_at)
   SELECT basis.occurrence_id,f.finding_id,f.rule_id,f.run_id,f.rule_version,basis.exposure_status,'FALSE_POSITIVE',
      original.reason_code,basis.response_origin,basis.response_origin_version,basis.revision,original.reviewed_by_user_id,
      new_version,jsonb_build_array('POLICY:REUSE-'||original.disposition_id),f.detected_at
   FROM secret_findings f WHERE f.finding_id=candidate.finding_id RETURNING assessment_id INTO new_decision;
  INSERT INTO secret_finding_dispositions(decision_id,finding_id,occurrence_id,scope_id,scope_revision,scope_origin_version,scope_fingerprint,
    source_object_digest,location_digest,object_version,rule_id,rule_version,engine,engine_version,config_hash,
    protected_evidence_identity,identity_key_version,issuer,credential_type,reason_code,decision_source,reused_from_disposition_id,
    reviewed_by_user_id,reuse_expires_at)
   SELECT new_decision,candidate.finding_id,basis.occurrence_id,scope_id,scope_revision,scope_origin_version,scope_fingerprint,
      source_object_digest,location_digest,object_version,rule_id,rule_version,engine,engine_version,config_hash,
      protected_evidence_identity,identity_key_version,issuer,credential_type,reason_code,'EXACT_EVIDENCE_REUSE',disposition_id,
      reviewed_by_user_id,reuse_expires_at FROM secret_finding_dispositions WHERE disposition_id=original.disposition_id;
  UPDATE secret_occurrences SET exposure_assessment_version=new_version WHERE occurrence_id=basis.occurrence_id;
  INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,safe_changes)
   VALUES('FINDING_CORRECTION_REUSED',original.reviewed_by_user_id,'OCCURRENCE',basis.occurrence_id,new_version,
      jsonb_build_object('decisionId',new_decision,'originalDecisionId',original.decision_id));
  UPDATE secret_query_snapshots snapshot SET expires_at=GREATEST(now(),snapshot.created_at+interval '1 microsecond') WHERE snapshot.expires_at>now()
   AND EXISTS(SELECT 1 FROM secret_snapshot_location_memberships m WHERE m.snapshot_id=snapshot.snapshot_id AND m.occurrence_id=basis.occurrence_id);
  total:=total+1;
 END LOOP;
 FOR candidate IN SELECT o.occurrence_id FROM secret_occurrences o
    JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
    JOIN secret_occurrence_policy_results p ON p.occurrence_id=o.occurrence_id
    WHERE c.component_state='CONFIRMED' AND o.presence_status='PRESENT' AND o.exposure_status='UNKNOWN'
      AND p.policy_result='ALLOWED' AND (target_run IS NULL OR o.last_seen_run_id=target_run)
      AND EXISTS(SELECT 1 FROM secret_storage_policies active WHERE active.policy_id=p.policy_id AND active.version=p.policy_version
          AND active.status='ACTIVE' AND active.valid_from<=clock_timestamp()
          AND (active.valid_until IS NULL OR active.valid_until>clock_timestamp()))
      AND EXISTS(SELECT 1 FROM secret_current_valid_findings f WHERE f.occurrence_id=o.occurrence_id)
      AND EXISTS(SELECT 1 FROM secret_connection_scopes s JOIN secret_scope_origin_decisions source ON source.scope_id=s.scope_id
          AND source.version=s.response_origin_version AND source.decision='APPROVED' WHERE s.scope_id=o.scope_id)
      AND NOT EXISTS(SELECT 1 FROM secret_exposure_assessments human WHERE human.occurrence_id=o.occurrence_id AND human.decision_source='HUMAN')
      AND NOT EXISTS(SELECT 1 FROM secret_scope_outcomes failure WHERE failure.scope_id=o.scope_id
          AND failure.scope_revision=(SELECT revision FROM secret_connection_scopes WHERE scope_id=o.scope_id)
          AND failure.scope_outcome IN ('PARTIAL','FAILED','SKIPPED','UNKNOWN') AND failure.requested_at>o.last_seen_at)
      AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_response_cases rc ON rc.case_id=co.case_id
          WHERE co.occurrence_id=o.occurrence_id AND rc.is_current)
    ORDER BY o.occurrence_id
 LOOP
  SELECT o.*,s.response_origin,s.response_origin_version,s.revision,p.binding_id,p.policy_id,p.policy_version INTO basis
   FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
   JOIN secret_occurrence_policy_results p ON p.occurrence_id=o.occurrence_id
   WHERE o.occurrence_id=candidate.occurrence_id AND o.exposure_status='UNKNOWN' AND p.policy_result='ALLOWED'
    AND EXISTS(SELECT 1 FROM secret_storage_policies active WHERE active.policy_id=p.policy_id AND active.version=p.policy_version
        AND active.status='ACTIVE' AND active.valid_from<=clock_timestamp()
        AND (active.valid_until IS NULL OR active.valid_until>clock_timestamp())) FOR UPDATE OF o;
  IF NOT FOUND THEN CONTINUE; END IF;
  new_version:=basis.exposure_assessment_version+1;
  INSERT INTO secret_exposure_assessments(occurrence_id,finding_id,finding_rule_id,finding_run_id,finding_rule_version,
     from_status,decision,reason_code,scope_origin,scope_version,scope_revision,policy_id,policy_version,policy_binding_id,
     policy_result,decision_source,actor_user_id,automatic_policy_version,version,observed_at)
   SELECT basis.occurrence_id,f.finding_id,f.rule_id,f.run_id,f.rule_version,'UNKNOWN','NORMAL','POLICY_ALLOWED_LOCATION',
     basis.response_origin,basis.response_origin_version,basis.revision,basis.policy_id,basis.policy_version,basis.binding_id,
     'ALLOWED','POLICY',NULL,basis.policy_version,new_version,f.detected_at FROM secret_current_valid_findings f
     WHERE f.occurrence_id=basis.occurrence_id ORDER BY f.finding_id LIMIT 1 RETURNING assessment_id INTO new_decision;
  UPDATE secret_occurrences SET exposure_status='NORMAL',exposure_assessment_version=new_version,
     policy_assessed_binding_id=basis.binding_id,policy_assessed_origin_version=basis.response_origin_version,
     policy_recheck_required=false WHERE occurrence_id=basis.occurrence_id;
  -- The approved policy's independent approver is the human authority; the assessment's actor remains POLICY.
  INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,safe_changes)
   SELECT 'POLICY_NORMAL_APPLIED',p.approved_by_user_id,'OCCURRENCE',basis.occurrence_id,new_version,
      jsonb_build_object('decisionId',new_decision,'policyId',p.policy_id,'policyVersion',p.version)
   FROM secret_storage_policies p WHERE p.policy_id=basis.policy_id AND p.version=basis.policy_version;
  UPDATE secret_query_snapshots snapshot SET expires_at=GREATEST(now(),snapshot.created_at+interval '1 microsecond') WHERE snapshot.expires_at>now()
   AND EXISTS(SELECT 1 FROM secret_snapshot_location_memberships m WHERE m.snapshot_id=snapshot.snapshot_id AND m.occurrence_id=basis.occurrence_id);
  total:=total+1;
 END LOOP;
 RETURN total;
END $$;
