ALTER TABLE secret_risk_evidence ALTER COLUMN evidence_ref DROP NOT NULL;
ALTER TABLE secret_risk_evidence ADD CONSTRAINT ck_secret_risk_manual_reference CHECK(record_kind<>'ASSERTION' OR source_kind<>'MANUAL' OR evidence_ref IS NOT NULL);
CREATE FUNCTION secret_risk_reference_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ref JSONB; parent_id BIGINT; parent_version BIGINT; permitted BOOLEAN; o secret_occurrences%ROWTYPE;
BEGIN
 SELECT * INTO o FROM secret_occurrences WHERE occurrence_id=NEW.occurrence_id;
 IF jsonb_array_length(NEW.source_refs)>30 THEN RAISE EXCEPTION 'RISK_REFERENCE_LIMIT' USING ERRCODE='23514';END IF;
 FOR ref IN SELECT jsonb_array_elements(NEW.source_refs) LOOP
  IF jsonb_typeof(ref)<>'object' OR NOT ref ?& ARRAY['type','id','version','role'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(ref) k WHERE k NOT IN('type','id','version','role')) THEN RAISE EXCEPTION 'RISK_REFERENCE_SCHEMA' USING ERRCODE='23514';END IF;
  parent_id:=(ref->>'id')::bigint;parent_version:=(ref->>'version')::bigint;permitted:=false;
  IF parent_id<=0 OR parent_version<0 OR ref->>'role' NOT IN('ASSERTS','BINDS_IDENTITY','CLASSIFIES','LIMITS') THEN RAISE EXCEPTION 'RISK_REFERENCE_SCHEMA' USING ERRCODE='23514';END IF;
  CASE ref->>'type'
   WHEN 'VALIDATION_ATTEMPT' THEN SELECT ref->>'role'='BINDS_IDENTITY' AND parent_version=NEW.credential_revision AND EXISTS(SELECT 1 FROM secret_validation_attempts WHERE attempt_id=parent_id AND occurrence_id=NEW.occurrence_id AND credential_set_id=NEW.credential_set_id AND credential_revision=parent_version AND evidence_version=1 AND attempt_state='COMPLETED' AND result='VALID' AND provider_checked_at IS NOT NULL) INTO permitted;
   WHEN 'RISK_EVIDENCE' THEN SELECT ref->>'role'='CLASSIFIES' AND EXISTS(SELECT 1 FROM secret_current_risk_evidence WHERE evidence_id=parent_id AND occurrence_id=NEW.occurrence_id AND kind='ASSET_CLASSIFICATION') AND parent_version=1 INTO permitted;
   WHEN 'ASSET' THEN permitted:=ref->>'role'='CLASSIFIES' AND parent_id=o.asset_id AND parent_version=1;
   WHEN 'INVESTIGATION_HISTORY' THEN SELECT ref->>'role' IN('ASSERTS','LIMITS') AND EXISTS(SELECT 1 FROM secret_investigation_history h JOIN secret_investigation_tasks t USING(task_id) JOIN secret_investigation_history original ON original.history_id=(h.safe_changes->>'acceptedHistoryId')::bigint AND original.task_id=t.task_id WHERE h.history_id=parent_id AND h.task_version=parent_version AND h.event_type='EVIDENCE_ACCEPTED' AND original.event_type='EVIDENCE_ADDED' AND original.safe_changes->>'evidenceKind'='PROVIDER_REFERENCE' AND t.target_type='OCCURRENCE' AND t.occurrence_id=NEW.occurrence_id AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=h.actor_user_id AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=o.connection_id))) INTO permitted;
   WHEN 'RUN_SCOPE' THEN SELECT NEW.source_kind='PROVIDER_OBSERVATION' AND EXISTS(SELECT 1 FROM secret_run_scopes WHERE run_scope_id=parent_id AND scope_id=NEW.scope_id AND scope_revision=parent_version AND collection_status='SUCCEEDED') INTO permitted;
   ELSE permitted:=false;
  END CASE;
  IF permitted IS DISTINCT FROM true THEN RAISE EXCEPTION 'RISK_REFERENCE_PARENT' USING ERRCODE='23514';END IF;
 END LOOP;RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_reference_guard BEFORE INSERT ON secret_risk_evidence FOR EACH ROW EXECUTE FUNCTION secret_risk_reference_guard();
CREATE TABLE secret_severity_policies (
 policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 policy_version VARCHAR(80) NOT NULL UNIQUE,
 state VARCHAR(10) NOT NULL CHECK(state IN ('DRAFT','ACTIVE','RETIRED')),
 engine_version VARCHAR(80) NOT NULL,
 normalizer_version VARCHAR(80) NOT NULL,
 freshness_profile_version VARCHAR(80) NOT NULL,
 freshness_profile JSONB NOT NULL,
 permission_mapping_manifest JSONB NOT NULL,
 content_hash BYTEA NOT NULL CHECK(octet_length(content_hash)=32),
 approval_mode VARCHAR(20) NOT NULL CHECK(approval_mode IN ('RELEASE_REVIEW','USER_APPROVAL')),
 release_ref VARCHAR(120),
 created_by_user_id BIGINT REFERENCES dashboard_users,
 approved_by_user_id BIGINT REFERENCES dashboard_users,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 retired_at TIMESTAMPTZ,
 valid_from TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 valid_until TIMESTAMPTZ,
 CHECK((approval_mode='RELEASE_REVIEW' AND release_ref IS NOT NULL) OR
 (approval_mode='USER_APPROVAL' AND created_by_user_id IS NOT NULL AND approved_by_user_id IS NOT NULL AND created_by_user_id<>approved_by_user_id)),
 CHECK(valid_until IS NULL OR valid_until>valid_from)
);
CREATE UNIQUE INDEX uq_secret_active_severity_policy ON secret_severity_policies((true)) WHERE state='ACTIVE';
CREATE TABLE secret_severity_rules (
 severity_rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 policy_id BIGINT NOT NULL REFERENCES secret_severity_policies,
 rule_id VARCHAR(10) NOT NULL,
 ordinal SMALLINT NOT NULL CHECK(ordinal>=0),
 conditions JSONB NOT NULL CHECK(jsonb_typeof(conditions)='object'),
 required_evidence JSONB NOT NULL DEFAULT '[]',
 result_status VARCHAR(20) NOT NULL CHECK(result_status IN ('ASSESSED','UNASSESSED','NOT_APPLICABLE')),
 result_severity VARCHAR(10) CHECK(result_severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
 reason_code VARCHAR(80) NOT NULL,
 UNIQUE(policy_id,rule_id), UNIQUE(policy_id,ordinal),
 CHECK((result_status='ASSESSED')=(result_severity IS NOT NULL))
);
INSERT INTO secret_severity_policies(policy_version,state,engine_version,normalizer_version,freshness_profile_version,
 freshness_profile,permission_mapping_manifest,content_hash,approval_mode,release_ref)
VALUES('severity-v2','ACTIVE','severity-engine-v1','risk-normalizer-v1','risk-freshness-v1',
 '{"accessMaxSeconds":21600,"permissionMaxSeconds":86400,"assetMaxSeconds":86400,"manualMaxSeconds":86400,"overrideMaxSeconds":604800,"futureSkewSeconds":300}',
 '{"automatedImpactSupport":"UNSUPPORTED","manualMappingVersion":"manual-evidence-v1","manualCapabilities":["IDENTITY_ADMINISTRATION","SECURITY_SETTINGS_WRITE","RESOURCE_ADMINISTRATION","PRODUCTION_DEPLOY","DATA_WRITE","SENSITIVE_DATA_READ","RESOURCE_READ","TEST_RESOURCE_READ"],"incidentObservers":[],"unknownPermissions":"UNKNOWN","authenticationImpliesImpact":false}',
 sha256(convert_to('severity-v2:reviewed-migration-V27','UTF8')),'RELEASE_REVIEW','MIGRATION_REVIEW:V27');
WITH r(id,n,exposure,ranges,credential,impact,abuse,status,severity) AS (VALUES
 ('R00',0,'NORMAL',NULL::text[],NULL::text,NULL::text,NULL::text,'NOT_APPLICABLE',NULL::text),
 ('R01',1,'ABNORMAL',NULL,NULL,NULL,'CONFIRMED','ASSESSED','CRITICAL'),
 ('R02',2,'ABNORMAL',ARRAY['BROAD'],'CONFIRMED','ADMIN',NULL,'ASSESSED','CRITICAL'),
 ('R03',3,'ABNORMAL',ARRAY['BOUNDED'],'CONFIRMED','ADMIN',NULL,'ASSESSED','HIGH'),
 ('R04',4,'ABNORMAL',ARRAY['BROAD','BOUNDED'],'CONFIRMED','IMPORTANT',NULL,'ASSESSED','HIGH'),
 ('R05',5,'ABNORMAL',ARRAY['BROAD','BOUNDED'],'CONFIRMED','LIMITED',NULL,'ASSESSED','MEDIUM'),
 ('R06',6,'ABNORMAL',ARRAY['BROAD'],'CONFIRMED','MINIMAL',NULL,'ASSESSED','MEDIUM'),
 ('R07',7,'ABNORMAL',ARRAY['BOUNDED'],'CONFIRMED','MINIMAL',NULL,'ASSESSED','LOW'),
 ('R99',99,NULL,NULL,NULL,NULL,NULL,'UNASSESSED',NULL))
INSERT INTO secret_severity_rules(policy_id,rule_id,ordinal,conditions,result_status,result_severity,reason_code)
SELECT p.policy_id,r.id,r.n,jsonb_build_object(
 'exposure',CASE WHEN r.exposure IS NULL THEN '{"op":"ANY"}'::jsonb ELSE jsonb_build_object('op','EQ','value',r.exposure) END,
 'exposureRange',CASE WHEN r.ranges IS NULL THEN '{"op":"ANY"}'::jsonb ELSE jsonb_build_object('op','IN','values',to_jsonb(r.ranges)) END,
 'credential',CASE WHEN r.credential IS NULL THEN '{"op":"ANY"}'::jsonb ELSE jsonb_build_object('op','EQ','value',r.credential) END,
 'impact',CASE WHEN r.impact IS NULL THEN '{"op":"ANY"}'::jsonb ELSE jsonb_build_object('op','EQ','value',r.impact) END,
 'abuse',CASE WHEN r.abuse IS NULL THEN '{"op":"ANY"}'::jsonb ELSE jsonb_build_object('op','EQ','value',r.abuse) END,
 'validity','{"op":"ANY"}'::jsonb),r.status,r.severity,CASE WHEN r.id='R99' THEN 'EVIDENCE_INCOMPLETE' ELSE 'RULE_MATCHED' END
FROM r CROSS JOIN secret_severity_policies p WHERE p.policy_version='severity-v2';
UPDATE secret_severity_policies SET content_hash=sha256(convert_to(
 freshness_profile::text||permission_mapping_manifest::text||
 (SELECT string_agg(rule_id||conditions::text||result_status||COALESCE(result_severity,''),',' ORDER BY ordinal) FROM secret_severity_rules),'UTF8'));

CREATE TABLE secret_severity_assessments (
 assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 record_kind VARCHAR(20) NOT NULL CHECK(record_kind IN ('AUTO_RESULT','OVERRIDE_PROPOSAL','REVIEW','APPLICATION')),
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,
 occurrence_sequence BIGINT NOT NULL CHECK(occurrence_sequence>0),
 policy_id BIGINT NOT NULL REFERENCES secret_severity_policies,
 matched_rule_id VARCHAR(10),
 assessment_status VARCHAR(20) CHECK(assessment_status IN ('ASSESSED','UNASSESSED','NOT_APPLICABLE')),
 severity VARCHAR(10) CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
 input_snapshot JSONB NOT NULL DEFAULT '{}',
 evidence_refs JSONB NOT NULL DEFAULT '[]',
 reason_codes JSONB NOT NULL DEFAULT '[]',
 missing_reason_codes JSONB NOT NULL DEFAULT '[]',
 input_digest BYTEA CHECK(input_digest IS NULL OR octet_length(input_digest)=32),
 evaluation_as_of TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 evidence_revision BIGINT NOT NULL,
 credential_revision BIGINT NOT NULL,
 scope_revision BIGINT NOT NULL,
 base_auto_assessment_id BIGINT REFERENCES secret_severity_assessments,
 target_assessment_id BIGINT REFERENCES secret_severity_assessments,
 previous_effective_assessment_id BIGINT REFERENCES secret_severity_assessments,
 previous_application_id BIGINT REFERENCES secret_severity_assessments,
 restored_effective_assessment_id BIGINT REFERENCES secret_severity_assessments,
 decision VARCHAR(25) CHECK(decision IN ('APPROVE','REJECT','APPLY','HOLD','EXPIRE_OVERRIDE')),
 reason_code VARCHAR(80) NOT NULL,
 actor_user_id BIGINT REFERENCES dashboard_users,
 writer_service_id VARCHAR(120),
 override_expires_at TIMESTAMPTZ,
 approval_id BIGINT REFERENCES secret_severity_assessments,
 request_job_id BIGINT REFERENCES secret_jobs,
 FOREIGN KEY(policy_id,matched_rule_id) REFERENCES secret_severity_rules(policy_id,rule_id),
 UNIQUE(occurrence_id,occurrence_sequence),
 CHECK((record_kind IN ('AUTO_RESULT','OVERRIDE_PROPOSAL') AND assessment_status IS NOT NULL
  AND ((assessment_status='ASSESSED')=(severity IS NOT NULL)) AND input_digest IS NOT NULL AND evaluation_as_of IS NOT NULL)
  OR(record_kind IN ('REVIEW','APPLICATION') AND assessment_status IS NULL AND severity IS NULL AND input_digest IS NULL AND matched_rule_id IS NULL)),
 CHECK((record_kind='AUTO_RESULT' AND matched_rule_id IS NOT NULL AND actor_user_id IS NULL AND writer_service_id IS NOT NULL AND base_auto_assessment_id IS NULL AND target_assessment_id IS NULL AND decision IS NULL)
 OR(record_kind='OVERRIDE_PROPOSAL' AND matched_rule_id IS NULL AND actor_user_id IS NOT NULL AND base_auto_assessment_id IS NOT NULL AND override_expires_at IS NOT NULL AND decision IS NULL AND assessment_status<>'UNASSESSED')
 OR(record_kind='REVIEW' AND actor_user_id IS NOT NULL AND target_assessment_id IS NOT NULL AND decision IN ('APPROVE','REJECT') AND approval_id IS NULL)
 OR(record_kind='APPLICATION' AND actor_user_id IS NULL AND writer_service_id IS NOT NULL AND target_assessment_id IS NOT NULL AND decision IN ('APPLY','HOLD','EXPIRE_OVERRIDE')))
);
CREATE UNIQUE INDEX uq_secret_auto_assessment ON secret_severity_assessments(occurrence_id,policy_id,input_digest) WHERE record_kind='AUTO_RESULT';
CREATE UNIQUE INDEX uq_secret_override_review ON secret_severity_assessments(target_assessment_id) WHERE record_kind='REVIEW';
CREATE UNIQUE INDEX uq_secret_application_successor ON secret_severity_assessments(previous_application_id) WHERE record_kind='APPLICATION' AND previous_application_id IS NOT NULL;
CREATE UNIQUE INDEX uq_secret_application_root ON secret_severity_assessments(occurrence_id) WHERE record_kind='APPLICATION' AND previous_application_id IS NULL;
CREATE INDEX idx_secret_assessment_history ON secret_severity_assessments(occurrence_id,occurrence_sequence DESC);
CREATE INDEX idx_secret_override_expiry ON secret_severity_assessments(override_expires_at,occurrence_id) WHERE record_kind='OVERRIDE_PROPOSAL';
CREATE FUNCTION secret_severity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o secret_occurrences%ROWTYPE; p secret_severity_assessments%ROWTYPE; a secret_severity_assessments%ROWTYPE; current_app secret_severity_assessments%ROWTYPE; ref BIGINT; effective BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'ASSESSMENT_IMMUTABLE' USING ERRCODE='23514'; END IF;
 SELECT * INTO o FROM secret_occurrences WHERE occurrence_id=NEW.occurrence_id FOR UPDATE;
 IF NEW.credential_set_id<>o.credential_set_id OR NEW.scope_id<>o.scope_id THEN RAISE EXCEPTION 'ASSESSMENT_PARENT_MISMATCH' USING ERRCODE='23514'; END IF;
 FOREACH ref IN ARRAY ARRAY[NEW.target_assessment_id,NEW.base_auto_assessment_id,NEW.previous_effective_assessment_id,NEW.previous_application_id,NEW.approval_id,NEW.restored_effective_assessment_id] LOOP
  IF ref IS NOT NULL AND(ref>=NEW.assessment_id OR NOT EXISTS(SELECT 1 FROM secret_severity_assessments x WHERE x.assessment_id=ref AND x.occurrence_id=NEW.occurrence_id AND x.credential_set_id=NEW.credential_set_id)) THEN RAISE EXCEPTION 'ASSESSMENT_REFERENCE_INVALID' USING ERRCODE='23514';END IF;
 END LOOP;
 IF NEW.target_assessment_id IS NOT NULL THEN
  SELECT * INTO p FROM secret_severity_assessments WHERE assessment_id=NEW.target_assessment_id;
  IF p.occurrence_id<>NEW.occurrence_id OR p.credential_set_id<>NEW.credential_set_id THEN RAISE EXCEPTION 'ASSESSMENT_TARGET_MISMATCH' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.record_kind='REVIEW' AND(p.record_kind<>'OVERRIDE_PROPOSAL' OR p.actor_user_id=NEW.actor_user_id OR p.policy_id<>NEW.policy_id) THEN RAISE EXCEPTION 'INDEPENDENT_REVIEW_REQUIRED' USING ERRCODE='23514'; END IF;
 IF NEW.record_kind='APPLICATION' AND p.record_kind NOT IN('AUTO_RESULT','OVERRIDE_PROPOSAL') THEN RAISE EXCEPTION 'ASSESSMENT_APPLICATION_TARGET' USING ERRCODE='23514';END IF;
 IF NEW.record_kind='APPLICATION' THEN
  SELECT * INTO current_app FROM secret_severity_assessments WHERE occurrence_id=NEW.occurrence_id AND record_kind='APPLICATION' ORDER BY occurrence_sequence DESC LIMIT 1;
  effective:=CASE WHEN current_app.decision='HOLD' THEN current_app.previous_effective_assessment_id WHEN current_app.decision='EXPIRE_OVERRIDE' THEN current_app.restored_effective_assessment_id ELSE current_app.target_assessment_id END;
  IF NEW.previous_application_id IS DISTINCT FROM current_app.assessment_id OR NEW.previous_effective_assessment_id IS DISTINCT FROM effective THEN RAISE EXCEPTION 'STALE_APPLICATION_HEAD' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.record_kind='OVERRIDE_PROPOSAL' AND NOT EXISTS(SELECT 1 FROM secret_severity_assessments x WHERE x.assessment_id=NEW.base_auto_assessment_id AND x.record_kind='AUTO_RESULT' AND x.policy_id=NEW.policy_id AND x.evidence_revision=NEW.evidence_revision) THEN RAISE EXCEPTION 'OVERRIDE_BASELINE_INVALID' USING ERRCODE='23514';END IF;
 IF NEW.record_kind='APPLICATION' AND NEW.decision='APPLY' AND p.record_kind='OVERRIDE_PROPOSAL' THEN
  SELECT * INTO a FROM secret_severity_assessments WHERE assessment_id=NEW.approval_id;
  IF a.record_kind IS DISTINCT FROM 'REVIEW' OR a.decision<>'APPROVE' OR a.target_assessment_id<>p.assessment_id THEN RAISE EXCEPTION 'APPROVAL_REQUIRED' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_severity_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_severity_assessments FOR EACH ROW EXECUTE FUNCTION secret_severity_guard();
CREATE FUNCTION secret_severity_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='secret_severity_rules' THEN
  IF EXISTS(SELECT 1 FROM secret_severity_policies WHERE policy_id IN(NEW.policy_id,OLD.policy_id) AND state<>'DRAFT') THEN RAISE EXCEPTION 'ACTIVE_RULE_IMMUTABLE' USING ERRCODE='23514'; END IF;
 ELSE
  IF OLD.state='DRAFT' AND NEW.state='ACTIVE' AND(NEW.engine_version<>'severity-engine-v1' OR NEW.normalizer_version<>'risk-normalizer-v1'
    OR NOT NEW.freshness_profile ?& ARRAY['accessMaxSeconds','permissionMaxSeconds','assetMaxSeconds','futureSkewSeconds']
    OR EXISTS(SELECT 1 FROM jsonb_each_text(NEW.freshness_profile) f WHERE f.value!~'^[0-9]+$' OR f.value::bigint<=0)
    OR NOT EXISTS(SELECT 1 FROM secret_severity_rules r WHERE r.policy_id=NEW.policy_id AND r.rule_id='R99' AND r.result_status='UNASSESSED' AND r.result_severity IS NULL AND NOT EXISTS(SELECT 1 FROM jsonb_each(r.conditions) c WHERE c.value->>'op'<>'ANY'))
    OR EXISTS(SELECT 1 FROM secret_severity_rules r WHERE r.policy_id=NEW.policy_id AND(NOT r.conditions ?& ARRAY['exposure','exposureRange','credential','impact','abuse','validity'] OR(SELECT count(*) FROM jsonb_object_keys(r.conditions))<>6 OR EXISTS(SELECT 1 FROM jsonb_each(r.conditions) c WHERE c.value->>'op' NOT IN('EQ','IN','ANY') OR c.value->>'op' IS NULL)))) THEN RAISE EXCEPTION 'POLICY_ACTIVATION_INVALID' USING ERRCODE='23514';END IF;
  IF OLD.state='ACTIVE' AND NEW.state NOT IN('ACTIVE','RETIRED') OR OLD.state='RETIRED' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN RAISE EXCEPTION 'POLICY_STATE_TRANSITION_INVALID' USING ERRCODE='23514';END IF;
  IF OLD.state<>'DRAFT' AND (TG_OP='DELETE' OR(to_jsonb(NEW)-ARRAY['state','retired_at','valid_until']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['state','retired_at','valid_until'])) THEN RAISE EXCEPTION 'ACTIVE_POLICY_IMMUTABLE' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN COALESCE(NEW,OLD);
END $$;
CREATE TRIGGER trg_secret_severity_policy_guard BEFORE UPDATE OR DELETE ON secret_severity_policies FOR EACH ROW EXECUTE FUNCTION secret_severity_policy_guard();
CREATE TRIGGER trg_secret_severity_rule_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_severity_rules FOR EACH ROW EXECUTE FUNCTION secret_severity_policy_guard();

CREATE FUNCTION secret_queue_assessment(target BIGINT) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE job BIGINT; o secret_occurrences%ROWTYPE; p BIGINT;
BEGIN
 SELECT * INTO o FROM secret_occurrences WHERE occurrence_id=target FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM secret_credential_sets WHERE credential_set_id=o.credential_set_id AND component_state='METADATA_ONLY') THEN RETURN NULL; END IF;
 SELECT policy_id INTO p FROM secret_severity_policies WHERE state='ACTIVE';
 IF p IS NULL THEN RETURN NULL; END IF;
 SELECT job_id INTO job FROM secret_jobs WHERE kind='ASSESS' AND target_occurrence_id=target AND expected_evidence_revision=o.risk_evidence_revision
  AND(expected_context->>'policyId')::bigint=p AND status IN('PENDING','LEASED') LIMIT 1;
 IF job IS NULL THEN
  INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,expected_evidence_revision,expected_context,scheduled_at,available_at,attempt_no,max_attempts,status)
  VALUES('ASSESS','SEVERITY_ASSESSMENT',o.connection_id,target,o.risk_evidence_revision,jsonb_build_object('policyId',p),clock_timestamp(),clock_timestamp(),0,3,'PENDING') RETURNING job_id INTO job;
 END IF; RETURN job;
END $$;
CREATE FUNCTION secret_risk_queue_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM secret_queue_assessment(NEW.occurrence_id);RETURN NEW;END $$;
CREATE TRIGGER trg_secret_risk_queue AFTER INSERT ON secret_risk_evidence FOR EACH ROW EXECUTE FUNCTION secret_risk_queue_change();
CREATE TRIGGER trg_secret_exposure_queue AFTER INSERT ON secret_exposure_assessments FOR EACH ROW EXECUTE FUNCTION secret_risk_queue_change();

CREATE FUNCTION secret_risk_occurrence_source_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.credential_set_id,NEW.scope_id,NEW.asset_id,NEW.latest_object_version,NEW.presence_status,NEW.exposure_status,NEW.exposure_range,NEW.last_seen_run_id,NEW.policy_recheck_required,NEW.policy_assessed_binding_id)
 IS DISTINCT FROM ROW(OLD.credential_set_id,OLD.scope_id,OLD.asset_id,OLD.latest_object_version,OLD.presence_status,OLD.exposure_status,OLD.exposure_range,OLD.last_seen_run_id,OLD.policy_recheck_required,OLD.policy_assessed_binding_id)
 THEN NEW.risk_evidence_revision:=OLD.risk_evidence_revision+1; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_occurrence_source BEFORE UPDATE ON secret_occurrences FOR EACH ROW EXECUTE FUNCTION secret_risk_occurrence_source_change();
CREATE FUNCTION secret_risk_occurrence_queue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.risk_evidence_revision<>OLD.risk_evidence_revision THEN PERFORM secret_queue_assessment(NEW.occurrence_id); END IF;RETURN NEW;END $$;
CREATE TRIGGER trg_secret_risk_occurrence_queue AFTER UPDATE ON secret_occurrences FOR EACH ROW EXECUTE FUNCTION secret_risk_occurrence_queue();
CREATE TRIGGER trg_secret_risk_new_occurrence AFTER INSERT ON secret_occurrences FOR EACH ROW EXECUTE FUNCTION secret_risk_queue_change();
CREATE FUNCTION secret_risk_shared_source_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='secret_credential_sets' THEN
  IF ROW(NEW.component_state,NEW.credential_revision) IS DISTINCT FROM ROW(OLD.component_state,OLD.credential_revision) THEN
   UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE credential_set_id=NEW.credential_set_id;
  END IF;
 ELSIF TG_TABLE_NAME='secret_connection_scopes' THEN
  IF ROW(NEW.revision,NEW.response_origin_version,NEW.enabled) IS DISTINCT FROM ROW(OLD.revision,OLD.response_origin_version,OLD.enabled) THEN
   UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE scope_id=NEW.scope_id;
  END IF;
 ELSE
  IF NEW.state IS DISTINCT FROM OLD.state THEN UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1;END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_credential_source AFTER UPDATE ON secret_credential_sets FOR EACH ROW EXECUTE FUNCTION secret_risk_shared_source_change();
CREATE TRIGGER trg_secret_risk_scope_source AFTER UPDATE ON secret_connection_scopes FOR EACH ROW EXECUTE FUNCTION secret_risk_shared_source_change();
CREATE TRIGGER trg_secret_risk_policy_source AFTER UPDATE ON secret_severity_policies FOR EACH ROW EXECUTE FUNCTION secret_risk_shared_source_change();
CREATE FUNCTION secret_risk_authority_source_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='assets' THEN
  IF NEW.environment IS DISTINCT FROM OLD.environment THEN UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE asset_id=NEW.asset_id;END IF;
 ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at AND NEW.role='SECURITY' THEN
  UPDATE secret_occurrences o SET risk_evidence_revision=o.risk_evidence_revision+1
  WHERE(NEW.connection_id IS NULL OR o.connection_id=NEW.connection_id)
    AND(EXISTS(SELECT 1 FROM secret_risk_evidence e WHERE e.occurrence_id=o.occurrence_id) OR EXISTS(SELECT 1 FROM secret_severity_assessments a WHERE a.occurrence_id=o.occurrence_id));
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_asset_source AFTER UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION secret_risk_authority_source_change();
CREATE TRIGGER trg_secret_risk_authority_source AFTER UPDATE ON secret_role_grants FOR EACH ROW EXECUTE FUNCTION secret_risk_authority_source_change();
CREATE FUNCTION secret_risk_validation_source_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.attempt_state='COMPLETED' AND(TG_OP='INSERT' OR ROW(NEW.result,NEW.current_eligible,NEW.provider_checked_at) IS DISTINCT FROM ROW(OLD.result,OLD.current_eligible,OLD.provider_checked_at)) THEN
  UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE credential_set_id=NEW.credential_set_id AND(NEW.occurrence_id IS NULL OR occurrence_id=NEW.occurrence_id);
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_validation_source AFTER INSERT OR UPDATE ON secret_validation_attempts FOR EACH ROW EXECUTE FUNCTION secret_risk_validation_source_change();

CREATE VIEW secret_current_occurrence_risks AS
 SELECT o.occurrence_id,l.assessment_id AS latest_assessment_id,l.assessment_status,l.severity,l.matched_rule_id AS rule_id,p.policy_version,
 e.assessment_id AS effective_assessment_id,e.assessment_status AS effective_status,e.severity AS effective_severity,a.reason_code AS application_reason_code,
 COALESCE(a.decision='HOLD' OR e.root_expired,false) AS held,COALESCE(e.root_expired,false) AS override_expired,c.severity AS last_confirmed_severity,c.assessment_id AS last_confirmed_assessment_id,c.created_at AS last_confirmed_at,
 COALESCE(l.assessment_status='UNASSESSED',true) AS unassessed
 FROM secret_occurrences o
 LEFT JOIN LATERAL(SELECT * FROM secret_severity_assessments x WHERE x.occurrence_id=o.occurrence_id AND x.record_kind='AUTO_RESULT' ORDER BY x.occurrence_sequence DESC LIMIT 1)l ON true
 LEFT JOIN secret_severity_policies p ON p.policy_id=l.policy_id
 LEFT JOIN LATERAL(SELECT * FROM secret_severity_assessments x WHERE x.occurrence_id=o.occurrence_id AND x.record_kind='APPLICATION' ORDER BY x.occurrence_sequence DESC LIMIT 1)a ON true
 LEFT JOIN LATERAL(
  WITH RECURSIVE chain AS(
   SELECT x.*,0 AS depth,(x.record_kind='OVERRIDE_PROPOSAL' AND(x.override_expires_at<=clock_timestamp() OR x.evidence_revision<>o.risk_evidence_revision
    OR x.credential_revision<>(SELECT credential_revision FROM secret_credential_sets WHERE credential_set_id=o.credential_set_id)
    OR x.scope_revision<>(SELECT revision FROM secret_connection_scopes WHERE scope_id=o.scope_id)
    OR NOT EXISTS(SELECT 1 FROM secret_severity_policies p WHERE p.policy_id=x.policy_id AND p.state='ACTIVE')
    OR NOT EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=x.actor_user_id AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=o.connection_id))
    OR NOT EXISTS(SELECT 1 FROM secret_severity_assessments r JOIN secret_role_grants g ON g.user_id=r.actor_user_id WHERE r.record_kind='REVIEW' AND r.target_assessment_id=x.assessment_id AND r.decision='APPROVE' AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=o.connection_id))
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(x.evidence_refs) ref WHERE NOT EXISTS(SELECT 1 FROM secret_current_risk_evidence proof WHERE proof.evidence_id=ref::bigint AND proof.occurrence_id=o.occurrence_id AND(proof.expires_at IS NULL OR proof.expires_at>clock_timestamp()))))) AS root_expired
   FROM secret_severity_assessments x WHERE x.assessment_id=CASE WHEN a.decision='HOLD' THEN a.previous_effective_assessment_id WHEN a.decision='EXPIRE_OVERRIDE' THEN a.restored_effective_assessment_id ELSE a.target_assessment_id END
   UNION ALL
   SELECT prior.*,chain.depth+1,chain.root_expired FROM chain
   JOIN LATERAL(SELECT previous_effective_assessment_id FROM secret_severity_assessments application WHERE application.record_kind='APPLICATION' AND application.decision='APPLY' AND application.target_assessment_id=chain.assessment_id ORDER BY occurrence_sequence LIMIT 1)application ON true
   JOIN secret_severity_assessments prior ON prior.assessment_id=application.previous_effective_assessment_id
   WHERE chain.root_expired AND chain.record_kind='OVERRIDE_PROPOSAL' AND chain.depth<100
  )SELECT * FROM chain WHERE NOT root_expired OR depth>0 OR NOT EXISTS(SELECT 1 FROM chain WHERE depth>0) ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,depth LIMIT 1
 )e ON true
 LEFT JOIN LATERAL(SELECT x.severity,x.assessment_id,x.created_at FROM secret_severity_assessments x WHERE x.occurrence_id=o.occurrence_id AND x.record_kind IN('AUTO_RESULT','OVERRIDE_PROPOSAL') AND x.assessment_status='ASSESSED'
 AND(x.record_kind='AUTO_RESULT' OR EXISTS(SELECT 1 FROM secret_severity_assessments r WHERE r.target_assessment_id=x.assessment_id AND r.record_kind='REVIEW' AND r.decision='APPROVE')) ORDER BY x.occurrence_sequence DESC LIMIT 1)c ON true;

-- Existing nonmetadata findings receive DB-only assessment jobs; no collection or authentication runs.
DO $$ DECLARE target BIGINT; BEGIN
 FOR target IN SELECT o.occurrence_id FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id) WHERE k.component_state<>'METADATA_ONLY' LOOP
  PERFORM secret_queue_assessment(target);
 END LOOP;
END $$;
