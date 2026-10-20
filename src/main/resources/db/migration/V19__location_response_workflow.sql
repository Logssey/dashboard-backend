-- Location ownership is independent of the case coordinator. Existing coordinator
-- assignments are not silently expanded into location permissions.
ALTER TABLE secret_case_occurrences
    ADD COLUMN assigned_team VARCHAR(100),
    ADD COLUMN assigned_user_id BIGINT REFERENCES dashboard_users(user_id),
    ADD COLUMN version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    ADD COLUMN action_cycle BIGINT NOT NULL DEFAULT 1 CHECK (action_cycle > 0),
    ADD COLUMN last_material_action_at TIMESTAMPTZ,
    ADD COLUMN actions_completed_at TIMESTAMPTZ;
ALTER TABLE secret_action_records ADD COLUMN action_cycle BIGINT NOT NULL DEFAULT 1;
ALTER TABLE secret_checklist_items
    ADD COLUMN occurrence_id BIGINT,
    ADD CONSTRAINT fk_secret_checklist_location FOREIGN KEY(case_id,occurrence_id)
        REFERENCES secret_case_occurrences(case_id,occurrence_id),
    DROP CONSTRAINT uq_secret_checklist_item,
    ADD CONSTRAINT uq_secret_checklist_item UNIQUE NULLS NOT DISTINCT(case_id,guide_version,item_code,occurrence_id);
INSERT INTO secret_checklist_items(case_id,occurrence_id,guide_version,item_code)
SELECT co.case_id,co.occurrence_id,'S2_V1',codes.code FROM secret_case_occurrences co
CROSS JOIN(VALUES('IDENTIFY_OWNER'),('ROTATE_OR_REVOKE'),('REMOVE_EXPOSURE'),('CHECK_ACCESS_LOGS'))codes(code);
CREATE FUNCTION secret_create_location_checklist() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN
 INSERT INTO secret_checklist_items(case_id,occurrence_id,guide_version,item_code)
 SELECT NEW.case_id,NEW.occurrence_id,'S2_V1',code FROM
 (VALUES('IDENTIFY_OWNER'),('ROTATE_OR_REVOKE'),('REMOVE_EXPOSURE'),('CHECK_ACCESS_LOGS'))codes(code);
 RETURN NEW;
END $$;
CREATE TRIGGER secret_location_checklist AFTER INSERT ON secret_case_occurrences
FOR EACH ROW EXECUTE FUNCTION secret_create_location_checklist();
CREATE TABLE secret_location_activities (
    activity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases(case_id),
    occurrence_id BIGINT,
    activity_type VARCHAR(40) NOT NULL CHECK (activity_type IN
        ('LOCATION_ASSIGNED','ACTION_RECORDED','ACTIONS_COMPLETED','CHECKLIST_CHANGED','COORDINATOR_ASSIGNED')),
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    case_version BIGINT NOT NULL,
    occurrence_version BIGINT,
    reference_id BIGINT,
    reason_code VARCHAR(40),
    happened_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id,occurrence_id) REFERENCES secret_case_occurrences(case_id,occurrence_id)
);
CREATE INDEX idx_secret_location_activities_case ON secret_location_activities(case_id,happened_at DESC,activity_id DESC);
-- Preserve events introduced by other feature migrations.
DO $$ DECLARE old_expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO old_expression FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('
     || old_expression || ') OR event_type IN (''LOCATION_ASSIGNED'',''LOCATION_ACTION_RECORDED'',''LOCATION_ACTIONS_COMPLETED''))';
END $$;
