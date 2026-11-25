-- Local evidence references record who confirmed what, in the same transaction as the workflow.
-- They do not bypass source provenance, independent approval, or revalidation.
CREATE TABLE secret_internal_records (
 record_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK(record_id BETWEEN 1 AND 9999999999),
 actor_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 target_type VARCHAR(24) NOT NULL CHECK(target_type IN ('CASE','OCCURRENCE','SCOPE','POLICY','INVESTIGATION')),
 target_id BIGINT NOT NULL CHECK(target_id>0),
 target_version BIGINT NOT NULL CHECK(target_version>=0),
 event_code VARCHAR(80) NOT NULL CHECK(event_code ~ '^[A-Z][A-Z0-9_]{0,79}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX secret_internal_records_target ON secret_internal_records(target_type,target_id,record_id);
CREATE TRIGGER secret_internal_record_immutable BEFORE UPDATE OR DELETE ON secret_internal_records
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();

-- A transfer request is not acceptance. The separate review stores the actual acceptance record.
ALTER TABLE secret_case_transfer_evidence ALTER COLUMN accepted_transfer_ref DROP NOT NULL;
ALTER TABLE secret_case_transfer_reviews ADD COLUMN acceptance_ref VARCHAR(120)
 CHECK(acceptance_ref IS NULL OR (decision='APPROVE' AND acceptance_ref ~ '^CHANGE:RECORD-[1-9][0-9]{0,9}$'));
