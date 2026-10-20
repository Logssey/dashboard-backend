-- Immutable run-scope facts and safe probe history. Historical facts are not invented.
ALTER TABLE secret_connection_scopes ADD COLUMN safe_display_alias VARCHAR(80);
ALTER TABLE secret_run_scopes
    ADD COLUMN scope_revision BIGINT,
    ADD COLUMN snapshot_content_type VARCHAR(80),
    ADD COLUMN snapshot_origin VARCHAR(20),
    ADD COLUMN safe_display_alias VARCHAR(80),
    ADD COLUMN evidence_version SMALLINT,
    ADD COLUMN detection_stage_status VARCHAR(20),
    ADD COLUMN detection_reason_code VARCHAR(80),
    ADD COLUMN validation_stage_status VARCHAR(20),
    ADD COLUMN validation_reason_code VARCHAR(80),
    ADD COLUMN validation_required BOOLEAN;

CREATE FUNCTION secret_capture_run_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT s.revision, s.content_type, s.response_origin, s.safe_display_alias
      INTO NEW.scope_revision, NEW.snapshot_content_type, NEW.snapshot_origin, NEW.safe_display_alias
    FROM secret_connection_scopes s
    LEFT JOIN LATERAL (SELECT to_origin FROM secret_scope_origin_decisions
                       WHERE scope_id=s.scope_id ORDER BY version DESC LIMIT 1) d ON true
    WHERE s.scope_id=NEW.scope_id;
    NEW.evidence_version := 1;
    RETURN NEW;
END $$;
CREATE TRIGGER secret_capture_run_scope BEFORE INSERT ON secret_run_scopes
FOR EACH ROW EXECUTE FUNCTION secret_capture_run_scope();

CREATE TABLE secret_connection_probes (
    probe_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    connection_id BIGINT NOT NULL REFERENCES secret_connections,
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users,
    check_kind VARCHAR(40) NOT NULL CHECK (check_kind='IDENTITY_OR_INSTALLATION'),
    status VARCHAR(20) NOT NULL CHECK(status IN ('CONNECTED','FAILED','UNAVAILABLE')),
    reason_code VARCHAR(80) CHECK(reason_code ~ '^[A-Z0-9_]{1,80}$'),
    checked_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_secret_probe_latest ON secret_connection_probes(connection_id, checked_at DESC, probe_id DESC);
CREATE INDEX idx_secret_scope_coverage ON secret_run_scopes(scope_id, scope_revision, run_id DESC);

-- Called only inside a live job lease, after a scope's real consumer completed.
CREATE FUNCTION secret_record_scope_evidence(target BIGINT, validation_failed BOOLEAN)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    s secret_run_scopes%ROWTYPE;
    t secret_tool_runs%ROWTYPE;
    a RECORD;
    candidates BIGINT;
BEGIN
    SELECT * INTO STRICT s FROM secret_run_scopes WHERE run_scope_id=target;
    IF s.evidence_version IS NULL THEN RETURN; END IF;
    IF right(s.snapshot_content_type,9)='_METADATA' THEN
        UPDATE secret_run_scopes SET detection_stage_status='SKIPPED', detection_reason_code='NOT_APPLICABLE_METADATA',
            validation_stage_status='SKIPPED', validation_reason_code='NOT_APPLICABLE_METADATA', validation_required=false
        WHERE run_scope_id=target;
        RETURN;
    END IF;
    SELECT * INTO t FROM secret_tool_runs WHERE run_scope_id=target AND engine='GITLEAKS';
    SELECT count(*) INTO candidates FROM secret_findings WHERE tool_run_id=t.tool_run_id;
    SELECT count(*) AS total,
        count(*) FILTER(WHERE v.result IN ('VALID','INVALID')) AS checked,
        count(*) FILTER(WHERE v.result='UNKNOWN' OR v.result='UNCHECKED' AND v.reason_code NOT IN ('DISABLED','SYNTHETIC_FIXTURE')) AS incomplete,
        count(*) FILTER(WHERE v.reason_code='DISABLED') AS disabled,
        count(*) FILTER(WHERE v.reason_code='SYNTHETIC_FIXTURE') AS fixture
    INTO a FROM secret_validation_attempts v
    WHERE v.run_id=s.run_id AND EXISTS (
        SELECT 1 FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
        WHERE f.tool_run_id=t.tool_run_id AND o.credential_set_id=v.credential_set_id);
    UPDATE secret_run_scopes SET
        detection_stage_status=COALESCE(t.status, CASE WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'SKIPPED' END),
        detection_reason_code=CASE WHEN t.tool_run_id IS NOT NULL THEN t.failure_code
             WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'NO_OBJECTS' ELSE 'DETECTION_NOT_RUN' END,
        validation_stage_status=CASE WHEN validation_failed OR a.incomplete>0 THEN 'PARTIAL'
             WHEN a.checked>0 THEN 'SUCCEEDED' ELSE 'SKIPPED' END,
        validation_reason_code=CASE WHEN validation_failed THEN 'VALIDATION_ATTEMPT_FAILED'
             WHEN a.incomplete>0 THEN 'VALIDATION_INCONCLUSIVE' WHEN a.checked>0 THEN NULL
             WHEN a.disabled>0 THEN 'VALIDATION_DISABLED' WHEN a.fixture>0 THEN 'SYNTHETIC_FIXTURE'
             WHEN candidates=0 THEN 'NO_CANDIDATES' ELSE 'NO_SUPPORTED_VALIDATOR' END,
        validation_required=(validation_failed OR a.checked>0 OR a.incomplete>0)
    WHERE run_scope_id=target;
END $$;

CREATE VIEW secret_scope_outcomes AS
SELECT rs.*,
    CASE WHEN evidence_version IS NULL THEN 'UNKNOWN'
         WHEN j.status='CANCELLED' AND rs.collection_status='PENDING' THEN 'SKIPPED'
         WHEN j.status='CANCELLED' AND rs.collection_status='RUNNING' THEN 'FAILED'
         WHEN rs.collection_status='PENDING' THEN 'PENDING'
         WHEN rs.collection_status='RUNNING' THEN 'RUNNING'
         WHEN rs.collection_status IN ('FAILED','SKIPPED','PARTIAL') THEN rs.collection_status
         WHEN rs.detection_stage_status IS NULL OR rs.validation_required IS NULL THEN 'UNKNOWN'
         WHEN rs.detection_stage_status NOT IN ('SUCCEEDED','SKIPPED')
           OR (rs.detection_stage_status='SKIPPED' AND rs.detection_reason_code NOT IN ('NOT_APPLICABLE_METADATA','NO_OBJECTS'))
           OR (rs.validation_required AND rs.validation_stage_status<>'SUCCEEDED') THEN 'PARTIAL'
         WHEN rs.object_count IS NULL OR rs.finished_at IS NULL THEN 'UNKNOWN'
         ELSE 'SUCCEEDED' END AS scope_outcome,
    r.connection_id, r.trigger_type, r.requested_at, r.finished_at AS run_finished_at,
    j.kind AS job_kind, j.status AS job_status
FROM secret_run_scopes rs JOIN secret_scan_runs r ON r.run_id=rs.run_id
JOIN secret_jobs j ON j.job_id=r.job_id;
