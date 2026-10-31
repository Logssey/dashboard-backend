-- Worker liveness, internal incident history and append-only audit protection.
CREATE TABLE secret_worker_heartbeats (
 instance_id UUID NOT NULL, component VARCHAR(30) NOT NULL CHECK(component IN('SCHEDULER','EXECUTOR','ASSESSMENT','PERMISSIONS','MAINTENANCE')),
 deployment_key VARCHAR(100) NOT NULL CHECK(deployment_key ~ '^[A-Za-z0-9._-]{1,100}$'),
 enabled BOOLEAN NOT NULL, state VARCHAR(20) NOT NULL CHECK(state IN('IDLE','RUNNING','FAILED')),
 poll_interval_ms BIGINT NOT NULL CHECK(poll_interval_ms BETWEEN 1000 AND 86400000),
 started_at TIMESTAMPTZ NOT NULL, last_heartbeat_at TIMESTAMPTZ NOT NULL,
 last_poll_started_at TIMESTAMPTZ, last_poll_finished_at TIMESTAMPTZ, last_success_at TIMESTAMPTZ,
 active_job_id BIGINT, error_code VARCHAR(80) CHECK(error_code ~ '^[A-Z0-9_]{1,80}$'),
 PRIMARY KEY(instance_id,component)
);
CREATE INDEX idx_secret_worker_component_heartbeat ON secret_worker_heartbeats(component,last_heartbeat_at DESC);
CREATE TABLE secret_operations_alerts (
 alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dedupe_key VARCHAR(150) NOT NULL UNIQUE CHECK(dedupe_key ~ '^[A-Z0-9_:.-]{1,150}$'),
 kind VARCHAR(40) NOT NULL CHECK(kind IN('COMPONENT_STALE','POLL_FAILED','QUEUE_STALLED','LEASE_EXPIRED','RUN_FAILED','RUN_PARTIAL')),
 subject_type VARCHAR(20) NOT NULL CHECK(subject_type IN('COMPONENT','CONNECTION','GLOBAL')),
 subject_id VARCHAR(100) NOT NULL CHECK(subject_id ~ '^[A-Z0-9_.-]{1,100}$'),
 status VARCHAR(20) NOT NULL CHECK(status IN('OPEN','RECOVERED')),
 opened_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL,recovered_at TIMESTAMPTZ,
 occurrences BIGINT NOT NULL DEFAULT 1 CHECK(occurrences>0),basis_key VARCHAR(150) NOT NULL,
 reason_code VARCHAR(80) NOT NULL CHECK(reason_code ~ '^[A-Z0-9_]{1,80}$')
);
CREATE INDEX idx_secret_operations_alert_state ON secret_operations_alerts(status,last_seen_at DESC);
CREATE TABLE secret_operations_alert_events (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 alert_id BIGINT NOT NULL REFERENCES secret_operations_alerts(alert_id),
 event_kind VARCHAR(20) NOT NULL CHECK(event_kind IN('OPENED','REOPENED','RECOVERED')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secret_operations_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'SECRET_OPERATIONS_APPEND_ONLY' USING ERRCODE='23514'; END $$;
CREATE TRIGGER trg_secret_operations_alert_history_immutable BEFORE UPDATE OR DELETE ON secret_operations_alert_events FOR EACH ROW EXECUTE FUNCTION secret_operations_append_only();
-- Runtime app identities may append audit facts, never rewrite/delete their history.
CREATE TRIGGER trg_secret_audit_append_only BEFORE UPDATE OR DELETE ON secret_audit_events FOR EACH ROW EXECUTE FUNCTION secret_operations_append_only();
