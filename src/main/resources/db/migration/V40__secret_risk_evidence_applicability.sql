-- Observation time is not the interval in which a fact was true. No historical inference/backfill.
ALTER TABLE secret_risk_evidence
 ADD COLUMN fact_valid_from TIMESTAMPTZ,
 ADD COLUMN fact_valid_until TIMESTAMPTZ,
 ADD COLUMN source_presence_observed_at TIMESTAMPTZ,
 ADD COLUMN applicability_basis VARCHAR(30) CHECK(applicability_basis IN ('OBSERVATION_ONLY','EFFECTIVE_INTERVAL')),
 ADD CONSTRAINT ck_secret_risk_fact_interval CHECK((
   (fact_valid_from IS NULL AND fact_valid_until IS NULL AND applicability_basis IS NULL AND source_presence_observed_at IS NULL)
   OR (fact_valid_from IS NULL AND fact_valid_until IS NULL AND applicability_basis='OBSERVATION_ONLY'
       AND source_presence_observed_at IS NOT NULL)
   OR (fact_valid_from IS NOT NULL AND fact_valid_until IS NOT NULL
       AND fact_valid_until>fact_valid_from AND applicability_basis='EFFECTIVE_INTERVAL'
       AND source_presence_observed_at IS NOT NULL)) IS TRUE);

CREATE OR REPLACE VIEW secret_current_risk_evidence AS
 SELECT e.* FROM secret_risk_evidence e
 WHERE e.record_kind='ASSERTION'
 AND NOT EXISTS(SELECT 1 FROM secret_risk_evidence r WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='RETRACTION')
 AND COALESCE((SELECT r.review_decision='ACCEPT' FROM secret_risk_evidence r
   WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='REVIEW' ORDER BY r.evidence_id DESC LIMIT 1),
   e.verification_level IN ('MANUAL_ACCEPTED','PROVIDER_OBSERVED','ASSET_CLASSIFIED'));
