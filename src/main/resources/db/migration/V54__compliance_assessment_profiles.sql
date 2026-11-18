-- 서비스 사용 여부와 조직 정책을 점검 대상별로 분리하고 Run 판정 근거를 스냅샷으로 남긴다.
ALTER TABLE compliance_targets
    ADD COLUMN assessment_profile JSONB NOT NULL
        DEFAULT '{"schemaVersion":1,"serviceUsage":{},"requirements":{}}'::jsonb,
    ADD CONSTRAINT compliance_targets_assessment_profile_object
        CHECK (jsonb_typeof(assessment_profile) = 'object');

ALTER TABLE compliance_runs
    ADD COLUMN assessment_profile JSONB NOT NULL
        DEFAULT '{"schemaVersion":1,"serviceUsage":{},"requirements":{}}'::jsonb,
    ADD COLUMN assessment_policy_version VARCHAR(50) NOT NULL DEFAULT 'legacy',
    ADD COLUMN inferred_services JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT compliance_runs_assessment_profile_object
        CHECK (jsonb_typeof(assessment_profile) = 'object'),
    ADD CONSTRAINT compliance_runs_inferred_services_array
        CHECK (jsonb_typeof(inferred_services) = 'array');
