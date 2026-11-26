-- 조치 진행 기록은 탐지 결과/위험 수용/해결 판정과 별도로 보관한다.
CREATE TABLE security_action_records (
    kind VARCHAR(20) NOT NULL CHECK (kind IN ('IMAGE', 'IAC_PATH', 'IAC_FINDING')),
    target_id BIGINT NOT NULL,
    image_finding_id BIGINT REFERENCES reach_findings(finding_id) ON DELETE CASCADE,
    iac_path_id BIGINT REFERENCES iac_attack_paths(path_id) ON DELETE CASCADE,
    iac_finding_id BIGINT REFERENCES iac_findings(finding_id) ON DELETE CASCADE,
    assignee_user_id BIGINT REFERENCES dashboard_users(user_id),
    status VARCHAR(25) NOT NULL DEFAULT 'NOT_STARTED'
        CHECK (status IN ('NOT_STARTED', 'IN_PROGRESS', 'AWAITING_CHECK', 'RECORDED')),
    note VARCHAR(2000) NOT NULL DEFAULT '',
    version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ,
    updated_by BIGINT REFERENCES dashboard_users(user_id),
    PRIMARY KEY (kind, target_id),
    CHECK ((kind = 'IMAGE' AND image_finding_id = target_id AND image_finding_id IS NOT NULL AND iac_path_id IS NULL AND iac_finding_id IS NULL)
        OR (kind = 'IAC_PATH' AND iac_path_id = target_id AND iac_path_id IS NOT NULL AND image_finding_id IS NULL AND iac_finding_id IS NULL)
        OR (kind = 'IAC_FINDING' AND iac_finding_id = target_id AND iac_finding_id IS NOT NULL AND image_finding_id IS NULL AND iac_path_id IS NULL))
);

CREATE TABLE security_action_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind VARCHAR(20) NOT NULL,
    target_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    assignee_user_id BIGINT REFERENCES dashboard_users(user_id),
    status VARCHAR(25) NOT NULL,
    note VARCHAR(2000) NOT NULL,
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (kind, target_id) REFERENCES security_action_records(kind, target_id) ON DELETE CASCADE,
    UNIQUE (kind, target_id, version)
);
