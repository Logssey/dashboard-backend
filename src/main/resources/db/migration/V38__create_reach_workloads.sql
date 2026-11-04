-- Reach L1 워크로드 (설계: security-solution-docs/reachability-analysis/03-architecture/database-schema.md 3-3, ARD 7-3 선택지 A)
-- 클러스터 안 수집기(또는 ADMIN 수동 업로드)가 네임스페이스마다 실행 중인 워크로드와 이미지 digest를 올린다
-- 업로드는 (cluster, namespace) 단위로 통째로 바꾼다. 조회 행을 덮어쓰고 그 네임스페이스의 워크로드를 지운 뒤 다시 넣는다
-- Finding의 deployment는 이 두 테이블로 다시 계산한다. 조회가 오래됐거나 없으면 NOT_RUNNING으로 추정하지 않고 UNKNOWN (PRD FR-04)

-- 네임스페이스별 마지막 조회. 신선도 판단과 동시 업로드 잠금(FOR UPDATE)에 쓴다
CREATE TABLE reach_workload_observations (
    cluster      VARCHAR(100) NOT NULL,
    namespace    VARCHAR(63)  NOT NULL,
    observed_at  TIMESTAMPTZ  NOT NULL,
    received_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- 명세 3-6 Workload.source 이름
    source       VARCHAR(20)  NOT NULL CHECK (source IN ('CLUSTER_READER', 'MANUAL')),
    -- 수집기 토큰의 sub, 수동 업로드면 USER:<user_id>
    reported_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (cluster, namespace)
);

-- 워크로드 + 컨테이너 + digest 한 행. 배포 도중 같은 컨테이너에 digest가 둘이면 행도 둘이다
CREATE TABLE reach_workloads (
    workload_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cluster         VARCHAR(100) NOT NULL,
    namespace       VARCHAR(63)  NOT NULL,
    kind            VARCHAR(30)  NOT NULL,
    name            VARCHAR(253) NOT NULL,
    container       VARCHAR(253) NOT NULL,
    -- 파드에 적힌 이미지 그대로 (레지스트리 주소·태그 포함). API-07 image.repository는 조회 때 잘라 준다
    image           VARCHAR(512) NOT NULL,
    image_digest    VARCHAR(71)  NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    ready_replicas  INTEGER      NOT NULL CHECK (ready_replicas >= 0),
    CONSTRAINT fk_reach_workloads_observation FOREIGN KEY (cluster, namespace)
        REFERENCES reach_workload_observations (cluster, namespace) ON DELETE CASCADE,
    CONSTRAINT uq_reach_workloads UNIQUE (cluster, namespace, kind, name, container, image_digest)
);

-- 재계산이 Finding 대상의 digest로 찾는다
CREATE INDEX idx_reach_workloads_digest ON reach_workloads (image_digest);
