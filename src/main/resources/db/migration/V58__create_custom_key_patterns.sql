-- 사용자 등록 키 형식 (커스텀 키 패턴)
-- 사용자는 정규식을 쓰지 않고 폼에 접두사·문자 종류·길이만 넣는다. 정규식은 서버(KeyRuleCompiler)가 만든다.
-- 정규식은 저장하지 않는다. 스캔할 때마다 아래 세 값으로 다시 만들어서, DB 값만 바꿔 임의 정규식을 넣을 수 없게 한다.
-- 키 원문·예시 값은 저장하지 않는다 (ADR-D009).

CREATE TABLE custom_key_patterns (
    pattern_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         VARCHAR(50)  NOT NULL CHECK (length(btrim(name)) > 0),
    prefix       VARCHAR(20)  NOT NULL CHECK (prefix ~ '^[A-Za-z0-9_.-]{2,20}$'),
    charset      VARCHAR(20)  NOT NULL
                     CHECK (charset IN ('HEX_LOWER', 'HEX', 'ALNUM', 'ALNUM_UPPER', 'ALNUM_LOWER', 'DIGITS', 'BASE64URL')),
    key_length   INTEGER      NOT NULL CHECK (key_length BETWEEN 16 AND 128),
    is_secret    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by   VARCHAR(100),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- 같은 규칙을 두 번 등록하지 않는다
    CONSTRAINT uq_custom_key_patterns_rule UNIQUE (prefix, charset, key_length)
);

-- 사용자 규칙으로 찾은 키는 credentials.issuer = 'CUSTOM'으로 저장한다
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_issuer_check;
ALTER TABLE credentials
    ADD CONSTRAINT credentials_issuer_check CHECK (issuer IN ('AWS', 'GITHUB', 'NOTION', 'CUSTOM'));
