-- Shared dispatch accounting across providers, API replicas and AI features.
-- The ledger contains operational metadata only, never a prompt or case identifier.
CREATE TABLE secret_ai_call_ledger (
    call_id UUID PRIMARY KEY,
    provider VARCHAR(12) NOT NULL,
    model VARCHAR(80) NOT NULL,
    purpose VARCHAR(12) NOT NULL CHECK (purpose IN ('GUIDE', 'BRIEFING')),
    state VARCHAR(12) NOT NULL CHECK (state IN ('DISPATCHING', 'COMPLETED')),
    reserved_at TIMESTAMPTZ NOT NULL,
    deadline_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK ((provider='CLAUDE' AND model='claude-sonnet-5-5')
        OR (provider='GROQ' AND model='openai/gpt-oss-20b')),
    CHECK (deadline_at>reserved_at AND deadline_at<=reserved_at+interval '90 seconds'),
    CHECK ((state='DISPATCHING' AND completed_at IS NULL)
        OR (state='COMPLETED' AND completed_at IS NOT NULL AND completed_at>=reserved_at))
);
CREATE INDEX idx_secret_ai_calls_reserved ON secret_ai_call_ledger(reserved_at);
CREATE INDEX idx_secret_ai_calls_active ON secret_ai_call_ledger(deadline_at)
    WHERE completed_at IS NULL;
REVOKE ALL ON secret_ai_call_ledger FROM PUBLIC;
