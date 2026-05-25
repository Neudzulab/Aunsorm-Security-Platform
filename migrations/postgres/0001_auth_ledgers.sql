-- PostgreSQL target schema for Aunsorm auth and transparency ledgers.
-- Mirrors the SQLite tables created by crates/jwt/src/jti.rs,
-- crates/server/src/state.rs, and crates/server/src/transparency.rs.

BEGIN;

CREATE SCHEMA IF NOT EXISTS aunsorm;

CREATE TABLE IF NOT EXISTS aunsorm.schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aunsorm.jti (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_jti_expires
    ON aunsorm.jti (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS aunsorm.tokens (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_expires
    ON aunsorm.tokens (expires_at);

CREATE TABLE IF NOT EXISTS aunsorm.refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    subject TEXT,
    role TEXT NOT NULL,
    scope TEXT,
    mfa_verified BOOLEAN NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    session_ttl BIGINT NOT NULL,
    CONSTRAINT refresh_tokens_session_ttl_non_negative
        CHECK (session_ttl >= 0)
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry
    ON aunsorm.refresh_tokens (expires_at);

CREATE TABLE IF NOT EXISTS aunsorm.transparency_events (
    idx BIGINT PRIMARY KEY,
    event_ts BIGINT NOT NULL,
    event_json JSONB NOT NULL,
    hash BYTEA NOT NULL,
    CONSTRAINT transparency_events_idx_positive
        CHECK (idx > 0),
    CONSTRAINT transparency_events_hash_size
        CHECK (octet_length(hash) = 32)
);

CREATE INDEX IF NOT EXISTS idx_transparency_ts
    ON aunsorm.transparency_events (event_ts);

INSERT INTO aunsorm.schema_migrations (version)
VALUES ('0001_auth_ledgers')
ON CONFLICT (version) DO NOTHING;

COMMIT;

