-- Research fixture only: run atomically with stopped/fenced writers.
-- Explicit projections are retained by canonical rows; old keys are not decoded.
INSERT INTO jti_legacy_tombstones(jti, expires_at)
    SELECT legacy_projection, expires_at FROM jti_canonical_fixture
    WHERE true
    ON CONFLICT(jti) DO UPDATE SET expires_at = CASE
        WHEN jti_legacy_tombstones.expires_at IS NULL OR excluded.expires_at IS NULL THEN NULL
        ELSE MAX(jti_legacy_tombstones.expires_at, excluded.expires_at) END;
DROP TRIGGER jti_fence_insert;
DROP TRIGGER jti_fence_delete;
DROP TRIGGER jti_fence_update;
DROP VIEW jti;
ALTER TABLE jti_legacy_tombstones RENAME TO jti;
-- Preserve jti_canonical_fixture; never discard post-cutover consumption.
