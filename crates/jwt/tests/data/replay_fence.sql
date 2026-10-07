-- Research fixture only: never loaded by the production store/verifier.
-- Install within one caller-owned IMMEDIATE transaction after writer quiescence.
ALTER TABLE jti RENAME TO jti_legacy_tombstones;
CREATE TABLE jti_canonical_fixture (
    identity BLOB PRIMARY KEY CHECK(length(identity) = 32),
    legacy_projection TEXT NOT NULL,
    expires_at INTEGER
);
CREATE VIEW jti AS SELECT jti, expires_at FROM jti_legacy_tombstones;
-- The original idx_jti_expires remains on the renamed table. This exercises
-- old CREATE TABLE/INDEX IF NOT EXISTS behavior with the actual global index.
CREATE TRIGGER jti_fence_insert INSTEAD OF INSERT ON jti BEGIN
    SELECT RAISE(ABORT, 'replay migration fence: legacy insert rejected');
END;
CREATE TRIGGER jti_fence_delete INSTEAD OF DELETE ON jti BEGIN
    SELECT RAISE(ABORT, 'replay migration fence: legacy delete rejected');
END;
CREATE TRIGGER jti_fence_update INSTEAD OF UPDATE ON jti BEGIN
    SELECT RAISE(ABORT, 'replay migration fence: legacy update rejected');
END;
