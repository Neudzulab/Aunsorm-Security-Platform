-- Roll back the initial Aunsorm auth and transparency ledger schema.
-- Destructive: only run after approved backup/restore validation.

BEGIN;

DROP TABLE IF EXISTS aunsorm.transparency_events;
DROP TABLE IF EXISTS aunsorm.refresh_tokens;
DROP TABLE IF EXISTS aunsorm.tokens;
DROP TABLE IF EXISTS aunsorm.jti;
DROP TABLE IF EXISTS aunsorm.schema_migrations;
DROP SCHEMA IF EXISTS aunsorm;

COMMIT;
