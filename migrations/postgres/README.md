# PostgreSQL migrations

These migrations define the production PostgreSQL target schema for the
SQLite-backed ledgers currently used by `aunsorm-server` and `aunsorm-jwt`.

## Apply

Run migrations in lexical order against the production DSN:

```bash
./scripts/apply-postgres-migrations.sh --database-url "$DATABASE_URL"
```

PowerShell:

```powershell
.\scripts\apply-postgres-migrations.ps1 -DatabaseUrl $env:DATABASE_URL
```

The scripts are idempotent and keep all Aunsorm tables under the `aunsorm`
schema. Application services must still be switched to a PostgreSQL backend
before `AUNSORM_JTI_DB` is retired from production.

## Rollback

Rollback files are only for pre-production validation or controlled incident
recovery. They drop ledger state and must not be run on production without an
approved backup and change ticket.

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/postgres/0001_auth_ledgers_down.sql
```
