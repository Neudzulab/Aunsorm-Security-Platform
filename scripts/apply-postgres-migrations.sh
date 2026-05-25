#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./scripts/apply-postgres-migrations.sh [--database-url DSN] [--migrations-path PATH]

Applies PostgreSQL migrations in lexical order using psql with ON_ERROR_STOP=1.
The DSN is read from --database-url or DATABASE_URL.
USAGE
}

database_url="${DATABASE_URL:-}"
migrations_path=""

while (($# > 0)); do
    case "$1" in
        --database-url)
            database_url="${2:-}"
            shift 2
            ;;
        --migrations-path)
            migrations_path="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$database_url" ]]; then
    echo "DATABASE_URL is required. Pass --database-url or set DATABASE_URL." >&2
    exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
    echo "psql was not found on PATH." >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

if [[ -z "$migrations_path" ]]; then
    migrations_path="$repo_root/migrations/postgres"
fi

if [[ ! -d "$migrations_path" ]]; then
    echo "Migration directory not found: $migrations_path" >&2
    exit 1
fi

shopt -s nullglob
migration_files=("$migrations_path"/*.sql)
shopt -u nullglob

pending=()
for migration in "${migration_files[@]}"; do
    if [[ "$migration" != *_down.sql ]]; then
        pending+=("$migration")
    fi
done

if ((${#pending[@]} == 0)); then
    echo "No migration files found in $migrations_path" >&2
    exit 1
fi

IFS=$'\n' pending=($(printf '%s\n' "${pending[@]}" | sort))
unset IFS

for migration in "${pending[@]}"; do
    echo "==> Applying $(basename "$migration")"
    psql "$database_url" -v ON_ERROR_STOP=1 -f "$migration"
done

echo "PostgreSQL migrations completed."

