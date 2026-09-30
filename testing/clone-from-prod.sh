#!/usr/bin/env bash
# Clone a production Askar wallet into the local test Postgres, through an SSM tunnel.
#
# Nothing here writes to production — pg_dump is a read. The tunnel is opened by YOU in
# a separate terminal, so this script never touches AWS credentials.
#
# ── 1. Open the tunnel (separate terminal, leave it running) ─────────────────
#   aws ssm start-session --profile <aws-profile> --target <instance-id> \
#     --document-name AWS-StartPortForwardingSession \
#     --parameters '{"portNumber":["<remote-db-port>"],"localPortNumber":["15455"]}'
#
# ── 2. Start the local database ──────────────────────────────────────────────
#   docker compose up -d
#
# ── 3. Run this ──────────────────────────────────────────────────────────────
#   # put the agent database POSTGRES_PASSWORD in a file (gitignored, chmod 600):
#   printf %s '<password>' > testing/.pgpass-prod && chmod 600 testing/.pgpass-prod
#   # ...or export PGPASSWORD_PROD if you prefer it not to touch disk.
#   ./clone-from-prod.sh                     # list candidate wallet databases
#   ./clone-from-prod.sh <db-name>           # clone it
#   ./clone-from-prod.sh <db-name> --replace # re-clone over an existing local copy
#
# WHY A LOGICAL DUMP IS A FAITHFUL ASKAR CLONE
# An Askar store is four ordinary tables: config, profiles, items, items_tags. The
# store key is NOT in the database — WALLET_KEY is supplied at open time — but the
# *wrapped* key is, in `config`, and pg_dump preserves it. Encrypted values and
# deterministically-encrypted tags copy across byte-identical. So the real WALLET_KEY
# opens this clone exactly as it opens production, and WQL tag filters behave the same.
set -euo pipefail

PROD_HOST=${PROD_HOST:-127.0.0.1}
PROD_PORT=${PROD_PORT:-15455}
PROD_USER=${PROD_USER:?set PROD_USER to the DB user the agent connects as (see POSTGRES_USER on the agent DB container) - Askar resolves its schema from this, so there is no safe default}
LOCAL_HOST=${LOCAL_HOST:-127.0.0.1}
LOCAL_PORT=${LOCAL_PORT:-5433}
LOCAL_USER=${LOCAL_USER:-postgres}
LOCAL_PASS=${LOCAL_PASS:-localtest}
LOCAL_CONTAINER=${LOCAL_CONTAINER:-owpurge-test-db}

die() { echo "ERROR: $*" >&2; exit 1; }

prod_psql()  { PGPASSWORD="$PGPASSWORD_PROD" psql -h "$PROD_HOST"  -p "$PROD_PORT"  -U "$PROD_USER"  -v ON_ERROR_STOP=1 "$@"; }
local_psql() { PGPASSWORD="$LOCAL_PASS"      psql -h "$LOCAL_HOST" -p "$LOCAL_PORT" -U "$LOCAL_USER" -v ON_ERROR_STOP=1 "$@"; }

# Password comes from the environment, or from a gitignored file so it survives
# between separate shell invocations without being retyped or echoed into history.
PASSFILE="${PASSFILE:-$(dirname "$0")/.pgpass-prod}"
if [ -z "${PGPASSWORD_PROD:-}" ] && [ -f "$PASSFILE" ]; then
  # strip a trailing newline if the file was written with echo
  PGPASSWORD_PROD=$(tr -d '\n' < "$PASSFILE")
fi
[ -n "${PGPASSWORD_PROD:-}" ] || die "no source-database password. Either:
    printf %s '<password>' > $PASSFILE && chmod 600 $PASSFILE
  or:
    export PGPASSWORD_PROD='<password>'"

nc -z "$PROD_HOST" "$PROD_PORT" 2>/dev/null \
  || die "nothing listening on $PROD_HOST:$PROD_PORT — is the SSM port-forward running? (see header)"

# Guard against ever pointing the destructive half of this script at something that is
# not the local throwaway container. Checked before any DROP can happen.
assert_local_is_disposable() {
  docker inspect "$LOCAL_CONTAINER" >/dev/null 2>&1 \
    || die "local container '$LOCAL_CONTAINER' not found — refusing to modify a database I cannot identify as the throwaway test instance"
  local mapped
  mapped=$(docker port "$LOCAL_CONTAINER" 5432/tcp 2>/dev/null | head -1)
  case "$mapped" in
    *:"$LOCAL_PORT") ;;
    *) die "'$LOCAL_CONTAINER' is not the thing listening on $LOCAL_PORT (it is on '${mapped:-nothing}') — refusing to drop anything";;
  esac
}

# Pick a database we can actually connect to for catalogue queries.
BOOTSTRAP=""
for cand in "${PROD_DB:-}" postgres "$PROD_USER" template1; do
  [ -n "$cand" ] || continue
  if prod_psql -d "$cand" -tAc 'select 1' >/dev/null 2>&1; then BOOTSTRAP="$cand"; break; fi
done
[ -n "$BOOTSTRAP" ] || die "could not connect to any bootstrap database as '$PROD_USER' — set PROD_DB=<name>"

if [ $# -eq 0 ]; then
  echo "Databases on the source server (queried via '$BOOTSTRAP'):"
  echo
  prod_psql -d "$BOOTSTRAP" -c "
    SELECT datname AS database,
           pg_size_pretty(pg_database_size(datname)) AS size
    FROM pg_database
    WHERE datistemplate = false AND datallowconn
    ORDER BY pg_database_size(datname) DESC"
  echo "Looking for Askar stores (any schema — Askar names the schema after the"
  echo "connecting user unless a ?schema= param is given, so it is usually NOT 'public'):"
  echo
  for db in $(prod_psql -d "$BOOTSTRAP" -tAc "SELECT datname FROM pg_database WHERE datistemplate=false AND datallowconn"); do
    found=$(prod_psql -d "$db" -tAc "
      SELECT table_schema || ' (' || string_agg(table_name, ',' ORDER BY table_name) || ')'
      FROM information_schema.tables
      WHERE table_name IN ('config','profiles','items','items_tags')
      GROUP BY table_schema
      HAVING count(*) >= 3" 2>/dev/null || true)
    if [ -n "$found" ]; then
      echo "  $db -> schema $found"
    else
      echo "  $db -> no Askar store"
    fi
  done
  echo
  echo "Re-run as: ./clone-from-prod.sh <db-name>"
  exit 0
fi

DB="$1"
REPLACE="${2:-}"
DUMP="./${DB}.dump"

echo "==> Locating the Askar store inside '$DB' (searching every schema)"
# Askar puts its tables in the schema named after the connecting user unless the URI
# carries ?schema=. Filtering on 'public' finds nothing on a normal Credo deployment.
ASKAR_SCHEMA=$(prod_psql -d "$DB" -tAc "
  SELECT table_schema
  FROM information_schema.tables
  WHERE table_name IN ('config','profiles','items','items_tags')
  GROUP BY table_schema
  HAVING count(*) >= 3
  ORDER BY (table_schema = '$PROD_USER') DESC
  LIMIT 1")
[ -n "$ASKAR_SCHEMA" ] || die "no Askar store found in '$DB' in any schema (expected config/profiles/items/items_tags)"
echo "    schema: $ASKAR_SCHEMA"
if [ "$ASKAR_SCHEMA" != "$PROD_USER" ]; then
  echo "    NOTE: schema differs from the connecting user '$PROD_USER'. Askar resolves the"
  echo "          store via search_path, so owpurge must connect as a user whose"
  echo "          search_path reaches '$ASKAR_SCHEMA' (see DB_SCHEMA in the README)."
fi

echo "==> Askar schema version (must be '1'; Store::open refuses anything else)"
prod_psql -d "$DB" -tAc "SELECT 'config.version = ' || value FROM \"$ASKAR_SCHEMA\".config WHERE name='version'" || true

echo "==> Source size and row estimates"
prod_psql -d "$DB" -c "
  SELECT relname AS \"table\",
         to_char(n_live_tup, 'FM999,999,999') AS est_rows,
         pg_size_pretty(pg_total_relation_size(relid)) AS total_size
  FROM pg_stat_user_tables ORDER BY n_live_tup DESC"
prod_psql -d "$DB" -tAc "SELECT 'profiles in store: ' || count(*) FROM \"$ASKAR_SCHEMA\".profiles"
prod_psql -d "$DB" -tAc "SELECT 'database size: ' || pg_size_pretty(pg_database_size('$DB'))"

# Decide about the local target BEFORE spending time on a dump.
EXISTS=$(local_psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB'" || true)
if [ "$EXISTS" = "1" ]; then
  if [ "$REPLACE" != "--replace" ]; then
    die "local database '$DB' already exists. Re-run with --replace to overwrite it, or drop it yourself."
  fi
  assert_local_is_disposable
  echo "==> --replace given; dropping the existing LOCAL copy of '$DB' on $LOCAL_HOST:$LOCAL_PORT"
  local_psql -d postgres -c "DROP DATABASE \"$DB\" WITH (FORCE)" >/dev/null
fi

echo "==> Dumping (read-only against production) -> $DUMP"
# --no-owner/--no-acl so the restore needs no source role to pre-exist locally.
PGPASSWORD="$PGPASSWORD_PROD" pg_dump \
  -h "$PROD_HOST" -p "$PROD_PORT" -U "$PROD_USER" -d "$DB" \
  --format=custom --no-owner --no-acl --file "$DUMP"
ls -lh "$DUMP"

echo "==> Restoring into $LOCAL_HOST:$LOCAL_PORT/$DB"
local_psql -d postgres -c "CREATE DATABASE \"$DB\"" >/dev/null
# pg_restore exits non-zero even when every error it hit was ignorable, and with
# `set -e` that aborts the script before the role and .env.local steps below. The
# common ignorable case is a client newer than the server: pg_restore 17+ emits
# `SET transaction_timeout = 0` in its per-connection preamble, which a PG16 server
# rejects as an unknown parameter. 0 is the default (no timeout), so nothing is lost.
# Separate that from a real failure rather than blanket-ignoring the exit code.
RESTORE_LOG=$(mktemp)
if ! PGPASSWORD="$LOCAL_PASS" pg_restore \
      -h "$LOCAL_HOST" -p "$LOCAL_PORT" -U "$LOCAL_USER" -d "$DB" \
      --no-owner --no-acl --jobs 4 "$DUMP" 2>"$RESTORE_LOG"; then
  REAL=$(grep -E '^pg_restore: error:' "$RESTORE_LOG" | grep -v 'transaction_timeout' || true)
  if [ -n "$REAL" ]; then
    echo "$REAL" >&2
    rm -f "$RESTORE_LOG"
    die "pg_restore hit real errors (above) — the clone is not trustworthy"
  fi
  IGNORED=$(grep -c 'transaction_timeout' "$RESTORE_LOG" || true)
  echo "    ignored $IGNORED harmless 'transaction_timeout' SET failures"
  echo "    (pg_restore $(pg_restore --version | awk '{print $NF}') emits a PG17+ parameter;"
  echo "     this server is PG16. The value it tried to set, 0, is already the default.)"
fi
rm -f "$RESTORE_LOG"

echo "==> Verifying the clone (compare these to the source figures above)"
local_psql -d "$DB" -c "
  SELECT relname AS \"table\", to_char(n_live_tup,'FM999,999,999') AS est_rows
  FROM pg_stat_user_tables ORDER BY n_live_tup DESC"
local_psql -d "$DB" -tAc "SELECT 'profiles: ' || count(*) FROM \"$ASKAR_SCHEMA\".profiles"
local_psql -d "$DB" -tAc "SELECT 'exact items: ' || count(*) FROM \"$ASKAR_SCHEMA\".items"
local_psql -d "$DB" -tAc "SELECT 'config.version = ' || value FROM \"$ASKAR_SCHEMA\".config WHERE name='version'"

echo "==> Creating role '$PROD_USER' locally so search_path resolves schema '$ASKAR_SCHEMA'"
# Askar finds its store through CURRENT_SCHEMAS(false), i.e. Postgres search_path,
# which defaults to "$user", public. Connecting as postgres would NOT see the
# the agent user schema and Store::open would report no store. Recreating the role makes
# the local clone behave exactly as production does.
local_psql -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$PROD_USER'" | grep -q 1 || \
  local_psql -d postgres -c "CREATE ROLE \"$PROD_USER\" LOGIN PASSWORD '$LOCAL_PASS'" >/dev/null
local_psql -d "$DB" -c "GRANT ALL ON SCHEMA \"$ASKAR_SCHEMA\" TO \"$PROD_USER\"" >/dev/null
local_psql -d "$DB" -c "GRANT ALL ON ALL TABLES IN SCHEMA \"$ASKAR_SCHEMA\" TO \"$PROD_USER\"" >/dev/null
local_psql -d "$DB" -c "GRANT ALL ON ALL SEQUENCES IN SCHEMA \"$ASKAR_SCHEMA\" TO \"$PROD_USER\"" >/dev/null
echo "    role '$PROD_USER' ready (password: $LOCAL_PASS)"

if [ ! -f .env.local ]; then
  cat > .env.local <<ENV
# Generated by clone-from-prod.sh — points owpurge at the LOCAL clone.
# WALLET_KEY must be the REAL key: the dump preserved the wrapped store key in the
# config table, so nothing else will decrypt it.
WALLET_ID=$DB
WALLET_KEY=PUT-THE-REAL-WALLET-KEY-HERE
KEY_DERIVATION_METHOD=raw
DB_HOST=$LOCAL_HOST
DB_PORT=$LOCAL_PORT
DB_USER=$PROD_USER
DB_PASSWORD=$LOCAL_PASS
DB_ADMIN_USER=$PROD_USER
DB_ADMIN_PASSWORD=$LOCAL_PASS
PURGE_MODE=dedicated
DRY_RUN=true
TTL_DAYS=30
AUDIT_CSV=./logs/purge-audit.csv
ENV
  echo
  echo "Wrote testing/.env.local — put the real WALLET_KEY in it."
else
  echo
  echo "testing/.env.local already exists; left it alone."
fi

cat <<'NEXT'

Next:
    cd <repo root>
    set -a; . testing/.env.local; set +a
    ./target/release/owpurge census          # read-only, should match production
    ./target/release/owpurge purge           # dry-run (DRY_RUN=true in .env.local)
    DRY_RUN=false ./target/release/owpurge purge   # live, against the CLONE only
NEXT
