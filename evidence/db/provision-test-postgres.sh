#!/usr/bin/env bash
# Provision a disposable PostgreSQL cluster for the ARTEX Go test harness.
#
# Why a private cluster: the suite's TestMain appends a per-package suffix to the
# database name in ARTEX_PG_DSN (artex_test -> artex_test_server) and db.Open
# creates each suffixed database and applies the embedded db/schema.sql. Using a
# throwaway PGDATA on a non-default port leaves the developer's Homebrew cluster
# and any real data untouched.
#
# Requirements: PostgreSQL 17 binaries. On macOS:
#   brew install postgresql@17
#
# Usage:
#   ./provision-test-postgres.sh            # provision and print the DSN
#   eval "$(./provision-test-postgres.sh -q)"  # export ARTEX_PG_DSN
#   ./provision-test-postgres.sh --reset    # drop the test databases, keep the cluster
#   ./provision-test-postgres.sh --stop     # stop the disposable cluster
#
# Environment overrides: PG_BIN, ARTEX_PGDATA, ARTEX_PGPORT, ARTEX_PG_BASE_DB.
set -euo pipefail

PG_BIN="${PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}"
PGDATA="${ARTEX_PGDATA:-/tmp/artex-pgdata}"
PORT="${ARTEX_PGPORT:-55432}"
BASE_DB="${ARTEX_PG_BASE_DB:-artex_test}"
DB_USER="${ARTEX_PG_USER:-$(id -un)}"
DSN="postgres://${DB_USER}@127.0.0.1:${PORT}/${BASE_DB}?sslmode=disable"
QUIET=0
RESET=0

for arg in "$@"; do
  case "$arg" in
    -q|--quiet) QUIET=1 ;;
    --reset) RESET=1 ;;
    --stop)
      if [ -d "$PGDATA" ]; then
        LC_ALL=C LANG=C "$PG_BIN/pg_ctl" -D "$PGDATA" -m fast -w stop || true
      fi
      exit 0
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -x "$PG_BIN/initdb" ]; then
  echo "PostgreSQL binaries not found at $PG_BIN" >&2
  echo "Install them first (macOS: brew install postgresql@17) or set PG_BIN." >&2
  exit 1
fi

if [ ! -f "$PGDATA/PG_VERSION" ]; then
  rm -rf "$PGDATA"
  "$PG_BIN/initdb" -D "$PGDATA" -U "$DB_USER" --auth=trust --encoding=UTF8 >/tmp/artex-initdb.log 2>&1
fi

# LC_ALL=C is required on macOS/Homebrew: without a valid locale the postmaster
# exits with "postmaster became multithreaded during startup" before listening.
if ! "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PORT" -q; then
  LC_ALL=C LANG=C "$PG_BIN/pg_ctl" -D "$PGDATA" \
    -l "$PGDATA/server.log" \
    -o "-p $PORT -h 127.0.0.1 -k $PGDATA" \
    -w start
fi

"$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PORT"

# --reset drops the per-package databases created by TestMain. The suite is green
# on a fresh cluster; this also clears fixed-name fixture residue from earlier
# runs (the test fixes in evidence/db/patches/test-idempotency.patch make a plain
# re-run spend less, but a reset is the strongest starting point).
if [ "$RESET" -eq 1 ]; then
  for suffix in "" _db _server _agent _evidence; do
    "$PG_BIN/psql" "postgres://${DB_USER}@127.0.0.1:${PORT}/postgres?sslmode=disable" \
      -q -c "DROP DATABASE IF EXISTS \"${BASE_DB}${suffix}\" WITH (FORCE)" || true
  done
fi

# The base database must exist before the suite (db.Open only creates the
# per-package suffixed databases, and it connects to /postgres as the admin).
if ! "$PG_BIN/psql" "$DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
  "$PG_BIN/createdb" -h 127.0.0.1 -p "$PORT" -U "$DB_USER" "$BASE_DB" 2>/dev/null || true
fi

if ! "$PG_BIN/psql" "$DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
  echo "base database $BASE_DB is not reachable at 127.0.0.1:$PORT" >&2
  exit 1
fi

if [ "$QUIET" -eq 1 ]; then
  printf 'export ARTEX_PG_DSN=%q\n' "$DSN"
else
  echo "PostgreSQL ready: $("$PG_BIN/postgres" --version)"
  echo "PGDATA=$PGDATA PORT=$PORT"
  echo "export ARTEX_PG_DSN='$DSN'"
fi
