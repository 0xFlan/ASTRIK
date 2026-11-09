# Disposable PostgreSQL for the ARTEX Go suite

This directory closes the execution-layer gap recorded in F-003 and F-004:
`go test ./...` used to stop the database-backed tests at

```
no database config found: the environment variable ARTEX_PG_DSN is not set
```

A throwaway PostgreSQL 17 cluster on `127.0.0.1:55432` runs them for real.

## Provision

macOS (Homebrew):

```bash
brew install postgresql@17
./provision-test-postgres.sh
# prints: export ARTEX_PG_DSN='postgres://<user>@127.0.0.1:55432/artex_test?sslmode=disable'
eval "$(./provision-test-postgres.sh -q)"
```

The script is idempotent: it initializes `$ARTEX_PGDATA` (default
`/tmp/artex-pgdata`) with trust auth only if `PG_VERSION` is absent, starts the
cluster if it is not already accepting connections, and creates the base
database. `--reset` drops the per-package databases; `--stop` stops the
cluster.

The exact command used for this pass:

```bash
/opt/homebrew/opt/postgresql@17/bin/initdb -D /tmp/artex-pgdata -U flan \
  --auth=trust --encoding=UTF8
LC_ALL=C LANG=C /opt/homebrew/opt/postgresql@17/bin/pg_ctl -D /tmp/artex-pgdata \
  -l /tmp/artex-pgdata/server.log \
  -o "-p 55432 -h 127.0.0.1 -k /tmp/artex-pgdata" -w start
/opt/homebrew/opt/postgresql@17/bin/createdb -h 127.0.0.1 -p 55432 flan artex_test
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

`LC_ALL=C` is not cosmetic: without a valid locale the Homebrew postmaster exits
at startup with `postmaster became multithreaded during startup`.

## Why it works without migrations

`db.TestMain` and `server.TestMain` rewrite `ARTEX_PG_DSN` to add a
per-package suffix (`artex_test` → `artex_test_db`, `artex_test_server`, …).
`db.Open` connects to `/postgres`, creates the suffixed database when missing,
then applies the embedded `db/schema.sql` under an advisory lock. No separate
migration tool is required; the schema is idempotent.

## Results

Full suite on a freshly reset cluster:

```
ok  github.com/Autumn-27/artex/agent         1.213s
ok  github.com/Autumn-27/artex/cmd/artex     0.338s
ok  github.com/Autumn-27/artex/config        0.446s
ok  github.com/Autumn-27/artex/db            5.314s
ok  github.com/Autumn-27/artex/evidence      1.613s
ok  github.com/Autumn-27/artex/guard         0.469s
ok  github.com/Autumn-27/artex/intercept     1.422s
ok  github.com/Autumn-27/artex/llmpool       1.557s
ok  github.com/Autumn-27/artex/llmrec        0.862s
ok  github.com/Autumn-27/artex/mcphttp       8.033s
ok  github.com/Autumn-27/artex/notify        1.287s
ok  github.com/Autumn-27/artex/server       21.197s
ok  github.com/Autumn-27/artex/sidequestion  1.627s
ok  github.com/Autumn-27/artex/traffic       6.564s
```

`enrich` and `report` have no test files. The only skipped server test is
`TestLiveContextReview`, which requires `ARTEX_REVIEW_LIVE_CONFIG` and an
external model (environment-only, not a suite failure). Full log:
`logs/go-test-fresh.log`. A second consecutive run is green after the
idempotency patch: `logs/go-test-rerun.log`.

## Test-idempotency patch

The first rerun exposed three fixture defects, not product defects:

- `db/llmretry_test.go` and `db/config_test.go` used `defer d.Close()` plus
  `t.Cleanup` DELETEs. Defers run before cleanups, so the DELETEs hit a closed
  pool and fixed-name profiles survived; the next run failed on
  `llm_profiles_name_key`.
- `db/company_scope_test.go` deleted its assets but not its company, so the
  fixed `198.51.100.0/24` scope survived and won attribution on the next run.

`patches/test-idempotency.patch` moves `Close` into the first `t.Cleanup`
(LIFO: it runs last) and deletes the test company. Apply from the ARTEX root:

```bash
git apply <skill-repo>/evidence/db/patches/test-idempotency.patch
```

Evidence of the failure before the patch:
`logs/go-test-rerun-before-fix.log`.

## Authz/injection probe

`repro/zz_evidence_dbfixture_test.go` drives the production `Server.Handler()`
over loopback with a valid JWT, creates two tasks through the public API, and
probes anonymous access, cross-task sub-resource operations, SQL
metacharacters, archive identifiers, traversal, and symlink confinement.

```bash
cp repro/zz_evidence_dbfixture_test.go <ARTEX-repo>/server/
cd <ARTEX-repo>
go test ./server -run TestDBFixtureAuthzMatrix -count=1 -v
```

- `logs/f005-probe-before.log`: the four symlink probes return `200` and reach
  outside the work dir.
- `logs/f005-probe-after.log`: the same four return `400 {"error":"invalid
  path"}`; the normal workspace write/read controls still return `200`.

The DB-backed matrix itself held: 11/11 anonymous routes `401`; cross-task
goal/constraint/scope/credential operations did not mutate the victim task;
intercept-rule operations changed nothing; SQL metacharacters left the result
sets identical; archive identifiers were rejected; traversal was rejected. The
one confirmed defect is the workspace symlink escape in F-005.

## Artifacts

| Path | Contents |
|---|---|
| `provision-test-postgres.sh` | idempotent cluster + base database provisioning (`-q`, `--reset`, `--stop`) |
| `repro/zz_evidence_dbfixture_test.go` | full-stack authz/injection/symlink probe |
| `patches/workspace-symlink.patch` | `wsResolve` symlink confinement fix |
| `patches/test-idempotency.patch` | fixture cleanup fixes for repeatable runs |
| `logs/f005-probe-before.log` | probe output on the unfixed tree |
| `logs/f005-probe-after.log` | probe output after the fix |
| `logs/go-test-fresh.log` | first full suite on a reset cluster (green) |
| `logs/go-test-rerun.log` | second consecutive full suite (green) |
| `logs/go-test-rerun-before-fix.log` | second run before the fixture patch (3 failures) |
