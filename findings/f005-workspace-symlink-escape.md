# F-005 — Workspace file manager follows symlinks: host file read/write outside the work dir

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | Medium (authenticated host file read/write through a planted link; CVSS 3.1 5.7, `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N`) |
| Affected | `server/workspace.go` `wsResolve` at BaaRai/ARTEX `fbe7839` |
| Trigger | Authenticated `GET /api/workspace/{read,download}` or `POST /api/workspace/{write,mkdir}` with a path that crosses a symlink under the work dir |
| Evidence | `evidence/db/logs/f005-probe-before.log`, `f005-probe-after.log`, `evidence/db/repro/` |
| Patch | `evidence/db/patches/workspace-symlink.patch` |

## Summary

`wsResolve` confined the workspace file manager with a **lexical** check only:
`filepath.Clean` on a rooted copy collapses `..`, and a prefix test rejects an
absolute path above `m.dir`. It never resolved symlinks, and every caller then
followed them through `os.Stat`, `os.ReadFile`, `os.WriteFile`, and
`os.MkdirAll`. A symlink planted inside the work dir therefore turned the
file-manager routes into host-file primitives:

| Request (valid JWT) | Before the fix | Effect |
|---|---|---|
| `GET /api/workspace/read?path=escape-link` | `200` | returned the outside canary `ARTEX-OUTSIDE-CANARY-F005` |
| `GET /api/workspace/download?path=escape-link` | `200` | served the same outside file as an attachment |
| `POST /api/workspace/write` `{"path":"escape-write-link","content":"ARTEX-OUTSIDE-WRITE-F005"}` | `200` | overwrote the outside target |
| `POST /api/workspace/mkdir` `{"path":"escape-dir-link/created-outside"}` | `200` | created a directory under the link's outside target |

The links were ordinary `os.Symlink` entries created in `m.dir`; the canary and
write target lived in a separate temporary directory outside it. The same test
kept a positive control: an ordinary `normal-probe.txt` write and read returned
`200` with `NORMAL-OK`, so the escape is not a general file-manager breakage.

After `pathCrossesSymlink` was added to `wsResolve`, all four requests return
`400 {"error":"invalid path"}`; the positive control still returns `200`.

## Why this is reachable rather than theoretical

The file manager's documented contract is "INSIDE the work dir". Two ordinary
workflows put symlinks inside that directory:

1. **The agent's Bash tool.** A task workspace is the agent's CWD. A target can
   steer it (prompt injection in a page, repository, ticket, or MCP
   description) to `ln -s ~/.ssh/id_rsa notes/key` or to clone a repository
   that already contains such a link. The agent already has host access, so
   this is not privilege escalation *from the agent*; it breaks the separate
   browser-side file manager, which the operator uses believing it is confined.
2. **Cloned or downloaded material.** `git clone` preserves repository
   symlinks, and archive extraction is not the only way files enter a
   workspace.

Once a link exists, the operator's own session reads or writes through it. A
write through a link aimed at `~/.ssh/authorized_keys`, a shell profile, or a
service unit is code execution as the server user. A read through a link aimed
at `~/.aws/credentials`, `jwt.key`, or the LLM profile store is credential
disclosure to the browser.

This is the gap the skill's own attack-surface reference had already flagged:
"`wsResolve` correctly rejects `..` and absolute-path escapes at the lexical
layer; only symlink resolution is missing." F-005 turns that note into a proven
primitive and a fix.

## Root cause

```go
clean := filepath.Clean("/" + rel)
abs := filepath.Clean(filepath.Join(base, clean))
if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
    return "", false
}
return abs, true
```

`filepath.Clean` is purely lexical; it does not consult the filesystem.
`abs` remains inside `base` as a string even when a component of it is a link
to `/etc` or `$HOME`. `os.Stat`/`ReadFile`/`WriteFile`/`MkdirAll` all resolve
links in the kernel, so the string check and the operation disagree.

## Fix

`wsResolve` now walks the components of the resolved relative path below the
work-dir root with `os.Lstat` and refuses the path if any existing component is
a symlink. A missing component ends the walk: nothing below it exists yet, and
`MkdirAll`/`WriteFile` will create regular entries there. The root itself is
not inspected, so a symlinked base (`/var` → `/private/var` on macOS) does not
break ordinary operation.

```go
if pathCrossesSymlink(base, abs) {
    return "", false
}
```

Exact diff: `evidence/db/patches/workspace-symlink.patch`. Apply from the ARTEX
repository root:

```bash
git apply <skill-repo>/evidence/db/patches/workspace-symlink.patch
gofmt -w server/workspace.go
go test ./server -run TestDBFixtureAuthzMatrix -count=1 -v
```

The check is a validation, not an atomic open: a concurrent agent could replace
a directory with a link between `Lstat` and `ReadFile`. For a single-operator
local tool that race is acceptable; a multi-tenant deployment should use
`openat`/`O_NOFOLLOW` and operate on file descriptors.

The same lexical pattern remains in the skill file routes
(`fsReadFile`, `fsWriteFile`, `fsDeletePath` join `s.skillDir/name/file` without
a symlink check). It was not exercised in this pass; the same helper should be
applied there, and the regression below should be extended to a link inside a
skill directory.

## Reproduction

The probe starts the real `Server.Handler()` (CORS → `requireAuth` → `ServeMux`)
on a loopback listener with a valid JWT, creates two tasks through the public
API, plants the links, and drives the routes. Unfixed code fails the four
assertions; the patched code passes them.

```bash
# Fresh disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>
cp <skill-repo>/evidence/db/repro/zz_evidence_dbfixture_test.go server/
go test ./server -run TestDBFixtureAuthzMatrix -count=1 -v
```

Before/after (both authenticated, same fixture):

| Probe | Before | After |
|---|---|---|
| `ws-read-symlink` | `200` + outside canary | `400 invalid path` |
| `ws-download-symlink` | `200` + outside canary | `400 invalid path` |
| `ws-write-symlink` | `200`, outside file changed | `400 invalid path` |
| `ws-mkdir-symlink` | `200`, outside dir created | `400 invalid path` |
| `ws-write-normal` / `ws-read-normal` | `200` / `200 NORMAL-OK` | `200` / `200 NORMAL-OK` |

## The PostgreSQL-backed surface this pass unlocked

The suite had never run its database tests: `go test ./...` stopped at
`no database config found: ARTEX_PG_DSN is not set`. A disposable PostgreSQL 17
cluster on `127.0.0.1:55432` (provisioning script and logs under
`evidence/db/`) runs the full suite green: 14 packages `ok`, 0 `FAIL`, the
`server` package in 21.197 s, and the only skipped test is
`TestLiveContextReview`, which requires `ARTEX_REVIEW_LIVE_CONFIG` and a live
model endpoint (environment-only). A second consecutive run is also green after
the fixture patch below.

With the DB-backed routes actually executing, the same probe recorded these
negatives through the production stack:

| Surface | Probes | Observed |
|---|---|---|
| Anonymous access | 11 routes (`/api/tasks`, `/api/task-archives`, archive restore/delete, credentials, goals, logs, LLM config, skill upload, workspace read) | all `401 Unauthorized` |
| Cross-task goals | `PATCH`/`DELETE /api/tasks/A/goals/{goal_of_B}` | `404 goal not found`; B's goal unchanged |
| Cross-task constraints | `PATCH`/`DELETE /api/tasks/A/constraints/{constraint_of_B}` | `500 constraint does not exist`; B's constraint unchanged |
| Cross-task scope | `DELETE /api/tasks/A/scope/{scope_of_B}` | `404 scope row not found`; B's scope unchanged |
| Cross-task credentials | `DELETE /api/tasks/A/credentials/{credential_of_B}` | `404 credential not found`; B's credential unchanged |
| Cross-task task-intercept rules | toggle/update/delete under A using B's rule id | toggle `200 {"enabled":false,"ok":true}` but **no row changed**; update `500 sql: no rows`; delete `200 {"deleted":false}`; B's rule still enabled and unchanged |
| SQL metacharacters | `task-archives?q=' OR 1=1--`, `state=…`, `findings?query=…`, `severity=…`, `logs/history?q=…` | all `200`; archive/finding result sets identical to the unfiltered baseline; values are parameterized |
| Archive identifiers | non-numeric, unknown, negative | `400 invalid archive id`, `404 archive not found`, `409 state does not allow` |
| Traversal | `..` on workspace read/download/list, skill name, skill file, `%252e%252e` | `404` / `400`; no outside file read; `list` normalizes to the workspace root |

Two non-security API-semantics defects were observed and left unfixed: a
cross-task intercept-rule toggle returns success while changing nothing, and a
constraint miss returns `500` where `404` is expected. Neither mutates the
victim row. The `?token=` query parameter is accepted on every route (`200` on
`/api/tasks?token=…`); it is documented in the attack-surface reference as a
leakage/logging concern, and is retained because SSE clients need it.

## Test-fixture defect found by the second run

The first full-suite run was green; the second failed in `db` on fixed-name
rows (`t-retry-roundtrip`, `t-retry-clamp`, `t-pool-*`) and on a fixed CIDR
company scope. `db/llmretry_test.go` and `db/config_test.go` registered
row-deletion cleanups but used `defer d.Close()`, which runs before
`t.Cleanup`, so the DELETEs landed on a closed pool and silently failed.
`db/company_scope_test.go` deleted its assets but not the company that owned
the fixed `198.51.100.0/24` scope, so the next run's attribution went to the
stale company.

The patch (`evidence/db/patches/test-idempotency.patch`) registers `Close` as
the first `t.Cleanup` (LIFO: it runs last) and removes the test company. Two
consecutive full-suite runs after the patch are green. This is a fixture bug,
not a product bug; it is recorded because it would otherwise make every future
verification of this package unrepeatable.

## Recommended remediation

1. Apply `evidence/db/patches/workspace-symlink.patch` to `server/workspace.go`.
2. Extend `pathCrossesSymlink` to the skill file read/write/delete routes.
3. For a multi-tenant deployment, replace check-then-use with
   `openat`/`O_NOFOLLOW` and keep the regression in the suite.
4. Keep the disposable-cluster provisioning script with the repository so the
   DB-backed tests are reproducible rather than permanently skipped.
