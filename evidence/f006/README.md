# F-006 evidence — file-route confinement and os.Root

All probes ran through the production `Server.Handler()` (CORS → `requireAuth`
→ `ServeMux`) on a loopback listener with a valid JWT, against a disposable
PostgreSQL. The archive-restore case calls `installTaskArchiveFiles` directly
because restore runs in the persistent archive worker rather than a synchronous
route.

## Provisioning

```bash
bash evidence/db/provision-test-postgres.sh -q
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

The script is the F-005 one; it initializes a trust-auth PostgreSQL 17 cluster
on `127.0.0.1:55432`, and `db.Open` creates the per-package suffixed databases
and applies the embedded schema. `LC_ALL=C LANG=C` is required for `pg_ctl` on
this macOS host.

## Reproduce

```bash
cd <ARTEX-repo>          # BaaRai/ARTEX at fbe7839 with the patches applied
cp <skill-repo>/evidence/f006/repro/zz_evidence_confinement_test.go server/
ARTEX_PG_DSN="$ARTEX_PG_DSN" \
  go test ./server -run TestFileRouteConfinementMatrix -count=1 -v
```

The probe fails on the unpatched code at each `F-006 GAP` assertion and passes
after `patches/file-route-confinement.patch`. It creates its own temporary
skill/data dirs and links; no external fixture is needed.

## Patches

- `patches/file-route-confinement.patch` — product fix for `workspace.go`,
  `server_mgmt.go`, `chatupload.go`, `platform_tools.go`, `ask_operator.go`,
  `task_archive_package.go`. Applies cleanly to `fbe7839` (`git apply --check`
  verified in a temp worktree). It supersedes
  `evidence/db/patches/workspace-symlink.patch` for `workspace.go`.
- `patches/test-skill-gaps-isolation.patch` — clears the global `skill_usage`
  table around `TestSkillGapsReport`; the report is global, so leftover rows
  from earlier runs made the ordering assertion non-repeatable.

## Results

| Probe | Before (unpatched) | After |
|---|---|---|
| `skill-read-filelink` | `200` + `ARTEX-OUTSIDE-CANARY-F006` | `400 invalid path` |
| `skill-write-filelink` | `200`, outside canary changed | `400 invalid path` |
| `skill-read-dirlink` | `200` + outside victim | `400 invalid path` |
| `skill-mkdir-dirlink` | `201`, outside dir created | `400 invalid path` |
| `skill-delete-dirlink` | `200`, outside victim deleted | `400 invalid path` |
| `skill-read-nested` | `200` + outside content | `400 invalid path` |
| `skill-meta-symlink` | `200`, outside `SKILL.md` rewritten | `400 invalid path` |
| `chat-upload-symlink` | `200`, outside upload written | `400 invalid path` |
| archive restore, symlinked `tasks/` | outside file, `err=nil` | error, no outside file |
| skill write/read/mkdir/delete controls | `200`/`201` | `200`/`201` |
| chat upload control | `200`, file in work dir | `200`, file in work dir |
| workspace controls | `200` | `200` |

Negative evidence: `..`, double-encoded `..`, absolute, and backslash skill
paths returned `400` both before and after; deleting a skill whose directory is
a symlink removed only the link; workspace symlink probes returned `400` on the
F-005 code and still do.

## Logs

- `logs/f006-before.log` — the full matrix on the pre-fix tree; seven
  `F-006 GAP` lines (skill read/write/dir-read/mkdir/delete/meta, chat upload).
  The archive probe in this run was the earlier, incorrectly ordered version,
  so its gap is recorded separately.
- `logs/f006-after.log` — the same matrix after the fix; `PASS`, every escape
  `400 invalid path`.
- `logs/f006-archive-before.log` — the archive assertion with only the restore
  parent check removed: `F-006 GAP ... (err=<nil>)`, test `FAIL`.
- `logs/f006-archive-after.log` — the check restored: `ok`.
- `logs/go-test-run1.log`, `logs/go-test-run2.log` — two consecutive full
  `go test ./...` runs with `ARTEX_PG_DSN` set: 14 packages `ok`, 0 `FAIL`,
  `server` 20.672 s / 21.368 s. `TestLiveContextReview` is the only skip and
  needs an external live-model configuration.

JWT values and per-test setup tokens were redacted from the logs (`token=eyJ…`
and `Setup token …`); the probe's ephemeral key directory is gone.

## State

Confirmed and fixed locally. The upstream repository is not writable from this
skill repository, so the patches are committed here. The operator-charter model
and the "target content is data, not instructions" rule are unchanged.
