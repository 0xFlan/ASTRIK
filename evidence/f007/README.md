# F-007 evidence — restore destination flip and the agent MCP stdio launcher

Two probes, both against the production server code and a disposable
PostgreSQL. `TestF007ArchiveRestoreDestinationFlip` calls the archive helper
directly because restore runs in the persistent archive worker, not a
synchronous HTTP route. `TestF007AgentMCPStdioChain` calls the real
`create_mcp` platform tool and then the same discovery path the startup worker
uses (`discoverAndCacheMCP`).

## Provisioning

```bash
bash evidence/db/provision-test-postgres.sh -q
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

`LC_ALL=C LANG=C` is required for `pg_ctl` on this macOS host. The script and
the per-package database creation are the F-005 ones; see `evidence/db/README.md`.

## Reproduce

```bash
cd <ARTEX-repo>          # fbe7839 + F-006 patches; add F-007 patches for the after run
cp <skill-repo>/evidence/f007/repro/zz_evidence_f007_test.go server/
ARTEX_PG_DSN="$ARTEX_PG_DSN" \
  go test ./server -run 'TestF007' -count=1 -v
```

The archive test is skipped on Windows because the swap uses POSIX symlink
semantics. Neither test needs an external fixture beyond the database.

## Patches

- `patches/archive-restore-single-root.patch` — product fix. Opens one
  `os.Root` on `dataDir`, derives `SourceRel`/`DestRel`, and uses
  `root.Lstat`/`root.MkdirAll`/`root.Rename` for install, rollback, and
  recovery; rejects an extraction outside the data dir; creates the `.restore`
  parent through the root; removes the now-unused `pathCrossesSymlink` from
  `workspace.go`.
- `patches/agent-mcp-stdio-boundary.patch` — product fix. Adds
  `validateAgentMCPTarget` (http/sse only, URL required) and applies it to
  `create_mcp` and `update_mcp`; `update_mcp` also refuses a missing id and an
  existing operator-managed stdio row.
- `patches/tests.patch` — tracked regression tests
  (`server/mcp_tool_boundary_test.go`, additions to
  `server/task_archive_package_test.go`). The MCP test covers agent stdio
  rejection, no persisted row, HTTP acceptance, and the operator route still
  accepting stdio. The archive test covers an outside extraction and a
  symlinked destination.

All three apply cleanly to the F-006 base commit
`8bb2245439a64bd66dd9b4f1ff46fe3d59a415e3` (`git apply --check` in a temporary
`git worktree`).

## Results

| Probe | Before | After |
|---|---|---|
| archive restore, `tasks/` swapped to outside link after the journal write | **20/20** outside writes, `installErr=<nil>` | **0/20**; rooted mkdir/rename refuse the link |
| archive restore, normal destination | restores inside `dataDir` | unchanged |
| archive restore, extraction outside `dataDir` | accepted | refused before the root is used |
| `create_mcp` stdio (`/bin/sh -c 'printf ARTEX-F007 > marker'`) | accepted, row persisted, no prompt | rejected before persistence |
| discovery after the stdio create | command executed, marker written (`discoverErr=mcp: connection closed`) | no row, no launch |
| `update_mcp` to stdio / on a stdio row | accepted | rejected |
| `create_mcp` http (positive control) | accepted | accepted |
| operator `POST /api/mcp` stdio (positive control) | accepted | accepted |

The before run logs:
`F-007 create_mcp accepted stdio` and
`F-007 GAP: agent-authored stdio MCP command executed on discovery`.
The after run logs:
`F-007 chain blocked at create_mcp: stdio MCP servers launch a local process
and are operator-only` and the HTTP positive control still accepted.

## Logs

- `logs/f007-before.log` — `TestF007` on the F-006 base with the F-007 fixes
  removed: 20 `destination link redirected the restore outside` lines plus the
  aggregate `F-007 GAP ... (20/20 attempts)`, `create_mcp accepted stdio`, and
  `F-007 GAP: agent-authored stdio MCP command executed on discovery`; both
  tests `FAIL`. The HTTP control is accepted in the same run, so the rejection
  after the fix is not a blanket refusal.
- `logs/f007-after.log` — the same probes on the fixed tree:
  `no outside write across 20 destination-symlink flips`, the stdio create
  rejected, HTTP control accepted; both tests `PASS`.
- `logs/go-test-run1.log`, `logs/go-test-run2.log` — two consecutive full
  `go test ./...` runs with `ARTEX_PG_DSN`: 14 packages `ok`, 0 `FAIL`, `server`
  21.469 s / 22.183 s. `TestLiveContextReview` is the only skip and needs an
  external live-model configuration.

Setup tokens and JWT values were redacted from the logs (`Setup token …`,
`token=eyJ…`); the probe's temporary key and data directories are gone.

## State

Confirmed and fixed locally. The upstream repository is not writable from this
skill repository, so the patches are committed here. The operator-charter model
and the "target content is data, not instructions" rule are unchanged.
