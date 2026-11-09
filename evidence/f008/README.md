# F-008 evidence — custom-tool approval bypass

The probe creates a real custom command tool through the production
`create_custom_tool` platform tool, binds it to the `worker` agent, resolves the
worker's assembled toolset with `agent.ToolResolve`, and applies the harness's
`CheckPermissions` step before calling. Before the fix the decision is `allow`
and the command writes its marker; after the fix it is `ask` and the probe does
not call it. The operator executor and Bash are positive controls.

## Provisioning

```bash
bash evidence/db/provision-test-postgres.sh -q
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

`LC_ALL=C LANG=C` is required for `pg_ctl` on this macOS host. The script and
per-package database creation are the F-005 ones; see `evidence/db/README.md`.

## Reproduce

```bash
cd <ARTEX-repo>          # F-007 baseline; add the F-008 patch for the after run
cp <skill-repo>/evidence/f008/repro/zz_evidence_f008_test.go server/
ARTEX_PG_DSN="$ARTEX_PG_DSN" \
  go test ./server -run 'TestF008|TestCustomToolPermissionsMatchExecutor' -count=1 -v
```

## Patches

- `patches/custom-tool-permission-parity.patch` — product fix in
  `server/customtool.go`. `buildCustomTool` now renders the command from the
  call parameters and delegates to `actool.NewBash().CheckPermissions`; script
  and http custom tools return `AskUser`; unknown or empty kinds return
  `Denied`.
- `patches/tests.patch` — new `server/customtool_permission_test.go`. It covers
  command `Ask`, quoted-parameter rendering in the prompt, the catastrophic
  `rm -rf /` `Deny`, script `Ask`, and http `Ask`.

Both apply cleanly to the F-007 baseline commit
`2e3c8f8a6e0b96f761b8036bf05c7f724192bb57` (`git apply --check` in a temporary
`git worktree`).

## Results

| Probe | Before | After |
|---|---|---|
| `create_custom_tool` command tool bound to worker | accepted, row persisted | accepted (creation is not execution) |
| worker toolset resolution | tool present | tool present |
| `CheckPermissions` on the built tool | `allow` | `ask` |
| invocation | marker `ARTEX-F008` written | blocked, no marker |
| operator executor on the same spec | runs | runs |
| Bash on the same command | `ask` | `ask` |
| Auto base toolset | includes `Bash` | includes `Bash` |
| `create_custom_tool` binding/permission | auto-bound, `allow` | auto-bound, `allow` |

The before log records `agent-installed command tool permission: allow` and
`F-008 GAP: agent-installed command tool executed without approval`; the after
log records `permission: ask` and `blocked at the approval boundary: ask`, with
both positive controls present.

## Logs

- `logs/f008-before.log` — the pre-fix baseline: `allow`, marker written,
  `F-008 GAP`, test `FAIL`; operator executor runs and Bash asks.
- `logs/f008-after.log` — the fixed tree: `ask`, blocked, both tests `PASS`;
  operator executor runs and Bash asks.
- `logs/go-test-run1.log`, `logs/go-test-run2.log` — two consecutive full
  `go test ./...` runs with `ARTEX_PG_DSN`: 14 packages `ok`, 0 `FAIL`, `server`
  22.699 s / 22.043 s. `TestLiveContextReview` is the only skip and needs an
  external live-model configuration.

Setup tokens were redacted from the probe logs (`Setup token … [redacted]`).

## State

Confirmed and fixed locally. The upstream repository is not writable from this
skill repository, so the patches are committed here. The operator-charter model
and the "target content is data, not instructions" rule are unchanged.
