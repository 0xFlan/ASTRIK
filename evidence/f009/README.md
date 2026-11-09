# F-009 evidence — reporter cross-task scope and destructive delete approval

The probe creates two tasks and two findings. It runs the reporter's assembled
toolset with task A's `RunInfo`, then calls `get_task_node_detail(task_id=B)`
and `update_finding_report(finding B)`. It also calls the Auto-bound
`delete_assets_by_host` against a task-B asset. Before the fix the reporter
reads and overwrites B and the delete returns `allow` and removes the asset;
after the fix the cross-task calls return `outside this run's task scope`, the
delete returns `ask`, and every positive control still succeeds.

## Provisioning

```bash
bash evidence/db/provision-test-postgres.sh -q
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

`LC_ALL=C LANG=C` is required for `pg_ctl` on this macOS host. See
`evidence/db/README.md`.

## Reproduce

```bash
cd <ARTEX-repo>          # F-008 baseline; add the F-009 patches for the after run
cp <skill-repo>/evidence/f009/repro/zz_evidence_f009_test.go server/
ARTEX_PG_DSN="$ARTEX_PG_DSN" \
  go test ./server -run TestF009Evidence -count=1 -v
```

## Patches

- `patches/task-scope-and-delete-approval.patch` — product fix:
  `runTriggeredRun`/`runConversationSync`/`Chat` carry the task id into
  `RunInfo`; `delegateToTask` and `update_finding_report` enforce it; the new
  `FindingTaskIDByNodeID` lookup supports the finding check; and
  `delete_assets_by_host` moves to `wrAskTool` (`AskUser`).
- `patches/tests.patch` — `server/agent_scope_test.go`,
  `agent/chat_runinfo_test.go`, and the `Chat` signature update in
  `agent/side_questions_test.go`.

Both apply cleanly to the F-008 baseline commit
`2e3c8f8a6e0b96f761b8036bf05c7f724192bb57` (`git apply --check` in a temporary
`git worktree`).

## Results

| Probe | Before | After |
|---|---|---|
| reporter cross-task read (A context, task B) | B evidence returned | `outside this run's task scope` |
| reporter cross-task report write | B report overwritten | rejected; B unchanged |
| reporter own-task read/update | works | works |
| Auto platform-wide read of B | works | works |
| Auto delete on task B host | `allow`, asset deleted | `ask`, asset retained |
| direct operator delete | works | works |
| direct operator report write on B | works | works |

The before log records
`F-009 reporter_cross_read=true ... delete_decision=allow ... asset_deleted=true`
and `F-009 GAP: reporter read another task=true, overwrote another task=true,
global delete was allowed=true`. The after log records all three `false` and
all positive controls `true`.

## Logs

- `logs/f009-before.log` — clean `2e3c8f8` worktree plus the probe; expected
  `FAIL` at `F-009 GAP`.
- `logs/f009-after.log` — fixed tree plus the probe; `PASS`.
- `logs/go-test-run1.log`, `logs/go-test-run2.log` — two full DB-backed
  `go test ./...` runs: 14 packages `ok`, 0 `FAIL`; `server` 22.644 s on run 1,
  run 2 cached. `TestLiveContextReview` is the only skip and needs an external
  live-model configuration.

Setup tokens were redacted from the probe logs (`Setup token … [redacted]`).

## Reachability

The reporter is authenticated and auto-triggered by `report_finding`; the
finding evidence is target-influenced. The probe demonstrates the authorization
boundary, not a live-model injection success. Auto's delete path remains
operator-assisted: Auto has no scheduler/trigger entry and target content reaches
it only after an operator request. No live-model prompt-injection test was run.

## State

Confirmed and fixed locally. The upstream repository is not writable from this
skill repository, so the patches are committed here. The operator-charter model
and the "target content is data, not instructions" rule are unchanged.
