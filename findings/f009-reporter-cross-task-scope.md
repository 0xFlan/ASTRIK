# F-009 — Auto-triggered reporter crosses task scope to read and overwrite another task's evidence; global asset delete was Allowed

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | High (CVSS 3.1 7.1, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`). The reporter is an authenticated, auto-triggered agent and can read another task's evidence and overwrite its report. The destructive delete is a separate Allowed primitive but is operator-assisted, not remote |
| Affected | `server/conversations.go` (`runTriggeredRun` → `runConversationSync` → `Chat`), `agent/chat.go` (`RunInfo`), `server/orchestration.go` (`delegateToTask`, `toolUpdateFindingReport`, `wrTool`), `server/platform_tools.go` (`toolDeleteAssetsByHost`), `db/finding_traffic.go` at BaaRai/ARTEX `fbe7839` + F-008 |
| Trigger | A worker calls `report_finding`; the scheduler starts the `reporter` custom agent for that task. The reporter reads the finding (target-influenced evidence) and its toolset includes cross-task query tools and `update_finding_report` |
| Evidence | `evidence/f009/logs/`, `evidence/f009/repro/zz_evidence_f009_test.go` |
| Patch | `evidence/f009/patches/task-scope-and-delete-approval.patch`, `evidence/f009/patches/tests.patch` |

## Summary

The F-008 pass left two authority-boundary candidates: the global
`delete_assets_by_host` tool and the task-scoped agents' access to cross-task
management tools. This pass resolves both by observation.

The reporter agent is not an operator-only tool. It is a custom agent started
automatically by the `report_finding` trigger. Unlike Auto, it has a task: the
trigger event carries `task_id`, and the reporter is expected to read that task's
finding, traces, and report. But the task id was dropped before the run
(`runTriggeredRun` called `runConversationSync` without it, and `Chat` set
`RunInfo{SessionID}` only), and the tools it is bound to did not enforce a task
scope. `get_task_node_detail`, `get_task_worker_trace`, `list_task_findings`,
`get_task_graph`, and `search_task_worker_traces` delegate to any `task_id`;
`update_finding_report` accepts any global finding node id. The reporter is
therefore a cross-task read/write principal, and its input includes the
worker-supplied finding evidence, which is derived from target content.

The probe starts with the reporter's intended task-A context and calls those
tools against task B. Before the fix it reads task B's secret evidence and
overwrites task B's finding report. After the fix both calls are rejected with
`outside this run's task scope`, while the same reporter still reads and updates
task A, Auto's task-less platform view still reads task B, and the direct
operator report write still succeeds.

The second primitive is the global asset deletion. `delete_assets_by_host` is
bound to Auto, returns `Allowed` from `wrTool`, and hard-deletes every asset for
a host from the shared, cross-task library. Before the fix the probe's Auto
context deletes a task-B asset with no approval. After the fix the decision is
`ask` and no asset is removed; the direct operator `DeleteByHost` control still
removes a fresh asset. This primitive is **operator-assisted only**: F-008
established that Auto has no unattended target-to-turn entry, and this pass did
not run a live model. It is fixed because the same agent boundary exposed it,
not claimed as a remote delete.

## Observed result

| Probe | Before | After |
|---|---|---|
| reporter `get_task_node_detail(task_id=B)` from task A | B evidence returned | `outside this run's task scope` |
| reporter `update_finding_report(finding B)` from task A | B report overwritten | rejected; B unchanged |
| reporter reads/updates its own task A | works | works |
| Auto (no task scope) reads task B | works | works |
| Auto `delete_assets_by_host` on task B host | `allow`; asset deleted | `ask`; asset retained |
| direct operator `DeleteByHost` | works | works |
| direct operator `update_finding_report` on B | works | works |

The exact one-line evidence is:

```text
F-009 reporter_cross_read=true reporter_cross_write=true own_read=true own_write=true auto_read=true delete_decision=allow delete_allowed=true asset_deleted=true operator_delete=true operator_write=true
F-009 GAP: reporter read another task=true, overwrote another task=true, global delete was allowed=true
```

After the fix:

```text
F-009 reporter_cross_read=false reporter_cross_write=false own_read=true own_write=true auto_read=true delete_decision=ask delete_allowed=false asset_deleted=false operator_delete=true operator_write=true
```

## Reachability classification

**The reporter chain is authenticated-agent, auto-triggered.** It does not need
an operator to start a reporter turn: a finding registration starts it. The
attacker precondition is that target content, embedded in the finding evidence,
can influence the reporter's choice of tool arguments. The probe demonstrates
the permission and scope boundary directly; it does not run a live model, so it
does not claim that a particular injected string will always steer the model.
The defect is still real without that claim: the reporter's tools accept
arbitrary task ids and finding ids, so any successful instruction (or a
confused/erroneous model) reaches another task without a second authorization
decision.

**The delete chain is operator-assisted.** Auto is a `ChatAgent` whose only
turn entries are operator conversation/side questions; scheduler and triggers
do not target it. Target content reaches Auto's read tools only after an
operator request. The delete tool is Allowed and irreversible, but the probe
does not establish an unattended target-to-Auto path. This is the same
classification F-008 recorded for the MCP chain.

## Root cause

Three independent assumptions combined:

1. **The trigger's task id never reached the run.** `runTriggeredRun` had
   `item.taskID`, but `runConversationSync` and `runConversationTurn` did not
   carry it, and `Chat` created `RunInfo` with only the session id. Every
   downstream tool saw `TaskID=0`, the "unknown/operator" value.
2. **The cross-task tools trusted the caller's `task_id`.** `delegateToTask`
   looked up any task and built a ToolSet for it; it never compared the
   requested id with the run's task.
3. **The report writer was global by node id.** `update_finding_report` wrote
   `SetFindingReportVersionByNodeID` without checking the finding's task, and
   the node id is enumerable.

The delete tool was a separate missing gate: the platform's most destructive
asset operation used the same unconditional `wrTool` as read-only metadata
tools.

## Fix

- `runTriggeredRun` passes `item.taskID` to `runConversationSync`; both sync and
  turn paths thread it to `Chat`.
- `Chat` sets `RunInfo{TaskID: taskID, SessionID: sessionID}`. Manual chat keeps
  `TaskID=0` (the platform-wide Auto/operator view).
- `delegateToTask` rejects a requested task that differs from a non-zero
  `RunInfo.TaskID`; Auto's zero scope is unchanged.
- `update_finding_report` looks up the finding's task and rejects a finding
  outside a non-zero run scope. `FindingTaskIDByNodeID` treats a deleted task as
  not owned.
- `delete_assets_by_host` now uses `wrAskTool` and returns `AskUser` with an
  explicit irreversible-deletion message. The operator/direct store path is
  unchanged.
- Regression tests: `server/agent_scope_test.go` covers cross-task read/write
  denial, own-task success, Auto's platform-wide read, delete `ask`, and the
  direct-delete control. `agent/chat_runinfo_test.go` verifies the actual Chat
  run carries the task id.

## Residual limits

- **No live-model prompt-injection test.** The probe demonstrates the
  authorization boundary, not model susceptibility. The classification is
  authenticated-agent/auto-triggered with target-influenced input, not an
  unauthenticated remote exploit.
- **`merge_mode=all` across tasks.** A merged trigger has one `RunInfo.TaskID`
  (the first task). The scope check is conservative: a reporter merged across
  tasks may be blocked from later tasks rather than allowed to cross them. The
  seeded reporter uses `merge_mode=none`; changing merge policy should be
  reviewed separately.
- **Traffic A5 is still a candidate.** Traffic remains instance-global; this
  pass did not add a task filter to `traffic_search`/`traffic_get`, so the
  cross-task credential-replay candidate is not demonstrated.
- **Prompt templates and trigger configuration** remain route-by-route
  unverified. They were not needed for this chain.
- The fix assumes the task id in the trigger is authoritative. It is set by the
  scheduler from the event's task, not by the model.

## Negative results

- **No unattended Auto delete path.** Auto's only entries are operator
  conversation/side questions; no scheduler or trigger targets it. The global
  delete is fixed as defense-in-depth, not claimed as remotely reachable.
- **The reporter's own task remains usable.** The scope check does not block
  legitimate report writing; the own-task read/update controls pass.
- **Auto's platform-wide view remains usable.** A zero `RunInfo.TaskID` (Auto,
  operator chat) is deliberately unscoped, and the Auto read control passes.
- **No cross-task write via the direct operator path.** The direct
  `SetFindingReportVersionByNodeID` control still writes B; the restriction is on
  the agent tool, not on the operator/database primitive.

## Reproduction

```bash
# Disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>          # pre-F-009 audit baseline `2e3c8f8`; add the F-009 patches for the after run
cp <skill-repo>/evidence/f009/repro/zz_evidence_f009_test.go server/
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF009Evidence -count=1 -v
```

Before the fix the probe fails at `F-009 GAP: reporter read another task=true,
overwrote another task=true, global delete was allowed=true`; after the fix it
passes with all three `false` and every positive control `true`. Logs:
`evidence/f009/logs/f009-before.log`, `f009-after.log`.

## Verification

With the disposable PostgreSQL, the full `go test ./...` is green twice in a
row: 14 packages `ok`, 0 `FAIL`, `server` 22.644 s and the second run cached.
The only skip is `TestLiveContextReview`, which needs an external live-model
configuration. Logs: `evidence/f009/logs/go-test-run1.log`,
`go-test-run2.log`.

The two patches apply cleanly to the F-008 baseline commit
`2e3c8f8a6e0b96f761b8036bf05c7f724192bb57` (`git apply --check` in a temporary
`git worktree`). The tracked regression tests are
`server/agent_scope_test.go` and `agent/chat_runinfo_test.go`.

## Recommended remediation

1. Apply both F-009 patches to the F-008 baseline and run the probe.
2. Keep `RunInfo.TaskID` populated for every trigger-started agent and enforce
   it at every tool that accepts a task id or a global node id. Do not rely on
   the prompt to say "only this task."
3. Keep the destructive asset deletion behind `AskUser`; do not restore the
   unconditional `wrTool` wrapper for a purge/delete/overwrite/detach tool.
4. Add a task filter to the traffic tools (A5) and a live-model prompt-injection
   probe before claiming remote reachability for the reporter chain.
