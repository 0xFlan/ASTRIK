# F-008 — Agent-bound custom tools bypass the Bash approval gate; the F-007 MCP chain is operator-assisted, not remote

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | High (approval-boundary bypass to unattended command execution; CVSS 3.1 7.5, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`). This is not privilege escalation from an agent that already has Bash; it removes the approval gate that Bash enforces |
| Affected | `server/customtool.go` (`buildCustomTool`, `runCommandTool`), `server/platform_tools.go` (`toolCreateCustomTool`, `toolUpdateCustomTool`), `server/orchestration.go` (`wrTool`), `agent/chat.go` (Auto's base toolset) at BaaRai/ARTEX `fbe7839` + F-007 |
| Trigger | An agent-bound custom tool with `kind=command`, `script`, or `http` is invoked after `create_custom_tool`/`update_custom_tool` persisted it |
| Evidence | `evidence/f008/logs/`, `evidence/f008/repro/zz_evidence_f008_test.go` |
| Patch | `evidence/f008/patches/custom-tool-permission-parity.patch`, `evidence/f008/patches/tests.patch` |

## Summary

F-007 closed the MCP stdio launch path but left the other agent-facing executor
alone. `create_custom_tool` and `update_custom_tool` are platform writes bound to
the Auto agent and their `wrTool` wrapper returns `permission.Allowed()`. They
accept `kind=command` with an arbitrary `exec.command`, `kind=script` with Python
code, and `kind=http` with a method/URL/body. `buildCustomTool` then wrapped
**every** kind in `permission.Allowed()`, while `runCommandTool` calls
`actool.NewBash().Call` directly. The harness only evaluates the outer custom
tool's permission, so Bash's `bashPermissions` — the `AskUser` prompt and the
irreversibly-destructive safety floor — never ran.

The probe drives the real `create_custom_tool` with a command tool bound to the
`worker` agent, resolves the worker's assembled toolset through
`agent.ToolResolve`, and applies the same `CheckPermissions` step the harness
uses. Before the fix the decision was `allow` and the command wrote its marker;
after the fix it is `ask`, the probe does not call it, and no marker is written.
The operator-facing executor still runs the same spec (positive control), and
Bash itself still returns `ask` (control).

This is an approval-boundary bypass, not a new capability: every agent's base
includes Bash. It matters because the approval gate is the platform's safety
control, and a custom tool can be bound to an autonomous worker that processes
target content. Once the tool exists, the bypass is deterministic; the probe
demonstrates that gate directly rather than relying on a model's cooperation.

## Part 1 — The permission bypass

| Step | Before | After |
|---|---|---|
| `create_custom_tool` with `kind=command`, `agents=["worker"]` | accepted, row persisted, no approval | accepted (creation is not execution) |
| worker toolset resolution | tool present | tool present |
| `CheckPermissions` on the built tool | `allow` | `ask` |
| invoke the tool | command runs; `ARTEX-F008` marker written | blocked at the approval boundary; no marker |
| operator executor on the same spec | runs (positive control) | runs (positive control) |
| Bash on the same command | `ask` | `ask` |

The pre-fix wrapper:

```go
return actool.Build(actool.Spec{
    Name: key, Description: t.Description, Schema: schema,
    Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
        return permission.Allowed()
    },
    Run: run,
})
```

The executor:

```go
func (s *Server) runCommandTool(...) (actool.Result, error) {
    ...
    return actool.NewBash().Call(ctx, bashIn, tc)
}
```

`CoreTool.Call` runs the handler; it does not consult `CheckPermissions`. The
harness calls `CheckPermissions` on the tool the model selected. Because the
selected tool is the custom tool, its `Allowed` verdict is final and the inner
Bash permission is never reached. The same pattern covered `script` (Python via
`exec.CommandContext`) and `http` (arbitrary request, optional proxy).

## Part 2 — F-007 reachability answer

F-007 proved that an Allowed `create_mcp` stdio target is launched by
`discoverMCP`/`discoverEmptyMCPsOnStartup`, but it explicitly left open whether
an attacker can steer Auto into making the call. The answer from this pass is
**operator-assisted only, not remotely autonomous**:

1. **Auto's only message entries are operator paths.** Auto is a `ChatAgent`
   driven by `POST /api/conversations/{id}/messages` and the side-question
   route; the scheduler and trigger system target custom agents, not Auto. No
   task, finding, or target response invokes Auto on its own.
2. **Target content reaches Auto only through a read tool.** Auto's
   orchestration tools (`list_task_findings`, `get_task_worker_trace`,
   `list_worker_traces`, `search_worker_traces`, `get_task_node_detail`) return
   target-derived text, so an operator who asks Auto to review a finding can
   expose injected instructions. That still requires the operator's request and
   the model's choice; this pass did not run a live model and does not claim a
   model-susceptibility result.
3. **F-007's impact was overstated.** `agent/chat.go` builds the ChatAgent base
   from `actool.DefaultTools()`, which includes `Bash` (AskUser-gated). The
   stdio MCP launch therefore did not add host command execution to Auto; it
   bypassed the MCP-specific approval gate and persisted a launcher that retries
   at startup. The correct F-007 severity is Medium (approval/persistence
   boundary), not a new code-execution capability. F-007's finding now carries
   this correction.

F-008 is independent of that unresolved model question. The bypass is in the
permission decision of the tool itself: any agent bound to a command custom tool
gets `allow`, including a worker that is processing hostile target content. The
creation step is Allowed to Auto, but the gate defect remains even for a tool an
operator created deliberately.

## Why this is reachable

`create_custom_tool` is in `platformToolKeys`, seeded for Auto, and returns
`Allowed` from `wrTool`. The schema accepts `agents` directly, so one call can
bind the new tool to `worker`, `pentest`, or another executor. `customTools()`
rebuilds the callable set from `ListCustomTools()` on every assembly, and
`ToolResolve` filters only by `Enabled` and `Agents`; the wrapper's permission
is carried through `DecorateTool` and `meterTool` unchanged.

A worker processes pages, API responses, tickets, and files supplied by the
target. If it is bound to a command tool, target content that induces a call
does not need the Bash approval prompt. The probe demonstrates the gate and the
binding; it does not require a live model to show that the gate is absent.

## Root cause

Authority was attached to the executor (`Bash` asks) but not to the wrapper that
re-exposes it (`buildCustomTool` allows). The wrapper also hid the rendered
command from the approval layer: even if a prompt were shown, it would be for
the custom tool name, not the command line. The fix moves the decision to the
same place Bash makes it, with the template rendered from the call's parameters
and shell-quoted.

## Fix

`buildCustomTool` now assigns a permission function per kind:

- **command** — parse the input parameters, render the template exactly as the
  executor will (`renderTemplate(..., shellQuote)`), marshal
  `{"command": ...}`, and delegate to `actool.NewBash().CheckPermissions`. This
  inherits both the catastrophic-command denial and the `AskUser` prompt, and the
  prompt shows the real command line.
- **script** — `AskUser("run python custom tool: <key>")`.
- **http** — `AskUser("run http custom tool: <key>")`.
- **unknown/empty** — `Denied`.

`runCommandTool` is unchanged; it remains the shared low-level executor for the
operator test route and approved calls. Creation remains Allowed: creating a
tool is not executing it, and the approval belongs at invocation.

## Residual limits

- `create_custom_tool`/`update_custom_tool` can still create and rebind
  executable tools without approval. The invocation gate is the fix; if the
  platform wants to prevent an agent from even staging an executable tool, that
  is a separate policy decision that would break the Auto "install the tool"
  workflow.
- `delete_assets_by_host` remains an Allowed, irreversible write bound to Auto.
  It was outside this chain (no code execution) and is recorded as the next
  authority-boundary candidate rather than silently changed.
- `ModeBypass` still allows everything by explicit operator choice; the fix
  restores the default/`auto`/`dontAsk` behavior, not an absolute sandbox.
- Auto's operator-assisted status means the F-007 MCP chain is not claimed as a
  remote exploit. A live-model prompt-injection test remains open.

## Negative results from this pass

- **No autonomous Auto entry point.** Conversation and side-question routes are
  the only paths that start an Auto turn; the scheduler and triggers do not
  target the built-in Auto agent. Target content can be read by Auto's tools,
  but only after an operator request.
- **No new cross-task read demonstrated.** Traffic remains instance-global
  (A5); this pass did not implement task scoping, so the credential-replay
  candidate is still a candidate, not a finding. Archive restore routes act on
  the archive's own task; no cross-task read was observed.
- **JWT boundary unchanged.** The F-003 shapes still reject; this pass added no
  new token-forgery primitive.
- **Custom HTTP tools are gated, not removed.** The operator test route and
  approved calls still execute; a rejected call does not run.

## Reproduction

```bash
# Disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>          # F-007 baseline, then the F-008 patch for the after run
cp <skill-repo>/evidence/f008/repro/zz_evidence_f008_test.go server/
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run 'TestF008|TestCustomToolPermissionsMatchExecutor' -count=1 -v
```

Before the fix the probe fails at `F-008 GAP: agent-installed command tool
executed without approval`; after the fix it passes with `permission: ask` and
`blocked at the approval boundary`, while the operator executor and Bash control
still run/ask as expected. Logs: `evidence/f008/logs/f008-before.log`,
`f008-after.log`.

## Verification

With the disposable PostgreSQL, the full `go test ./...` is green twice in a
row: 14 packages `ok`, 0 `FAIL`, the `server` package in 22.699 s and 22.043 s.
The only skip is `TestLiveContextReview`, which needs an external live-model
configuration. Logs: `evidence/f008/logs/go-test-run1.log`, `go-test-run2.log`.

The two patches apply cleanly to the F-007 baseline commit
`2e3c8f8a6e0b96f761b8036bf05c7f724192bb57` (`git apply --check` in a temporary
`git worktree`). The tracked regression test is
`server/customtool_permission_test.go`; it asserts command `Ask` (including a
quoted-parameter prompt), the catastrophic-command `Deny`, and script/http
`Ask`.

## Recommended remediation

1. Apply both F-008 patches to the F-007 baseline and run the probe.
2. Keep the permission function per kind in `buildCustomTool`; do not replace it
   with a blanket allow when adding a new kind.
3. Treat creation and invocation as separate authority decisions: a new executor
   kind must inherit the wrapped executor's safety floor, not only its run path.
4. Gate `delete_assets_by_host` (and any other irreversible platform write)
   behind the same approval boundary in a follow-up.
5. If remote Auto reachability matters, add a live-model prompt-injection probe
   with planted finding/traffic text; until then, keep the operator-assisted
   classification.
