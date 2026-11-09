# F-007 — Archive restore still races a destination symlink; the agent-facing MCP tool installs a stdio launcher outside the approval gate

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | High (agent tool authority bypass to persistent host command execution; CVSS 3.1 7.5, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`). Archive restore is Medium on its own (authenticated host write during restore) |
| Affected | `server/task_archive_package.go`, `server/task_archives.go`, `server/workspace.go` (residual race) at BaaRai/ARTEX `fbe7839` + F-006; `server/platform_tools.go` (agent MCP tools) |
| Trigger | A restore destination link swapped after the pre-fix check; an agent tool call to `create_mcp` with `transport=stdio` and a command |
| Evidence | `evidence/f007/logs/`, `evidence/f007/repro/zz_evidence_f007_test.go` |
| Patch | `evidence/f007/patches/archive-restore-single-root.patch`, `evidence/f007/patches/agent-mcp-stdio-boundary.patch`, `evidence/f007/patches/tests.patch` |

## Summary

F-006 replaced the file routes with `os.Root` but explicitly left one
check-then-use path: `installTaskArchiveFiles` validated the restore destination
with `pathCrossesSymlink`, wrote the journal, then called `os.MkdirAll` and
`os.Rename` on the same re-resolved absolute path. The link could be swapped
between the check and the rename. The F-007 probe waits for the journal — which
is written after the check and before the first rename — replaces
`<dataDir>/tasks` with a link to an outside directory, and records whether the
restore writes outside. On the F-006 tree it did so in **20/20 attempts**, each
with `installErr=<nil>`.

The same pass widened the chain hunt to the agent-tool authority boundary.
`create_mcp` and `update_mcp` are platform tools seeded into the `tools` table
and bound to the built-in Auto agent. Their `wrTool` wrapper returns
`permission.Allowed()` unconditionally, and `toolCreateMCP` accepted
`transport=stdio` with an arbitrary `command`/`args`. MCP *tool calls* are
`AskUser`-gated, but the *launch configuration* is not: `connectMCP` starts a
stdio server with `mcp.NewStdioClient(command, args)`, and
`discoverEmptyMCPsOnStartup` walks every enabled MCP with an empty cache at
server startup regardless of which agent can see it. A row written through the
Allowed tool therefore becomes host command execution on the next discovery,
with no approval prompt and no task still running.

The probe drives the real `create_mcp` tool with
`/bin/sh -c 'printf ARTEX-F007 > <marker>'`, then calls the same discovery path
the startup worker uses. The marker appeared (`discoverErr=mcp: connection
closed`, because the stub command exits after writing). After the fix
`create_mcp` refuses stdio before persisting, `update_mcp` refuses an existing
stdio row and any stdio target, and the same tool still accepts an `http` MCP
(positive control). The operator route `POST /api/mcp` keeps stdio, because
that is the intended place for an operator to install a local server.

The two defects are reported together because they share the F-006 root cause:
a security decision was made on one resolution and the operation used another,
and an authority check was attached to the invocation rather than to the
capability being configured.

## Part 1 — Archive restore destination flip

| Probe | Before (F-006 tree) | After |
|---|---|---|
| restore with `tasks/` swapped to an outside link after the journal write | **20/20** wrote `<outside>/42/artifact.txt`, `err=<nil>` | **0/20**; `root.MkdirAll`/`root.Rename` refuse the link |
| restore with a normal destination | files restored inside `dataDir` | unchanged |
| restore extraction outside `dataDir` | accepted by the lexical check | refused before any write |

The pre-fix code:

```go
for _, move := range sources {
    if pathCrossesSymlink(dataDir, move.Destination) {   // check
        return nil, fmt.Errorf("restore destination crosses a symlink")
    }
    ...
}
writeArchiveJournal(...)                                  // window opens
for _, move := range sources {
    os.MkdirAll(filepath.Dir(move.Destination), 0o755)    // second resolution
    os.Rename(move.Source, move.Destination)
}
```

`pathCrossesSymlink` walks the path at check time. Between the check and the
rename there is a journal write and a sync; the probe polls for the journal and
swaps the parent in that window. Because `os.MkdirAll` and `os.Rename` resolve
the path again in the kernel, the swap is followed. The task id is numeric and
the parents are server-created, so this is not attacker-chosen path traversal;
it is a race on a directory the server itself owns. The impact is a restore
write outside the data dir, which is why it is Medium on its own.

### Fix

`installTaskArchiveFiles` now opens **one** `os.Root` on `dataDir` and uses it
for the extraction source, the destination, and rollback. Absolute paths are
mapped to root-relative names once (`restoreRel`, `newRestoredArchivePath`);
`root.Lstat`, `root.MkdirAll`, and `root.Rename` resolve every component
through the same descriptor, so there is no check-then-use interval and a link
swapped at any point is refused. A path outside `dataDir` is rejected before
the root is used, and journal recovery re-derives the relative names and
refuses an escape. `.restore` parent creation in `task_archives.go` goes
through the same root, and `pathCrossesSymlink` is deleted from
`workspace.go` because no route uses it any more.

`os.Root` cannot rename across two roots; that is exactly why the old code had
two resolutions. Deriving both names under one `dataDir` root removes the
second root instead of checking between them.

## Part 2 — Agent MCP stdio launch chain

| Stage | Action | Result before | Result after |
|---|---|---|---|
| 1 | Auto agent calls `create_mcp` with `transport=stdio`, `command=/bin/sh`, `args=["-c","printf ARTEX-F007 > marker"]` | accepted, row persisted, no prompt | rejected: `stdio MCP servers launch a local process and are operator-only` |
| 2 | startup/discovery path `discoverAndCacheMCP` → `connectMCP` → `mcp.NewStdioClient` | command executed; marker written | no row, no launch |
| 3 | `update_mcp` on an existing stdio row, or changing a row to stdio | accepted | rejected before the save |
| 4 | `create_mcp` with `transport=http` + `url` (positive control) | accepted | accepted |
| 5 | operator `POST /api/mcp` with stdio (positive control) | accepted | accepted |

The important asymmetry is in the permission model, not in the transport:
`wrTool` gives every platform write `permission.Allowed()`, while the MCP
tools that a stdio server exposes are `AskUser`-gated when called. An agent that
can be steered to call `create_mcp` can therefore install the launcher without
the prompt that the resulting tools would require. Startup discovery does not
consult visibility at all — it iterates `ListMCP()` and launches every enabled
row whose cache is empty — so the command also runs when no agent is using the
server, and it runs again after a restart if the cache stays empty (for example
because the command is a one-shot that exits, as in the probe).

`discoverEmptyMCPsOnStartup` is asynchronous and best-effort; a failed handshake
leaves the cache empty, which makes the row retry on the next start. That is
normal for a seeded browser MCP, but for an agent-authored stdio row it is a
persistence mechanism: the command does not need a successful MCP session, only
the launch.

### Fix

`validateAgentMCPTarget` accepts only `http`/`sse` with a non-empty URL for the
agent-facing tools. `toolCreateMCP` calls it before `SaveMCP`, so a rejected
stdio row is never persisted. `toolUpdateMCP` loads the existing row, refuses a
missing id, refuses an existing stdio row (operator-managed), and validates the
new target, so an http row cannot be converted to stdio either. The operator
route is untouched: `POST /api/mcp` still creates stdio servers, which keeps the
System → MCP workflow and the seeded browser MCP working.

This is a boundary fix, not a feature removal: the capability remains, but only
for the principal that is allowed to install local processes without an agent
prompt.

## Why the chain is reachable

The Auto agent is the platform's operations assistant. Its prompt directs it to
`create_mcp`/`update_mcp` when the operator asks for an MCP server, and the
tools are bound to it by default (`platformToolKeys`, `seedAutoDefaultBindings`).
The write tools are unconditionally Allowed, so no permission prompt stands
between the model's tool call and the persisted launch command.

The remaining precondition is steering: the attacker needs the Auto agent to
call `create_mcp` with an attacker-chosen command. That can come from operator
chat (a support ticket, a pasted MCP configuration, a repository README) or from
target-derived text that is relayed into the Auto conversation. This probe
demonstrates the tool boundary and the execution, not an unprompted
content-to-Auto path. In a deployment where the executor already has host shell
access, this is not privilege escalation *from that executor*; it is an
authority-boundary bypass for the operations agent plus persistence beyond the
task, which is the part the MCP `AskUser` gate was supposed to prevent.

## Negative results from this pass

- **Custom HTTP tool → SSRF.** `create_custom_tool`/`update_custom_tool` are
  also Allowed platform writes and accept a URL, but the tool is only invoked
  by an agent that is bound to it, and the request is made from the same host
  the agent can already reach with Bash. No cross-tenant read or metadata
  credential was reachable through it in this pass, so it is recorded as a
  lower-value duplicate of the agent's own egress rather than a separate
  finding.
- **Traffic blob hash and evidence path.** `blobHashRe` validates the blob
  hash, and `hashPath` validates the evidence path before use; no traversal or
  arbitrary-file read held.
- **JWT in browser storage.** The token is in `localStorage`/cookie but no HTML
  sink renders it; the auth boundary probes from F-003 still hold.
- **Archive ZIP/tar traversal.** Re-ran the F-004 matrix on the F-007 tree:
  every traversal, absolute, link, hardlink, and FIFO entry is still rejected;
  no outside canary.
- **Restore extraction outside the data dir.** The single-root install refuses
  it; this closes the "source is outside the root" variant rather than adding a
  new check on the destination alone.

## Residual limits

- The restore probe swaps `tasks/` after the journal appears. On the fixed
  tree the swap happens too, but `root.MkdirAll`/`root.Rename` return an error;
  no outside file is created in 20/20 runs. This is a race demonstration, not a
  claim that every timing wins on the pre-fix tree; 20/20 with a journal-based
  trigger is the reproducible window.
- The MCP probe uses a one-shot `/bin/sh` command so the evidence is a marker
  file, not a live session. A real payload would use a long-running process,
  which the same launch path supports.
- The Auto-agent steering precondition above is not demonstrated end to end
  from target content. The finding claims the authority bypass and the
  execution, not an unauthenticated remote chain.
- `ask_operator` still reads an arbitrary `image_path` by design; the agent
  already has host read access. This was recorded in F-006 and is unchanged.

## Reproduction

```bash
# Disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>          # fbe7839 + F-006 patches, then the F-007 patches for the after run
cp <skill-repo>/evidence/f007/repro/zz_evidence_f007_test.go server/
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run 'TestF007' -count=1 -v
```

Before the fix the run fails at both `F-007 GAP` assertions; after the fix both
tests pass and the HTTP/operator controls still succeed. Logs:
`evidence/f007/logs/f007-before.log`, `f007-after.log`.

## Verification

With the disposable PostgreSQL, the full `go test ./...` is green twice in a
row: 14 packages `ok`, 0 `FAIL`, the `server` package in 21.469 s and 22.183 s.
The only skip is `TestLiveContextReview`, which needs an external live-model
configuration. Logs: `evidence/f007/logs/go-test-run1.log`, `go-test-run2.log`.

## Fixture defect found by the second run

`TestF007AgentMCPStdioChain` originally registered its row cleanup with
`t.Cleanup` after `defer m.Close()`, so the DELETEs could run against a closed
pool and leave `f007-chain-*` rows behind. The tracked test now deletes the
fixed-name rows before the insert and registers a LIFO `defer` cleanup before
`defer m.Close()`, so cleanup runs while the pool is open. This is a fixture
isolation bug, not a product bug; no assertion or product behaviour changed
(`evidence/f007/patches/tests.patch`).

## Recommended remediation

1. Apply all three F-007 patches to the F-006 base and run the two probes.
2. Keep one `os.Root` for restore source and destination; do not reintroduce a
   path check followed by a second resolution.
3. Keep stdio MCP creation on the operator route only. If an agent must be able
   to add MCP servers, constrain the command to an operator-approved allowlist
   and require an approval prompt at write time, not only at call time.
4. Treat startup discovery as privileged: filter by visibility or require an
   operator flag before launching a server that no agent can see.
5. Add both probes to the regular DB-backed suite so a new launch path or a new
   restore helper cannot ship without the same checks.
