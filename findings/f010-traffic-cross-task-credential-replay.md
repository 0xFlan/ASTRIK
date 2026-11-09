# F-010 — Cross-task traffic read exposes captured credentials and replays them

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the local audit tree; product commit `0d22b30` |
| Severity | High (CVSS 3.1 7.1, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`). The chain reads another task's live bearer credential and can replay it. The high attack-complexity component reflects the need for a usable captured credential and a target that accepts it; the read itself is deterministic |
| Affected | `traffic/traffic.go` (`Traffic.Tools`, `query`, `Get`, `BlobRange`), `server/manager.go` (`HostTools`, `ProxyAddr`), `traffic/external.go` (`RecordExternal`), BaaRai/ARTEX `80de359` + F-009 |
| Trigger | Task A captures a request with `Authorization`/`Cookie`; a worker in task B calls `traffic_search(host=A)` and `traffic_get(id)` or `traffic_blob(hash)`. The traffic tools were `Allowed`, read-only, and had no task filter |
| Evidence | `evidence/f010/logs/`, `evidence/f010/repro/` |
| Patch | `evidence/f010/patches/traffic-scope-and-redaction.patch`, `evidence/f010/patches/tests.patch` |

## Summary

F-009 left A5 unresolved: the traffic recorder is one process-wide SQLite
index shared by every task. This pass built two tasks with distinct assets and
distinct captured credentials and observed the actual agent-facing tools.

Before the fix, task B's worker context could:

1. `traffic_search(host=task-A-host)` and receive task A's exchange metadata;
2. `traffic_get(id)` and receive task A's `Authorization: Bearer
   F010_TASK_A_SECRET` request header and secret-bearing body;
3. follow the oversized response's `@blob sha256:` pointer with
   `traffic_blob` and receive task A's large-body secret; and
4. send the extracted token to a local service that required exactly that
   token, authenticating successfully.

The same calls against task B's own host and record worked, and the operator's
`Traffic.Get` still returned the raw capture. After the fix, the cross-task
search/get/blob calls are `deny`, the credential is not present in the tool
output, replay fails, and the own-task and operator controls still pass.

## Observed result

Pre-fix, clean `80de359` worktree plus the probe:

```text
F010 cross_search=true cross_search_perm=allow cross_get_visible=true cross_get_perm=allow cross_blob_read=true cross_blob_perm=allow replay=true own_search=true own_search_perm=allow own_read=true own_read_perm=allow own_token_redacted=false operator_raw=true
--- FAIL: TestF010TrafficCrossTaskCredentialReadAndReplay
```

Post-fix, `0d22b30`:

```text
F010 cross_search=false cross_search_perm=deny cross_get_visible=false cross_get_perm=deny cross_blob_read=false cross_blob_perm=deny replay=false own_search=true own_search_perm=allow own_read=true own_read_perm=allow own_token_redacted=true operator_raw=true
--- PASS: TestF010TrafficCrossTaskCredentialReadAndReplay
```

The denial decision is `permission.Deny`, not `Ask`, so neither a read-only
auto-allow nor an `Allowed` custom-tool wrapper can turn the cross-task read
back on. The handler repeats the scope check before querying, so a direct
`.Call` that bypasses the permission pipeline is also blocked.

## Reachability classification

**Authenticated-agent, cross-task.** The worker is an authenticated principal
inside a shared ARTEX instance. The probe exercises the same assembled toolset
the worker receives, with task B's `RunInfo`, and does not require operator UI
access. It does not run a live model, so it does not claim that a specific
target string will steer a model to name task A's host. The boundary defect is
independent of that claim: the tool accepted any host and any exchange id from
a task-scoped caller, and returned the raw credential.

It is not an unauthenticated remote vulnerability. It is also not solely
operator-assisted: a worker turn is enough once the host/id is known. The
replay control is local and demonstrates that the captured credential remains
usable; the probe does not test a real third-party target.

## Root cause

1. **The recorder is process-global and has no task identity.** `Traffic.Open`
   creates one index per manager; `exchanges` has no `task_id`/owner column.
   `record()` and `RecordExternal()` write the same table for every caller.
2. **The tools had no scope argument and always returned `Allowed`.**
   `traffic_search` took only host/URL/body filters; `traffic_get` took only an
   id; `traffic_blob` took only a hash. None consulted `RunInfo.TaskID`.
3. **The agent-facing reader returned raw credentials.** `traffic_get` returned
   `Traffic.Get` verbatim, including `Authorization`/`Cookie` headers and
   secret-shaped body fields. The blob path returned the raw large body.
4. **A read-only `Allow` is not a boundary.** The permission pipeline treats a
   read-only tool as auto-allowed, so changing only the prompt or the tool
   description would not have closed the path.

## Fix

- `server/manager.go` now builds the traffic tools with
  `Manager.trafficHostScope`: a non-zero `RunInfo.TaskID` resolves to the task's
  asset host set through `HostsByTaskWithSources`; a zero/operator context stays
  platform-wide.
- `traffic.Tools(scope)` enforces the scope in both
  `CheckPermissions` (Deny with an operator-page pointer) and the handler
  (`search`, `get`, `blob`). `get` resolves the exchange's host from the index;
  `blob` resolves every exchange that references the hash, so a shared blob
  cannot be used to cross a task boundary.
- The agent-facing `traffic_get` redacts credential headers (`Authorization`,
  `Cookie`, `Set-Cookie`, API-key/auth-token headers) and secret-shaped JSON/form
  fields. `traffic_blob` redacts text segments. The operator `Traffic.Get`,
  `Search`, and the Traffic page remain raw.
- Regression tests: `server/zz_evidence_f010_test.go` is the two-task read/blob/
  replay probe; `traffic/redact_test.go` covers header and body redaction;
  `server/trigger_merge_test.go` records the merged-run scope result;
  `server/zz_evidence_f010_routes_test.go` records the prompt/trigger route
  negative.

## Residual limits

- **Capture is still not partitioned by task.** The fix is a reader-side host
  boundary plus redaction, not a per-task capture store. If two tasks attach the
  same host, both can read that host's exchange metadata; the credential
  redaction removes the common replay material, but arbitrary non-credential
  traffic remains shared. The durable fix is a `task_id`/owner on each exchange
  written by the capture path, with a task-scoped ingest token.
- **Redaction is pattern-based.** Header names and common JSON/form secret keys
  are covered; an unusual encoding or a secret in a binary blob can evade it.
  The operator view is intentionally raw and must remain access-controlled.
- **No live-model injection test.** The probe demonstrates the authorization
  and data-flow boundary directly. It does not claim a particular hostile page
  will always produce the required tool call.
- **`merge_mode=all` is conservative.** A merged run keeps the first task's
  `RunInfo.TaskID`; later tasks in the merged message are outside that scope and
  are rejected by F-009's checks. This is a negative for privilege promotion,
  not a new cross-task grant.

## Negative results recorded in this pass

### Prompt-template and trigger-configuration routes

`server/zz_evidence_f010_routes_test.go` drove the authenticated management
routes:

```text
F010 prompt_unauth=401 preview_status=200 preview_persisted=false prompt_saved=true builtin_trigger=400 custom_trigger_saved=true agent_route_tool=false
```

The prompt save route requires the JWT; the preview route renders an arbitrary
template but does not persist it; the built-in agent rejects triggers; a custom
agent's trigger persists only through the authenticated operator route. The
worker's assembled toolset contains no prompt/trigger management tool. Target
content therefore cannot persist instructions through these routes without an
operator-authenticated request. This is a route-level negative, not a claim that
prompt injection is impossible; the model-in-the-loop question remains open.

### `merge_mode=all` reporter behaviour

```text
F010 merge_all first_task=101 contains_task_202=true contains_task_101=true
```

The merged run keeps the first task's id. F-009's scope check rejects tools
aimed at the later task, so the merge does not widen the reporter's authority.
The existing `TestReporterTaskScopeBlocksCrossTaskReadAndWrite` covers the
cross-task denial and own-task/Auto controls.

## Reproduction

```bash
# Disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>          # clean pre-fix tree at 80de359 for the before run
cp <skill-repo>/evidence/f010/repro/zz_evidence_f010_test.go server/
cp <skill-repo>/evidence/f010/repro/zz_evidence_f010_routes_test.go server/   # after-run extras
cp <skill-repo>/evidence/f010/repro/trigger_merge_test.go server/             # after-run extras
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF010TrafficCrossTaskCredentialReadAndReplay -count=1 -v
```

Before the fix the traffic probe fails at the cross-task/credential/replay
assertions; after applying both patches it passes. The before/after logs are
`evidence/f010/logs/f010-before.log` and `f010-after.log`.

## Verification

- `go test ./... -count=1` with `ARTEX_PG_DSN` twice: 14 test packages `ok`,
  0 `FAIL`; `server` 24.680 s / 23.187 s; `traffic` 7.021 s / 6.875 s. Logs:
  `evidence/f010/logs/go-test-run1.log`, `go-test-run2.log`.
- `scripts/validate_skill.sh` passes at revision 1.14.
- `scripts/test_validate_skill.sh` mutation suite passes.
- The campaign suite `S63_LIVE=0 node --test hardening/*/index.test.js` passes.
- `bash -n` is clean on changed scripts.
- Both patches pass `git apply --check` on a temporary `80de359` worktree.

## Recommended remediation

1. Apply both F-010 patches to F-009 (`80de359`) and run the probe.
2. Keep task identity in every agent-facing traffic query; do not rely on the
   prompt to say "only this task."
3. Put a task/owner column on captured exchanges (and on external ingest) so
   same-host multi-task traffic can be separated at the source, not only by
   asset membership.
4. Keep raw credential material in the operator-only view and continue
   redacting the agent-facing readers. Extend the redactor to binary/encoded
   bodies or require an explicit operator approval for those reads.
5. Re-run the live-model prompt-injection and same-host multi-task probes before
   claiming a fully partitioned traffic store.
