# F-010 evidence — cross-task traffic credential read and replay

The probe creates two tasks with distinct asset hosts and distinct captured
credentials. Task A's exchange contains `Authorization: Bearer
F010_TASK_A_SECRET`, a body password, and an oversized response body with a
blob-only secret. Task B runs with its own `RunInfo.TaskID` and calls the
assembled worker `traffic_search`, `traffic_get`, and `traffic_blob` tools.

Before the fix task B sees task A's metadata, raw `Authorization`/body secret,
and blob secret, and the extracted token authenticates to a local service that
requires exactly task A's token. After the fix the cross-task decisions are
`deny`, the credential is absent from the output, replay fails, and task B's
own host/record plus the operator `Traffic.Get` still work.

## Files

- `repro/zz_evidence_f010_test.go` — two-task search/get/blob/replay probe with
  own-task and operator positive controls.
- `repro/zz_evidence_f010_routes_test.go` — authenticated prompt/trigger route
  probe: unauthenticated 401, preview does not persist, built-in trigger 400,
  custom trigger persists only through the authenticated route, no worker
  prompt/trigger tool.
- `repro/trigger_merge_test.go` — `merge_mode=all` keeps the first task's scope;
  later tasks in the merged message are not promoted.
- `patches/traffic-scope-and-redaction.patch` — product fix:
  `Traffic.Tools(scope)`, task-asset host scope in both permission and handler
  paths, exchange/blob scope resolution, and agent-facing credential redaction.
- `patches/tests.patch` — the three probe/regression files.

## Provisioning

```bash
bash evidence/db/provision-test-postgres.sh -q
export ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable'
```

`LC_ALL=C LANG=C` is required for `pg_ctl` on this macOS host. See
`evidence/db/README.md`.

## Reproduce

```bash
cd <ARTEX-repo>          # 80de359 for before; apply both patches for after
cp <skill-repo>/evidence/f010/repro/zz_evidence_f010_test.go server/
cp <skill-repo>/evidence/f010/repro/zz_evidence_f010_routes_test.go server/
cp <skill-repo>/evidence/f010/repro/trigger_merge_test.go server/
ARTEX_PG_DSN="$ARTEX_PG_DSN" \
  go test ./server -run TestF010TrafficCrossTaskCredentialReadAndReplay -count=1 -v
```

## Results

| Probe | Before (`80de359`) | After (`0d22b30`) |
|---|---|---|
| task B `traffic_search(task A host)` | returns A exchange (`allow`) | `deny` |
| task B `traffic_get(task A id)` | raw `Authorization`/body secret | `deny`; no credential |
| task B `traffic_blob(task A hash)` | blob secret returned (`allow`) | `deny` |
| replay A's captured token against local verifier | succeeds | no token; cannot replay |
| task B own host/record | works | works |
| operator `Traffic.Get(task A)` raw | works | works |
| own-task credential output | raw | redacted |

Exact lines:

```text
F010 cross_search=true cross_search_perm=allow cross_get_visible=true cross_get_perm=allow cross_blob_read=true cross_blob_perm=allow replay=true own_search=true own_search_perm=allow own_read=true own_read_perm=allow own_token_redacted=false operator_raw=true
F010 cross_search=false cross_search_perm=deny cross_get_visible=false cross_get_perm=deny cross_blob_read=false cross_blob_perm=deny replay=false own_search=true own_search_perm=allow own_read=true own_read_perm=allow own_token_redacted=true operator_raw=true
```

The prompt/trigger negative:

```text
F010 prompt_unauth=401 preview_status=200 preview_persisted=false prompt_saved=true builtin_trigger=400 custom_trigger_saved=true agent_route_tool=false
```

The merge negative:

```text
F010 merge_all first_task=101 contains_task_202=true contains_task_101=true
```

## Logs

- `logs/f010-before.log` — clean `80de359` worktree plus the traffic probe;
  expected `FAIL` with all four cross-task/replay booleans true.
- `logs/f010-after.log` — fixed tree; `PASS` for the traffic probe, the
  prompt/trigger route probe, and the merge probe.
- `logs/go-test-run1.log`, `logs/go-test-run2.log` — two consecutive full
  DB-backed `go test ./... -count=1` runs: 14 test packages `ok`, 0 `FAIL`;
  `server` 24.680 s / 23.187 s.

Setup tokens were redacted from the probe logs (`Setup token … [redacted]`).

## Reachability

The chain is authenticated-agent and cross-task. The worker is already inside
the instance; the probe uses the same assembled worker toolset and task-B
`RunInfo`, and demonstrates a raw credential read plus a local replay. It does
not claim a live-model injection success. The operator traffic view remains
available, and the fix does not require an operator prompt for own-task reads.

## Residual

The process-wide recorder still has no `task_id` on each exchange. The fix
therefore scopes by the caller task's asset hosts and redacts the common
credential carriers; two tasks that attach the same host still share that
host's metadata. A durable capture-level task partition is recommended before
claiming full multi-tenant separation. The finding records this limitation
rather than overclaiming.

## State

Confirmed and fixed in the local audit product tree (`0d22b30`); the skill
records the finding, patches, reproducer, and logs.
