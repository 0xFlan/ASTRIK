# F-017 — insert_assets self-expands the task ingest allowlist

| Field | Value |
|---|---|
| Status | Superseded — fixed at the root by F-019's pre-insert host-scope gate |
| Severity | Low (global asset/ingest write pollution in M2; not a confidentiality defect) |
| Affected | `agent/tools_insert.go` (`insertAssets`), `server/traffic_ingest.go` (`ingestTraffic`), `db/task_assets_context.go` (`HostsByTaskWithSources`) |
| Trigger | Task B calls `insert_assets` with a service URL on task A's host, then presents B's task token to `/api/traffic/ingest` |
| Evidence | `evidence/f017/probe-fixed.log`, `evidence/f017/repro/zz_evidence_f017_test.go` |

## Result

Before the insert, B's token rejects A's host with `ingested:0`. `insert_assets`
accepts the foreign URL, links it to B, and the same ingest then succeeds with
`ingested:1` and owner B (`F017 ... host_expanded=true post_owner=2246`).

This is the documented discovery path: `insert_assets` is the worker's
asset-registration tool and auto-scope is explicitly derived from the item the
worker inserts. At 1.17 the ingested row was B-owned, the traffic readers still
filtered by owner, and A's raw exchange remained invisible to B (`F017 ...
operator=200`, task-token routes `401`). That was incomplete: F-018 showed the
same auto-scope makes A's asset row visible to B's `list_assets`, including the
stored `auth` credentials. F-018 redacts foreign credentials at the scoped read;
the raw traffic path remains blocked by F-013 and the owner-scoped readers.

## Composition

F-017 supplies the first link of F-018: B registers a different URL on A's host,
which auto-adds the host scope. The write alone did not expose raw traffic, but
it did expose A's asset metadata until F-018's read-side redaction. F-013's
fixed `evidence.Store.prepare` still requires the traffic row to belong to the
finding task, so the composed chain does not reach A's raw exchange.
