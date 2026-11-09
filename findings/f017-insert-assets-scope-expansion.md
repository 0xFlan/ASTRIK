# F-017 — insert_assets self-expands the task ingest allowlist

| Field | Value |
|---|---|
| Status | Closed as design-intent scope expansion; no cross-task read |
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
worker inserts. It is not a cross-task read: the ingested row is owned by B,
`traffic_search`/`traffic_get`/`traffic_blob` still filter by owner, and A's raw
exchange remains invisible to B (`F017 ... operator=200`, task-token routes
`401`). The residual is that a compromised worker can add arbitrary global asset
records and write its own traffic for them; that is a write/pollution boundary,
not proof of data access outside the task.

## Non-composition

The write does not chain with F-013: F-013's fixed `evidence.Store.prepare`
requires the traffic row to be in the finding task's scope, and B's new row is
B-owned; A's raw row still fails the owner check. It also does not turn the
compact IDs into a read primitive.
