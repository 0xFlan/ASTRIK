# F-014 — Alternate traffic and tool routes

| Field | Value |
|---|---|
| Status | Closed — no cross-task read or privilege bypass reproduced |
| Severity | None proven |
| Affected | `server/server.go` traffic routes, `server/auth.go`, `server/traffic_ingest.go`, traffic tools |
| Trigger | Task token presented to raw traffic, blob, tools, or findings export; malformed and replayed tokens; task-token ingest against foreign hosts; task-scoped blob reads |
| Evidence | `evidence/f014/logs/f014-routes.log`, `evidence/f014/repro/zz_evidence_f014_routes_test.go` |
| Proof basis | Executed against the production `Server.Handler()` with real JWT and real task tokens |

## Result

```text
F014 traffic=401 exchange=401 blob=401 tools=401 export=401 cookie=401 malformed=401
     operator=200 operator_blob=200 foreign_ingested=0 own_ingested=1
     own_owner=2022 replay=401 blob_b_denied=true blob_a_has_secret=true
```

- A task token is accepted only on `POST /api/traffic/ingest`; it is rejected by
  `/api/traffic`, `/api/traffic/exchange`, `/api/traffic/blob`, `/api/tools`, and
  the findings export, whether sent as a bearer, a cookie, or a malformed token.
- The operator JWT still reads the raw exchange and blob (`200`).
- Task B's token cannot ingest a URL on task A's host (`ingested:0`); its own
  host is accepted and the row carries the real task ID.
- The two task tokens are distinct; deleting B invalidates its token (`401`).
- `traffic_blob` denies B and allows A for the same content-addressed body.

No cross-task data or extra privilege was obtained on these alternate routes.
The F-011 owner check is therefore not limited to the `traffic_get` handler.
