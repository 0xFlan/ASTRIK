# F-014 evidence — alternate traffic routes

This probe covers the routes adjacent to the F-011 traffic tools.

| Artifact | Purpose |
|---|---|
| `repro/zz_evidence_f014_routes_test.go` | Task-token reads, cookie/malformed tokens, raw operator access, replay after deletion, foreign-host ingest, and task-scoped blob reads |
| `logs/f014-routes.log` | Full observed route matrix |

## Run

```sh
cd artex-audit/baarai
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF014AlternateTrafficAndToolRoutes -count=1 -v
```

Observed line:

```text
F014 traffic=401 exchange=401 blob=401 tools=401 export=401 cookie=401 malformed=401 operator=200 operator_blob=200 foreign_ingested=0 own_ingested=1 own_owner=2022 replay=401 blob_b_denied=true blob_a_has_secret=true
```

`operator=200` and `operator_blob=200` are the positive controls. The task token
is ingest-only; the own ingest row is stamped with task B's ID, while the
foreign host is rejected and a deleted task's token no longer resolves.
