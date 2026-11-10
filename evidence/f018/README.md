# F-018 evidence — cross-task asset credential read

The runnable reproducer is `../baarai/server/zz_evidence_f018_test.go` (copied here
for review). It creates task A's service asset with an `auth` password, has task B
insert a different URL on the same host, and then reads A's asset through the
worker's `list_assets` by ID and by domain DSL.

```bash
cd ../../baarai
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test -count=1 ./server -run TestF018AssetMergeCredentialRead -v
```

| File | Purpose |
|---|---|
| `probe-prefix.log` | Pre-fix transcript: `after_id_has_secret=true after_dsl_has_secret=true` |
| `probe-fixed.log` | Post-fix transcript: both false, B's own secret remains true |
| `repro/zz_evidence_f018_test.go` | Copied regression; canonical test is in the product tree |

The test also checks the exact-URL path: a direct upsert of A's URL is rejected,
so the bypass uses a distinct URL on the same host.
