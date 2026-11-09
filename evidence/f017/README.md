# F-017 evidence — direct backend authorization

The runnable reproducer is the product test
`server/zz_evidence_f017_test.go`. It builds two real tasks and assets in the
PostgreSQL test database, starts the production `Server.Handler()` on a loopback
`httptest` listener, uses real `EnsureTaskTrafficToken` tokens, and calls the
worker tools directly (no model).

```bash
cd ../../baarai
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test -count=1 ./server -run TestF017DirectBackendAuthorization -v
```

| File | Purpose |
|---|---|
| `probe-prefix.log` | Pre-fix run: `report_finding` accepted A's asset (`anchored=1`) |
| `probe-fixed.log` | Post-fix run: foreign anchor denied (`anchored=0`), all token routes 401 |
| `repro/zz_evidence_f017_test.go` | Copied regression for review; canonical test lives in the product tree |

The fixed transcript also records the remaining `insert_assets` self-expansion
(`host_expanded=true`) and the ID measurements
(`1794264849-0001`/`...-0002`, findings `3903`/`3904`).
