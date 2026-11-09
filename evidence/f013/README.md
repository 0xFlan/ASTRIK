# F-013 evidence — finding traffic scope

Product commit for the fixed tree: `51cb13e`.

| Artifact | Purpose |
|---|---|
| `repro/zz_evidence_f013_test.go` | Pre-fix/fixed test; task B binds A's traffic to B's finding, then a same-task positive control |
| `logs/f013-prefix.log` | Run at `d6ff46e` with `ARTEX_F013_EXPECT_LEAK=1`; raw header and body copied |
| `logs/f013-fixed.log` | Fixed-tree run; cross-task bind denied, same-task bind succeeds |
| `patches/finding-traffic-scope.patch` | Product patch from `d6ff46e` to `51cb13e` |
| `logs/go-test.log` | Full DB-backed `go test ./...` run |

## Run

Pre-fix:

```sh
git worktree add --detach /tmp/f013 d6ff46e
cp evidence/f013/repro/zz_evidence_f013_test.go /tmp/f013/server/
cd /tmp/f013
ARTEX_F013_EXPECT_LEAK=1 \
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF013CrossTaskFindingTrafficBind -count=1 -v
```

Fixed:

```sh
cd artex-audit/baarai
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF013CrossTaskFindingTrafficBind -count=1 -v
```

Observed lines:

```text
F013_PREFIX cross_bind=bound raw_head_secret=true raw_body_has_A=true
F013 cross_bind=denied snapshot_count=0 own_bind=bound own_bindings=1
```
