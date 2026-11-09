# F-011 evidence — same-host ownership and A11 ingest

This directory contains the executed regression for F-011 and the A11 ingest
boundary.

Product commit for the fixed tree: `d6ff46e`.

| Artifact | Purpose |
|---|---|
| `repro/zz_evidence_f011_test.go` | Two tasks share one host; checks same-host search/get/blob isolation, own-task reads, operator raw view, decorated-tool denial, redaction, binary blob refusal, task-token ingest, foreign-host rejection, and task-token read denial |
| `repro/zz_evidence_f011_prefix_test.go` | Run against `0d22b30`; records the older same-host metadata/body read and the F-010 credential redaction |
| `logs/f011-before.log` | Pre-fix run at `0d22b30` |
| `logs/f011-after.log` | Fixed-tree run with the observed summary lines |
| `patches/traffic-ownership-and-task-scoped-ingest.patch` | Product patch from F-010 commit `0d22b30` to the F-011 tree |
| `logs/go-test-run1.log` | First full `go test ./...` result with `ARTEX_PG_DSN` set |
| `logs/go-test-run2.log` | Second consecutive full-suite run |

## Run

```sh
cd artex-audit/baarai
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestF011SameHostOwnershipRedactionAndIngest -count=1 -v
```

Observed lines:

```text
F011 same_host_cross_search=false cross_search_perm=allow cross_get_perm=deny cross_blob_perm=deny own_search=true own_get=true ownA_search=true ownA_get=true redacted=true search_redacted=true binary_redacted=true operator_raw=true wrapper_perm=deny wrapper_call_denied=true ingest_own=200 ingest_foreign=200 ingested_owner=<task-B> A_sees_ingested=false B_sees_ingested=true
F011 A11 operator_ingest=200 operator_owner=0 task_token_read=401
--- PASS: TestF011SameHostOwnershipRedactionAndIngest
```

`cross_search_perm=allow` is expected: the host is attached to both tasks, so
the host check permits the search. The owner filter is what removes A's row.
The foreign ingest response contains `ingested:0`, `failed:1`. In the pre-fix log,
`same_host_search_has_A=true` and `get_A_has_body=true` while
`get_A_has_secret=false`: that is the measured residual and the reason the
severity is Medium rather than F-010's credential-replay High.

## Patch scope

The patch includes the per-exchange owner column, task token table, proxy owner
attribution, scope/redaction changes, task-token ingest, agent transport wiring,
and the F-011 regression. It is applied on top of F-010 `0d22b30`. The pre-fix
probe is kept separately as `repro/zz_evidence_f011_prefix_test.go` and was run
in a clean `0d22b30` worktree; `logs/f011-before.log` records the observed
same-host metadata/body read and the already-redacted credential.
