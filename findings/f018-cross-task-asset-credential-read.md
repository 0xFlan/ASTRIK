# F-018 — Cross-task asset credential read through auto-scope

| Field | Value |
|---|---|
| Status | Confirmed; root cause closed by F-019, credential redaction retained |
| Severity | High in M2: task B reads task A's stored asset credentials (`auth`) without a traffic or finding bypass |
| Affected | `agent/tools_insert.go` (`insert_assets` auto-scope), `db/asset_dsl.go` (`GetByIDsInScope`, `QueryDSLInScope`) |
| Trigger | B inserts a **new** service URL on A's host. `insert_assets` auto-adds a subdomain scope for that host; B then calls `list_assets(id=A's service)` or a domain DSL query |
| Evidence | `evidence/f018/probe-prefix.log`, `evidence/f018/probe-fixed.log`, `evidence/f018/repro/zz_evidence_f018_test.go` |
| Proof basis | Two real tasks, real PostgreSQL, production worker tools; A's asset carried a real `auth` entry |

## Result

The exact-URL upsert is rejected by the foreign-owner guard, but a **different URL
on the same host** succeeds. Its auto-scope entry is enough for the scoped read:

```text
F018 pre_has_secret=false
     insert={"errors":null,"results":[{"index":0,"id":579,"type":"service"}]}
     after_id_has_secret=true after_dsl_has_secret=true task_ids={2370}
```

B never obtained A's traffic or finding: it obtained A's asset metadata through
`list_assets`. This is a direct cross-task credential disclosure and upgrades
F-017 from write-only pollution to a read primitive.

The fixed tree redacts `auth` from any asset whose `task_ids` does not contain the
calling task, in both scoped read methods. B's own asset remains readable:

```text
F018 ... after_id_has_secret=false after_dsl_has_secret=false own_has_secret=true
```

## Chain

`insert_assets` new URL on foreign host → auto-subdomain scope → `list_assets`
scope membership → A's `auth`. The F-017 host-claim write is therefore not
harmless: it was the first link of this read chain. The fix is at the read sink;
shared asset enumeration still works, but credentials are task-owned.
