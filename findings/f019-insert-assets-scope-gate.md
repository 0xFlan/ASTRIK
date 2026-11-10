# F-019 — insert_assets can manufacture scope over an unproven host

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the local audit tree |
| Severity | High in M2: lets a task acquire the authorization edge used by F-017/F-018 and enumerate another task's asset metadata |
| Affected | `agent/tools_insert.go` (`insertAssets`), `db/task_scope.go` (`HostCoveredByTaskScope`) |
| Trigger | Task B calls `insert_assets` with a service/endpoint URL, subdomain, root domain, or IP that is not covered by B's existing scope or owned assets |
| Evidence | `evidence/f019/probe-redaction-on.log`, `evidence/f019/probe-redaction-off.log`, `evidence/f019/repro/zz_evidence_f018_test.go` |
| Proof basis | Two real tasks, real PostgreSQL, production worker tools; the F-018 chain rerun with the scoped-read redaction both enabled and disabled |

## Result

At 1.18, the F-018 read was closed by redacting foreign `auth`, but the write
that created the authorization edge was still accepted. B registered a
different URL on A's host, `insert_assets` auto-added a subdomain scope for that
host, and B's `list_assets` could then enumerate A's asset row. The redaction
only removed the credential; it did not remove the scope acquisition, the
foreign metadata visibility, or B's ability to attach its own row to A's host.

F-019 moves the boundary before the upsert. `insertAssets` computes one
`assetScopeHost` (URL host, including IP literals; subdomain/root domain; or IP)
and calls `HostCoveredByTaskScope` before the asset gate and before any
`Upsert*` or `AddAutoScope`. Coverage is satisfied by the task's or a direct
source task's:

- `root_domain` scope for the host or a parent;
- exact `subdomain` scope;
- `ip`/`cidr` scope containing the host;
- `company` scope when an existing asset for that host is attributed to it; or
- an existing asset already owned by that task/source.

A new host requires an explicit `add_task_scope` grant. This is the claim step;
inserting a URL is no longer a claim. Apps have no host and are outside this
gate.

## Reproduction

`TestF018ForeignHostScopeGate` creates A's service with a real `auth` password,
then B inserts a different URL (DNS host and IP-literal host) on A's host. The
rejected insert is:

```text
asset [service] https://shared-f018-.../other is outside task scope; add_task_scope before inserting a new host
```

The measured state is:

```text
pending_asset=0
after_id_has_url=false after_id_has_secret=false
after_dsl_has_url=false after_dsl_has_secret=false
task_ids={A}
```

The same test passes with `redactForeignAssetAuth` temporarily replaced by an
immediate `return`, so the no-metadata result does not depend on the redaction
layer.

`TestF018ExplicitScopeDiscovery` grants B an explicit subdomain scope. Shared
metadata discovery returns A's URL (`grant_id_has_url=true`,
`grant_dsl_has_url=true`), A's credential remains hidden
(`grant_id_has_secret=false`, `grant_dsl_has_secret=false`), and B can insert
and read its own asset (`own_has_secret=true`).

The existing F-017 probe now measures `host_expanded=false`,
`post_ingest=ingested:0`, and `post_owner=0`; B's own host still ingests.

## Verification

- `go test -count=1 ./...`: all packages pass; `server` 26.261s.
- The core F-018 regression passes with redaction on and with redaction off.
- `scripts/validate_skill.sh`: OK.
- `bash scripts/test_validate_skill.sh`: OK.

## Residual

The policy is host coverage, not a full tenant boundary: once a task has an
explicit shared scope, it can enumerate non-credential metadata for every asset
under it, by design. The F-018 credential redaction remains necessary for that
shared path. `insert_assets` still accepts a new host only after an explicit
scope grant; the grant UI/tool remains the operator or agent's claim surface.
The temporary `/tmp/asset-foreign-owner-guard.patch` from the 1.18 pass was not
used: the guard was rejected by the two-task shared-host fixtures, and F-019
enforces host-scope coverage instead of per-row ownership.
