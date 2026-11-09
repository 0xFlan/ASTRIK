# F-011 — Same-host traffic attribution and task-scoped ingest

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the local audit tree (product commit `d6ff46e`) |
| Severity | Medium in M2 (shared instance): another task's exchange metadata, URL, status, and response body are readable when both tasks attach the same host. F-010's agent-facing redaction already removes the captured credential, so this residual is an isolation/confidentiality defect, not a credential-replay path |
| Affected | `traffic/traffic.go` (exchange owner, query, tools, blob content type), `traffic/scope.go` (owner + host scope), `traffic/external.go`, `traffic/owner.go`, `db/task_traffic_tokens.go`, `db/schema.sql`, `server/manager.go`, `server/traffic_ingest.go`, `server/auth.go`, `agent/{worker,planner,mainagent,chat}.go`, `server/task_llm.go` |
| Trigger | Tasks A and B both attach `shared.example.test`. Before this change the F-010 reader scope checked only the host, so B could search that host and read A's exchange metadata and body (the credential header was already redacted). After the change every exchange carries `task_id`, search filters by both owner and host, `get`/`blob` require an exact owner match, and the proxy/ingest paths stamp the owner from a task-scoped bearer, not from target data |
| Evidence | `evidence/f011/logs/f011-after.log`, `evidence/f011/repro/zz_evidence_f011_test.go`, `evidence/f011/patches/traffic-ownership-and-task-scoped-ingest.patch` |
| Proof basis | Executed lab runs on both trees: the pre-fix probe at `0d22b30` observed A's exchange in B's same-host search and B's `traffic_get` returned A's body with the credential redacted; the fixed-tree probe denies the cross-owner read and allows B's own row |

## Summary

F-010 introduced reader-side host scoping but explicitly left a residual: the
recorder had no per-exchange task id, so two tasks that attached the same host
shared every non-credential field and could read each other's captured
credentials. This pass closes that residual at capture and at query time.

The probe creates two tasks, attaches the same host to both, and records an
exchange for each. Task A's exchange contains a query token, an `Authorization`
header, a cookie, a custom session header, a form body, nested JSON credentials,
and a binary blob. Task B's exchange is a distinct own-host marker.

The pre-fix probe at `0d22b30` observed the residual: B's same-host search
returned both A's and B's IDs, and B's `traffic_get(A)` returned A's URL, status,
and `{"owner":"A"}` body. F-010's redaction kept the credential header out of the
agent-facing output (`authorization: [redacted]`), so the confirmed impact is
cross-owner metadata/body disclosure, not credential replay.

After the fix:

- task B's same-host search returns only B's exchange, even though the host
  permission check is `allow` (the host is legitimately shared);
- task B's `traffic_get` of A's id is `deny`;
- task B's `traffic_blob` of A's binary hash is `deny`;
- task A's own search/get/blob still work, and the agent-facing output is
  redacted;
- the operator's `Traffic.Get` still returns the raw credential material;
- a decorated tool (`DecorateTool`) preserves the same `deny` decision, so the
  binding surface cannot be used to bypass the scope check.

## A11 — ingest authorization

The same probe covers the A11 ingest path:

| Case | Result |
|---|---|
| Task B's task token ingests a URL on B's own host | `200`, `ingested=1`, row owner = task B |
| Task B's task token ingests a foreign host | `200`, `ingested=0`, `failed=1`; no foreign row is created |
| Task B's task token calls a read/management route (`/api/tasks`) | `401` |
| Operator JWT ingests a foreign host | `200`, row owner `0` (operator-only) |

The task token is accepted only on `POST /api/traffic/ingest`; it cannot read or
manage. Ingest validates the URL host against `HostsByTaskWithSources(taskID)`
and records the exchange with that task id. Operator JWT ingest remains
unrestricted by design for the single-admin browser-extension path, but its rows
are owner `0`, which task-scoped readers never see. A11 is therefore closed as
a cross-task primitive; it remains an operator-controlled provenance feature,
not a second principal.

## Fix

`db/task_traffic_tokens.go` creates a stable 256-bit task token
(`astk_…`) and resolves it only to a live task. The pre-fix probe is retained in
`evidence/f011/logs/f011-before.log`; the fixed probe is
`evidence/f011/logs/f011-after.log`. `traffic/owner.go` consumes the
token from `Proxy-Authorization` and maps the client connection to its task, so
the token is never forwarded to the target. `traffic/traffic.go` adds the
`task_id` column and index, stamps every record, filters `query` by owner, and
uses `BlobContentType` so a binary segment without a NUL byte is still refused.
`traffic/scope.go` resolves `Scope{TaskID, Hosts, Scoped}` and requires an exact
owner match for `get` and `blob`. `server/manager.go` installs the per-task
proxy URL and token resolver; `server/traffic_ingest.go` validates the host
allowlist before recording. `server/auth.go` accepts a task token only for
ingest. The test reproducer is in the evidence directory.

## Residual

Operator JWT ingest can still write an arbitrary host as owner `0`. That is the
operator provenance path and is not readable by task-scoped agents; in a shared
instance an operator already controls the evidence store. If the deployment
model is changed to multiple mutually untrusted operators, this path needs a
separate signed-provenance design. The live-model probe (F-012) did not produce
a chain through this path.
