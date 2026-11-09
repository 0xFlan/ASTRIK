# F-013 — Finding evidence binding bypasses traffic ownership

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the local audit tree (product commit `51cb13e`) |
| Severity | High in M2 (shared instance) when the caller knows a traffic ID: a task can copy another task's raw exchange, including credentials and body, into its own durable finding snapshot |
| Affected | `evidence/store.go` (`Store.prepare`), `server/finding_traffic.go` (`evidenceStore`), `traffic/evidence.go` (`ExchangeInScope`) |
| Trigger | Task B calls `bind_finding_traffic` or `report_finding` with a real traffic ID owned by task A. The finding-scope check validates the finding's task, but pre-fix `Store.prepare` called `Traffic.ReadEvidence` without the F-011 owner/host check and copied the raw request/response into the snapshot |
| Evidence | `evidence/f013/logs/f013-prefix.log`, `evidence/f013/logs/f013-fixed.log`, `evidence/f013/repro/zz_evidence_f013_test.go`, `evidence/f013/patches/finding-traffic-scope.patch` |
| Proof basis | Executed pre-fix worktree at `d6ff46e` and fixed tree at `51cb13e`; the pre-fix bind copied A's raw `Authorization` header and response body, and the fixed bind denied it while same-task binding still worked |

## Summary

F-011 stopped the three direct traffic tools from crossing the task owner
boundary. It did not cover the finding-evidence path. `report_finding` and
`bind_finding_traffic` call `evidence.Store.Record`/`Bind`, whose `prepare`
method read exchange IDs directly from the traffic store. That made a finding a
second, raw reader: a task that knew another task's exchange ID could bind it and
then read the snapshot through `get_finding_traffic`.

The pre-fix probe at `d6ff46e` used task B to bind task A's exchange to B's own
finding:

```text
F013_PREFIX cross_bind=bound raw_head_secret=true raw_body_has_A=true
```

The fixed probe denies the bind:

```text
F013 cross_bind=denied snapshot_count=0 own_bind=bound own_bindings=1
```

The prerequisite is knowledge of the traffic ID. IDs are compact timestamp/seq
values, not cryptographic capabilities, so they should not be treated as an
authorization token. The test supplies the ID directly to isolate the missing
scope check; it does not claim that an arbitrary task can enumerate IDs through
the fixed traffic tools.

## Fix

`evidence.Store` now carries an optional `traffic.ScopeFunc`. The server sets it
to `Manager.trafficHostScope` for the finding workflow and leaves it nil for
operator-only export/archive helpers. `Store.prepare` calls the same
`ExchangeInScope` check used by `traffic_get` before reading a body; a foreign
owner or host fails the whole bind before any snapshot is written. Same-task
binding and operator binding remain usable.

## Chain analysis

F-013 is a direct bypass of the F-011 reader boundary:

1. F-011 prevents B from selecting A's exchange with `traffic_search`.
2. F-013 supplies a known A ID to the finding binder instead.
3. Pre-fix, the binder copied raw credentials/body into B's finding.
4. B then read that snapshot through `get_finding_traffic`, bypassing the
   agent-facing traffic redaction.

The chain therefore composes only when the ID is already known. It does not give
B an ID-enumeration primitive, and it does not combine with A11: a B task token
can create only B-owned traffic and cannot create a foreign row whose ID can be
bound. After the fix, the copy fails at step 3 and the chain stops.

## Residual

Operator/API binds still use the raw traffic store by design. The operator
already has cross-task visibility; an operator who supplies another task's ID is
not crossing a task boundary. A multi-operator deployment would need an explicit
operator identity and audit surface, which this single-admin model does not have.
