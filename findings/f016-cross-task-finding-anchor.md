# F-016 — Cross-task finding and fact anchors

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the local audit tree |
| Severity | Medium in M2: task B can anchor its own finding/fact to task A's asset ID, polluting the global finding tree and widening B's ingest host set without adding the asset to B's declared scope |
| Affected | `agent/tools.go` (`validateAssetIDsInScope`, `addFinding`, `recordOneFact`) |
| Trigger | A worker calls `report_finding` or `record_fact` directly with another task's asset ID |
| Evidence | `evidence/f017/probe-prefix.log`, `evidence/f017/probe-fixed.log`, `evidence/f017/repro/zz_evidence_f017_test.go` |
| Proof basis | Production handler and real PostgreSQL, two real tasks, real worker toolset; pre-fix `anchored=1`, post-fix `anchored=0` |

## Result

The pre-fix direct call returned `finding recorded` and wrote a B finding whose
`asset_ids` contained A's asset (`anchored=1`). `record_fact` accepted the same
foreign anchor. The fixed helper resolves every requested id through
`AssetStore.GetByIDsInScope`; a partial result is rejected before the finding or
node transaction starts.

```text
prefix: F017 report_foreign_asset=false anchored=1 fact_foreign_asset=false
fixed:  F017 report_foreign_asset=true  anchored=0 fact_foreign_asset=true
```

The ID prerequisite is practical: traffic IDs are `<unix-seconds>-<seq:04d>`
(observed `1794264833-0001` immediately followed by `...-0002`), and finding
IDs are `BIGSERIAL` (observed `3900`/`3901`). A task that knows its own adjacent
ID can derive A's. The fixed scope check is what stops the write; ID secrecy is
not assumed.

## Chain

Predictable asset ID → `report_finding` foreign anchor → `HostsByTaskWithSources`
includes A's host → B's task token ingests that host. The chain is closed at the
anchor write by F-016. It does not compose into a cross-task traffic read:
F-011/F-013 still filter exchange ownership and evidence snapshots by task.
