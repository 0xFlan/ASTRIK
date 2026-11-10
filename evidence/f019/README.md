# F-019 evidence — pre-insert host-scope gate

The F-018 regression is the canonical chain: task A owns a service on a host
with an `auth` password; task B inserts a different URL on that host; B then
reads by asset ID and by a domain DSL query. F-019 requires that insert to be
covered by B's existing scope before any upsert.

## Run

```bash
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test -count=1 ./server -run 'TestF018ForeignHostScopeGate|TestF018ExplicitScopeDiscovery' -v
```

`probe-redaction-on.log` is the normal run. `TestF018ForeignHostScopeGate`
asserts the rejected insert created no asset, no ownership change, and no
foreign URL or `auth` through either read. `TestF018ExplicitScopeDiscovery`
asserts an explicit scope grant restores shared metadata, keeps A's `auth`
redacted, and leaves B's own `auth` readable.

## Redaction-off control

`probe-redaction-off.log` was produced by temporarily making
`db/asset_dsl.go:redactForeignAssetAuth` return immediately, then rerunning only
the core gate:

```bash
cp db/asset_dsl.go /tmp/asset_dsl.go.f019-backup
perl -0pi -e 's/(func redactForeignAssetAuth\(taskID int64, assets \[\]\*Asset\) \{\n)/$1\treturn\n/' db/asset_dsl.go
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test -count=1 ./server -run 'TestF018ForeignHostScopeGate' -v
cp /tmp/asset_dsl.go.f019-backup db/asset_dsl.go
```

The core gate still passes: `pending_asset=0` and no foreign URL or secret are
returned. This shows the fix holds without the F-018 credential redaction. The
explicit-scope test is expected to expose `auth` when redaction is disabled,
because that path is an intentional shared-scope read; the redaction layer is
what protects credentials there.

`repro/zz_evidence_f018_test.go` is the committed test at the time of this
revision.
