# GO-2026-6865 — zstd panic through the real skill upload handler

**Advisory:** GHSA-fpmh-frq8-7rj8 / CVE-2026-116591, fixed in compress 1.20.2.
**ARTEX path:** `POST /api/skills/upload` → `fsUploadSkill` → `readZipEntry` →
`zstd.ZipDecompressor` (method 93 entry) → panic in `fse.nextFast`.

## Run

```bash
# from the ARTEX checkout root
cp <this-skill>/evidence/zstd/repro/zz_evidence_zstd_panic_test.go server/
go test ./server -run 'TestUploadCraftedZstdSkillZip|TestSkillUploadRejectsMissingJWT' -count=1 -v
```

`TestUploadCraftedZstdSkillZip` wraps the advisory frame in a method-93 ZIP entry
and drives the real handler. `TestSkillUploadRejectsMissingJWT` proves the API
wrapper returns 401 before the handler.

## Observed

- compress **1.18.6**: panic `index out of range [33077] with length 32768`,
  stack through `huff0.ReadTable` → `zstd.decodeLiterals` → `server.readZipEntry`
  → `server.fsUploadSkill`. Test exits 1.
  Log: `logs/go-test-1.18.6.log`.
- compress **1.20.2**: `400` with
  `corrupt input: weights tableLog too big`. Test exits 0.
  Log: `logs/go-test-1.20.2.log`.

## Fix

`patches/compress-1.20.2.patch` (go.mod/go.sum). The ARTEX repository is an
upstream copy, so the patch is committed here rather than pushed upstream:

```bash
cd <artex> && git apply <this-skill>/evidence/zstd/patches/compress-1.20.2.patch
go mod download
go test ./server -run TestUploadCraftedZstdSkillZip -count=1 -v
```

The upload route is behind `requireAuth` (`server.go:967`, `auth.go:195`), so the
crash requires a valid JWT. This is a post-auth DoS, not an unauthenticated one.
