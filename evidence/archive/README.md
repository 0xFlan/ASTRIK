# Archive-handling evidence (F-004)

This directory contains the reproducer, logs, and exact patch for the
authenticated zstd-window memory amplification in the skill-upload path.

## Files

- `repro/zz_evidence_archive_test.go` — self-contained `server` package test.
  It starts the production `Server.Handler()` on a loopback listener, signs a
  JWT, and sends crafted archives.
- `patches/artex-zstd-window.patch` — exact upstream diff for
  `server/skill_zip.go`.
- `logs/` — the before/after runs on klauspost/compress 1.18.6 and 1.20.2.

## Run

From the ARTEX repository root:

```bash
cp <skill-repo>/evidence/archive/repro/zz_evidence_archive_test.go server/
go test ./server -run \
  'TestSkillUploadRejectsOversizedZstdWindow|TestSkillUploadTraversalMatrix|TestTaskArchiveExtractor' \
  -count=1 -v
```

On unfixed 1.18.6 or 1.20.2, `TestSkillUploadRejectsOversizedZstdWindow` fails:
the crafted archive returns `201` and installs a skill, and the logged heap
delta is about 135 MB. After applying `patches/artex-zstd-window.patch`, the
same test returns `400 {"error":"failed to read SKILL.md: window size exceeded"}`
and the legitimate-zstd control still returns `201`.

## Crafted archive

The test generates the archive deterministically. The oversized frame is a
normal small zstd frame with byte 5 (`Window_Descriptor`) set to `0x88`
(windowLog 27 = 128 MiB). The observed fixture is:

```
archive sha256 a843104ffb6f8ddc30934eb52b62e3646a19c1b9095125bc7ca861aac2ec63ba
archive bytes  228
frame   sha256 20ff032aa79fd83b345f990e18203b0d88cb4047c5a64a52f15b7e165bf6f076
frame   bytes  72
```

The legitimate control uses the same body with an unmodified small window.

## Apply the fix

```bash
git apply evidence/archive/patches/artex-zstd-window.patch
go test ./server -run \
  'TestSkillUploadRejectsOversizedZstdWindow|TestSkillUploadTraversalMatrix|TestTaskArchiveExtractor' \
  -count=1 -v
```

The patch is against BaaRai/ARTEX `fbe7839`; it changes only
`server/skill_zip.go`. The upstream repository is not writable from this skill
repository, so the patch is committed here instead of being pushed upstream.
