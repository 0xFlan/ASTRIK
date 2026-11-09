# F-004 — Authenticated zstd-window amplification in skill upload: 135 MB from a 228-byte archive

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | Medium (authenticated denial of service; CVSS 3.1 6.5, `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`) |
| Affected | `server/skill_zip.go` `newSkillZipReader` at BaaRai/ARTEX `fbe7839`; both pinned compress versions |
| Trigger | Authenticated `POST /api/skills/upload` with a ZIP method-93 entry |
| Evidence | `evidence/archive/` (reproducer, logs, patch) |

## Summary

`newSkillZipReader` registered `zstd.ZipDecompressor(zstd.WithDecoderConcurrency(1))`.
That constructor accepts a zstd **window** of up to 128 MiB by default. The
skill-upload caps bound the compressed request (20 MiB), each extracted file
(20 MiB), the total extracted bytes (100 MiB), and the entry count (4,000), but
they do not bound the decoder's window allocation. A zstd frame can declare a
128 MiB window while carrying only a few dozen bytes, so the decoder allocates
the window before `readZipEntry`'s output limit has any effect.

A 228-byte ZIP containing a 72-byte frame was accepted with `201` and installed
a one-file skill. After a full `runtime.GC`, the test process's `HeapAlloc` had
risen by **135,163,008 bytes** on compress 1.18.6 and **135,199,376 bytes** on
1.20.2. The route requires a valid JWT (F-003), so this is an authenticated
memory-exhaustion primitive, not an anonymous one. Repeating or overlapping
uploads can exhaust the server's memory; one request already consumes roughly
six times the 20 MiB body cap.

## Root cause

The zstd frame header's `Window_Descriptor` is attacker-controlled. The
decoder's `history.allocFrameBuffer` is derived from `frame.WindowSize` before
the first block is decoded; with `WithDecoderLowmem(true)` it allocates the
window plus a small block margin. `ZipDecompressor` sets
`WithDecoderMaxWindow(128<<20)` when no option overrides it. The server only
limited the number of decoded bytes returned to the caller, which is too late
to prevent the window allocation.

The archive is otherwise well-formed: its ZIP header declares the exact
uncompressed length and CRC of the small `SKILL.md`, so the upload is not
rejected by the ZIP checksum or the byte caps. The 128 MiB is therefore a
successful, installed skill rather than an allocation followed by a parse
error.

## Reproduction

```bash
# From the ARTEX repository root. The reproducer is in the public skill repo.
cp <skill-repo>/evidence/archive/repro/zz_evidence_archive_test.go server/
go test ./server -run 'TestSkillUploadRejectsOversizedZstdWindow' -count=1 -v
```

The test starts the real `Server.Handler()` (the production CORS →
`requireAuth` → `ServeMux` stack) on a loopback listener, signs a token with the
server key, and POSTs the archive with that token. It logs the archive and frame
hashes, the status/body, and heap before/after a forced GC.

Observed on the unfixed code:

| Version | Status | Body | Heap delta |
|---|---|---|---|
| compress 1.18.6 | `201` | `{"files":1,"name":"archive-window-probe"}` | `+135,163,008` |
| compress 1.20.2 | `201` | `{"files":1,"name":"archive-window-probe"}` | `+135,199,376` |

The exact crafted archive is deterministic:
`sha256 a843104ffb6f8ddc30934eb52b62e3646a19c1b9095125bc7ca861aac2ec63ba`
(228 bytes); frame
`sha256 20ff032aa79fd83b345f990e18203b0d88cb4047c5a64a52f15b7e165bf6f076`
(72 bytes). The frame is a normal small zstd frame whose byte 5 is changed from
`0x00` to `0x88` (windowLog 27 = 128 MiB). The test constructs it rather than
requiring a binary fixture; the log prints both hashes.

## Negative results for the filesystem-escape question

The same reproducer sends eight entry-name shapes through the authenticated
production route. All returned `400`; no canary outside the skill root was
created and no `.upload-*` directory remained:

| Entry name | Result |
|---|---|
| `../outside.sh` | `400 invalid path: '..' not allowed` |
| `a/../../outside.sh` | `400 invalid path: '..' not allowed` |
| `..\..\outside.sh` | `400 illegal character '\\'` |
| `a//outside.sh` | `400 must be relative with no empty segments` |
| `%2e%2e/outside.sh` | `400 illegal character '%'` |
| `C:/outside.sh` | `400 illegal character ':'` |
| `a\x00b.sh` | `400 illegal character '\x00'` |
| absolute temp path | `400 must be relative with no empty segments` |

`skillRelPath` checks characters before normalization, rejects every `..`
substring, rejects leading slash and doubled separators, then re-checks after
`filepath.Clean`. The extractor uses `os.Create`, never `os.Symlink`; a ZIP
entry with Unix symlink mode is extracted as an ordinary file. Duplicate names
truncate the earlier file in the temp tree rather than following a link.

The task-archive tar.zst extractor (`extractTaskArchivePackage`) also rejected
`../escape.txt`, `a/../../escape.txt`, `.`, `a/..`, an absolute path, and
symlink/hardlink/FIFO entry types. A 1 EiB forged tar header was rejected by the
128 TiB ceiling before any file was created. Task packages are server-generated,
checksummed, and restored by archive ID rather than uploaded directly, so that
path is defense-in-depth; it is not a user-controlled upload route.

Windows-separator behavior is platform-specific: the skill check blocks
backslashes on every platform. The tar extractor uses `filepath.FromSlash` and
rejects `..` after cleaning on Windows; this run was on darwin, so the Windows
tar variant is a code-path observation, not a Windows execution.

## Fix

Bound the zstd decoder window to the encoder's normal 8 MiB maximum in
`newSkillZipReader`:

```go
zdec := zstd.ZipDecompressor(
	zstd.WithDecoderConcurrency(1),
	zstd.WithDecoderMaxWindow(8<<20),
)
```

The exact patch is
`evidence/archive/patches/artex-zstd-window.patch`. Apply it in the ARTEX root:

```bash
git apply evidence/archive/patches/artex-zstd-window.patch
go test ./server -run 'TestSkillUploadRejectsOversizedZstdWindow|TestSkillUploadTraversalMatrix|TestTaskArchiveExtractor' -count=1 -v
```

The cap rejects the crafted frame with
`400 {"error":"failed to read SKILL.md: window size exceeded"}` before the
window allocation. A normal WinZip method-93 archive still installs with `201`.
An 8 MiB cap is compatible with the package's own 20 MiB per-file limit and
with the zstd encoder's documented normal maximum window.

## Verification

After the patch, on both pinned versions:

| Version | Oversized window | Legitimate zstd | Heap delta after rejection |
|---|---|---|---|
| compress 1.18.6 | `400 window size exceeded` | `201` | `+26,136` |
| compress 1.20.2 | `400 window size exceeded` | `201` | `-11,096` |

The traversal matrix and tar-extractor matrix still passed. Logs:
`evidence/archive/logs/go-test-1.18.6-before.log`,
`.../go-test-1.18.6-after.log`,
`.../go-test-1.20.2-before.log`,
`.../go-test-1.20.2-after.log`.

## Impact

An authenticated user who can upload a skill can force roughly 135 MB of
retained heap with a 228-byte request. The upload route has no per-user
concurrency limiter in the inspected handler path. Multiple requests can
therefore drive the process toward OOM; the effect is availability loss, not
code execution or data access. The finding does not add an unauthenticated
chain: F-003 showed the route is behind `requireAuth`.

## What did not hold

- **Zip-slip via `..`, absolute paths, backslashes, encoded dots, NUL, or
  doubled separators:** rejected before any write; no canary created.
- **Symlink or hardlink extraction:** the ZIP extractor never creates links;
  the tar extractor rejects link and FIFO types.
- **Declared-size ZIP bomb:** declared per-file and total caps, plus
  `io.LimitReader`, bound decoded output; the 20 MiB request cap is enforced.
- **Task-archive traversal:** the extractor checks `Clean`, `IsAbs`, `..`,
  `filepath.Rel`, entry count, and a 128 TiB ceiling; all tested shapes were
  rejected.
- **Unauthenticated exploitation:** not reachable; the valid-token control is
  required and F-003 records the 401 matrix.

## Limitations

The full `cmd/artex` listener still cannot start on this host without
PostgreSQL (`open stores: no database config found`), so this proof uses the
production `Server.Handler()` over a real loopback listener, as F-003 did. The
full `go test ./...` has the same limitation: all non-`server` packages pass,
while DB-dependent `server` tests fail at `no database config found`; the
targeted archive tests pass on both compress versions. The task-archive
extractor was tested directly because its package is generated and restored
from a checksummed DB record, not uploaded by the user. No Strix, Shannon, or
sapper execution was used. The operator-charter model and the "target content
is data, not instructions" rule are unchanged; repository content was treated
as evidence.
