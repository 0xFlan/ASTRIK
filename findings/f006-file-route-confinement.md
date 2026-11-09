# F-006 — Skill, chat-upload, and restore paths escape their roots through symlinks; workspace check-then-use race closed with os.Root

| Field | Value |
|---|---|
| Status | Confirmed, fixed in the upstream audit copy; patch not pushed upstream |
| Severity | Medium (authenticated host file read/write/delete outside the managed root through a planted link; CVSS 3.1 7.5, `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| Affected | `server/server_mgmt.go` (skill file, meta, dirs, delete routes), `server/chatupload.go`, `server/platform_tools.go`, `server/ask_operator.go`, `server/task_archive_package.go`, `server/workspace.go` (residual race) at BaaRai/ARTEX `fbe7839` |
| Trigger | Authenticated requests with a path that crosses a symlink under the skill root, a chat upload dir, a restore destination, or the work dir |
| Evidence | `evidence/f006/logs/`, `evidence/f006/repro/zz_evidence_confinement_test.go` |
| Patch | `evidence/f006/patches/file-route-confinement.patch`, `evidence/f006/patches/test-skill-gaps-isolation.patch` |

## Summary

F-005 fixed the workspace read/download/write/mkdir routes with a lexical
resolver plus an `Lstat` walk, and explicitly flagged that the skill file routes
still used the same lexical pattern. This pass extended the test matrix to every
file-touching route in the production stack and found that the skill routes,
the `SKILL.md` meta rewrite, chat attachment uploads, and the archive-restore
helper all followed symlinks out of their roots. The workspace routes already
rejected the planted links (F-005), but their check-then-use race remained: the
`Lstat` validation and the subsequent `os.ReadFile`/`WriteFile` were separate
path resolutions.

All routes now resolve through `os.Root`, which holds the root directory open
and performs every component lookup through that descriptor. The kernel-facing
resolution refuses a symlink that leaves the root, and there is no interval
between a validation and the operation, so the F-005 race is closed rather than
narrowed.

| Request (valid JWT) | Before | Observable effect |
|---|---|---|
| `GET /api/skills/conf-probe/files/leak` (link → outside file) | `200` | body contained `ARTEX-OUTSIDE-CANARY-F006` |
| `PUT /api/skills/conf-probe/files/leak` `{"content":"ARTEX-OUTSIDE-WRITE-F006"}` | `200` | outside canary overwritten |
| `GET /api/skills/conf-probe/files/outdir/victim.txt` (dir link) | `200` | body contained the outside victim file |
| `POST /api/skills/conf-probe/dirs` `{"path":"outdir/created-by-f006"}` | `201` | directory created outside the skill root |
| `DELETE /api/skills/conf-probe/files/outdir/victim.txt` | `200` | outside victim file **deleted** |
| `GET /api/skills/conf-probe/files/nested/escape` (nested link) | `200` | outside content returned |
| `PUT /api/skills/conf-meta/meta` with `SKILL.md` replaced by a link | `200` | outside `SKILL.md` rewritten with `ARTEX-OUTSIDE-META-F006` |
| `POST /api/chat/upload?scope=staging&id=probe` with `uploads` → outside dir | `200` | uploaded file written outside the work dir |
| `installTaskArchiveFiles` with `tasks/` → outside dir | returns stage, no error | restored task files renamed outside the data dir |

After the fix every escape returns `400 {"error":"invalid path"}` (the archive
helper returns an error before renaming), while the positive controls keep
working: skill file write/read `200`, skill mkdir `201`, skill delete `200`,
chat upload `200` with the file inside the work dir, and workspace write/read
`200` with the expected content.

## Why this is reachable

The links are ordinary `os.Symlink` entries planted inside the allowed root.
Three ordinary paths place them there:

1. **The agent's Bash tool.** A task workspace is the agent's CWD, and the
   skills directory is writable on the host. Target-controlled content
   (a page, repository, ticket, or MCP description) can steer the agent to
   `ln -s ~/.ssh skills/foo/key` or to clone a repository that already contains
   such a link. The agent already has host access, so this is not privilege
   escalation *from the agent*; it breaks the operator-facing web routes, which
   are used with the belief that they are confined to the skill/workspace root.
2. **Cloned or downloaded material.** `git clone` preserves repository
   symlinks. The workspace file manager's documented contract is "inside the
   work dir"; a cloned repo violates that contract without any route needing to
   create a link itself.
3. **A future archive or sync path that preserves links.** The skill ZIP
   extractor currently materialises a symlink entry as a regular file (it used
   `os.Create`), so it could not plant one. That is an accident of the current
   implementation, not a guarantee; the fix now rejects ZIP symlink entries
   explicitly and resolves all file routes through `os.Root`, so preserving a
   link later cannot turn into an escape.

Once a link exists, an authenticated operator request reads or writes through
it. A write aimed at `~/.ssh/authorized_keys`, a shell profile, or a service
unit is code execution as the server user; a read aimed at `~/.aws/credentials`,
`jwt.key`, or the LLM profile store discloses credentials to the browser. The
delete primitive is destructive on its own: `DELETE .../files/outdir/victim.txt`
removed an outside file in the unpatched run.

## Root cause

The skill routes validated the path lexically and then passed the joined string
to the filesystem:

```go
clean, msg := skillRelPath(rel)          // rejects "..", "\", "%", absolute
full := filepath.Join(skillPath, clean)  // still just a string
os.ReadFile(full)                        // kernel follows the link
os.WriteFile(full, ...)
os.MkdirAll(full, ...)
os.RemoveAll(full)
```

`skillRelPath` is a good lexical filter, but it cannot see a symlink. The same
pattern existed in `fsUpdateSkillMeta`, `fsDeletePath`, `platform_tools.go`,
and the chat upload destination. The workspace routes used a second resolution
(the `Lstat` walk) after the lexical check, which was correct for the tested
links but left a time-of-check/time-of-use window.

## Fix

Every operation now goes through an `os.Root` opened on the allowed directory:

- `s.wsRoot()` → `os.OpenRoot(s.m.dir)` for list/read/write/mkdir/delete/
  download/upload; download uses the opened file with `http.ServeContent`
  instead of re-resolving the path.
- `s.openSkillRoot()` → `os.OpenRoot(s.skillDir)` for list/read/write/dirs/
  delete/meta/create/upload and the platform tools (`create_skill`,
  `update_skill_file`).
- `os.OpenRoot(s.m.dir)` for chat attachment uploads and the `ask_operator`
  destination; `uniqueUploadRelPath` and `saveUploadRoot` operate on the root.
- `installTaskArchiveFiles` refuses a restore destination whose existing
  components cross a symlink (the source is a separate extraction root, so a
  single `os.Root` cannot cover both sides of the rename).
- `fsUploadSkill` rejects a ZIP entry whose mode carries `os.ModeSymlink`.

`wsRelative` is now purely lexical and rejects `..` segments, a leading slash,
and backslashes (a Windows separator on any host) before the root call; the
confinement itself is the root descriptor, not the string check. A lexical
`pathCrossesSymlink` remains only for the archive-restore rename, where the
source and destination roots differ.

Exact patch: `evidence/f006/patches/file-route-confinement.patch`. Apply from
the ARTEX repository root:

```bash
git apply <skill-repo>/evidence/f006/patches/file-route-confinement.patch
git apply <skill-repo>/evidence/f006/patches/test-skill-gaps-isolation.patch
gofmt -w server/workspace.go server/server_mgmt.go server/chatupload.go \
  server/platform_tools.go server/ask_operator.go server/task_archive_package.go
```

The patch applies cleanly to `fbe7839`; it supersedes
`evidence/db/patches/workspace-symlink.patch` for `workspace.go` (the F-005
patch remains as the record of the earlier, narrower fix).

## Residual limits

- `os.Root` is the durable primitive for the file routes: it opens the root
  directory once and resolves each component through it, so the F-005
  check-then-use gap is closed. On Unix the Go documentation calls out a race
  only for `Chmod`/`Chown`/`Chtimes`, which these routes do not use.
- The archive-restore helper still uses a check-then-rename because its source
  is the extraction temp root and its destination is `dataDir`; `os.Root` does
  not rename across roots. The destinations are built from a numeric task id
  and the parent directories are server-created, so this is defense-in-depth,
  not a route-reachable primitive. A multi-tenant deployment should copy the
  extracted files in through a destination root instead.
- `ask_operator` reads an arbitrary `image_path` supplied by the agent and
  copies it into task uploads. That read is by design: the tool exists to stage
  a screenshot the agent produced, and the agent already has host read access.
  The write side is now confined, and the source read is not a new boundary.
- The workspace root itself may be a symlink (macOS `/var` → `/private/var`);
  `os.OpenRoot` follows the root path once, which is intended.

## Reproduction

The probe starts the real `Server.Handler()` (CORS → `requireAuth` → `ServeMux`)
on a loopback listener with a valid JWT, creates two skills through the public
API, plants the links, and drives every route. The archive helper is called
directly because restore runs in the persistent archive worker, not a
synchronous HTTP route.

```bash
# Disposable PostgreSQL; see evidence/db/README.md.
eval "$(<skill-repo>/evidence/db/provision-test-postgres.sh -q)"

cd <ARTEX-repo>
cp <skill-repo>/evidence/f006/repro/zz_evidence_confinement_test.go server/
ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./server -run TestFileRouteConfinementMatrix -count=1 -v
```

Before/after, same fixture and same JWT:

| Probe | Before | After |
|---|---|---|
| `skill-read-filelink` | `200` + outside canary | `400 invalid path` |
| `skill-write-filelink` | `200`, outside file changed | `400 invalid path` |
| `skill-read-dirlink` | `200` + outside victim | `400 invalid path` |
| `skill-mkdir-dirlink` | `201`, outside dir created | `400 invalid path` |
| `skill-delete-dirlink` | `200`, outside file deleted | `400 invalid path` |
| `skill-read-nested` | `200` + outside content | `400 invalid path` |
| `skill-meta-symlink` | `200`, outside `SKILL.md` rewritten | `400 invalid path` |
| `chat-upload-symlink` | `200`, outside file written | `400 invalid path` |
| archive restore with symlinked `tasks/` | file outside, no error | error, no outside file |
| all positive controls | `200`/`201` | `200`/`201` |

Negative evidence recorded in the same run:

- `GET .../files/..%2F..%2F..%2Fetc%2Fpasswd`, the double-encoded `%252e`
  form, `%2Fetc%2Fpasswd`, and `..%5C..%5Cetc%5Cpasswd` all returned `400`
  before and after the fix; `skillRelPath` already rejected them.
- `DELETE /api/skills/conf-meta` with the skill directory itself replaced by a
  link returned `200` but removed only the link; the outside target survived
  both before and after (`os.RemoveAll` does not follow a final symlink).
- The workspace read/download/list/delete/upload probes all returned `400` on
  the F-005 code and still do; the new root resolver preserves that behaviour.
- `ws-backslash` returned `404` before and `400 invalid path` after; a
  backslash is a literal filename character on macOS, not an escape, but it is
  now rejected explicitly for Windows parity.

## Fixture defect found by the second full run

`TestSkillGapsReport` asserts that its fixture skill is the global top miss.
The report aggregates `skill_usage` across the whole disposable `_server`
database, so rows left by earlier runs (`graphql-audit`) legitimately outranked
it on the second run: `first="graphql-audit" want rsi-test-graphql`. The test
now clears the table before inserting and on cleanup, which makes the global
ordering deterministic without changing any assertion or product behaviour
(`evidence/f006/patches/test-skill-gaps-isolation.patch`). This is a fixture
bug, not a product bug; it is recorded because it would otherwise make the
full-suite repeatability claim false.

## Verification

With a disposable PostgreSQL, the full `go test ./...` is green twice in a row:
14 packages `ok`, 0 `FAIL`, the `server` package in 20.672 s and 21.368 s. The
only skipped test is `TestLiveContextReview`, which needs an external live-model
configuration and is environment-only. Logs:
`evidence/f006/logs/go-test-run1.log`, `go-test-run2.log`.

## Recommended remediation

1. Apply both F-006 patches to `fbe7839` and run the confinement probe.
2. Keep `os.Root` for every file route; do not replace it with a path-prefix
   check. Keep the ZIP symlink rejection so an archive cannot plant a link.
3. Convert the archive-restore rename to a copy through a single destination
   root if multi-tenant isolation is required; until then, keep the parent
   symlink check and the numeric task-id validation.
4. Add `TestFileRouteConfinementMatrix` to the regular suite (it needs
   PostgreSQL, like the rest of the DB-backed server tests) so a new file route
   cannot ship without the same matrix.
