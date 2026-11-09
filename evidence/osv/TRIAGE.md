# OSV-Scanner triage — skill arsenal, 2026-11-09

**Scanner:** osv-scanner 2.7.0 (osv-scalibr 0.5.3), installed with Homebrew.
**Scope:** every dependency manifest in the skill's arsenal
(`/Users/flan/artex-audit/{baarai,hinln,ruoji6,norma}`), plus the generated
CycloneDX SBOM. The campaign tree (`synology-bounty`) and this skill repository
contain no package sources; both were scanned and recorded as empty (exit 0
with `--allow-no-lockfiles`).

## Commands

```bash
osv-scanner scan source -r /Users/flan/artex-audit \
  --format json --output-file evidence/osv/scan-arsenal.json

osv-scanner scan source -r /Users/flan/artex-audit \
  --format cyclonedx-1-6 --output-file evidence/osv/arsenal.cdx.json

osv-scanner scan source --sbom evidence/osv/arsenal.cdx.json \
  --format json --output-file evidence/osv/scan-sbom.json
```

The SBOM round-trip produced the same 130 advisory IDs as the direct scan
(`only_in_raw=0`, `only_in_sbom=0`). The CycloneDX file records the 34 vulnerable
components, which is why its component count is smaller than the package count.

`evidence/osv/baarai-advisories.tsv` is the per-advisory ledger: 123 deduped
package/advisory rows covering 119 unique advisory IDs for the primary ARTEX
repository. `hinln` and `ruoji6` carry the same lockfiles (documented
reference-only forks), so they add duplicate rows, not new reachability.

## Verdict rule

A version match is an L1 clue. The verdict below is about the **vulnerable code
path**, using three observed facts:

1. is the package imported by application code (`rg` over `web/src`, `server/`,
   `skills/`), or only present transitively;
2. what dependency path reaches it (lockfile reverse edges, root dependency set);
3. for Go, whether OSV call analysis marks the vulnerable symbol `called`.

"Not reachable" means the vulnerable component is not on a path an attacker can
influence in this deployment, not that the CVE is fake.

## Verdicts by package

| Package | Version | Adv. | Dependency path | Reachability verdict |
|---|---|---|---|---|
| `github.com/klauspost/compress` | 1.18.6 | 2 | direct Go | **Confirmed L2 DoS, post-auth (F-002/F-003).** `zstd` imported in `server/skill_zip.go` and `server/task_archive_package.go`; the advisory frame wrapped in a ZIP method-93 entry panics through `fsUploadSkill → readZipEntry` on 1.18.6 (`index out of range [33077]`) and returns `400 corrupt input: weights tableLog too big` on 1.20.2. The upload route is behind `requireAuth`, so the crash requires a JWT. GO-2026-5841 is `s2` (not called). Fix: 1.20.2; patch in `evidence/zstd/patches/`. **F-004:** the server's `ZipDecompressor` accepted a 128 MiB zstd window; a 228-byte authenticated archive returned `201` and retained ~135 MB of heap on both 1.18.6 and 1.20.2. The `server/skill_zip.go` patch adds an 8 MiB decoder-window cap and returns a bounded `400`; see `evidence/archive/` and `findings/f004-zstd-window-memory-amplification.md`. |
| `github.com/andybalholm/brotli` | 1.2.1 | 1 | indirect Go | Not reachable: not imported by application code; OSV `called:false`. Fix: 1.2.7. |
| `golang.org/x/crypto` | 0.58.0 | 1 | direct Go | Not reachable: advisory is `openpgp`, which is not imported; `called:false`. Bump on maintenance. |
| `next` | 16.2.9 | 20 | direct runtime | **Middleware bypass disproven for this app (F-002).** The advisory requires a single `config.i18n.locales` entry; `web/next.config.mjs` has no `i18n` block, and the matcher covers locale-prefixed paths. A real 16.2.9 build redirected `/function/tasks`, `/en/function/tasks`, RSC, prefetch, and `x-middleware-subrequest` probes to `/login` (all 307). The upstream class was reproduced in a single-locale fixture: `/en/protected` returned 200 on 16.2.9 and 307 on 16.2.11. Rewrites SSRF is not reachable (static env destination); image RCE is config-gated; Server Actions/`use cache`/`next/og` are unused. Fix: 16.2.11; patch in `evidence/next/patches/`. |
| `sharp` | 0.34.5 | 3 | `next` → sharp | Image-optimizer component; only local/static images are configured, so no attacker-controlled image input was found. Not demonstrated. Fix: 0.35.5. |
| `zod` | 4.4.3 | 1 | direct dependency | No import in `web/src`; validation is not on an observed request path. Not reachable in current code. Fix: 4.6.6 before use. |
| `shadcn` CLI tree: `@modelcontextprotocol/sdk` 6, `hono` 9, `@hono/node-server` 2, `undici` 23, `express`/`qs` 3/`body-parser` 1/`proxy-addr` 1/`ip-address` 16, `fast-uri` 12, `js-yaml` 2, `minimatch` 1, `browserslist` 2, `baseline-browser-mapping` 1, `brace-expansion` 5, `deepmerge` 1, `postcss-selector-parser` 1, `systeminformation` 3 | as locked | 83 | transitive via `shadcn` | **CLI/build-time only.** None are imported by the Next runtime; `rg` over `web/src` found only a placeholder string mentioning `@modelcontextprotocol`. They are reachable when a developer runs the `shadcn` CLI, which processes repository-controlled config, not target input. Not remotely reachable. |
| `postcss` 6, `nanoid` 2, `source-map-js` 1 | as locked | 9 | build CSS pipeline | Build-time only; input is repository CSS, not attacker data. Not reachable at runtime. |
| `basic-ftp` | 5.3.1 | 1 | `api-recon` install tree | Operator tooling; not imported by `skills/api-recon/scripts/*` (`rg` found it only in the lockfile). Not reachable from a scanned target. |
| `extract-zip` | 2.0.1 | 2 | `@puppeteer/browsers` | Unzips the browser download during operator setup; the archive is fetched from the browser vendor, not the target. Not reachable from target input. |

No `basic-ftp` or `extract-zip` import exists in the recon scripts; both are
transitive setup dependencies. No SBOM-only advisory exists.

### Auth boundary (F-003)

The production `Server.Handler()` was served on a loopback listener and probed
with the crafted zstd archive and every anonymous credential/route shape: no
token, empty bearer/cookie/query token, `alg:none`, RS256, wrong-key HS256,
dot-dot and encoded-dot-dot paths, repeated slashes, trailing slash, uppercase
`/API`, `/api/auth/*` and `/api/health` exemptions, task-archive restore routes,
and `OPTIONS`. All import attempts were rejected (`401`) or redirected to
`/api/skills/upload`, where a redirect-following client also got `401`; encoded
traversal returned `404`; no request panicked. The valid-token control reached
`fsUploadSkill` (1.18.6 panic, 1.20.2 bounded 400). The auth boundary holds; the
crash remains post-auth. Details: `findings/f003-jwt-route-bypass-does-not-hold.md`.

### Archive handling (F-004)

The production `Server.Handler()` was driven with the oversized-window archive on
compress 1.18.6 and 1.20.2. Before the fix, each returned `201` and installed a
skill; after a forced GC, `HeapAlloc` rose by 135,163,008 bytes (1.18.6) and
135,199,376 bytes (1.20.2). The ZIP is only 228 bytes and the frame is 72 bytes.
After adding `zstd.WithDecoderMaxWindow(8<<20)`, the same archive returns
`400 {"error":"failed to read SKILL.md: window size exceeded"}` with a heap delta
of +26,136 / -11,096 bytes. A normal zstd archive still returns `201`.

The same run rejected all eight ZIP traversal shapes (`..`, nested `..`,
backslashes, doubled separators, `%2e%2e`, drive/colon, NUL, absolute path) with
`400` and no outside canary. The tar.zst extractor rejected traversal, `.`,
`a/..`, absolute paths, symlinks, hardlinks, FIFOs, and a forged 1 EiB header;
the task package is server-generated and checksummed, so this is defense-in-depth.
Details: `findings/f004-zstd-window-memory-amplification.md`.

### PostgreSQL-backed routes and workspace confinement (F-005)

The suite's database tests had never executed: `go test ./...` failed at
`no database config found: ARTEX_PG_DSN is not set`. A disposable PostgreSQL 17
cluster on `127.0.0.1:55432` (`evidence/db/provision-test-postgres.sh`, exact
commands in `evidence/db/README.md`) now runs them for real. On a reset cluster
the full suite is green: 14 packages `ok`, 0 `FAIL`, `server` in 21.197 s, and
the only skip is `TestLiveContextReview`, which needs
`ARTEX_REVIEW_LIVE_CONFIG` and an external model (environment-only). A second
consecutive run is green after the fixture patch
(`evidence/db/patches/test-idempotency.patch`); before that patch the rerun
failed on fixed-name rows because `defer d.Close()` ran before the cleanup
DELETEs, and on a company scope that survived into the next run.

The production `Server.Handler()` was driven over loopback with a valid JWT and
two tasks created through the public API. The DB-backed authz/injection matrix
held: 11/11 anonymous requests to task, archive, credential, goal, log, LLM,
skill-upload, and workspace routes returned `401`; cross-task goal/constraint/
scope/credential operations returned `404`/`500` and left the victim task
unchanged; cross-task task-intercept-rule toggle/update/delete changed nothing
(the toggle returns a misleading `200 ok` — an API-semantics defect, not a
mutation); SQL metacharacters in `task-archives?q=`, `?state=`, `findings?query=`,
`?severity=`, and `logs/history?q=` left the result sets identical to the
baseline; non-numeric, unknown, and negative archive ids returned `400`/`404`/`409`.

The confirmed defect is outside the DB layer: `wsResolve` confined workspace
paths lexically but followed symlinks. A link planted in the work dir made
`/api/workspace/read` and `/download` return an outside canary (`200`), `/write`
overwrite an outside file (`200`), and `/mkdir` create an outside directory
(`200`). After `pathCrossesSymlink`, all four return `400 invalid path`, while a
normal write/read control still returns `200`. Details:
`findings/f005-workspace-symlink-escape.md`.

## What this does and does not prove

- F-004 is a confirmed authenticated memory-exhaustion primitive (L2→availability
  impact): the 20 MiB upload cap does not bound the decoder window. The 8 MiB
  server patch closes it; it is not an unauthenticated chain.
- The PostgreSQL gap recorded in F-003/F-004 is closed. A disposable cluster
  runs the full `go test ./...` green (14 packages, `server` 21.197 s); only the
  live-model test skips, and it is skipped because its external configuration is
  absent, not because the database is. The suite is repeatable: a second run is
  green after the fixture patch, and both logs are under `evidence/db/logs/`.
- F-005 is a confirmed authenticated confinement escape (L2→host file
  read/write), not privilege escalation from the agent: the agent's Bash can
  already reach the host. It breaks the browser file manager's documented
  "inside the work dir" boundary and turns any symlink in a cloned repo or task
  workspace into an operator-session read/write primitive. The fix rejects paths
  that cross a symlink; the check-then-use race remains for a multi-tenant
  deployment, where `openat`/`O_NOFOLLOW` is the right primitive.
- The Go panic is a reachable code path (L2): the vulnerable symbol is compiled
  in and called on an archive path. F-003 exercised its authentication boundary
  with the full route stack: anonymous requests do not reach it, and a valid JWT
  does. The 10 MiB multipart size limit was not separately exercised.
- The Next middleware bypass is reachable in principle (middleware is present),
  but no running instance was built or tested. It is a candidate, not a finding.
- Everything else is an L1 version match with no observed path from target input.
- Recommended remediation for the platform repositories: bump
  `github.com/klauspost/compress` to 1.20.2 and `next` to 16.2.11+, then re-run
  the same three commands. These repositories are upstream to this skill; this
  repository records the triage rather than editing them.
