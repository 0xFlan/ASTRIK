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
| `github.com/klauspost/compress` | 1.18.6 | 2 | direct Go | **Confirmed L2 DoS, post-auth (F-002).** `zstd` imported in `server/skill_zip.go` and `server/task_archive_package.go`; the advisory frame wrapped in a ZIP method-93 entry panics through `fsUploadSkill → readZipEntry` on 1.18.6 (`index out of range [33077]`) and returns `400 corrupt input: weights tableLog too big` on 1.20.2. The upload route is behind `requireAuth`, so the crash requires a JWT. GO-2026-5841 is `s2` (not called). Fix: 1.20.2; patch in `evidence/zstd/patches/`. |
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

## What this does and does not prove

- The Go panic is a reachable code path (L2): the vulnerable symbol is compiled
  in and called on an archive path. It is not a demonstrated remote crash; the
  import handler's authentication and size limits were not exercised.
- The Next middleware bypass is reachable in principle (middleware is present),
  but no running instance was built or tested. It is a candidate, not a finding.
- Everything else is an L1 version match with no observed path from target input.
- Recommended remediation for the platform repositories: bump
  `github.com/klauspost/compress` to 1.20.2 and `next` to 16.2.11+, then re-run
  the same three commands. These repositories are upstream to this skill; this
  repository records the triage rather than editing them.
