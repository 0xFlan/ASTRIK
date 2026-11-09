# F-002 — Next middleware bypass → unauthenticated zstd import panic: chain does not hold

| Field | Value |
|---|---|
| Status | Chain disproven; zstd panic confirmed (post-auth upstream DoS) |
| Severity of chain | None end-to-end; the zstd component is Medium (authenticated DoS) |
| Links tested | GHSA-6gpp-xcg3-4w24 (Next 16.2.9), GO-2026-6865 / CVE-2026-116591 (compress 1.18.6) |
| Evidence | `evidence/next/`, `evidence/zstd/` |

## Chain under test

```
unauthenticated request
  → Next middleware/proxy bypass (GHSA-6gpp-xcg3-4w24)
  → attacker-controlled zstd archive reaches /api/skills/upload
  → panic in klauspost/compress 1.18.6
```

**Verdict: the chain does not hold.** Two independent blockers break it, and
the zstd panic remains real once an authenticated caller reaches the handler.

## Link 1 — Next bypass: not present in this app

The advisory requires an App Router build with Turbopack and a **single entry in
`config.i18n.locales`**. `web/next.config.mjs` contains no `i18n` block at all
(`rg -n "i18n|locales" web/next.config.mjs` → no match). The proxy matcher is a
negative lookahead that covers every non-static path, including locale-prefixed
and RSC variants.

A real production build of `web/` (Next 16.2.9, `next build` then
`next start -p 3217`) was probed without credentials:

| Request | Result |
|---|---|
| `GET /function/tasks` | `307` → `/login` |
| `GET /function/tasks` + `Cookie: artex_token=test` | `200` |
| `GET /en/function/tasks` | `307` → `/login` |
| `GET /en/function/tasks` + `RSC: 1` + router state | `307` → `/login` |
| `GET /function/tasks` + `RSC: 1` | `307` → `/login` |
| `GET /function/tasks` + `Next-Router-Prefetch: 1` | `307` → `/login` |
| `GET /function/tasks` + `x-middleware-subrequest: …` | `307` → `/login` |

Logs: `evidence/next/logs/app-probes.txt`, build:
`evidence/next/logs/app-build-16.2.9.log`.

The upstream class is real, just not reachable in this configuration. A minimal
single-locale Turbopack fixture (`i18n.locales: ['en']`, `matcher: '/protected'`)
was built twice:

| Fixture | `/protected` no cookie | `/en/protected` no cookie |
|---|---|---|
| Next 16.2.9 | `307` → `/login` | **`200` protected page** |
| Next 16.2.11 | `307` → `/login` | `307` → `/login` |

The 16.2.9 middleware manifest regexp omits the locale-prefix branch; the
16.2.11 manifest includes it. Logs:
`evidence/next/logs/fixture-16.2.9.txt`,
`evidence/next/logs/fixture-16.2.11.txt`. This proves the test detects the bug
and the patch changes behavior.

## Link 2 — the upload API is a separate JWT boundary

Even a page-level middleware bypass would not authenticate an API call:

- `server/server.go:967`: `api := cors(s.requireAuth(mux))` wraps the whole API.
- `server/auth.go:195`: `requireAuth` returns `401 Unauthorized` when no token
  is present; only `/api/auth/*` and `/api/health` are exempt.
- `web/src/proxy.ts` explicitly excludes `api/` from the matcher, so the page
  proxy never guarded `/api/*` in the first place.

`TestSkillUploadRejectsMissingJWT` drives the real wrapper: the handler is not
reached and the response is `401`. Log:
`evidence/zstd/logs/auth-missing-jwt.log`.

## Link 3 — zstd panic: confirmed on the real handler

The crafted two-block frame from GHSA-fpmh-frq8-7rj8 was placed inside a ZIP
entry with method 93 (Zstandard), then POSTed through the real
`fsUploadSkill` handler. No direct decompressor call is made.

**compress 1.18.6** — panic (exit 1):

```
panic: runtime error: index out of range [33077] with length 32768
github.com/klauspost/compress/fse.(*decoder).nextFast
github.com/klauspost/compress/huff0.ReadTable
github.com/klauspost/compress/zstd.(*blockDec).decodeLiterals
github.com/Autumn-27/artex/server.readZipEntry
github.com/Autumn-27/artex/server.(*Server).fsUploadSkill
```

**compress 1.20.2** — bounded rejection (exit 0):

```
bounded rejection: status=400 body={"error":"failed to read SKILL.md: corrupt input: weights tableLog too big"}
```

Logs: `evidence/zstd/logs/go-test-1.18.6.log`,
`evidence/zstd/logs/go-test-1.20.2.log`.

Impact is a crash of the ARTEX server by an authenticated user who can upload a
skill archive. It is not an unauthenticated crash. The fix removes the panic and
returns a decode error.

## Fixes

Both manifests are upstream copies (`github.com/BaaRai/ARTEX`); this repository
cannot commit to them. Exact patches and bump commands are committed instead:

- `evidence/zstd/patches/compress-1.20.2.patch` — `go.mod`/`go.sum` from 1.18.6
  to 1.20.2. Apply with `git apply` in the ARTEX root, then
  `go mod download && go test ./server -run TestUploadCraftedZstdSkillZip`.
- `evidence/next/patches/next-16.2.11.patch` — `web/package.json` and
  `web/package-lock.json` from 16.2.9 to 16.2.11. Apply with `git apply`, then
  `cd web && npm ci && npm run build`. `web/next.config.mjs` needs no change.

The tester passes on 16.2.9 only as a detector of the upstream bug; on the app it
passes before and after because the app was never affected. The zstd tester fails
(panics) on 1.18.6 and passes on 1.20.2.

## Reproduction

```bash
# zstd, pinned version
cp evidence/zstd/repro/zz_evidence_zstd_panic_test.go <artex>/server/
cd <artex> && go test ./server -run TestUploadCraftedZstdSkillZip -count=1 -v
# zstd, fixed version (after git apply evidence/zstd/patches/compress-1.20.2.patch)
go test ./server -run TestUploadCraftedZstdSkillZip -count=1 -v
```

Next fixture: `npm install next@16.2.9 react@19.2.7 react-dom@19.2.7`, with
`i18n: { locales: ['en'], defaultLocale: 'en' }`, `matcher: '/protected'`, and a
middleware that redirects when the `auth` cookie is absent; build with
`next build --turbopack`, then request `/en/protected`. Repeat with 16.2.11.

## What would make the chain hold

A deployment that (a) adds `i18n` with exactly one locale and (b) uses a narrow
middleware matcher such as `/protected`, and (c) has a pre-auth path into an
archive handler that decodes zstd. None of those is true here. The correct
defensive order is still: upgrade both components, and never rely on middleware
alone for API authorization.
