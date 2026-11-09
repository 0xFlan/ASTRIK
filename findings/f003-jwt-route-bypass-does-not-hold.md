# F-003 — JWT and route-table bypass against the zstd import: chain does not hold

| Field | Value |
|---|---|
| Status | Chain disproven; no unauthenticated auth bypass found |
| Severity of chain | None end-to-end; the zstd component remains Medium (authenticated DoS) |
| Links tested | JWT issuance/verification, `requireAuth`, route registration, path normalization, CORS preflight, query/cookie/header token extraction |
| Evidence | `evidence/auth/` |

## Question

F-002 proved the zstd panic through `fsUploadSkill` and showed that the upload
route is behind `requireAuth`. This finding treats the JWT layer and the route
table as the target: can an anonymous request forge or bypass credentials, or
reach an auth-skipped route that still reaches archive import, and then panic
`klauspost/compress` 1.18.6?

**Verdict: no.** Every anonymous import request was rejected or redirected to a
path that still enforces the JWT boundary. A valid token is required, and the
only path that reaches the decoder is the wrapped `POST /api/skills/upload`.

## How it was tested

`evidence/auth/repro/zz_evidence_auth_boundary_test.go` starts the real
`Server.Handler()` (the same `cors → requireAuth → ServeMux` stack used by
`cmd/artex`) on a loopback HTTP listener and sends the crafted method-93 zstd
archive on every request. If a path or credential bypass reached
`fsUploadSkill`, compress 1.18.6 would panic and the request would fail instead
of returning an auth/route error.

Two tests run on both pinned versions:

- `TestAuthBoundaryAnonymousImportRoutesRejected` — anonymous bypass shapes and
  a fresh-client redirect-following pass.
- `TestAuthenticatedCraftedZipReachesUpload` — positive control with a
  `signJWT` token, proving the same archive reaches the handler.

The full `cmd/artex` binary was also built successfully:

```
$ go build -o /tmp/artex-real ./cmd/artex
$ ARTEX_PG_DSN= /tmp/artex-real
open stores: no database config found: ...
```

It cannot listen without PostgreSQL, which is not installed or running on this
host. The request proof therefore uses the production `Handler()` rather than
the full binary; the JWT key, route table, middleware, CORS wrapper and upload
handler are the production implementations. This limitation is explicit and is
not presented as a full-binary run.

## Anonymous requests and observed responses

Compress 1.18.6 and 1.20.2 produced the same routing/status results.

| Request (all with crafted zip where a body is accepted) | Status | Location / body |
|---|---|---|
| `POST /api/skills/upload` | `401` | `{"error":"Unauthorized"}` |
| `POST /api/auth/../api/skills/upload` | `307` | `/api/api/skills/upload` |
| `POST /api/auth/../skills/upload` | `307` | `/api/skills/upload` → follow: `401` |
| `POST /api/auth/%2e%2e/skills/upload` | `404` | `404 page not found` |
| `POST /api/auth/%2e%2e%2fskills%2fupload` | `404` | `404 page not found` |
| `POST /api/health/../skills/upload` | `307` | `/api/skills/upload` → follow: `401` |
| `POST /api//skills/upload` | `307` | `/api/skills/upload` → follow: `401` |
| `POST /api/skills/upload/` | `401` | `Unauthorized` |
| `POST /API/skills/upload` | `404` | frontend stub, not the API |
| `POST /api/skills/upload?token=` | `401` | `Unauthorized` |
| `Authorization: Bearer ` (empty) | `401` | `Unauthorized` |
| `Cookie: artex_token=` (empty) | `401` | `Unauthorized` |
| `Authorization: Bearer <alg:none>` | `401` | `token is invalid or expired` |
| `Authorization: Bearer <RS256 header>` | `401` | `token is invalid or expired` |
| `Authorization: Bearer <wrong-key HS256>` | `401` | `token is invalid or expired` |
| `POST /api/task-archives/1/restore` | `401` | `Unauthorized` |
| `POST /api/task-archives/restore/batch` | `401` | `Unauthorized` |
| `OPTIONS /api/skills/upload` | `204` | CORS preflight; no handler |
| `GET /api/health` | `200` | `{"ok":true}` (no service/version) |
| `GET /api/auth/status` | `503` | DB helper reports unavailable; no import |

No anonymous request returned `200`, `201`, `400`, `409`, or `500` on an import
handler, and the server log contained no panic. The three redirect paths were
also followed with a default-policy client; each final request was `401` at
`/api/skills/upload`.

Logs: `evidence/auth/logs/go-test-1.18.6.log`,
`evidence/auth/logs/go-test-1.20.2.log`. Archive:
`sha256 df24672c03596d295ae4a000940ecd11ef0c6268fa4660629f372c4bb69a0461`,
27,681 bytes.

## Why the auth layer held

- **Key material is random and local.** `loadOrCreateJWTKey` generates a
  32-character key when `jwt.key` is absent, writes it `0600`, refuses short
  keys, and `New` terminates on a load error. There is no default, hardcoded, or
  environment-supplied JWT secret in `.env.example` or `config.example.json`.
- **Only HMAC is accepted.** `verifyJWT` rejects non-HMAC signing methods, so
  `alg:none` and RS256 are returned as invalid before the key is used.
- **The token must be signed.** The wrong-key HS256 probe returned `401`; an
  unsigned/empty bearer, empty cookie, and empty query token all returned `401`.
- **All import routes share the wrapper.** `POST /api/skills/upload` and the
  task-archive restore routes are registered on the same `mux` that
  `api := cors(s.requireAuth(mux))` wraps (`server/server.go:967`). There is no
  second, raw-mux import handler.
- **Exempt routes do not import.** The only exemptions are `/api/auth/*` and
  `/api/health`. `/api/auth/status` is a read-only status probe (503 with no DB
  here); `/api/health` returns only `{"ok":true}` without a token.
- **Normalization does not bypass the wrapper.** Go's `ServeMux` redirects
  `..`, encoded `..`, repeated slashes, and trailing-slash variants before the
  inner handler; following those redirects lands on `/api/skills/upload`, which
  returns `401`. Encoded `%2e%2e` variants returned `404` rather than reaching
  the route.
- **CORS preflight is not an import.** `OPTIONS` is answered `204` by `cors`
  before `requireAuth`, but it never calls a handler.

## Positive control

With a token signed by the server key, the same archive reached the real
handler:

- **compress 1.18.6** — `http: panic serving ...: runtime error: index out of
  range [33077] with length 32768`; stack through `fse.nextFast → huff0.ReadTable
  → zstd.decodeLiterals → readZipEntry → fsUploadSkill`, then
  `requireAuth.func1` at `server/auth.go:211`. net/http recovered the panic and
  closed the request.
- **compress 1.20.2** — `400 {"error":"failed to read SKILL.md: corrupt input:
  weights tableLog too big"}`.

This is the same crash as F-002, now shown through the full production route
stack with a valid token.

## Impact

No unauthenticated impact. An attacker who can authenticate can still crash the
process with a crafted archive on compress 1.18.6; that remains the Medium
post-auth DoS recorded in F-002. The auth boundary itself was not bypassed.

## Recommended fix

No auth fix is required for this chain. The existing wrapper and key handling
held under the tested shapes. Defense-in-depth options, not prerequisites:

1. Pin the verifier to HS256 with
   `jwt.Parse(..., jwt.WithValidMethods([]string{"HS256"}))`. The current HMAC
   family check is safe (it still requires the key), but the comment says HS256
   and the code accepts HS384/HS512.
2. Require `exp` with `jwt.WithExpirationRequired()`. Issued tokens have `exp`,
   but a key-holder could mint one without it; this is not reachable without the
   key.
3. Avoid `?token=` for non-SSE routes. It is an intentional SSE affordance, not
   a bypass, but query tokens leak through logs, Referer, and browser history.

These are hardening changes to the upstream copy; this repository does not edit
or push upstream. If applied, add a test that a token without `exp` and an
HS384 token are rejected.

## Reproduction

```bash
# from the ARTEX repository root
cp evidence/auth/repro/zz_evidence_auth_boundary_test.go server/
go test ./server -run \
  'TestAuthBoundaryAnonymousImportRoutesRejected|TestAuthenticatedCraftedZipReachesUpload' \
  -count=1 -v
```

On compress 1.18.6 the anonymous test passes and the positive control logs the
recovered panic. On 1.20.2 both pass and the positive control logs the bounded
400. The logs in `evidence/auth/logs/` were produced from the upstream ARTEX
copy at `baarai` and the `/tmp/baarai-zstd-fixed` 1.20.2 copy.

Full-binary caveat: `cmd/artex` needs PostgreSQL (`ARTEX_PG_DSN` or
`config.json`); without it the binary exits at `open stores` before listening.
That is why the request proof drives `Server.Handler()` rather than a listening
`cmd/artex` process.
