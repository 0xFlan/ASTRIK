# Auth-boundary evidence (F-003)

This directory decides whether the zstd import crash can be made
unauthenticated by attacking the JWT layer or the route table.

## Reproducer

`repro/zz_evidence_auth_boundary_test.go` starts the production
`Server.Handler()` on a loopback HTTP listener and sends the crafted method-93
zstd archive with:

- no credential, an empty bearer, an empty cookie, and an empty query token;
- `alg:none`, RS256, and wrong-key HS256 tokens;
- the canonical upload route and task-archive restore routes;
- traversal forms (`..`, `%2e%2e`, `%2e%2e%2f`), repeated slashes, a trailing
  slash, an uppercase API prefix, and a path using the `/api/auth/` and
  `/api/health` exemptions;
- a redirect-following client for the 307 paths;
- `OPTIONS` preflight, `/api/health`, and `/api/auth/status`.

A separate positive control sends a valid `signJWT` token and the same archive
to `/api/skills/upload`.

## Results

| Artifact | Result |
|---|---|
| `logs/go-test-1.18.6.log` | anonymous test passes (all import shapes 401/307/404); positive control logs `panic: index out of range [33077]` in `fsUploadSkill` |
| `logs/go-test-1.20.2.log` | both tests pass; positive control returns `400 corrupt input: weights tableLog too big` |

All anonymous import paths were rejected or redirected to `/api/skills/upload`,
which then returned `401`; no anonymous request reached the archive decoder.
`OPTIONS` returned `204` without invoking a handler, and `/api/health` returned
`{"ok":true}` without a version.

## Commands

```bash
# 1.18.6 upstream copy
cd /Users/flan/artex-audit/baarai
cp <skill>/evidence/auth/repro/zz_evidence_auth_boundary_test.go server/
go test ./server -run \
  'TestAuthBoundaryAnonymousImportRoutesRejected|TestAuthenticatedCraftedZipReachesUpload' \
  -count=1 -v

# 1.20.2 copy
cd /tmp/baarai-zstd-fixed
cp <skill>/evidence/auth/repro/zz_evidence_auth_boundary_test.go server/
go test ./server -run \
  'TestAuthBoundaryAnonymousImportRoutesRejected|TestAuthenticatedCraftedZipReachesUpload' \
  -count=1 -v
```

Environment: go1.27.3 darwin/arm64, ARTEX upstream copy `BaaRai/ARTEX` at
compress 1.18.6, and the patched `/tmp` copy at 1.20.2.

## Limitation

`cmd/artex` builds, but exits at `open stores: no database config found` because
PostgreSQL is not installed or listening on this host. The proof drives the
production `Server.Handler()` (same `cors`, `requireAuth`, `ServeMux`, and
`fsUploadSkill`) instead of the full listening binary. This is a test harness
limitation, not an auth result.
