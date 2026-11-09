# GHSA-6gpp-xcg3-4w24 — middleware bypass test on Next 16.2.9

**Advisory:** single-locale `config.i18n.locales` + Turbopack + App Router;
fixed in Next 16.2.11.

## Real app (not vulnerable)

Built `baarai/web` at Next 16.2.9 with `npx next build`, served with
`npx next start -p 3217`, and probed without credentials. All redirect:

| Request | Status |
|---|---|
| `/function/tasks` | 307 → `/login` |
| `/function/tasks` + `Cookie: artex_token=test` | 200 |
| `/en/function/tasks` | 307 → `/login` |
| `/en/function/tasks` + `RSC: 1` + state tree | 307 → `/login` |
| `/function/tasks` + `RSC: 1` | 307 → `/login` |
| `/function/tasks` + `Next-Router-Prefetch: 1` | 307 → `/login` |
| `/function/tasks` + `x-middleware-subrequest` | 307 → `/login` |

Raw headers/bodies: `logs/app-probes.txt`; build log:
`logs/app-build-16.2.9.log`.

The app has no `i18n` block in `web/next.config.mjs`, and its matcher is a
negative lookahead covering `/en/...`. The advisory precondition is absent.

## Minimal fixture (upstream bug and fix)

`/tmp/next-i18n`: Pages Router with `i18n: { locales: ['en'], defaultLocale:
'en' }`, `matcher: '/protected'`, middleware redirects without an `auth` cookie.
Built with `next build --turbopack`.

| Version | `/protected` | `/en/protected` |
|---|---|---|
| 16.2.9 | 307 → `/login` | **200** protected page |
| 16.2.11 | 307 → `/login` | 307 → `/login` |

Logs: `logs/fixture-16.2.9.txt`, `logs/fixture-16.2.11.txt`; build logs
alongside them. On 16.2.9 the manifest regexp lacks the locale-prefix branch; on
16.2.11 it includes `(?:/((?!_next/)[^/.]{1,}))`.

## Fix

`patches/next-16.2.11.patch` updates `web/package.json` and
`web/package-lock.json`. ARTEX is an upstream copy, so apply it locally:

```bash
cd <artex> && git apply <this-skill>/evidence/next/patches/next-16.2.11.patch
cd web && npm ci && npm run build
```

The real app was already protected, so its probe passes before and after; the
fixture is the fail-before/pass-after test for the upstream issue.
