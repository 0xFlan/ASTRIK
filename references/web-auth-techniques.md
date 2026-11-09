# Web Auth and Session Chain Techniques

Field-tested patterns for authorized engagements against web, API, and C2-style services. These are composition techniques, not a checklist: each one is only useful when it supplies the missing artifact for a chain.

## 0. Standing rules

- Written scope first. Read-only by default. Writes only to objects you created, with a cleanup step.
- Two controlled accounts maximum. Never a real customer identifier, cookie, or token.
- One hypothesis, one small request budget. Five requests is a field test; a hundred is noise.
- Stop the vector on the first 429 or 5xx. Do not retry into a rate limiter.
- A negative result is a valid deliverable. Record it; do not promote it into a finding.

## 1. Hypothesis card

Before the first request, write:

```
id: H-01
check that should exist: server maps a parent-domain cookie to the caller's session
where it appears absent: console reads c2_*_lid without re-binding it
expected effect: attacker-chosen cookie changes the authenticated principal
missing link: server acceptance (not the cookie write)
request budget: 4 GETs
kill criterion: baseline and canary responses are byte-identical
```

If the "missing link" is not named, the test is fishing.

## 2. Signed-request replay windows

Common shape: `X-*-Date`, `X-*-Signature`, `X-*-Public-Key`, `X-*-Sign-Headers`; RSA PKCS#1 v1.5 with SHA-256 is typical.

Test matrix:

| Control | Purpose |
|---|---|
| Same request, same date | proves the signer works |
| Date shifted +1s / -1s | clock-skew boundary |
| Date shifted +1d / +30d / +365d | freshness window |
| Same signature without the session cookie | separates crypto validity from session binding |
| Same signature with the cookie | end-to-end acceptance |

Rules:

- A `401` without the cookie is a **session gap**, not a signature defect. Do not call it a broken signature.
- A `200` with a far-future date **and** the session cookie is a replay window. Impact requires a stolen signed request plus the session, so cap severity accordingly.
- Test both bounds. A far-future date accepted is an upper-bound gap; a far-past date rejected is only half a control. If the server also issues a time-var, that nonce is the remaining freshness gate; measure its lifetime separately.
- Do not replay state-changing requests. Prove the window on a read-only route.
- Do not attack keys or brute-force the HMAC/RSA material.

Field test S65 (2026-11-09): with a registered key and a fresh server-issued time-var, `X-C2-Date` at +30 days and +365 days both returned 200; -30 days returned 403 `invalid date string`. The time-var lifetime was not measured, so this is an upper-bound gap, not a proven 365-day replay window.

**Stateful time-vars.** A server-issued time-var can be reusable yet stateful. Test the exact same signed request twice, then a fresh signature at the same date, a higher date, a lower date, and after a new challenge. Two behaviors change the replay conclusion:

- **Monotonic floor:** a higher accepted date can make a lower-date replay fail. The token is not a static bearer; the next legitimate request can invalidate an older capture.
- **Rotation:** a new challenge can invalidate the previous token. Re-send the old exact request after requesting a new challenge.

Do not infer a year-long replay window from an `exp` field around 31.5 million. Measure exact replay and separate `exp` from rotation and the date floor. S66: exact +365d and current-date requests each returned 200 twice; after +365d was accepted, the lower current-date replay was 403; a new challenge invalidated the prior token; the same token signed a different path at the same date. The effective window is bounded by rotation and the monotonic floor, not by `exp` alone.

## 3. Parent-domain cookie shadowing

Look for `Set-Cookie` with `Domain=<parent>`, `SameSite=None`, and no `HttpOnly` on a value the console later reads (`*_lid`, `*_tid`, `*_hid`, `session`, `token`).

The write primitive is easy: any subdomain may set a cookie for its parent. That is **not** a finding by itself. The chain needs:

1. **Write**: a controlled subdomain (or user-content host) sets the cookie.
2. **Acceptance**: the parent service treats the client-supplied value as identity/state, rather than re-binding it to a server session.
3. **Victim**: a victim loads the subdomain, then the parent service.
4. **Impact**: session fixation, account confusion, or a secret read.

Test:

- Baseline: parent route with no cookie.
- Canary: same route with `Cookie: <name>=<unique-canary>`.
- Compare status, `Location`, body hash, `Set-Cookie`, and whether the canary appears anywhere.
- If all identical, record **write-only, acceptance not demonstrated**. Do not claim session fixation.
- A locale redirect or a login redirect is not acceptance. Follow it only if the scope allows and the redirect stays in scope.

## 4. postMessage and opener handoffs

Grep client bundles for `postMessage`, `event.origin`, `event.source`, `opener`, `targetOrigin`, `endsWith`, `indexOf`.

Questions:

- Is `event.origin` compared exactly, or with `endsWith(".example.com")`? A suffix check accepts every subdomain, including user-content hosts.
- Is `event.source` checked against the expected window?
- Is `targetOrigin` `*`, or an attacker-supplied value?
- Does the message carry a key, token, OTP, or account identifier?

A suffix allowlist is a **conditional** primitive: it needs a script-capable origin inside the suffix. If the only such host renders user content as text, the chain is still missing the script execution link.

Test with a local attacker page and a window you control. Never involve a real victim or a real key.

## 5. CORS wildcard plus credentials

`Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` looks alarming but is **browser-inert for credentialed reads** unless the server reflects the exact request origin.

The full chain requires:

1. Exact origin reflection (`ACAO` equals the attacker origin, not `*`).
2. `ACAC: true`.
3. A cookie that the browser will attach to the cross-origin request.
4. A response body containing a secret.

Test:

- Five origins: attacker, loopback, a sibling service, `null`, and the victim origin.
- `OPTIONS` preflight.
- Browser `fetch` with `credentials: 'omit'` and `'include'`; capture the console error.
- If `ACAO` is constant `*`, the credentialed read is blocked by the browser. Record the negative.

Never report the header pair alone as a vulnerability.

**Authenticated route allowlist.** A protected API can reflect any subdomain of the cookie parent (`evil.c2.example.com`) while rejecting unrelated suffixes. Test five origins: the legitimate origin, a real sibling, a synthetic device-style subdomain, an unrelated suffix, and `null`. Reflection with `ACAC:true` is a policy gap, not a read: test cookie-only and unregistered-key requests separately. Field test S65: any `*.c2` origin was reflected on the account route; cookie-only and a fresh unregistered 1024-bit key were both 403; a registered key plus a fresh time-var returned 200. No read without the key.

**Exact replay + CORS.** A CORS reflection becomes a read only when paired with a captured signed request. An exact replay can be sent from a reflected `*.c2` origin with the victim's cookie; the missing artifact is the captured headers, not the CORS header. Do not count the CORS reflection alone.

## 6. HTML sink gating

A reflected payload is not XSS until the client-side gate emits it. Typical gate names: `show_err_desc`, `useHtml`, `allowHtml`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML`.

Procedure:

1. Trace the sink: source field → sanitizer → `innerHTML`/`v-html`/`srcdoc`.
2. Identify the gate variable and its default.
3. Build a synthetic response with the gate **true** to prove the sink is reachable (local harness only).
4. Search captured responses for a client-reachable path where the gate is true and the source is attacker-controlled.
5. Check the sanitizer configuration: allowlist, rawtext tags (`textarea`, `xmp`, `noembed`, `noframes`), URL scheme, sandbox, CSP.

If the gate is false in every captured response, the finding is a **latent sink**, not XSS. Name the missing byte: "a client-reachable response with `show_err_desc:true` and an attacker-controlled `error_desc`".

## 7. OAuth / OIDC configuration observations

Discovery metadata is not a vulnerability. Distinguish:

- `alg: none` in `request_object_signing_alg_values_supported` → only matters if a registered client accepts unsigned request objects. Needs a real client.
- `require_request_uri_registration: true` → closes the SSRF-via-`request_uri` class. Good; do not chase.
- PKCE `plain` → weaker than `S256`; exploit needs code interception. Hardening note.
- `implicit` / `token` / `id_token` response types → token leakage surface; hardening unless a live client uses it.
- Redirect URI: exact match, no wildcard, no path traversal, no open redirect on the client.
- `state` binding and mix-up: test with two controlled clients, never a victim.

## 8. Evidence ladder for latent chains

| Level | What you have | Reportable as |
|---|---|---|
| L1 | Configuration observation, version match, client-side sink only | Not a finding; record as a hypothesis |
| L2 | One half of the chain (client sink, cookie write, signature math) | Low/Medium at most; name the missing link |
| L3 | Server acceptance with a controlled account and a canary | High, if impact is real |
| L4 | Full chain against a victim-equivalent controlled setup | Critical |

A chain is capped by its weakest proven link. "Client half" is not a finding; it is a lead.

## 9. Five-request field protocol

A compact, repeatable way to kill or promote a hypothesis without noise:

1. Baseline request, no canary.
2. Canary request with one controlled input.
3. Control request with a harmless valid value.
4. Variant request that isolates the suspected mechanism.
5. Confirmation request only if 2–4 differ.

Sequential, one second apart. Store the raw request and response, body size, SHA-256, `Location`, `Set-Cookie`, and a canary-reflection check. One command block, exit status preserved.

## 10. Field test record (sanitized)

**Date:** 2026-11-09. **Target class:** public C2 SaaS bounty surface. **Mode:** read-only, no auth, five GETs.

| Hypothesis | Result |
|---|---|
| `X-Forwarded-Host` / `X-Forwarded-Proto` reflected into tenant-routing metadata | **Negative** — 200, 115-byte body, identical SHA-256 with and without the canary |
| Parent-domain auth cookie accepted as console state | **Negative** — 302 locale redirect, identical body hash, no `Set-Cookie`, canary absent |

No finding. The test demonstrates two useful negatives: a cookie-write primitive is not server acceptance, and a wildcard CORS pair is not a credentialed read. Target details and raw captures are withheld from this public repository.

**S65 (2026-11-09).** Authenticated CORS and signature freshness. 30 explicit read-only GET/OPTIONS, no POST/PUT/DELETE. The protected account route reflected any `*.c2` origin with credentials; cookie-only and unregistered-key requests were 403; a registered key plus a fresh time-var was 200. Signed dates at +30d and +365d were accepted, while -30d was rejected. Conditional only; no data read without a registered signature, and no captured signed request. Raw captures are withheld.

**S66 (2026-11-09).** Stateful time-var replay. Exact current-date and +365d signed requests each returned 200 twice with the same body hash. A higher accepted date imposed a monotonic floor: the next lower-date replay was 403. A new challenge invalidated the prior token, and the same token signed a different path at the same date (200). The server `exp` field was around 31.5 million (roughly 365 days), but the effective window is bounded by rotation and the floor; post-expiry replay was not reachable at low rate. No captured-request/CORS PoC; no customer data.

## 11. Checklist

```
[ ] Hypothesis card written, missing link named
[ ] Scope and rate rules re-checked
[ ] No third-party identifier, cookie, token, or data
[ ] Baseline + canary + control captured
[ ] Body hashes and redirect targets compared
[ ] Canary reflection checked in headers and body
[ ] Negative result recorded, not promoted
[ ] Evidence stored with request count and timestamps
```
