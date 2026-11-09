# Chain Playbook: From Minor Primitive to Critical Impact

Bounty triage and real engagements pay for impact, not for volume. This file is the composition layer: how to inventory small capabilities and turn them into one proven chain.

## 1. Primitive, not finding

A primitive is any reliable effect you can reproduce, even if it is worthless alone. Record it as a card:

```
id: P-014
class: path-read
precondition: authenticated, workspace write
effect: read one file outside the workspace root via symlink
artifact: contents of /app/keys/jwt.key (first 8 chars only in notes)
repeatability: deterministic
evidence: evidence/ev-014-<hash>.txt
chains-into: token forgery, admin API
```

Rules:

- One card per mechanism, not per URL. The same bug on five endpoints is one primitive.
- The **artifact** is what matters. "Can read files" is vague; "can read the JWT signing key" is a chain input.
- A primitive with no artifact is a clue, not a primitive.
- Negative results get cards too: "no path from X to Y" prevents re-walking dead ends.

## 2. Primitive catalog

| Class | Cheap probes | Primitive yielded | Usually chains into |
|---|---|---|---|
| Surface disclosure | `robots.txt`, `sitemap.xml`, `.git/HEAD`, source maps, `swagger.json`, `/actuator`, verbose errors, backup/zip files | Internal paths, versions, endpoints, sometimes secrets | Targeted auth tests, hidden admin routes |
| Identity oracle | Login/register/reset differentials: status, message, timing | Valid usernames/emails | Password spray within policy, reset poisoning, phishing pretext |
| Token weakness | JWT `alg:none`, weak HMAC, `kid` traversal, missing `aud`/`iss`, long TTL, no revocation, token in URL | Forged or replayable session | Admin API, persistence after password change |
| Session transport | Non-HttpOnly cookie, `localStorage`, token in query/Referer, token in logs | Session theft path | Account takeover via XSS or log access |
| Signed-request freshness | `X-*-Date`/signature headers, exact replay, shifted dates, with and without session | Replay race window or session gap | Captured-request replay, state change |
| Stateful time-var | exact signed replay twice; higher/lower date; new challenge | Rotation or monotonic floor | Short race window, not a year-long token |
| Cookie scope/shadowing | `Domain=parent`, `SameSite=None`, controlled subdomain | Parent-cookie write | Session fixation, account confusion |
| postMessage handoff | `postMessage`, `event.origin`, `endsWith` allowlist, opener | Cross-origin message | Key/token handoff |
| CORS wildcard pair | `ACAO:*` + `ACAC:true`, origin reflection, browser credentials | Usually none (browser gate) | Negative; do not report alone |
| HTML sink gate | Reflection plus a gate flag (`show_err_desc`, `useHtml`) | Conditional XSS | Stored XSS, admin action |
| CORS authenticated allowlist | Exact reflection of any cookie-parent subdomain, `ACAC:true` | Credentialed request surface | Cross-origin read if a cookie-only or key-confused route exists |
| Future-dated signature | `X-*-Date` at +30d/+365d with a fresh time-var | Upper-bound gap | Replay of a captured signed request + session |
| Access control | Sequential/UUID IDs, tenant header, bulk endpoints, method swap, `/v1` vs `/v2` | BOLA/BFLA read or write | Data export, victim email change, privilege escalation |
| Injection | SQLi, NoSQLi, template, command, deserialization, XXE, SSRF | Query/file/network capability | Credential harvest, metadata credentials, RCE |
| File handling | Traversal, symlink follow, upload type, archive extract, filename handling | Arbitrary read/write | Secret read, stored XSS, webshell |
| Shared state | Global search, cache, task/session store, queue, traffic recorder | Cross-user or cross-task data | Credential replay, impersonation |
| Agent/tool | Prompt injection, malicious tool description, MCP metadata, shell tool | Instruction execution inside the trust boundary | Secret read, egress, destructive action |
| Supply chain | Mutable image tags, unpinned installs, `curl \| bash`, CI tokens, update scripts | Build-time code execution | Root container, host mounts, downstream users |
| Infrastructure | Metadata endpoint, Docker socket, mounted secrets, permissive egress | Cloud creds or host access | Full environment control |

## 3. Chain grammar

Every chain is scored by four stages. Each stage must consume an artifact from the one before it.

```
ENTRY      observe or read something you should not
   ↓ artifact: data, path, identifier, error detail
IDENTITY   convert observation into a principal
   ↓ artifact: session, token, credential, signed request
AUTHORITY  convert principal into privilege
   ↓ artifact: admin action, cross-tenant read, role change
IMPACT     convert privilege into the objective (minimal proof)
```

Write the ledger:

| # | Stage | Action | Artifact produced | Evidence | Confidence |
|---|---|---|---|---|---|
| 1 | Entry | symlink read of `/app/keys/jwt.key` | signing key | ev-014 | observed |
| 2 | Identity | mint HS256 token, `sub=ARTEX`, `exp=+1h` | admin JWT | ev-015 | observed |
| 3 | Authority | call admin-only settings endpoint | config write accepted | ev-016 | observed |
| 4 | Impact | create a second admin credential | new principal | ev-017 | observed |

If any row is `inferred`, the chain is **partial**. State the missing link and cap severity at the weakest proven row.

## 4. Chain templates

### T1 — Secret → forge → admin
`read key/config/backup` → `recover signing key or DB creds` → `mint token or direct DB auth` → `admin action`.
Minimum proof: one forged token accepted by an endpoint that rejects the anonymous baseline. Do not create a real persistent admin unless the scope allows it.

### T2 — IDOR → account takeover
`register two accounts` → `enumerate object IDs from a list response` → `read victim object as A` → `write victim email as A` → `trigger reset` → `log in as victim`.
Minimum proof: one victim field read, one controlled write, one login. Use controlled accounts unless the charter explicitly covers another design.

### T3 — Upload → stored XSS → admin session
`find accepted types` → `upload SVG/HTML with a script` → `locate the admin view that renders it` → `exfiltrate cookie/localStorage` → `replay token`.
Minimum proof: script execution in the admin context (or a CSP report), not just a successful upload.

### T4 — Path → read → credentials
`traversal/symlink/zip-slip` → `read .env, config, key, backup` → `authenticate to DB/API/cloud` → `read one authorized record`.
Minimum proof: the credential works; do not dump the datastore.

### T5 — SSRF → metadata → cloud
`URL-taking parameter` → `reach 169.254.169.254 or an internal admin plane` → `obtain role credentials` → `call one cloud API read`.
Minimum proof: the metadata response and one successful API read. Default: do not touch production data; the charter may define a safe equivalent.

### T6 — First-run claim → admin
`detect uninitialized setup` → `race the legitimate owner or obtain the setup token from logs` → `claim admin` → `persist a test-only marker`.
Minimum proof: the claim succeeds and the legitimate setup then fails. This is inherently state-changing; the charter must authorize it first.

### T7 — Shared store → cross-task leak
`capture traffic in task/tenant A` → `search the same host from task/tenant B` → `extract Authorization/Cookie` → `replay as A`.
Minimum proof: B reads A's token and one authenticated request succeeds. This is the classic agent-platform isolation bug.

### T8 — Prompt injection → tool abuse
`place an instruction in content the agent reads` → `agent treats it as a task` → `tool call reads a secret or fetches an attacker URL` → `listener captures the artifact`.
Minimum proof: a controlled canary (unique filename or listener token) appears in the tool call. Never use a real credential as the canary.

### T9 — Supply chain → build RCE
`unverified download or @latest dependency` → `poison the upstream artifact` → `build executes it` → `root in the build/runtime container` → `reach host mounts`.
Minimum proof: a harmless marker file created at build time. This is a lab-only chain unless the program explicitly covers supply chain.

### T10 — MCP/tool poisoning
`malicious MCP server or tool description` → `model invokes the tool with context secrets` → `tool sends them to the attacker` → `replay the secret`.
Minimum proof: the secret canary arrives at the listener. The finding is the trust boundary, not the specific prompt.

### T11 — Signed-request replay window
`capture a signed read request` → `shift the signature date forward` → `replay with the victim's session cookie` → `read or act as the victim`.
Minimum proof: a far-future date is accepted on a read-only route with the cookie; without the cookie it is a session gap, not a signature defect. Cap severity unless a state-changing route is also proven.

### T12 — Parent-domain cookie shadow
`any subdomain sets the parent-domain cookie` → `victim visits the parent console` → `console trusts the client-supplied value` → `session fixation or account confusion`.
Minimum proof: baseline and canary responses differ, or a controlled account's state changes. Identical responses mean write-only; do not claim acceptance.

### T13 — postMessage suffix allowlist
`allowed host ends with the vendor suffix` → `attacker gets script on any such host` → `popup posts a key/token to an attacker-supplied origin` → `key or token theft`.
Minimum proof: a local attacker origin receives the value with the expected `targetOrigin`; a suffix check alone is not a finding.

### T14 — HTML sink gate
`reflected field` → `client-side gate evaluates true` → `sanitizer allows the payload` → `innerHTML`/`v-html` execution.
Minimum proof: script execution in a controlled browser, not a reflected string. If the gate is false in every captured response, the finding is latent.

### T15 — CORS wildcard (negative pattern)
`ACAO:*` + `ACAC:true` → `browser credentialed fetch` → blocked unless the exact origin is reflected and a secret is in the body.
Minimum proof: for a negative, five origins, OPTIONS, and a `credentials:'include'` browser fetch. Record the block; do not report the header pair alone.

### T16 — Parent-cookie origin reflection
`any subdomain can write the parent cookie` → `authenticated API reflects any cookie-parent subdomain origin with ACAC:true` → `protected route accepts cookie-only or a client-registered key` → `cross-origin account read`.
Minimum proof: a valid preflight is only the policy gap. Prove the protected route accepts the parent cookie without a registered signature, or accepts a key the attacker can register. A self-generated key rejected with `invalid Signature match` means key binding; record the negative.

### T17 — Stateful signed-request replay
`capture a signed request (signature + time-var) and the session cookie` → `replay the exact request while the token is active` → `read the response from an allowed origin`.
Minimum proof: exact replay returns 200 twice; then test a fresh signature at the same date, a higher date, a lower date, and after a new challenge. A higher accepted date can impose a monotonic floor that rejects lower-date replays; a new challenge can rotate the token. Do not infer a year-long replay from `exp`; report the observed pre-expiry window and the missing capture vector. Without a captured signed request this is a conditional hardening finding.

### T18 — Exact replay + authenticated CORS
`capture signed request headers` → `victim visits a script-capable *.c2 origin` → `send exact headers with the session cookie` → `reflected ACAO/ACAC exposes the response`.
Minimum proof: exact replay is 200 with the controlled session, and the S65-style preflight reflects the origin. The missing link is capture of the signed headers; S49.1 parent-cookie write is not required for this chain. Cap at Medium until a real capture vector is shown.

### T19 — Archive decoder memory amplification
`authenticated upload/extract` → `compressed frame declares a large decoder window` → `decoder allocates the window before the output cap` → `a tiny request consumes hundreds of MB`.
Minimum proof: record the archive's compressed size, the frame's declared window, and the measured heap after a forced GC. Then add a decoder option that caps the window and show the same archive returns a bounded error while a normal archive still succeeds. F-004 used a 228-byte ZIP with a 128 MiB window: 201 and ~135 MB before, 400 and ~26 KB after `WithDecoderMaxWindow(8<<20)`.

## 5. Amplifiers

Multiply severity when a primitive reaches any of these. Test for them explicitly:

| Amplifier | Why it matters |
|---|---|
| Multi-tenancy | One bug becomes every tenant's data |
| Admin impersonation | Read becomes control |
| Persistence | Password change / logout does not evict the attacker |
| Secret access | Enables new chains beyond the current app |
| Root / container escape | Host and sibling workloads |
| Shared cache/store/queue | Cross-user contamination without direct access |
| CI/build access | Compromises every downstream build |
| SSO / email | Pivot to other applications |

A useful qualitative score: `severity = base × reach × persistence × principal`. A medium read that reaches admin credentials and survives logout is critical in practice.

## 6. "One link short" worksheet

When blocked, do not abandon the chain. Fill this in:

```
Objective:
Proven capability so far:
Missing capability: read / write / identity / network / execution
Candidate primitives that yield it:
Cheapest test (one request or one command):
Kill criterion (what result closes this direction):
```

Then test the cheapest candidate. A chain usually dies because the operator stopped at the first "no", not because the target is clean.

## 7. Verification rules for chains

- Reproduce each link independently; a chain is only as strong as its weakest replay.
- Change one variable at a time: new session for identity, new path for access, new account for authorization.
- For authz, always use two principals. "Admin can read admin data" is not a finding.
- Preserve the *order* of requests; some links are state-dependent. Record nonces and timestamps.
- If a later link fails, keep the earlier links and report the partial chain. Do not discard proven impact.

## 8. Anti-patterns

- **Bug salad**: unrelated lows stapled together with "an attacker could". No shared artifact, no chain.
- **Version-match link**: "this version has CVE-X, therefore RCE". That is L1, not a link.
- **Output cap is not a memory cap**: a decompressor can allocate a declared window or dictionary before producing bytes. Measure both the decoded output and the decoder's window/allocation; cap the option, not only `io.LimitReader`.
- **Destructive proof**: dropping a table to show SQLi. Read one row.
- **Out-of-scope pivot**: using a scoped bug to reach an unscoped host. Stop; report the pivot surface.
- **PII hoard**: exporting 1,000 records to prove an IDOR. One is enough.
- **Victim-dependent chain**: requiring the victim to click a link that the program forbids testing.
- **Model-said-so**: accepting an agent's claim that a tool call succeeded without the raw output.
- **Auth as a footnote**: treating "the upload route is behind requireAuth" as a
  reason to skip the link. The wrapper is a link; test its exemptions, path
  normalization, token extraction, and every route registration. F-003 found no
  bypass, but only after 20 anonymous requests and a valid-token control.

## 9. Auth-boundary link template

When a chain's missing link is "get past authentication":

1. List the sink's route registrations and the wrapper around each one.
2. List every exemption and every auth entry point (login, init, status, health).
3. Send the sink's real body to each exemption and path alias; classify the
   response as sink-reached (`400`/`409`/`500`/panic) or rejected (`401`/`403`/
   `404`/`405`/redirect).
4. Follow redirects with a default client; a 307 is not a bypass if it lands on
   the protected route.
5. Prove a valid credential reaches the same sink. No positive control, no
   negative finding.

Report the chain as disproven only with the request matrix, statuses, headers,
and the code line where the wrapper encloses the sink.
