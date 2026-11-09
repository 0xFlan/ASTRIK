# ARTEX Attack Surface (Static Map)

Code-anchored review of `artex-audit/baarai` at `fbe78395d5712aa775acd911a5e6c523c69e1419`. **Nothing here was runtime-proven on this host** (no Docker/PostgreSQL available during the audit). Treat every item as a static hypothesis with a test recipe, not a confirmed vulnerability. Severity depends on the deployment model, stated per item.

## 0. Threat models that decide severity

ARTEX has a **single admin account** (`ARTEX`) and no multi-user model. That changes what counts as a bug:

| Model | Description | What becomes serious |
|---|---|---|
| M1 Solo operator | One trusted person runs one instance against their own targets | Only bugs that cross a trust boundary the operator relies on (target content → agent, browser extension → host) |
| M2 Shared instance | A team or several engagements share one instance | Cross-task traffic leakage, token persistence, evidence poisoning |
| M3 Exposed instance | Port reachable beyond loopback / behind a proxy | Auth bypass, setup claim, CSRF, rate-limit trust |
| M4 Untrusted content | The agent reads attacker-controlled pages, files, tickets | Prompt injection → tool abuse, secret read, egress |

State the model in the report. "Critical" for M2 is often "by design" for M1.

## 1. Summary

| ID | Class | Static severity | Status | Anchor |
|---|---|---|---|---|
| A1 | JWT signing key co-located with the agent shell | High (M2/M4) | static | `docker-compose.yml:44-52`, `server/auth.go:27,162` |
| A2 | 7-day JWT, no revocation, weak claim checks | Medium | static | `server/auth.go:171,322` |
| A3 | Token in localStorage, non-HttpOnly cookie, query param | Medium | static | `web/src/lib/auth.ts:23`, `server/auth.go:183` |
| A4 | Workspace path confinement follows symlinks | High (M2) | static | `server/workspace.go:29,105,225` |
| A5 | Traffic store is global, not task-scoped | High (M2) | static | `traffic/traffic.go:134`, `server/manager.go:400` |
| A6 | CORS wildcard | Low | static; field-negative (analog) | `server/server.go:4045` |
| A7 | Destructive-action gating is deletable DB config | High (M4) | static | `guard/guard.go:1-6`, `db/asset_intercept.go:70` |
| A8 | Browser extension has debugger + all-URLs + plaintext capture | High (M1 host) | static | `extension/manifest.json`, `extension/background.js:36,140` |
| A9 | Build downloads unverified binaries and `@latest` packages | Medium | static | `Dockerfile:55,71,81,87,115` |
| A10 | Setup token printed to logs | Low | static | `server/auth.go` (`initSetupToken`) |
| A11 | Authenticated traffic ingest accepts arbitrary hosts (evidence poisoning) | Medium (M2) | static | `server/traffic_ingest.go:22` |
| A12 | Agent-facing MCP write installs a stdio launcher that executes outside the MCP approval gate | Medium (approval/persistence bypass; F-008 correction) | confirmed (F-007) | `server/platform_tools.go` (`toolCreateMCP`), `server/mcpdiscover.go` (`discoverEmptyMCPsOnStartup`) |
| A13 | Agent-created command/script/http custom tools bypass Bash's approval gate | High (M1/M2) | confirmed (F-008) | `server/customtool.go` (`buildCustomTool`), `server/platform_tools.go` (`toolCreateCustomTool`) |
| A14 | Auto-triggered reporter reads/overwrites another task's evidence; global delete is Allowed | High (authenticated-agent cross-task write; delete is operator-assisted) | confirmed (F-009) | `server/conversations.go` (`runTriggeredRun`), `agent/chat.go` (`RunInfo`), `server/orchestration.go` (`delegateToTask`, `toolUpdateFindingReport`), `server/platform_tools.go` (`toolDeleteAssetsByHost`) |

Sound areas are listed in §6. Do not report those as gaps.

## 2. Findings in detail

### A1 — JWT signing key is reachable from the agent's own shell

**Anchors.** `server/auth.go:27` (`jwtTTL = 7 * 24h`), `:162` (`signJWT`), `docker-compose.yml:44-52` (`./keys:/app/keys`), `Dockerfile` (runtime as root, Bash tool in the same container).

**Mechanism.** The key is deliberately outside the browsable data directory, but the agent's Bash tool runs in the same container and filesystem. Any command execution inside the container — the intended tool, a prompt-injected instruction, or a chained file read — can read `/app/keys/jwt.key`. A 32-character HS256 key is then enough to mint a token with `sub=ARTEX` and any expiry.

**Why it matters.** For M1 the agent is already root in that container, so a forged token adds little. It becomes serious when:
- untrusted target content can steer the agent (M4), giving a path from "page text" to "API admin";
- the instance is shared (M2), so one operator's agent can mint a token for the shared admin;
- the agent is sandboxed in a future version while the key stays in the same volume.

**Test recipe (lab).**
1. From an agent Bash step: `cat /app/keys/jwt.key` (or `wc -c` first; do not print a real key into chat).
2. Mint HS256 with claims `{"sub":"ARTEX","exp":<now+3600>}`.
3. Call `GET /api/tasks` with the forged token; expect 200. Compare with no token (401).
4. Record: key length, forged-token response, original-token response.

**Fix.** Keep the key out of every filesystem the agent can read (separate process/volume, KMS, or an auth service); bind the agent to a scoped token rather than the admin key.

### A2 — Long-lived token with no revocation and thin claim validation

**Anchors.** `server/auth.go:171` (`verifyJWT` checks HMAC + `exp` only; no `iss`, `aud`, `jti`, no deny-list), `:322` (`authChangePassword` re-hashes but does not invalidate existing tokens), `:27` (7-day TTL).

**Mechanism.** A stolen or forged token survives a password change and logout for up to seven days. `extractToken` accepts it from a header, a cookie, or a query string, so the theft surface is wider than one transport.

**Test recipe.** Log in, capture token T1. Change the password. Replay T1 against `GET /api/tasks`. Expect 200 (static prediction). Then mint a token with a wrong `iss`/`aud`; expect it is still accepted.

**Fix.** Add a key-id/version claim and rotate on password change; add `iss`/`aud`; shorten TTL with refresh; support a server-side revocation list.

### A3 — Token transport encourages theft and persistence

**Anchors.** `web/src/lib/auth.ts:23` (`document.cookie = ... SameSite=Lax`, no `HttpOnly`, no `Secure`), the same file storing the token in `localStorage`, `server/auth.go:183` (query-param fallback for SSE).

**Mechanism.** Any XSS in the UI can read the token from `localStorage` or the cookie and replay it for seven days. A token in a query string also lands in browser history, reverse-proxy logs, and Referer headers. The SSE endpoint needs the query form, so the exposure is structural, not a one-off bug.

**Scope note.** The observed cookie has no `Domain=` attribute, so the parent-domain shadowing technique in `references/web-auth-techniques.md` is not part of this path; the exploitable surface is XSS/localStorage or query-string leakage.

**Test recipe.** After login, inspect `document.cookie` and `localStorage`; confirm the cookie lacks `HttpOnly`; check whether `?token=` authenticates a normal API call (static prediction: yes, via `extractToken`). Capture both.

**Fix.** `HttpOnly; Secure; SameSite=Strict` cookie for the session; stop persisting the token in JS; for SSE use a short-lived one-time ticket instead of the session token.

### A4 — Workspace confinement is lexical; file operations follow symlinks

**Anchors.** `server/workspace.go:29` (`wsResolve` cleans and prefix-checks), `:105`/`:124` (`wsRead` → `os.ReadFile`), `:211`/`:225` (`wsDownload` → `http.ServeFile`), `:229` (upload).

**Mechanism.** `filepath.Clean` neutralizes `..` and absolute paths, but the resolved path is then passed to `os.Stat`, `os.ReadFile`, and `http.ServeFile`, all of which follow symlinks. A symlink created inside the workspace (by an agent Bash step, a restored task archive, or any future write primitive) points anywhere in the container. The file manager then reads it as if it were workspace content.

**Chain.** Write symlink → `GET /api/workspace/read?path=<link>` → `/app/keys/jwt.key` (A1) → forged token (A2) → admin API. This is the cleanest static chain in the codebase; it needs one write primitive inside the workspace.

**Test recipe (lab).**
1. Create a harmless marker outside the workspace: `/tmp/artex-symlink-canary`.
2. From the agent/workspace, `ln -s /tmp/artex-symlink-canary <workspace>/canary`.
3. `GET /api/workspace/read?path=canary`; expect the marker content.
4. Repeat with `/app/keys/jwt.key` only if the instance is throwaway; record length, not the key.
5. Negative control: `path=../../etc/passwd` should be 400.

**Fix.** Resolve with `filepath.EvalSymlinks` and re-check the prefix, or open with `O_NOFOLLOW`; reject any component that is a symlink; apply the same check to download.

### A5 — Traffic capture is instance-global, not task-scoped

**Anchors.** `server/manager.go:400` (`traffic.Open(filepath.Join(dir,"traffic"), ...)` — one store per manager), `traffic/traffic.go:134` (`TrafficSearchDescription`: host is required; no task filter), `server/traffic_ingest.go:22` (authenticated ingest).

**Mechanism.** Every task and every browser-extension capture writes to the same SQLite index and file tree. `traffic_search` filters by host/URL/body, not by task or owner. In a shared instance (M2), task B can search a host tested by task A and read A's captured `Authorization`/`Cookie` headers, then replay them. The same store also makes evidence poisoning possible: an authenticated ingest can plant a fabricated exchange that a later finding binds as proof (A11).

**Test recipe (lab, two tasks).**
1. In task A, ingest a synthetic exchange to `canary.test` with header `Authorization: Bearer CANARY-A`.
2. From task B, `traffic_search(host="canary.test")`, then `traffic_get` the hit.
3. Expect `CANARY-A` in the response. Record both task IDs and the exchange ID.

**Fix.** Add `task_id`/`owner` to exchanges and require it in every search/get/blob; scope ingest to a task token; partition the store per task.

### A6 — CORS wildcard

**Anchor.** `server/server.go:4045`: `Access-Control-Allow-Origin: *`, methods including DELETE, allowed headers `Content-Type` only.

**Mechanism.** `*` without `Access-Control-Allow-Credentials` means a cross-origin page cannot read authenticated responses using the cookie. Bearer tokens are not auto-sent, so exploitation needs a token the attacker already has. This is a hardening gap, not a standalone takeover. It becomes relevant if credentials support is ever added or if a browser quirk treats the cookie as same-site.

**Field correction (2026-11-09).** A live five-request field test of the same header pattern returned `ACAO:*` + `ACAC:true` for five origins, no origin reflection, byte-identical public bodies, and a browser block on `credentials:'include'`. The header pair alone is not a finding; the missing links are exact origin reflection and a secret-bearing body.

**Test recipe.** `curl -H 'Origin: https://evil.test' -i` on an authenticated endpoint; confirm `*` and the absence of `Allow-Credentials`. Try a cross-origin `fetch` with `credentials:'include'` in a browser; expect the response to be blocked.

**Fix.** Echo an allow-list of origins; add `Vary: Origin`; never combine `*` with credentials.

### A7 — The safety boundary is mutable data, not code

**Anchors.** `guard/guard.go:1-6`: "Destructive/exfil gating is no longer hard-coded here — it lives in the DB intercept rules (seeded as ordinary [built-in] rules, so users can disable or delete them)". `db/asset_intercept.go:70`: built-in rules are deletable too. `server/manager.go:872` wires the interceptor.

**Mechanism.** An agent with shell access can read `ARTEX_PG_DSN` from its own environment (`docker-compose.yml` injects it), reach PostgreSQL, and disable or delete the rules that gate destructive actions. The guard then approves what it was meant to block. Even without DB access, an operator UI action can disable a rule, and the audit trail records tool calls rather than rule changes.

**Static chain (M4).** Prompt injection → agent runs `env` → gets DSN → connects to Postgres (needs a client; the image has no `psql`, so this link is inferred until a client is available) → `UPDATE asset_intercept_rules SET enabled=false` → destructive tool call passes. Treat the DB-client step as the unproven link.

**Test recipe (lab).** From agent Bash, `env | grep ARTEX_PG_DSN` (redact the value). Confirm rule state via the API/DB. Disable one rule in the UI, then attempt a harmless action of that class against a dummy file; compare with the rule enabled. Do **not** run a genuinely destructive action.

**Fix.** Keep a non-deletable, code-level floor for destructive/exfil classes; make rule changes require a separate privileged confirmation; run the agent without DB credentials.

### A8 — Browser extension is a high-value target

**Anchors.** `extension/manifest.json` (`debugger`, `storage`, `tabs`, `<all_urls>`), `extension/background.js:36` (token in `chrome.storage.local`), `:140` (Bearer to `/api/traffic/ingest`).

**Mechanism.** The extension can read every tab's traffic, including cookies and Authorization headers, and ships it to the configured ARTEX URL. If that URL is `http://`, the traffic crosses the network in plaintext. The ARTEX token sits in extension storage, readable by any code that compromises the extension or the ARTEX origin. The captured data is stored unredacted in `data/traffic/`.

**Test recipe (lab).** Load the extension, point it at a local lab, log in to a dummy site, then inspect `data/traffic/` for `Cookie:`/`Authorization:` in plaintext and inspect `chrome.storage.local` for the token. Confirm the ingest URL scheme.

**Fix.** Require HTTPS, store the token in memory/session only, redact auth headers at capture time, narrow host permissions, and encrypt the traffic store at rest.

### A9 — Build-time supply chain is not integrity-checked

**Anchors.** `Dockerfile:55` (`curl … nodesource … | bash`), `:71`/`:81` (release downloads without checksum verification), `:87` (`git clone --depth 1` sqlmap default branch), `:115` (`@playwright/mcp@latest @playwright/cli@latest playwright@latest`).

**Mechanism.** A compromised upstream release, a moved tag, or a compromised npm package executes at build time as root in the build container. The runtime image then ships that code. `sqlmap` tracking a branch means the built artifact is not reproducible from the commit.

**Test recipe.** Build twice and diff the tool versions; `docker history` the layers; compare downloaded archive hashes against upstream published checksums; `git -C /opt/sqlmap rev-parse HEAD`.

**Fix.** Pin every tool to a version + SHA-256, vendor the archives, replace `@latest` with exact versions and a lockfile, pin sqlmap to a commit.

### A10 — Setup token in logs

**Anchor.** `server/auth.go` (`initSetupToken` prints `[auth] … Setup token for the /setup page: <token>`).

**Mechanism.** Anyone who can read container logs before the first password is set can claim the instance. `/api/logs` is behind auth, so this needs host/log access; it is a low-severity exposure, but it matters in shared logging stacks.

**Fix.** Print the token only to an interactive TTY, or require a local file that the operator reads; expire it after first use (already done) and after a short TTL.

### A11 — Ingest can poison the evidence store

**Anchor.** `server/traffic_ingest.go:22` (authenticated, accepts host/exchange data from the caller).

**Mechanism.** A finding binds `traffic_refs` as proof. If any authenticated principal (or a compromised agent) can inject an exchange for an arbitrary host, it can manufacture "evidence" that a later finding or report cites. This is an integrity issue, not confidentiality; it matters for M2 and for any workflow where the report is trusted downstream.

**Fix.** Scope ingest to a task/session, sign captures, and mark extension-ingested traffic as a distinct provenance class.

### A12 — Agent-facing MCP write installs a stdio launcher

**Anchor.** `server/platform_tools.go:379` (`toolCreateMCP`),
`server/platform_tools.go:400` (`toolUpdateMCP`), `server/mcpdiscover.go:77`
(`discoverEmptyMCPsOnStartup`), `server/orchestration.go:134` (`wrTool` returns
`permission.Allowed()`).

**Mechanism.** `create_mcp` is seeded into the `tools` table and bound to the
built-in Auto agent (`platformToolKeys`, `seedAutoDefaultBindings`). Every
platform write tool is unconditionally Allowed. The schema accepts
`transport=stdio` plus `command`/`args`, and `connectMCP` starts that command
with `mcp.NewStdioClient`. MCP *tool calls* are `AskUser`-gated, but the launch
command is not; startup discovery then launches every enabled MCP with an empty
cache regardless of visibility. An agent that can be steered to call
`create_mcp` therefore reaches host command execution without the approval
prompt, and the row retries on later starts because a one-shot command leaves
the cache empty.

**Fix.** Agent-facing MCP tools accept only `http`/`sse` with a URL;
`update_mcp` also refuses a missing id and an existing operator-managed stdio
row. Operator `POST /api/mcp` keeps stdio. Confirmed by F-007: the pre-fix probe
executed the command on discovery, the post-fix probe is rejected before
persistence, and the HTTP control still succeeds.

### A13 — Custom tools bypass the Bash approval gate

**Anchor.** `server/customtool.go:289` (`buildCustomTool` permissions),
`server/customtool.go:331` (`runCommandTool`), `server/platform_tools.go:213`
(`toolCreateCustomTool`), `server/orchestration.go:134` (`wrTool` returns
`permission.Allowed()`).

**Mechanism.** `create_custom_tool`/`update_custom_tool` are Allowed platform
writes bound to Auto and accept `kind=command` with an arbitrary
`exec.command`, `kind=script`, and `kind=http`. The built tool returned
`Allowed` for every kind, while the command executor called
`actool.NewBash().Call` directly. The harness checks only the outer custom
tool's decision, so Bash's `AskUser` and catastrophic-command floor never ran;
a custom tool bound to a worker executed without the approval Bash requires.
F-008's probe reproduced `allow` + command execution pre-fix and `ask` + no
execution post-fix, with the operator executor and Bash control intact.

**Fix.** `buildCustomTool` now renders the command from the call parameters and
delegates to `actool.NewBash().CheckPermissions`; script and http return
`AskUser`; unknown/empty kinds return `Denied`. Creation stays Allowed because
it is not execution. F-009 now gates `delete_assets_by_host` (see A14).

**F-007 correction.** Auto's ChatAgent base is `actool.DefaultTools()` (including
Bash), and its only turn entries are operator conversation/side questions, so
the MCP stdio launch was an approval/persistence bypass, not remote code
execution. The reachability answer is operator-assisted.

### A14 — Reporter cross-task read/write and Allowed global delete

**Anchor.** `server/conversations.go` (`runTriggeredRun` drops `item.taskID`),
`agent/chat.go:122` (`RunInfo{SessionID}` only), `server/orchestration.go`
(`delegateToTask` trusts `task_id`; `toolUpdateFindingReport` writes by global
node id), `server/platform_tools.go` (`toolDeleteAssetsByHost` uses `wrTool`).

**Mechanism.** The reporter is auto-triggered by `report_finding`; its trigger
carries the task id, but the run discarded it. The reporter is bound to
`get_task_node_detail`, worker-trace, finding-list, graph, and
`update_finding_report`; the query tools delegated to any supplied `task_id`, and
the report writer accepted any finding node. A task-A reporter read task B's
secret evidence and overwrote task B's report. Separately, Auto's
`delete_assets_by_host` returned `allow` and removed a task-B asset from the
shared library. F-009's probe observed all three pre-fix; after threading the
task id into `RunInfo` and enforcing it at `delegateToTask` and
`update_finding_report`, the cross-task read/write calls return
`outside this run's task scope`, and the delete returns `ask` with the asset
intact. Own-task read/write, Auto's platform-wide read, the direct operator
delete, and the operator report write all still succeed.

**Reachability.** The reporter chain is authenticated-agent and auto-triggered;
its input includes target-influenced finding evidence. The delete chain is
operator-assisted: Auto has no scheduler/trigger entry, and no live-model
prompt-injection test was run. Do not claim either as unauthenticated remote.

**Fix.** `runTriggeredRun` → `runConversationSync` → `Chat` now carries the task
id into `RunInfo`; `delegateToTask` rejects a different non-zero scope;
`update_finding_report` checks the finding's task via
`FindingTaskIDByNodeID`; `delete_assets_by_host` uses `wrAskTool` and returns
`AskUser`. Regression tests: `server/agent_scope_test.go`,
`agent/chat_runinfo_test.go`; evidence: `evidence/f009/`.

## 3. Chain: symlink → key → admin (the one to prove first)

| # | Stage | Action | Artifact | Confidence |
|---|---|---|---|---|
| 1 | Entry | create a symlink inside the workspace pointing at `/app/keys/jwt.key` | link path | observed (lab) |
| 2 | Entry | `GET /api/workspace/read?path=<link>` | key material | inferred from `os.ReadFile` |
| 3 | Identity | mint HS256 `sub=ARTEX`, `exp=+1h` | admin JWT | inferred from `signJWT` |
| 4 | Authority | call an admin-only endpoint with the JWT | 200 + data | inferred |
| 5 | Impact | change a setting / create a credential (scope permitting) | state change | inferred |

Steps 2–5 are code-supported but unproven. Prove step 2 with a harmless marker before touching a real key. If step 2 is blocked, the chain stops there — record the negative.

## 4. Chain: cross-task credential replay (M2)

| # | Stage | Action | Artifact |
|---|---|---|---|
| 1 | Entry | task A captures a login to `target.test` | exchange with `Authorization` |
| 2 | Entry | task B searches `host=target.test` | exchange metadata |
| 3 | Identity | `traffic_get` reads A's token | bearer token |
| 4 | Authority | replay the token against the target | authenticated session |
| 5 | Impact | read one authorized record | data |

The missing link in the current code is a task filter; the search description explicitly takes only a host. Prove with a canary token, not a real credential.

## 5. Porting the classes to other agent platforms

Ask these of any AI pentest/agent product:

1. Where does the agent's shell run relative to signing keys, DB credentials, and cloud tokens?
2. Is the session token scoped to a task/tenant, or instance-wide?
3. Are captured requests/browser traffic partitioned by task? Can one task search another's?
4. Are safety rules code or mutable data? Can the agent's own credentials change them?
5. Can target content (page, file, ticket, MCP description) reach a tool call?
6. Does a "read-only" tool have network egress? Can it POST?
7. Is model output rendered as HTML or interpolated into a shell command?
8. Are MCP servers and tool descriptions trusted? Who can add one?
9. Is the browser extension's token readable by the page? Does it capture auth headers in plaintext?
10. Are build inputs pinned and checksummed?
11. Does the API accept the session token in a query string, and is it logged?
12. Does a password change or logout revoke existing sessions?

## 6. Inspected-sound areas (do not report as gaps)

- `authInit` uses `InsertSettingIfAbsent` plus a constant-time setup-token comparison; the first-run race is handled (`server/auth.go:260`).
- Login is rate-limited per client IP with `Retry-After`; `ARTEX_TRUSTED_PROXIES` is empty by default, so `X-Forwarded-For` is ignored unless explicitly trusted (`server/auth.go:385`).
- New passwords are 12 runes minimum / 72 bytes maximum, bcrypt-hashed; login still accepts legacy shorter passwords, which is intentional.
- **F-005/F-006 correction:** `wsResolve` rejected `..` and absolute paths lexically but did not resolve symlinks. A link planted in the work dir made `/api/workspace/read` and `/download` return an outside canary (`200`), `/write` overwrite an outside file (`200`), and `/mkdir` create an outside directory (`200`). F-006 then proved the same pattern in the skill read/write/dirs/delete/meta routes, chat uploads (symlinked `uploads` dir), platform tools, and archive restore (symlinked `tasks/` parent); the skill delete route removed an outside file and the meta route rewrote an outside `SKILL.md`. Every file route now resolves through `os.Root` (directory descriptor, no check-then-use window) and escapes return `400 invalid path`; ZIP symlink entries are rejected and restore destinations with a symlinked parent are refused. Normal in-root I/O still returns `200`/`201`.
- Upload strips path components with `filepath.Base` and rejects `.`/`..`.
- `verifyJWT` rejects non-HMAC signing methods, so `alg:none` does not work.
- Task archive restore validates paths and uses a checksum (`server/task_archive_package.go`).
- **F-004 correction:** skill-upload byte caps do not bound the zstd decoder
  window. A 228-byte method-93 ZIP with a 128 MiB declared window returned
  `201` and retained ~135 MB; the fix adds `WithDecoderMaxWindow(8<<20)` in
  `server/skill_zip.go`. Logs and patch: `evidence/archive/`.
- Traffic search caps page size and blob reads (8 KiB), and the FTS index degrades gracefully without FTS5.

## 7. What is still unverified

- No runtime test of A1/A4/A5/A7 (no Docker/Postgres on the audit host).
- The PostgreSQL-backed routes were exercised under F-005's loopback probe: anonymous access (11 routes, all `401`), cross-task goal/constraint/scope/credential/rule operations, archive identifiers, and SQL metacharacters on the archive/findings/log filters. No authz or injection defect held. The file routes are now covered by F-006's loopback matrix (skill read/write/dirs/delete/meta, chat uploads, workspace, archive restore). F-007 covered MCP create/update and F-008 covered custom-tool create/update and execution permission; the remaining non-DB management modules (prompt templates, trigger configuration) remain route-by-route unverified. F-008 also established that Auto's ChatAgent base includes Bash, that its only turn entries are operator conversation/side questions, and that target content reaches its read tools only after an operator request; no live-model prompt-injection probe was run, so remote Auto reachability remains unproven. F-009 covered the auto-triggered reporter and the remaining destructive platform tool: the reporter's cross-task reads and `update_finding_report` writes are now scoped to the triggering task, and `delete_assets_by_host` is `AskUser`-gated. Traffic A5, prompt templates, and trigger configuration remain unverified; no live-model injection test was run.
- No review of `mcphttp/`, `llmrec/`, `enrich/`, or the browser extension's message handling beyond permissions.
- No CORS/CSRF browser test; the analysis is header-level only.
- `guard.New()` is documented as the pentest-task guard, but current non-test call sites all use `NewWithInterceptor`; confirm per version before claiming a rule-less mode.
