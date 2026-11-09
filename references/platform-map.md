# ARTEX Platform Map

How the pinned ARTEX source works as a hunt engine, and how to drive it without the web UI. Source of truth: `artex-audit/baarai` at `fbe78395d5712aa775acd911a5e6c523c69e1419`.

## 1. Runtime shape

| Component | Default | Notes |
|---|---|---|
| API + UI | `127.0.0.1:8787` | Go `net/http`, embedded Next.js static export |
| Recording proxy | `127.0.0.1:8788` | MITM proxy; every agent HTTP request is captured |
| Database | PostgreSQL 16 | Required; schema is idempotently applied on start |
| Data dir | `./data` (`/app/data`) | `tasks/<id>/`, `traffic/`, `archives/`, SQLite indexes |
| Key dir | `./keys` (`/app/keys`) | `jwt.key`; deliberately outside the browsable data dir |
| Skills | `./skills` (`/app/skills`) | Bind-mounted over the image's copy |

The API router is `server/server.go:678` (`Handler`), with auth wrapped at `server/server.go:967`. All `/api/*` routes require a JWT except `/api/auth/*` and `/api/health` (`server/auth.go:194`).

## 2. How the hunt engine thinks

ARTEX separates **what the goals are** (asset graph) from **how far testing has progressed** (exploration graph).

- `goals` decomposes the task goal and extracts constraints.
- `planner` is the only intent generator. It reads the situation, checks coverage, and dispatches intents with asset IDs. It keeps a **shared todolist across wake-ups**, so a multi-step chain is dispatched one prerequisite at a time.
- `worker` claims exactly one intent, executes real tools, and writes back facts/assets/findings. It can search other workers' step traces (`search_all_worker_traces`, `get_worker_trace`) before a fact exists.
- `prove_goal` is the only way a goal closes; `goal_met` is unbound by default because it bypasses per-goal proof.

This is a good manual discipline even without the platform:

1. Keep `plan.md` as a serial chain with explicit prerequisites.
2. Do one intent at a time; write the fact before designing the next link.
3. Before re-testing a direction, search your own prior evidence for it.
4. Close a goal only with a proved artifact, not with a hunch.

## 3. Driving it headlessly

Login (single fixed username `ARTEX`; password set on `/setup`):

```bash
BASE=http://127.0.0.1:8787
TOKEN=$(curl -sS -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ARTEX","password":"'"$ARTEX_PASS"'"}' | jq -r .token)
AUTH=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
```

Create a task (`createTaskReq`, `server/server.go:1574`):

```bash
curl -sS -X POST "$BASE/api/tasks" "${AUTH[@]}" -d @task.json | jq .
```

```json
{
  "name": "engagement-slug",
  "description": "Authorized scope: app.example.com only. Rules: 5 req/s, no scanners, no DoS.",
  "goal": "Prove impact on app.example.com. Report only chains with replayable evidence; a clean negative is valid.",
  "timeout_seconds": 3600,
  "seed_first_intent": true,
  "coverage_enabled": true,
  "credentials": [
    {"domain": "app.example.com", "username": "tester-a", "password": "..."},
    {"domain": "app.example.com", "username": "tester-b", "password": "..."}
  ]
}
```

Useful task fields: `llm_profile_ids` (ordered model chain), `source_task_ids` (read-only inherited context), `company_ids` (link company scope), `intercept_rules` (task-level allow/deny), `plan_heartbeat_seconds` (floor 600), `credentials` (declared test accounts; empty password means the agent generates and records one).

Scope and control:

```bash
curl -sS -X POST "$BASE/api/tasks/$ID/scope" "${AUTH[@]}" -d @scope.json   # read taskScopeAdd for the exact shape
curl -sS -X POST "$BASE/api/tasks/$ID/control" "${AUTH[@]}" -d '{"action":"pause"}'
curl -sS -X POST "$BASE/api/tasks/$ID/intents/rerun-blocked" "${AUTH[@]}"
```

Observe and export:

| Purpose | Endpoint |
|---|---|
| Task state | `GET /api/tasks/{id}` |
| Goals / constraints | `GET /api/tasks/{id}/goals`, `GET /api/tasks/{id}/constraints` |
| Findings | `GET /api/exploration/findings?task={id}` |
| Finding detail / lineage / retests | `GET /api/exploration/findings/{id}`, `.../lineage`, `.../retests` |
| Activity stream | `GET /api/exploration/activity/stream?token=...` (SSE) |
| Coverage | `GET /api/tasks/{id}/coverage`, `.../coverage-graph` |
| Traffic | `GET /api/traffic?host=...`, `GET /api/traffic/hosts` |
| Markdown report | `GET /api/exploration/findings/export` |
| Audit of approvals | `GET /api/audit?task={id}` |

`scripts/benchmark/run_bench.py` is a working example of creating tasks and polling them; read it before writing a custom driver.

## 4. Tool surface (reuse manually or bind to an agent)

From `agent/tools.go` and `agent/toolcatalog.go`:

| Group | Tools | Use |
|---|---|---|
| Situation | `graph_overview`, `node_detail`, `list_facts`, `list_findings`, `list_goals`, `list_assets`, `list_companies` | Read state before acting; never re-derive a fact that exists |
| Write-back | `record_fact`, `add_hint`, `add_intent`, `prove_goal`, `insert_assets`, `add_company_scope` | Persist observations with lineage |
| Findings | `report_finding` / `addFinding`, `bind_finding_traffic`, `list_findings` | Bind real traffic IDs; do not guess associations |
| Exchange | `search_all_worker_traces`, `list_worker_traces`, `get_worker_trace`, `get_worker_output` | Reuse another worker's observations before a formal fact exists |
| Control | `kill_work`, `steer_work` | Stop or redirect a stuck intent |
| Traffic | `traffic_search`, `traffic_get`, `traffic_blob` | Search by host + URL substring or body keyword; read one exchange at a time |
| Credentials | `save_task_credential`, `list_task_credentials` | Store declared/generated test accounts |
| General | Bash, Read, Write, Edit, MultiEdit, LS, Glob, Grep | The SDK's default toolset |

Two operator rules:

- A model's tool call is a hypothesis until the response is captured. Treat the agent's prose as a lead, not evidence.
- Prefer traffic-bound evidence (`traffic_get` output) over re-typed curl in the report; it is timestamped and replayable.

## 5. Scenario skills shipped in the repo

`baarai/skills/*/SKILL.md` (11):

| Skill | Use | Gate to respect |
|---|---|---|
| `api-recon` | Map APIs, routes, parameters, UI triggers | Recon only; do not turn it into exploitation |
| `api-security` | BOLA/BFLA, JWT/OAuth, GraphQL, mass assignment | Two principals for authz; impact budget for rate tests |
| `bbot-recon` | Recursive breadth-first recon | Passive-only when the program bans scanners |
| `codeaudit` | White-box forward tracing to sinks | First-party production code only |
| `patch-diff` | Recover an n-day from a vendor fix | Lab builds only; no unowned target |
| `php2shell` | LFI → RCE via session upload progress | Lab first; check the program's n-day policy |
| `playwright-cli` | Browser automation for SPA/2FA flows | Authorized accounts only |
| `rea` | Binary/APK/IPA/JS static analysis | Host paths must be under the shared data dir |
| `edr-bypass-re` | Endpoint telemetry evaluation | Requires an authorized Windows lab |
| `scopesentry` | Query a ScopeSentry deployment | API key handling; read-only by default |

## 6. Traffic and evidence plane

- The proxy captures **target HTTP only**, full bodies, no redaction (`traffic/traffic.go` package comment). Anything that passes through it — cookies, bearer tokens, PII — is stored in plaintext in `data/traffic/`.
- Bodies over 256 KiB spill to a content-addressed blob store; `traffic_blob` caps one read at 8 KiB to protect context.
- Search is an FTS5 trigram index, so arbitrary substrings (including CJK) work down to 3 characters; shorter queries fall back to metadata.
- Finding evidence uses `traffic_refs` with roles `baseline`, `proof`, `verification`, `supporting`. Bind only IDs that actually support the conclusion.
- The browser extension posts text exchanges to `POST /api/traffic/ingest` (authenticated) in batches of 50, 256 KiB per body. It is the way to capture a human-driven login with OTP/2FA.

## 7. Approval plane

- `guard/` and `intercept/` gate tool calls before execution; read-only tools pass, destructive ones require approval.
- Rules can be global or task-level (`/api/tasks/{id}/intercept-rules`).
- `GET /api/audit?task={id}` returns the guard's audit entries and attributions.
- When reviewing an agent platform, test whether a dangerous action can be expressed through a tool the gate classifies as safe (rename, copy, archive, export, template render).

## 8. Limits

- ARTEX does not certify findings. Its report is a draft; the operator owns severity and evidence.
- It is an offensive tool with a root container and network egress by default. Run it only in a lab or against authorized targets, with egress restricted where possible.
- The LLM is not a source of truth. Version banners, CVE matches, and "the page looks like admin" are L1 clues.
