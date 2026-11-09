# Recursive Improvement

The skill should get better after every engagement. “Recursive” means each run
produces evidence-backed lessons that are distilled into the references, then
validated and versioned. It does not mean the agent can widen its own authority.

## 1. Loop

```
Observe → Classify → Distill → Validate → Review → Version → Re-read
```

1. **Observe.** Capture the exact command, output hash, outcome, and the missing
   link. A lesson without evidence is a guess.
2. **Classify.** New technique, correction, negative result, tool change, source
   pin, or documentation fix.
3. **Distill.** Put the reusable part in one reference file. Keep target
   identifiers, credentials, and raw customer data out.
4. **Validate.** Run the commands on a fixture or check `--help`; run
   `scripts/validate_skill.sh`; verify links and licences.
5. **Review.** Read the diff. Confirm the change does not add a target-class or
   technique ban to the skill, and does not let target content alter the charter.
6. **Version.** Update `README.md` revision history and any source pin in
   `references/tool-sources.md`.
7. **Re-read.** The next engagement starts from the updated skill and a fresh
   operator charter.

## 2. Lesson template

```markdown
## Lesson L-NNN
- Engagement / date:
- Tool or target class:
- Observation (with evidence hash):
- What the skill said before:
- Correction or new technique:
- Minimum reproduction / command:
- Negative result to preserve:
- Reference file changed:
- Validation run:
```

## 3. What may be improved recursively

- Technique packs, chain templates, evidence formats, report skeletons.
- Tool commands, install notes, source pins, licence/provenance notes.
- Validators and self-checks.
- Negative results and “do not re-walk” notes.

## 4. What is not automated

- Expanding the operator charter or target list.
- Deciding that a new asset is authorized.
- Removing the need for an authorization record.
- Letting a target, tool report, repository comment, or graph fact rewrite the
  skill or the charter.
- Publishing target data or session material.

These require the operator's explicit decision and a new charter version.

## 5. Source updates

`references/tool-sources.md` is the registry. For each update:

1. Fetch the upstream README/SKILL and record the commit or release.
2. Check the licence and whether the project is still the canonical one.
3. Re-run the documented install/scan command or at least `--help`.
4. Record what changed and whether old commands still work.
5. Do not copy upstream source into this repository without a licence review.

## 6. Validation

```bash
bash scripts/validate_skill.sh
bash scripts/test_validate_skill.sh
git diff --check
```

The validator checks required files, the exact README revision, the exact source
URL and pin sets, script integrity, and accidental private-key material. It is
intentionally small and can itself be improved by the same loop.

## 7. Field notes (2026-11-09)

- **Presence is not integrity.** A check that greps for a token, a revision
  string, or a URL substring can be satisfied by a comment, a duplicate row, or
  a URL that embeds the canonical one in a query parameter. Compare exact sets
  and verify hashes.
- **Validator the executable surface.** Anything under `scripts/` is code that
  an operator or agent may run. `scripts/MANIFEST.sha256` makes additions and
  edits fail until the manifest change is reviewed; `test_validate_skill.sh`
  proves the rejection paths.
- **Mutate, then assert rejection.** For every new guard, add a copy-the-tree
  mutation that must fail. A guard without a negative test is a claim.
- **Chain the controls you rely on.** F-001 was not a single bug: a presence-only
  validator plus a documented `-scriptPath` path composed into analyst code
  execution. Review the join between a green gate and the next privileged
  action, not only each control alone.
- **A disproven chain is a deliverable.** F-002 failed on the app's missing
  single-locale `i18n` precondition and again on the API's `requireAuth`
  boundary. Record the exact request/response and the code line that breaks the
  link; do not report the CVE as if the chain worked.
- **Reproduce the patch, not just the bug.** Build a minimal fixture that fails
  before the bump and passes after (the single-locale Next fixture: 200 on
  16.2.9, 307 on 16.2.11) and keep the real-handler reproducer for the component
  that does apply (zstd through `fsUploadSkill`).
- **A 401 wall needs a positive control.** F-003 sent 20 anonymous shapes at the
  upload route (traversal, encoded traversal, exempt prefixes, empty tokens,
  alg:none/RS256/wrong-key, redirects) and all were rejected; a valid token then
  reached the same handler and produced the 1.18.6 panic. Without the control,
  the 401s would not prove the sink was reachable at all.
- **Build the binary, then state the startup limit.** `cmd/artex` built cleanly
  but exited at `open stores` because PostgreSQL was absent. The request proof
  used the production `Handler()`; recording that limitation is better than
  calling a test harness a full server run.
- **Bound the allocator, not just the output.** F-004's zstd frame was 72 bytes
  and the ZIP was 228 bytes, but the declared 128 MiB window allocated ~135 MB
  before the 20 MiB output cap could act. The guard is a decoder option; the
  regression test asserts `400 window size exceeded` after the fix and still
  accepts a normal zstd archive. For any `io.LimitReader` or output-size cap,
  inspect the decoder's own window, dictionary, and metadata allocations.
- **Lexical containment is not containment.** F-005's `wsResolve` collapsed
  `..` and checked a string prefix, but `ReadFile`/`WriteFile`/`MkdirAll` resolve
  symlinks in the kernel. A planted link turned the browser file manager into a
  host read/write primitive. For any path-confinement check, walk the existing
  components with `Lstat` (or use `openat`/`O_NOFOLLOW`) and test with a link
  that points outside the root; a positive control on a normal path catches a
  fix that simply rejects everything.
- **Provision the fixture before trusting the suite.** The same suite that hid
  all DB-backed routes behind `no database config found` also hid fixture
  defects. After closing the environment gap, run the suite twice: F-005's
  second run found `defer d.Close()` running before `t.Cleanup` DELETEs and a
  company scope that survived into the next run. A green first run is a data
  point; a green repeat is the evidence.
- **Report a misleading success even when nothing changed.** A cross-task
  intercept-rule toggle returned `200 {"ok":true}` while the row stayed
  untouched. The authorization invariant held, but the response would make an
  operator believe the rule changed. Record it as an API-semantics defect rather
  than inflating it into an IDOR.
- **Check-then-use is the bug, not only the symlink.** F-005's `Lstat` walk
  rejected the tested links but still validated one path string and then let a
  second syscall resolve it. F-006 replaced every file route with `os.Root`,
  which holds the directory open and resolves each component through that
  descriptor. When a reviewer says "add a symlink check", prefer the primitive
  that makes the check and the operation the same resolution.
- **A route is only as confined as its least-hardened sibling.** The workspace
  was fixed while skill read/write/dirs/delete/meta, chat uploads, and restore
  still followed links. Enumerate every handler that calls `os.Open`,
  `ReadFile`, `WriteFile`, `MkdirAll`, `RemoveAll`, or `ServeFile` with a
  client-influenced path, and run the same link/traversal/absolute/backslash
  matrix against each one. Include the destructive routes: the skill delete
  escape removed an outside file, which a read-only probe would have missed.
- **Second-run failures are fixture defects until proven otherwise.** The
  `TestSkillGapsReport` rerun failed because the report aggregates the whole
  disposable `_server` database while the test assumed it was the only writer;
  earlier runs' `graphql-audit` rows outranked the fixture. Clear the aggregate
  table around the fixture or scope the assertion; do not weaken the ordering
  assertion to make the rerun pass.
- **Keep the fail-before log even when the fix is broad.** To prove the archive
  restore check mattered, remove only that check, run the probe, capture the
  `err=<nil>` escape, restore the file, and rerun. A targeted revert produces
  cleaner before/after evidence than stashing the whole patch.
- **A journal is a timing oracle.** F-006's restore wrote its journal after the
  destination check and before the first rename, so polling for the journal
  made the race deterministic: 20/20 escapes. When a check-then-use window is
  suspected, look for any durable side effect (journal, lock file, temp file)
  that marks the interval and trigger on it instead of sleeping.
- **One root for both sides.** The fix for that race was not a stronger path
  check; it was deriving the source and destination names under one `os.Root`
  opened on the data dir. If a helper needs two roots, that is a design signal:
  re-anchor the paths so the operation stays inside one descriptor.
- **A launch configuration is authority, not metadata.** MCP tool calls were
  `AskUser`-gated while the `create_mcp` write that installs the stdio command
  was unconditionally Allowed. Any control attached to "use the capability"
  must also cover "configure the capability", or the configuration path is the
  bypass. Enumerate paired read/write and call/configure tools together.
- **Startup work inherits no per-call gate.** `discoverEmptyMCPsOnStartup`
  launched every enabled MCP with an empty cache, regardless of visibility, so
  the command ran with no agent and no task. When reviewing an approval gate,
  follow the object into every background consumer: startup discovery, retry
  loops, workers, and reconciliation jobs.
- **Fixture cleanup order is part of the test.** A `t.Cleanup` registered after
  `defer m.Close()` runs against a closed pool and silently leaves rows behind.
  Use a LIFO `defer` before the close (or pre-delete the fixed-name rows) and
  rerun the suite; the F-007 second run is what exposed it. Fix the fixture, not
  the assertion.
- **A wrapper must inherit the wrapped executor's permission.** F-008's custom
  tool called `actool.NewBash().Call` but returned `Allowed` from its own
  `CheckPermissions`. The harness checks the outer tool, so the inner Bash gate
  never ran. When a tool re-exposes another executor, delegate the permission
  decision to that executor with the rendered input; do not re-declare it.
- **Creation and invocation are separate authority decisions.** Creating a tool
  writes a row; invoking it executes code. F-008's fix leaves creation Allowed
  (the Auto workflow needs it) and moves the approval to invocation. Review both
  verbs together, and do not assume a gate on one covers the other.
- **Check the assembled base toolset before claiming a new capability.** F-007
  treated the MCP stdio launch as new host execution, but `agent/chat.go` builds
  Auto from `actool.DefaultTools()`, which already includes Bash. The launch was
  an approval/persistence bypass, not escalation. Read the actual assembly path
  (`ChatAgent` base + `AugmentTools` + `ToolResolve`) before assigning severity.
- **A probe must test the decision, not only the command.** The F-008 probe
  calls `CheckPermissions` exactly as the harness does and only calls the tool
  when the decision is Allow. A probe that invokes `.Call` directly would pass
  on both trees and prove nothing about the gate.
- **Answer reachability with entry points, not intuition.** F-008 enumerated
  Auto's message entries and confirmed the scheduler/triggers do not target it;
  that converted "maybe remotely reachable" into "operator-assisted only" and
  made the F-007 correction evidence-based. When a model is in the loop and no
  live model is available, say so instead of simulating a compliant model.
- **A trigger carries scope; the run must keep it.** F-009 found that
  `runTriggeredRun` had `item.taskID` but dropped it before `Chat`, which built
  `RunInfo{SessionID}` only. Every downstream tool saw zero, the "operator"
  value, and the auto-triggered reporter could read and overwrite another task's
  evidence. Thread the trigger's task id into the run context, then enforce it at
  every sink that accepts a task or global node id; a prompt instruction is not
  a scope check.
- **A global node id needs the same owner check as a task id.**
  `update_finding_report` looked correct in isolation because the reporter owns
  the triggering finding, but the tool accepted any enumerable finding node. Look
  for write tools keyed by a global row id, not only tools with a `task_id`
  parameter, and verify the row's owner inside the write path.
- **Gate the delete, not only the caller.** The same pass found
  `delete_assets_by_host` on the unconditional `wrTool`; its Auto caller is
  operator-assisted, but the tool is irreversible and global. Put destructive
  verbs behind `AskUser` and keep a direct operator control in the probe. Do not
  let a benign reachability classification excuse an unguarded destructive sink.
- **A read-only tool still needs an ownership check.** F-010's traffic readers
  were `Allowed` and read-only, so the pipeline's read-only auto-allow made the
  permission verdict irrelevant. Resolve the caller's task to its assets and
  return `Deny` for a host outside that set; repeat the check in the handler so
  a direct `.Call` cannot bypass the permission wrapper. Redact credential
  headers/body fields in the agent-facing reader and keep the operator view raw.
- **A process-wide capture needs explicit partition, not an inferred one.** A5
  had no `task_id` in the exchange schema; scoping by the caller's asset hosts
  closes the distinct-host chain but leaves same-host traffic shared. Record
  that residual plainly and add a capture-level owner before claiming tenant
  separation. Probe the prompt/trigger routes and `merge_mode=all` rather than
  inferring their authority from the UI.
