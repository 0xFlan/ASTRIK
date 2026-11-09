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
git diff --check
```

The validator checks required files, the README revision, source URLs, stale
references, and accidental private-key material. It is intentionally small and
can itself be improved by the same loop.
