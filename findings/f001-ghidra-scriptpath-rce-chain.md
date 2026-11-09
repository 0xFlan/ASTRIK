# F-001 — Validator-green repository can execute code through Ghidra `-scriptPath`

| Field | Value |
|---|---|
| Status | Fixed in revision 1.5 |
| Severity | Medium (requires repository write/PR merge, then the analyst runs the documented command) |
| Affected | `scripts/validate_skill.sh` and `references/reverse-engineering.md` at revision 1.4 and earlier |
| Impact | Arbitrary code execution as the analyst on the workstation that runs the RE pack |
| Evidence | `evidence/chain/` |

## Summary

Two weak controls composed into code execution:

1. **The validator was a presence check, not an integrity check.** It verified
   that required Markdown files existed, that the README contained the revision
   string, and that the five canonical source URLs appeared as substrings. It
   did not constrain `scripts/`, did not verify the pinned SHAs, and did not
   reject extra files. Adding `scripts/ghidra/ProofMarker.java` still produced
   `skill validation: OK` (exit 0).
2. **The RE pack pointed Ghidra at that directory.** The documented workflow was
   `analyzeHeadless ... -scriptPath <scripts> -postScript <Script>.java`, while
   the pack described headless analysis as analysis-only. Ghidra compiles and
   executes postScripts with the privileges of the user running Ghidra.

A contributor pull request that adds a script under `scripts/` therefore passes
the project's own green gate, and the next operator or agent that follows the
documented command executes it. No target interaction is required.

## Links and evidence

**L1 — validator accepts the added script.**

```
$ rsync -a --exclude .git <repo>/ /tmp/artex-mutant/
$ cp evidence/chain/repro/ProofMarker.java /tmp/artex-mutant/scripts/ghidra/
$ (cd /tmp/artex-mutant && bash scripts/validate_skill.sh)
skill validation: OK
exit 0
```

Log: `evidence/chain/logs/chain-validator-before.txt`.

**L2 — the pack treats the directory as trusted input.** Revision 1.4:

```
analyzeHeadless <project> <name> -import <bin> -overwrite \
  -scriptPath <scripts> -postScript Decompile.java <out>
```

No statement that the directory is executable code.

**L3 — execution with analyst privileges.** The same input binary, but
`-scriptPath` pointing at the mutant repository:

```
$ analyzeHeadless /tmp/ghidra-proj-chain Chain \
    -import evidence/re/target/vuln_target.stripped \
    -overwrite -scriptPath /tmp/artex-mutant/scripts/ghidra \
    -postScript ProofMarker.java -deleteProject
$ cat /tmp/artex-ghidra-scriptpath-proof.txt
ghidra_script_executed=true
user=flan
cwd=/private/tmp/artex-mutant
program=vuln_target.stripped
payload=benign-marker-only
```

The payload is deliberately benign: it writes a marker and exits. A hostile
script would inherit the same context and could read SSH keys, browser profiles,
environment tokens, or modify the evidence being captured.

## Why Medium, not Critical

The attacker needs write access to the repository (or a merged PR) and must wait
for an operator to run the RE pack. There is no remote trigger and no target
data is exposed by the chain itself. It is still a supply-chain path from a
merged contribution to workstation compromise, and the validator is the control
the repository advertises as its gate.

## Fix (revision 1.5)

- `scripts/MANIFEST.sha256` pins every file under `scripts/`. The validator
  verifies each hash and rejects added, removed, or modified scripts.
- Source registry checks now compare the exact URL set and exact 40-hex pin set,
  not substrings; each pin must also appear in the README.
- `references/reverse-engineering.md` states that Ghidra scripts execute with
  the analyst's privileges and limits runs to manifest-verified scripts.
- `scripts/test_validate_skill.sh` applies nine hostile mutations and asserts
  each is rejected; the mutant above is one of them.

## Verification

After the fix the same mutant fails validation:

```
$ (cd /tmp/artex-mutant && bash scripts/validate_skill.sh)
scripts/ contains files not in MANIFEST.sha256 (or is missing listed files)
exit 1
```

Log: `evidence/chain/logs/validator-after.txt`. Clean tree:
`skill validation: OK`; mutation suite: `validator mutation tests: OK`.

## Candidates examined and rejected

- **Private-key grep bypass.** Splitting the PEM header across two writes evades
  the `BEGIN ... PRIVATE KEY` pattern. It does not cross a trust boundary: the
  repository is public, so a committed key is already exposed and the grep is
  hygiene, not a gate. Not a chain.
- **URL substring alone.** A payload URL such as
  `<https://evil.example/?u=<https://github.com/usestrix/strix>>` previously
  satisfied the URL check. It is a real weakness, but by itself it only
  repoints a documentation link; impact needs the executor link above or a
  reviewer who follows the link. It is fixed by the exact-set check and is
  recorded here as a supporting L1, not a standalone finding.
