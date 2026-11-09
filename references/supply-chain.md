# Supply Chain: OSV-Scanner

**Source:** <https://github.com/google/osv-scanner> — Apache-2.0.
OSV-Scanner maps lockfiles, manifests, container images, and SBOMs to the OSV
database. It is a dependency-risk primitive, not proof of exploitability.

## 1. Install and verify

Use a prebuilt release or build from source:

```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
osv-scanner --version
```

Prefer a pinned release. Record the version and the OSV database date. The
scanner queries OSV.dev and deps.dev; use `--offline` when the charter forbids
external metadata.

## 2. Scan

```bash
# Recursive source tree: package.json, go.mod, pom.xml, lockfiles, etc.
osv-scanner scan source -r .

# Container image (layer-aware OS and language packages)
osv-scanner scan image registry.example/app:tag

# Licences (deps.dev data)
osv-scanner --licenses .
osv-scanner --licenses="MIT,Apache-2.0" .

# Offline database
osv-scanner --offline --download-offline-databases .
```

Use `osv-scanner --help` for the installed version; v1 and v2 flags differ. Save
the raw JSON/SARIF output if the installed version supports it, plus the exact
command and the lockfile hash.

## 3. Triage

1. **Direct vs transitive:** record the dependency path and whether the vulnerable
   package is reachable from the application entry point.
2. **Version range:** confirm the installed version is affected, not just the
   package name.
3. **Call analysis / reachability:** use OSV call analysis or the Shannon/Strix
   source-aware workflow when available; a CVE in an unused function is not a
   confirmed exploit.
4. **Severity and exploitability:** keep the OSV/CVSS score separate from the
   demonstrated impact. A critical CVE with no reachable path may be lower.
5. **Remediation:** identify the fixed version, breaking changes, and a test
   path. `osv-scanner fix` is experimental and can cause package managers to run
   scripts; use a disposable branch or trusted copy.

## 4. Chaining

- **SCA → exploit:** use Shannon (source-aware) or Strix (black-box/live) to test
  whether the vulnerable path is actually reachable. Do not report a scanner hit
  as an exploit.
- **SCA → secret/CI:** combine with repository review and CI configuration; an
  exposed build token can be more valuable than a transitive CVE.
- **SCA → container:** scan the image, then verify the runtime package and
  entrypoint; base-image findings may not be reachable.

## 5. Evidence

Record:

- scanner version and database date;
- exact command and working directory;
- lockfile/manifest hashes;
- raw result file hash;
- affected package, installed version, fixed version, dependency path;
- reachability decision and the evidence for it;
- remediation and retest result.

A scanner report alone is an L1 clue. It becomes a finding only when the
vulnerable code path is reachable and the impact is demonstrated under the
operator charter.
