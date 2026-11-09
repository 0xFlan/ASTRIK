#!/usr/bin/env bash
# Mutation tests for validate_skill.sh. Each case copies the repo to a temp
# directory, applies one hostile edit, and asserts the validator rejects it.
# The clean tree must pass.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/artex-validator.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

bad=0
fresh() {
  rm -rf "$tmp/repo"
  mkdir -p "$tmp/repo"
  rsync -a --exclude .git "$root/" "$tmp/repo/"
}
runv() {
  bash "$tmp/repo/scripts/validate_skill.sh" >"$tmp/out.log" 2>&1
}

fresh
if runv; then
  echo "PASS clean tree accepted"
else
  echo "FAIL clean tree rejected"
  cat "$tmp/out.log"
  bad=1
fi

expect_reject() {
  name="$1"
  mutator="$2"
  fresh
  "$mutator"
  if runv; then
    echo "FAIL $name accepted"
    bad=1
  else
    echo "PASS $name rejected"
  fi
}

mut_add_script() {
  cp "$root/evidence/chain/repro/ProofMarker.java" "$tmp/repo/scripts/ghidra/ProofMarker.java"
}
mut_tamper_script() {
  printf '\n// tampered after manifest generation\n' >>"$tmp/repo/scripts/ghidra/ReportArtifacts.java"
}
mut_tamper_manifest() {
  python3 - "$tmp/repo/scripts/MANIFEST.sha256" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
lines[0] = ("0" if lines[0][0] != "0" else "1") + lines[0][1:]
open(p, "w").write("\n".join(lines) + "\n")
PY
}
mut_extra_url() {
  printf '\n[extra](<https://evil.example/payload>)\n' >>"$tmp/repo/references/tool-sources.md"
}
mut_swap_url() {
  python3 - "$tmp/repo/references/tool-sources.md" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("<https://github.com/usestrix/strix>", "<https://github.com/usestrix/strix-fork>")
open(p, "w").write(s)
PY
}
mut_repin() {
  python3 - "$tmp/repo/references/tool-sources.md" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r"`[0-9a-f]{40}`", "`" + "0" * 40 + "`", s, count=1)
open(p, "w").write(s)
PY
}
mut_stale_revision() {
  python3 - "$tmp/repo/README.md" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("| Revision | 1.7 |", "| Revision | 1.6 |", 1)
open(p, "w").write(s)
PY
}
mut_missing_required() {
  rm "$tmp/repo/references/supply-chain.md"
}
mut_private_key() {
  { printf 'BEGIN RSA'; printf ' PRIVATE KEY-----\n'; } >>"$tmp/repo/references/supply-chain.md"
}

expect_reject "added scripts/ghidra/ProofMarker.java" mut_add_script
expect_reject "modified ReportArtifacts.java" mut_tamper_script
expect_reject "tampered MANIFEST.sha256" mut_tamper_manifest
expect_reject "extra source URL" mut_extra_url
expect_reject "repointed source URL" mut_swap_url
expect_reject "altered source pin" mut_repin
expect_reject "stale README revision" mut_stale_revision
expect_reject "missing required reference" mut_missing_required
expect_reject "private-key material" mut_private_key

if [ "$bad" -ne 0 ]; then
  echo "validator mutation tests: FAILED" >&2
  exit 1
fi
echo "validator mutation tests: OK"
