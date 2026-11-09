#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  "SKILL.md"
  "README.md"
  "NOTICE"
  "references/operator-charter.md"
  "references/agentic-pentest.md"
  "references/reverse-engineering.md"
  "references/supply-chain.md"
  "references/recursive-improvement.md"
  "references/tool-sources.md"
  "scripts/validate_skill.sh"
  "scripts/test_validate_skill.sh"
  "scripts/ghidra/ReportArtifacts.java"
  "findings/f001-ghidra-scriptpath-rce-chain.md"
  "findings/f002-chain-next-bypass-to-zstd-panic.md"
  "findings/f003-jwt-route-bypass-does-not-hold.md"
  "findings/f004-zstd-window-memory-amplification.md"
  "findings/f005-workspace-symlink-escape.md"
  "evidence/db/README.md"
  "evidence/db/provision-test-postgres.sh"
  "evidence/db/repro/zz_evidence_dbfixture_test.go"
  "evidence/db/patches/workspace-symlink.patch"
  "evidence/db/patches/test-idempotency.patch"
  "evidence/db/logs/f005-probe-before.log"
  "evidence/db/logs/f005-probe-after.log"
  "evidence/db/logs/go-test-fresh.log"
  "evidence/db/logs/go-test-rerun.log"
  "findings/f006-file-route-confinement.md"
  "evidence/f006/README.md"
  "evidence/f006/repro/zz_evidence_confinement_test.go"
  "evidence/f006/patches/file-route-confinement.patch"
  "evidence/f006/patches/test-skill-gaps-isolation.patch"
  "evidence/f006/logs/f006-before.log"
  "evidence/f006/logs/f006-after.log"
  "evidence/f006/logs/f006-archive-before.log"
  "evidence/f006/logs/f006-archive-after.log"
  "evidence/f006/logs/go-test-run1.log"
  "evidence/f006/logs/go-test-run2.log"
  "findings/f007-archive-restore-and-mcp-launch-chain.md"
  "evidence/f007/README.md"
  "evidence/f007/repro/zz_evidence_f007_test.go"
  "evidence/f007/patches/archive-restore-single-root.patch"
  "evidence/f007/patches/agent-mcp-stdio-boundary.patch"
  "evidence/f007/patches/tests.patch"
  "evidence/f007/logs/f007-before.log"
  "evidence/f007/logs/f007-after.log"
  "evidence/f007/logs/go-test-run1.log"
  "evidence/f007/logs/go-test-run2.log"
  "findings/f008-custom-tool-approval-bypass.md"
  "evidence/f008/README.md"
  "evidence/f008/repro/zz_evidence_f008_test.go"
  "evidence/f008/patches/custom-tool-permission-parity.patch"
  "evidence/f008/patches/tests.patch"
  "evidence/f008/logs/f008-before.log"
  "evidence/f008/logs/f008-after.log"
  "evidence/f008/logs/go-test-run1.log"
  "evidence/f008/logs/go-test-run2.log"
  "findings/f009-reporter-cross-task-scope.md"
  "evidence/f009/README.md"
  "evidence/f009/repro/zz_evidence_f009_test.go"
  "evidence/f009/patches/task-scope-and-delete-approval.patch"
  "evidence/f009/patches/tests.patch"
  "evidence/f009/logs/f009-before.log"
  "evidence/f009/logs/f009-after.log"
  "evidence/f009/logs/go-test-run1.log"
  "evidence/f009/logs/go-test-run2.log"
  "findings/f010-traffic-cross-task-credential-replay.md"
  "evidence/f010/README.md"
  "evidence/f010/repro/zz_evidence_f010_test.go"
  "evidence/f010/repro/zz_evidence_f010_routes_test.go"
  "evidence/f010/repro/trigger_merge_test.go"
  "evidence/f010/patches/traffic-scope-and-redaction.patch"
  "evidence/f010/patches/tests.patch"
  "evidence/f010/logs/f010-before.log"
  "evidence/f010/logs/f010-after.log"
  "evidence/f010/logs/go-test-run1.log"
  "evidence/f010/logs/go-test-run2.log"
  "findings/f011-same-host-traffic-ownership-and-ingest.md"
  "evidence/f011/README.md"
  "evidence/f011/repro/zz_evidence_f011_test.go"
  "evidence/f011/patches/traffic-ownership-and-task-scoped-ingest.patch"
  "evidence/f011/logs/f011-after.log"
  "evidence/f011/logs/go-test-run1.log"
  "findings/f012-live-model-prompt-injection.md"
  "findings/f013-finding-traffic-scope.md"
  "evidence/f013/README.md"
  "evidence/f013/repro/zz_evidence_f013_test.go"
  "evidence/f013/patches/finding-traffic-scope.patch"
  "evidence/f013/logs/f013-prefix.log"
  "evidence/f013/logs/f013-fixed.log"
  "evidence/f013/logs/go-test.log"
  "findings/f014-alternate-traffic-routes.md"
  "evidence/f014/README.md"
  "evidence/f014/repro/zz_evidence_f014_routes_test.go"
  "evidence/f014/logs/f014-routes.log"
  "findings/f015-injection-variant-matrix.md"
  "evidence/live/README.md"
  "evidence/live/probes-1.16.log"
  "evidence/live/probes-1.16.json"
  "evidence/live/repro/zz_evidence_live_injection_variants_test.go"
  "evidence/live/probe.log"
  "evidence/live/probe.json"
  "evidence/live/repro/zz_evidence_live_injection_test.go"
)

for f in "${required[@]}"; do
  if [ ! -s "$f" ]; then
    echo "missing or empty: $f" >&2
    exit 1
  fi
done

if ! grep -q '| Revision | 1.16 |' README.md; then
  echo "README revision is not 1.16" >&2
  exit 1
fi

# A finding may be open, but it must not be left as an unowned placeholder in
# the register or the attack-surface map.
if grep -RInE 'not started|TODO[[:space:]]*finding|unstarted' findings README.md references/artex-attack-surface.md 2>/dev/null; then
  echo "unstarted finding marker present" >&2
  exit 1
fi

for token in operator-charter agentic-pentest reverse-engineering supply-chain recursive-improvement tool-sources; do
  if ! grep -q "$token" SKILL.md; then
    echo "SKILL.md does not reference $token" >&2
    exit 1
  fi
done

# The source registry is an exact set: one canonical URL and one 40-hex pin per
# upstream. Substring matches are not enough; a typosquat or extra row must fail.
expected_urls=(
  'https://github.com/usestrix/strix'
  'https://github.com/KeygraphHQ/shannon'
  'https://github.com/N1nEmAn/sapper-v2'
  'https://github.com/NationalSecurityAgency/ghidra'
  'https://github.com/google/osv-scanner'
)
expected_shas=(
  '215482eb2204cd30ac6b87520e3f5c6511e2e2e8'
  '4cef63e5900c9eda0b259a44f89458c7f8b1e10d'
  'd4de0770ae1fba706f00b7e29197ce739adbea94'
  'e45e5a62fd66c2e48514931f6e356aff33a79fcb'
  '02f96a40691c2d155fdda799af436e111231e365'
)

got_urls="$(grep -oE '<https://[^>]+>' references/tool-sources.md | sort -u | tr '\n' ' ')"
want_urls="$(for u in "${expected_urls[@]}"; do printf '<%s>\n' "$u"; done | sort -u | tr '\n' ' ')"
if [ "$got_urls" != "$want_urls" ]; then
  echo "source registry URLs are not the exact expected set" >&2
  echo "expected: $want_urls" >&2
  echo "found:    $got_urls" >&2
  exit 1
fi

got_shas="$(grep -oE '`[0-9a-f]{40}`' references/tool-sources.md | tr -d '`' | sort -u | tr '\n' ' ')"
want_shas="$(printf '%s\n' "${expected_shas[@]}" | sort -u | tr '\n' ' ')"
if [ "$got_shas" != "$want_shas" ]; then
  echo "source pins are not the exact expected set" >&2
  echo "expected: $want_shas" >&2
  echo "found:    $got_shas" >&2
  exit 1
fi

for sha in "${expected_shas[@]}"; do
  if ! grep -q "$sha" README.md; then
    echo "README does not repeat pin $sha" >&2
    exit 1
  fi
done

# Everything executable in this repo is code execution on the analyst's machine
# (notably Ghidra postScripts). The manifest is the reviewed set; any added,
# removed or modified script fails until the manifest itself is reviewed.
if [ ! -s scripts/MANIFEST.sha256 ]; then
  echo "missing scripts/MANIFEST.sha256" >&2
  exit 1
fi
if ! ( cd scripts && shasum -a 256 -c MANIFEST.sha256 >/dev/null 2>&1 ); then
  echo "scripts/ integrity check failed" >&2
  ( cd scripts && shasum -a 256 -c MANIFEST.sha256 >&2 ) || true
  exit 1
fi
listed="$(awk '{print $2}' scripts/MANIFEST.sha256 | sort | tr '\n' ' ')"
actual="$(cd scripts && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | sort | tr '\n' ' ')"
if [ "$listed" != "$actual" ]; then
  echo "scripts/ contains files not in MANIFEST.sha256 (or is missing listed files)" >&2
  echo "listed: $listed" >&2
  echo "actual: $actual" >&2
  exit 1
fi

if grep -RInE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . --exclude-dir=.git --exclude='validate_skill.sh' 2>/dev/null; then
  echo "private-key material found" >&2
  exit 1
fi

echo "skill validation: OK"
