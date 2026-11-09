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
)

for f in "${required[@]}"; do
  if [ ! -s "$f" ]; then
    echo "missing or empty: $f" >&2
    exit 1
  fi
done

if ! grep -q '| Revision | 1.4 |' README.md; then
  echo "README revision is not 1.4" >&2
  exit 1
fi

for token in operator-charter agentic-pentest reverse-engineering supply-chain recursive-improvement tool-sources; do
  if ! grep -q "$token" SKILL.md; then
    echo "SKILL.md does not reference $token" >&2
    exit 1
  fi
done

if grep -RInE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . --exclude-dir=.git --exclude='validate_skill.sh' 2>/dev/null; then
  echo "private-key material found" >&2
  exit 1
fi

for url in \
  'https://github.com/usestrix/strix' \
  'https://github.com/KeygraphHQ/shannon' \
  'https://github.com/N1nEmAn/sapper-v2' \
  'https://github.com/NationalSecurityAgency/ghidra' \
  'https://github.com/google/osv-scanner'; do
  if ! grep -q "$url" references/tool-sources.md; then
    echo "source registry missing $url" >&2
    exit 1
  fi
done

echo "skill validation: OK"
