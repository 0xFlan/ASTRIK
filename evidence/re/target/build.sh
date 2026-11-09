#!/usr/bin/env bash
# Build the RE fixture twice: a symbol-bearing reference build and the stripped
# copy that Ghidra actually analyzes. Record hashes so the artifacts are tied to
# exact bytes.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

clang -O1 -g -Wall -Wextra -o vuln_target vuln_target.c
cp vuln_target vuln_target.stripped
strip -x vuln_target.stripped

printf 'built: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
shasum -a 256 vuln_target vuln_target.stripped | tee SHA256SUMS
file vuln_target.stripped
