#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
#
# Phase-1 witness: compile the standalone C KAT and require current production
# to remain RED. Exit 0 means RED was reproduced; an unexpected GREEN exits 1.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cc_bin=${CC:-cc}
out="${TMPDIR:-/tmp}/ninlil-mfdt-v1-contract-red-$$"
trap 'rm -f "$out"' EXIT HUP INT TERM

"$cc_bin" -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo_root/src/runtime/mfdt_v1" \
  "$repo_root/tests/runtime/mfdt_v1/mfdt_v1_contract_red_test.c" \
  -o "$out"

set +e
"$out"
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  echo "MFDT RED witness FAIL: production unexpectedly satisfies repaired contract" >&2
  exit 1
fi
if [ "$rc" -ne 1 ]; then
  echo "MFDT RED witness FAIL: test exited unexpectedly with $rc" >&2
  exit 1
fi

echo "MFDT RED witness OK: repaired contract is executable and current production is RED"
