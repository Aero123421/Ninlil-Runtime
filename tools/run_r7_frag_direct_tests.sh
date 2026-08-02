#!/usr/bin/env bash
# Direct C11 + ASan/UBSan for NRW1 LINK/FRAG private candidate (no CMake).
# Runs pure state + session + completion + production N6/R2/R1 integration.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Fail-closed: ban always-true asserts and over-broad multi-status ORs.
echo "==> r7_frag_false_green_gate"
python3 tools/r7_frag_false_green_gate.py

CC="${CC:-clang}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
if [[ ! -d "$OPENSSL_PREFIX" ]]; then
  OPENSSL_PREFIX="/usr/local/opt/openssl@3"
fi

INC=(
  -Isrc/radio
  -Isrc/radio/r7_frag
  -Isrc/model
  -Iinclude
  -Itests/support
)
if [[ -d "$OPENSSL_PREFIX/include" ]]; then
  INC+=("-I$OPENSSL_PREFIX/include")
fi
LIBS=()
if [[ -d "$OPENSSL_PREFIX/lib" ]]; then
  LIBS+=("-L$OPENSSL_PREFIX/lib")
fi
LIBS+=(-lcrypto)

COMMON=(
  -std=c11
  -Wall -Wextra -Werror -pedantic
  -Wvla
  -O1
  "${INC[@]}"
)

STATE_SRC=(
  src/radio/r7_frag/r7_frag_state.c
  tests/radio/r7_frag/r7_frag_state_test.c
)

ACK_LEDGER_SRC=(
  src/radio/r7_frag/r7_frag_ack_ledger.c
  tests/radio/r7_frag/r7_frag_ack_ledger_test.c
)

DUR_SNAP_SRC=(
  src/radio/r7_frag/r7_frag_state.c
  src/radio/r7_frag/r7_frag_durable.c
  tests/radio/r7_frag/r7_frag_durable_snapshot_test.c
)

FRAG_CORE=(
  src/radio/r7_frag/r7_frag_state.c
  src/radio/r7_frag/r7_frag_durable.c
  src/radio/r7_frag/r7_frag_wire.c
  src/radio/r7_frag/r7_frag_core.c
  src/radio/r7_frag/r7_frag_ack_ledger.c
  src/radio/r7_frag/r7_frag_checked_issue.c
  src/radio/r7_frag/r7_frag_issue_coordinator.c
  src/radio/r7_frag/r7_frag_session.c
  src/radio/r7_frag/r7_frag_adapters.c
  src/radio/r7_frag/r7_r2_authority_clock.c
  src/radio/r7_frag/r7_frag_target_smoke.c
)

SESS_SRC=(
  "${FRAG_CORE[@]}"
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  src/radio/radio_hal.c
  src/radio/pcp_authority.c
  src/radio/n6_context_store.c
  src/radio/n6_crypto_host.c
  src/radio/n6_record_codec.c
  src/model/domain_store_codec.c
  tests/radio/r7_frag/r7_frag_session_test.c
)

COMP_SRC=(
  "${FRAG_CORE[@]}"
  src/radio/r7_frag/r7_frag_prod_orch.c
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  src/radio/r7_wire_codec.c
  src/radio/radio_hal.c
  src/radio/pcp_authority.c
  src/radio/n6_context_store.c
  src/radio/n6_crypto_host.c
  src/radio/n6_record_codec.c
  src/model/domain_store_codec.c
  tests/radio/r7_frag/r7_frag_completion_test.c
)

SMOKE_SRC=(
  "${FRAG_CORE[@]}"
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  src/radio/radio_hal.c
  src/radio/pcp_authority.c
  src/radio/n6_context_store.c
  src/radio/n6_crypto_host.c
  src/radio/n6_record_codec.c
  src/model/domain_store_codec.c
  tests/radio/r7_frag/r7_frag_target_smoke_test.c
)

PROD_SRC=(
  "${FRAG_CORE[@]}"
  src/radio/r7_frag/r7_frag_prod_orch.c
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  src/radio/r7_wire_codec.c
  src/radio/radio_hal.c
  src/radio/pcp_authority.c
  src/radio/n6_context_store.c
  src/radio/n6_crypto_host.c
  src/radio/n6_record_codec.c
  src/model/domain_store_codec.c
  tests/support/n6_mem_storage.c
  tests/support/n6_local_identity_fixture.c
  tests/support/radio_hal_spy.c
  tests/support/in_memory_storage.c
  tests/support/platform_basic_fixtures.c
  tests/support/deterministic_entropy.c
  tests/radio/r7_frag/r7_frag_prod_integration_test.c
)

WIRE_SRC=(
  src/radio/r7_frag/r7_frag_wire.c
  src/radio/r7_frag/r7_frag_core.c
  src/radio/r7_wire_codec.c
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  tests/radio/r7_frag/r7_radio_wire_v1_fixture_test.c
)

OUT_STATE="${TMPDIR:-/tmp}/ninlil_r7_frag_state_test"
OUT_ACK="${TMPDIR:-/tmp}/ninlil_r7_frag_ack_ledger_test"
OUT_DUR="${TMPDIR:-/tmp}/ninlil_r7_frag_durable_snapshot_test"
OUT_SESS="${TMPDIR:-/tmp}/ninlil_r7_frag_session_test"
OUT_COMP="${TMPDIR:-/tmp}/ninlil_r7_frag_completion_test"
OUT_SMOKE="${TMPDIR:-/tmp}/ninlil_r7_frag_target_smoke_test"
OUT_PROD="${TMPDIR:-/tmp}/ninlil_r7_frag_prod_integration_test"
OUT_WIRE="${TMPDIR:-/tmp}/ninlil_r7_radio_wire_v1_fixture_test"

run_one() {
  local name="$1"
  local out="$2"
  shift 2
  local -a defs=()
  if [[ "$name" == *prod* || "$name" == *session* || "$name" == *completion* || "$name" == *smoke* ]]; then
    defs+=(-DNINLIL_N6_TEST_BUILD=1 -DNINLIL_R7_FRAG_WITH_N6=1)
  fi
  local src=("$@")
  echo "==> $name strict ($CC)"
  if ((${#defs[@]})); then
    "$CC" "${COMMON[@]}" "${defs[@]}" "${src[@]}" "${LIBS[@]}" -o "$out"
  else
    "$CC" "${COMMON[@]}" "${src[@]}" "${LIBS[@]}" -o "$out"
  fi
  "$out"
  echo "==> $name ASan/UBSan"
  if ((${#defs[@]})); then
    "$CC" "${COMMON[@]}" "${defs[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer \
      "${src[@]}" "${LIBS[@]}" -o "${out}_san"
  else
    "$CC" "${COMMON[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer \
      "${src[@]}" "${LIBS[@]}" -o "${out}_san"
  fi
  "${out}_san"
}

run_one "r7_frag_state" "$OUT_STATE" "${STATE_SRC[@]}"
run_one "r7_frag_ack_ledger" "$OUT_ACK" "${ACK_LEDGER_SRC[@]}"
run_one "r7_frag_durable_snapshot" "$OUT_DUR" "${DUR_SNAP_SRC[@]}"
run_one "r7_frag_session" "$OUT_SESS" "${SESS_SRC[@]}"
run_one "r7_frag_completion" "$OUT_COMP" "${COMP_SRC[@]}"
run_one "r7_frag_target_smoke" "$OUT_SMOKE" "${SMOKE_SRC[@]}"
run_one "r7_frag_prod_integration" "$OUT_PROD" "${PROD_SRC[@]}"
run_one "r7_radio_wire_v1_fixture" "$OUT_WIRE" "${WIRE_SRC[@]}"

echo "==> r7_radio_wire_v1 materialize verify"
python3 tools/r7_radio_wire_v1_materialize.py verify

echo "==> r7_frag packaging / OFF residual gates"
python3 tools/esp_idf_r7_frag_packaging_gate.py check
python3 tools/esp_idf_r7_frag_packaging_gate.py self-test
python3 tools/r7_crypto_tests_off_packaging_gate.py self-test
python3 tools/r7_wire_tests_off_packaging_gate.py self-test

echo "run_r7_frag_direct_tests: OK"
