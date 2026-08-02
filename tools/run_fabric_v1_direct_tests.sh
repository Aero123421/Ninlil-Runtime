#!/usr/bin/env bash
# Direct C11 compile/run for private Fabric v1 (default-OFF candidate).
# Canonical NFL1: src/transport/fabric_v1/nfl1_codec.c (only encode/decode authority).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CC="${CC:-cc}"
OUT_DIR="${TMPDIR:-/tmp}/ninlil-fabric-v1-tests"
mkdir -p "$OUT_DIR"

CFLAGS=(
  -std=c11
  -Wall
  -Wextra
  -Werror
  -pedantic
  -Wvla
  -O1
  -g
  -Isrc/transport/fabric_v1
  -Iinclude
)

if [[ "${1:-}" == "--asan" ]]; then
  CFLAGS+=("-fsanitize=address,undefined" -fno-omit-frame-pointer)
  shift || true
fi
if [[ "${1:-}" == "--ubsan" ]]; then
  CFLAGS+=(-fsanitize=undefined -fno-omit-frame-pointer)
  shift || true
fi

echo "Compiler: $CC"
echo "CFLAGS: ${CFLAGS[*]}"

NFL1_SRC=(
  src/transport/fabric_v1/nfl1_codec.c
  src/transport/fabric_v1/fabric_private_util.c
)

FABRIC_SRC=(
  "${NFL1_SRC[@]}"
  src/transport/fabric_v1/fabric_workspace.c
  src/transport/fabric_v1/fabric_private_records.c
  src/transport/fabric_v1/fabric_private_select.c
  src/transport/fabric_v1/fabric_private_core.c
)

run_one() {
  local name="$1"
  local test_src="$2"
  shift 2
  local srcs=("$@")
  local out="$OUT_DIR/$name"
  echo "==> building $name"
  "$CC" "${CFLAGS[@]}" "$test_src" "${srcs[@]}" -o "$out"
  echo "==> running $name"
  "$out"
}

run_one nfl1_codec_test \
  tests/transport/fabric_v1/nfl1_codec_test.c \
  "${NFL1_SRC[@]}"

run_one fabric_v1_nfl1_test \
  tests/transport/fabric_v1/fabric_v1_nfl1_test.c \
  "${NFL1_SRC[@]}"

run_one fabric_v1_records_test \
  tests/transport/fabric_v1/fabric_v1_records_test.c \
  "${FABRIC_SRC[@]}"

run_one fabric_v1_selection_test \
  tests/transport/fabric_v1/fabric_v1_selection_test.c \
  "${FABRIC_SRC[@]}"

run_one fabric_v1_lifecycle_test \
  tests/transport/fabric_v1/fabric_v1_lifecycle_test.c \
  "${FABRIC_SRC[@]}"

run_one fabric_v1_p1_contracts_test \
  tests/transport/fabric_v1/fabric_v1_p1_contracts_test.c \
  "${FABRIC_SRC[@]}"

run_one fabric_v1_nfl1_property_test \
  tests/transport/fabric_v1/fabric_v1_nfl1_property_test.c \
  "${NFL1_SRC[@]}"

run_one fabric_v1_vector_matrix_test \
  tests/transport/fabric_v1/fabric_v1_vector_matrix_test.c \
  "${FABRIC_SRC[@]}"

run_one fabric_v1_host_acceptance_test \
  tests/transport/fabric_v1/fabric_v1_host_acceptance_test.c \
  "${FABRIC_SRC[@]}" \
  src/transport/fabric_v1/fabric_host_radio_packet_link.c

echo "All private Fabric v1 direct tests passed."
