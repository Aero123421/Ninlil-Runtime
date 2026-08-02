#!/usr/bin/env bash
# Direct compile/run for private r7_frag candidate (not CMake, not installed).
# Usage: tools/r7_frag_direct_test_driver.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CC="${CC:-clang}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
if [[ ! -d "$OPENSSL_PREFIX" ]]; then
  OPENSSL_PREFIX="/usr/local/opt/openssl@3"
fi

INC=(-Isrc/radio -Isrc/radio/r7_frag)
if [[ -d "$OPENSSL_PREFIX/include" ]]; then
  INC+=("-I$OPENSSL_PREFIX/include")
fi
LIBS=()
if [[ -d "$OPENSSL_PREFIX/lib" ]]; then
  LIBS+=("-L$OPENSSL_PREFIX/lib")
fi
LIBS+=(-lcrypto)

SRC=(
  src/radio/r7_frag/r7_frag_wire.c
  src/radio/r7_frag/r7_frag_core.c
  src/radio/r7_crypto_portable.c
  src/radio/r7_crypto_nonce.c
  src/radio/r7_crypto_openssl3.c
  tests/radio/r7_frag/r7_frag_direct_test.c
)

OUT="${TMPDIR:-/tmp}/ninlil_r7_frag_direct_test"

COMMON_FLAGS=(
  -std=c11
  -Wall -Wextra -Werror -pedantic
  -Wvla
  -O1
  "${INC[@]}"
)

echo "==> strict build ($CC)"
"$CC" "${COMMON_FLAGS[@]}" "${SRC[@]}" "${LIBS[@]}" -o "$OUT"

echo "==> ASan/UBSan build"
"$CC" "${COMMON_FLAGS[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer \
  "${SRC[@]}" "${LIBS[@]}" -o "${OUT}_san"

echo "==> run strict"
"$OUT"

echo "==> run sanitizer"
"${OUT}_san"

echo "r7_frag_direct_test_driver: OK"
