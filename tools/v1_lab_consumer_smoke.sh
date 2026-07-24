#!/usr/bin/env bash
# Reproducible external consumer install → find_package → link → run smoke.
# V1 LAB packaging (item 10b). Not a production conformance gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${NINLIL_BUILD_DIR:-$ROOT/tmp-v1}"
CONFIG="${NINLIL_BUILD_CONFIG:-Debug}"
GENERATOR="${NINLIL_CMAKE_GENERATOR:-Unix Makefiles}"

if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
  echo "v1_lab_consumer_smoke: configure build dir first: $BUILD" >&2
  exit 1
fi

# Discover SQLite pin from the producer cache when present.
SQLITE_LIB=""
SQLITE_INC=""
if [[ -f "$BUILD/CMakeCache.txt" ]]; then
  SQLITE_LIB="$(grep -E '^NINLIL_SQLITE_LIBRARY_PATH:' "$BUILD/CMakeCache.txt" 2>/dev/null | sed 's/.*=//' || true)"
  SQLITE_INC="$(grep -E '^SQLite3_INCLUDE_DIR:' "$BUILD/CMakeCache.txt" 2>/dev/null | head -1 | sed 's/.*=//' || true)"
fi
EXPECT_STATIC=OFF
if grep -q '^NINLIL_SQLITE_IS_STATIC:BOOL=ON' "$BUILD/CMakeCache.txt" 2>/dev/null; then
  EXPECT_STATIC=ON
fi

SANITIZERS=OFF
if grep -q '^NINLIL_ENABLE_SANITIZERS:BOOL=ON' "$BUILD/CMakeCache.txt" 2>/dev/null; then
  SANITIZERS=ON
fi

CTEST="${CTEST:-ctest}"
if ! command -v ctest >/dev/null 2>&1; then
  CTEST="$(cmake -LA -N "$BUILD" 2>/dev/null | awk -F= '/^CMAKE_CTEST_COMMAND:/{print $2; exit}')"
fi

ARGS=(
  -DNINLIL_BUILD_DIR="$BUILD"
  -DNINLIL_SOURCE_DIR="$ROOT"
  -DNINLIL_GENERATOR="$GENERATOR"
  -DNINLIL_CTEST_COMMAND="$CTEST"
  -DNINLIL_BUILD_CONFIG="$CONFIG"
  -DNINLIL_INSTALL_SMOKE_SANITIZERS="$SANITIZERS"
  -DNINLIL_SMOKE_EXPECT_STATIC_SQLITE="$EXPECT_STATIC"
  -P "$ROOT/cmake/installed_posix_sqlite_consumer_smoke.cmake"
)
if [[ -n "$SQLITE_LIB" ]]; then
  ARGS+=("-DNINLIL_SMOKE_SQLITE3_LIBRARY=$SQLITE_LIB")
fi
if [[ -n "$SQLITE_INC" ]]; then
  ARGS+=("-DNINLIL_SMOKE_SQLITE3_INCLUDE_DIR=$SQLITE_INC")
fi

echo "v1_lab_consumer_smoke: build=$BUILD config=$CONFIG sanitizers=$SANITIZERS"
cmake "${ARGS[@]}"
echo "v1_lab_consumer_smoke ok"
