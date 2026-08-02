#!/usr/bin/env bash
# Fabric v1 toolchain evidence: -Wvla, host Clang/GCC, optional ILP32 sizes.
# Does not edit Wi-Fi sources. Exit 0 when required host evidence passes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${TMPDIR:-/tmp}/ninlil-fabric-v1-evidence"
mkdir -p "$OUT"
REPORT="$OUT/toolchain_evidence.txt"
: >"$REPORT"

SRC=(
  src/transport/fabric_v1/nfl1_codec.c
  src/transport/fabric_v1/fabric_private_util.c
  src/transport/fabric_v1/fabric_workspace.c
  src/transport/fabric_v1/fabric_private_records.c
  src/transport/fabric_v1/fabric_private_select.c
  src/transport/fabric_v1/fabric_private_core.c
)
INC=(-Isrc/transport/fabric_v1 -Iinclude -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
CFLAGS_COMMON=(-std=c11 -Wall -Wextra -Werror -pedantic -Wvla -O1 -c)

log() { echo "$*" | tee -a "$REPORT"; }

compile_host() {
  local cc="$1"
  local tag="$2"
  local odir="$OUT/$tag"
  mkdir -p "$odir"
  log "== host compile cc=$cc tag=$tag"
  for s in "${SRC[@]}"; do
    local base
    base="$(basename "$s" .c)"
    "$cc" "${CFLAGS_COMMON[@]}" "${INC[@]}" "$s" -o "$odir/${base}.o"
  done
  log "OK $tag object set"
}

# Size probe for ILP32 / LP64
write_probe() {
  cat >"$OUT/size_probe.c" <<'EOF'
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
int main(void) {
  printf("sizeof(void*)=%zu sizeof(long)=%zu sizeof(int)=%zu sizeof(size_t)=%zu\n",
    sizeof(void *), sizeof(long), sizeof(int), sizeof(size_t));
  printf("UINTPTR_MAX_hex=%llx\n", (unsigned long long)UINTPTR_MAX);
  return 0;
}
EOF
}

log "host uname: $(uname -a)"
log "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if command -v clang >/dev/null 2>&1; then
  compile_host clang host-clang
  log "clang: $(clang --version | head -1)"
else
  log "WARN: clang missing"
fi

if command -v gcc >/dev/null 2>&1; then
  compile_host gcc host-gcc
  log "gcc: $(gcc --version | head -1)"
else
  log "WARN: gcc missing"
fi

# Prefer arm-none-eabi for 32-bit pointer model evidence (ILP32-like baremetal)
write_probe
if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
  log "== ILP32-like size probe via arm-none-eabi-gcc -mcpu=cortex-m4"
  if arm-none-eabi-gcc -std=c11 -mcpu=cortex-m4 -mthumb -mfloat-abi=soft \
      -Wall -Wextra -Werror -Wvla -O1 \
      -o "$OUT/size_probe_m4.elf" "$OUT/size_probe.c" \
      -specs=rdimon.specs -lc -lrdimon 2>>"$REPORT"; then
    log "OK arm-none-eabi linked size probe"
  else
    log "NOTE: arm-none-eabi link may need rdimon; compiling to object only"
  fi
  arm-none-eabi-gcc -std=c11 -mcpu=cortex-m4 -mthumb -mfloat-abi=soft \
    -Wall -Wextra -Werror -Wvla -O1 -c \
    -o "$OUT/size_probe_m4.o" "$OUT/size_probe.c"
  arm-none-eabi-gcc -std=c11 -mcpu=cortex-m4 -mthumb -mfloat-abi=soft \
    -Wall -Wextra -Werror -Wvla -O1 -c \
    "${INC[@]}" \
    -o "$OUT/fabric_core_m4.o" src/transport/fabric_v1/fabric_private_core.c
  log "OK fabric_private_core.o for cortex-m4 (ILP32 pointers)"
  # Extract sizeof via nm/size is weak; emit preprocessor evidence:
  arm-none-eabi-gcc -std=c11 -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -dM -E -x c /dev/null \
    | rg "UINTPTR_MAX|__SIZEOF_POINTER__|__INTPTR_WIDTH__" | tee -a "$REPORT" || true
else
  log "WARN: arm-none-eabi-gcc missing; ILP32 object evidence skipped"
fi

# Host LP64 size probe
cc -std=c11 -O1 -o "$OUT/size_probe_host" "$OUT/size_probe.c"
log "host sizes: $("$OUT/size_probe_host")"

# Generator compare-only + mutation self-test
python3 tools/fabric_v1_selection_vector_gen.py --check
python3 tools/fabric_v1_selection_vector_gen.py --self-test
python3 tools/fabric_v1_exec_catalog_gen.py --check
python3 tools/fabric_v1_exec_catalog_gen.py --self-test
python3 tools/fabric_v1_vector_fixture_gen.py --check
python3 tools/fabric_v1_vector_fixture_gen.py --self-test
log "OK generator --check and --self-test"

log "evidence report: $REPORT"
echo "fabric_v1_toolchain_evidence: PASS"
echo "report=$REPORT"
