#!/usr/bin/env bash
# ESP-IDF final-ELF + map proof for private route-relay / multi-parent (RRMP).
#
# CI/release authority (immutable amd64):
#   docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb
#   platform linux/amd64 — same as tools/esp_idf_ci_docker_run.sh
#
# Local Apple Silicon (native arm64, no QEMU):
#   NINLIL_RRMP_ESP_PROOF_MODE=local_arm64
#   docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
#
# Env:
#   NINLIL_RRMP_ESP_PROOF_MODE=auto|ci|local_arm64  (default auto)
#   NINLIL_ESP_CI_DRY_RUN=1  — contract check only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

MODE="${NINLIL_RRMP_ESP_PROOF_MODE:-auto}"
HOST_ARCH="$(uname -m)"

if [[ "${MODE}" == "auto" ]]; then
  if [[ "${HOST_ARCH}" == "arm64" || "${HOST_ARCH}" == "aarch64" ]]; then
    MODE="local_arm64"
  else
    MODE="ci"
  fi
fi

PIN="${ESP_IDF_PIN:-v5.5.3}"
readonly CI_AMD64_IMAGE="docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
readonly ARM64_IMAGE="docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"

if [[ "${MODE}" == "local_arm64" ]]; then
  IMAGE="${ARM64_IMAGE}"
  PLATFORM="linux/arm64"
else
  IMAGE="${CI_AMD64_IMAGE}"
  PLATFORM="linux/amd64"
fi

if [[ "${NINLIL_ESP_CI_DRY_RUN:-}" == "1" ]]; then
  echo "rrmp_esp_idf_map_proof dry-run OK pin=${PIN} platform=${PLATFORM} image=${IMAGE}"
  python3 tools/rrmp_esp_dram_budget_gate.py self-test
  exit 0
fi

docker run --rm -i \
  --platform "${PLATFORM}" \
  --user 0:0 \
  -v "${ROOT}:/project" \
  -w /project \
  -e CCACHE_DISABLE=1 \
  -e IDF_CCACHE_ENABLE=0 \
  "${IMAGE}" \
  bash -s <<'EOF'
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
command -v xtensa-esp32s3-elf-gcc

APP=ports/esp-idf/smoke_app
idf.py -C "${APP}" fullclean || true
# Merge RRMP-on defaults over base smoke defaults.
export SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.rrmp_on"
idf.py -C "${APP}" set-target esp32s3
idf.py -C "${APP}" -D SDKCONFIG_DEFAULTS="${SDKCONFIG_DEFAULTS}" build

ELF="${APP}/build/ninlil_m3_combined_smoke.elf"
MAP="${APP}/build/ninlil_m3_combined_smoke.map"
test -f "${ELF}" && test -s "${ELF}"
test -f "${MAP}" && test -s "${MAP}"

SDKCONFIG_H="${APP}/build/config/sdkconfig.h"
test -f "${SDKCONFIG_H}"
grep -E 'CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1 1' "${SDKCONFIG_H}"

# Required symbols present in final ELF (GC-resistant smoke probe).
for sym in \
  ninlil_route_install_batch \
  ninlil_parent_set_install \
  ninlil_rrmp_owner_init \
  ninlil_rrmp_seam_fabric_relay_cycle \
  ninlil_rrmp_core_forward_admit_with_carrier \
  ninlil_rrmp_core_hop_forward_execute \
  ninlil_rrmp_core_link_ack_from_evidence \
  ninlil_rrmp_core_worker_tick \
  ninlil_parent_recover_commit_unknown \
  ninlil_rrmp_sha256_selftest \
  ninlil_rrmp_composition_bind \
  ninlil_rrmp_composition_recover \
  ninlil_rrmp_target_smoke_run
do
  if ! nm -C "${ELF}" | grep -E " ${sym}\$" >/dev/null; then
    echo "FAIL: missing RRMP symbol in final ELF: ${sym}" >&2
    exit 1
  fi
done
# Host-only sim / host lifecycle fixture must not appear
if nm -C "${ELF}" | grep -E ' ninlil_rrmp_sim_' >/dev/null; then
  echo "FAIL: rrmp_sim symbols present in ESP ELF" >&2
  exit 1
fi
if nm -C "${ELF}" | grep -E ' ninlil_rrmp_host_lifecycle_run' >/dev/null; then
  echo "FAIL: host lifecycle fixture linked into ESP ELF" >&2
  exit 1
fi
if nm -C "${ELF}" | grep -E ' ninlil_rrmp_composition_deterministic_logic' >/dev/null; then
  echo "FAIL: host deterministic_logic must not be in ESP production ELF" >&2
  exit 1
fi
# Map objects present (production thin composition + target smoke)
for obj in rrmp_core.c.obj rrmp_codec.c.obj rrmp_store.c.obj rrmp_util.c.obj \
  rrmp_seam.c.obj rrmp_composition.c.obj rrmp_target_smoke.c.obj; do
  if ! grep -F "${obj}" "${MAP}" >/dev/null; then
    echo "FAIL: map missing ${obj}" >&2
    exit 1
  fi
done
# Smoke must use production bind/recover + real lifecycle (not symbol-only).
if ! grep -F 'ninlil_rrmp_composition_bind' \
  ports/esp-idf/src/rrmp_target_smoke.c >/dev/null; then
  echo "FAIL: rrmp_target_smoke does not call composition_bind" >&2
  exit 1
fi
if ! grep -F 'ninlil_rrmp_composition_recover' \
  ports/esp-idf/src/rrmp_target_smoke.c >/dev/null; then
  echo "FAIL: rrmp_target_smoke does not call composition_recover" >&2
  exit 1
fi
if ! grep -F 'MALLOC_CAP_SPIRAM' ports/esp-idf/src/rrmp_target_smoke.c >/dev/null; then
  echo "FAIL: rrmp_target_smoke missing explicit SPIRAM CAPS design" >&2
  exit 1
fi
if ! grep -F 'NINLIL_PARENT_SPLIT_BRAIN' ports/esp-idf/src/rrmp_target_smoke.c >/dev/null; then
  echo "FAIL: rrmp_target_smoke missing unique parent_loss SPLIT_BRAIN assert" >&2
  exit 1
fi
# No multi-hundred-KiB static owner/workspace arrays in smoke/composition.
if grep -E 'static[[:space:]]+uint8_t[[:space:]]+[a-zA-Z0-9_]+\[.*\*[[:space:]]*1024' \
  ports/esp-idf/src/rrmp_target_smoke.c \
  src/runtime/route_relay_v1/rrmp_composition.c >/dev/null; then
  echo "FAIL: large static KiB arrays in ESP production/smoke TUs" >&2
  exit 1
fi

python3 tools/rrmp_esp_dram_budget_gate.py check \
  --map "${MAP}" \
  --sdkconfig "${APP}/sdkconfig"

EVID="${APP}/build/rrmp_evidence"
mkdir -p "${EVID}"
cp -f "${ELF}" "${MAP}" "${EVID}/"
cp -f "${APP}/sdkconfig" "${EVID}/"
nm -C "${ELF}" | grep -E 'ninlil_(route_|parent_|rrmp_)' > "${EVID}/nm_rrmp.txt"
idf.py --version > "${EVID}/idf_version.txt"
echo "feature=ON" > "${EVID}/feature_on.txt"
xtensa-esp32s3-elf-size "${ELF}" > "${EVID}/size.txt" || true
echo "rrmp_esp_idf_map_proof OK elf=${ELF}"
EOF
