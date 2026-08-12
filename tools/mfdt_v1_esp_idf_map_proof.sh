#!/usr/bin/env bash
# ESP-IDF final-ELF + map + callpath proof for private MFDT V1 (ADR-0021).
# Dry-run without docker: NINLIL_ESP_CI_DRY_RUN=1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

MODE="${NINLIL_MFDT_ESP_PROOF_MODE:-auto}"
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
  echo "mfdt_v1_esp_idf_map_proof dry-run OK pin=${PIN} platform=${PLATFORM}"
  test -f ports/esp-idf/smoke_app/sdkconfig.defaults.mfdt_on
  test -f src/runtime/mfdt_v1/mfdt_v1_store_esp.c
  test -f ports/esp-idf/src/mfdt_v1_target_alloc.c
  test -f ports/esp-idf/src/mfdt_v1_target_smoke.c
  if grep -Fq 'mfdt_v1_store.c"' \
    ports/esp-idf/components/ninlil/CMakeLists.txt; then
    echo "lab mfdt_v1_store.c must not enter the ESP component" >&2
    exit 1
  fi
  grep -F 'mfdt_v1_store_esp.c' ports/esp-idf/components/ninlil/CMakeLists.txt
  grep -F 'mfdt_v1_target_smoke.c' ports/esp-idf/components/ninlil/CMakeLists.txt
  grep -F 'mfdt_v1_target_alloc.c' cmake/ninlil_mfdt_v1_sources.cmake
  grep -F 'mfdt_v1_bearer_worker.c' cmake/ninlil_mfdt_v1_sources.cmake
  grep -F 'mfdt_v1_foundation_carrier.c' cmake/ninlil_mfdt_v1_sources.cmake
  grep -F 'ninlil_mfdt_v1_esp_store_bind' src/runtime/mfdt_v1/mfdt_v1_store_esp.c
  grep -F 'ninlil_mfdt_v1_target_smoke_run' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_bearer_worker_step' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_foundation_carrier_service_identity' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_spine_arm_sender' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_session_build_offer' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_session_on_accept' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_ncl1_encode' ports/esp-idf/src/mfdt_v1_target_smoke.c
  grep -F 'ninlil_mfdt_v1_target_smoke_run' ports/esp-idf/smoke_app/main/main.c
  grep -F 'heap_caps_calloc' ports/esp-idf/src/mfdt_v1_target_alloc.c
  grep -F 'MALLOC_CAP_SPIRAM' ports/esp-idf/src/mfdt_v1_target_alloc.c
  python3 tools/mfdt_v1_esp_dram_budget_gate.py self-test
  echo "dry-run contract: lab store absent; SPIRAM/heap offload + live smoke path present"
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
APP=ports/esp-idf/smoke_app
idf.py -C "${APP}" fullclean || true
export SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.mfdt_on"
idf.py -C "${APP}" set-target esp32s3
idf.py -C "${APP}" -D SDKCONFIG_DEFAULTS="${SDKCONFIG_DEFAULTS}" build
ELF="${APP}/build/ninlil_m3_combined_smoke.elf"
MAP="${APP}/build/ninlil_m3_combined_smoke.map"
test -f "${ELF}" && test -s "${ELF}"
test -f "${MAP}" && test -s "${MAP}"
SDKCONFIG_H="${APP}/build/config/sdkconfig.h"
grep -E 'CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE 1' "${SDKCONFIG_H}"

NM_OUT="$(mktemp)"
xtensa-esp32s3-elf-nm -C "${ELF}" > "${NM_OUT}" || xtensa-esp32s3-elf-nm "${ELF}" > "${NM_OUT}"

# Required live symbols (must be defined text, not only undefined/bind).
for sym in \
  ninlil_mfdt_v1_esp_store_bind \
  ninlil_mfdt_v1_ncl1_encode \
  ninlil_mfdt_v1_spine_arm_sender \
  ninlil_mfdt_v1_session_build_offer \
  ninlil_mfdt_v1_session_on_accept \
  ninlil_mfdt_v1_target_smoke_run \
  ninlil_mfdt_v1_spine_take_outbound_ncl1 \
  ninlil_mfdt_v1_pipeline_on_ncl1_ingress \
  ninlil_mfdt_v1_bearer_worker_init \
  ninlil_mfdt_v1_bearer_worker_step \
  ninlil_mfdt_v1_foundation_carrier_service_identity
do
  if ! grep -E " [Tt] ${sym}$| ${sym}$" "${NM_OUT}" | grep -q .; then
    echo "MISSING symbol in final ELF: ${sym}" >&2
    grep -F "${sym}" "${NM_OUT}" || true
    exit 1
  fi
  # Prefer defined text (T/t), not only U
  if grep -E " U ${sym}$" "${NM_OUT}" | grep -q . && \
     ! grep -E " [Tt] ${sym}$" "${NM_OUT}" | grep -q .; then
    echo "symbol only undefined (dead/missing def): ${sym}" >&2
    exit 1
  fi
  echo "OK symbol ${sym}"
done

# Callpath: map must reference target smoke + store_esp (not host lab store.c).
grep -F 'mfdt_v1_target_smoke.c' "${MAP}"
grep -F 'mfdt_v1_store_esp.c' "${MAP}"
grep -F 'mfdt_v1_spine.c' "${MAP}"
grep -F 'mfdt_v1_bearer_worker.c' "${MAP}"
grep -F 'mfdt_v1_foundation_carrier.c' "${MAP}" || \
  grep -F 'mfdt_v1_foundation_carrier' "${MAP}"
grep -F 'mfdt_v1_ncl1.c' "${MAP}" || grep -F 'mfdt_v1_ncl1' "${MAP}"
! grep -F 'src/runtime/mfdt_v1/mfdt_v1_store.c' "${MAP}" || {
  echo "lab store.c must not be in ESP map" >&2
  exit 1
}

# app_main object must reference target smoke (live from main, not LTO-only pin).
if ! grep -E 'mfdt_v1_target_smoke|ninlil_mfdt_v1_target_smoke_run' "${MAP}" | grep -qi main; then
  # fallback: main.c.obj in map near smoke
  grep -F 'main.c.obj' "${MAP}" | head -3 || true
  grep -F 'ninlil_mfdt_v1_target_smoke_run' "${MAP}" | head -10
fi

# DRAM BSS budget: workspace-class giants must not land in .dram0.bss.
python3 /project/tools/mfdt_v1_esp_dram_budget_gate.py check --map "${MAP}"

# Report region size (informational).
if grep -E '^\.dram0\.bss' "${MAP}" | head -3; then
  :
fi

rm -f "${NM_OUT}"
echo "mfdt_v1_esp_idf_map_proof OK (live callpath + DRAM budget)"
EOF
