#!/usr/bin/env bash
# ESP-IDF final-ELF + map proof dispatcher for private wifi_v1.
#
# CI/release authority (immutable amd64):
#   docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb
#   platform linux/amd64 — same as tools/esp_idf_ci_docker_run.sh
#
# Local Apple Silicon (native arm64, no QEMU):
#   tools/wifi_v1_esp_idf_map_proof_local_arm64.sh
#   docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
#   platform linux/arm64
#
# Env:
#   NINLIL_WIFI_ESP_PROOF_MODE=auto|ci|local_arm64  (default auto)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

MODE="${NINLIL_WIFI_ESP_PROOF_MODE:-auto}"
HOST_ARCH="$(uname -m)"

if [[ "${MODE}" == "auto" ]]; then
  if [[ "${HOST_ARCH}" == "arm64" || "${HOST_ARCH}" == "aarch64" ]]; then
    MODE="local_arm64"
  else
    MODE="ci"
  fi
fi

if [[ "${MODE}" == "local_arm64" ]]; then
  exec bash "${ROOT}/tools/wifi_v1_esp_idf_map_proof_local_arm64.sh"
fi

# --- CI / release amd64 path (authority digest) ---
PIN="${ESP_IDF_PIN:-v5.5.3}"
readonly CI_AMD64_IMAGE="docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
readonly CI_PLATFORM="linux/amd64"

if [[ "${NINLIL_ESP_CI_DRY_RUN:-}" == "1" ]]; then
  echo "wifi_v1_esp_idf_map_proof ci dry-run OK pin=${PIN} platform=${CI_PLATFORM} image=${CI_AMD64_IMAGE}"
  exit 0
fi

docker run --rm -i \
  --platform "${CI_PLATFORM}" \
  --user 0:0 \
  -v "${ROOT}:/project" \
  -w /project \
  -e CCACHE_DISABLE=1 \
  -e IDF_CCACHE_ENABLE=0 \
  "${CI_AMD64_IMAGE}" \
  bash -s <<'EOF'
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
command -v xtensa-esp32s3-elf-gcc

idf.py -C ports/esp-idf/wifi_hil_app fullclean || true
idf.py -C ports/esp-idf/wifi_hil_app set-target esp32s3
idf.py -C ports/esp-idf/wifi_hil_app build

ELF=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.elf
MAP=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.map
COMPONENT_ARCHIVE=ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil/libninlil.a
test -f "${ELF}" && test -s "${ELF}"
test -f "${MAP}" && test -s "${MAP}"
test -f "${COMPONENT_ARCHIVE}" && test -s "${COMPONENT_ARCHIVE}"

SDKCONFIG=ports/esp-idf/wifi_hil_app/sdkconfig
if [[ ! -f "${SDKCONFIG}" && -f ports/esp-idf/wifi_hil_app/build/sdkconfig ]]; then
  SDKCONFIG=ports/esp-idf/wifi_hil_app/build/sdkconfig
fi
SDKCONFIG_H=ports/esp-idf/wifi_hil_app/build/config/sdkconfig.h
SIZE_JSON=ports/esp-idf/wifi_hil_app/build/wifi_v1_size.json
test -f "${SDKCONFIG}"
test -f "${SDKCONFIG_H}"
grep -F 'CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y' "${SDKCONFIG}"
python3 "${IDF_PATH}/tools/idf_size.py" \
  --format json2 -o "${SIZE_JSON}" "${MAP}"
test -s "${SIZE_JSON}"

SU_ARGS=()
if [[ -d ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil ]]; then
  SU_ARGS=(--su-dir ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil)
fi

python3 tools/wifi_v1_esp_resource_gate.py \
  --map "${MAP}" \
  --elf "${ELF}" \
  --component-archive "${COMPONENT_ARCHIVE}" \
  --expect-symbols \
  --expect-export-symbol \
  --check-acceptance \
  --sdkconfig "${SDKCONFIG}" \
  --sdkconfig-h "${SDKCONFIG_H}" \
  --size-json "${SIZE_JSON}" \
  --max-owner-bytes 12288 \
  "${SU_ARGS[@]+"${SU_ARGS[@]}"}"

python3 tools/r7_wifi_allocator_closure_gate.py \
  --elf "${ELF}" \
  --map "${MAP}" \
  --component-archive "${COMPONENT_ARCHIVE}" \
  --idf-path "${IDF_PATH}" \
  --evidence-json \
    ports/esp-idf/wifi_hil_app/build/r7_wifi_allocator_closure_evidence.json

grep -E 'ninlil_wifi_esp_owner_init|ninlil_wifi_esp_owner_step|ninlil_wifi_nwb1_encode' "${MAP}"
grep -F 'mbedtls_ssl_export_keying_material' "${MAP}"
xtensa-esp32s3-elf-nm "${ELF}" | grep -E 'ninlil_wifi_|mbedtls_ssl_export_keying_material' | sed -n '1,50p' \
  | tee ports/esp-idf/wifi_hil_app/build/wifi_v1_nm.txt

echo "wifi_v1_esp_idf_map_proof(ci-amd64): PASS elf=${ELF} map=${MAP}"
EOF
