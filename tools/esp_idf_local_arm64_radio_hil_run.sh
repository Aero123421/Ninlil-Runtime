#!/usr/bin/env bash
# LOCAL Apple Silicon (linux/arm64) ESP-IDF build for SX1262 radio_hil composition.
#
# NOT CI / release authority. CI and packaging gates remain bound to:
#   tools/esp_idf_ci_docker_run.sh
#   docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb
#   --platform linux/amd64
#
# This launcher uses the official ESP-IDF v5.5.3 arm64 OCI digest for native
# Apple Silicon Docker (Colima/lima) without amd64 emulation:
#   docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
#
# Usage:
#   bash tools/esp_idf_local_arm64_radio_hil_run.sh
#   bash tools/esp_idf_local_arm64_radio_hil_run.sh v5.5.3
#   NINLIL_ESP_LOCAL_DRY_RUN=1 bash tools/esp_idf_local_arm64_radio_hil_run.sh
#
# Claims: compile/link of radio_hil_app + ELF/map evidence only.
# Does NOT claim RF HIL PASS / legal / Japan production / Accepted ADR-0025.
set -euo pipefail
unalias -a 2>/dev/null || true
if shopt -q expand_aliases 2>/dev/null; then
  shopt -u expand_aliases
fi

readonly EXPECTED_ESP_IDF_PIN="v5.5.3"
# Official multi-arch index member for linux/arm64 (v5.5.3).
readonly ESP_IDF_ARM64_IMAGE="docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"
readonly ESP_IDF_ARM64_PLATFORM="linux/arm64"
# Document CI authority (must remain distinct; do not use in this launcher).
readonly ESP_IDF_CI_AMD64_DIGEST="sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"

pin=""
if [[ "${1:-}" != "" ]]; then
  pin="$1"
elif [[ "${ESP_IDF_PIN:-}" != "" ]]; then
  pin="${ESP_IDF_PIN}"
else
  pin="${EXPECTED_ESP_IDF_PIN}"
fi

if [[ ! "${pin}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "esp_idf_local_arm64_radio_hil_run.sh: invalid pin format: ${pin}" >&2
  exit 1
fi
if [[ "${pin}" != "${EXPECTED_ESP_IDF_PIN}" ]]; then
  echo "esp_idf_local_arm64_radio_hil_run.sh: pin must be ${EXPECTED_ESP_IDF_PIN}, got ${pin}" >&2
  exit 1
fi

host_arch="$(uname -m)"
if [[ "${host_arch}" != "arm64" && "${host_arch}" != "aarch64" ]]; then
  echo "esp_idf_local_arm64_radio_hil_run.sh: host arch must be arm64/aarch64, got ${host_arch}" >&2
  echo "CI/release: use tools/esp_idf_ci_docker_run.sh (linux/amd64 ${ESP_IDF_CI_AMD64_DIGEST})" >&2
  exit 1
fi

if [[ "${NINLIL_ESP_LOCAL_DRY_RUN:-}" == "1" ]]; then
  echo "esp_idf_local_arm64_radio_hil_run.sh dry-run OK pin=${pin} platform=${ESP_IDF_ARM64_PLATFORM} image=${ESP_IDF_ARM64_IMAGE} ci_amd64_authority=${ESP_IDF_CI_AMD64_DIGEST}"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "esp_idf_local_arm64_radio_hil_run.sh: docker not found" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

echo "local arm64 radio_hil: pulling ${ESP_IDF_ARM64_IMAGE} (platform ${ESP_IDF_ARM64_PLATFORM})"
docker pull --platform "${ESP_IDF_ARM64_PLATFORM}" "${ESP_IDF_ARM64_IMAGE}"

# IMAGE argv is a literal string (same closed identity as dry-run).
# --interactive required so heredoc stdin reaches bash -s (same as CI launcher).
docker run --rm --interactive \
  --platform linux/arm64 \
  --user 0:0 \
  -v "${ROOT}:/project" \
  -w /project \
  "docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1" \
  bash -s <<'NINLIL_RADIO_HIL'
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
command -v xtensa-esp32s3-elf-gcc
command -v xtensa-esp32s3-elf-nm
command -v xtensa-esp32s3-elf-readelf

APP=ports/esp-idf/radio_hil_app
idf.py -C "${APP}" set-target esp32s3
idf.py -C "${APP}" build

ELF="${APP}/build/ninlil_radio_hil.elf"
MAP="${APP}/build/ninlil_radio_hil.map"
ARCHIVE="${APP}/build/esp-idf/ninlil/libninlil.a"
# idf.py writes project-level sdkconfig (not always build/sdkconfig).
SDK="${APP}/sdkconfig"
if [[ ! -f "${SDK}" && -f "${APP}/build/sdkconfig" ]]; then
  SDK="${APP}/build/sdkconfig"
fi
BIN="${APP}/build/ninlil_radio_hil.bin"

test -f "${ELF}"
test -f "${MAP}"
test -f "${ARCHIVE}"
test -f "${SDK}"
test -f "${BIN}"
test -s "${ELF}"
test -s "${MAP}"

# Board profile pins (Kconfig / sdkconfig).
for kv in \
  "CONFIG_NINLIL_SX1262_PIN_NSS=41" \
  "CONFIG_NINLIL_SX1262_PIN_SCK=7" \
  "CONFIG_NINLIL_SX1262_PIN_MOSI=9" \
  "CONFIG_NINLIL_SX1262_PIN_MISO=8" \
  "CONFIG_NINLIL_SX1262_PIN_RESET=42" \
  "CONFIG_NINLIL_SX1262_PIN_BUSY=40" \
  "CONFIG_NINLIL_SX1262_PIN_DIO1=39" \
  "CONFIG_NINLIL_SX1262_PIN_ANT_SW=38"
do
  grep -E "^${kv}$" "${SDK}"
done
grep -E '^CONFIG_NINLIL_SX1262_ANT_SW_ACTIVE_HIGH=y$' "${SDK}"

# R1/R2/R5/R9 authority path symbols in final ELF (linked from app).
xtensa-esp32s3-elf-nm "${ELF}" | tee "${APP}/build/ninlil_radio_hil.nm.txt" >/dev/null
for sym in \
  ninlil_radio_hal_transmit_with_permit \
  ninlil_sx1262_phy_arm_tx \
  ninlil_sx1262_r9_edge_init \
  ninlil_sx1262_request_transmit \
  ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability \
  ninlil_model_domain_sha256 \
  ninlil_airtime_lora_us \
  ninlil_pcp_issue \
  ninlil_pcp_validate \
  ninlil_pcp_consume \
  ninlil_pcp_recover \
  ninlil_r5_issue \
  ninlil_r5_permit_ops \
  ninlil_port_esp_storage_flash_bind \
  ninlil_port_esp_storage_config_production \
  ninlil_r7_crypto_mbedtls_provider_init \
  ninlil_sx1262_phy_ldro_auto_effective \
  ninlil_sx1262_board_profile_xiao_wio_sx1262_v1 \
  ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1
do
  if ! xtensa-esp32s3-elf-nm "${ELF}" | grep -E " ${sym}$"; then
    echo "missing final-ELF symbol: ${sym}" >&2
    exit 1
  fi
done
# Board profile TU must be in archive; backend carries SetDio2/3/CAL path.
if ! xtensa-esp32s3-elf-ar t "${ARCHIVE}" | grep -E 'ninlil_sx1262_board_profiles'; then
  echo "board profile object missing from radio_hil archive" >&2
  exit 1
fi
if ! xtensa-esp32s3-elf-ar t "${ARCHIVE}" | grep -E 'ninlil_sx1262_backend'; then
  echo "backend object missing from radio_hil archive" >&2
  exit 1
fi

# Legacy fixture / mock / session RAM ledger must not appear in release HIL.
for bad in \
  ninlil_sx1262_request_transmit_with_permit \
  fill_permit \
  hil_permit_validate \
  hil_permit_consume \
  ninlil_pcp_lab_session_ledger_init \
  ninlil_pcp_lab_session_ledger_shutdown
do
  if xtensa-esp32s3-elf-nm "${ELF}" | grep -E " ${bad}$"; then
    echo "forbidden production symbol present: ${bad}" >&2
    exit 1
  fi
done
if xtensa-esp32s3-elf-nm "${ARCHIVE}" | grep -E " ninlil_sx1262_request_transmit_with_permit$"; then
  echo "legacy request_transmit_with_permit must not be in libninlil.a" >&2
  exit 1
fi
if xtensa-esp32s3-elf-ar t "${ARCHIVE}" | grep -E 'pcp_lab_session_ledger'; then
  echo "session ledger object must not be in release radio_hil archive" >&2
  exit 1
fi
if ! xtensa-esp32s3-elf-ar t "${ARCHIVE}" | grep -E 'esp_storage_flash_media'; then
  echo "flash adapter object missing from radio_hil archive" >&2
  exit 1
fi

# Map must reference phy / radio_hal / flash authority TUs (link placement proof).
grep -E "ninlil_sx1262_phy|radio_hal|sx1262_r9_edge|pcp_authority|profile_loader|esp_storage_flash" "${MAP}" | head -30 || true
grep -E '^CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576$' "${SDK}"
grep -E '^CONFIG_NINLIL_ENABLE_SX1262_R9=y$' "${SDK}"
if grep -E '^CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y$' "${SDK}"; then
  echo "release radio_hil must not enable SESSION_LEDGER_DIAG" >&2
  exit 1
fi
# Real -fstack-usage artifacts for multi-chain stack gate (init/tx/recovery/rx).
for su in main.c.su ninlil_sx1262_phy.c.su sx1262_r9_edge.c.su pcp_authority.c.su profile_loader.c.su radio_hal.c.su; do
  if [[ "${su}" == "main.c.su" ]]; then
    mapfile -t hits < <(find "${APP}/build/esp-idf/main" -name "${su}" -type f 2>/dev/null | sort)
  else
    mapfile -t hits < <(find "${APP}/build/esp-idf/ninlil" -name "${su}" -type f 2>/dev/null | sort)
  fi
  if [[ "${#hits[@]}" -ne 1 ]]; then
    echo "missing unique ${su} under radio_hil component (got ${#hits[@]})" >&2
    exit 1
  fi
done

# Host-side evidence gate (paths relative to repo): retained call-chain sum+margin.
python3 tools/sx1262_radio_hil_elf_evidence_gate.py self-test
python3 tools/sx1262_radio_hil_elf_evidence_gate.py check \
  --elf "${ELF}" \
  --map "${MAP}" \
  --sdkconfig "${SDK}" \
  --nm-dump "${APP}/build/ninlil_radio_hil.nm.txt" \
  --archive "${ARCHIVE}" \
  --su-dir "${APP}/build" \
  --out-json "${APP}/build/ninlil_radio_hil_evidence.json"

echo "radio_hil local arm64 build OK"
ls -la "${ELF}" "${MAP}" "${BIN}" "${APP}/build/ninlil_radio_hil_evidence.json"
NINLIL_RADIO_HIL
