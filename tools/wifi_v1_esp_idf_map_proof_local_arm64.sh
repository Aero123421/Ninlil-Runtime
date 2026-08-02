#!/usr/bin/env bash
# Local Apple Silicon ESP-IDF final-ELF + map proof for private wifi_v1.
#
# Authority split (exact):
#   LOCAL (this host, arm64 native — no QEMU/amd64):
#     docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
#     platform: linux/arm64
#   CI/release (tools/esp_idf_ci_docker_run.sh) remains:
#     docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb
#     platform: linux/amd64
#
# Does not claim physical AP/HIL hardware pass.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

readonly PIN="v5.5.3"
readonly LOCAL_ARM64_IMAGE="docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"
readonly LOCAL_PLATFORM="linux/arm64"

HOST_ARCH="$(uname -m)"
if [[ "${HOST_ARCH}" != "arm64" && "${HOST_ARCH}" != "aarch64" ]]; then
  echo "wifi_v1_esp_idf_map_proof_local_arm64: host is ${HOST_ARCH}, not arm64" >&2
  echo "use tools/wifi_v1_esp_idf_map_proof.sh (CI amd64) or native amd64" >&2
  exit 2
fi

if [[ "${NINLIL_ESP_CI_DRY_RUN:-}" == "1" ]]; then
  echo "wifi_v1_esp_idf_map_proof_local_arm64 dry-run OK pin=${PIN} platform=${LOCAL_PLATFORM} image=${LOCAL_ARM64_IMAGE}"
  exit 0
fi

echo "wifi_v1_esp_idf_map_proof_local_arm64: pin=${PIN} platform=${LOCAL_PLATFORM}"
echo "image=${LOCAL_ARM64_IMAGE}"

# -i required so heredoc reaches bash -s (non-interactive docker drops stdin).
docker run --rm -i \
  --platform "${LOCAL_PLATFORM}" \
  --user 0:0 \
  -v "${ROOT}:/project" \
  -w /project \
  -e CCACHE_DISABLE=1 \
  -e IDF_CCACHE_ENABLE=0 \
  "${LOCAL_ARM64_IMAGE}" \
  bash -s <<'EOF'
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
command -v xtensa-esp32s3-elf-gcc
uname -m | tee /tmp/wifi_idf_container_arch.txt
# Must be arm64/aarch64 native (no qemu-user).
grep -Eq 'aarch64|arm64' /tmp/wifi_idf_container_arch.txt

# Wipe any partial/host-polluted build tree before idf.py (fullclean refuses
# non-CMake directories that only hold status crumbs). STATUS lives outside
# build/ so set-target's implicit fullclean does not see a dirty non-CMake dir.
rm -rf ports/esp-idf/wifi_hil_app/build
STATUS=ports/esp-idf/wifi_hil_app/wifi_map_proof_status.txt
echo "START $(date -u +%FT%TZ) arch=$(uname -m)" > "${STATUS}"

idf.py -C ports/esp-idf/wifi_hil_app set-target esp32s3
idf.py -C ports/esp-idf/wifi_hil_app build

ELF=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.elf
MAP=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.map
COMPONENT_ARCHIVE=ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil/libninlil.a
test -f "${ELF}"
test -f "${MAP}"
test -f "${COMPONENT_ARCHIVE}"
test -s "${ELF}"
test -s "${MAP}"
test -s "${COMPONENT_ARCHIVE}"

# Prefer project-level sdkconfig; fall back to build tree copy.
SDKCONFIG=ports/esp-idf/wifi_hil_app/sdkconfig
if [[ ! -f "${SDKCONFIG}" && -f ports/esp-idf/wifi_hil_app/build/sdkconfig ]]; then
  SDKCONFIG=ports/esp-idf/wifi_hil_app/build/sdkconfig
fi
SDKCONFIG_H=ports/esp-idf/wifi_hil_app/build/config/sdkconfig.h
SIZE_JSON=ports/esp-idf/wifi_hil_app/build/wifi_v1_size.json
test -f "${SDKCONFIG}"
test -f "${SDKCONFIG_H}"
grep -F 'CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y' "${SDKCONFIG}"
grep -E 'CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT' "${SDKCONFIG_H}"
python3 "${IDF_PATH}/tools/idf_size.py" \
  --format json2 -o "${SIZE_JSON}" "${MAP}"
test -s "${SIZE_JSON}"

# .su may be absent if component did not emit stack-usage for all TUs;
# require dir only when present, else symbol gate still hard-fails.
SU_ARGS=()
if find ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil -name '*.su' 2>/dev/null | grep -q .; then
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

# HIL composition evidence (serial surface + symbols); not physical AP pass.
{
  echo "wifi_hil_app_elf=${ELF}"
  echo "wifi_hil_app_map=${MAP}"
  echo "container_arch=$(uname -m)"
  echo "idf_version=ESP-IDF v5.5.3"
  echo "image_digest=sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"
  echo "owner_size_authority=final_elf_nm_S_symbol"
  echo "mbedtls_ssl_keying_material_export=y"
  echo "physical_ap_hil=NOT_RUN"
  echo "physical_allocator_trace=NOT_RUN"
  echo "claim=wifi_r7_composition_target_software_candidate"
  echo "r7_other_registered=IMPLEMENTED_PROPOSED"
  echo "c7=RED"
  echo "c8=RED"
} | tee ports/esp-idf/wifi_hil_app/build/wifi_hil_evidence.txt

echo "PASS $(date -u +%FT%TZ)" >> "${STATUS}"
echo "wifi_v1_esp_idf_map_proof_local_arm64: PASS elf=${ELF} map=${MAP}"
EOF
