#!/usr/bin/env bash
# Domain schema1 feature-ON ESP32-S3 smoke build + ELF/map evidence.
#
# Local Apple Silicon (default when uname -m is arm64/aarch64):
#   Official v5.5.3 arm64 digest (NOT CI/release amd64 authority):
#   sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
#
# CI/release amd64 authority remains tools/esp_idf_ci_docker_run.sh
# (sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb).
# This script never rewrites that file.
#
# Usage:
#   bash tools/domain_schema1_esp_map_evidence.sh
#   NINLIL_DOMAIN_ESP_PLATFORM=linux/amd64 bash tools/domain_schema1_esp_map_evidence.sh  # force amd64
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Official ESP-IDF v5.5.3 digests (closed).
readonly ESP_IDF_ARM64_DIGEST="sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"
readonly ESP_IDF_AMD64_DIGEST="sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"

HOST_ARCH="$(uname -m)"
PLATFORM="${NINLIL_DOMAIN_ESP_PLATFORM:-}"
if [[ -z "${PLATFORM}" ]]; then
  case "${HOST_ARCH}" in
    arm64|aarch64) PLATFORM="linux/arm64" ;;
    *) PLATFORM="linux/amd64" ;;
  esac
fi

case "${PLATFORM}" in
  linux/arm64)
    IMAGE="docker.io/espressif/idf@${ESP_IDF_ARM64_DIGEST}"
    ;;
  linux/amd64)
    IMAGE="docker.io/espressif/idf@${ESP_IDF_AMD64_DIGEST}"
    ;;
  *)
    echo "domain_schema1_esp_map_evidence: unsupported platform ${PLATFORM}" >&2
    exit 2
    ;;
esac

OUT_DIR="${NINLIL_DOMAIN_ESP_EVIDENCE_DIR:-${ROOT}/ports/esp-idf/smoke_app/build/domain_schema1_evidence}"
mkdir -p "${OUT_DIR}"

echo "domain_schema1_esp_map_evidence: host=${HOST_ARCH} platform=${PLATFORM} image=${IMAGE}"

# Temporarily append Domain feature ON to sdkconfig.defaults (restored on exit).
SDK_DEFAULTS="${ROOT}/ports/esp-idf/smoke_app/sdkconfig.defaults"
SDK_BAK="$(mktemp)"
cp "${SDK_DEFAULTS}" "${SDK_BAK}"
cleanup() {
  cp "${SDK_BAK}" "${SDK_DEFAULTS}"
  rm -f "${SDK_BAK}"
}
trap cleanup EXIT

cat "${ROOT}/ports/esp-idf/smoke_app/sdkconfig.defaults.domain_schema1_on" \
  >> "${SDK_DEFAULTS}"

docker run --rm \
  --platform "${PLATFORM}" \
  --user 0:0 \
  -e IDF_CCACHE_ENABLE=0 \
  -v "${ROOT}:/project" \
  -w /project \
  "${IMAGE}" \
  bash -lc '
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
APP=ports/esp-idf/smoke_app
# Clean Domain feature-ON build.
rm -rf "${APP}/build"
idf.py -C "${APP}" set-target esp32s3
idf.py -C "${APP}" build
ELF="${APP}/build/ninlil_m3_combined_smoke.elf"
MAP="${APP}/build/ninlil_m3_combined_smoke.map"
test -f "${ELF}"
test -f "${MAP}"
EVD="${APP}/build/domain_schema1_evidence"
mkdir -p "${EVD}"
cp -f "${ELF}" "${EVD}/"
cp -f "${MAP}" "${EVD}/"
idf.py --version | tee "${EVD}/idf_version.txt"
# sdkconfig proof feature ON
if [[ -f "${APP}/build/sdkconfig" ]]; then
  cp -f "${APP}/build/sdkconfig" "${EVD}/sdkconfig"
elif [[ -f "${APP}/sdkconfig" ]]; then
  cp -f "${APP}/sdkconfig" "${EVD}/sdkconfig"
fi
grep -E "CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=y" \
  "${EVD}/sdkconfig" \
  | tee "${EVD}/feature_on.txt"
xtensa-esp32s3-elf-size "${ELF}" | tee "${EVD}/size.txt"
xtensa-esp32s3-elf-nm -g "${APP}/build/esp-idf/ninlil/libninlil.a" \
  | tee "${EVD}/nm_domain.txt" \
  | grep -E "ninlil_domain_schema1_service_register|ninlil_domain_schema1_owner_run_storage_recovery"
python3 - <<'"'"'PY'"'"'
from pathlib import Path
import re
mp = Path("ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.map")
text = mp.read_text(errors="replace")
out = Path("ports/esp-idf/smoke_app/build/domain_schema1_evidence/map_summary.txt")
lines = []
for ln in text.splitlines():
    if re.search(r"\b(DRAM|DIRAM|FLASH|iram0|dram0)\b", ln, re.I):
        lines.append(ln)
out.write_text("\n".join(lines[:200]) + "\n")
print("map_summary lines", min(200, len(lines)))
totals = {}
for m in re.finditer(
    r"^\s*\.(dram0\.[a-zA-Z0-9_]+)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)",
    text,
    re.M,
):
    totals[m.group(1)] = totals.get(m.group(1), 0) + int(m.group(2), 16)
print("dram0 sections", totals)
PY
echo "domain_schema1_esp_map_evidence container OK"
'

MAP_HOST="${ROOT}/ports/esp-idf/smoke_app/build/domain_schema1_evidence/ninlil_m3_combined_smoke.map"
test -f "${MAP_HOST}"
mkdir -p "${OUT_DIR}"
cp -f "${ROOT}/ports/esp-idf/smoke_app/build/domain_schema1_evidence/"* "${OUT_DIR}/" 2>/dev/null || true

# Host completion gate with real map (no false-green without map).
python3 tools/domain_schema1_memory_gate.py completion --esp-map "${MAP_HOST}"

{
  echo "platform=${PLATFORM}"
  echo "image=${IMAGE}"
  echo "map=${MAP_HOST}"
  echo "host_arch=${HOST_ARCH}"
  date -u +"collected_at=%Y-%m-%dT%H:%M:%SZ"
} | tee "${OUT_DIR}/collection_meta.txt"

echo "domain_schema1_esp_map_evidence OK evidence=${OUT_DIR}"
ls -la "${OUT_DIR}"
