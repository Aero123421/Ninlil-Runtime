#!/usr/bin/env bash
# Sole authorized ESP-IDF CI container launcher.
#
# Workflow contract (exact):
#   bash tools/esp_idf_ci_docker_run.sh "${{ steps.pin.outputs.version }}"
# Local/executable contract:
#   bash tools/esp_idf_ci_docker_run.sh v5.5.3
#   ESP_IDF_PIN=v5.5.3 bash tools/esp_idf_ci_docker_run.sh
#
# Pin is a real shell argument/env — never a GitHub Actions expression literal.
# Optional NINLIL_ESP_CI_DRY_RUN=1 validates pin/image contract and exits before
# docker (host packaging / executable self-test path).
# No floating image tags, aliases, functions, eval, or alternate docker paths.
set -euo pipefail
# Drop any inherited shell aliases/functions that could shadow docker.
unalias -a 2>/dev/null || true
# Refuse to run under interactive alias expansion contexts.
if shopt -q expand_aliases 2>/dev/null; then
  shopt -u expand_aliases
fi

readonly EXPECTED_ESP_IDF_PIN="v5.5.3"
readonly ESP_IDF_IMMUTABLE_IMAGE="docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
readonly ESP_IDF_PLATFORM="linux/amd64"

pin=""
if [[ "${1:-}" != "" ]]; then
  pin="$1"
elif [[ "${ESP_IDF_PIN:-}" != "" ]]; then
  pin="${ESP_IDF_PIN}"
else
  echo "esp_idf_ci_docker_run.sh: missing pin" >&2
  echo "usage: bash tools/esp_idf_ci_docker_run.sh <vX.Y.Z>" >&2
  echo "   or: ESP_IDF_PIN=vX.Y.Z bash tools/esp_idf_ci_docker_run.sh" >&2
  exit 2
fi

if [[ ! "${pin}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "esp_idf_ci_docker_run.sh: invalid pin format: ${pin}" >&2
  exit 1
fi
if [[ "${pin}" != "${EXPECTED_ESP_IDF_PIN}" ]]; then
  echo "esp_idf_ci_docker_run.sh: pin must be ${EXPECTED_ESP_IDF_PIN}, got ${pin}" >&2
  exit 1
fi

if [[ "${NINLIL_ESP_CI_DRY_RUN:-}" == "1" ]]; then
  echo "esp_idf_ci_docker_run.sh dry-run OK pin=${pin} platform=${ESP_IDF_PLATFORM} image=${ESP_IDF_IMMUTABLE_IMAGE}"
  exit 0
fi

# Image/platform are literal argv (packaging gate static proof). Variables above
# document the same closed identity for dry-run diagnostics only.
docker run --rm --interactive \
  --platform linux/amd64 \
  --user 0:0 \
  -v "$PWD:/project" \
  -w /project \
  "docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb" \
  bash -s <<'NINLIL_ESP_CI'
set -euo pipefail
. "${IDF_PATH}/export.sh"
idf.py --version | grep -F "ESP-IDF v5.5.3"
# R2: mandatory Xtensa ESP32-S3 ABI compile of time_sample offsetof static_assert.
# Missing toolchain or compile failure ⇒ job fail (not optional / not host-only).
command -v xtensa-esp32s3-elf-gcc
xtensa-esp32s3-elf-gcc -std=c11 -ffreestanding \
  -I include \
  -c tests/radio/pcp_r2_time_sample_abi_static.c \
  -o /tmp/pcp_r2_time_sample_abi_esp32s3.o
test -s /tmp/pcp_r2_time_sample_abi_esp32s3.o
idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build
idf.py -C ports/esp-idf/hil_app set-target esp32s3 build
ELF=ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.elf
SMOKE_MAP=ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.map
HIL_MAP=ports/esp-idf/hil_app/build/ninlil_storage_powercut_hil.map
HIL_ELF=ports/esp-idf/hil_app/build/ninlil_storage_powercut_hil.elf
ARCHIVE=ports/esp-idf/smoke_app/build/esp-idf/ninlil/libninlil.a
SDK=ports/esp-idf/smoke_app/sdkconfig
# Prefer build/sdkconfig when present (idf may rewrite it there).
if [[ -f ports/esp-idf/smoke_app/build/config/sdkconfig.h ]]; then
  if [[ -f ports/esp-idf/smoke_app/build/sdkconfig ]]; then
    SDK=ports/esp-idf/smoke_app/build/sdkconfig
  fi
fi
test -f "$ELF"
test -f "$SMOKE_MAP"
test -f "$HIL_MAP"
test -f "$HIL_ELF"
test -f "$ARCHIVE"
# R2 ABI static_assert TU must be in ninlil component archive (ESP32-S3).
xtensa-esp32s3-elf-nm "${ARCHIVE}" | grep -E 'ninlil_pcp_r2_time_sample_abi_static_anchor'
python3 tools/esp_idf_app_main_frame_gate.py check \
  --elf "${ELF}" \
  --sdkconfig "${SDK}" \
  --objdump xtensa-esp32s3-elf-objdump
python3 tools/esp_idf_private_symbol_gate.py check \
  --elf "${ELF}" \
  --readelf xtensa-esp32s3-elf-readelf
# nm cross-check: private helper must not be text GLOBAL default-looking T
# without hidden (readelf is authoritative for DEFAULT vs HIDDEN).
xtensa-esp32s3-elf-nm -g "${ELF}" | tee /tmp/ninlil_nm_g.txt >/dev/null
if xtensa-esp32s3-elf-nm -g "${ELF}" | grep -E " ninlil_esp_idf_cell_config_stage_nested_owner$"; then
  echo "cell_config_stage_nested_owner must not be a global nm symbol" >&2
  exit 1
fi
python3 tools/esp_storage_public_api_gate.py \
  --archive "${ARCHIVE}" \
  --archive-kind target \
  --elf "${HIL_ELF}" \
  --nm xtensa-esp32s3-elf-nm \
  --readelf xtensa-esp32s3-elf-readelf \
  --compile-commands ports/esp-idf/smoke_app/build/compile_commands.json
# Both official maps are required (smoke placement + HIL placement).
python3 tools/esp_storage_map_gate.py "${SMOKE_MAP}"
python3 tools/esp_storage_map_gate.py "${HIL_MAP}"
find ports/esp-idf/smoke_app/build \( \
  -name "esp_storage_*.su" -o \
  -name "*esp_storage_model*.su" \) \
  | tee ports/esp-idf/smoke_app/build/ninlil_su_list.txt
# N6 production .su: collect actual ESP component objects only.
# Host ninlil_runtime_private.dir substitute is forbidden.
# Each exact .su basename must have find match count exactly 1
# (0 or 2+ ⇒ FAIL). head -1 first-match selection is forbidden.
N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
rm -rf "${N6_SU_DIR}"
mkdir -p "${N6_SU_DIR}"
for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
  mapfile -t matches < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil \
    -name "${name}" -type f 2>/dev/null | sort)
  n="${#matches[@]}"
  if [[ "${n}" -ne 1 ]]; then
    echo "ESP N6 .su ${name}: expected exactly 1 match, got ${n}" >&2
    echo "searched under ports/esp-idf/smoke_app/build/esp-idf/ninlil" >&2
    printf '%s\n' "${matches[@]}" >&2
    find ports/esp-idf/smoke_app/build -name '*.su' 2>/dev/null | head -50 >&2 || true
    exit 1
  fi
  found="${matches[0]}"
  test -f "${found}"
  cp "${found}" "${N6_SU_DIR}/${name}"
  test -s "${N6_SU_DIR}/${name}"
done
ls -la "${N6_SU_DIR}" | tee ports/esp-idf/smoke_app/build/ninlil_n6_su_list.txt
# Both --su-dir and --esp-su-dir point at the actual ESP N6 .su dir
# (not a host build tree). Gate enforces boot_scan<=1024 / all N6<=2048.
python3 tools/n6_frame_stack_gate.py check \
  --su-dir "${N6_SU_DIR}" \
  --esp-su-dir "${N6_SU_DIR}"
# ADR-0032/0033: the ESP package uses the same public Fabric/Composition
# implementation as Host, each exact once. The target probe executes every
# Composition API validation path without pretending flash FULL is attested.
composition_members=(
  nfl1_codec.c.obj
  fabric_private_util.c.obj
  fabric_workspace.c.obj
  fabric_private_records.c.obj
  fabric_private_select.c.obj
  fabric_private_core.c.obj
  fabric_v1_public.c.obj
  composition_v1.c.obj
)
for member in "${composition_members[@]}"; do
  count="$(xtensa-esp32s3-elf-ar t "${ARCHIVE}" \
    | grep -E "^${member}$" | wc -l | tr -d ' ')"
  if [[ "${count}" != "1" ]]; then
    echo "ESP Composition member ${member}: expected exact 1, got ${count}" >&2
    exit 1
  fi
done
composition_symbols=(
  ninlil_composition_v1_workspace_required
  ninlil_composition_v1_create
  ninlil_composition_v1_runtime
  ninlil_composition_v1_fabric
  ninlil_composition_v1_step
  ninlil_composition_v1_close_begin
  ninlil_composition_v1_close_poll
  ninlil_composition_v1_destroy
)
xtensa-esp32s3-elf-nm "${ELF}" > /tmp/ninlil_composition_nm.txt
for symbol in "${composition_symbols[@]}"; do
  grep -E "[[:space:]][Tt][[:space:]]${symbol}$" \
    /tmp/ninlil_composition_nm.txt
done
grep -F 'libninlil.a(composition_v1.c.obj)' "${SMOKE_MAP}"
grep -F 'libninlil.a(fabric_v1_public.c.obj)' "${SMOKE_MAP}"
composition_probe=ports/esp-idf/smoke_app/main/composition_public_target_smoke.c
test "$(grep -Ec '^#include "ninlil/composition_v1\.h"$' \
  "${composition_probe}")" = "1"
if grep -E '^#include "(src|drivers|ninlil_private|wifi_|r7_|rrmp_|mfdt_)' \
    "${composition_probe}"; then
  echo "public Composition target probe includes a private header" >&2
  exit 1
fi
# R7: after N6 stack gate only.  Inline python/heredoc before the N6
# gate confuses n6_frame_stack_gate structure analysis ($() + if).
# Component-archive compile alone is a false green: require exact
# source composition plus a real final-ELF reference.
test -f ports/esp-idf/smoke_app/build/compile_commands.json
python3 tools/r7_esp_link_presence_gate.py check \
  --compile-commands ports/esp-idf/smoke_app/build/compile_commands.json
grep -E '^CONFIG_MBEDTLS_HKDF_C=y$' "${SDK}"
for member in \
  r7_crypto_portable.c.obj \
  r7_crypto_nonce.c.obj \
  r7_crypto_mbedtls.c.obj \
  r7_context_binding.c.obj \
  r7_wire_codec.c.obj
do
  count="$(xtensa-esp32s3-elf-ar t "${ARCHIVE}" \
    | grep -E "^${member}$" | wc -l | tr -d ' ')"
  test "${count}" = "1"
done
# compile_commands: binding production TU exact once; no TEST_BUILD.
python3 - <<'PY'
import json
import pathlib
import sys
cc = pathlib.Path(
    "ports/esp-idf/smoke_app/build/compile_commands.json"
)
try:
    entries = json.loads(cc.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"false-green: cannot read compile_commands: {exc}", file=sys.stderr)
    sys.exit(1)
if not isinstance(entries, list):
    print("false-green: compile_commands is not a list", file=sys.stderr)
    sys.exit(1)
binding = 0
test_build = 0
for entry in entries:
    if not isinstance(entry, dict):
        continue
    file_path = entry.get("file")
    cmd = entry.get("command") or entry.get("arguments")
    if isinstance(file_path, str) and file_path.replace("\\", "/").endswith(
        "/src/radio/r7_context_binding.c"
    ):
        binding += 1
    text = ""
    if isinstance(cmd, str):
        text = cmd
    elif isinstance(cmd, list):
        text = " ".join(str(x) for x in cmd)
    if "NINLIL_R7_BINDING_TEST_BUILD" in text:
        test_build += 1
if binding != 1:
    print(
        f"false-green: r7_context_binding.c compile commands={binding} "
        f"(expected exact 1)",
        file=sys.stderr,
    )
    sys.exit(1)
if test_build != 0:
    print(
        "false-green: NINLIL_R7_BINDING_TEST_BUILD present in ESP compile",
        file=sys.stderr,
    )
    sys.exit(1)
print("T1b ESP compile_commands: binding=1 test_build=0")
PY
xtensa-esp32s3-elf-nm "${ELF}" > /tmp/ninlil_r7_nm.txt
for symbol in \
  ninlil_r7_crypto_mbedtls_provider_init \
  ninlil_r7_mbedtls_sha256 \
  ninlil_r7_mbedtls_hkdf_extract_sha256 \
  ninlil_r7_mbedtls_hkdf_expand_sha256 \
  ninlil_r7_mbedtls_aes128_gcm_seal \
  ninlil_r7_mbedtls_aes128_gcm_open \
  mbedtls_hkdf_extract \
  mbedtls_hkdf_expand
do
  grep -E "[[:space:]][Tt][[:space:]]${symbol}$" \
    /tmp/ninlil_r7_nm.txt
done
# docs/33 exact private T1b API set (6): final-ELF T/t presence.
# Smoke must reference all six so archive-only dead code cannot
# false-green. Test seams must be absent.
t1b_symbols=(
  ninlil_r7_encode_hop_binding
  ninlil_r7_encode_e2e_binding
  ninlil_r7_digest_hop_binding
  ninlil_r7_digest_e2e_binding
  ninlil_r7_derive_hop_key_bundle_verified
  ninlil_r7_derive_e2e_key_bundle_verified
)
if [[ "${#t1b_symbols[@]}" -ne 6 ]]; then
  echo "false-green: expected exact 6 R7 T1b binding symbols" >&2
  exit 1
fi
for symbol in "${t1b_symbols[@]}"; do
  grep -E "[[:space:]][Tt][[:space:]]${symbol}$" \
    /tmp/ninlil_r7_nm.txt
done
if grep -E 'ninlil_r7_binding_test_' /tmp/ninlil_r7_nm.txt; then
  echo "false-green: T1b test seam symbol present in ESP ELF" >&2
  exit 1
fi
# No extra GLOBAL ninlil_r7_*binding* production API spellings
# beyond the four encode/digest names (derive APIs omit 'binding';
# local static helpers are nm 't' and excluded by T-only filter).
printf '%s\n' \
  ninlil_r7_digest_e2e_binding \
  ninlil_r7_digest_hop_binding \
  ninlil_r7_encode_e2e_binding \
  ninlil_r7_encode_hop_binding \
  | sort > /tmp/ninlil_r7_t1b_binding_expected.txt
awk '$2 == "T" && $3 ~ /^ninlil_r7_.*binding/ { print $3 }' \
  /tmp/ninlil_r7_nm.txt | sort -u \
  > /tmp/ninlil_r7_t1b_binding_actual.txt
diff -u /tmp/ninlil_r7_t1b_binding_expected.txt \
  /tmp/ninlil_r7_t1b_binding_actual.txt
# Exact full T1b API multiset (6) — GLOBAL T only, like T1 wire.
printf '%s\n' "${t1b_symbols[@]}" | sort \
  > /tmp/ninlil_r7_t1b_api_expected.txt
{
  for symbol in "${t1b_symbols[@]}"; do
    awk -v s="${symbol}" \
      '$2 == "T" && $3 == s { print $3 }' /tmp/ninlil_r7_nm.txt
  done
} | sort -u > /tmp/ninlil_r7_t1b_api_actual.txt
diff -u /tmp/ninlil_r7_t1b_api_expected.txt \
  /tmp/ninlil_r7_t1b_api_actual.txt
# Live link into smoke: production object in map + APIs in final ELF
# (archive-only dead code cannot satisfy both).
grep -F 'libninlil.a(r7_context_binding.c.obj)' "${SMOKE_MAP}"
grep -F 'ninlil_r7_encode_hop_binding' "${SMOKE_MAP}"
grep -F 'ninlil_r7_derive_e2e_key_bundle_verified' "${SMOKE_MAP}"
# docs/32 exact private wire API set (8): final-ELF T/t presence.
wire_symbols=(
  ninlil_r7_wire_pack_outer_data_aad
  ninlil_r7_wire_parse_outer_data_aad
  ninlil_r7_wire_pack_e2e_single_aad
  ninlil_r7_wire_parse_e2e_single_aad
  ninlil_r7_wire_seal_e2e_single
  ninlil_r7_wire_open_e2e_single
  ninlil_r7_wire_seal_outer_single
  ninlil_r7_wire_open_outer_single
)
if [[ "${#wire_symbols[@]}" -ne 8 ]]; then
  echo "false-green: expected exact 8 R7 T1 wire symbols" >&2
  exit 1
fi
for symbol in "${wire_symbols[@]}"; do
  grep -E "[[:space:]][Tt][[:space:]]${symbol}$" \
    /tmp/ninlil_r7_nm.txt
done
printf '%s\n' "${wire_symbols[@]}" | sort \
  > /tmp/ninlil_r7_wire_expected.txt
awk '$2 == "T" && $3 ~ /^ninlil_r7_wire_/ { print $3 }' \
  /tmp/ninlil_r7_nm.txt | sort -u \
  > /tmp/ninlil_r7_wire_actual.txt
diff -u /tmp/ninlil_r7_wire_expected.txt \
  /tmp/ninlil_r7_wire_actual.txt
r7_hidden_count="$(xtensa-esp32s3-elf-readelf -Ws "${ELF}" \
  | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "HIDDEN" \
    && $8 == "ninlil_r7_crypto_mbedtls_provider_init" { n++ } \
    END { print n + 0 }')"
test "${r7_hidden_count}" = "1"
grep -F 'libninlil.a(r7_crypto_mbedtls.c.obj)' "${SMOKE_MAP}"
grep -F 'mbedtls_hkdf_extract' "${SMOKE_MAP}"
grep -F 'mbedtls_hkdf_expand' "${SMOKE_MAP}"
# U2: real public port symbols linked (init_object + ops, not link_anchor).
xtensa-esp32s3-elf-nm "${ELF}" | tee /tmp/ninlil_u2_nm.txt >/dev/null
grep -E 'ninlil_esp_idf_usb_cdc_(init_object|open|close|object_size)' \
  /tmp/ninlil_u2_nm.txt
if grep -E 'link_anchor' /tmp/ninlil_u2_nm.txt; then
  echo "link_anchor testing smell must not appear in ELF" >&2
  exit 1
fi
# No U1 POSIX usb serial object in ESP archive
if xtensa-esp32s3-elf-nm "${ARCHIVE}" | grep -E 'ninlil_posix_usb_serial'; then
  echo "U1 POSIX usb serial must not appear in ESP component archive" >&2
  exit 1
fi
# Control CDC isolation: no console init symbol in smoke ELF
if xtensa-esp32s3-elf-nm "${ELF}" | grep -E 'esp_tusb_init_console'; then
  echo "esp_tusb_init_console must not be linked for control CDC path" >&2
  exit 1
fi
# Expected USB CDC config in build sdkconfig / generated header
if ! grep -E '^CONFIG_TINYUSB_CDC_ENABLED=y' "${SDK}" 2>/dev/null; then
  grep -E 'CONFIG_TINYUSB_CDC_ENABLED[[:space:]]+1' \
    ports/esp-idf/smoke_app/build/config/sdkconfig.h
fi
# No test-only FORCE macro in target object compile commands
if grep -R 'NINLIL_POSIX_USB_SERIAL_FORCE' \
    ports/esp-idf/smoke_app/build/compile_commands.json 2>/dev/null; then
  echo "test-only FORCE macro must not appear in target compile" >&2
  exit 1
fi
# Structural lock pin still exact after resolve
python3 tools/esp_usb_cdc_u2_gate.py check
# Private FRAG packaging authority (default-OFF structural).
python3 tools/esp_idf_r7_frag_packaging_gate.py check
# Default (Kconfig OFF): FRAG TUs and target-smoke symbols must be absent.
if xtensa-esp32s3-elf-nm "${ARCHIVE}" | grep -E 'r7_frag_'; then
  echo "false-green: r7_frag object present in default-OFF component archive" >&2
  exit 1
fi
if xtensa-esp32s3-elf-nm "${ELF}" | grep -E 'ninlil_r7_frag_'; then
  echo "false-green: ninlil_r7_frag_* symbol present in default-OFF smoke ELF" >&2
  exit 1
fi
if grep -E 'r7_frag_' "${SMOKE_MAP}" | grep -v 'r7_frag_packaging\|r7_frag_private'; then
  # Map may mention path strings only when objects linked; reject object members.
  if grep -E 'libninlil\.a\(r7_frag_' "${SMOKE_MAP}"; then
    echo "false-green: r7_frag member in default-OFF map" >&2
    exit 1
  fi
fi
echo "R7 FRAG default-OFF: archive/ELF symbol absence OK"
# Enabled target proof: separate build dir + sdkconfig overlay (not default).
FRAG_ON_BUILD=ports/esp-idf/smoke_app/build-r7frag-on
rm -rf "${FRAG_ON_BUILD}"
idf.py -C ports/esp-idf/smoke_app -B "${FRAG_ON_BUILD}" \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.r7_frag_on" \
  set-target esp32s3 build
FRAG_ELF="${FRAG_ON_BUILD}/ninlil_m3_combined_smoke.elf"
FRAG_ARC="${FRAG_ON_BUILD}/esp-idf/ninlil/libninlil.a"
FRAG_MAP="${FRAG_ON_BUILD}/ninlil_m3_combined_smoke.map"
test -f "${FRAG_ELF}"
test -f "${FRAG_ARC}"
test -f "${FRAG_MAP}"
# Enabled: FRAG objects and smoke entry must be linked (not archive-dead).
xtensa-esp32s3-elf-nm "${FRAG_ARC}" | grep -E 'r7_frag_state|r7_frag_session|r7_frag_target_smoke'
xtensa-esp32s3-elf-nm "${FRAG_ELF}" | grep -E '[[:space:]][Tt][[:space:]]ninlil_r7_frag_target_smoke_run$'
grep -F 'libninlil.a(r7_frag_target_smoke.c.obj)' "${FRAG_MAP}" \
  || grep -F 'r7_frag_target_smoke.c.obj' "${FRAG_MAP}"
grep -F 'ninlil_r7_frag_target_smoke_run' "${FRAG_MAP}"
# Exact stack-usage gate for every production FRAG source (ceiling 4096).
FRAG_SU_DIR="${FRAG_ON_BUILD}/esp-idf/ninlil"
mkdir -p /tmp/ninlil_r7_frag_su
rm -rf /tmp/ninlil_r7_frag_su
mkdir -p /tmp/ninlil_r7_frag_su
# Collect each exact production-authority .su (count must be 1 per basename).
# Do not duplicate the source list here: additions to the CMake authority must
# automatically become required CI stack evidence in the same change.
while IFS= read -r _ident; do
  mapfile -t _hits < <(find "${FRAG_SU_DIR}" -type f -name "${_ident}.su" 2>/dev/null | sort)
  if [[ "${#_hits[@]}" -ne 1 ]]; then
    echo "false-green: expected exactly one ${_ident}.su, got ${#_hits[@]}" >&2
    exit 1
  fi
  cp -f "${_hits[0]}" "/tmp/ninlil_r7_frag_su/"
done < <(python3 tools/r7_frag_stack_gate.py list-production)
python3 tools/r7_frag_stack_gate.py check --su-dir /tmp/ninlil_r7_frag_su
# Public installed surface still has no FRAG headers (structural).
if grep -R 'r7_frag' include/ninlil ports/esp-idf/include 2>/dev/null; then
  echo "false-green: FRAG leaked into public include trees" >&2
  exit 1
fi
echo "R7 FRAG Kconfig-ON: ESP32-S3 compile/link + smoke + stack gate OK"

# --- MFDT V1 feature-ON (official linux/amd64): compile/link/map/stack ---
# Default smoke remains OFF; separate -B tree + sdkconfig overlay (not dry-run).
MFDT_ON_BUILD=ports/esp-idf/smoke_app/build-mfdt-on
rm -rf "${MFDT_ON_BUILD}"
idf.py -C ports/esp-idf/smoke_app -B "${MFDT_ON_BUILD}" \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.mfdt_on" \
  set-target esp32s3 build
MFDT_ELF="${MFDT_ON_BUILD}/ninlil_m3_combined_smoke.elf"
MFDT_MAP="${MFDT_ON_BUILD}/ninlil_m3_combined_smoke.map"
MFDT_ARC="${MFDT_ON_BUILD}/esp-idf/ninlil/libninlil.a"
MFDT_SDK_H="${MFDT_ON_BUILD}/config/sdkconfig.h"
test -f "${MFDT_ELF}" && test -s "${MFDT_ELF}"
test -f "${MFDT_MAP}" && test -s "${MFDT_MAP}"
test -f "${MFDT_ARC}"
grep -E 'CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE 1' "${MFDT_SDK_H}"
xtensa-esp32s3-elf-nm "${MFDT_ELF}" | tee /tmp/ninlil_mfdt_nm.txt >/dev/null
for sym in \
  ninlil_mfdt_v1_esp_store_bind \
  ninlil_mfdt_v1_ncl1_encode \
  ninlil_mfdt_v1_spine_arm_sender \
  ninlil_mfdt_v1_session_build_offer \
  ninlil_mfdt_v1_session_on_accept \
  ninlil_mfdt_v1_foundation_carrier_service_identity \
  ninlil_mfdt_v1_target_smoke_run
do
  grep -E "[[:space:]][Tt][[:space:]]${sym}$" /tmp/ninlil_mfdt_nm.txt
done
grep -F 'mfdt_v1_target_smoke.c' "${MFDT_MAP}"
grep -F 'mfdt_v1_store_esp.c' "${MFDT_MAP}"
if grep -F 'src/runtime/mfdt_v1/mfdt_v1_store.c' "${MFDT_MAP}"; then
  echo "false-green: host lab mfdt_v1_store.c linked into ESP MFDT map" >&2
  exit 1
fi
# Stack-usage evidence for portable MFDT TUs when .su present.
MFDT_SU_DIR="${MFDT_ON_BUILD}/ninlil_mfdt_su"
rm -rf "${MFDT_SU_DIR}"
mkdir -p "${MFDT_SU_DIR}"
for name in mfdt_v1_ncl1.c.su mfdt_v1_spine.c.su mfdt_v1_store_esp.c.su; do
  mapfile -t matches < <(find "${MFDT_ON_BUILD}/esp-idf/ninlil" \
    -name "${name}" -type f 2>/dev/null | sort)
  if [[ "${#matches[@]}" -eq 1 ]]; then
    cp "${matches[0]}" "${MFDT_SU_DIR}/${name}"
  fi
done
echo "MFDT V1 Kconfig-ON: ESP32-S3 compile/link/map OK"

# --- RRMP route-relay/multi-parent feature-ON (official linux/amd64) ---
RRMP_ON_BUILD=ports/esp-idf/smoke_app/build-rrmp-on
rm -rf "${RRMP_ON_BUILD}"
idf.py -C ports/esp-idf/smoke_app -B "${RRMP_ON_BUILD}" \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.rrmp_on" \
  set-target esp32s3 build
RRMP_ELF="${RRMP_ON_BUILD}/ninlil_m3_combined_smoke.elf"
RRMP_MAP="${RRMP_ON_BUILD}/ninlil_m3_combined_smoke.map"
RRMP_ARC="${RRMP_ON_BUILD}/esp-idf/ninlil/libninlil.a"
RRMP_SDK_H="${RRMP_ON_BUILD}/config/sdkconfig.h"
test -f "${RRMP_ELF}" && test -s "${RRMP_ELF}"
test -f "${RRMP_MAP}" && test -s "${RRMP_MAP}"
test -f "${RRMP_ARC}"
grep -E 'CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1 1' "${RRMP_SDK_H}"
xtensa-esp32s3-elf-nm "${RRMP_ELF}" | tee /tmp/ninlil_rrmp_nm.txt >/dev/null
for sym in \
  ninlil_route_install_batch \
  ninlil_parent_set_install \
  ninlil_rrmp_owner_init
do
  grep -E "[[:space:]][Tt][[:space:]]${sym}$|[[:space:]]${sym}$" \
    /tmp/ninlil_rrmp_nm.txt
done
if grep -E ' ninlil_rrmp_sim_' /tmp/ninlil_rrmp_nm.txt; then
  echo "false-green: host-only rrmp_sim symbols in ESP ELF" >&2
  exit 1
fi
for obj in rrmp_core.c.obj rrmp_codec.c.obj rrmp_store.c.obj rrmp_util.c.obj; do
  grep -F "${obj}" "${RRMP_MAP}"
done
python3 tools/rrmp_esp_dram_budget_gate.py check \
  --map "${RRMP_MAP}" \
  --sdkconfig "${RRMP_SDK_H}"
# Source-level frame/stack gate (no 4 KiB page temps; ceiling 2048).
python3 tools/rrmp_frame_stack_gate.py
# Collect .su evidence when toolchain emitted it (informational archive).
RRMP_SU_DIR="${RRMP_ON_BUILD}/ninlil_rrmp_su"
rm -rf "${RRMP_SU_DIR}"
mkdir -p "${RRMP_SU_DIR}"
for name in rrmp_core.c.su rrmp_codec.c.su rrmp_store.c.su rrmp_util.c.su; do
  mapfile -t matches < <(find "${RRMP_ON_BUILD}/esp-idf/ninlil" \
    -name "${name}" -type f 2>/dev/null | sort)
  if [[ "${#matches[@]}" -eq 1 ]]; then
    cp "${matches[0]}" "${RRMP_SU_DIR}/${name}"
  fi
done
echo "RRMP Kconfig-ON: ESP32-S3 compile/link/map/stack OK"

# --- Domain schema1 feature-ON (official linux/amd64) ---
DOMAIN_ON_BUILD=ports/esp-idf/smoke_app/build-domain-schema1-on
rm -rf "${DOMAIN_ON_BUILD}"
idf.py -C ports/esp-idf/smoke_app -B "${DOMAIN_ON_BUILD}" \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.domain_schema1_on" \
  set-target esp32s3 build
DOMAIN_ELF="${DOMAIN_ON_BUILD}/ninlil_m3_combined_smoke.elf"
DOMAIN_MAP="${DOMAIN_ON_BUILD}/ninlil_m3_combined_smoke.map"
DOMAIN_ARC="${DOMAIN_ON_BUILD}/esp-idf/ninlil/libninlil.a"
DOMAIN_SDK="${DOMAIN_ON_BUILD}/sdkconfig"
if [[ ! -f "${DOMAIN_SDK}" ]]; then
  DOMAIN_SDK=ports/esp-idf/smoke_app/sdkconfig
fi
test -f "${DOMAIN_ELF}" && test -s "${DOMAIN_ELF}"
test -f "${DOMAIN_MAP}" && test -s "${DOMAIN_MAP}"
test -f "${DOMAIN_ARC}"
grep -E '^CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=y$' "${DOMAIN_SDK}" \
  || grep -E 'CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING 1' \
    "${DOMAIN_ON_BUILD}/config/sdkconfig.h"
xtensa-esp32s3-elf-nm -g "${DOMAIN_ARC}" | tee /tmp/ninlil_domain_nm.txt >/dev/null
grep -E 'ninlil_domain_schema1_service_register|ninlil_domain_schema1_owner_run_storage_recovery' \
  /tmp/ninlil_domain_nm.txt
python3 tools/domain_schema1_memory_gate.py completion --esp-map "${DOMAIN_MAP}"
echo "Domain schema1 Kconfig-ON: ESP32-S3 compile/link/map OK"

# --- ALL private features simultaneous ON (combined overlay; not per-feature sub) ---
# Individual overlays prove each feature alone. This build is mandatory and must
# not be replaced by the sum of individual overlay builds.
ALLFEAT_OVERLAY=ports/esp-idf/smoke_app/sdkconfig.defaults.all_private_features_on
test -f "${ALLFEAT_OVERLAY}" \
  || { echo "false-green: missing combined all-private-features overlay" >&2; exit 1; }
# Fail-closed: combined overlay must list every private feature flag (not a stub).
for _k in \
  CONFIG_NINLIL_ENABLE_SX1262_R9=y \
  CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE=y \
  CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH=y \
  CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=y \
  CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE=y \
  CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=y \
  CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1=y \
  CONFIG_NINLIL_ENABLE_PRIVATE_FABRIC_V1=y
do
  grep -F "${_k}" "${ALLFEAT_OVERLAY}" \
    || { echo "false-green: combined overlay missing ${_k}" >&2; exit 1; }
done
ALLFEAT_ON_BUILD=ports/esp-idf/smoke_app/build-all-private-features-on
rm -rf "${ALLFEAT_ON_BUILD}"
# Isolate config from the default smoke sdkconfig; overlays must be authoritative.
idf.py -C ports/esp-idf/smoke_app -B "${ALLFEAT_ON_BUILD}" \
  -DSDKCONFIG="${PWD}/${ALLFEAT_ON_BUILD}/sdkconfig" \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;../wifi_hil_app/sdkconfig.defaults;sdkconfig.defaults.all_private_features_on" \
  set-target esp32s3 build
ALLFEAT_ELF="${ALLFEAT_ON_BUILD}/ninlil_m3_combined_smoke.elf"
ALLFEAT_MAP="${ALLFEAT_ON_BUILD}/ninlil_m3_combined_smoke.map"
ALLFEAT_ARC="${ALLFEAT_ON_BUILD}/esp-idf/ninlil/libninlil.a"
ALLFEAT_SDK_H="${ALLFEAT_ON_BUILD}/config/sdkconfig.h"
test -f "${ALLFEAT_ELF}" && test -s "${ALLFEAT_ELF}"
test -f "${ALLFEAT_MAP}" && test -s "${ALLFEAT_MAP}"
test -f "${ALLFEAT_ARC}"
# Every private feature must actually be compiled ON in the combined tree.
for _sym_h in \
  'CONFIG_NINLIL_ENABLE_SX1262_R9 1' \
  'CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE 1' \
  'CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH 1' \
  'CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING 1' \
  'CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE 1' \
  'CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1 1' \
  'CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1 1' \
  'CONFIG_NINLIL_ENABLE_PRIVATE_FABRIC_V1 1'
do
  grep -E "${_sym_h}" "${ALLFEAT_SDK_H}" \
    || { echo "false-green: combined build missing ${_sym_h}" >&2; exit 1; }
done
xtensa-esp32s3-elf-nm "${ALLFEAT_ELF}" | tee /tmp/ninlil_allfeat_elf_nm.txt >/dev/null
xtensa-esp32s3-elf-nm -g "${ALLFEAT_ARC}" | tee /tmp/ninlil_allfeat_arc_nm.txt >/dev/null
# Smoke entrypoints must be live in the ELF (not archive-dead).
for sym in \
  ninlil_r7_frag_target_smoke_run \
  ninlil_mfdt_v1_target_smoke_run \
  ninlil_rrmp_target_smoke_run
do
  grep -E "[[:space:]][Tt][[:space:]]${sym}$" /tmp/ninlil_allfeat_elf_nm.txt \
    || { echo "false-green: combined ELF missing live ${sym}" >&2; exit 1; }
done
# Remaining private families must at least package into the component archive.
for sym in \
  ninlil_domain_schema1_owner_run_storage_recovery \
  ninlil_v1_lab_radio_packet_link_init \
  ninlil_v1_lab_board_owner_step \
  ninlil_wifi_esp_owner_step
do
  grep -E "${sym}" /tmp/ninlil_allfeat_arc_nm.txt \
    || { echo "false-green: combined archive missing ${sym}" >&2; exit 1; }
done
echo "ALL private features simultaneous Kconfig-ON: ESP32-S3 compile/link/map OK"

# --- Wi-Fi V1 wifi_hil_app (official linux/amd64): compile/link/map ---
idf.py -C ports/esp-idf/wifi_hil_app set-target esp32s3 build
WIFI_ELF=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.elf
WIFI_MAP=ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.map
WIFI_COMPONENT_ARCHIVE=ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil/libninlil.a
test -f "${WIFI_ELF}" && test -s "${WIFI_ELF}"
test -f "${WIFI_MAP}" && test -s "${WIFI_MAP}"
test -f "${WIFI_COMPONENT_ARCHIVE}" && test -s "${WIFI_COMPONENT_ARCHIVE}"
WIFI_SDK=ports/esp-idf/wifi_hil_app/sdkconfig
if [[ -f ports/esp-idf/wifi_hil_app/build/sdkconfig ]]; then
  WIFI_SDK=ports/esp-idf/wifi_hil_app/build/sdkconfig
fi
WIFI_SDK_H=ports/esp-idf/wifi_hil_app/build/config/sdkconfig.h
test -f "${WIFI_SDK}"
test -f "${WIFI_SDK_H}"
grep -F 'CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y' "${WIFI_SDK}"
SU_ARGS=()
if [[ -d ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil ]]; then
  SU_ARGS=(--su-dir ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil)
fi
python3 tools/wifi_v1_esp_resource_gate.py \
  --map "${WIFI_MAP}" \
  --elf "${WIFI_ELF}" \
  --component-archive "${WIFI_COMPONENT_ARCHIVE}" \
  --expect-symbols \
  --expect-export-symbol \
  --check-acceptance \
  --sdkconfig "${WIFI_SDK}" \
  --sdkconfig-h "${WIFI_SDK_H}" \
  --max-owner-bytes 12288 \
  "${SU_ARGS[@]+"${SU_ARGS[@]}"}"
grep -E 'ninlil_wifi_esp_owner_init|ninlil_wifi_esp_owner_step|ninlil_wifi_nwb1_encode' \
  "${WIFI_MAP}"
echo "Wi-Fi V1 wifi_hil: ESP32-S3 compile/link/map OK"

# --- SX1262 radio_hil (official linux/amd64): R9 ON + final ELF/map gate ---
# Default smoke archive must have zero R9 symbols (Kconfig default n).
if xtensa-esp32s3-elf-nm "${ARCHIVE}" | grep -E ' ninlil_sx1262_phy_arm_tx$| ninlil_sx1262_r9_edge_init$'; then
  echo "false-green: R9 symbols present in default smoke archive (R9 must default OFF)" >&2
  exit 1
fi
if xtensa-esp32s3-elf-nm "${ELF}" | grep -E ' ninlil_sx1262_phy_arm_tx$| ninlil_sx1262_r9_edge_init$'; then
  echo "false-green: R9 symbols present in default smoke ELF (R9 must default OFF)" >&2
  exit 1
fi
echo "SX1262 R9 default-OFF: smoke archive/ELF zero-symbol OK"

idf.py -C ports/esp-idf/radio_hil_app set-target esp32s3 build
RADIO_ELF=ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.elf
RADIO_MAP=ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.map
RADIO_ARC=ports/esp-idf/radio_hil_app/build/esp-idf/ninlil/libninlil.a
RADIO_SDK=ports/esp-idf/radio_hil_app/sdkconfig
if [[ -f ports/esp-idf/radio_hil_app/build/sdkconfig ]]; then
  RADIO_SDK=ports/esp-idf/radio_hil_app/build/sdkconfig
fi
test -f "${RADIO_ELF}"
test -f "${RADIO_MAP}"
test -f "${RADIO_ARC}"
test -s "${RADIO_ELF}"
test -s "${RADIO_MAP}"
grep -E '^CONFIG_NINLIL_ENABLE_SX1262_R9=y$' "${RADIO_SDK}"
grep -E '^CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576$' "${RADIO_SDK}"
if grep -E '^CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y$' "${RADIO_SDK}"; then
  echo "release radio_hil must not enable SESSION_LEDGER_DIAG" >&2
  exit 1
fi
xtensa-esp32s3-elf-nm "${RADIO_ELF}" | tee ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt >/dev/null
# Flash FULL + recovery required; session ledger forbidden in release ELF/archive.
for sym in \
  ninlil_port_esp_storage_flash_bind \
  ninlil_port_esp_storage_config_production \
  ninlil_pcp_recover \
  ninlil_sx1262_board_profile_xiao_wio_sx1262_v1 \
  ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1 \
  ninlil_pcp_publish_initial_meta \
  app_main
do
  grep -E " [Tt] ${sym}$" ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt
done
# Local retained call-chain symbols (static in main / pcp).
for sym in handle_line cmd_init authority_init pcp_scan_namespace; do
  grep -E " [Tt] ${sym}$" ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt
done
if ! xtensa-esp32s3-elf-ar t "${RADIO_ARC}" | grep -E 'ninlil_sx1262_board_profiles'; then
  echo "false-green: board profile object missing from radio_hil archive" >&2
  exit 1
fi
for bad in ninlil_pcp_lab_session_ledger_init ninlil_pcp_lab_session_ledger_shutdown; do
  if grep -E " [Tt] ${bad}$" ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt; then
    echo "false-green: session ledger symbol in release radio_hil ELF: ${bad}" >&2
    exit 1
  fi
done
if xtensa-esp32s3-elf-ar t "${RADIO_ARC}" | grep -E 'pcp_lab_session_ledger'; then
  echo "false-green: session ledger object in release radio_hil archive" >&2
  exit 1
fi
if ! xtensa-esp32s3-elf-ar t "${RADIO_ARC}" | grep -E 'esp_storage_flash_media'; then
  echo "false-green: flash adapter object missing from radio_hil archive" >&2
  exit 1
fi
# Stack-usage evidence for call-chain + R9/PCP/R5/HAL TUs (real .su).
RADIO_SU_DIR=ports/esp-idf/radio_hil_app/build/ninlil_r9_su
rm -rf "${RADIO_SU_DIR}"
mkdir -p "${RADIO_SU_DIR}"
for name in \
  main.c.su \
  ninlil_sx1262_phy.c.su \
  sx1262_r9_edge.c.su \
  pcp_authority.c.su \
  profile_loader.c.su \
  radio_hal.c.su \
  airtime_calculator.c.su
do
  if [[ "${name}" == "main.c.su" ]]; then
    mapfile -t matches < <(find ports/esp-idf/radio_hil_app/build/esp-idf/main \
      -name "${name}" -type f 2>/dev/null | sort)
  else
    mapfile -t matches < <(find ports/esp-idf/radio_hil_app/build/esp-idf/ninlil \
      -name "${name}" -type f 2>/dev/null | sort)
  fi
  n="${#matches[@]}"
  if [[ "${n}" -ne 1 ]]; then
    echo "radio_hil .su ${name}: expected exactly 1 match, got ${n}" >&2
    find ports/esp-idf/radio_hil_app/build -name '*.su' 2>/dev/null | head -40 >&2 || true
    exit 1
  fi
  cp "${matches[0]}" "${RADIO_SU_DIR}/${name}"
  test -s "${RADIO_SU_DIR}/${name}"
done
# Retained multi-chain symbols (TX/new-epoch worst path).
for sym in \
  cmd_tx_data \
  ninlil_r5_issue \
  ninlil_r5_issue_with_bind \
  ninlil_pcp_issue \
  pcp_algorithm_e_body \
  pcp_rw_scan_check \
  pcp_scan_namespace
do
  grep -E " [Tt] ${sym}$" ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt
done
python3 tools/sx1262_radio_hil_elf_evidence_gate.py self-test
python3 tools/sx1262_radio_hil_elf_evidence_gate.py check \
  --elf "${RADIO_ELF}" \
  --map "${RADIO_MAP}" \
  --sdkconfig "${RADIO_SDK}" \
  --nm-dump ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt \
  --archive "${RADIO_ARC}" \
  --su-dir "${RADIO_SU_DIR}" \
  --out-json ports/esp-idf/radio_hil_app/build/ninlil_radio_hil_evidence.json
# Archive member presence for R9 authority TUs.
for member in \
  ninlil_sx1262_phy.c.obj \
  sx1262_r9_edge.c.obj \
  pcp_authority.c.obj \
  profile_loader.c.obj \
  radio_hal.c.obj
do
  count="$(xtensa-esp32s3-elf-ar t "${RADIO_ARC}" \
    | grep -E "^${member}$" | wc -l | tr -d ' ')"
  test "${count}" = "1"
done
python3 tools/sx1262_radio_hil_protocol.py not-run-evidence \
  --out-json ports/esp-idf/radio_hil_app/build/ninlil_radio_hil_physical.json
echo "SX1262 radio_hil official amd64 compile/link + multi-chain stack gate OK"

# Default-off V1 board profile: compile the real USB + single-hop owner with
# the existing flash adapter in a separate build. This proves target wiring
# only; it does not replace physical power-cut or USB/RF evidence.
(
  cd ports/esp-idf/radio_hil_app
  idf.py -B build-v1-board \
    -D SDKCONFIG=build-v1-board/sdkconfig.v1-board \
    -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.v1-board.defaults" \
    build
)
V1_BOARD_DIR=ports/esp-idf/radio_hil_app/build-v1-board
V1_BOARD_ELF="${V1_BOARD_DIR}/ninlil_radio_hil.elf"
V1_BOARD_SDK="${V1_BOARD_DIR}/sdkconfig.v1-board"
test -s "${V1_BOARD_ELF}"
for config in \
  CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE \
  CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH \
  CONFIG_NINLIL_RADIO_HIL_V1_BOARD
do
  grep -E "^${config}=y$" "${V1_BOARD_SDK}"
done
if grep -E '^CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y$' "${V1_BOARD_SDK}"; then
  echo "V1 board target must not enable SESSION_LEDGER_DIAG" >&2
  exit 1
fi
xtensa-esp32s3-elf-nm "${V1_BOARD_ELF}" > "${V1_BOARD_DIR}/ninlil_v1_board.nm.txt"
for sym in \
  app_main \
  ninlil_esp_idf_usb_cdc_open \
  ninlil_port_esp_storage_config_production \
  ninlil_port_esp_storage_flash_bind \
  ninlil_v1_lab_provisioner_init_controller \
  ninlil_v1_lab_board_owner_init \
  ninlil_v1_lab_board_owner_step
do
  grep -E " [Tt] ${sym}$" "${V1_BOARD_DIR}/ninlil_v1_board.nm.txt"
done
if grep -E ' [Tt] ninlil_pcp_lab_session_ledger_' "${V1_BOARD_DIR}/ninlil_v1_board.nm.txt"; then
  echo "V1 board target linked diagnostic session-ledger symbols" >&2
  exit 1
fi
echo "V1 USB+SX1262 board target compile/link OK (flash candidate, not physical HIL)"

# The generic peer is the same board owner with one fixed build-time role
# bit. Build it separately so peer adoption cannot exist only in Host tests.
(
  cd ports/esp-idf/radio_hil_app
  idf.py -B build-v1-peer \
    -D SDKCONFIG=build-v1-peer/sdkconfig.v1-peer \
    -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.v1-board.defaults;sdkconfig.v1-peer.defaults" \
    build
)
V1_PEER_DIR=ports/esp-idf/radio_hil_app/build-v1-peer
V1_PEER_ELF="${V1_PEER_DIR}/ninlil_radio_hil.elf"
V1_PEER_SDK="${V1_PEER_DIR}/sdkconfig.v1-peer"
test -s "${V1_PEER_ELF}"
for config in \
  CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE \
  CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH \
  CONFIG_NINLIL_RADIO_HIL_V1_BOARD \
  CONFIG_NINLIL_RADIO_HIL_V1_PEER
do
  grep -E "^${config}=y$" "${V1_PEER_SDK}"
done
if grep -E '^CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y$' "${V1_PEER_SDK}"; then
  echo "V1 peer target must not enable SESSION_LEDGER_DIAG" >&2
  exit 1
fi
xtensa-esp32s3-elf-nm "${V1_PEER_ELF}" > "${V1_PEER_DIR}/ninlil_v1_peer.nm.txt"
for sym in \
  app_main \
  ninlil_esp_idf_usb_cdc_open \
  ninlil_port_esp_storage_config_production \
  ninlil_port_esp_storage_flash_bind \
  ninlil_v1_lab_provisioner_init_peer \
  ninlil_v1_lab_board_owner_init \
  ninlil_v1_lab_board_owner_step
do
  grep -E " [Tt] ${sym}$" "${V1_PEER_DIR}/ninlil_v1_peer.nm.txt"
done
if grep -E ' [Tt] ninlil_pcp_lab_session_ledger_' "${V1_PEER_DIR}/ninlil_v1_peer.nm.txt"; then
  echo "V1 peer target linked diagnostic session-ledger symbols" >&2
  exit 1
fi
echo "V1 generic peer USB+SX1262 target compile/link OK (flash candidate, not physical HIL)"
NINLIL_ESP_CI
