#!/usr/bin/env bash
# Host CI matrix for software-completion private features (default-OFF).
#
# Fail-closed: introspects ctest -N / cmake targets; never invents names.
# Does not claim SPEC_ACCEPTED, physical HIL, RF, or public ABI promotion.
#
# Usage:
#   tools/ci_completion_feature_host_matrix.sh <family> <profile>
#
# Families:
#   domain_schema1 | fabric_v1 | r7_frag | rrmp | all
# Profiles:
#   off_residual | on_normal | on_asan | tests_off_boundary | all_profiles
#
# Env:
#   NINLIL_CI_COMPLETION_ROOT  — repo root (default: parent of tools/)
#   NINLIL_CI_COMPLETION_JOBS  — cmake/ctest parallel (default: 2)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${NINLIL_CI_COMPLETION_ROOT:-$ROOT}"
cd "${ROOT}"
JOBS="${NINLIL_CI_COMPLETION_JOBS:-2}"

FAMILY="${1:-}"
PROFILE="${2:-}"
if [[ -z "${FAMILY}" || -z "${PROFILE}" ]]; then
  echo "usage: $0 <domain_schema1|fabric_v1|r7_frag|rrmp|all> <off_residual|on_normal|on_asan|tests_off_boundary|all_profiles>" >&2
  exit 2
fi

log() { printf '+ %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_cmd cmake
require_cmd ctest
require_cmd ninja
require_cmd nm

# ---- introspection helpers -------------------------------------------------

ctest_names() {
  local build_dir="$1"
  ctest --test-dir "${build_dir}" -N 2>/dev/null | sed -n 's/^  Test[ ]*#[0-9]*: //p'
}

require_tests_present() {
  local build_dir="$1"
  shift
  local names
  names="$(ctest_names "${build_dir}")"
  local missing=0
  local want
  for want in "$@"; do
    if ! printf '%s\n' "${names}" | grep -E "^${want}$" >/dev/null; then
      echo "false-green: expected ctest '${want}' absent in ${build_dir}" >&2
      missing=1
    fi
  done
  if [[ "${missing}" -ne 0 ]]; then
    echo "registered tests in ${build_dir}:" >&2
    printf '%s\n' "${names}" | head -200 >&2
    exit 1
  fi
}

require_tests_absent_regex() {
  local build_dir="$1"
  local regex="$2"
  local label="$3"
  if ctest_names "${build_dir}" | grep -E "${regex}" >/dev/null; then
    echo "false-green: ${label}: tests matching /${regex}/ registered in ${build_dir}" >&2
    ctest_names "${build_dir}" | grep -E "${regex}" >&2
    exit 1
  fi
}

require_build_targets() {
  local build_dir="$1"
  shift
  local t
  for t in "$@"; do
    if ! cmake --build "${build_dir}" --target help 2>/dev/null | grep -E "^${t}: " >/dev/null \
      && ! ninja -C "${build_dir}" -t targets 2>/dev/null | grep -E "^${t}:" >/dev/null; then
      # Fallback: try building (fail if missing).
      if ! cmake --build "${build_dir}" --parallel "${JOBS}" --target "${t}" 2>/dev/null; then
        echo "false-green: expected build target '${t}' missing or failed in ${build_dir}" >&2
        exit 1
      fi
    fi
  done
}

build_targets_or_fail() {
  local build_dir="$1"
  shift
  if [[ "$#" -eq 0 ]]; then
    echo "build_targets_or_fail: no targets" >&2
    exit 1
  fi
  log "build targets in ${build_dir}: $*"
  cmake --build "${build_dir}" --parallel "${JOBS}" --target "$@"
}

run_ctest_regex() {
  local build_dir="$1"
  local regex="$2"
  local listed
  listed="$(ctest --test-dir "${build_dir}" -N -R "${regex}" 2>/dev/null | tail -n 1 || true)"
  if [[ "${listed}" == "Total Tests: 0" ]]; then
    echo "false-green: ctest -R '${regex}' matched 0 tests in ${build_dir}" >&2
    exit 1
  fi
  log "ctest -R '${regex}' in ${build_dir} (${listed})"
  ctest --test-dir "${build_dir}" --output-on-failure --parallel 1 --no-tests=error -R "${regex}"
}

configure_ninja() {
  local build_dir="$1"
  shift
  log "configure ${build_dir}: $*"
  cmake -S "${ROOT}" -B "${build_dir}" -G Ninja "$@"
}

# ---- domain schema1 --------------------------------------------------------

domain_off_residual() {
  local b="build/ci-domain-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=OFF
  build_targets_or_fail "${b}" ninlil_runtime ninlil_runtime_private \
    ninlil_domain_schema1_runtime_binding_test
  # Feature-gated owner test must not appear when OFF.
  require_tests_absent_regex "${b}" '^domain_schema1_startup_owner$' "domain OFF residual"
  require_tests_absent_regex "${b}" '^domain_schema1_memory_gate_' "domain OFF residual memory"
  # Always-on unit tests still register (compile private TUs with feature def ON in test binary).
  require_tests_present "${b}" \
    domain_schema1_runtime_binding \
    domain_schema1_runtime_binding_feature_symbol_archive \
    domain_schema1_runtime_binding_bridge \
    domain_schema1_startup_authority
  build_targets_or_fail "${b}" ninlil_runtime_private
  ctest --test-dir "${b}" --output-on-failure --no-tests=error \
    -R 'domain_schema1_runtime_binding_feature_symbol_archive'
  # Private archive must have zero domain_schema1 symbols when OFF.
  nm -g -U "${b}/libninlil_runtime_private.a" 2>/dev/null \
    | grep -E 'ninlil_domain_schema1_' \
    && {
      echo "false-green: domain_schema1 symbols in feature-OFF private archive" >&2
      exit 1
    } || true
  log "domain_schema1 OFF residual OK"
}

domain_on_normal() {
  local b="build/ci-domain-on"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON
  build_targets_or_fail "${b}" \
    ninlil_runtime \
    ninlil_runtime_private \
    ninlil_domain_schema1_runtime_binding_test \
    ninlil_domain_schema1_runtime_binding_bridge_test \
    ninlil_domain_schema1_startup_authority_test \
    ninlil_domain_schema1_startup_owner_test \
    ninlil_domain_schema1_publication_not_ready_test
  require_tests_present "${b}" \
    domain_schema1_runtime_binding \
    domain_schema1_runtime_binding_bridge \
    domain_schema1_startup_authority \
    domain_schema1_startup_owner \
    domain_schema1_publication_not_ready \
    domain_schema1_runtime_binding_feature_symbol_archive \
    domain_schema1_runtime_binding_vector_bridge \
    domain_schema1_memory_gate_host_only \
    host_runtime_tests_off_installed_consumer_domain_on
  run_ctest_regex "${b}" \
    '^(domain_schema1_|host_runtime_tests_off_installed_consumer_domain_on)'
  log "domain_schema1 ON normal OK"
}

domain_on_asan() {
  local b="build/ci-domain-asan"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DNINLIL_ENABLE_SANITIZERS=ON \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON
  build_targets_or_fail "${b}" \
    ninlil_domain_schema1_runtime_binding_test \
    ninlil_domain_schema1_runtime_binding_bridge_test \
    ninlil_domain_schema1_startup_authority_test \
    ninlil_domain_schema1_startup_owner_test
  require_tests_present "${b}" \
    domain_schema1_runtime_binding \
    domain_schema1_startup_owner \
    domain_schema1_startup_authority
  ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1}" \
  UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    run_ctest_regex "${b}" \
      '^(domain_schema1_runtime_binding|domain_schema1_runtime_binding_bridge|domain_schema1_startup_authority|domain_schema1_startup_owner)$'
  log "domain_schema1 ON ASan/UBSan OK"
}

domain_tests_off_boundary() {
  local b="build/ci-domain-tests-off"
  local pref="${b}/install"
  # Default OFF install: no domain symbols.
  configure_ninja "${b}-off" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_BUILD_HOST_RUNTIME=ON \
    -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=OFF
  cmake --build "${b}-off" --parallel "${JOBS}"
  _toff="$(ctest --test-dir "${b}-off" -N 2>&1 || true)"
  if ! printf '%s\n' "${_toff}" | grep -E 'Total Tests:[ \t]*0|No tests were found' >/dev/null; then
    echo "false-green: domain tests-OFF registered tests unexpectedly" >&2
    printf '%s\n' "${_toff}" >&2
    exit 1
  fi
  cmake --install "${b}-off" --prefix "${pref}-off"
  if find "${pref}-off" -iname '*domain_schema1*' | grep -q .; then
    echo "false-green: domain_schema1 path in tests-OFF feature-OFF install" >&2
    find "${pref}-off" -iname '*domain_schema1*'
    exit 1
  fi
  # Domain ON tests-OFF install consumer / symbol boundary via cmake smoke authority.
  # Invoke the same scripted smoke used by CTest when tests are ON.
  cmake -DNINLIL_SOURCE_DIR="${ROOT}" \
    -DNINLIL_PARENT_BUILD_DIR="${b}-smoke-parent" \
    -DNINLIL_GENERATOR=Ninja \
    -DNINLIL_CTEST_COMMAND="$(command -v ctest)" \
    -DNINLIL_SMOKE_WITH_SQLITE=OFF \
    -DNINLIL_SMOKE_DOMAIN_SCHEMA1=ON \
    -P "${ROOT}/cmake/installed_host_runtime_tests_off_smoke.cmake"
  log "domain_schema1 tests-OFF install/symbol boundary OK"
}

# ---- fabric v1 -------------------------------------------------------------

fabric_off_residual() {
  local b="build/ci-fabric-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=OFF \
    -DNINLIL_ENABLE_PRIVATE_WIFI_V1=OFF
  build_targets_or_fail "${b}" \
    ninlil_runtime_private \
    ninlil_fabric_v1_nfl1_codec_test \
    ninlil_fabric_v1_lifecycle_test \
    ninlil_fabric_v1_host_acceptance_test
  require_tests_present "${b}" \
    fabric_v1_nfl1_codec \
    fabric_v1_lifecycle \
    fabric_v1_private_feature_symbol_archive
  # OFF: private archive must not carry fabric_private symbols.
  ctest --test-dir "${b}" --output-on-failure --no-tests=error \
    -R '^fabric_v1_private_feature_symbol_archive$'
  nm -g -U "${b}/libninlil_runtime_private.a" 2>/dev/null \
    | grep -E 'ninlil_fabric_private_' \
    && {
      echo "false-green: fabric symbols in feature-OFF private archive" >&2
      exit 1
    } || true
  log "fabric_v1 OFF residual OK"
}

fabric_on_normal() {
  local b="build/ci-fabric-on"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
    -DNINLIL_ENABLE_PRIVATE_WIFI_V1=OFF
  build_targets_or_fail "${b}" \
    ninlil_runtime_private \
    ninlil_fabric_v1_public_api_test \
    ninlil_fabric_v1_public_behavior_test \
    ninlil_fabric_v1_nfl1_codec_test \
    ninlil_fabric_v1_lifecycle_test \
    ninlil_fabric_v1_p1_contracts_test \
    ninlil_fabric_v1_selection_test \
    ninlil_fabric_v1_records_test \
    ninlil_fabric_v1_nfl1_semantic_test \
    ninlil_fabric_v1_vector_matrix_test \
    ninlil_fabric_v1_host_acceptance_test
  require_tests_present "${b}" \
    fabric_v1_public_api \
    fabric_v1_public_behavior \
    fabric_v1_nfl1_codec \
    fabric_v1_lifecycle \
    fabric_v1_p1_contracts \
    fabric_v1_selection \
    fabric_v1_records \
    fabric_v1_nfl1_semantic \
    fabric_v1_vector_matrix \
    fabric_v1_host_acceptance \
    fabric_v1_private_feature_symbol_archive
  run_ctest_regex "${b}" '^fabric_v1_'
  # Direct driver (non-CMake) normal path.
  CC=gcc bash tools/run_fabric_v1_direct_tests.sh
  # Toolchain / ILP32 evidence (install arm-none-eabi when available).
  bash tools/fabric_v1_toolchain_evidence.sh
  log "fabric_v1 ON normal + direct + toolchain OK"
}

fabric_on_asan() {
  local b="build/ci-fabric-asan"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DNINLIL_ENABLE_SANITIZERS=ON \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON
  build_targets_or_fail "${b}" \
    ninlil_fabric_v1_nfl1_codec_test \
    ninlil_fabric_v1_lifecycle_test \
    ninlil_fabric_v1_p1_contracts_test \
    ninlil_fabric_v1_selection_test \
    ninlil_fabric_v1_records_test \
    ninlil_fabric_v1_nfl1_semantic_test \
    ninlil_fabric_v1_vector_matrix_test \
    ninlil_fabric_v1_host_acceptance_test
  ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1}" \
  UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    run_ctest_regex "${b}" \
      '^(fabric_v1_nfl1_codec|fabric_v1_lifecycle|fabric_v1_p1_contracts|fabric_v1_selection|fabric_v1_records|fabric_v1_nfl1_semantic|fabric_v1_vector_matrix|fabric_v1_host_acceptance)$'
  CC=clang bash tools/run_fabric_v1_direct_tests.sh --asan
  log "fabric_v1 ON ASan OK"
}

fabric_tests_off_boundary() {
  local b="build/ci-fabric-tests-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=OFF
  cmake --build "${b}" --parallel "${JOBS}"
  cmake --install "${b}" --prefix "${b}/install"
  if find "${b}/install" \( -iname '*fabric_v1*' -o -iname '*nfl1*' \) | grep -q .; then
    echo "false-green: fabric private path in tests-OFF install" >&2
    find "${b}/install" \( -iname '*fabric_v1*' -o -iname '*nfl1*' \)
    exit 1
  fi
  # Feature ON still non-installed (private candidate).
  configure_ninja "${b}-on" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON
  # Build the normal install set as well as the EXCLUDE_FROM_ALL private
  # archive.  Building only ninlil_runtime_private leaves installed public
  # archives (for example the optional POSIX SQLite port) absent.
  cmake --build "${b}-on" --parallel "${JOBS}"
  cmake --build "${b}-on" --parallel "${JOBS}" --target ninlil_runtime_private
  cmake --install "${b}-on" --prefix "${b}-on/install"
  if find "${b}-on/install" \( -iname '*fabric_v1*' -o -path '*/include/*fabric*' \) | grep -q .; then
    echo "false-green: fabric private headers/path installed under tests-OFF feature-ON" >&2
    find "${b}-on/install" \( -iname '*fabric_v1*' -o -path '*/include/*fabric*' \)
    exit 1
  fi
  # Public installed headers must not expose private fabric API.
  if grep -R 'ninlil_fabric_private_' "${b}-on/install/include" 2>/dev/null; then
    echo "false-green: fabric private symbol names in installed headers" >&2
    exit 1
  fi
  log "fabric_v1 tests-OFF non-installed boundary OK"
}

# ---- r7 frag ---------------------------------------------------------------

r7_frag_off_residual() {
  local b="build/ci-r7frag-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_R7_FRAG_PRIVATE=OFF
  build_targets_or_fail "${b}" ninlil_runtime
  require_tests_absent_regex "${b}" 'nrw1_frag_|r7_frag_' "r7_frag OFF residual"
  # Packaging structural gate always available.
  python3 tools/esp_idf_r7_frag_packaging_gate.py check
  log "r7_frag OFF residual OK"
}

r7_frag_on_normal() {
  local b="build/ci-r7frag-on"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON
  # Introspect: private suite must register.
  require_tests_present "${b}" \
    nrw1_frag_state_private \
    nrw1_frag_ack_ledger_private \
    nrw1_frag_durable_snapshot_private \
    nrw1_frag_session_private \
    nrw1_frag_completion_private \
    nrw1_frag_target_smoke_private \
    nrw1_frag_private_build
  build_targets_or_fail "${b}" \
    ninlil_r7_frag_private \
    ninlil_r7_frag_state_test \
    ninlil_r7_frag_ack_ledger_test \
    ninlil_r7_frag_durable_snapshot_test \
    ninlil_r7_frag_session_test \
    ninlil_r7_frag_completion_test \
    ninlil_r7_frag_target_smoke_test
  # prod_integration is optional on target graph when n6 testbuild exists.
  if ninja -C "${b}" -t targets 2>/dev/null | grep -E '^ninlil_r7_frag_prod_integration_test:' >/dev/null \
    || cmake --build "${b}" --target help 2>/dev/null | grep -E 'ninlil_r7_frag_prod_integration_test' >/dev/null; then
    build_targets_or_fail "${b}" ninlil_r7_frag_prod_integration_test
  fi
  run_ctest_regex "${b}" 'nrw1_frag_'
  python3 tools/r7_frag_false_green_gate.py
  # Direct non-CMake path (also ASan inside script).
  CC=clang bash tools/run_r7_frag_direct_tests.sh
  log "r7_frag ON normal OK"
}

r7_frag_on_asan() {
  local b="build/ci-r7frag-asan"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DNINLIL_ENABLE_SANITIZERS=ON \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON
  require_tests_present "${b}" \
    nrw1_frag_state_private \
    nrw1_frag_session_private \
    nrw1_frag_target_smoke_private
  build_targets_or_fail "${b}" \
    ninlil_r7_frag_state_test \
    ninlil_r7_frag_ack_ledger_test \
    ninlil_r7_frag_durable_snapshot_test \
    ninlil_r7_frag_session_test \
    ninlil_r7_frag_completion_test \
    ninlil_r7_frag_target_smoke_test
  ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1}" \
  UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    run_ctest_regex "${b}" \
      '^(nrw1_frag_state_private|nrw1_frag_ack_ledger_private|nrw1_frag_durable_snapshot_private|nrw1_frag_session_private|nrw1_frag_completion_private|nrw1_frag_target_smoke_private|nrw1_frag_prod_integration_private|nrw1_frag_stack_gate_host_su)$'
  log "r7_frag ON ASan/UBSan OK"
}

r7_frag_tests_off_boundary() {
  local b="build/ci-r7frag-tests-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_R7_FRAG_PRIVATE=OFF
  cmake --build "${b}" --parallel "${JOBS}"
  cmake --install "${b}" --prefix "${b}/install"
  if find "${b}/install" -iname '*r7_frag*' | grep -q .; then
    echo "false-green: r7_frag path in tests-OFF install" >&2
    find "${b}/install" -iname '*r7_frag*'
    exit 1
  fi
  # Feature ON + tests OFF: still non-installed private candidate.
  configure_ninja "${b}-on" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON
  cmake --build "${b}-on" --parallel "${JOBS}"
  cmake --install "${b}-on" --prefix "${b}-on/install"
  if find "${b}-on/install" -iname '*r7_frag*' | grep -q .; then
    echo "false-green: r7_frag installed under tests-OFF feature-ON" >&2
    find "${b}-on/install" -iname '*r7_frag*'
    exit 1
  fi
  if grep -R 'r7_frag' "${b}-on/install/include" 2>/dev/null; then
    echo "false-green: r7_frag leaked into installed headers" >&2
    exit 1
  fi
  python3 tools/esp_idf_r7_frag_packaging_gate.py check
  log "r7_frag installed/tests-OFF boundary OK"
}

# ---- route-relay / multi-parent --------------------------------------------

rrmp_off_residual() {
  local b="build/ci-rrmp-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF
  build_targets_or_fail "${b}" \
    ninlil_runtime_private \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test \
    ninlil_rrmp_prod_off_proxy
  require_tests_present "${b}" \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test \
    rrmp_private_feature_symbol_archive \
    rrmp_private_feature_symbol_prod_off_proxy
  require_tests_absent_regex "${b}" '^rrmp_private_feature_symbol_probe$' "rrmp OFF residual probe"
  run_ctest_regex "${b}" '^(ninlil_rrmp_|rrmp_private_|route_relay_multiparent_)'
  nm -g -U "${b}/libninlil_runtime_private.a" 2>/dev/null \
    | grep -E ' ninlil_(rrmp_owner_init|route_install_batch)$' \
    && {
      echo "false-green: rrmp catalog symbols in feature-OFF production archive" >&2
      exit 1
    } || true
  log "rrmp OFF residual OK"
}

rrmp_on_normal() {
  local b="build/ci-rrmp-on"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
  require_tests_present "${b}" \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test \
    rrmp_private_feature_symbol_probe \
    rrmp_private_feature_symbol_archive
  build_targets_or_fail "${b}" \
    ninlil_runtime_private \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test \
    ninlil_rrmp_private_probe
  run_ctest_regex "${b}" '^(ninlil_rrmp_|rrmp_private_|route_relay_multiparent_)'
  python3 tools/rrmp_frame_stack_gate.py
  python3 tools/rrmp_storage_abi_gate.py
  # Physical residual template: NOT_RUN only (no physical claim).
  test -f tools/rrmp_hil_evidence_template.json
  grep -F '"status": "NOT_RUN"' tools/rrmp_hil_evidence_template.json
  grep -F '"rf_2hop": "NOT_RUN"' tools/rrmp_hil_evidence_template.json
  log "rrmp ON normal OK"
}

rrmp_on_asan() {
  local b="build/ci-rrmp-asan"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DNINLIL_ENABLE_SANITIZERS=ON \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
  build_targets_or_fail "${b}" \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test
  require_tests_present "${b}" \
    ninlil_rrmp_codec_test \
    ninlil_rrmp_sm_test \
    ninlil_rrmp_crash_corrupt_test \
    ninlil_rrmp_storage_atomicity_test \
    ninlil_rrmp_token_ledger_test \
    ninlil_rrmp_sim_lifecycle_test \
    ninlil_rrmp_composition_test \
    ninlil_rrmp_fabric_two_instance_isolation_test
  ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1}" \
  UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    run_ctest_regex "${b}" '^ninlil_rrmp_'
  log "rrmp ON ASan/UBSan OK"
}

rrmp_tests_off_boundary() {
  local b="build/ci-rrmp-tests-off"
  configure_ninja "${b}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF
  cmake --build "${b}" --parallel "${JOBS}"
  cmake --install "${b}" --prefix "${b}/install"
  if find "${b}/install" \( -iname '*rrmp*' -o -iname '*route_relay*' \) | grep -q .; then
    echo "false-green: rrmp path in tests-OFF install" >&2
    find "${b}/install" \( -iname '*rrmp*' -o -iname '*route_relay*' \)
    exit 1
  fi
  configure_ninja "${b}-on" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNINLIL_BUILD_TESTS=OFF \
    -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
  # Build the normal install set as well as the EXCLUDE_FROM_ALL private
  # archive.  Building only ninlil_runtime_private leaves installed public
  # archives (for example the optional POSIX SQLite port) absent.
  cmake --build "${b}-on" --parallel "${JOBS}"
  cmake --build "${b}-on" --parallel "${JOBS}" --target ninlil_runtime_private
  cmake --install "${b}-on" --prefix "${b}-on/install"
  if find "${b}-on/install" \( -iname '*rrmp*' -o -iname '*route_relay*' \) | grep -q .; then
    echo "false-green: rrmp installed under tests-OFF feature-ON" >&2
    exit 1
  fi
  if grep -R 'ninlil_route_install_batch\|ninlil_rrmp_owner_init' \
    "${b}-on/install/include" 2>/dev/null; then
    echo "false-green: rrmp private API in installed headers" >&2
    exit 1
  fi
  log "rrmp installed/tests-OFF boundary OK"
}

# ---- dispatch --------------------------------------------------------------

run_family_profile() {
  local family="$1"
  local profile="$2"
  case "${family}:${profile}" in
    domain_schema1:off_residual) domain_off_residual ;;
    domain_schema1:on_normal) domain_on_normal ;;
    domain_schema1:on_asan) domain_on_asan ;;
    domain_schema1:tests_off_boundary) domain_tests_off_boundary ;;
    fabric_v1:off_residual) fabric_off_residual ;;
    fabric_v1:on_normal) fabric_on_normal ;;
    fabric_v1:on_asan) fabric_on_asan ;;
    fabric_v1:tests_off_boundary) fabric_tests_off_boundary ;;
    r7_frag:off_residual) r7_frag_off_residual ;;
    r7_frag:on_normal) r7_frag_on_normal ;;
    r7_frag:on_asan) r7_frag_on_asan ;;
    r7_frag:tests_off_boundary) r7_frag_tests_off_boundary ;;
    rrmp:off_residual) rrmp_off_residual ;;
    rrmp:on_normal) rrmp_on_normal ;;
    rrmp:on_asan) rrmp_on_asan ;;
    rrmp:tests_off_boundary) rrmp_tests_off_boundary ;;
    *:all_profiles)
      run_family_profile "${family}" off_residual
      run_family_profile "${family}" on_normal
      run_family_profile "${family}" on_asan
      run_family_profile "${family}" tests_off_boundary
      ;;
    all:*)
      for f in domain_schema1 fabric_v1 r7_frag rrmp; do
        run_family_profile "${f}" "${profile}"
      done
      ;;
    *)
      echo "unknown family/profile: ${family}/${profile}" >&2
      exit 2
      ;;
  esac
}

run_family_profile "${FAMILY}" "${PROFILE}"
echo "ci_completion_feature_host_matrix: PASS family=${FAMILY} profile=${PROFILE}"
