#!/usr/bin/env bash
# CMake-built coexistence proof + test-only multi-process transport fixture.
# Strict greps only — no soft fallbacks. Timeout + orphan cleanup.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=1:detect_stack_use_after_return=1:detect_leaks=0}"

DRIVER="${HOST_COMPLETION_DRIVER:-}"
COEXISTENCE_PROBE="${HOST_COMPLETION_COEXISTENCE_PROBE:-}"
LABEL="${HOST_COMPLETION_LABEL:-cmake}"
NEGATIVE_SELF_TEST=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --driver)
      [[ "$#" -ge 2 ]] || {
        echo "--driver requires an executable path" >&2
        exit 2
      }
      DRIVER="$2"
      shift 2
      ;;
    --coexistence-probe)
      [[ "$#" -ge 2 ]] || {
        echo "--coexistence-probe requires an executable path" >&2
        exit 2
      }
      COEXISTENCE_PROBE="$2"
      shift 2
      ;;
    --label)
      [[ "$#" -ge 2 ]] || {
        echo "--label requires a value" >&2
        exit 2
      }
      LABEL="$2"
      shift 2
      ;;
    --negative-self-test)
      NEGATIVE_SELF_TEST=1
      shift
      ;;
    *)
      echo "usage: $0 --driver PATH --coexistence-probe PATH" \
        "[--label LABEL] [--negative-self-test]" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${DRIVER}" || ! -x "${DRIVER}" ]]; then
  echo "CMake-built Host completion driver is missing/not executable: ${DRIVER}" >&2
  exit 2
fi
if [[ -z "${COEXISTENCE_PROBE}" || ! -x "${COEXISTENCE_PROBE}" ]]; then
  echo "CMake-built all-private coexistence probe is missing/not executable:" \
    "${COEXISTENCE_PROBE}" >&2
  exit 2
fi
if [[ ! "${LABEL}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid --label (expected [A-Za-z0-9_.-]+): ${LABEL}" >&2
  exit 2
fi

OUT_DIR="${TMPDIR:-/tmp}/ninlil-host-completion-e2e"
mkdir -p "${OUT_DIR}"
WORKDIR="${OUT_DIR}/run-$$"
mkdir -p "${WORKDIR}"
export HOST_COMPLETION_WORKDIR="${WORKDIR}"
PIDS=()

cleanup() {
  local p round alive
  local tracked=()
  # Bash 3.2 + nounset treats an empty array expansion as unbound.
  set +u
  tracked=("${PIDS[@]}")
  for p in "${tracked[@]}"; do
    if kill -0 "${p}" 2>/dev/null; then
      kill -TERM "${p}" 2>/dev/null || true
    fi
  done
  for round in 1 2 3 4 5 6 7 8 9 10; do
    alive=0
    for p in "${tracked[@]}"; do
      if kill -0 "${p}" 2>/dev/null; then
        alive=1
      fi
    done
    if [[ "${alive}" -eq 0 ]]; then
      break
    fi
    sleep 0.1
  done
  for p in "${tracked[@]}"; do
    if kill -0 "${p}" 2>/dev/null; then
      kill -KILL "${p}" 2>/dev/null || true
    fi
    wait "${p}" 2>/dev/null || true
  done
  rm -rf "${WORKDIR}"
  set -u
}
trap cleanup EXIT INT TERM

echo "==> gen certs"
bash tools/wifi_v1_gen_test_certs.sh "${WORKDIR}/certs"

require_f() {
  local file="$1"
  local needle="$2"
  if ! grep -F -- "${needle}" "${file}" >/dev/null; then
    echo "MISSING required marker in ${file}: ${needle}" >&2
    cat "${file}" >&2 || true
    return 1
  fi
}

wait_for_regex() {
  local file="$1"
  local regex="$2"
  local pid="$3"
  local limit="$4"
  local step=0
  while [[ "${step}" -lt "${limit}" ]]; do
    if grep -E -- "${regex}" "${file}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      echo "child exited before marker pid=${pid} regex=${regex}" >&2
      cat "${file}" >&2 || true
      return 1
    fi
    sleep 0.1
    step=$((step + 1))
  done
  echo "timeout waiting for marker pid=${pid} regex=${regex}" >&2
  cat "${file}" >&2 || true
  return 1
}

wait_child_ok() {
  local pid="$1"
  local role="$2"
  local log="$3"
  local limit="$4"
  local step=0
  local rc
  while kill -0 "${pid}" 2>/dev/null; do
    if [[ "${step}" -ge "${limit}" ]]; then
      echo "timeout waiting for ${role} pid=${pid}" >&2
      cat "${log}" >&2 || true
      return 1
    fi
    sleep 0.1
    step=$((step + 1))
  done
  if wait "${pid}"; then
    echo "${role}: exit_status=0"
    return 0
  else
    rc=$?
  fi
  echo "${role}: nonzero exit_status=${rc}" >&2
  cat "${log}" >&2 || true
  return 1
}

launch_role() {
  local role_label="$1"
  local log="$2"
  shift 2
  (
    local rc=0
    if "$@"; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      exit "${rc}"
    fi
    if [[ "${HOST_COMPLETION_INJECT_SANITIZER_MARKER_ROLE:-}" == "${role_label}" ]]; then
      echo "ERROR: AddressSanitizer: injected-negative-self-test"
    fi
    if [[ "${HOST_COMPLETION_FORCE_CHILD_FAILURE:-}" == "${role_label}" ]]; then
      echo "${role_label}: FORCED_EXIT code=97"
      exit 97
    fi
    exit 0
  ) >"${log}" 2>&1 &
  LAST_PID=$!
  PIDS+=("${LAST_PID}")
}

scan_role_logs() {
  local label="$1"
  shift
  local file
  local pattern='AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|runtime error:|SUMMARY:.*Sanitizer|ERROR:.*Sanitizer'
  for file in "$@"; do
    if grep -E -- "${pattern}" "${file}" >/dev/null 2>&1; then
      echo "sanitizer/fatal diagnostic in ${label} role log ${file}" >&2
      grep -En -- "${pattern}" "${file}" >&2 || true
      return 1
    fi
  done
}

run_coexistence_probe() {
  local label="$1"
  local log="${WORKDIR}/${label}-all-private-coexistence.log"
  local marker
  local markers=(
    "all_private_coexistence: feature=Domain status=PASS"
    "all_private_coexistence: feature=Fabric status=PASS"
    "all_private_coexistence: feature=Wi-Fi status=PASS"
    "all_private_coexistence: feature=R7FRAG status=PASS"
    "all_private_coexistence: feature=RRMP status=PASS"
    "all_private_coexistence: feature=MFDT status=PASS"
    "all_private_coexistence: ALL PASS process_calls=6 canonical_cross_feature_e2e=NOT_CLAIMED physical_hil=NOT_RUN"
  )

  echo "==> all-private one-process coexistence calls (${label})"
  if ! "${COEXISTENCE_PROBE}" >"${log}" 2>&1; then
    echo "all-private coexistence probe failed: ${COEXISTENCE_PROBE}" >&2
    cat "${log}" >&2 || true
    return 1
  fi
  scan_role_logs "${label}-all-private-coexistence" "${log}"
  for marker in "${markers[@]}"; do
    require_f "${log}" "${marker}"
  done
  cat "${log}"
}

snapshot_logs() {
  local label="$1"
  shift
  local destination="${OUT_DIR}/last-logs/${label}"
  local file
  rm -rf "${destination}"
  mkdir -p "${destination}"
  for file in "$@"; do
    cp -f "${file}" "${destination}/"
  done
}

run_scenario() {
  local bin="$1"
  local label="$2"
  local prefix="${WORKDIR}/${label}"
  local p1_log="${prefix}-p1.log"
  local p2_log="${prefix}-p2.log"
  local relay_log="${prefix}-relay.log"
  local endpoint_log="${prefix}-endpoint.log"
  local p1_pid p2_pid relay_pid endpoint_pid
  local P1 P2 RELAY
  local child_failure=0
  local ED PD
  local logs=("${endpoint_log}" "${relay_log}" "${p1_log}" "${p2_log}")

  PIDS=()
  echo "==> scenario ${label} listeners bind port=0 atomically"

  launch_role P1 "${p1_log}" \
    "${bin}" --role parent --port 0 --certs "${WORKDIR}/certs" --tag P1
  p1_pid="${LAST_PID}"
  launch_role P2 "${p2_log}" \
    "${bin}" --role parent --port 0 --certs "${WORKDIR}/certs" --tag P2
  p2_pid="${LAST_PID}"
  wait_for_regex "${p1_log}" '^P1: listening port=[1-9][0-9]*$' "${p1_pid}" 100
  wait_for_regex "${p2_log}" '^P2: listening port=[1-9][0-9]*$' "${p2_pid}" 100
  P1="$(sed -En 's/^P1: listening port=([1-9][0-9]*)$/\1/p' "${p1_log}")"
  P2="$(sed -En 's/^P2: listening port=([1-9][0-9]*)$/\1/p' "${p2_log}")"
  test -n "${P1}" && test -n "${P2}" && test "${P1}" != "${P2}"

  launch_role relay "${relay_log}" \
    "${bin}" --role relay --listen 0 --p1 "${P1}" --p2 "${P2}" \
    --certs "${WORKDIR}/certs" --switch-after 2 --cold-restart
  relay_pid="${LAST_PID}"
  wait_for_regex \
    "${relay_log}" '^relay: listening for E port=[1-9][0-9]*$' "${relay_pid}" 300
  RELAY="$(sed -En \
    's/^relay: listening for E port=([1-9][0-9]*)$/\1/p' "${relay_log}")"
  test -n "${RELAY}" && test "${RELAY}" != "${P1}" && test "${RELAY}" != "${P2}"
  echo "==> scenario ${label} p1=${P1} p2=${P2} relay=${RELAY}"

  launch_role endpoint "${endpoint_log}" \
    "${bin}" --role endpoint --relay "${RELAY}" --certs "${WORKDIR}/certs" \
    --disconnect-after 2 --duplicate --cold-restart
  endpoint_pid="${LAST_PID}"

  wait_child_ok "${endpoint_pid}" endpoint "${endpoint_log}" 600 \
    || child_failure=1
  wait_child_ok "${relay_pid}" relay "${relay_log}" 200 \
    || child_failure=1
  wait_child_ok "${p1_pid}" P1 "${p1_log}" 200 \
    || child_failure=1
  wait_child_ok "${p2_pid}" P2 "${p2_log}" 200 \
    || child_failure=1
  PIDS=()
  snapshot_logs "${label}" "${logs[@]}"
  scan_role_logs "${label}" "${logs[@]}" || child_failure=1
  if [[ "${child_failure}" -ne 0 ]]; then
    echo "scenario ${label}: child/status/sanitizer failure" >&2
    return 1
  fi

  # --- hard markers only (no soft OR / no RECONNECT_PENDING / no substring fallback) ---
  require_f "${endpoint_log}" "endpoint: DISCONNECT mid-transfer"
  require_f "${endpoint_log}" "endpoint: RECONNECTED"
  require_f "${endpoint_log}" "endpoint: DUPLICATE_RETRANSMIT"
  require_f "${endpoint_log}" "endpoint: COLD_RECOVER durable_bytes="
  require_f "${endpoint_log}" "endpoint: COMPLETE digest="
  require_f "${endpoint_log}" "endpoint: DONE"
  require_f "${endpoint_log}" "endpoint: SHUTDOWN_SENT"
  require_f "${endpoint_log}" "endpoint: SHUTDOWN_ACK_RECEIVED"
  if ! grep -F "complete=1" "${endpoint_log}" >/dev/null; then
    echo "false-green: endpoint sender complete=1 required" >&2
    cat "${endpoint_log}" >&2 || true
    return 1
  fi
  if grep -F "RECONNECT_PENDING" "${endpoint_log}" >/dev/null 2>&1; then
    echo "false-green: RECONNECT_PENDING is not success" >&2
    return 1
  fi

  require_f "${relay_log}" "relay: SWITCH_TO_P2 exact_parent_b=404142434445464748494a4b4c4d4e4f"
  require_f "${relay_log}" "relay: COLD_RECOVER durable_bytes="
  require_f "${relay_log}" "live_route=1 live_attempt=1"
  require_f "${relay_log}" "relay: hop_ok "
  require_f "${relay_log}" "relay: E REATTACHED"
  require_f "${relay_log}" "relay: DUPLICATE_NO_NEW_CUSTODY hop_custody_count="
  require_f "${relay_log}" "relay: SHUTDOWN_PROPAGATED endpoint_ack=1 p1=1 p2=1"
  require_f "${relay_log}" "relay: DONE"
  require_f "${relay_log}" "p1_sub="
  require_f "${relay_log}" "p2_sub="

  # Require client submit AND independently parsed receiver evidence on P1/P2.
  if ! grep -E 'p1_sub=[1-9][0-9]*' "${relay_log}" >/dev/null; then
    echo "false-green: p1_sub must be >=1 (real hop on P1)" >&2
    cat "${relay_log}" >&2 || true
    return 1
  fi
  if ! grep -E 'p2_sub=[1-9][0-9]*' "${relay_log}" >/dev/null; then
    echo "false-green: p2_sub must be >=1 (real hop + MFDT on P2)" >&2
    cat "${relay_log}" >&2 || true
    return 1
  fi
  require_f "${p1_log}" "P1: ATTACHED"
  require_f "${p2_log}" "P2: ATTACHED"
  if [[ "$(grep -c '^P1: VERIFIED_HOP_FRAME ' "${p1_log}")" -ne 1 ]]; then
    echo "false-green: P1 must parse exactly one verified hop frame" >&2
    cat "${p1_log}" >&2 || true
    return 1
  fi
  if [[ "$(grep -c '^P2: VERIFIED_HOP_FRAME ' "${p2_log}")" -lt 1 ]]; then
    echo "false-green: P2 must parse at least one verified hop frame" >&2
    cat "${p2_log}" >&2 || true
    return 1
  fi
  require_f "${p1_log}" "P1: SHUTDOWN_RECEIVED"
  require_f "${p2_log}" "P2: SHUTDOWN_RECEIVED"
  require_f "${p1_log}" "explicit_shutdown=1"
  require_f "${p2_log}" "explicit_shutdown=1"

  # Parent publication exactly once on the completing parent (P2 after switch).
  require_f "${p2_log}" "PUBLICATION_ONCE count=1 digest="
  if grep -F "PUBLICATION_ONCE count=1" "${p1_log}" >/dev/null 2>&1; then
    echo "false-green: P1 must not publish when completion is on P2 path" >&2
    return 1
  fi
  if [[ "$(grep -c 'PUBLICATION_ONCE count=1' "${p2_log}")" -ne 1 ]]; then
    echo "false-green: P2 publication exactly once required" >&2
    return 1
  fi

  # Digest equality endpoint ↔ P2
  ED="$(sed -En \
    's/^endpoint: COMPLETE digest=([0-9a-f]{64})$/\1/p' \
    "${endpoint_log}" | head -1)"
  PD="$(sed -En \
    's/^P2: PUBLICATION_ONCE count=1 digest=([0-9a-f]{64}) durable_pub=1$/\1/p' \
    "${p2_log}" | head -1)"
  test -n "${ED}" && test -n "${PD}"
  if [[ "${ED}" != "${PD}" ]]; then
    echo "digest mismatch endpoint=${ED} p2=${PD}" >&2
    return 1
  fi

  # Real multi-frame MFDT + subsequent P2 traffic after switch
  test "$(grep -c 'endpoint: sent_frame=' "${endpoint_log}")" -ge 4
  test "$(grep -c 'P2: ncl1_frame' "${p2_log}")" -ge 4

  echo "scenario ${label}: PASS digest=${ED}"
}

run_coexistence_probe "${LABEL}"

if [[ "${NEGATIVE_SELF_TEST}" -eq 0 ]]; then
  run_scenario "${DRIVER}" "${LABEL}"
  echo "host_completion_transport_fixture_e2e: ALL PASS label=${LABEL}"
  exit 0
fi

HOST_COMPLETION_FORCE_CHILD_FAILURE=P1
export HOST_COMPLETION_FORCE_CHILD_FAILURE
if run_scenario "${DRIVER}" "negative-child-exit"; then
  echo "false-green: forced P1 exit 97 was accepted" >&2
  exit 1
fi
require_f \
  "${OUT_DIR}/last-logs/negative-child-exit/negative-child-exit-p1.log" \
  "P1: FORCED_EXIT code=97"
unset HOST_COMPLETION_FORCE_CHILD_FAILURE
PIDS=()
HOST_COMPLETION_INJECT_SANITIZER_MARKER_ROLE=relay
export HOST_COMPLETION_INJECT_SANITIZER_MARKER_ROLE
if run_scenario "${DRIVER}" "negative-sanitizer-log"; then
  echo "false-green: injected sanitizer marker was accepted" >&2
  exit 1
fi
require_f \
  "${OUT_DIR}/last-logs/negative-sanitizer-log/negative-sanitizer-log-relay.log" \
  "ERROR: AddressSanitizer: injected-negative-self-test"
unset HOST_COMPLETION_INJECT_SANITIZER_MARKER_ROLE
PIDS=()
echo "host_completion_transport_fixture_e2e: NEGATIVE SELF-TEST PASS"
