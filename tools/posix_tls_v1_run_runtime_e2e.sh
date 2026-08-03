#!/usr/bin/env bash
set -euo pipefail

TEST_BIN="${1:?installed consumer binary required}"
SOURCE_DIR="${2:?source directory required}"
WORK_DIR="${3:?work directory required}"
CERT_DIR="${WORK_DIR}/certs"
SERVER_DB="${WORK_DIR}/server.sqlite3"
CLIENT_DB="${WORK_DIR}/client.sqlite3"
SERVER_PID=""
CLIENT_PID=""

cleanup_processes() {
  if [[ -n "${CLIENT_PID}" ]]; then
    kill "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup_processes EXIT

remove_db_artifacts() {
  local path="$1"
  rm -f "${path}" "${path}-wal" "${path}-shm" "${path}.ninlil-lock"
}

wait_for_file() {
  local pid="$1"
  local path="$2"
  local label="$3"
  local attempt
  for ((attempt = 0; attempt < 600; ++attempt)); do
    if [[ -s "${path}" ]]; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" || true
      echo "${label} exited before publishing ${path}" >&2
      return 1
    fi
    sleep 0.05
  done
  echo "${label} timed out waiting for ${path}" >&2
  return 1
}

wait_bounded() {
  local pid="$1"
  local label="$2"
  local watchdog
  (
    sleep 40
    kill -TERM "${pid}" 2>/dev/null || true
  ) &
  watchdog=$!
  if ! wait "${pid}"; then
    kill "${watchdog}" 2>/dev/null || true
    wait "${watchdog}" 2>/dev/null || true
    echo "${label} failed or exceeded its bounded runtime" >&2
    return 1
  fi
  kill "${watchdog}" 2>/dev/null || true
  wait "${watchdog}" 2>/dev/null || true
}

mkdir -p "${WORK_DIR}"
remove_db_artifacts "${SERVER_DB}"
remove_db_artifacts "${CLIENT_DB}"
rm -rf "${CERT_DIR}"
bash "${SOURCE_DIR}/tools/wifi_v1_gen_test_certs.sh" "${CERT_DIR}"

# Test-control only: choose one free loopback port before either durable side
# is created, then keep that trusted endpoint unchanged across both rounds.
PORT="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  echo "failed to choose a bounded loopback port" >&2
  exit 1
fi

for ROUND in 1 2; do
  READY_FILE="${WORK_DIR}/server-ready-${ROUND}"
  SUCCESS_FILE="${WORK_DIR}/round-success-${ROUND}"
  SERVER_LOG="${WORK_DIR}/server-${ROUND}.log"
  CLIENT_LOG="${WORK_DIR}/client-${ROUND}.log"
  rm -f "${READY_FILE}" "${SUCCESS_FILE}" "${SERVER_LOG}" "${CLIENT_LOG}"

  "${TEST_BIN}" server "${SERVER_DB}" "${CERT_DIR}" "${PORT}" \
      "${READY_FILE}" "${SUCCESS_FILE}" "${ROUND}" \
      >"${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!
  if ! wait_for_file "${SERVER_PID}" "${READY_FILE}" "server round ${ROUND}"; then
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi

  "${TEST_BIN}" client "${CLIENT_DB}" "${CERT_DIR}" "${PORT}" \
      "${READY_FILE}" "${SUCCESS_FILE}" "${ROUND}" \
      >"${CLIENT_LOG}" 2>&1 &
  CLIENT_PID=$!
  if [[ "${CLIENT_PID}" == "${SERVER_PID}" ]]; then
    echo "server and client must be distinct processes" >&2
    exit 1
  fi
  if ! wait_bounded "${CLIENT_PID}" "client round ${ROUND}"; then
    cat "${CLIENT_LOG}" >&2 || true
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi
  CLIENT_PID=""
  if ! wait_bounded "${SERVER_PID}" "server round ${ROUND}"; then
    cat "${CLIENT_LOG}" >&2 || true
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi
  SERVER_PID=""

  grep -Eq "role=client round=${ROUND} .*satisfied=1 .*verified=1 .*clean_close=1 PASS" \
      "${CLIENT_LOG}"
  grep -Eq "role=server round=${ROUND} .*callback=1 .*clean_close=1 PASS" \
      "${SERVER_LOG}"
done

[[ -s "${SERVER_DB}" && -s "${CLIENT_DB}" ]]
echo "posix_tls_v1_runtime_e2e: PASS processes=2 rounds=2 sqlite_reuse=1"
