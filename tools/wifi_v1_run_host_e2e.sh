#!/usr/bin/env bash
# Orchestrate 2-process real-socket Wi-Fi Host e2e scenarios.
# Soft-pass forbidden: every scenario requires exact log tokens (grep -F only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?usage: wifi_v1_run_host_e2e.sh PATH_TO_wifi_v1_host_e2e_driver}"
FRAMES="${FRAMES:-10000}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=1:detect_stack_use_after_return=1}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/wifi_v1_e2e.XXXXXX")"
cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
}

exact_grep() {
  local pat="$1"
  local f="$2"
  if ! grep -F -q -- "${pat}" "${f}"; then
    echo "wifi_v1_run_host_e2e: missing exact token: ${pat} in ${f}" >&2
    cat "${f}" >&2 || true
    return 1
  fi
  return 0
}

bash "${ROOT}/tools/wifi_v1_gen_test_certs.sh" "${WORKDIR}/certs"
echo "wifi_v1_run_host_e2e: frames=${FRAMES}"
FABRIC_SEND_ARGS=()
FABRIC_REPLY_ARGS=()
FABRIC_SEND_SUPPORTED=0
RUNTIME_E2E_SUPPORTED=0
if "${BIN}" --supports-fabric-send >/dev/null 2>&1; then
  FABRIC_SEND_ARGS=(--fabric-send)
  FABRIC_REPLY_ARGS=(--fabric-reply)
  FABRIC_SEND_SUPPORTED=1
fi
if "${BIN}" --supports-runtime-e2e >/dev/null 2>&1; then
  RUNTIME_E2E_SUPPORTED=1
fi

# 1) Happy path
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames "${FRAMES}" \
  "${FABRIC_REPLY_ARGS[@]}" \
  >"${WORKDIR}/server.log" 2>&1 &
SPID=$!
sleep 0.4
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames "${FRAMES}" \
  "${FABRIC_SEND_ARGS[@]}" "${FABRIC_REPLY_ARGS[@]}" \
  >"${WORKDIR}/client.log" 2>&1
wait "${SPID}"
exact_grep "server received frames=${FRAMES} ordered" "${WORKDIR}/server.log"
exact_grep "client sent frames=${FRAMES}" "${WORKDIR}/client.log"
if [ "${FABRIC_SEND_SUPPORTED}" -eq 1 ]; then
  exact_grep "server Fabric responses=${FRAMES}" "${WORKDIR}/server.log"
  exact_grep \
    "Fabric start_send/TLS completion/release frames=${FRAMES} responses=${FRAMES} exactly-once replay-denied=live+restart" \
    "${WORKDIR}/client.log"
fi
echo "wifi_v1_run_host_e2e: ordered PASS frames=${FRAMES}"

# 2) Joined public Runtime -> Fabric -> real TLS -> peer Runtime -> Receipt.
if [ "${RUNTIME_E2E_SUPPORTED}" -eq 1 ]; then
  PORT="$(free_port)"
  "${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 \
    --runtime-e2e >"${WORKDIR}/server_runtime.log" 2>&1 &
  SPID=$!
  sleep 0.5
  if ! "${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 \
      --runtime-e2e >"${WORKDIR}/client_runtime.log" 2>&1; then
    echo "wifi_v1_run_host_e2e: joined client failed" >&2
    cat "${WORKDIR}/client_runtime.log" >&2 || true
    cat "${WORKDIR}/server_runtime.log" >&2 || true
    kill "${SPID}" 2>/dev/null || true
    wait "${SPID}" 2>/dev/null || true
    exit 1
  fi
  if ! wait "${SPID}"; then
    echo "wifi_v1_run_host_e2e: joined server failed" >&2
    cat "${WORKDIR}/server_runtime.log" >&2 || true
    cat "${WORKDIR}/client_runtime.log" >&2 || true
    exit 1
  fi
  exact_grep \
    "public Runtime/Fabric/TLS peer delivery verified exactly-once" \
    "${WORKDIR}/server_runtime.log"
  exact_grep \
    "public submit/Fabric/TLS/peer Runtime/Receipt satisfied" \
    "${WORKDIR}/client_runtime.log"
  echo "wifi_v1_run_host_e2e: joined public Runtime/Fabric/TLS PASS"
else
  echo "wifi_v1_run_host_e2e: joined public Runtime/Fabric/TLS NOT RUN in this build"
fi

# 3) Bidirectional
PORT="$(free_port)"
BF=2000
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames "${BF}" --bidirectional \
  >"${WORKDIR}/server_bi.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames "${BF}" --bidirectional \
  >"${WORKDIR}/client_bi.log" 2>&1
wait "${SPID}"
exact_grep "server received frames=${BF} ordered" "${WORKDIR}/server_bi.log"
exact_grep "client received frames=${BF} ordered" "${WORKDIR}/client_bi.log"
echo "wifi_v1_run_host_e2e: bidirectional PASS"

# 4) Slow reader
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 200 \
  >"${WORKDIR}/server_slow.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 200 --slow-ms 2 \
  >"${WORKDIR}/client_slow.log" 2>&1
wait "${SPID}"
exact_grep "server received frames=200 ordered" "${WORKDIR}/server_slow.log"
echo "wifi_v1_run_host_e2e: slow reader PASS"

# 5) Malformed — exact client inject token; server must not complete ordered path
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 --malformed \
  >"${WORKDIR}/server_mal.log" 2>&1 &
SPID=$!
sleep 0.35
set +e
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 --malformed \
  >"${WORKDIR}/client_mal.log" 2>&1
wait "${SPID}"
set -e
if grep -F -q "server received frames=1 ordered" "${WORKDIR}/server_mal.log"; then
  echo "wifi_v1_run_host_e2e: malformed must not complete ordered happy path" >&2
  exit 1
fi
exact_grep "client injected malformed" "${WORKDIR}/client_mal.log"
exact_grep "server saw malformed OK" "${WORKDIR}/server_mal.log"
echo "wifi_v1_run_host_e2e: malformed fail-closed PASS"

# 5) Expired client — client fails closed at TLS configure (local leaf expired).
# Server may never accept; do not wait forever on server (soft-pass forbidden:
# require exact client reject token and no ordered server completion).
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 \
  >"${WORKDIR}/server_exp.log" 2>&1 &
SPID=$!
sleep 0.35
set +e
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 --expired-client \
  >"${WORKDIR}/client_exp.log" 2>&1
EC=$?
set -e
# Client must exit success after printing reject token (no ATTACHED).
if [ "${EC}" -ne 0 ]; then
  echo "wifi_v1_run_host_e2e: expired-client client exit=${EC}" >&2
  cat "${WORKDIR}/client_exp.log" >&2 || true
  kill "${SPID}" 2>/dev/null || true
  wait "${SPID}" 2>/dev/null || true
  exit 1
fi
kill "${SPID}" 2>/dev/null || true
wait "${SPID}" 2>/dev/null || true
if grep -F -q "server received frames=1 ordered" "${WORKDIR}/server_exp.log"; then
  echo "wifi_v1_run_host_e2e: server accepted expired client" >&2
  exit 1
fi
exact_grep "expired-client rejected OK" "${WORKDIR}/client_exp.log"
echo "wifi_v1_run_host_e2e: credential mismatch/expired PATH exercised PASS"

# 6) Exact leaf profile negative matrix. Each fixture mutates one rule only:
# KU extra keyAgreement, role EKU ambiguity, non-critical SAN, wrong SKI
# derivation, or missing AKI. Every case must reach an explicit credential
# fence; timeout or a merely missing happy-path token is not success.
for VARIANT in bad-ku bad-eku bad-san bad-ski bad-aki; do
  VARIANT_CERTS="${WORKDIR}/certs-${VARIANT}"
  mkdir -p "${VARIANT_CERTS}"
  cp \
    "${WORKDIR}/certs/ca.cert.pem" \
    "${WORKDIR}/certs/server.cert.pem" \
    "${WORKDIR}/certs/server.key.pem" \
    "${WORKDIR}/certs/client.key.pem" \
    "${VARIANT_CERTS}/"
  cp \
    "${WORKDIR}/certs/client.${VARIANT}.cert.pem" \
    "${VARIANT_CERTS}/client.cert.pem"
  PORT="$(free_port)"
  "${BIN}" --server --port "${PORT}" --certs "${VARIANT_CERTS}" --frames 1 \
    >"${WORKDIR}/server_${VARIANT}.log" 2>&1 &
  SPID=$!
  sleep 0.35
  set +e
  "${BIN}" --client --port "${PORT}" --certs "${VARIANT_CERTS}" --frames 1 \
    >"${WORKDIR}/client_${VARIANT}.log" 2>&1
  EC=$?
  set -e
  kill "${SPID}" 2>/dev/null || true
  wait "${SPID}" 2>/dev/null || true
  if [ "${EC}" -eq 0 ]; then
    echo "wifi_v1_run_host_e2e: ${VARIANT} client unexpectedly accepted" >&2
    cat "${WORKDIR}/client_${VARIANT}.log" >&2 || true
    exit 1
  fi
  if ! grep -F -q "tls configure failed st=16" \
      "${WORKDIR}/client_${VARIANT}.log" \
      && ! grep -F -q "connect/handshake failed phase=7" \
      "${WORKDIR}/client_${VARIANT}.log"; then
    echo "wifi_v1_run_host_e2e: ${VARIANT} lacked explicit credential fence" >&2
    cat "${WORKDIR}/client_${VARIANT}.log" >&2 || true
    exit 1
  fi
  if grep -F -q "server received frames=1 ordered" \
      "${WORKDIR}/server_${VARIANT}.log"; then
    echo "wifi_v1_run_host_e2e: ${VARIANT} reached ordered delivery" >&2
    exit 1
  fi
  echo "wifi_v1_run_host_e2e: exact leaf ${VARIANT} rejected PASS"
done

# 7) Exporter
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 10 --export-check \
  >"${WORKDIR}/server_expc.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 10 --export-check \
  >"${WORKDIR}/client_expc.log" 2>&1
wait "${SPID}"
exact_grep "export contexts 62/64 + ids 16/16 OK" "${WORKDIR}/client_expc.log"
echo "wifi_v1_run_host_e2e: exporter 62/64 contexts + 16-byte ids PASS"

# 8) Cred revoke
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 \
  >"${WORKDIR}/server_rev.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 1 --cred-revoke \
  >"${WORKDIR}/client_rev.log" 2>&1
wait "${SPID}" || true
exact_grep "cred-revoke fail-closed OK" "${WORKDIR}/client_rev.log"
echo "wifi_v1_run_host_e2e: cred revoke PASS"

# 9) Cred rotate fence+reauth
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 50 --cred-rotate \
  >"${WORKDIR}/server_rot.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 50 --cred-rotate \
  >"${WORKDIR}/client_rot.log" 2>&1
wait "${SPID}"
exact_grep "cred-rotate fence+reauth OK" "${WORKDIR}/client_rot.log"
exact_grep "server received frames=50 ordered" "${WORKDIR}/server_rot.log"
echo "wifi_v1_run_host_e2e: cred rotate PASS"

# 10) AP disconnect
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 100 --ap-disconnect \
  >"${WORKDIR}/server_ap.log" 2>&1 &
SPID=$!
sleep 0.35
set +e
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 100 \
  >"${WORKDIR}/client_ap.log" 2>&1
set -e
wait "${SPID}" || true
exact_grep "ap-disconnect" "${WORKDIR}/server_ap.log"
echo "wifi_v1_run_host_e2e: ap-disconnect PASS"

# 11) Restart midstream — hard require exact OK
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 40 --restart-midstream \
  >"${WORKDIR}/server_rs.log" 2>&1 &
SPID=$!
sleep 0.3
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 40 --restart-midstream \
  >"${WORKDIR}/client_rs.log" 2>&1
wait "${SPID}"
exact_grep "restart-midstream OK" "${WORKDIR}/client_rs.log"
echo "wifi_v1_run_host_e2e: restart-midstream PASS"

# 12) Journal/durable credential
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 20 --journal-durable \
  >"${WORKDIR}/server_jd.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 20 --journal-durable \
  >"${WORKDIR}/client_jd.log" 2>&1
wait "${SPID}"
exact_grep "journal-durable recovery OK" "${WORKDIR}/client_jd.log"
exact_grep "server received frames=20 ordered" "${WORKDIR}/server_jd.log"
echo "wifi_v1_run_host_e2e: journal-durable PASS"

# 13) Blackhole fence
PORT="$(free_port)"
"${BIN}" --server --port "${PORT}" --certs "${WORKDIR}/certs" --frames 5 \
  >"${WORKDIR}/server_bh.log" 2>&1 &
SPID=$!
sleep 0.35
"${BIN}" --client --port "${PORT}" --certs "${WORKDIR}/certs" --frames 5 --blackhole-inject \
  >"${WORKDIR}/client_bh.log" 2>&1
wait "${SPID}" || true
exact_grep "blackhole fence OK" "${WORKDIR}/client_bh.log"
echo "wifi_v1_run_host_e2e: blackhole fence PASS"

echo "wifi_v1_run_host_e2e: ALL PASS"
