#!/usr/bin/env bash
set -euo pipefail

TEST_BIN="${1:?test binary required}"
SOURCE_DIR="${2:?source directory required}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ninlil-posix-tls-v1.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

bash "${SOURCE_DIR}/tools/wifi_v1_gen_test_certs.sh" "${WORK_DIR}/certs"
"${TEST_BIN}" "${WORK_DIR}/certs"
