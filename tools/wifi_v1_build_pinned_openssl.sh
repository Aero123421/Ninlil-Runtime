#!/usr/bin/env bash
# Build the Wi-Fi Host authority dependency from the exact OpenSSL release.
#
# Output:
#   <build-root>/install with static libssl.a/libcrypto.a, headers and openssl.
#   <build-root>/install/.ninlil-openssl-pin.json records immutable identity.
#
# This script intentionally does not use a system package, Homebrew, or a
# floating git ref.  The official release archive is accepted only after the
# exact SHA-256 below matches.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

readonly VERSION="3.5.7"
readonly TAG="openssl-3.5.7"
readonly PEELED_COMMIT="8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
readonly ARCHIVE_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
readonly ARCHIVE_URL="https://github.com/openssl/openssl/releases/download/${TAG}/openssl-${VERSION}.tar.gz"

BUILD_ROOT="${NINLIL_OPENSSL_BUILD_ROOT:-${ROOT}/build/openssl-${VERSION}-authority}"
DOWNLOAD_ROOT="${NINLIL_OPENSSL_DOWNLOAD_ROOT:-${ROOT}/build/downloads}"
JOBS="${NINLIL_OPENSSL_BUILD_JOBS:-2}"
PREFIX="${BUILD_ROOT}/install"
ARCHIVE="${DOWNLOAD_ROOT}/openssl-${VERSION}.tar.gz"
SOURCE="${BUILD_ROOT}/src"
MANIFEST="${PREFIX}/.ninlil-openssl-pin.json"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

verify_install() {
    test -x "${PREFIX}/bin/openssl"
    test -f "${PREFIX}/include/openssl/ssl.h"
    test -f "${MANIFEST}"
    local ssl_archive crypto_archive
    ssl_archive="$(find "${PREFIX}" -type f -name libssl.a -print -quit)"
    crypto_archive="$(find "${PREFIX}" -type f -name libcrypto.a -print -quit)"
    test -n "${ssl_archive}"
    test -n "${crypto_archive}"
    if find "${PREFIX}" -type f \
        \( -name 'libssl.so*' -o -name 'libcrypto.so*' \
           -o -name 'libssl.dylib' -o -name 'libcrypto.dylib' \) \
        | grep -q .; then
        echo "pinned OpenSSL install contains a shared SSL/Crypto library" >&2
        return 1
    fi
    local actual_version
    actual_version="$(
        OPENSSL_CONF=/dev/null OPENSSL_MODULES=/nonexistent \
            "${PREFIX}/bin/openssl" version -v
    )"
    test "${actual_version}" = "OpenSSL ${VERSION} 9 Jun 2026 (Library: OpenSSL ${VERSION} 9 Jun 2026)" \
        || test "${actual_version}" = "OpenSSL ${VERSION} 9 Jun 2026"
    python3 - "${MANIFEST}" "${PREFIX}" "${PEELED_COMMIT}" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "archive_sha256": "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8",
    "configure": ["no-shared", "no-tests", "no-module", "no-legacy"],
    "peeled_commit": sys.argv[3],
    "static_only": True,
    "tag": "openssl-3.5.7",
    "version": "3.5.7",
}
for key, value in expected.items():
    if manifest.get(key) != value:
        raise SystemExit(f"manifest mismatch {key}: {manifest.get(key)!r}")
if pathlib.Path(manifest.get("prefix", "")).resolve() != pathlib.Path(sys.argv[2]).resolve():
    raise SystemExit("manifest prefix mismatch")
PY
}

if verify_install >/dev/null 2>&1; then
    echo "${PREFIX}"
    exit 0
fi

mkdir -p "${DOWNLOAD_ROOT}" "${BUILD_ROOT}"
if [[ ! -f "${ARCHIVE}" ]] \
    || [[ "$(sha256_file "${ARCHIVE}")" != "${ARCHIVE_SHA256}" ]]; then
    rm -f "${ARCHIVE}"
    curl --proto '=https' --tlsv1.2 --fail --location --retry 4 \
        --output "${ARCHIVE}" "${ARCHIVE_URL}"
fi
ACTUAL_SHA256="$(sha256_file "${ARCHIVE}")"
if [[ "${ACTUAL_SHA256}" != "${ARCHIVE_SHA256}" ]]; then
    echo "OpenSSL archive SHA-256 mismatch" >&2
    echo "expected=${ARCHIVE_SHA256}" >&2
    echo "actual=${ACTUAL_SHA256}" >&2
    exit 1
fi

rm -rf "${SOURCE}" "${PREFIX}"
mkdir -p "${SOURCE}" "${PREFIX}"
tar -xzf "${ARCHIVE}" --strip-components=1 -C "${SOURCE}"

(
    cd "${SOURCE}"
    ./config \
        "--prefix=${PREFIX}" \
        "--openssldir=${PREFIX}/ssl" \
        no-shared no-tests no-module no-legacy
    make -s -j"${JOBS}" build_sw
    make -s install_sw
)

python3 - "${MANIFEST}" "${PREFIX}" "${PEELED_COMMIT}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    json.dumps(
        {
            "archive_sha256": "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8",
            "configure": ["no-shared", "no-tests", "no-module", "no-legacy"],
            "peeled_commit": sys.argv[3],
            "prefix": str(pathlib.Path(sys.argv[2]).resolve()),
            "source_url": "https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz",
            "static_only": True,
            "tag": "openssl-3.5.7",
            "version": "3.5.7",
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

verify_install
echo "${PREFIX}"
