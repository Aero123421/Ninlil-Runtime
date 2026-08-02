#!/usr/bin/env python3
"""Fail-closed OpenSSL 3.5.7 static/isolated Host authority gate.

Strict mode (the default) requires all of:
  * official release archive with the exact pinned SHA-256;
  * static-only install manifest for tag + peeled commit;
  * exact OpenSSL runtime version from the pinned prefix;
  * CMake cache and link command resolving libssl/libcrypto to that prefix;
  * no dynamic libssl/libcrypto dependency in the exercised final binary;
  * retained OpenSSL symbols in that final binary;
  * the Wi-Fi TLS implementation's isolated OSSL_LIB_CTX/default-provider path.

`--report-only` is the only soft mode.  It is for ordinary system-OpenSSL LAB
jobs and can never set authority_claim_allowed=true when evidence is missing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TLS_HOST_SOURCE = REPO_ROOT / "src" / "transport" / "wifi_v1" / "wifi_tls_host.c"
PIN_VERSION = "3.5.7"
PIN_TAG = "openssl-3.5.7"
PIN_COMMIT = "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
PIN_ARCHIVE_SHA256 = (
    "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
)
PIN_VERSION_TEXTS = {
    "OpenSSL 3.5.7 9 Jun 2026",
    "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)",
}
PIN_CONFIGURE = ["no-shared", "no-tests", "no-module", "no-legacy"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cache_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("//") or raw.startswith("#") or "=" not in raw:
            continue
        key_type, value = raw.split("=", 1)
        key = key_type.split(":", 1)[0]
        values[key] = value
    return values


def find_one(root: Path, filename: str) -> Path | None:
    found = sorted(path.resolve() for path in root.glob(f"lib*/**/{filename}"))
    return found[0] if len(found) == 1 else None


def run_output(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, check=False, capture_output=True, text=True
        )
    except FileNotFoundError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def tls_source_isolated(source: str) -> bool:
    required = (
        r"OSSL_LIB_CTX_new\s*\(",
        r'OSSL_PROVIDER_load\s*\([^;]*,\s*"default"\s*\)',
        r'EVP_set_default_properties\s*\([^;]*,\s*"provider=default"\s*\)',
        r'SSL_CTX_new_ex\s*\([^;]*,\s*"provider=default"\s*,',
    )
    return all(re.search(pattern, source) is not None for pattern in required)


def self_test() -> int:
    good = """
    x = OSSL_LIB_CTX_new();
    p = OSSL_PROVIDER_load(x, "default");
    EVP_set_default_properties(x, "provider=default");
    c = SSL_CTX_new_ex(x, "provider=default", m);
    """
    if not tls_source_isolated(good):
        print("FAIL: valid isolation source rejected", file=sys.stderr)
        return 1
    for statement in (
        "x = OSSL_LIB_CTX_new();",
        'p = OSSL_PROVIDER_load(x, "default");',
        'EVP_set_default_properties(x, "provider=default");',
        'c = SSL_CTX_new_ex(x, "provider=default", m);',
    ):
        if tls_source_isolated(good.replace(statement, "", 1)):
            print(f"FAIL: missing {statement} false-green", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="ninlil-openssl-pin-gate-") as td:
        sample = Path(td) / "CMakeCache.txt"
        sample.write_text(
            "OPENSSL_SSL_LIBRARY:FILEPATH=/pin/lib/libssl.a\n"
            "OPENSSL_CRYPTO_LIBRARY:FILEPATH=/pin/lib/libcrypto.a\n",
            encoding="utf-8",
        )
        values = cache_values(sample)
        if values.get("OPENSSL_SSL_LIBRARY") != "/pin/lib/libssl.a":
            print("FAIL: CMake cache parser", file=sys.stderr)
            return 1
    print("OK wifi_v1_openssl_pin_provenance self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="")
    parser.add_argument("--source-archive", default="")
    parser.add_argument("--cmake-cache", default="")
    parser.add_argument("--link-evidence", default="")
    parser.add_argument("--binary", default="")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    checks: dict[str, bool] = {}
    details: dict[str, object] = {}
    root = Path(args.root).resolve() if args.root else None
    archive = Path(args.source_archive).resolve() if args.source_archive else None
    cmake_cache = Path(args.cmake_cache).resolve() if args.cmake_cache else None
    link_evidence = (
        Path(args.link_evidence).resolve() if args.link_evidence else None
    )
    binary = Path(args.binary).resolve() if args.binary else None

    checks["root_supplied"] = root is not None and root.is_dir()
    checks["source_archive_supplied"] = (
        archive is not None and archive.is_file()
    )
    checks["cmake_cache_supplied"] = (
        cmake_cache is not None and cmake_cache.is_file()
    )
    checks["link_evidence_supplied"] = (
        link_evidence is not None and link_evidence.is_file()
    )
    checks["binary_supplied"] = binary is not None and binary.is_file()

    ssl_archive: Path | None = None
    crypto_archive: Path | None = None
    if checks["root_supplied"] and root is not None:
        ssl_archive = find_one(root, "libssl.a")
        crypto_archive = find_one(root, "libcrypto.a")
        shared = sorted(
            str(path.relative_to(root))
            for pattern in (
                "lib*/**/libssl.so*",
                "lib*/**/libcrypto.so*",
                "lib*/**/libssl.dylib",
                "lib*/**/libcrypto.dylib",
            )
            for path in root.glob(pattern)
            if path.is_file()
        )
        checks["static_archives_exact_once"] = (
            ssl_archive is not None and crypto_archive is not None
        )
        checks["shared_ssl_crypto_absent"] = len(shared) == 0
        details["shared_ssl_crypto"] = shared

        manifest_path = root / ".ninlil-openssl-pin.json"
        manifest: dict[str, object] = {}
        if manifest_path.is_file():
            try:
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                manifest = {}
        expected_manifest = {
            "archive_sha256": PIN_ARCHIVE_SHA256,
            "configure": PIN_CONFIGURE,
            "peeled_commit": PIN_COMMIT,
            "static_only": True,
            "tag": PIN_TAG,
            "version": PIN_VERSION,
        }
        checks["install_manifest_exact"] = all(
            manifest.get(key) == value
            for key, value in expected_manifest.items()
        )
        try:
            manifest_prefix = Path(str(manifest.get("prefix", ""))).resolve()
        except OSError:
            manifest_prefix = Path("/")
        checks["install_manifest_prefix_exact"] = manifest_prefix == root

        openssl_bin = root / "bin" / "openssl"
        rc, version_out = run_output(
            [str(openssl_bin), "version", "-v"]
        ) if openssl_bin.is_file() else (127, "missing")
        version_out = version_out.strip()
        checks["runtime_version_exact"] = (
            rc == 0 and version_out in PIN_VERSION_TEXTS
        )
        details["runtime_version"] = version_out
    else:
        checks["static_archives_exact_once"] = False
        checks["shared_ssl_crypto_absent"] = False
        checks["install_manifest_exact"] = False
        checks["install_manifest_prefix_exact"] = False
        checks["runtime_version_exact"] = False

    if checks["source_archive_supplied"] and archive is not None:
        actual_archive_sha = sha256_file(archive)
        checks["source_archive_sha256_exact"] = (
            actual_archive_sha == PIN_ARCHIVE_SHA256
        )
        details["source_archive_sha256"] = actual_archive_sha
    else:
        checks["source_archive_sha256_exact"] = False

    if (
        checks["cmake_cache_supplied"]
        and cmake_cache is not None
        and ssl_archive is not None
        and crypto_archive is not None
        and root is not None
    ):
        cache = cache_values(cmake_cache)
        try:
            cached_ssl = Path(cache.get("OPENSSL_SSL_LIBRARY", "")).resolve()
            cached_crypto = Path(
                cache.get("OPENSSL_CRYPTO_LIBRARY", "")
            ).resolve()
            cached_include = Path(
                cache.get("OPENSSL_INCLUDE_DIR", "")
            ).resolve()
        except OSError:
            cached_ssl = cached_crypto = cached_include = Path("/")
        checks["cmake_static_ssl_exact"] = cached_ssl == ssl_archive
        checks["cmake_static_crypto_exact"] = cached_crypto == crypto_archive
        checks["cmake_include_under_pin"] = (
            cached_include == (root / "include").resolve()
        )
        checks["cmake_authority_option_on"] = (
            cache.get("NINLIL_WIFI_OPENSSL_AUTHORITY") == "ON"
        )
    else:
        checks["cmake_static_ssl_exact"] = False
        checks["cmake_static_crypto_exact"] = False
        checks["cmake_include_under_pin"] = False
        checks["cmake_authority_option_on"] = False

    if (
        checks["link_evidence_supplied"]
        and link_evidence is not None
        and ssl_archive is not None
        and crypto_archive is not None
    ):
        link_text = link_evidence.read_text(
            encoding="utf-8", errors="replace"
        )
        checks["link_command_has_static_ssl"] = str(ssl_archive) in link_text
        checks["link_command_has_static_crypto"] = (
            str(crypto_archive) in link_text
        )
        checks["link_command_has_no_shared_ssl_crypto"] = re.search(
            r"lib(?:ssl|crypto)\.(?:so(?:\.\d+)*|dylib)", link_text
        ) is None
    else:
        checks["link_command_has_static_ssl"] = False
        checks["link_command_has_static_crypto"] = False
        checks["link_command_has_no_shared_ssl_crypto"] = False

    if checks["binary_supplied"] and binary is not None:
        if platform.system() == "Darwin":
            rc, dynamic_out = run_output(["otool", "-L", str(binary)])
        else:
            rc, dynamic_out = run_output(["readelf", "-d", str(binary)])
        checks["binary_dynamic_inspection_ok"] = rc == 0
        checks["binary_has_no_dynamic_ssl_crypto"] = (
            rc == 0
            and re.search(
                r"lib(?:ssl|crypto)\.(?:so(?:\.\d+)*|dylib)", dynamic_out
            )
            is None
        )
        rc, nm_out = run_output(["nm", "-g", str(binary)])
        defined = False
        if rc == 0:
            for line in nm_out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                name = parts[-1].lstrip("_")
                if name == "OPENSSL_version_major":
                    kind = parts[-2] if len(parts) >= 2 else ""
                    if kind.upper() != "U":
                        defined = True
                        break
        checks["binary_retains_static_openssl_symbol"] = defined
    else:
        checks["binary_dynamic_inspection_ok"] = False
        checks["binary_has_no_dynamic_ssl_crypto"] = False
        checks["binary_retains_static_openssl_symbol"] = False

    source_text = (
        TLS_HOST_SOURCE.read_text(encoding="utf-8", errors="replace")
        if TLS_HOST_SOURCE.is_file()
        else ""
    )
    checks["tls_source_uses_isolated_libctx_default_provider"] = (
        tls_source_isolated(source_text)
    )

    authority_allowed = all(checks.values())
    output = {
        "authority_claim_allowed": authority_allowed,
        "checks": checks,
        "expected": {
            "archive_sha256": PIN_ARCHIVE_SHA256,
            "configure": PIN_CONFIGURE,
            "peeled_commit": PIN_COMMIT,
            "static_only": True,
            "tag": PIN_TAG,
            "version": PIN_VERSION,
        },
        "details": details,
        "mode": "REPORT_ONLY" if args.report_only else "STRICT",
        "provenance_status": "OK" if authority_allowed else "INCOMPLETE",
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if args.report_only:
        return 0
    return 0 if authority_allowed else 1


if __name__ == "__main__":
    sys.exit(main())
