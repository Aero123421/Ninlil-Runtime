#!/usr/bin/env python3
"""Fail-closed ESP-IDF v5.5.3 R7/Wi-Fi allocator closure proof.

This gate binds four independent facts:

* the repository production sources implement one closed
  OTHER_REGISTERED(R7_RAW_V1) owner;
* the pinned ESP-IDF mbedTLS sources have the exact allocation closure used
  to derive the 304-byte reservation;
* the ESP component archive retains the required definitions/relocations; and
* the final ESP32-S3 ELF retains the real R7 callback call graph and exact
  target ABI/charge probe sizes.

It is target-software evidence only.  It never upgrades physical HIL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

REPO_CLOSURE_PATHS = (
    "ports/esp-idf/src/r7_crypto_mbedtls.c",
    "ports/esp-idf/src/r7_crypto_mbedtls.h",
    "src/radio/r7_crypto_portable.c",
    "src/radio/r7_crypto_provider.h",
    "src/transport/wifi_v1/wifi_esp_tls_allocator.c",
    "src/transport/wifi_v1/wifi_esp_tls_allocator.h",
    "src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c",
    "src/transport/wifi_v1/wifi_tls_arena.c",
    "src/transport/wifi_v1/wifi_tls_arena.h",
    "src/transport/wifi_v1/wifi_tls_resource_policy.c",
    "src/transport/wifi_v1/wifi_tls_resource_policy.h",
    "ports/esp-idf/components/ninlil/CMakeLists.txt",
    "ports/esp-idf/wifi_hil_app/main/CMakeLists.txt",
    "ports/esp-idf/wifi_hil_app/main/main.c",
)

IDF_RELATIVE_HASHES = {
    "components/mbedtls/mbedtls/library/hkdf.c":
        "c23ddf951e5037cf279a8974a6b228711ecdc0e7ada33b0eb3937f540079391c",
    "components/mbedtls/mbedtls/library/md.c":
        "5ba79d51ff85951cb4001a22b2428568e4bc1072b367222808f3eac1ad91884d",
    "components/mbedtls/mbedtls/library/gcm.c":
        "5ce85be78c3367a78088f892ad31e45d57681e604b7672e635071408612d9f81",
    "components/mbedtls/mbedtls/library/cipher.c":
        "e9e81deb2e31bfed80278428959b0a115de4cd454a13ecffb913748fd9937eff",
    "components/mbedtls/mbedtls/library/cipher_wrap.c":
        "fb742e7fd4e2c7a8dbf67206e554ec20095a2f6cab3f4d38d1cc846466fea673",
    "components/mbedtls/mbedtls/include/mbedtls/gcm.h":
        "7bc4445fb595f2d65ea940b0a0afdaa1bbf92fbb6a90adae95e1d7d2a6a4a037",
    "components/mbedtls/mbedtls/include/mbedtls/aes.h":
        "ce71f35d91cf1609bddff21d613863c1177bccc97327f7994c39965ebf044b56",
}

EXACT_TARGET_PROBES = {
    "ninlil_wifi_esp_tls_target_max_align_size_probe": 16,
    "ninlil_wifi_esp_tls_target_max_align_alignment_probe": 8,
    "ninlil_wifi_esp_tls_target_r7_sha_context_size_probe": 108,
    "ninlil_wifi_esp_tls_target_r7_sha_charge_probe": 128,
    "ninlil_wifi_esp_tls_target_r7_hmac_charge_probe": 152,
    "ninlil_wifi_esp_tls_target_r7_aes_context_size_probe": 280,
    "ninlil_wifi_esp_tls_target_r7_gcm_charge_probe": 304,
    "ninlil_wifi_esp_tls_target_r7_reservation_probe": 304,
}

FINAL_R7_ROOTS = (
    "ninlil_r7_crypto_mbedtls_provider_init",
    "ninlil_r7_crypto_hkdf_extract_sha256",
    "ninlil_r7_crypto_hkdf_expand_sha256",
    "ninlil_r7_crypto_aes128_gcm_seal",
    "ninlil_r7_crypto_aes128_gcm_open",
    "ninlil_r7_mbedtls_hkdf_extract_sha256",
    "ninlil_r7_mbedtls_hkdf_expand_sha256",
    "ninlil_r7_mbedtls_aes128_gcm_seal",
    "ninlil_r7_mbedtls_aes128_gcm_open",
    "ninlil_wifi_esp_tls_allocator_other_register",
    "ninlil_wifi_esp_tls_allocator_other_snapshot",
    "ninlil_wifi_esp_tls_allocator_trace_at",
    "ninlil_wifi_esp_tls_allocator_owner_enter",
    "ninlil_wifi_esp_tls_allocator_owner_leave_checked",
)

R7_OBJECT_UNDEFINED = (
    "mbedtls_gcm_auth_decrypt",
    "mbedtls_gcm_crypt_and_tag",
    "mbedtls_gcm_free",
    "mbedtls_gcm_init",
    "mbedtls_gcm_setkey",
    "mbedtls_hkdf_extract",
    "mbedtls_hkdf_expand",
    "mbedtls_md_info_from_type",
    "mbedtls_sha256_finish",
    "mbedtls_sha256_free",
    "mbedtls_sha256_init",
    "mbedtls_sha256_starts",
    "mbedtls_sha256_update",
    "ninlil_wifi_esp_tls_allocator_bootstrap",
    "ninlil_wifi_esp_tls_allocator_other_register",
    "ninlil_wifi_esp_tls_allocator_other_release",
    "ninlil_wifi_esp_tls_allocator_other_snapshot",
    "ninlil_wifi_esp_tls_allocator_owner_enter",
    "ninlil_wifi_esp_tls_allocator_owner_leave_checked",
)

ALLOCATOR_OBJECT_UNDEFINED = (
    "heap_caps_calloc",
    "heap_caps_free",
    "mbedtls_platform_set_calloc_free",
)

CONTRACT = {
    "component_id": "0x52375231",
    "r7_other_registered_bytes": 304,
    "wifi_r7_total_bytes": 262448,
    "wifi_r7_internal_envelope_bytes": 164144,
    "wifi_r7_internal_only_bytes": 327984,
    "trace_capacity": 32,
    "idf_version": "v5.5.3",
}

# Filled only after the production source set is frozen.  A source edit must
# deliberately update this value after independent review.
EXPECTED_CLOSURE_ROOT = (
    "755959d4d2d7f00501b1967e1aa7002fb39a5460cbb54e137fd47323176c0387"
)


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_nm(text: str) -> dict[str, tuple[int, int, str]]:
    symbols: dict[str, tuple[int, int, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 1:
            kind, name = parts
            symbols[name] = (0, 0, kind)
            continue
        if len(parts) < 3:
            continue
        if len(parts) >= 4:
            address_text, size_text, kind, name = parts[-4:]
            try:
                address = int(address_text, 16)
                size = int(size_text, 16)
            except ValueError:
                continue
        else:
            address, size, kind, name = 0, 0, parts[-2], parts[-1]
        if len(kind) == 1:
            symbols[name] = (address, size, kind)
    return symbols


def run_text(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing tool {command[0]}") from exc
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{output.strip()}"
        )
    return output


def require_tokens(
    errors: list[str], label: str, text: str, tokens: tuple[str, ...]
) -> None:
    for token in tokens:
        if token not in text:
            errors.append(f"{label}: missing token {token!r}")


def source_closure(idf_path: Path) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    repo_hashes: dict[str, str] = {}
    for relative in REPO_CLOSURE_PATHS:
        path = REPO / relative
        if not path.is_file():
            errors.append(f"repository closure source missing: {relative}")
            continue
        repo_hashes[relative] = sha256_file(path)

    idf_hashes: dict[str, str] = {}
    idf_texts: dict[str, str] = {}
    for relative, expected in IDF_RELATIVE_HASHES.items():
        path = idf_path / relative
        if not path.is_file():
            errors.append(f"pinned ESP-IDF source missing: {relative}")
            continue
        measured = sha256_file(path)
        idf_hashes[relative] = measured
        idf_texts[relative] = path.read_text(
            encoding="utf-8", errors="strict"
        )
        if measured != expected:
            errors.append(
                f"ESP-IDF source hash drift: {relative} "
                f"measured={measured} expected={expected}"
            )

    if errors:
        return {}, errors

    allocator = (REPO / REPO_CLOSURE_PATHS[4]).read_text(encoding="utf-8")
    r7 = (REPO / REPO_CLOSURE_PATHS[0]).read_text(encoding="utf-8")
    policy = (
        REPO / "src/transport/wifi_v1/wifi_tls_resource_policy.h"
    ).read_text(encoding="utf-8")
    hil = (
        REPO / "ports/esp-idf/wifi_hil_app/main/main.c"
    ).read_text(encoding="utf-8")

    require_tokens(
        errors,
        "allocator",
        allocator,
        (
            "NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1",
            "ninlil_wifi_esp_tls_allocator_other_register",
            "ninlil_wifi_esp_tls_allocator_other_release",
            "ninlil_wifi_esp_tls_allocator_other_snapshot",
            "ninlil_wifi_esp_tls_allocator_owner_leave_checked",
            "NINLIL_WIFI_ESP_TLS_TRACE_FATAL",
        ),
    )
    if allocator.count("heap_caps_calloc(") != 4:
        errors.append("allocator: raw heap_caps_calloc callsites must equal 4")
    if allocator.count("heap_caps_free(") != 1:
        errors.append("allocator: raw heap_caps_free callsites must equal 1")

    require_tokens(
        errors,
        "R7 adapter",
        r7,
        (
            "ninlil_wifi_esp_tls_allocator_bootstrap",
            "ninlil_wifi_esp_tls_allocator_other_register",
            "ninlil_wifi_esp_tls_allocator_other_release",
            "ninlil_r7_crypto_mbedtls_provider_close",
            "NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET",
        ),
    )
    if r7.count("ninlil_r7_mbedtls_owner_begin(ctx)") != 5:
        errors.append("R7 adapter: exactly five callback owner entries required")
    if r7.count("ninlil_r7_mbedtls_owner_finish(ctx, status)") != 5:
        errors.append("R7 adapter: exactly five callback owner leaves required")
    if "WIFI_TLS_GLOBAL_OWNER" in r7 or "CRYPTO_GLOBAL" in r7:
        errors.append("R7 adapter: CRYPTO_GLOBAL charging is forbidden")

    require_tokens(
        errors,
        "resource policy",
        policy,
        (
            "#define NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET 304u",
            "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_COMPOSITION_TOTAL_BUDGET 262448u",
            "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ENVELOPE 164144u",
            "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ONLY_REQUIREMENT_BYTES 327984u",
        ),
    )
    profile_probe = (
        REPO
        / "src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c"
    ).read_text(encoding="utf-8")
    require_tokens(
        errors,
        "target profile probe",
        profile_probe,
        (
            "#if defined(MBEDTLS_BLOCK_CIPHER_C)",
            "defined(MBEDTLS_MD_SHA256_VIA_PSA)",
        ),
    )
    require_tokens(
        errors,
        "Wi-Fi HIL instrumentation",
        hil,
        (
            "r7_cotenant_start",
            "ninlil_r7_crypto_mbedtls_provider_init",
            "ninlil_r7_crypto_hkdf_extract_sha256",
            "ninlil_r7_crypto_hkdf_expand_sha256",
            "ninlil_r7_crypto_aes128_gcm_seal",
            "ninlil_r7_crypto_aes128_gcm_open",
            "g_r7_allocator.peak_bytes",
            "g_r7_allocator.outstanding_allocations",
            "allocator_trace_dropped",
            "R7_ALLOC_TRACE",
            "scope=runtime_observation",
            "physical_ap_hil=NOT_RUN",
        ),
    )

    hkdf = idf_texts["components/mbedtls/mbedtls/library/hkdf.c"]
    md = idf_texts["components/mbedtls/mbedtls/library/md.c"]
    gcm = idf_texts["components/mbedtls/mbedtls/library/gcm.c"]
    cipher = idf_texts["components/mbedtls/mbedtls/library/cipher.c"]
    cipher_wrap = idf_texts[
        "components/mbedtls/mbedtls/library/cipher_wrap.c"
    ]
    gcm_h = idf_texts[
        "components/mbedtls/mbedtls/include/mbedtls/gcm.h"
    ]
    aes_h = idf_texts[
        "components/mbedtls/mbedtls/include/mbedtls/aes.h"
    ]
    require_tokens(
        errors,
        "pinned hkdf.c",
        hkdf,
        (
            "return mbedtls_md_hmac(",
            "mbedtls_md_setup(&ctx, md, 1)",
        ),
    )
    require_tokens(
        errors,
        "pinned md.c",
        md,
        (
            "mbedtls_calloc(1, sizeof(mbedtls_##type##_context))",
            "mbedtls_calloc(2, md_info->block_size)",
        ),
    )
    require_tokens(
        errors,
        "pinned GCM closure",
        gcm + gcm_h + cipher + cipher_wrap + aes_h,
        (
            "mbedtls_cipher_setup(&ctx->cipher_ctx, cipher_info)",
            "mbedtls_cipher_get_base(cipher_info)->ctx_alloc_func()",
            "mbedtls_calloc(1, sizeof(mbedtls_aes_context))",
            "typedef struct mbedtls_aes_context",
        ),
    )

    manifest: dict[str, object] = {
        "contract": CONTRACT,
        "exact_target_probes": EXACT_TARGET_PROBES,
        "final_roots": FINAL_R7_ROOTS,
        "idf_sha256": idf_hashes,
        "repo_sha256": repo_hashes,
    }
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    root = hashlib.sha256(canonical).hexdigest()
    manifest["closure_root_sha256"] = root
    return manifest, errors


def archive_object(
    archive: Path, member: str, ar_tool: str, destination: Path
) -> Path:
    try:
        result = subprocess.run(
            [ar_tool, "p", str(archive), member],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing tool {ar_tool}") from exc
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError(
            f"{ar_tool} p failed for member {member}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    path = destination / member
    path.write_bytes(result.stdout)
    return path


def artifact_closure(
    elf: Path,
    map_path: Path,
    archive: Path,
    nm_tool: str,
    ar_tool: str,
) -> list[str]:
    errors: list[str] = []
    for label, path in (
        ("ELF", elf),
        ("map", map_path),
        ("component archive", archive),
    ):
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"{label} missing/empty: {path}")
    if errors:
        return errors

    try:
        elf_nm = parse_nm(run_text([nm_tool, "-S", "-a", str(elf)]))
        map_text = map_path.read_text(encoding="utf-8", errors="replace")
        members = {
            line.strip()
            for line in run_text([ar_tool, "t", str(archive)]).splitlines()
            if line.strip()
        }
    except (OSError, RuntimeError) as exc:
        return [str(exc)]

    for symbol in FINAL_R7_ROOTS:
        row = elf_nm.get(symbol)
        if (
            row is None
            or row[0] == 0
            or row[1] == 0
            or row[2].upper() == "U"
        ):
            errors.append(f"final ELF root missing/discarded: {symbol}")
        if symbol not in map_text:
            errors.append(f"final map root missing: {symbol}")
    for symbol, expected in EXACT_TARGET_PROBES.items():
        row = elf_nm.get(symbol)
        if row is None or row[0] == 0 or row[1] != expected:
            errors.append(
                f"target probe mismatch {symbol}: "
                f"measured={None if row is None else row[1]} expected={expected}"
            )

    required_members = {
        "r7_crypto_mbedtls.c.obj",
        "r7_crypto_portable.c.obj",
        "wifi_esp_tls_allocator.c.obj",
        "wifi_esp_mbedtls_profile_probe.c.obj",
    }
    missing_members = sorted(required_members - members)
    if missing_members:
        errors.append(f"component archive members missing: {missing_members}")
        return errors

    with tempfile.TemporaryDirectory(prefix="ninlil-r7-wifi-closure-") as td:
        destination = Path(td)
        try:
            r7_object = archive_object(
                archive, "r7_crypto_mbedtls.c.obj", ar_tool, destination
            )
            allocator_object = archive_object(
                archive,
                "wifi_esp_tls_allocator.c.obj",
                ar_tool,
                destination,
            )
            r7_nm = parse_nm(run_text([nm_tool, "-S", "-a", str(r7_object)]))
            allocator_nm = parse_nm(
                run_text([nm_tool, "-S", "-a", str(allocator_object)])
            )
        except (OSError, RuntimeError) as exc:
            return errors + [str(exc)]

        for symbol in (
            "ninlil_r7_crypto_mbedtls_provider_init",
            "ninlil_r7_crypto_mbedtls_provider_close",
            "ninlil_r7_mbedtls_sha256",
            "ninlil_r7_mbedtls_hkdf_extract_sha256",
            "ninlil_r7_mbedtls_hkdf_expand_sha256",
            "ninlil_r7_mbedtls_aes128_gcm_seal",
            "ninlil_r7_mbedtls_aes128_gcm_open",
        ):
            row = r7_nm.get(symbol)
            if row is None or row[1] == 0 or row[2].upper() == "U":
                errors.append(f"R7 object definition missing/zero: {symbol}")
        for symbol in R7_OBJECT_UNDEFINED:
            row = r7_nm.get(symbol)
            if row is None or row[2].upper() != "U":
                errors.append(f"R7 object relocation missing: {symbol}")
        for symbol in ALLOCATOR_OBJECT_UNDEFINED:
            row = allocator_nm.get(symbol)
            if row is None or row[2].upper() != "U":
                errors.append(f"allocator object relocation missing: {symbol}")
    return errors


def self_test() -> int:
    sample = parse_nm(
        "42000000 00000020 T retained\n"
        "00000000 00000000 U dependency\n"
    )
    if sample.get("retained") != (0x42000000, 0x20, "T"):
        return fail("self-test retained nm parse")
    if sample.get("dependency", (0, 0, ""))[2] != "U":
        return fail("self-test undefined nm parse")

    base = {
        "contract": CONTRACT,
        "exact_target_probes": EXACT_TARGET_PROBES,
        "repo_sha256": {"a": "0" * 64},
    }
    first = hashlib.sha256(
        json.dumps(base, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    mutated = json.loads(json.dumps(base))
    mutated["contract"]["r7_other_registered_bytes"] = 305
    second = hashlib.sha256(
        json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if first == second:
        return fail("self-test canonical root mutation false-green")

    measured = dict(IDF_RELATIVE_HASHES)
    key = next(iter(measured))
    measured[key] = "0" * 64
    if measured == IDF_RELATIVE_HASHES:
        return fail("self-test IDF hash mutation false-green")
    print("OK r7_wifi_allocator_closure_gate self-test")
    return 0


def main() -> int:
    if sys.argv[1:] == ["self-test"]:
        return self_test()
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True)
    parser.add_argument("--map", required=True)
    parser.add_argument("--component-archive", required=True)
    parser.add_argument("--idf-path", required=True)
    parser.add_argument(
        "--nm-tool", default="xtensa-esp32s3-elf-nm"
    )
    parser.add_argument(
        "--ar-tool", default="xtensa-esp32s3-elf-ar"
    )
    parser.add_argument("--evidence-json", default="")
    parser.add_argument(
        "--expected-root",
        default=EXPECTED_CLOSURE_ROOT,
        help="independently pinned canonical closure root",
    )
    args = parser.parse_args()

    manifest, source_errors = source_closure(Path(args.idf_path))
    if source_errors:
        return fail("; ".join(source_errors))
    measured_root = str(manifest["closure_root_sha256"])
    if (
        args.expected_root == "TO_BE_PINNED_AFTER_SOURCE_FREEZE"
        or measured_root != args.expected_root
    ):
        return fail(
            "canonical closure root mismatch/unpinned: "
            f"measured={measured_root} expected={args.expected_root}"
        )

    artifact_errors = artifact_closure(
        Path(args.elf),
        Path(args.map),
        Path(args.component_archive),
        args.nm_tool,
        args.ar_tool,
    )
    if artifact_errors:
        return fail("; ".join(artifact_errors))

    manifest["claim"] = "wifi_r7_composition_target_software_candidate"
    manifest["physical_allocator_trace"] = "NOT_RUN"
    manifest["physical_ap_hil"] = "NOT_RUN"
    if args.evidence_json:
        evidence_path = Path(args.evidence_json)
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(
        "OK R7/Wi-Fi allocator closure "
        f"root_sha256={measured_root} target_reservation=304"
    )
    print("physical_allocator_trace=NOT_RUN physical_ap_hil=NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
