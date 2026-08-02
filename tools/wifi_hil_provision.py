#!/usr/bin/env python3
"""Build a validated, secret-safe ESP-IDF NVS image for wifi_hil_app.

The manifest and all referenced secret files are read locally.  Their contents
are never printed.  Staged files are created with mode 0600 in a mode-0700
directory and the generated CSV contains file paths, not secret values.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


NAMESPACE = "ninlil_wifi"
SCHEMA = 1
LEAF_BYTES = 82
PEM_MAX_STORED_BYTES = 4095
NVS_SIZE = "0x6000"

ROLE = {"client": 1, "server": 2}
AUTH = {
    "wpa2_psk": 1,
    "wpa3_sae": 2,
    "wpa2_wpa3_transition": 3,
}


class ProvisionError(ValueError):
    """Manifest or local provisioning input is not acceptable."""


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProvisionError(f"{name} must be an object")
    return value


def _integer(
    value: Any, name: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProvisionError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ProvisionError(
            f"{name} must be in the closed range {minimum}..{maximum}"
        )
    return value


def _hex(value: Any, name: str, length: int, nonzero: bool = True) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise ProvisionError(f"{name} must be exactly {length * 2} hex digits")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ProvisionError(f"{name} must contain only hex digits") from exc
    if nonzero and not any(decoded):
        raise ProvisionError(f"{name} must not be all-zero")
    return decoded


def _read_file(
    manifest_dir: Path,
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProvisionError(f"{name} must be a non-empty file path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = manifest_dir / path
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProvisionError(f"{name} cannot be read: {path}") from exc
    if len(data) < minimum or len(data) > maximum:
        raise ProvisionError(
            f"{name} must contain {minimum}..{maximum} bytes"
        )
    return data


def _leaf(value: Any, name: str, expected_role: int) -> bytes:
    wire = _hex(value, name, LEAF_BYTES)
    if wire[0] != 1 or wire[1] != expected_role:
        raise ProvisionError(f"{name} has the wrong version or TLS role")
    if not any(wire[2:18]):
        raise ProvisionError(f"{name} runtime ID must not be all-zero")
    if not any(wire[18:50]):
        raise ProvisionError(f"{name} attachment binding must not be all-zero")
    if not any(wire[50:66]):
        raise ProvisionError(f"{name} authority ID must not be all-zero")
    if int.from_bytes(wire[66:74], "big") == 0:
        raise ProvisionError(f"{name} authority term must be non-zero")
    if int.from_bytes(wire[74:78], "big") == 0:
        raise ProvisionError(f"{name} credential generation must be non-zero")
    if int.from_bytes(wire[78:82], "big") == 0:
        raise ProvisionError(f"{name} revocation generation must be non-zero")
    return wire


def _validate_leaf_pair(local_leaf: bytes, peer_leaf: bytes) -> None:
    if local_leaf[50:66] != peer_leaf[50:66]:
        raise ProvisionError("local/peer leaf authority IDs differ")
    if local_leaf[66:74] != peer_leaf[66:74]:
        raise ProvisionError("local/peer leaf authority terms differ")
    if local_leaf[18:50] != peer_leaf[18:50]:
        raise ProvisionError("local/peer attachment bindings differ")
    if local_leaf[2:18] == peer_leaf[2:18]:
        raise ProvisionError("local/peer runtime IDs must differ")


def _validate_pem(data: bytes, name: str, expected_label: bytes) -> bytes:
    if b"\x00" in data:
        raise ProvisionError(f"{name} must not contain embedded NUL bytes")
    if not data.startswith(b"-----BEGIN "):
        raise ProvisionError(f"{name} is not PEM")
    if expected_label not in data.splitlines()[0]:
        raise ProvisionError(f"{name} has an unexpected PEM object type")
    return data


def _stage(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o600)
    return path.resolve()


def _load_manifest(path: Path) -> tuple[dict[str, Any], Path]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"manifest cannot be read as UTF-8 JSON: {path}") from exc
    return _object(document, "manifest"), path.resolve().parent


def build_csv_rows(
    manifest: dict[str, Any],
    manifest_dir: Path,
    stage_dir: Path,
) -> list[list[str]]:
    schema = _integer(manifest.get("schema"), "schema", SCHEMA, SCHEMA)
    if manifest.get("enabled") is not True:
        raise ProvisionError("enabled must be true")
    role_name = manifest.get("role")
    if role_name not in ROLE:
        raise ProvisionError("role must be 'client' or 'server'")
    role = ROLE[role_name]

    wifi = _object(manifest.get("wifi"), "wifi")
    auth_name = wifi.get("auth")
    if auth_name not in AUTH:
        raise ProvisionError(
            "wifi.auth must be wpa2_psk, wpa3_sae, or "
            "wpa2_wpa3_transition"
        )
    if wifi.get("pmf_required") is not True:
        raise ProvisionError("wifi.pmf_required must be true")
    channel = _integer(wifi.get("channel"), "wifi.channel", 0, 14)
    profile_revision = _integer(
        wifi.get("profile_revision"),
        "wifi.profile_revision",
        1,
        (1 << 64) - 1,
    )
    profile_id = _hex(wifi.get("profile_id_hex"), "wifi.profile_id_hex", 16)
    cred_bind = _hex(
        wifi.get("credential_binding_id_hex"),
        "wifi.credential_binding_id_hex",
        16,
    )
    ssid = _read_file(
        manifest_dir, wifi.get("ssid_file"), "wifi.ssid_file", 1, 32
    )
    if b"\x00" in ssid or b"\r" in ssid or b"\n" in ssid:
        raise ProvisionError("wifi.ssid_file contains NUL or a line ending")
    psk = _read_file(
        manifest_dir, wifi.get("psk_file"), "wifi.psk_file", 8, 64
    )
    if b"\x00" in psk or b"\r" in psk or b"\n" in psk:
        raise ProvisionError("wifi.psk_file contains NUL or a line ending")
    if len(psk) == 64:
        try:
            int(psk, 16)
        except ValueError as exc:
            raise ProvisionError(
                "a 64-byte Wi-Fi PSK must contain only ASCII hex"
            ) from exc

    endpoint = _object(manifest.get("endpoint"), "endpoint")
    peer_port = _integer(
        endpoint.get("port"), "endpoint.port", 1, (1 << 16) - 1
    )
    if role_name == "server":
        if endpoint.get("address") not in (None, ""):
            raise ProvisionError("server endpoint.address must be omitted")
        address_kind = 3
        peer_address = bytes(16)
    else:
        address_value = endpoint.get("address")
        if not isinstance(address_value, str) or not address_value:
            raise ProvisionError("client endpoint.address is required")
        try:
            address = ipaddress.ip_address(address_value)
        except ValueError as exc:
            raise ProvisionError(
                "client endpoint.address must be a numeric IPv4 or IPv6 address"
            ) from exc
        if address.is_unspecified or address.is_multicast:
            raise ProvisionError(
                "client endpoint.address must be a non-zero unicast address"
            )
        if isinstance(address, ipaddress.IPv6Address) and address.is_link_local:
            raise ProvisionError("link-local IPv6 is not supported by this profile")
        address_kind = 1 if isinstance(address, ipaddress.IPv4Address) else 2
        peer_address = address.packed.ljust(16, b"\x00")

    session = _object(manifest.get("session"), "session")
    config_revision = _integer(
        session.get("configuration_revision"),
        "session.configuration_revision",
        1,
        (1 << 64) - 1,
    )
    assignment_epoch = _integer(
        session.get("assignment_epoch"),
        "session.assignment_epoch",
        1,
        (1 << 64) - 1,
    )
    instance_id = _hex(
        session.get("instance_id_hex"), "session.instance_id_hex", 16
    )
    local_leaf = _leaf(
        session.get("local_leaf_hex"),
        "session.local_leaf_hex",
        role,
    )
    peer_leaf = _leaf(
        session.get("peer_leaf_hex"),
        "session.peer_leaf_hex",
        2 if role == 1 else 1,
    )
    _validate_leaf_pair(local_leaf, peer_leaf)
    fabric_desc = _hex(
        session.get("fabric_descriptor_digest_hex"),
        "session.fabric_descriptor_digest_hex",
        32,
    )
    registry_epoch = _hex(
        session.get("registry_epoch_id_hex"),
        "session.registry_epoch_id_hex",
        16,
    )
    credential = _hex(
        session.get("credential_candidate_digest_hex"),
        "session.credential_candidate_digest_hex",
        32,
    )
    ca_pem = _validate_pem(
        _read_file(
            manifest_dir,
            session.get("ca_pem_file"),
            "session.ca_pem_file",
            32,
            PEM_MAX_STORED_BYTES,
        ),
        "session.ca_pem_file",
        b"CERTIFICATE",
    )
    cert_pem = _validate_pem(
        _read_file(
            manifest_dir,
            session.get("cert_pem_file"),
            "session.cert_pem_file",
            32,
            PEM_MAX_STORED_BYTES,
        ),
        "session.cert_pem_file",
        b"CERTIFICATE",
    )
    key_pem = _validate_pem(
        _read_file(
            manifest_dir,
            session.get("key_pem_file"),
            "session.key_pem_file",
            32,
            PEM_MAX_STORED_BYTES,
        ),
        "session.key_pem_file",
        b"PRIVATE KEY",
    )

    blobs = {
        "profile_id": profile_id,
        "cred_bind": cred_bind,
        "instance_id": instance_id,
        "peer_addr": peer_address,
        "local_leaf": local_leaf,
        "peer_leaf": peer_leaf,
        "fabric_desc": fabric_desc,
        "registry_epoch": registry_epoch,
        "credential": credential,
        "ssid": ssid,
        "psk": psk,
        "ca_pem": ca_pem,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    }
    staged = {
        key: _stage(stage_dir / f"{key}.bin", value)
        for key, value in blobs.items()
    }

    rows: list[list[str]] = [
        ["key", "type", "encoding", "value"],
        [NAMESPACE, "namespace", "", ""],
        ["schema", "data", "u32", str(schema)],
        ["enabled", "data", "u8", "1"],
        ["role", "data", "u8", str(role)],
        ["auth", "data", "u8", str(AUTH[auth_name])],
        ["pmf", "data", "u8", "1"],
        ["channel", "data", "u8", str(channel)],
        ["addr_kind", "data", "u8", str(address_kind)],
        ["peer_port", "data", "u16", str(peer_port)],
        ["profile_rev", "data", "u64", str(profile_revision)],
        ["config_rev", "data", "u64", str(config_revision)],
        ["assign_epoch", "data", "u64", str(assignment_epoch)],
    ]
    rows.extend(
        [key, "file", "binary", str(staged[key])]
        for key in (
            "profile_id",
            "cred_bind",
            "instance_id",
            "peer_addr",
            "local_leaf",
            "peer_leaf",
            "fabric_desc",
            "registry_epoch",
            "credential",
            "ssid",
            "psk",
            "ca_pem",
            "cert_pem",
            "key_pem",
        )
    )
    return rows


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerows(rows)
    path.chmod(0o600)


def _wipe_and_unlink(path: Path) -> None:
    """Best-effort overwrite followed by unlink for a tool-owned regular file."""
    try:
        if path.is_file() and not path.is_symlink():
            length = path.stat().st_size
            with path.open("r+b", buffering=0) as stream:
                block = bytes(4096)
                remaining = length
                while remaining:
                    count = min(remaining, len(block))
                    stream.write(block[:count])
                    remaining -= count
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        # Unlink is still attempted. COW/flash media do not permit a secure
        # deletion claim even when the overwrite succeeds.
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _cleanup_staging(stage_dir: Path) -> bool:
    if not stage_dir.exists() or stage_dir.is_symlink():
        return not stage_dir.exists()
    for name in (
        "profile_id.bin",
        "cred_bind.bin",
        "instance_id.bin",
        "peer_addr.bin",
        "local_leaf.bin",
        "peer_leaf.bin",
        "fabric_desc.bin",
        "registry_epoch.bin",
        "credential.bin",
        "ssid.bin",
        "psk.bin",
        "ca_pem.bin",
        "cert_pem.bin",
        "key_pem.bin",
        "wifi_hil_nvs.csv",
    ):
        _wipe_and_unlink(stage_dir / name)
    try:
        stage_dir.rmdir()
    except OSError:
        pass
    return not stage_dir.exists()


def _generator_path(idf_path: Path) -> Path:
    return (
        idf_path
        / "components"
        / "nvs_flash"
        / "nvs_partition_generator"
        / "nvs_partition_gen.py"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Wi-Fi HIL provisioning and build an NVS partition "
            "without printing secret material"
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--idf-path",
        type=Path,
        default=Path(os.environ["IDF_PATH"]) if "IDF_PATH" in os.environ else None,
    )
    parser.add_argument(
        "--csv-only",
        action="store_true",
        help="write validated staging files and CSV without invoking ESP-IDF",
    )
    args = parser.parse_args(argv)

    output_dir = args.output_dir.expanduser().resolve()
    stage_dir = output_dir / ".staging"
    keep_staging = bool(args.csv_only)
    try:
        if output_dir.exists() and any(output_dir.iterdir()):
            raise ProvisionError(
                f"output directory must be absent or empty: {output_dir}"
            )
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        output_dir.chmod(0o700)
        stage_dir.mkdir(mode=0o700)
        manifest, manifest_dir = _load_manifest(args.manifest.expanduser())
        rows = build_csv_rows(manifest, manifest_dir, stage_dir)
        csv_path = stage_dir / "wifi_hil_nvs.csv"
        _write_csv(csv_path, rows)
        print(f"validated_csv={csv_path}")
        if args.csv_only:
            print("temporary_staging=RETAINED_FOR_CSV_ONLY")
            print("nvs_binary=NOT_GENERATED")
            return 0
        if args.idf_path is None:
            raise ProvisionError(
                "IDF_PATH is not set; export ESP-IDF v5.5.3 or use --csv-only"
            )
        generator = _generator_path(args.idf_path.expanduser().resolve())
        if not generator.is_file():
            raise ProvisionError(
                f"ESP-IDF NVS generator is missing: {generator}"
            )
        binary = output_dir / "wifi_hil_nvs.bin"
        subprocess.run(
            [
                sys.executable,
                str(generator),
                "generate",
                str(csv_path),
                binary.name,
                NVS_SIZE,
                "--outdir",
                str(output_dir),
            ],
            check=True,
        )
        binary.chmod(0o600)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if not _cleanup_staging(stage_dir):
            raise ProvisionError(
                f"temporary staging could not be removed: {stage_dir}"
            )
        print(f"nvs_binary={binary}")
        print(f"nvs_binary_sha256={digest}")
        print("temporary_staging=REMOVED")
        return 0
    except (ProvisionError, subprocess.CalledProcessError, OSError) as exc:
        print(f"wifi_hil_provision: error: {exc}", file=sys.stderr)
        return 2
    finally:
        if not keep_staging:
            _cleanup_staging(stage_dir)


if __name__ == "__main__":
    raise SystemExit(main())
