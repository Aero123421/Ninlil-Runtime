#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "wifi_hil_provision.py"
SPEC = importlib.util.spec_from_file_location("wifi_hil_provision", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def leaf(role: int, runtime_fill: int) -> str:
    value = bytearray(82)
    value[0] = 1
    value[1] = role
    value[2:18] = bytes([runtime_fill]) * 16
    value[18:50] = bytes([0x33]) * 32
    value[50:66] = bytes([0x44]) * 16
    value[66:74] = (7).to_bytes(8, "big")
    value[74:78] = (3).to_bytes(4, "big")
    value[78:82] = (5).to_bytes(4, "big")
    return value.hex()


class WifiHilProvisionToolTest(unittest.TestCase):
    def material(self, directory: Path) -> dict:
        (directory / "ssid").write_bytes(b"private-ap")
        (directory / "psk").write_bytes(b"0123456789abcdef")
        (directory / "ca.pem").write_bytes(
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
        )
        (directory / "cert.pem").write_bytes(
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
        )
        (directory / "key.pem").write_bytes(
            b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
        )
        return {
            "schema": 1,
            "enabled": True,
            "role": "client",
            "wifi": {
                "auth": "wpa3_sae",
                "pmf_required": True,
                "channel": 0,
                "profile_revision": 1,
                "profile_id_hex": "11" * 16,
                "credential_binding_id_hex": "22" * 16,
                "ssid_file": "ssid",
                "psk_file": "psk",
            },
            "endpoint": {"address": "192.0.2.10", "port": 7443},
            "session": {
                "configuration_revision": 1,
                "assignment_epoch": 1,
                "instance_id_hex": "55" * 16,
                "local_leaf_hex": leaf(1, 0x11),
                "peer_leaf_hex": leaf(2, 0x22),
                "fabric_descriptor_digest_hex": "66" * 32,
                "registry_epoch_id_hex": "77" * 16,
                "credential_candidate_digest_hex": "88" * 32,
                "ca_pem_file": "ca.pem",
                "cert_pem_file": "cert.pem",
                "key_pem_file": "key.pem",
            },
        }

    def test_client_csv_stages_secret_files_without_inline_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            rows = MODULE.build_csv_rows(manifest, root, stage)
            self.assertEqual(rows[1], ["ninlil_wifi", "namespace", "", ""])
            self.assertIn(["role", "data", "u8", "1"], rows)
            self.assertIn(["addr_kind", "data", "u8", "1"], rows)
            psk_row = next(row for row in rows if row[0] == "psk")
            self.assertEqual(psk_row[1:3], ["file", "binary"])
            self.assertNotIn("0123456789abcdef", ",".join(",".join(r) for r in rows))
            self.assertEqual(Path(psk_row[3]).read_bytes(), b"0123456789abcdef")

    def test_server_requires_omitted_address_and_opposite_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            manifest["role"] = "server"
            manifest["endpoint"] = {"port": 7443}
            manifest["session"]["local_leaf_hex"] = leaf(2, 0x11)
            manifest["session"]["peer_leaf_hex"] = leaf(1, 0x22)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            rows = MODULE.build_csv_rows(manifest, root, stage)
            self.assertIn(["role", "data", "u8", "2"], rows)
            self.assertIn(["addr_kind", "data", "u8", "3"], rows)
            peer = next(row for row in rows if row[0] == "peer_addr")
            self.assertEqual(Path(peer[3]).read_bytes(), bytes(16))

    def test_wrong_leaf_role_and_secret_newline_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            manifest["session"]["local_leaf_hex"] = leaf(2, 0x11)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            with self.assertRaises(MODULE.ProvisionError):
                MODULE.build_csv_rows(manifest, root, stage)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            (root / "psk").write_bytes(b"01234567\n")
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            with self.assertRaises(MODULE.ProvisionError):
                MODULE.build_csv_rows(manifest, root, stage)

    def test_leaf_authority_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            peer = bytearray.fromhex(manifest["session"]["peer_leaf_hex"])
            peer[50] ^= 1
            manifest["session"]["peer_leaf_hex"] = peer.hex()
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            with self.assertRaises(MODULE.ProvisionError):
                MODULE.build_csv_rows(manifest, root, stage)

    def test_materialization_is_deterministic_except_for_file_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            stage_a = root / "stage-a"
            stage_b = root / "stage-b"
            stage_a.mkdir(mode=0o700)
            stage_b.mkdir(mode=0o700)
            rows_a = MODULE.build_csv_rows(manifest, root, stage_a)
            rows_b = MODULE.build_csv_rows(manifest, root, stage_b)
            self.assertEqual(
                [row[:3] for row in rows_a],
                [row[:3] for row in rows_b],
            )
            values_a = {
                row[0]: Path(row[3]).read_bytes()
                for row in rows_a
                if row[1:3] == ["file", "binary"]
            }
            values_b = {
                row[0]: Path(row[3]).read_bytes()
                for row in rows_b
                if row[1:3] == ["file", "binary"]
            }
            self.assertEqual(values_a, values_b)

    def test_cleanup_removes_every_tool_owned_staging_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            stage = root / ".staging"
            stage.mkdir(mode=0o700)
            rows = MODULE.build_csv_rows(manifest, root, stage)
            MODULE._write_csv(stage / "wifi_hil_nvs.csv", rows)
            MODULE._cleanup_staging(stage)
            self.assertFalse(stage.exists())

    @unittest.skipUnless(
        os.environ.get("IDF_PATH"),
        "ESP-IDF is required for NVS binary determinism evidence",
    )
    def test_generated_nvs_is_deterministic_and_staging_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.material(root)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            output_a = root / "output-a"
            output_b = root / "output-b"
            self.assertEqual(
                MODULE.main(
                    [
                        "--manifest",
                        str(manifest_path),
                        "--output-dir",
                        str(output_a),
                    ]
                ),
                0,
            )
            self.assertEqual(
                MODULE.main(
                    [
                        "--manifest",
                        str(manifest_path),
                        "--output-dir",
                        str(output_b),
                    ]
                ),
                0,
            )
            binary_a = output_a / "wifi_hil_nvs.bin"
            binary_b = output_b / "wifi_hil_nvs.bin"
            self.assertEqual(binary_a.read_bytes(), binary_b.read_bytes())
            self.assertFalse((output_a / ".staging").exists())
            self.assertFalse((output_b / ".staging").exists())
            self.assertEqual(binary_a.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
