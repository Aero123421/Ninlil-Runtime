#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ninlil_lab_console", ROOT / "tools" / "ninlil_lab_console.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NinlilLabConsoleTest(unittest.TestCase):
    def test_mesh_parser_and_command_validation(self) -> None:
        self.assertEqual(
            MODULE.parse_mesh_line(
                "MESH node=0123456789abcdef role=node parent=1122334455667788 hops=2"
            ),
            {
                "node": "0123456789abcdef",
                "role": "node",
                "parent": "1122334455667788",
                "hops": "2",
            },
        )
        self.assertIsNone(MODULE.parse_mesh_line("noise node=0123456789abcdef"))
        self.assertEqual(MODULE.build_command("status"), "MESH STATUS")
        self.assertEqual(
            MODULE.build_command(
                "send", {"destination": "AABBCCDDEEFF0011", "payload": "0102ff"}
            ),
            "MESH SEND aabbccddeeff0011 0102ff",
        )
        self.assertEqual(
            MODULE.build_command(
                "penalty", {"node": "0123456789ABCDEF", "score": 200}
            ),
            "MESH PENALTY 0123456789abcdef 200",
        )
        for action, values in (
            ("send", {"destination": "0" * 16, "payload": "0"}),
            ("send", {"destination": "../ttyUSB0", "payload": "00"}),
            ("penalty", {"node": "0" * 16, "score": 201}),
            ("raw", {"command": "MESH LEAVE"}),
        ):
            with self.subTest(action=action, values=values):
                with self.assertRaises(ValueError):
                    MODULE.build_command(action, values)


if __name__ == "__main__":
    unittest.main()
