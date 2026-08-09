#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import http.client
from pathlib import Path
import threading
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

    def test_demo_query_loads_the_ui(self) -> None:
        app = MODULE.LabApplication()
        server = MODULE.ThreadingHTTPServer(
            ("127.0.0.1", 0), MODULE.make_handler(app, "test-token")
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.request("GET", "/?demo=1")
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn(b"Ninlil Mesh Lab", body)
            self.assertIn(b"test-token", body)
            connection.close()

            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.request(
                "POST", "/api/attach-all", body=b"{}",
                headers={"Content-Type": "application/json",
                         "X-Ninlil-Token": "wrong"},
            )
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()

            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.request(
                "POST", "/api/attach-all", body=b"x" * 4097,
                headers={"Content-Type": "application/json",
                         "X-Ninlil-Token": "test-token"},
            )
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()

            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.putrequest("GET", "/", skip_host=True)
            connection.putheader("Host", "example.invalid")
            connection.endheaders()
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
