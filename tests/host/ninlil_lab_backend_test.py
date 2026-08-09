#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ninlil_lab_backend", ROOT / "tools" / "ninlil_lab_backend.py")
assert SPEC is not None and SPEC.loader is not None
BACKEND = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKEND)


class NinlilLabBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = [100.0]
        self.wall = [1_725_000_000.0]
        self.peers: dict[str, socket.socket] = {}
        self.open_count: dict[str, int] = {}

        def opener(path: str) -> int:
            self.open_count[path] = self.open_count.get(path, 0) + 1
            host, peer = socket.socketpair()
            self.peers[path] = peer
            return host.detach()

        self.backend = BACKEND.LabBackend(
            port_lister=lambda: ["/dev/demo-a", "/dev/demo-b", "/dev/demo-c"], opener=opener,
            clock=lambda: self.now[0], wall_clock=lambda: self.wall[0],
        )

    def tearDown(self) -> None:
        self.backend.disconnect_all()
        for peer in self.peers.values():
            peer.close()

    def test_attach_all_status_and_structured_node(self) -> None:
        self.assertEqual(
            self.backend.attach_all(),
            ["/dev/demo-a", "/dev/demo-b", "/dev/demo-c"],
        )
        self.backend.service()
        self.assertIn(b"MESH STATUS", self.peers["/dev/demo-a"].recv(128))
        self.backend.ingest("/dev/demo-a", "MESH node=0123456789abcdef role=node joined=1 joining=0 parent=1122334455667788 hops=2 lease_ms=19000 tx=3 rx=4 relay=1 duplicate=0 route_changes=1")
        node = self.backend.snapshot()["nodes"]["0123456789abcdef"]
        self.assertEqual(node["port"], "/dev/demo-a")
        self.assertTrue(node["joined"])
        self.assertEqual((node["parent"], node["hops"], node["lease_ms"], node["relay"]),
                         ("1122334455667788", 2, 19000, 1))
        self.assertEqual(node["last_seen"], 1_725_000_000_000)
        self.backend.ingest(
            "/dev/demo-a",
            "MESH node=0123456789abcdef role=node joined=1 parent=2233445566778899 hops=1 route_changes=2",
        )
        event_kinds = [event["kind"] for event in self.backend.snapshot()["events"]]
        self.assertIn("join", event_kinds)
        self.assertIn("route_change", event_kinds)

    def test_probe_correlates_data_ack_and_preserves_one_in_flight(self) -> None:
        self.backend.attach("/dev/demo-a")
        self.backend.ingest("/dev/demo-a", "MESH node=0123456789abcdef joined=1")
        probe = self.backend.probe("0123456789abcdef", "1122334455667788", "0102")
        self.assertIn(b"MESH SEND 1122334455667788 0102", self.peers["/dev/demo-a"].recv(128))
        with self.assertRaisesRegex(ValueError, "DATA transaction"):
            self.backend.probe("/dev/demo-a", "1122334455667788")
        self.now[0] += 1.234
        self.wall[0] += 1.234
        self.backend.ingest("/dev/demo-a", "MESH data_ack attempts=2 lab_only=true")
        result = self.backend.snapshot()["probes"][-1]
        self.assertEqual((result["id"], result["state"], result["attempts"], result["rtt_ms"]),
                         (probe, "ack", 2, 1234))

        self.backend.probe("0123456789abcdef", "1122334455667788")
        self.peers["/dev/demo-a"].recv(128)
        self.backend.ingest(
            "/dev/demo-a",
            "MESH error=no_route_or_tx_busy lab_only=true",
        )
        rejected = self.backend.snapshot()["probes"][-1]
        self.assertEqual(rejected["state"], "send_rejected")
        self.assertIsNone(rejected["rtt_ms"])

    def test_bounded_test_run_probes_each_route_once(self) -> None:
        self.backend.attach_all()
        self.backend.ingest(
            "/dev/demo-a",
            "MESH node=0000000000000001 role=controller joined=1 parent=0000000000000000 hops=0",
        )
        self.backend.ingest(
            "/dev/demo-b",
            "MESH node=0000000000000002 role=node joined=1 parent=0000000000000001 hops=1",
        )
        self.backend.start_test(expected_nodes=2)
        self.backend.service()
        self.assertIn(
            b"MESH SEND 0000000000000002 70696e67",
            self.peers["/dev/demo-a"].recv(256),
        )
        self.now[0] += 0.75
        self.backend.ingest(
            "/dev/demo-a", "MESH data_ack attempts=1 lab_only=true"
        )
        self.backend.service()
        run = self.backend.snapshot()["run"]
        self.assertEqual(
            (run["active"], run["phase"], run["progress"]),
            (False, "COMPLETE", 100),
        )

    def test_generic_send_and_probe_cannot_share_ack_correlation(self) -> None:
        self.backend.attach("/dev/demo-a")
        self.backend.ingest(
            "/dev/demo-a", "MESH node=0123456789abcdef joined=1"
        )
        self.backend.command(
            "0123456789abcdef",
            "MESH SEND 1122334455667788 0102",
        )
        self.peers["/dev/demo-a"].recv(128)
        with self.assertRaisesRegex(ValueError, "DATA transaction"):
            self.backend.probe(
                "0123456789abcdef", "1122334455667788"
            )
        self.backend.ingest(
            "/dev/demo-a", "MESH data_ack attempts=1 lab_only=true"
        )
        probe_id = self.backend.probe(
            "0123456789abcdef", "1122334455667788"
        )
        self.peers["/dev/demo-a"].recv(128)
        with self.assertRaisesRegex(ValueError, "DATA transaction"):
            self.backend.command(
                "0123456789abcdef",
                "MESH SEND 1122334455667788 0304",
            )
        self.backend.ingest(
            "/dev/demo-a", "MESH data_ack attempts=1 lab_only=true"
        )
        self.assertEqual(
            self.backend.snapshot()["probes"][-1]["id"], probe_id
        )

    def test_sweep_waits_after_timeout_then_continues_next_route(self) -> None:
        self.backend.attach_all()
        self.backend.ingest(
            "/dev/demo-a",
            "MESH node=0000000000000001 role=controller joined=1 parent=0000000000000000 hops=0",
        )
        self.backend.ingest(
            "/dev/demo-b",
            "MESH node=0000000000000002 role=node joined=1 parent=0000000000000001 hops=1",
        )
        self.backend.ingest(
            "/dev/demo-c",
            "MESH node=0000000000000003 role=node joined=1 parent=0000000000000001 hops=1",
        )
        self.backend.start_test(expected_nodes=3)
        self.backend.service()
        self.peers["/dev/demo-a"].recv(512)
        self.now[0] += 12.0
        self.wall[0] += 12.0
        self.backend.service()
        waiting = self.backend.snapshot()["run"]
        self.assertTrue(waiting["active"])
        self.assertIn("quiet period", waiting["detail"])
        self.now[0] += 5.1
        self.wall[0] += 5.1
        self.backend.service()
        sent = self.peers["/dev/demo-a"].recv(1024)
        self.assertIn(b"MESH SEND 0000000000000003", sent)
        self.backend.ingest(
            "/dev/demo-a", "MESH data_ack attempts=1 lab_only=true"
        )
        self.backend.service()
        completed = self.backend.snapshot()["run"]
        self.assertEqual(
            (completed["active"], completed["phase"], completed["progress"]),
            (False, "ATTENTION", 100),
        )

    def test_concurrent_attach_opens_once_and_detach_race_fails_closed(self) -> None:
        errors: list[Exception] = []

        def attach_once() -> None:
            try:
                self.backend.attach("/dev/demo-a")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=attach_once)
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(self.open_count["/dev/demo-a"], 1)

        self.backend.ingest(
            "/dev/demo-a", "MESH node=0123456789abcdef joined=1"
        )
        resolved = threading.Event()
        resume = threading.Event()
        original_resolve = self.backend._resolve

        def paused_resolve(target: str) -> str:
            path = original_resolve(target)
            resolved.set()
            resume.wait(timeout=2)
            return path

        self.backend._resolve = paused_resolve
        result: list[Exception] = []

        def probe_during_detach() -> None:
            try:
                self.backend.probe(
                    "0123456789abcdef", "1122334455667788"
                )
            except Exception as exc:
                result.append(exc)

        probe_thread = threading.Thread(target=probe_during_detach)
        probe_thread.start()
        self.assertTrue(resolved.wait(timeout=2))
        self.backend._detach_path("/dev/demo-a")
        resume.set()
        probe_thread.join(timeout=2)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], ValueError)


if __name__ == "__main__":
    unittest.main()
