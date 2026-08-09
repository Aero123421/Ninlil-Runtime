#!/usr/bin/env python3
"""Small multi-USB observation backend for the private NJM1 LAB.

It deliberately observes the existing text console only.  It adds no radio
wire messages: a successful ``MESH data_ack`` is the Pong for a host probe.
"""

from __future__ import annotations

import glob
import os
import re
import select
import stat
import termios
import threading
import time
from collections import deque
from typing import Any, Callable


MAX_EVENTS = 500
MAX_PROBES = 128
HEX64 = re.compile(r"[0-9a-fA-F]{16}\Z")
MESH_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
PORT_PATTERNS = ("/dev/cu.usbmodem*", "/dev/cu.usbserial*", "/dev/ttyACM*", "/dev/ttyUSB*")


def scan_ports() -> list[str]:
    """Return USB serial character devices on macOS and Linux."""
    found: set[str] = set()
    for pattern in PORT_PATTERNS:
        for path in glob.glob(pattern):
            try:
                if stat.S_ISCHR(os.stat(path).st_mode):
                    found.add(path)
            except OSError:
                pass
    return sorted(found)


def parse_mesh_line(line: str) -> dict[str, str] | None:
    """Parse the firmware's bounded ``MESH key=value`` telemetry."""
    if not line.startswith("MESH ") or len(line) > 2048:
        return None
    fields: dict[str, str] = {}
    for token in line[5:].split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if MESH_KEY.fullmatch(key) and 0 < len(value) <= 128:
            fields[key] = value
    return fields or None


class _Connection:
    def __init__(self, path: str, fd: int, next_status_at: float) -> None:
        self.path = path
        self.fd = fd
        self.io_lock = threading.RLock()
        self.input = bytearray()
        self.node_id: str | None = None
        self.next_status_at = next_status_at
        self.error = ""
        self.last_seen = 0
        self.closing = False
        self.pending_probe: int | None = None
        self.generic_send_pending = False
        self.generic_send_deadline = 0.0
        self.correlation_quiet_until = 0.0


class LabBackend:
    """Bounded, thread-safe observation state for up to many USB LAB nodes.

    ``service()`` is intentionally public so a UI event loop can drive it.
    ``start()`` is optional and supplies the same periodic servicing in a small
    daemon thread.  A source port has one in-flight probe because the current
    firmware reports only ``data_ack attempts=N`` and no sequence number.
    """

    def __init__(self, *, status_interval_s: float = 1.0,
                 probe_timeout_s: float = 12.0,
                 port_lister: Callable[[], list[str]] = scan_ports,
                 opener: Callable[[str], int] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time) -> None:
        if not 0.1 <= status_interval_s <= 60.0:
            raise ValueError("status_interval_s must be in 0.1..60")
        if not 1.0 <= probe_timeout_s <= 60.0:
            raise ValueError("probe_timeout_s must be in 1..60")
        self._status_interval_s = status_interval_s
        self._probe_timeout_s = probe_timeout_s
        self._port_lister = port_lister
        self._opener = opener or self._open_serial
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.RLock()
        self._connections: dict[str, _Connection] = {}
        self._nodes: dict[str, dict[str, Any]] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._probes: deque[dict[str, Any]] = deque(maxlen=MAX_PROBES)
        self._next_probe_id = 1
        self._test_run: dict[str, Any] = {
            "active": False,
            "phase": "Ready",
            "progress": 0,
            "detail": "Attach eight boards and wait for topology discovery.",
        }
        self._test_targets: list[str] = []
        self._test_source = ""
        self._test_probe: int | None = None
        self._test_results: list[dict[str, Any]] = []
        self._error = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def _open_serial(path: str) -> int:
        flags = os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            attrs = termios.tcgetattr(fd)
            attrs[0] = attrs[1] = attrs[3] = 0
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[4] = attrs[5] = termios.B115200
            attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            termios.tcflush(fd, termios.TCIOFLUSH)
            return fd
        except Exception:
            os.close(fd)
            raise

    def attach(self, path: str) -> None:
        """Attach one currently discovered USB serial device."""
        if not isinstance(path, str) or path not in self._port_lister():
            raise ValueError("select an available USB serial port")
        with self._lock:
            existing = self._connections.get(path)
            if existing is not None and existing.closing:
                raise ValueError("serial port disconnect is in progress")
            if existing is not None:
                return
            try:
                fd = self._opener(path)
            except OSError as exc:
                raise ValueError(
                    f"cannot open serial port: {exc.strerror or exc}"
                ) from exc
            self._connections[path] = _Connection(path, fd, self._clock())
        self._event("attach", path=path)

    def attach_all(self) -> list[str]:
        """Attach each currently discovered device; failures are retained as events."""
        attached: list[str] = []
        for path in self._port_lister():
            try:
                self.attach(path)
                attached.append(path)
            except ValueError as exc:
                self._event("attach_error", path=path, error=str(exc))
        return attached

    def disconnect(self, target: str) -> None:
        path = self._resolve(target)
        self._detach_path(path)

    def _detach_path(self, path: str) -> None:
        with self._lock:
            connection = self._connections.get(path)
            if connection is not None:
                connection.closing = True
        if connection is None:
            return
        self._finish_probe(path, "disconnected", self._clock(), None)
        with connection.io_lock:
            with self._lock:
                if self._connections.get(path) is not connection:
                    return
                self._connections.pop(path)
            try:
                os.close(connection.fd)
            except OSError:
                pass
        self._event("disconnect", path=path)

    def disconnect_all(self) -> None:
        with self._lock:
            paths = list(self._connections)
        for path in paths:
            self._detach_path(path)

    def command(self, target: str, command: str) -> None:
        """Send an existing one-line ``MESH`` command to a port or node ID."""
        if (not isinstance(command, str) or not command.startswith("MESH ")
                or len(command) > 256 or "\r" in command or "\n" in command):
            raise ValueError("command must be one bounded MESH line")
        path = self._resolve(target)
        data_send = command.startswith("MESH SEND ")
        if not data_send:
            self._write(path, command)
            return
        with self._lock:
            connection = self._connections.get(path)
        if connection is None:
            raise ValueError("target is not attached")
        with connection.io_lock:
            now = self._clock()
            with self._lock:
                if (self._connections.get(path) is not connection
                        or connection.closing):
                    raise ValueError("target is not attached")
                if (connection.pending_probe is not None
                        or connection.generic_send_pending
                        or now < connection.correlation_quiet_until):
                    raise ValueError("source already has a DATA transaction")
                connection.generic_send_pending = True
                connection.generic_send_deadline = now + self._probe_timeout_s
            try:
                self._write(path, command)
            except Exception:
                with self._lock:
                    connection.generic_send_pending = False
                    connection.generic_send_deadline = 0.0
                raise

    def probe(self, source: str, destination: str, payload: str = "70696e67") -> int:
        """Send one DATA probe; its matching firmware ACK completes the probe."""
        if not isinstance(destination, str) or not HEX64.fullmatch(destination):
            raise ValueError("destination must be exactly 16 hex digits")
        if (not isinstance(payload, str) or len(payload) < 2 or len(payload) > 128
                or len(payload) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", payload)):
            raise ValueError("payload must be 1..64 bytes of hex")
        path = self._resolve(source)
        now = self._clock()
        with self._lock:
            connection = self._connections.get(path)
        if connection is None:
            raise ValueError("target is not attached")
        with connection.io_lock:
            with self._lock:
                if (self._connections.get(path) is not connection
                        or connection.closing):
                    raise ValueError("target is not attached")
                if (connection.pending_probe is not None
                        or connection.generic_send_pending
                        or now < connection.correlation_quiet_until):
                    raise ValueError("source already has a DATA transaction")
                probe_id = self._next_probe_id
                self._next_probe_id += 1
                self._probes.append({
                    "id": probe_id, "source": connection.node_id or path,
                    "source_port": path, "destination": destination.lower(),
                    "payload": payload.lower(), "state": "waiting_ack",
                    "started_at": int(self._wall_clock() * 1000), "rtt_ms": None,
                    "attempts": None,
                    "deadline_at": int(
                        (self._wall_clock() + self._probe_timeout_s) * 1000
                    ),
                    "_started_monotonic": now,
                })
                connection.pending_probe = probe_id
            try:
                self._write(
                    path,
                    f"MESH SEND {destination.lower()} {payload.lower()}",
                )
            except Exception:
                self._finish_probe(path, "send_error", now, None)
                raise
        self._event("probe", path=path, probe_id=probe_id, destination=destination.lower())
        return probe_id

    def start_test(self, expected_nodes: int = 8) -> None:
        """Start one bounded controller-to-node Ping/Pong sweep.

        This is deliberately an observation-plane scheduler, not a new radio
        protocol.  It reuses DATA and its correlated ACK and runs one probe at
        a time so the test itself does not manufacture avoidable contention.
        """
        if not 2 <= expected_nodes <= 32:
            raise ValueError("expected_nodes must be in 2..32")
        with self._lock:
            if self._test_run["active"]:
                raise ValueError("a LAB test is already running")
            attached = set(self._connections)
            fresh_after = int((self._wall_clock() - 5.0) * 1000)
            nodes = {
                node_id: node for node_id, node in self._nodes.items()
                if node.get("port") in attached
                and int(node.get("last_seen", 0)) >= fresh_after
            }
            controllers = [node_id for node_id, node in nodes.items()
                           if node.get("role") == "controller"]
            if len(nodes) < expected_nodes:
                raise ValueError(
                    f"discover {expected_nodes} nodes before starting the test "
                    f"({len(nodes)} visible)"
                )
            if len(controllers) != 1:
                raise ValueError("the test requires exactly one visible controller")
            targets = [node_id for node_id, node in nodes.items()
                       if node_id != controllers[0] and node.get("joined")]
            if len(targets) < expected_nodes - 1:
                raise ValueError("all non-controller nodes must be joined")
            targets.sort(key=lambda node_id: (
                int(nodes[node_id].get("hops", 99)), node_id))
            self._test_targets = targets[:expected_nodes - 1]
            self._test_source = controllers[0]
            self._test_probe = None
            self._test_results = []
            self._test_run = {
                "active": True,
                "phase": "PING / PONG",
                "progress": 0,
                "detail": f"Probing 0 / {len(self._test_targets)} routes.",
                "expected_nodes": expected_nodes,
                "started_at": int(self._wall_clock() * 1000),
            }
        self._event("test_start", expected_nodes=expected_nodes)

    def ingest(self, path: str, line: str) -> None:
        """Ingest one decoded serial line (also useful for deterministic tests)."""
        now_ms = int(self._wall_clock() * 1000)
        self._event("serial", path=path, direction="rx", line=line[:2048])
        fields = parse_mesh_line(line)
        if fields is None:
            return
        parts = line.split()
        label = parts[1] if len(parts) > 1 and "=" not in parts[1] else ""
        with self._lock:
            connection = self._connections.get(path)
            if connection is None:
                return
            connection.last_seen = now_ms
            node_id = fields.get("node")
            if node_id and HEX64.fullmatch(node_id):
                node_id = node_id.lower()
                connection.node_id = node_id
                known_node = node_id in self._nodes
                node = self._nodes.setdefault(node_id, self._new_node(node_id, path))
                previous_joined = bool(node.get("joined"))
                previous_parent = str(node.get("parent", ""))
                previous_route_changes = int(node.get("route_changes", 0))
                node["port"] = path
                node["last_seen"] = now_ms
                self._apply_status(node, fields)
                if not previous_joined and node["joined"]:
                    self._event(
                        "join", node=node_id, parent=node["parent"],
                        hops=node["hops"],
                    )
                if known_node and ((previous_parent and node["parent"] != previous_parent)
                        or node["route_changes"] > previous_route_changes):
                    self._event(
                        "route_change", node=node_id,
                        previous_parent=previous_parent,
                        parent=node["parent"], hops=node["hops"],
                    )
            elif connection.node_id and connection.node_id in self._nodes:
                node = self._nodes[connection.node_id]
                for key in ("rssi", "snr"):
                    value = self._as_int(fields.get(key))
                    if value is not None:
                        node[key] = value
            data_terminal = label in {"data_ack", "data_drop", "tx_drop"}
            send_rejected = fields.get("error") == "no_route_or_tx_busy"
            if data_terminal or send_rejected:
                if connection.generic_send_pending:
                    connection.generic_send_pending = False
                    connection.generic_send_deadline = 0.0
                    self._event(
                        "send_result", path=path,
                        state="ack" if label == "data_ack" else
                        ("send_rejected" if send_rejected else label),
                    )
                elif label == "data_ack":
                    self._finish_probe(
                        path, "ack", self._clock(),
                        self._as_int(fields.get("attempts")),
                    )
                elif label in {"data_drop", "tx_drop"}:
                    self._finish_probe(
                        path, label, self._clock(),
                        self._as_int(fields.get("attempts")),
                    )
                elif send_rejected:
                    self._finish_probe(
                        path, "send_rejected", self._clock(), None
                    )

    @staticmethod
    def _new_node(node_id: str, path: str) -> dict[str, Any]:
        return {"node_id": node_id, "port": path, "role": "unknown", "joined": False,
                "joining": False, "parent": "", "hops": 0, "lease_ms": 0,
                "tx": 0, "rx": 0, "relay": 0, "duplicate": 0,
                "route_changes": 0, "last_seen": 0}

    @staticmethod
    def _as_int(value: str | None) -> int | None:
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    def _apply_status(self, node: dict[str, Any], fields: dict[str, str]) -> None:
        text_fields = ("role", "parent", "site", "controller")
        int_fields = ("hops", "lease_ms", "tx", "rx", "relay", "duplicate",
                      "route_changes", "epoch")
        for key in text_fields:
            if key in fields:
                node[key] = fields[key].lower() if key == "parent" else fields[key]
        for key in int_fields:
            value = self._as_int(fields.get(key))
            if value is not None:
                node[key] = value
        for key in ("joined", "joining"):
            if key in fields:
                node[key] = fields[key] == "1"

    def service(self) -> None:
        """Drain all attached ports, issue periodic STATUS, and expire probes."""
        now = self._clock()
        with self._lock:
            connections = list(self._connections.values())
        for connection in connections:
            if now >= connection.next_status_at:
                try:
                    self._write(connection.path, "MESH STATUS")
                except ValueError:
                    pass
                connection.next_status_at = now + self._status_interval_s
        readable = [connection.fd for connection in connections]
        if readable:
            try:
                ready, _, _ = select.select(readable, [], [], 0)
            except (OSError, ValueError):
                ready = []
            for connection in connections:
                if connection.fd in ready:
                    self._drain(connection)
        with self._lock:
            for connection in self._connections.values():
                if connection.pending_probe is not None:
                    probe = self._probe(connection.pending_probe)
                    if probe and now - probe["_started_monotonic"] >= self._probe_timeout_s:
                        self._finish_probe(connection.path, "timeout", now, None)
                        connection.correlation_quiet_until = now + 5.0
                if (connection.generic_send_pending
                        and now >= connection.generic_send_deadline):
                    connection.generic_send_pending = False
                    connection.generic_send_deadline = 0.0
                    connection.correlation_quiet_until = now + 5.0
                    self._event("send_result", path=connection.path,
                                state="timeout")
        self._service_test_run()

    def _service_test_run(self) -> None:
        with self._lock:
            if not self._test_run["active"]:
                return
            current = self._probe(self._test_probe) if self._test_probe is not None else None
            if current is not None and current["state"] == "waiting_ack":
                return
            if current is not None:
                self._test_results.append(dict(current))
                self._test_probe = None
            completed = len(self._test_results)
            total = len(self._test_targets)
            if completed >= total:
                passed = sum(result["state"] == "ack" for result in self._test_results)
                self._test_run.update({
                    "active": False,
                    "phase": "COMPLETE" if passed == total else "ATTENTION",
                    "progress": 100,
                    "detail": f"{passed} / {total} routes returned a correlated ACK.",
                    "completed_at": int(self._wall_clock() * 1000),
                })
                self._event("test_complete", passed=passed, total=total)
                return
            target = self._test_targets[completed]
            source_node = self._nodes.get(self._test_source)
            source_connection = self._connections.get(
                str(source_node.get("port")) if source_node else ""
            )
            if (source_connection is not None
                    and self._clock() < source_connection.correlation_quiet_until):
                self._test_run.update({
                    "progress": round(completed * 100 / total),
                    "detail": "Waiting for the bounded ACK correlation quiet period.",
                })
                return
            self._test_run.update({
                "progress": round(completed * 100 / total),
                "detail": f"Probing {completed + 1} / {total}: {target}",
            })
            source = self._test_source
        try:
            probe_id = self.probe(source, target)
        except ValueError as exc:
            with self._lock:
                self._test_run.update({"active": False, "phase": "ATTENTION",
                                       "detail": str(exc)})
            self._event("test_error", error=str(exc))
            return
        with self._lock:
            self._test_probe = probe_id

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="ninlil-lab-observer", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread:
            thread.join(timeout=1.0)
        self.disconnect_all()

    def _run(self) -> None:
        while not self._stop.wait(0.05):
            self.service()

    def _drain(self, connection: _Connection) -> None:
        with connection.io_lock:
            with self._lock:
                if self._connections.get(connection.path) is not connection:
                    return
            try:
                data = os.read(connection.fd, 2048)
                if not data:
                    raise OSError("serial device closed")
                connection.input.extend(data)
                while b"\n" in connection.input:
                    raw, _, connection.input = connection.input.partition(b"\n")
                    self.ingest(
                        connection.path,
                        raw.rstrip(b"\r").decode("utf-8", "replace"),
                    )
                if len(connection.input) > 4096:
                    connection.input.clear()
                    self._event("serial_overflow", path=connection.path)
            except BlockingIOError:
                return
            except OSError as exc:
                connection.error = str(exc)
                self._error = connection.error
                self._event(
                    "serial_error", path=connection.path, error=connection.error
                )
                self._detach_path(connection.path)

    def _write(self, path: str, command: str) -> None:
        with self._lock:
            connection = self._connections.get(path)
        if connection is None:
            raise ValueError("target is not attached")
        wire = (command + "\r\n").encode("ascii")
        with connection.io_lock:
            with self._lock:
                if self._connections.get(path) is not connection:
                    raise ValueError("target is not attached")
                if connection.closing:
                    raise ValueError("target is disconnecting")
            try:
                offset = 0
                while offset < len(wire):
                    _, writable, _ = select.select([], [connection.fd], [], 1.0)
                    if not writable:
                        raise OSError("serial write timed out")
                    written = os.write(connection.fd, wire[offset:])
                    if written <= 0:
                        raise OSError("serial write failed")
                    offset += written
            except OSError as exc:
                connection.error = str(exc)
                self._error = connection.error
                self._event("serial_error", path=path, error=connection.error)
                raise ValueError(f"serial write failed: {exc}") from exc
        self._event("serial", path=path, direction="tx", line=command)

    def _resolve(self, target: str) -> str:
        if not isinstance(target, str):
            raise ValueError("target must be an attached port or node ID")
        with self._lock:
            if target in self._connections:
                return target
            node = self._nodes.get(target.lower())
            if node and node["port"] in self._connections:
                return str(node["port"])
        raise ValueError("target is not attached")

    def _probe(self, probe_id: int) -> dict[str, Any] | None:
        return next((probe for probe in self._probes if probe["id"] == probe_id), None)

    def _finish_probe(self, path: str, state: str, now: float, attempts: int | None) -> None:
        with self._lock:
            connection = self._connections.get(path)
            if connection is None or connection.pending_probe is None:
                return
            probe = self._probe(connection.pending_probe)
            connection.pending_probe = None
            if probe is None:
                return
            probe["state"] = state
            probe["attempts"] = attempts
            probe["completed_at"] = int(self._wall_clock() * 1000)
            elapsed_ms = max(
                0, round((now - probe.pop("_started_monotonic")) * 1000)
            )
            probe["elapsed_ms"] = elapsed_ms
            probe["rtt_ms"] = elapsed_ms if state == "ack" else None
        self._event("probe_result", path=path, probe_id=probe["id"], state=state,
                    attempts=attempts, rtt_ms=probe["rtt_ms"],
                    elapsed_ms=elapsed_ms)

    def _event(self, kind: str, **values: Any) -> None:
        event = {"kind": kind, "at": int(self._wall_clock() * 1000), **values}
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            connections = {
                path: {"connected": True, "node": item.node_id, "error": item.error,
                       "last_seen": item.last_seen,
                       "pending_probe": item.pending_probe,
                       "pending_send": item.generic_send_pending}
                for path, item in self._connections.items()
            }
            probes = []
            for probe in self._probes:
                copy = dict(probe)
                copy.pop("_started_monotonic", None)
                probes.append(copy)
            return {"ports": self._port_lister(), "connections": connections,
                    "nodes": {node: dict(state) for node, state in self._nodes.items()},
                    "events": list(self._events), "probes": probes,
                    "run": {**self._test_run, "mode": "live",
                            "status_interval_ms": round(self._status_interval_s * 1000)},
                    "error": self._error}
