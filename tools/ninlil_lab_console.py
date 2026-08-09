#!/usr/bin/env python3
"""Dependency-free browser console for the private Ninlil NJM1 LAB."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import signal
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ninlil_lab_backend import LabBackend, parse_mesh_line, scan_ports


MAX_BODY = 4096
HEX_PAYLOAD_LIMIT = 128
UI_PATH = Path(__file__).with_name("ninlil_lab_ui.html")


def _hex_node(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 16:
        raise ValueError(f"{name} must be exactly 16 hex digits")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be exactly 16 hex digits") from exc
    return value.lower()


def build_command(action: Any, values: Any = None) -> str:
    """Validate a browser action and produce one bounded firmware command."""
    if not isinstance(action, str):
        raise ValueError("action must be a string")
    simple = {
        "status": "MESH STATUS",
        "controller": "MESH CONTROLLER",
        "node": "MESH NODE",
        "leave": "MESH LEAVE",
    }
    if action in simple:
        return simple[action]
    if not isinstance(values, dict):
        raise ValueError("command values must be an object")
    if action == "penalty":
        node = _hex_node(values.get("node"), "node")
        score = values.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 200:
            raise ValueError("score must be an integer in 0..200")
        return f"MESH PENALTY {node} {score}"
    if action == "send":
        destination = _hex_node(values.get("destination"), "destination")
        payload = values.get("payload")
        if not isinstance(payload, str) or not 2 <= len(payload) <= HEX_PAYLOAD_LIMIT:
            raise ValueError("payload must be 1..64 bytes of even-length hex")
        if len(payload) % 2:
            raise ValueError("payload must be 1..64 bytes of even-length hex")
        try:
            bytes.fromhex(payload)
        except ValueError as exc:
            raise ValueError("payload must be 1..64 bytes of even-length hex") from exc
        return f"MESH SEND {destination} {payload.lower()}"
    raise ValueError("unknown action")


class LabApplication:
    def __init__(self, backend: LabBackend | None = None) -> None:
        self.backend = backend or LabBackend()

    def start(self) -> None:
        self.backend.start()

    def stop(self) -> None:
        self.backend.stop()

    def snapshot(self) -> dict[str, Any]:
        value = self.backend.snapshot()
        value["log"] = [self._event_line(event) for event in value["events"]]
        # Compatibility with the first one-port console API.
        value["connected"] = next(iter(value["connections"]), None)
        value["status"] = next(iter(value["nodes"].values()), {})
        return value

    @staticmethod
    def _event_line(event: dict[str, Any]) -> str:
        at = event.get("at")
        values = " ".join(
            f"{key}={value}" for key, value in event.items()
            if key not in {"at", "kind"}
        )
        return f"{at or '-'} {event.get('kind', 'event')} {values}".rstrip()

    def attach(self, port: Any) -> None:
        self.backend.attach(port)

    def attach_all(self) -> None:
        self.backend.attach_all()

    def disconnect(self, target: Any = None) -> None:
        if target is None:
            self.backend.disconnect_all()
        else:
            self.backend.disconnect(target)

    def command(self, target: Any, action: Any, values: Any) -> None:
        target = self._target(target)
        self.backend.command(target, build_command(action, values))

    def probe(self, source: Any, destination: Any) -> None:
        destination = _hex_node(destination, "destination")
        self.backend.probe(self._source(source), destination)

    def run_test(self) -> None:
        self.backend.start_test(8)

    def _source(self, value: Any) -> str:
        if isinstance(value, str) and value:
            return value
        state = self.backend.snapshot()
        controllers = [node_id for node_id, node in state["nodes"].items()
                       if node.get("role") == "controller"]
        if len(controllers) != 1:
            raise ValueError("select a source or expose exactly one controller")
        return controllers[0]

    def _target(self, value: Any) -> str:
        if isinstance(value, str) and value:
            return value
        state = self.backend.snapshot()
        if len(state["connections"]) != 1:
            raise ValueError("select a target node or USB port")
        return next(iter(state["connections"]))


def make_handler(app: LabApplication, token: str) -> type[BaseHTTPRequestHandler]:
    try:
        page = UI_PATH.read_text(encoding="utf-8").replace(
            "__TOKEN__", json.dumps(token)).encode("utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot load UI: {exc}") from exc

    class Handler(BaseHTTPRequestHandler):
        server_version = "NinlilLabConsole"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(3.0)

        def _headers(self, status: int, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'",
            )
            self.end_headers()

        def _json(self, status: int, value: Any) -> None:
            data = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)

        def _valid_host(self) -> bool:
            port = self.server.server_port
            return self.headers.get("Host", "") in {
                f"127.0.0.1:{port}", f"localhost:{port}",
            }

        def do_GET(self) -> None:
            request_path = self.path.split("?", 1)[0]
            if not self._valid_host():
                self._json(403, {"error": "invalid Host header"})
            elif request_path == "/":
                self._headers(200, "text/html; charset=utf-8", len(page))
                self.wfile.write(page)
            elif request_path == "/api/state":
                self._json(200, app.snapshot())
            elif request_path == "/favicon.ico":
                self._headers(204, "image/x-icon", 0)
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._valid_host():
                self._json(403, {"error": "invalid Host header"})
                return
            if not secrets.compare_digest(self.headers.get("X-Ninlil-Token", ""), token):
                self._json(403, {"error": "invalid request token"})
                return
            try:
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("application/json required")
                length = int(self.headers.get("Content-Length", ""))
                if not 0 < length <= MAX_BODY:
                    raise ValueError("request body is too large or missing")
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("request body must be an object")
                if self.path == "/api/connect":
                    app.attach(body.get("port"))
                elif self.path == "/api/attach-all":
                    app.attach_all()
                elif self.path in {"/api/disconnect", "/api/disconnect-all"}:
                    app.disconnect(body.get("target") if self.path == "/api/disconnect" else None)
                elif self.path == "/api/command":
                    app.command(body.get("target"), body.get("action"), body.get("values", {}))
                elif self.path == "/api/probe":
                    app.probe(body.get("source"), body.get("destination"))
                elif self.path == "/api/run-test":
                    app.run_test()
                else:
                    self._json(404, {"error": "not found"})
                    return
                self._json(200, {"ok": True})
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})

        def log_message(self, _format: str, *args: Any) -> None:
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-port", type=int, default=8765,
                        help="loopback HTTP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--demo", action="store_true",
                        help="open the UI with its eight-node demo fixture")
    args = parser.parse_args(argv)
    if not 0 <= args.http_port <= 65535:
        parser.error("--http-port must be in 0..65535")

    app = LabApplication()
    token = secrets.token_urlsafe(24)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.http_port), make_handler(app, token))
    except (OSError, RuntimeError) as exc:
        print(f"ninlil_lab_console: cannot start: {exc}", file=sys.stderr)
        return 1
    address = f"http://127.0.0.1:{server.server_port}/"
    if args.demo:
        address += "?demo=1"
    print(f"Ninlil Mesh Lab: {address}", flush=True)
    app.start()
    if not args.no_browser:
        threading.Timer(0.25, webbrowser.open, args=(address,)).start()

    def stop(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        app.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
