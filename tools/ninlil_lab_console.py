#!/usr/bin/env python3
"""Small dependency-free browser console for the Ninlil NJM1 LAB firmware."""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import secrets
import select
import signal
import stat
import sys
import termios
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


MAX_BODY = 4096
MAX_LOG_LINES = 500
HEX64 = re.compile(r"[0-9A-Fa-f]{16}\Z")
HEX_PAYLOAD = re.compile(r"[0-9A-Fa-f]+\Z")
MESH_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
PORT_PATTERNS = (
    "/dev/cu.usbmodem*",
    "/dev/cu.usbserial*",
    "/dev/ttyACM*",
    "/dev/ttyUSB*",
)


def scan_ports() -> list[str]:
    """Return plausible USB serial character devices on macOS and Linux."""
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
    """Parse bounded ``MESH key=value ...`` telemetry; ignore loose text."""
    if not line.startswith("MESH ") or len(line) > 2048:
        return None
    parsed: dict[str, str] = {}
    for token in line[5:].split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if MESH_KEY.fullmatch(key) and 0 < len(value) <= 128:
            parsed[key] = value
    return parsed or None


def _hex_node(value: Any, name: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError(f"{name} must be exactly 16 hex digits")
    return value.lower()


def build_command(action: Any, values: Any = None) -> str:
    """Validate a UI action and produce the firmware command line."""
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
        if (
            not isinstance(payload, str)
            or not 2 <= len(payload) <= 128
            or len(payload) % 2
            or not HEX_PAYLOAD.fullmatch(payload)
        ):
            raise ValueError("payload must be 1..64 bytes of even-length hex")
        return f"MESH SEND {destination} {payload.lower()}"
    raise ValueError("unknown action")


class ConsoleState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.fd: int | None = None
        self.port: str | None = None
        self.reader: threading.Thread | None = None
        self.stop_reader: threading.Event | None = None
        self.log: deque[str] = deque(maxlen=MAX_LOG_LINES)
        self.status: dict[str, str] = {}
        self.nodes: dict[str, dict[str, str]] = {}
        self.last_error = ""

    def _log(self, direction: str, text: str) -> None:
        text = text.replace("\x00", "�")[:2048]
        with self.lock:
            self.log.append(f"{time.strftime('%H:%M:%S')} {direction} {text}")

    def _accept_line(self, line: str) -> None:
        self._log("<", line)
        fields = parse_mesh_line(line)
        if fields is None:
            return
        with self.lock:
            self.status.update(fields)
            node_id = next(
                (fields[k] for k in ("node", "node_id", "id", "source") if k in fields),
                None,
            )
            if node_id and HEX64.fullmatch(node_id):
                previous = self.nodes.get(node_id.lower(), {})
                previous.update(fields)
                self.nodes[node_id.lower()] = previous

    @staticmethod
    def _open_serial(path: str) -> int:
        flags = os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            attrs = termios.tcgetattr(fd)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[3] = 0
            attrs[4] = termios.B115200
            attrs[5] = termios.B115200
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            termios.tcflush(fd, termios.TCIOFLUSH)
            return fd
        except Exception:
            os.close(fd)
            raise

    def connect(self, path: Any) -> None:
        if not isinstance(path, str) or len(path) > 255 or path not in scan_ports():
            raise ValueError("select an available USB serial port")
        self.disconnect()
        try:
            fd = self._open_serial(path)
        except OSError as exc:
            raise ValueError(f"cannot open serial port: {exc.strerror or exc}") from exc
        stop = threading.Event()
        with self.lock:
            self.fd, self.port, self.stop_reader = fd, path, stop
            self.last_error = ""
        reader = threading.Thread(target=self._read_loop, args=(fd, stop), daemon=True)
        self.reader = reader
        reader.start()
        self._log("*", f"connected {path} at 115200 baud")

    def disconnect(self) -> None:
        with self.lock:
            fd, port, stop = self.fd, self.port, self.stop_reader
            self.fd = self.port = self.stop_reader = None
        if stop is not None:
            stop.set()
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if port:
            self._log("*", f"disconnected {port}")

    def _read_loop(self, fd: int, stop: threading.Event) -> None:
        pending = bytearray()
        try:
            while not stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.25)
                if not ready:
                    continue
                try:
                    data = os.read(fd, 1024)
                except BlockingIOError:
                    continue
                if not data:
                    raise OSError("serial device closed")
                pending.extend(data)
                while b"\n" in pending:
                    raw, _, pending = pending.partition(b"\n")
                    self._accept_line(raw.rstrip(b"\r").decode("utf-8", "replace"))
                if len(pending) > 4096:
                    self._accept_line(pending[:2048].decode("utf-8", "replace") + " …")
                    pending.clear()
        except (OSError, ValueError) as exc:
            if not stop.is_set():
                with self.lock:
                    self.last_error = str(exc)
                self._log("!", str(exc))
                self.disconnect()

    def send(self, command: str) -> None:
        wire = (command + "\r\n").encode("ascii")
        with self.lock:
            fd = self.fd
        if fd is None:
            raise ValueError("connect a serial port first")
        offset = 0
        try:
            while offset < len(wire):
                _, writable, _ = select.select([], [fd], [], 1.0)
                if not writable:
                    raise OSError("serial write timed out")
                written = os.write(fd, wire[offset:])
                if written <= 0:
                    raise OSError("serial device accepted no data")
                offset += written
        except OSError as exc:
            raise ValueError(f"serial write failed: {exc}") from exc
        self._log(">", command)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "ports": scan_ports(),
                "connected": self.port,
                "log": list(self.log),
                "status": dict(self.status),
                "nodes": dict(self.nodes),
                "error": self.last_error,
            }


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ninlil LAB Console</title><style>
:root{color-scheme:dark;--bg:#0b1016;--card:#151d27;--line:#283647;--ink:#e7eef7;--muted:#91a2b7;--hot:#62d4ad;--warn:#ffb45b}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#0b1016,#101a24);color:var(--ink);font:14px ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1200px;margin:auto;padding:24px}h1{font-size:23px;margin:0}.sub{color:var(--muted);margin:5px 0 22px}.bar,.actions,.form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.card{background:rgba(21,29,39,.94);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px;box-shadow:0 12px 30px #0004}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}.grid .card{margin:0}button,input,select{font:inherit;color:var(--ink);background:#0d141d;border:1px solid #35475c;border-radius:6px;padding:9px 11px}button{cursor:pointer}button:hover{border-color:var(--hot)}button.primary{color:#07130f;background:var(--hot);border-color:var(--hot);font-weight:700}input{min-width:130px;flex:1}.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 12px}.kv b{color:var(--muted);font-weight:400}.empty{color:var(--muted)}#badge{display:inline-block;border-radius:12px;padding:3px 9px;background:#293341;color:var(--muted)}#badge.on{background:#143b31;color:var(--hot)}#error{color:var(--warn);min-height:18px;margin:8px 0 0}pre{height:310px;overflow:auto;margin:0;padding:11px;background:#090e14;border-radius:7px;white-space:pre-wrap;word-break:break-all;line-height:1.45}h2{font-size:14px;margin:0 0 12px;color:#bdcad9;text-transform:uppercase;letter-spacing:.08em}@media(max-width:600px){main{padding:14px}.bar>*{width:100%}}
</style></head><body><main><h1>Ninlil NJM1 LAB Console</h1><p class="sub">Local-only serial control · 115200 baud <span id="badge">disconnected</span></p>
<section class="card"><h2>Connection</h2><div class="bar"><select id="port"></select><button onclick="connectPort()" class="primary">Connect</button><button onclick="post('/api/disconnect',{})">Disconnect</button><button onclick="refresh()">Scan</button></div><div id="error"></div></section>
<section class="card"><h2>Role and state</h2><div class="actions"><button onclick="command('status')">Refresh status</button><button onclick="command('controller')">Controller</button><button onclick="command('node')">Node</button><button onclick="command('leave')">Leave</button></div></section>
<div class="grid"><section class="card"><h2>Mesh status</h2><div id="status"></div></section><section class="card"><h2>Topology</h2><div id="nodes"></div></section></div>
<div class="grid" style="margin-top:14px"><section class="card"><h2>Send application data</h2><div class="form"><input id="dest" maxlength="16" placeholder="destination: 16 hex"><input id="payload" maxlength="128" placeholder="payload: 1..64 bytes hex"><button onclick="command('send',{destination:dest.value,payload:payload.value})">Send</button></div></section><section class="card"><h2>Test penalty</h2><div class="form"><input id="pnode" maxlength="16" placeholder="node: 16 hex"><input id="score" type="number" min="0" max="200" value="0"><button onclick="command('penalty',{node:pnode.value,score:Number(score.value)})">Apply</button></div></section></div>
<section class="card" style="margin-top:14px"><h2>Raw serial log</h2><pre id="log"></pre></section>
</main><script>
const token=__TOKEN__;let busy=false;const $=id=>document.getElementById(id),dest=$('dest'),payload=$('payload'),pnode=$('pnode'),score=$('score');
async function post(path,body){try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Ninlil-Token':token},body:JSON.stringify(body)});const j=await r.json();if(!r.ok)throw Error(j.error||'request failed');$('error').textContent='';await refresh()}catch(e){$('error').textContent=e.message}}
function command(action,values={}){return post('/api/command',{action,values})}function connectPort(){return post('/api/connect',{port:$('port').value})}
function kv(obj){const d=document.createElement('div');d.className='kv';for(const [k,v] of Object.entries(obj)){const a=document.createElement('b'),b=document.createElement('span');a.textContent=k;b.textContent=v;d.append(a,b)}if(!Object.keys(obj).length){d.className='empty';d.textContent='No MESH telemetry yet.'}return d}
async function refresh(){if(busy)return;busy=true;try{const r=await fetch('/api/state',{cache:'no-store'}),s=await r.json(),sel=$('port'),old=sel.value;sel.replaceChildren(...s.ports.map(p=>new Option(p,p)));if(s.connected&&!s.ports.includes(s.connected))sel.append(new Option(s.connected,s.connected));sel.value=s.connected||old||s.ports[0]||'';const badge=$('badge');badge.textContent=s.connected?s.connected:'disconnected';badge.className=s.connected?'on':'';$('error').textContent=s.error||'';$('status').replaceChildren(kv(s.status));const nodes=$('nodes');nodes.replaceChildren();for(const [id,data] of Object.entries(s.nodes)){const box=document.createElement('div');box.style.marginBottom='12px';const title=document.createElement('strong');title.textContent=id;box.append(title,kv(data));nodes.append(box)}if(!Object.keys(s.nodes).length)nodes.append(kv({}));const log=$('log'),bottom=log.scrollHeight-log.scrollTop-log.clientHeight<30;log.textContent=s.log.join('\n');if(bottom)log.scrollTop=log.scrollHeight}catch(e){$('error').textContent=e.message}finally{busy=false}}
refresh();setInterval(refresh,800);
</script></body></html>'''


def make_handler(state: ConsoleState, token: str) -> type[BaseHTTPRequestHandler]:
    page = HTML.replace("__TOKEN__", json.dumps(token)).encode("utf-8")

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
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()

        def _json(self, status: int, value: Any) -> None:
            data = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)

        def _valid_host(self) -> bool:
            port = self.server.server_port
            return self.headers.get("Host", "") in {
                f"127.0.0.1:{port}",
                f"localhost:{port}",
            }

        def do_GET(self) -> None:
            if not self._valid_host():
                self._json(403, {"error": "invalid Host header"})
                return
            if self.path == "/":
                self._headers(200, "text/html; charset=utf-8", len(page))
                self.wfile.write(page)
            elif self.path == "/api/state":
                self._json(200, state.snapshot())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._valid_host():
                self._json(403, {"error": "invalid Host header"})
                return
            if not secrets.compare_digest(self.headers.get("X-Ninlil-Token", ""), token):
                self._json(403, {"error": "invalid request token"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(415, {"error": "application/json required"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
                if not 0 < length <= MAX_BODY:
                    raise ValueError("request body is too large or missing")
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("request body must be an object")
                if self.path == "/api/connect":
                    state.connect(body.get("port"))
                elif self.path == "/api/disconnect":
                    state.disconnect()
                elif self.path == "/api/command":
                    state.send(build_command(body.get("action"), body.get("values")))
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
    parser.add_argument("--http-port", type=int, default=8765, help="loopback HTTP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = parser.parse_args(argv)
    if not 0 <= args.http_port <= 65535:
        parser.error("--http-port must be in 0..65535")

    state = ConsoleState()
    token = secrets.token_urlsafe(24)
    try:
        server = HTTPServer(("127.0.0.1", args.http_port), make_handler(state, token))
    except OSError as exc:
        print(f"ninlil_lab_console: cannot start: {exc}", file=sys.stderr)
        return 1
    address = f"http://127.0.0.1:{server.server_port}/"
    print(f"Ninlil LAB Console: {address}", flush=True)
    if not args.no_browser:
        threading.Timer(0.25, webbrowser.open, args=(address,)).start()

    def stop(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        state.disconnect()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
