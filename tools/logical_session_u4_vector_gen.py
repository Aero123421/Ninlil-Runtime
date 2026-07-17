#!/usr/bin/env python3
"""U4 logical-session machine-executable scenario vectors (no production C).

Each of 38 engine IDs is an ordered action list. Every mutating action carries
exact expect: status, snapshot fields, counter absolute/delta, TX wire summary.
No assertion_key, no state_ne, no handshake_active/step_pair/quiet_drain macros.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
import tempfile
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
NCL1_VECTOR = REPO / "spec" / "vectors" / "ncl1-u4-v1.json"
VECTOR_PATH = REPO / "spec" / "vectors" / "logical-session-u4-v1.json"
FORMAT = "ninlil-logical-session-u4-v1"

MAGIC_NCG1 = b"NCG1"
NCG1_VER = 1
TYPE_PING, TYPE_PONG, TYPE_DATA, TYPE_RESET = 0x01, 0x02, 0x03, 0x04
MAGIC_NCL1 = b"NCL1"
NCL1_VER = 1
MSG_HELLO, MSG_HELLO_ACK, MSG_CTRL_ERROR = 0x01, 0x02, 0x03
MSG_PING, MSG_PONG, MSG_RESET = 0x10, 0x11, 0x12

ROLE_CTRL, ROLE_CELL = 1, 2
ST_DISC, ST_LINK, ST_HSENT, ST_HRECV, ST_ACT = 0, 1, 2, 3, 4
TX_NONE, TX_PEND, TX_RAW = 0, 1, 2
KIND_NONE, KIND_HELLO, KIND_ACK, KIND_PING, KIND_PONG, KIND_RESET = 0, 1, 2, 3, 4, 5
KIND_CTRL_ERROR = 6
STATUS_OK = 0
STATUS_CONTINUITY_LOST = 5
STATUS_DEADLINE_OVERFLOW = 10
COOKIE = 0xC0FFEE0123456789
ERR_TYPE_BINDING = 7
# docs/23 §5.5.2: legal max TX sequence is UINT32_MAX-1; next==MAX is terminal.
TX_SEQ_LEGAL_MAX = 0xFFFFFFFE
TX_SEQ_TERMINAL = 0xFFFFFFFF
# Max now+duration pure precheck ceiling (HELLO max +20% jitter = 6000).
DEADLINE_MAX_ADD_MS = 6000
UINT64_MAX = (1 << 64) - 1
HELLO_RETRY_MS = 200
PING_CADENCE_MS = 5000

PURE_CODEC_ONLY_IDS = frozenset(
    {
        "U4-N-BAD-MAGIC",
        "U4-N-VER",
        "U4-N-FLAGS",
        "U4-N-BODY-LEN",
        "U4-N-UNKNOWN-TYPE",
        "U4-N-TYPE-BIND-HELLO-IN-PING",
        "U4-N-TYPE-BIND-PING-IN-DATA",
        "U4-N-REQ-ZERO",
    }
)
FAMILIES = {
    1: "normal_handshake_active",
    2: "reset_session_lifecycle",
    3: "ack_loss_retry",
    4: "controller_restart_halfopen",
    5: "cell_restart_rxcold",
    6: "controller_rxcold",
    7: "continuity_notice_lifecycle",
    8: "stale_continuity_reset",
    9: "sequence_baseline_guards",
    10: "entropy_ctrl_error",
}
COUNTER_FIELDS = [
    "rx_overflow",
    "ncg1_reject_stream_id",
    "ncg1_reject_seq_gap",
    "ncg1_reject_seq_dup",
    "ncg1_reject_seq_regress",
    "ncg1_reject_seq_reserved",
    "ncg1_reject_baseline",
    "ncl1_reject_short",
    "ncl1_reject_magic",
    "ncl1_reject_version",
    "ncl1_reject_flags",
    "ncl1_reject_body_len",
    "ncl1_reject_unknown_message_type",
    "ncl1_reject_type_binding",
    "ncl1_reject_body_layout",
    "ncl1_reject_session_mismatch",
    "ncl1_reject_request",
    "ncl1_reject_state",
    "ncl1_reject_reserved",
    "hello_invalid_role",
    "hello_invalid_bootstrap",
    "hello_halfopen_fence",
    "hello_bootstrap_epoch_restart",
    "hello_baseline_resync",
    "hello_ack_baseline_resync",
    "hello_retry",
    "session_fence_inflight_dropped",
    "continuity_reset_notice_cancelled",
    "ctrl_error_rate_drop",
    "pong_miss",
    "ping_dispatch_miss",
    "liveness_fail",
    "logical_rejects",
    "raw_accepts",
    "tx_actions_submitted",
    "continuity_notice_created",
    "continuity_notice_accepted",
    "generation_burns",
]

MODE_FIXED, MODE_ACTIVE, MODE_ACTIVE_PLUS, MODE_ACTIVE_XOR = 0, 1, 2, 3
MODE_ZERO, MODE_LAST_RX, MODE_LAST_RX_PLUS = 4, 5, 6
MODE_SOLE_HELLO, MODE_SOLE_HELLO_XOR = 7, 8

PEER = {"ctrl": 0, "cell": 1, "ctrl2": 2, "cell2": 3}
OP = {
    "step": 2,
    "forward": 3,
    "drop_tx": 4,
    "inject": 6,
    "mark_baseline": 7,
    "force_state": 8,
    "force_rx_baseline": 9,
    "force_next_tx_seq": 10,
    "force_ping_eligible": 11,
    "request_hello_now": 12,
    "cell_continuity_loss": 13,
    "set_write_would_block": 14,
    "init_peer": 15,
    "set_rng_fail": 16,
}


def crc32c(data: bytes) -> int:
    if hasattr(zlib, "crc32c"):
        return zlib.crc32c(data) & 0xFFFFFFFF
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFFFFFF


def ncg1_encode(type_: int, stream_id: int, sequence: int, payload: bytes) -> bytes:
    """Encode NCG1. Callers must pre-validate ranges (no silent mask truncation)."""
    prefix = bytearray()
    prefix += MAGIC_NCG1
    prefix.append(NCG1_VER)
    prefix.append(type_)
    prefix += struct.pack(">H", 0)
    prefix += struct.pack(">I", stream_id)
    prefix += struct.pack(">I", sequence)
    prefix += struct.pack(">H", len(payload))
    header = bytes(prefix) + struct.pack(">I", crc32c(bytes(prefix)))
    body = header + payload
    return body + struct.pack(">I", crc32c(body))


def ncl1_encode(msg_type, request_id, generation, cookie, body: bytes) -> bytes:
    """Encode NCL1. Callers must pre-validate ranges (no silent mask truncation)."""
    hdr = bytearray()
    hdr += MAGIC_NCL1
    hdr.append(NCL1_VER)
    hdr.append(msg_type)
    hdr += struct.pack(">H", 0)
    hdr += struct.pack(">I", request_id)
    hdr += struct.pack(">I", generation)
    hdr += struct.pack(">Q", cookie)
    hdr += struct.pack(">H", len(body))
    return bytes(hdr) + body


def hello_body() -> bytes:
    return struct.pack(">HHHH", 1, 1, 0, 0)


def hello_ack_body(result: int = 0) -> bytes:
    # Match production encode: selected_control_version is 1 only for HELLO_OK.
    selected = 1 if result == 0 else 0
    return struct.pack(">HHHH", selected, 0, result, 0)


def ping_body(token: int) -> bytes:
    return struct.pack(">Q", token)


def reset_body(code: int = 1) -> bytes:
    return bytes([code, 0, 0, 0])


def ctrl_error_body(code: int = 3) -> bytes:
    return struct.pack(">HHI", code, 0, 0)


def hx(b: bytes) -> str:
    return b.hex()



# ---- Exact TX semantic oracle (no snapshot synthesis, no defaults) ----
U8_MAX = 0xFF
U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
U64_MAX = 0xFFFFFFFFFFFFFFFF
SEQ_RESERVED_TERMINAL = U32_MAX  # NCG1 sequence UINT32_MAX is reserved

HELLO_OK = 0
HELLO_VERSION_MISMATCH = 1
HELLO_BUSY = 2
HELLO_DENIED = 3
HELLO_RESULTS = frozenset(
    {HELLO_OK, HELLO_VERSION_MISMATCH, HELLO_BUSY, HELLO_DENIED}
)
RESET_CODES = frozenset({1, 2, 3})  # SESSION / PARSER / LINK
CTRL_ERROR_CODES = frozenset({1, 2, 3, 4, 5, 6, 7})
CONTROL_VERSION_V1 = 1

# NCG1 type × NCL1 message_type closed binding (docs/23 / ncl1_codec).
FT_MSG_BINDING = {
    MSG_HELLO: TYPE_DATA,
    MSG_HELLO_ACK: TYPE_DATA,
    MSG_CTRL_ERROR: TYPE_DATA,
    MSG_PING: TYPE_PING,
    MSG_PONG: TYPE_PONG,
    MSG_RESET: TYPE_RESET,
}

TX_BASE_REQUIRED = (
    "frame_type",
    "stream_id",
    "sequence",
    "message_type",
    "generation",
    "session_cookie",
    "request_id",
)
TX_MSG_REQUIRED = {
    MSG_HELLO: (
        "hello_min_version",
        "hello_max_version",
        "hello_flags_supported",
        "hello_reserved",
    ),
    MSG_HELLO_ACK: (
        "hello_ack_selected_version",
        "hello_ack_flags_selected",
        "hello_ack_result",
        "hello_ack_reserved",
    ),
    MSG_PING: ("opaque_echo_token",),
    MSG_PONG: ("opaque_echo_token",),
    MSG_RESET: ("reset_code", "reset_reserved0", "reset_reserved1", "reset_reserved2"),
    MSG_CTRL_ERROR: ("error_code", "error_reserved", "related_request_id"),
}


def _require_int(desc: dict, key: str, *, lo: int, hi: int) -> int:
    """Exact integer in [lo, hi]. Rejects bool, float, and silent truncation."""
    if key not in desc:
        raise RuntimeError(f"tx descriptor missing required field {key!r}")
    v = desc[key]
    if isinstance(v, bool) or not isinstance(v, int):
        raise RuntimeError(
            f"tx descriptor field {key!r} must be int (not {type(v).__name__})"
        )
    if v < lo or v > hi:
        raise RuntimeError(
            f"tx descriptor field {key!r}={v} out of range [{lo}, {hi}] "
            "(silent mask truncation forbidden)"
        )
    return v


def validate_tx_desc(desc: dict, *, where: str = "tx") -> dict[str, int]:
    """Hard-fail semantic + range validation. Returns normalized ints."""
    if not isinstance(desc, dict):
        raise RuntimeError(f"{where}: tx descriptor must be a dict")
    for k in TX_BASE_REQUIRED:
        if k not in desc:
            raise RuntimeError(f"{where}: missing required field {k!r}")
    mt = _require_int(desc, "message_type", lo=0, hi=U8_MAX)
    if mt not in TX_MSG_REQUIRED:
        raise RuntimeError(f"{where}: unknown message_type {mt}")
    for k in TX_MSG_REQUIRED[mt]:
        if k not in desc:
            raise RuntimeError(f"{where}: missing message field {k!r}")
    allowed = set(TX_BASE_REQUIRED) | set(TX_MSG_REQUIRED[mt])
    surplus = set(desc.keys()) - allowed
    if surplus:
        raise RuntimeError(f"{where}: surplus fields {sorted(surplus)}")

    ft = _require_int(desc, "frame_type", lo=0, hi=U8_MAX)
    if FT_MSG_BINDING[mt] != ft:
        raise RuntimeError(
            f"{where}: frame_type={ft} incompatible with message_type={mt} "
            f"(required NCG1 type {FT_MSG_BINDING[mt]})"
        )

    stream = _require_int(desc, "stream_id", lo=0, hi=U32_MAX)
    if stream != 0:
        raise RuntimeError(f"{where}: stream_id must be 0 (U4 single control stream)")

    seq = _require_int(desc, "sequence", lo=0, hi=U32_MAX)
    if seq == SEQ_RESERVED_TERMINAL:
        raise RuntimeError(
            f"{where}: sequence UINT32_MAX is reserved terminal (not a TX seq)"
        )

    gen = _require_int(desc, "generation", lo=0, hi=U32_MAX)
    cookie = _require_int(desc, "session_cookie", lo=0, hi=U64_MAX)
    req = _require_int(desc, "request_id", lo=0, hi=U32_MAX)
    out: dict[str, int] = {
        "frame_type": ft,
        "stream_id": stream,
        "sequence": seq,
        "message_type": mt,
        "generation": gen,
        "session_cookie": cookie,
        "request_id": req,
    }

    if mt == MSG_HELLO:
        # Bootstrap HELLO: gen=0, cookie=0, req≠0; min=max=1; flags=0; reserved=0.
        if gen != 0 or cookie != 0:
            raise RuntimeError(f"{where}: HELLO requires generation=0 and cookie=0")
        if req == 0:
            raise RuntimeError(f"{where}: HELLO request_id must be non-zero")
        mn = _require_int(desc, "hello_min_version", lo=0, hi=U16_MAX)
        mx = _require_int(desc, "hello_max_version", lo=0, hi=U16_MAX)
        flags = _require_int(desc, "hello_flags_supported", lo=0, hi=U16_MAX)
        reserved = _require_int(desc, "hello_reserved", lo=0, hi=U16_MAX)
        if mn != CONTROL_VERSION_V1 or mx != CONTROL_VERSION_V1:
            raise RuntimeError(
                f"{where}: HELLO min/max control version must be {CONTROL_VERSION_V1}"
            )
        if flags != 0 or reserved != 0:
            raise RuntimeError(f"{where}: HELLO flags_supported/reserved must be 0")
        out.update(
            {
                "hello_min_version": mn,
                "hello_max_version": mx,
                "hello_flags_supported": flags,
                "hello_reserved": reserved,
            }
        )
    elif mt == MSG_HELLO_ACK:
        if req == 0:
            raise RuntimeError(f"{where}: HELLO_ACK request_id must be non-zero (echo)")
        selected = _require_int(desc, "hello_ack_selected_version", lo=0, hi=U16_MAX)
        flags_sel = _require_int(desc, "hello_ack_flags_selected", lo=0, hi=U16_MAX)
        result = _require_int(desc, "hello_ack_result", lo=0, hi=U16_MAX)
        reserved = _require_int(desc, "hello_ack_reserved", lo=0, hi=U16_MAX)
        if flags_sel != 0 or reserved != 0:
            raise RuntimeError(f"{where}: HELLO_ACK flags_selected/reserved must be 0")
        if result not in HELLO_RESULTS:
            raise RuntimeError(f"{where}: HELLO_ACK result_code {result} not in catalog")
        if result == HELLO_OK:
            if gen == 0 or cookie == 0:
                raise RuntimeError(
                    f"{where}: HELLO_ACK OK requires generation≠0 and cookie≠0"
                )
            if selected != CONTROL_VERSION_V1:
                raise RuntimeError(
                    f"{where}: HELLO_ACK OK selected_control_version must be "
                    f"{CONTROL_VERSION_V1}"
                )
        else:
            if gen != 0 or cookie != 0:
                raise RuntimeError(
                    f"{where}: HELLO_ACK error requires generation=0 and cookie=0"
                )
            if selected != 0:
                raise RuntimeError(
                    f"{where}: HELLO_ACK error selected_control_version must be 0"
                )
        out.update(
            {
                "hello_ack_selected_version": selected,
                "hello_ack_flags_selected": flags_sel,
                "hello_ack_result": result,
                "hello_ack_reserved": reserved,
            }
        )
    elif mt in (MSG_PING, MSG_PONG):
        # §5.5.1: PING request_id ≠ 0; PONG echoes. Token is caller-chosen u64
        # (docs/23 §8.2) — zero is wire-valid (not silently rewritten here).
        if mt == MSG_PING and req == 0:
            raise RuntimeError(f"{where}: PING request_id must be non-zero")
        if mt == MSG_PONG and req == 0:
            raise RuntimeError(f"{where}: PONG request_id must be non-zero (echo)")
        if gen == 0 or cookie == 0:
            raise RuntimeError(
                f"{where}: PING/PONG requires active generation≠0 and cookie≠0"
            )
        token = _require_int(desc, "opaque_echo_token", lo=0, hi=U64_MAX)
        out["opaque_echo_token"] = token
    elif mt == MSG_RESET:
        # §7.4: normal and continuity-loss RESET both require gen≠0, cookie≠0.
        if req == 0:
            raise RuntimeError(f"{where}: RESET request_id must be non-zero")
        if gen == 0 or cookie == 0:
            raise RuntimeError(
                f"{where}: RESET requires generation≠0 and cookie≠0 "
                "(active or pre-fence snapshot)"
            )
        code = _require_int(desc, "reset_code", lo=0, hi=U8_MAX)
        r0 = _require_int(desc, "reset_reserved0", lo=0, hi=U8_MAX)
        r1 = _require_int(desc, "reset_reserved1", lo=0, hi=U8_MAX)
        r2 = _require_int(desc, "reset_reserved2", lo=0, hi=U8_MAX)
        if code not in RESET_CODES:
            raise RuntimeError(f"{where}: RESET reset_code {code} not in closed catalog")
        if r0 != 0 or r1 != 0 or r2 != 0:
            raise RuntimeError(f"{where}: RESET reserved fields must be 0")
        out.update(
            {
                "reset_code": code,
                "reset_reserved0": r0,
                "reset_reserved1": r1,
                "reset_reserved2": r2,
            }
        )
    elif mt == MSG_CTRL_ERROR:
        # §7.3/§7.4: request_id may be 0 (no correlation); else echo reference.
        # gen/cookie: either both 0 (unestablished) or both nonzero (active pair).
        if (gen == 0) != (cookie == 0):
            raise RuntimeError(
                f"{where}: CTRL_ERROR requires (generation==0)==(cookie==0)"
            )
        ec = _require_int(desc, "error_code", lo=0, hi=U16_MAX)
        er = _require_int(desc, "error_reserved", lo=0, hi=U16_MAX)
        related = _require_int(desc, "related_request_id", lo=0, hi=U32_MAX)
        if ec not in CTRL_ERROR_CODES:
            raise RuntimeError(f"{where}: CTRL_ERROR error_code {ec} not in catalog")
        if er != 0:
            raise RuntimeError(f"{where}: CTRL_ERROR reserved must be 0")
        out.update(
            {
                "error_code": ec,
                "error_reserved": er,
                "related_request_id": related,
            }
        )
    else:
        raise RuntimeError(f"{where}: unhandled message_type {mt}")
    return out


def encode_tx_desc(desc: dict) -> str:
    """Encode only from validated explicit descriptor fields. Hard-fail on any gap."""
    n = validate_tx_desc(desc)
    mt = n["message_type"]
    if mt == MSG_HELLO:
        body = struct.pack(
            ">HHHH",
            n["hello_min_version"],
            n["hello_max_version"],
            n["hello_flags_supported"],
            n["hello_reserved"],
        )
    elif mt == MSG_HELLO_ACK:
        body = struct.pack(
            ">HHHH",
            n["hello_ack_selected_version"],
            n["hello_ack_flags_selected"],
            n["hello_ack_result"],
            n["hello_ack_reserved"],
        )
    elif mt in (MSG_PING, MSG_PONG):
        body = ping_body(n["opaque_echo_token"])
    elif mt == MSG_RESET:
        body = bytes(
            [
                n["reset_code"],
                n["reset_reserved0"],
                n["reset_reserved1"],
                n["reset_reserved2"],
            ]
        )
    elif mt == MSG_CTRL_ERROR:
        body = struct.pack(
            ">HHI",
            n["error_code"],
            n["error_reserved"],
            n["related_request_id"],
        )
    else:
        raise RuntimeError(f"unhandled message_type {mt}")

    payload = ncl1_encode(
        mt, n["request_id"], n["generation"], n["session_cookie"], body
    )
    return ncg1_encode(n["frame_type"], n["stream_id"], n["sequence"], payload).hex()


FORCE_OPS_CAUSAL = frozenset(
    {
        "force_state",
        "force_rx_baseline",
        "force_next_tx_seq",
        "force_ping_eligible",
    }
)


def action_tx_peer(a: dict) -> str | None:
    """Peer that owns residual TX authority for the action."""
    op = a.get("op")
    if op == "forward":
        return a.get("frm") or a.get("from") or a.get("src") or a.get("peer")
    return a.get("peer")


def action_deliver_peer(a: dict) -> str | None:
    """Peer that receives wire for forward/inject."""
    op = a.get("op")
    if op == "forward":
        return a.get("to") or a.get("dst")
    if op == "inject":
        return a.get("peer")
    return None


def _inject_hello_ack_fields(ncl1: dict) -> dict[str, int] | None:
    """Parse inject ncl1 as HELLO_ACK (OK or error) when body is well-formed."""
    if int(ncl1.get("msg_type") or -1) != MSG_HELLO_ACK:
        return None
    req = int(ncl1.get("request_id") or 0)
    gen = int(ncl1.get("generation") or 0)
    cookie = int(ncl1.get("cookie") or 0)
    body = bytes.fromhex(ncl1.get("body_hex") or "")
    if len(body) < 8:
        return None
    selected = int.from_bytes(body[0:2], "big")
    flags_sel = int.from_bytes(body[2:4], "big")
    result = int.from_bytes(body[4:6], "big")
    reserved = int.from_bytes(body[6:8], "big")
    if req == 0 or flags_sel != 0 or reserved != 0:
        return None
    if result not in HELLO_RESULTS:
        return None
    if result == HELLO_OK:
        if gen == 0 or cookie == 0 or selected != CONTROL_VERSION_V1:
            return None
    else:
        if gen != 0 or cookie != 0 or selected != 0:
            return None
    return {
        "request_id": req,
        "generation": gen,
        "session_cookie": cookie,
        "hello_ack_result": result,
        "hello_ack_selected_version": selected,
    }


class CausalTracker:
    """
    Strict peer-pair causal proof for HELLO/ACK/PING/PONG/RESET/CTRL_ERROR.

    Outstanding HELLO: (origin, responder, request_id)
    Outstanding PING:  (origin, responder, request_id, token)
    Pending ACK (OK or error): (origin, responder, req, result, gen, cookie)
      — HELLO outstanding is NOT consumed at TX; only after delivery correlation.
    session_pair: current ACTIVE gen/cookie per peer (exact, not ever-active).
    pre_fence: snapshot after continuity fence (for RESET notice header).

    Normative: latest HELLO/PING for (responder, req) supersedes prior outstanding.
    Inject ACK requires source responder + dest origin + full field correlation.
    """

    def __init__(self) -> None:
        self.hellos_out: set[tuple[str, str, int]] = set()
        self.pings_out: set[tuple[str, str, int, int]] = set()
        # (origin, responder, req, result, gen, cookie)
        self.ack_pending: set[tuple[str, str, int, int, int, int]] = set()
        self.pong_pending: set[tuple[str, str, int, int]] = set()
        self.delivered_ack_to_origin: set[tuple[str, str, int]] = set()
        self.handshake_active: set[str] = set()
        # Current ACTIVE authority (gen, cookie) — not "ever active".
        self.session_pair: dict[str, tuple[int, int]] = {}
        # Continuity pre-fence snapshot for RESET notice headers.
        self.pre_fence: dict[str, tuple[int, int]] = {}

    def observe(self, a: dict, *, where: str, enforce: bool) -> None:
        op = a.get("op")
        if op in FORCE_OPS_CAUSAL:
            return

        exp = a.get("expect") or {}
        tlen = int(exp.get("tx_len") or 0)
        tx = exp.get("tx") if tlen > 0 else None
        peer = action_tx_peer(a)

        if op == "inject":
            self._observe_inject(a, where=where, enforce=enforce)

        if op == "cell_continuity_loss" and peer:
            self._fence_peer(peer)

        if tx is None:
            self._track_state_transition(op, peer, exp)
            self._maybe_origin_active_from_step(op, peer, exp)
            return

        try:
            n = validate_tx_desc(tx, where=where if enforce else f"{where}:soft")
        except RuntimeError:
            if enforce:
                raise
            return

        mt = n["message_type"]
        # Only step produces new TX authority events. forward/drop_tx residuals
        # are delivery/drop of already-submitted frames (do not re-consume).
        if op == "step":
            if mt == MSG_HELLO_ACK:
                self._observe_ack_tx(peer, n, where=where, enforce=enforce)
            elif mt == MSG_PONG:
                self._observe_pong_tx(peer, n, where=where, enforce=enforce)
            elif mt == MSG_CTRL_ERROR:
                self._observe_ctrl_error(peer, n, where=where, enforce=enforce)
            elif mt == MSG_RESET:
                self._observe_reset_tx(peer, n, where=where, enforce=enforce)

        if op == "forward" and action_deliver_peer(a) is not None and peer is not None:
            self._observe_forward_delivery(
                frm=peer,
                to=str(action_deliver_peer(a)),
                n=n,
                where=where,
                enforce=enforce,
            )

        self._track_state_transition(op, peer, exp)
        self._maybe_origin_active_from_step(op, peer, exp)

    def _fence_peer(self, peer: str) -> None:
        if peer in self.session_pair:
            self.pre_fence[peer] = self.session_pair[peer]
            del self.session_pair[peer]

    def _track_state_transition(
        self, op: str | None, peer: str | None, exp: dict
    ) -> None:
        """When expect shows non-ACTIVE after peer had session_pair, record pre_fence."""
        if not peer or op not in ("step", "inject", "cell_continuity_loss"):
            return
        if "state" not in exp:
            return
        st = int(exp["state"])
        if st != ST_ACT and peer in self.session_pair:
            self.pre_fence[peer] = self.session_pair[peer]
            del self.session_pair[peer]

    def _add_hello_outstanding(
        self, origin: str, responder: str, req: int, *, where: str, enforce: bool
    ) -> None:
        """Latest HELLO for (responder, request_id) supersedes prior outstanding.

        Normative replace: half-open / re-HELLO / DUP-HELLO — at most one
        outstanding HELLO per (responder, request_id). Completed triples are
        already removed and cannot be reused. Concurrent dual-origin is
        resolved by replace (not multi-outstanding); wrong-destination after
        replace still fails because only the latest origin remains.
        """
        del where, enforce  # replace rule; no concurrent multi-origin outstanding
        self.hellos_out = {
            (o, r, rq)
            for (o, r, rq) in self.hellos_out
            if not (r == responder and rq == req)
        }
        # Drop stale pending ACK for superseded HELLO on this responder+req.
        self.ack_pending = {
            p
            for p in self.ack_pending
            if not (p[1] == responder and p[2] == req)
        }
        self.hellos_out.add((origin, responder, req))

    def _add_ping_outstanding(
        self,
        origin: str,
        responder: str,
        req: int,
        token: int,
        *,
        where: str,
        enforce: bool,
    ) -> None:
        del where, enforce
        # Latest PING for (responder, request_id) supersedes (any prior token).
        self.pings_out = {
            (o, r, rq, t)
            for (o, r, rq, t) in self.pings_out
            if not (r == responder and rq == req)
        }
        self.pong_pending = {
            p
            for p in self.pong_pending
            if not (p[1] == responder and p[2] == req)
        }
        self.pings_out.add((origin, responder, req, token))

    def _observe_inject(self, a: dict, *, where: str, enforce: bool) -> None:
        ncl1 = a.get("ncl1")
        if not ncl1:
            return
        # inject peer = destination (RX into this peer).
        dest = action_deliver_peer(a)
        # Source of the injected frame (HELLO origin or ACK/PONG responder).
        source = (
            a.get("frm")
            or a.get("from")
            or a.get("src")
            or a.get("source")
            or a.get("origin")
        )
        mt = int(ncl1.get("msg_type") or -1)
        req = int(ncl1.get("request_id") or 0)

        if mt == MSG_HELLO and req and dest and source:
            self._add_hello_outstanding(
                str(source), str(dest), req, where=where, enforce=enforce
            )
            return

        if mt == MSG_PING and req and dest and source:
            body = bytes.fromhex(ncl1.get("body_hex") or "")
            if len(body) >= 8:
                token = int.from_bytes(body[0:8], "big")
                self._add_ping_outstanding(
                    str(source),
                    str(dest),
                    req,
                    token,
                    where=where,
                    enforce=enforce,
                )
            return

        if mt == MSG_HELLO_ACK:
            fields = _inject_hello_ack_fields(ncl1)
            if fields is None:
                # Malformed/incomplete inject is engine stimulus only (no authority).
                return
            if not dest or not source:
                if enforce:
                    raise RuntimeError(
                        f"{where}: inject HELLO_ACK requires source responder "
                        f"(frm/from/src) and dest peer"
                    )
                return
            # Exact: origin=dest (controller receiving ACK), responder=source.
            origin = str(dest)
            responder = str(source)
            req_i = fields["request_id"]
            gen = fields["generation"]
            cookie = fields["session_cookie"]
            result = fields["hello_ack_result"]
            key = (origin, responder, req_i)
            if key not in self.hellos_out:
                if enforce:
                    raise RuntimeError(
                        f"{where}: inject HELLO_ACK requires exact outstanding "
                        f"HELLO (origin={origin!r}, responder={responder!r}, "
                        f"request_id={req_i})"
                    )
                return
            # Delivery correlation completes: consume HELLO (+ any pending).
            self.hellos_out.discard(key)
            self.ack_pending = {
                p
                for p in self.ack_pending
                if not (p[0] == origin and p[1] == responder and p[2] == req_i)
            }
            if result == HELLO_OK:
                self.handshake_active.add(responder)
                self.session_pair[responder] = (gen, cookie)
                self.delivered_ack_to_origin.add(key)
            return

        if mt == MSG_PONG:
            if not dest or not source:
                if enforce:
                    raise RuntimeError(
                        f"{where}: inject PONG requires source responder and dest peer"
                    )
                return
            body = bytes.fromhex(ncl1.get("body_hex") or "")
            if len(body) < 8:
                return
            token = int.from_bytes(body[0:8], "big")
            origin = str(dest)
            responder = str(source)
            key = (origin, responder, req, token)
            if key not in self.pings_out:
                if enforce:
                    raise RuntimeError(
                        f"{where}: inject PONG requires exact outstanding PING "
                        f"(origin={origin!r}, responder={responder!r}, "
                        f"request_id={req}, token={token})"
                    )
                return
            self.pings_out.discard(key)
            return

    def _observe_ack_tx(
        self, peer: str | None, n: dict[str, int], *, where: str, enforce: bool
    ) -> None:
        if not peer:
            if enforce:
                raise RuntimeError(f"{where}: HELLO_ACK requires action peer")
            return
        req = n["request_id"]
        matches = [
            (o, r, rq) for (o, r, rq) in self.hellos_out if r == peer and rq == req
        ]
        if not matches:
            if enforce:
                raise RuntimeError(
                    f"{where}: HELLO_ACK request_id={req} has no outstanding HELLO "
                    f"delivered to responder={peer!r} "
                    f"(outstanding={sorted(self.hellos_out)})"
                )
            return
        if len(matches) > 1:
            if enforce:
                raise RuntimeError(
                    f"{where}: ambiguous HELLO outstanding for responder={peer!r} "
                    f"request_id={req}: {sorted(matches)}"
                )
            return
        (origin, responder, rq) = matches[0]
        result = int(n.get("hello_ack_result", -1))
        gen = n["generation"]
        cookie = n["session_cookie"]
        # Do NOT consume HELLO outstanding at TX — hold pending until delivery.
        self.ack_pending = {
            p
            for p in self.ack_pending
            if not (p[0] == origin and p[1] == responder and p[2] == rq)
        }
        self.ack_pending.add((origin, responder, rq, result, gen, cookie))
        if result == HELLO_OK:
            # Cell becomes ACTIVE on OK ACK TX accept (docs/23 §5.2).
            self.handshake_active.add(peer)
            self.session_pair[peer] = (gen, cookie)

    def _observe_pong_tx(
        self, peer: str | None, n: dict[str, int], *, where: str, enforce: bool
    ) -> None:
        if not peer:
            if enforce:
                raise RuntimeError(f"{where}: PONG requires action peer")
            return
        req = n["request_id"]
        token = n["opaque_echo_token"]
        matches = [
            (o, r, rq, tok)
            for (o, r, rq, tok) in self.pings_out
            if r == peer and rq == req and tok == token
        ]
        if not matches:
            if enforce:
                raise RuntimeError(
                    f"{where}: PONG (req={req}, token={token}) has no outstanding "
                    f"PING delivered to responder={peer!r}"
                )
            return
        if len(matches) > 1:
            if enforce:
                raise RuntimeError(
                    f"{where}: ambiguous PING outstanding for responder={peer!r} "
                    f"request_id={req} token={token}: {sorted(matches)}"
                )
            return
        (origin, responder, rq, tok) = matches[0]
        self.pings_out.discard((origin, responder, rq, tok))
        self.pong_pending = {
            p
            for p in self.pong_pending
            if not (p[0] == origin and p[1] == responder and p[2] == rq and p[3] == tok)
        }
        self.pong_pending.add((origin, responder, rq, tok))

    def _observe_ctrl_error(
        self, peer: str | None, n: dict[str, int], *, where: str, enforce: bool
    ) -> None:
        """CTRL_ERROR gen/cookie: current ACTIVE exact pair, else 0/0 (§7.4)."""
        if not enforce:
            return
        gen = n["generation"]
        cookie = n["session_cookie"]
        if peer and peer in self.session_pair:
            exp = self.session_pair[peer]
            if (gen, cookie) != exp:
                raise RuntimeError(
                    f"{where}: CTRL_ERROR gen/cookie={(gen, cookie)} must equal "
                    f"current ACTIVE pair {exp} for peer={peer!r}"
                )
        else:
            if gen != 0 or cookie != 0:
                raise RuntimeError(
                    f"{where}: CTRL_ERROR on non-ACTIVE peer={peer!r} "
                    "requires generation=0 and cookie=0 (not ever-active nonzero)"
                )

    def _observe_reset_tx(
        self, peer: str | None, n: dict[str, int], *, where: str, enforce: bool
    ) -> None:
        """RESET gen/cookie: exact ACTIVE pair or continuity pre-fence snapshot."""
        if not enforce:
            return
        if not peer:
            raise RuntimeError(f"{where}: RESET requires action peer")
        pair = (n["generation"], n["session_cookie"])
        if peer in self.session_pair:
            if pair != self.session_pair[peer]:
                raise RuntimeError(
                    f"{where}: RESET gen/cookie={pair} must equal current ACTIVE "
                    f"{self.session_pair[peer]} for peer={peer!r}"
                )
            # Sending RESET while ACTIVE fences local session authority.
            self.pre_fence[peer] = pair
            del self.session_pair[peer]
            return
        if peer in self.pre_fence:
            if pair != self.pre_fence[peer]:
                raise RuntimeError(
                    f"{where}: RESET gen/cookie={pair} must equal pre-fence "
                    f"snapshot {self.pre_fence[peer]} for peer={peer!r}"
                )
            return
        raise RuntimeError(
            f"{where}: RESET has no ACTIVE pair or pre-fence snapshot for "
            f"peer={peer!r} (nonzero alone is insufficient)"
        )

    def _observe_forward_delivery(
        self,
        *,
        frm: str,
        to: str,
        n: dict[str, int],
        where: str,
        enforce: bool,
    ) -> None:
        mt = n["message_type"]
        if mt == MSG_HELLO:
            self._add_hello_outstanding(
                frm, to, n["request_id"], where=where, enforce=enforce
            )
            return
        if mt == MSG_PING:
            self._add_ping_outstanding(
                frm,
                to,
                n["request_id"],
                n["opaque_echo_token"],
                where=where,
                enforce=enforce,
            )
            return
        if mt == MSG_HELLO_ACK:
            req = n["request_id"]
            result = int(n.get("hello_ack_result", -1))
            gen = n["generation"]
            cookie = n["session_cookie"]
            matches = [
                p
                for p in self.ack_pending
                if p[1] == frm
                and p[2] == req
                and p[3] == result
                and p[4] == gen
                and p[5] == cookie
            ]
            if not matches:
                # Same residual after step: unique outstanding HELLO → open pending.
                hellos = [
                    (o, r, rq)
                    for (o, r, rq) in self.hellos_out
                    if r == frm and rq == req
                ]
                if len(hellos) == 1:
                    o, r, rq = hellos[0]
                    self.ack_pending.add((o, r, rq, result, gen, cookie))
                    if result == HELLO_OK:
                        self.handshake_active.add(frm)
                        self.session_pair[frm] = (gen, cookie)
                    matches = [(o, r, rq, result, gen, cookie)]
                elif len(hellos) > 1:
                    if enforce:
                        raise RuntimeError(
                            f"{where}: ambiguous HELLO for ACK forward "
                            f"responder={frm!r} request_id={req}: {sorted(hellos)}"
                        )
                    return
            if not matches:
                if enforce:
                    raise RuntimeError(
                        f"{where}: HELLO_ACK forward has no pending ACK "
                        f"(frm/source={frm!r}, req={req}, result={result})"
                    )
                return
            if len(matches) > 1:
                if enforce:
                    raise RuntimeError(
                        f"{where}: ambiguous pending ACK for forward "
                        f"frm={frm!r} req={req}: {sorted(matches)}"
                    )
                return
            (origin, responder, rq, res, g, c) = matches[0]
            if frm != responder:
                if enforce:
                    raise RuntimeError(
                        f"{where}: HELLO_ACK source={frm!r} must equal "
                        f"responder={responder!r}"
                    )
                return
            if to != origin:
                if enforce:
                    raise RuntimeError(
                        f"{where}: HELLO_ACK delivered to {to!r} but origin is "
                        f"{origin!r} (destination must equal HELLO origin)"
                    )
                return
            # Correlated delivery: consume HELLO outstanding + pending.
            self.hellos_out.discard((origin, responder, rq))
            self.ack_pending.discard((origin, responder, rq, res, g, c))
            if res == HELLO_OK:
                self.delivered_ack_to_origin.add((origin, responder, rq))
            return
        if mt == MSG_PONG:
            req = n["request_id"]
            tok = n["opaque_echo_token"]
            matches = [
                (o, r, rq, t)
                for (o, r, rq, t) in self.pong_pending
                if r == frm and rq == req and t == tok
            ]
            if not matches:
                # Residual path: unique outstanding PING.
                pings = [
                    (o, r, rq, t)
                    for (o, r, rq, t) in self.pings_out
                    if r == frm and rq == req and t == tok
                ]
                if len(pings) == 1:
                    o, r, rq, t = pings[0]
                    self.pings_out.discard((o, r, rq, t))
                    self.pong_pending.add((o, r, rq, t))
                    matches = [(o, r, rq, t)]
                elif len(pings) > 1:
                    if enforce:
                        raise RuntimeError(
                            f"{where}: ambiguous PING for PONG forward: {sorted(pings)}"
                        )
                    return
            if not matches:
                if enforce:
                    raise RuntimeError(
                        f"{where}: PONG forward has no pending PONG "
                        f"(frm={frm!r}, req={req})"
                    )
                return
            if len(matches) > 1:
                if enforce:
                    raise RuntimeError(
                        f"{where}: ambiguous pending PONG: {sorted(matches)}"
                    )
                return
            (origin, responder, rq, t) = matches[0]
            if to != origin:
                if enforce:
                    raise RuntimeError(
                        f"{where}: PONG delivered to {to!r} but origin is "
                        f"{origin!r} (destination must equal PING origin)"
                    )
                return
            self.pong_pending.discard((origin, responder, rq, t))
            return

    def _maybe_origin_active_from_step(
        self, op: str | None, peer: str | None, exp: dict
    ) -> None:
        if op != "step" or not peer:
            return
        if exp.get("state") != ST_ACT:
            return
        # Origin becomes ACTIVE after ACK OK delivery; bind session pair from ACK.
        for o, r, rq in list(self.delivered_ack_to_origin):
            if o != peer:
                continue
            self.handshake_active.add(peer)
            # Pair from responder's session or pending-less delivery: use responder pair.
            if r in self.session_pair:
                self.session_pair[peer] = self.session_pair[r]
            elif "active_generation" in exp and "active_cookie" in exp:
                self.session_pair[peer] = (
                    int(exp["active_generation"]),
                    int(exp["active_cookie"]),
                )
            break


def track_handshake_active(actions: list[dict]) -> set[str]:
    """Shared handshake ACTIVE proof used by gate force checks and causal scan."""
    tr = CausalTracker()
    for i, a in enumerate(actions):
        tr.observe(a, where=f"handshake[{i}]", enforce=False)
    return set(tr.handshake_active)


def validate_scenario_tx_causal(scenario: dict) -> None:
    """Peer-pair causal ACK/PONG + CTRL_ERROR vs unified handshake proof."""
    sid = scenario.get("id", "?")
    tr = CausalTracker()
    for i, a in enumerate(scenario.get("actions") or []):
        tr.observe(a, where=f"{sid}[{i}]", enforce=True)


def tx_hello(req: int, seq: int, stream: int = 0) -> dict:
    return {
        "frame_type": TYPE_DATA,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_HELLO,
        "generation": 0,
        "session_cookie": 0,
        "request_id": int(req),
        "hello_min_version": 1,
        "hello_max_version": 1,
        "hello_flags_supported": 0,
        "hello_reserved": 0,
    }


def tx_ack(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    stream: int = 0,
    result: int = 0,
) -> dict:
    selected = 1 if int(result) == 0 else 0
    return {
        "frame_type": TYPE_DATA,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_HELLO_ACK,
        "generation": int(gen),
        "session_cookie": int(cookie),
        "request_id": int(req),
        "hello_ack_selected_version": selected,
        "hello_ack_flags_selected": 0,
        "hello_ack_result": int(result),
        "hello_ack_reserved": 0,
    }


def tx_ping(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    token: int,
    stream: int = 0,
) -> dict:
    return {
        "frame_type": TYPE_PING,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_PING,
        "generation": int(gen),
        "session_cookie": int(cookie),
        "request_id": int(req),
        "opaque_echo_token": int(token),
    }


def tx_pong(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    token: int,
    stream: int = 0,
) -> dict:
    return {
        "frame_type": TYPE_PONG,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_PONG,
        "generation": int(gen),
        "session_cookie": int(cookie),
        "request_id": int(req),
        "opaque_echo_token": int(token),
    }


def tx_reset(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    code: int = 1,
    stream: int = 0,
) -> dict:
    return {
        "frame_type": TYPE_RESET,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_RESET,
        "generation": int(gen),
        "session_cookie": int(cookie),
        "request_id": int(req),
        "reset_code": int(code),
        "reset_reserved0": 0,
        "reset_reserved1": 0,
        "reset_reserved2": 0,
    }


def tx_ctrl_error(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    code: int,
    related: int = 0,
    stream: int = 0,
) -> dict:
    return {
        "frame_type": TYPE_DATA,
        "stream_id": int(stream),
        "sequence": int(seq),
        "message_type": MSG_CTRL_ERROR,
        "generation": int(gen),
        "session_cookie": int(cookie),
        "request_id": int(req),
        "error_code": int(code),
        "error_reserved": 0,
        "related_request_id": int(related),
    }


def ping_token(req: int, now_ms: int) -> int:
    """Explicit token formula used by scenario authors (must store result in tx desc)."""
    token = ((req & 0xFFFFFFFF) << 32) ^ (now_ms & 0xFFFFFFFFFFFFFFFF) ^ 0xA5A5A5A5
    token &= 0xFFFFFFFFFFFFFFFF
    return 1 if token == 0 else token


# Compatibility aliases that return descriptors (not bare hex).
def wire_hello(req: int = 1, seq: int = 0, stream: int = 0) -> dict:
    return tx_hello(req, seq, stream)


def wire_ack(
    req: int = 1,
    gen: int = 1,
    cookie: int = COOKIE,
    seq: int = 0,
    stream: int = 0,
    result: int = 0,
) -> dict:
    return tx_ack(req, gen, cookie, seq, stream, result)


def wire_ping(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    now_ms: int,
    stream: int = 0,
) -> dict:
    return tx_ping(req, gen, cookie, seq, ping_token(req, now_ms), stream)


def wire_pong(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    token: int,
    stream: int = 0,
) -> dict:
    return tx_pong(req, gen, cookie, seq, token, stream)


def wire_reset(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    code: int = 1,
    stream: int = 0,
) -> dict:
    return tx_reset(req, gen, cookie, seq, code, stream)


def wire_ctrl_error(
    req: int,
    gen: int,
    cookie: int,
    seq: int,
    code: int,
    related: int = 0,
    stream: int = 0,
) -> dict:
    return tx_ctrl_error(req, gen, cookie, seq, code, related, stream)


WIRE_HELLO_R1_S0 = tx_hello(1, 0)
WIRE_ACK_R1_G1_S0 = tx_ack(1, 1, COOKIE, 0)

def load_ncl1_required() -> list[str]:
    data = json.loads(NCL1_VECTOR.read_text(encoding="utf-8"))
    ids = data["required_ids"]
    if len(ids) != 46 or len(set(ids)) != 46:
        raise RuntimeError("ncl1-u4 required_ids must be 46 unique")
    return list(ids)


def engine_required_ids(ncl1_required: list[str]) -> list[str]:
    eng = [i for i in ncl1_required if i not in PURE_CODEC_ONLY_IDS]
    if len(eng) != 38:
        raise RuntimeError(f"expected 38 engine ids, got {len(eng)}")
    return eng


def peer(name: str, role: int, cookies=None, rng_fail: int = 0) -> dict:
    return {
        "name": name,
        "role": role,
        "cookie_seq": list(cookies if cookies is not None else [COOKIE]),
        "rng_fail": int(rng_fail),
    }


def dual(cell_cookies=None, cell_rng_fail: int = 0) -> list[dict]:
    return [
        peer("ctrl", ROLE_CTRL),
        peer("cell", ROLE_CELL, cell_cookies, cell_rng_fail),
    ]


def E(
    *,
    status: int | None = STATUS_OK,
    state: int | None = None,
    gen: int | None = None,
    cookie: int | None = None,
    next_tx: int | None = None,
    have_rx: int | None = None,
    last_rx: int | None = None,
    commit: int | None = None,
    kind: int | None = None,
    burns: int | None = None,
    notice_p: int | None = None,
    notice_a: int | None = None,
    ping_zero: int | None = None,
    hello_nz: int | None = None,
    counters: dict | None = None,
    counter_deltas: dict | None = None,
    tx_len: int | None = None,
    tx_type: int | None = None,
    tx_seq: int | None = None,
    tx_hex: str | None = None,
    tx: dict | None = None,
) -> dict:
    e: dict = {}
    if status is not None:
        e["status"] = int(status)
    if state is not None:
        e["state"] = int(state)
    if gen is not None:
        e["active_generation"] = int(gen)
    if cookie is not None:
        e["active_cookie"] = int(cookie)
    if next_tx is not None:
        e["next_tx_seq"] = int(next_tx)
    if have_rx is not None:
        e["have_rx_seq"] = int(have_rx)
    if last_rx is not None:
        e["last_rx_seq"] = int(last_rx)
    if commit is not None:
        e["last_tx_commit"] = int(commit)
    if kind is not None:
        e["last_tx_kind"] = int(kind)
    if burns is not None:
        e["burned_generation_count"] = int(burns)
    if notice_p is not None:
        e["continuity_notice_pending"] = int(notice_p)
    if notice_a is not None:
        e["continuity_notice_raw_accepted"] = int(notice_a)
    if ping_zero is not None:
        e["sole_ping_request_id_zero"] = int(ping_zero)
    if hello_nz is not None:
        e["sole_hello_request_id_nonzero"] = int(hello_nz)
    if counters:
        e["counters"] = {k: int(v) for k, v in counters.items()}
    if counter_deltas:
        e["counter_deltas"] = {k: int(v) for k, v in counter_deltas.items()}
    if tx is not None:
        # Explicit semantic oracle only path.
        if tx_hex is not None:
            raise RuntimeError("provide tx descriptor only (not raw tx_hex)")
        hx_s = encode_tx_desc(tx)
        e["tx"] = {k: int(v) if isinstance(v, bool) else v for k, v in tx.items()}
        # Normalize ints
        e["tx"] = {k: (int(v) if not isinstance(v, str) else v) for k, v in tx.items()}
        e["tx_hex"] = hx_s
        e["tx_len"] = len(hx_s) // 2
        raw = bytes.fromhex(hx_s)
        e["tx_ncg1_type"] = raw[5]
        e["tx_sequence"] = struct.unpack(">I", raw[12:16])[0]
    elif tx_hex is not None:
        # Accept legacy call-site style where wire_* already returns descriptor dict.
        if isinstance(tx_hex, dict):
            return E(
                status=status,
                state=state,
                gen=gen,
                cookie=cookie,
                next_tx=next_tx,
                have_rx=have_rx,
                last_rx=last_rx,
                commit=commit,
                kind=kind,
                burns=burns,
                notice_p=notice_p,
                notice_a=notice_a,
                ping_zero=ping_zero,
                hello_nz=hello_nz,
                counters=counters,
                counter_deltas=counter_deltas,
                tx=tx_hex,
            )
        raise RuntimeError(
            "bare tx_hex forbidden: pass tx=<complete semantic descriptor>"
        )
    else:
        if tx_len is not None:
            e["tx_len"] = int(tx_len)
        if tx_type is not None:
            e["tx_ncg1_type"] = int(tx_type)
        if tx_seq is not None:
            e["tx_sequence"] = int(tx_seq)
    return e


def require_rich_expect(e: dict, where: str) -> None:
    if "state_ne" in e:
        raise RuntimeError(f"{where}: state_ne forbidden")
    keys = set(e.keys()) - {"peer"}
    if keys <= {"state"} or not keys:
        raise RuntimeError(f"{where}: state-only/empty expect forbidden")
    has_major = any(
        k in e
        for k in (
            "state",
            "active_generation",
            "active_cookie",
            "next_tx_seq",
            "last_rx_seq",
            "last_tx_commit",
            "last_tx_kind",
            "counters",
            "counter_deltas",
            "status",
            "tx_len",
            "tx_hex",
        )
    )
    if not has_major:
        raise RuntimeError(f"{where}: missing major expect fields")
    tlen = int(e.get("tx_len") or 0)
    if tlen > 0:
        if "tx" not in e:
            raise RuntimeError(f"{where}: non-empty TX requires explicit tx descriptor")
        if "tx_hex" not in e:
            raise RuntimeError(f"{where}: non-empty TX missing derived tx_hex")
        if len(e["tx_hex"]) != tlen * 2:
            raise RuntimeError(f"{where}: tx_hex length mismatch tx_len")
        # Re-encode descriptor and require byte-identical oracle.
        if encode_tx_desc(e["tx"]) != e["tx_hex"]:
            raise RuntimeError(f"{where}: tx_hex not rebuild-identical from tx descriptor")
        # last_tx_kind (when present) must match message_type (no HELLO bytes under ACK kind).
        kind = e.get("last_tx_kind")
        mt = int(e["tx"]["message_type"])
        if kind is not None:
            expect_mt = {
                KIND_HELLO: MSG_HELLO,
                KIND_ACK: MSG_HELLO_ACK,
                KIND_PING: MSG_PING,
                KIND_PONG: MSG_PONG,
                KIND_RESET: MSG_RESET,
                KIND_CTRL_ERROR: MSG_CTRL_ERROR,
            }.get(int(kind))
            if expect_mt is not None and mt != expect_mt:
                raise RuntimeError(
                    f"{where}: last_tx_kind={kind} mismatches tx.message_type={mt}"
                )
    if tlen == 0 and ("tx_hex" in e or "tx" in e):
        raise RuntimeError(f"{where}: empty TX must not carry tx/tx_hex")


def A(op: str, **kw) -> dict:
    d = {"op": op}
    d.update(kw)
    if op in (
        "step",
        "inject",
        "cell_continuity_loss",
        "drop_tx",
        "forward",
        "init_peer",
        "force_state",
        "force_rx_baseline",
        "force_next_tx_seq",
        "request_hello_now",
        "set_write_would_block",
        "force_ping_eligible",
        "set_rng_fail",
    ):
        if "expect" not in d and op in ("step", "inject", "cell_continuity_loss", "drop_tx"):
            raise RuntimeError(f"{op} requires expect")
    if "expect" in d:
        require_rich_expect(d["expect"], f"action {op}")
    return d


def step(peer_name: str, now_ms: int, expect: dict, *, now_delta: int | None = None) -> dict:
    d = {"op": "step", "peer": peer_name, "expect": expect}
    if now_delta is not None:
        d["now_delta_ms"] = int(now_delta)
    else:
        d["now_ms"] = int(now_ms)
    return d


def forward(frm: str, to: str, expect: dict) -> dict:
    return {"op": "forward", "frm": frm, "to": to, "expect": expect}


def drop_tx(peer_name: str, expect: dict) -> dict:
    return {"op": "drop_tx", "peer": peer_name, "expect": expect}


def force_next_tx_seq(peer_name: str, next_tx_seq: int, expect: dict) -> dict:
    return A(
        "force_next_tx_seq",
        peer=peer_name,
        next_tx_seq=int(next_tx_seq),
        expect=expect,
    )


def force_ping_eligible(peer_name: str, eligible_at_ms: int, expect: dict | None = None) -> dict:
    d = A(
        "force_ping_eligible",
        peer=peer_name,
        eligible_at_ms=int(eligible_at_ms),
    )
    if expect is not None:
        d["expect"] = expect
    return d


def mark(peer_name: str) -> dict:
    return {"op": "mark_baseline", "peer": peer_name}


def inject(
    peer_name: str,
    ncg1_type: int,
    expect: dict,
    *,
    seq_mode: str = "abs",
    seq: int = 0,
    stream_id: int = 0,
    msg_type: int | None = None,
    req_mode: str = "fixed",
    request_id: int = 0,
    gen_mode: str = "fixed",
    generation: int = 0,
    cookie_mode: str = "fixed",
    cookie: int = 0,
    body_hex: str = "",
    payload_hex: str | None = None,
) -> dict:
    d: dict = {
        "op": "inject",
        "peer": peer_name,
        "ncg1_type": int(ncg1_type),
        "seq_mode": seq_mode,
        "seq": int(seq),
        "stream_id": int(stream_id),
        "expect": expect,
    }
    if payload_hex is not None:
        d["payload_hex"] = payload_hex
    elif msg_type is not None:
        d["ncl1"] = {
            "msg_type": int(msg_type),
            "req_mode": req_mode,
            "request_id": int(request_id),
            "gen_mode": gen_mode,
            "generation": int(generation),
            "cookie_mode": cookie_mode,
            "cookie": int(cookie),
            "body_hex": body_hex,
        }
    else:
        d["payload_hex"] = ""
    return d


# Minimal handshake (both ACTIVE at end of step5); TX wire from independent encoder.
def hs_actions() -> list[dict]:
    return [
        step(
            "ctrl",
            1000,
            E(
                status=STATUS_OK,
                state=ST_HSENT,
                gen=0,
                cookie=0,
                next_tx=1,
                have_rx=0,
                commit=TX_RAW,
                kind=KIND_HELLO,
                counters={"raw_accepts": 1, "hello_retry": 0},
                tx=WIRE_HELLO_R1_S0,
            ),
        ),
        forward(
            "ctrl",
            "cell",
            E(status=STATUS_OK, state=ST_HSENT, tx=WIRE_HELLO_R1_S0),
        ),
        step(
            "cell",
            1000,
            E(
                status=STATUS_OK,
                state=ST_HRECV,
                gen=0,
                cookie=0,
                next_tx=0,
                have_rx=1,
                last_rx=0,
                commit=TX_NONE,
                kind=KIND_NONE,
                burns=1,
                counters={"raw_accepts": 0, "hello_baseline_resync": 1},
                tx_len=0,
            ),
        ),
        forward("cell", "ctrl", E(status=STATUS_OK, tx_len=0, state=ST_HRECV)),
        step(
            "ctrl",
            1000,
            E(
                status=STATUS_OK,
                state=ST_HSENT,
                gen=0,
                cookie=0,
                next_tx=1,
                have_rx=0,
                commit=TX_RAW,
                kind=KIND_HELLO,
                counters={"raw_accepts": 1},
                tx_len=0,
            ),
        ),
        forward("ctrl", "cell", E(status=STATUS_OK, tx_len=0, state=ST_HSENT)),
        step(
            "cell",
            1000,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                next_tx=1,
                have_rx=1,
                last_rx=0,
                commit=TX_RAW,
                kind=KIND_ACK,
                burns=1,
                counters={"raw_accepts": 1, "hello_baseline_resync": 1},
                tx=WIRE_ACK_R1_G1_S0,
            ),
        ),
        forward(
            "cell",
            "ctrl",
            E(status=STATUS_OK, state=ST_ACT, tx=WIRE_ACK_R1_G1_S0),
        ),
        step(
            "ctrl",
            1050,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                next_tx=1,
                have_rx=1,
                last_rx=0,
                commit=TX_RAW,
                kind=KIND_HELLO,
                counters={"raw_accepts": 1, "hello_ack_baseline_resync": 1},
                tx_len=0,
            ),
        ),
        forward("ctrl", "cell", E(status=STATUS_OK, tx_len=0, state=ST_ACT)),
    ]


def fin(
    peer_name: str,
    *,
    state: int,
    gen: int,
    cookie: int,
    next_tx: int | None = None,
    have_rx: int | None = None,
    last_rx: int | None = None,
    commit: int | None = None,
    kind: int | None = None,
    burns: int | None = None,
    notice_p: int | None = None,
    counters: dict | None = None,
    counter_deltas: dict | None = None,
    ping_zero: int | None = None,
) -> dict:
    e = E(
        status=None,
        state=state,
        gen=gen,
        cookie=cookie,
        next_tx=next_tx,
        have_rx=have_rx,
        last_rx=last_rx,
        commit=commit,
        kind=kind,
        burns=burns,
        notice_p=notice_p,
        counters=counters,
        counter_deltas=counter_deltas,
        ping_zero=ping_zero,
    )
    e["peer"] = peer_name
    # drop status for final
    e.pop("status", None)
    require_rich_expect(e, f"final {peer_name}")
    return e


def scenario(
    sid: str,
    family: int,
    peers: list[dict],
    actions: list[dict],
    expect_final: list[dict],
    *,
    initial: list[dict] | None = None,
) -> dict:
    if not actions:
        raise RuntimeError(f"{sid}: empty actions")
    for i, a in enumerate(actions):
        if a["op"] in ("handshake_active", "step_pair", "quiet_drain", "quiet_drain_tx"):
            raise RuntimeError(f"{sid}: macro op forbidden: {a['op']}")
        if "assertion_key" in a:
            raise RuntimeError(f"{sid}: assertion_key forbidden")
        if a["op"] in ("step", "inject", "cell_continuity_loss", "drop_tx", "forward"):
            if "expect" not in a:
                raise RuntimeError(f"{sid} action[{i}] missing expect")
            require_rich_expect(a["expect"], f"{sid}[{i}]")
    for e in expect_final:
        require_rich_expect(e, f"{sid} final")
        if "state_ne" in e:
            raise RuntimeError(f"{sid}: state_ne forbidden")
        if set(e.keys()) - {"peer"} <= {"state"}:
            raise RuntimeError(f"{sid}: state-only final forbidden")
    return {
        "id": sid,
        "kind": "engine_behavior",
        "family": family,
        "family_name": FAMILIES[family],
        "codec_case": False,
        "precondition": {
            "peers": peers,
            "bind": True,
            "initial": initial or [],
        },
        "actions": actions,
        "expect_final": expect_final,
    }


def build_engine_scenarios() -> list[dict]:
    out: list[dict] = []

    # 1 HELLO-OK
    out.append(
        scenario(
            "U4-G-HELLO-OK",
            1,
            dual(),
            hs_actions(),
            [
                fin(
                    "ctrl",
                    state=ST_ACT,
                    gen=1,
                    cookie=COOKIE,
                    next_tx=1,
                    have_rx=1,
                    last_rx=0,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                    counters={"raw_accepts": 1, "hello_ack_baseline_resync": 1},
                ),
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=1,
                    cookie=COOKIE,
                    next_tx=1,
                    have_rx=1,
                    last_rx=0,
                    commit=TX_RAW,
                    kind=KIND_ACK,
                    burns=1,
                    counters={"raw_accepts": 1, "hello_baseline_resync": 1},
                ),
            ],
        )
    )

    # 2 PING-PONG — time advance to cadence (no force_ping)
    out.append(
        scenario(
            "U4-G-PING-PONG",
            1,
            dual(),
            hs_actions()
            + [
                mark("ctrl"),
                step(
                    "ctrl",
                    1050 + PING_CADENCE_MS,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        commit=TX_RAW,
                        kind=KIND_PING,
                        counter_deltas={"raw_accepts": 1, "pong_miss": 0, "liveness_fail": 0},
                        tx=wire_ping(2, 1, COOKIE, 1, 1050 + PING_CADENCE_MS),
                    ),
                ),
                forward(
                    "ctrl",
                    "cell",
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        tx=wire_ping(2, 1, COOKIE, 1, 1050 + PING_CADENCE_MS),
                    ),
                ),
                step(
                    "cell",
                    1050 + PING_CADENCE_MS,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        have_rx=1,
                        last_rx=1,
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1050 + PING_CADENCE_MS,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        have_rx=1,
                        last_rx=1,
                        commit=TX_RAW,
                        kind=KIND_PONG,
                        tx=wire_pong(2, 1, COOKIE, 1, ping_token(2, 1050 + PING_CADENCE_MS)),
                    ),
                ),
                forward(
                    "cell",
                    "ctrl",
                    E(status=STATUS_OK, state=ST_ACT, tx=wire_pong(2, 1, COOKIE, 1, ping_token(2, 1050 + PING_CADENCE_MS))),
                ),
                step(
                    "ctrl",
                    1050 + PING_CADENCE_MS + 1,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        ping_zero=1,
                        have_rx=1,
                        last_rx=1,
                        counter_deltas={"pong_miss": 0, "liveness_fail": 0},
                        tx_len=0,
                    ),
                ),
                # --- P1-B: DEADLINE_OVERFLOW zero-mutation ---
                mark("ctrl"),
                # eligible_at + slack overflow → DEADLINE_OVERFLOW, exact zero mutation.
                force_ping_eligible(
                    "ctrl",
                    UINT64_MAX - 10,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                ),
                step(
                    "ctrl",
                    1050 + PING_CADENCE_MS + 1,
                    E(
                        status=STATUS_DEADLINE_OVERFLOW,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        have_rx=1,
                        last_rx=1,
                        counter_deltas={
                            "pong_miss": 0,
                            "liveness_fail": 0,
                            "raw_accepts": 0,
                            "tx_actions_submitted": 0,
                        },
                        tx_len=0,
                    ),
                ),
                # Pure now+max_add overflow (eligible restored to in-window high value).
                force_ping_eligible(
                    "ctrl",
                    UINT64_MAX - DEADLINE_MAX_ADD_MS,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                ),
                step(
                    "ctrl",
                    UINT64_MAX - DEADLINE_MAX_ADD_MS + 1,
                    E(
                        status=STATUS_DEADLINE_OVERFLOW,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        have_rx=1,
                        last_rx=1,
                        counter_deltas={
                            "pong_miss": 0,
                            "liveness_fail": 0,
                            "raw_accepts": 0,
                        },
                        tx_len=0,
                    ),
                ),
                # Boundary success: now == eligible == UINT64_MAX - DEADLINE_MAX_ADD
                # (within PING dispatch slack; no overflow).
                step(
                    "ctrl",
                    UINT64_MAX - DEADLINE_MAX_ADD_MS,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=3,
                        have_rx=1,
                        commit=TX_RAW,
                        kind=KIND_PING,
                        counter_deltas={"raw_accepts": 1},
                        tx=wire_ping(
                            3,
                            1,
                            COOKIE,
                            2,
                            UINT64_MAX - DEADLINE_MAX_ADD_MS,
                        ),
                    ),
                ),
                # --- P1-A: Controller TX sequence terminal exhaustion ---
                force_next_tx_seq(
                    "ctrl",
                    TX_SEQ_TERMINAL,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=TX_SEQ_TERMINAL,
                        tx_len=0,
                    ),
                ),
                step(
                    "ctrl",
                    UINT64_MAX - DEADLINE_MAX_ADD_MS,
                    E(
                        status=STATUS_CONTINUITY_LOST,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=0,
                        have_rx=0,
                        tx_len=0,
                    ),
                ),
                # Recovery: Controller re-HELLO at seq0 (not silent session DATA wrap).
                step(
                    "ctrl",
                    UINT64_MAX - DEADLINE_MAX_ADD_MS,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=0,
                        cookie=0,
                        next_tx=1,
                        have_rx=0,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(4, 0),
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    next_tx=1,
                    have_rx=0,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                )
            ],
        )
    )

    # 3 RESET via real gap inject (no cell_continuity_loss for behavior)
    out.append(
        scenario(
            "U4-G-RESET-SESSION",
            2,
            dual(),
            hs_actions()
            + [
                A("set_write_would_block", peer="cell", enable=1, expect=E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0)),
                mark("cell"),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=0,
                        notice_p=1,
                        counter_deltas={"ncg1_reject_seq_gap": 1, "continuity_notice_created": 1},
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    have_rx=0,
                    notice_p=1,
                    counters={"ncg1_reject_seq_gap": 1, "continuity_notice_created": 1},
                )
            ],
        )
    )

    # 4 HELLO retry next seq
    out.append(
        scenario(
            "U4-G-HELLO-RETRY-NEXT-SEQ",
            3,
            [peer("ctrl", ROLE_CTRL)],
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=0,
                        cookie=0,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        counters={"hello_retry": 0, "raw_accepts": 1},
                        tx=wire_hello(1, 0),
                    ),
                ),
                mark("ctrl"),
                step(
                    "ctrl",
                    1000 + HELLO_RETRY_MS + 100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=2,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        counter_deltas={"hello_retry": 1, "raw_accepts": 1},
                        tx=wire_hello(2, 1),
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    next_tx=2,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                    counters={"hello_retry": 1, "raw_accepts": 2},
                )
            ],
        )
    )

    # 5 HELLO-RETRY-SEQ0-COLD (same path, pin next!=0)
    out.append(
        scenario(
            "U4-N-HELLO-RETRY-SEQ0-COLD",
            3,
            [peer("ctrl", ROLE_CTRL)],
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        counters={"hello_retry": 0},
                        tx=wire_hello(1, 0),
                    ),
                ),
                mark("ctrl"),
                step(
                    "ctrl",
                    1000 + HELLO_RETRY_MS + 100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=2,
                        counter_deltas={"hello_retry": 1},
                        tx=wire_hello(2, 1),
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    next_tx=2,
                    commit=TX_RAW,
                    counters={"hello_retry": 1, "raw_accepts": 2},
                )
            ],
        )
    )

    # Helper: drop ACK path partial then rehello for halfopen family
    def ackloss_to_cell_active_drop_ack() -> list[dict]:
        acts = [
            step(
                "ctrl",
                1000,
                E(
                    status=STATUS_OK,
                    state=ST_HSENT,
                    next_tx=1,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                    counters={"raw_accepts": 1},
                    tx=wire_hello(1, 0),
                ),
            ),
            forward(
                "ctrl",
                "cell",
                E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
            ),
            step(
                "cell",
                1000,
                E(
                    status=STATUS_OK,
                    state=ST_HRECV,
                    have_rx=1,
                    last_rx=0,
                    burns=1,
                    counters={"hello_baseline_resync": 1},
                    tx_len=0,
                ),
            ),
            forward("cell", "ctrl", E(status=STATUS_OK, tx_len=0, state=ST_HRECV)),
            step(
                "ctrl",
                1000,
                E(status=STATUS_OK, state=ST_HSENT, next_tx=1, counters={"raw_accepts": 1}, tx_len=0),
            ),
            forward("ctrl", "cell", E(status=STATUS_OK, tx_len=0, state=ST_HSENT)),
            step(
                "cell",
                1000,
                E(
                    status=STATUS_OK,
                    state=ST_ACT,
                    gen=1,
                    cookie=COOKIE,
                    next_tx=1,
                    have_rx=1,
                    last_rx=0,
                    commit=TX_RAW,
                    kind=KIND_ACK,
                    burns=1,
                    counters={"raw_accepts": 1},
                    tx=wire_ack(1, 1, COOKIE, 0),
                ),
            ),
            drop_tx(
                "cell",
                E(
                    status=STATUS_OK,
                    state=ST_ACT,
                    gen=1,
                    cookie=COOKIE,
                    tx=wire_ack(1, 1, COOKIE, 0),
                ),
            ),
        ]
        return acts


    # 6 ACKLOSS LAST0 HALFOPEN — drop ACK, retry HELLO, halfopen fence, recover
    acts = ackloss_to_cell_active_drop_ack() + [
        mark("cell"),
        step(
            "ctrl",
            1300,
            E(
                status=STATUS_OK,
                state=ST_HSENT,
                gen=0,
                cookie=0,
                next_tx=2,
                commit=TX_RAW,
                kind=KIND_HELLO,
                counters={"hello_retry": 1, "raw_accepts": 2},
                tx=wire_hello(2, 1),
            ),
        ),
        forward(
            "ctrl",
            "cell",
            E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(2, 1)),
        ),
        step(
            "cell",
            1300,
            E(
                status=STATUS_OK,
                state=ST_HRECV,
                gen=0,
                cookie=0,
                have_rx=1,
                last_rx=1,
                burns=2,
                counter_deltas={"hello_halfopen_fence": 1},
                commit=TX_RAW,
                kind=KIND_ACK,
                tx_len=0,
            ),
        ),
        forward("cell", "ctrl", E(status=STATUS_OK, state=ST_HRECV, tx_len=0)),
        step(
            "ctrl",
            1300,
            E(
                status=STATUS_OK,
                state=ST_HSENT,
                gen=0,
                cookie=0,
                next_tx=2,
                counters={"hello_retry": 1, "raw_accepts": 2},
                tx_len=0,
            ),
        ),
        forward("ctrl", "cell", E(status=STATUS_OK, state=ST_HSENT, tx_len=0)),
        step(
            "cell",
            1300,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=2,
                cookie=COOKIE,
                have_rx=1,
                last_rx=1,
                burns=2,
                commit=TX_RAW,
                kind=KIND_ACK,
                counters={"hello_halfopen_fence": 1, "raw_accepts": 2},
                tx=wire_ack(2, 2, COOKIE, 1),
            ),
        ),
        forward(
            "cell",
            "ctrl",
            E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(2, 2, COOKIE, 1)),
        ),
        step(
            "ctrl",
            1320,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=2,
                cookie=COOKIE,
                have_rx=1,
                commit=TX_RAW,
                counters={"hello_ack_baseline_resync": 1, "raw_accepts": 2},
                tx_len=0,
            ),
        ),
    ]
    out.append(
        scenario(
            "U4-G-ACKLOSS-LAST0-HALFOPEN",
            3,
            dual(),
            acts,
            [
                fin(
                    "ctrl",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 1},
                ),
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    counters={"hello_halfopen_fence": 1},
                ),
            ],
        )
    )

    # 7 ACKLOSS reverse SBR
    acts = ackloss_to_cell_active_drop_ack() + [
        mark("ctrl"),
        step(
            "ctrl",
            1300,
            E(
                status=STATUS_OK,
                state=ST_HSENT,
                gen=0,
                cookie=0,
                next_tx=2,
                have_rx=0,
                counters={"hello_retry": 1, "hello_ack_baseline_resync": 0},
                tx=wire_hello(2, 1),
            ),
        ),
        forward(
            "ctrl",
            "cell",
            E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(2, 1)),
        ),
        step(
            "cell",
            1300,
            E(
                status=STATUS_OK,
                state=ST_HRECV,
                gen=0,
                cookie=0,
                burns=2,
                counters={"hello_halfopen_fence": 1},
                commit=TX_RAW,
                tx_len=0,
            ),
        ),
        forward("cell", "ctrl", E(status=STATUS_OK, state=ST_HRECV, tx_len=0)),
        step(
            "ctrl",
            1300,
            E(status=STATUS_OK, state=ST_HSENT, gen=0, cookie=0, next_tx=2, tx_len=0),
        ),
        forward("ctrl", "cell", E(status=STATUS_OK, state=ST_HSENT, tx_len=0)),
        step(
            "cell",
            1300,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=2,
                cookie=COOKIE,
                commit=TX_RAW,
                kind=KIND_ACK,
                counters={"hello_halfopen_fence": 1},
                tx=wire_ack(2, 2, COOKIE, 1),
            ),
        ),
        forward(
            "cell",
            "ctrl",
            E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(2, 2, COOKIE, 1)),
        ),
        step(
            "ctrl",
            1320,
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=2,
                cookie=COOKIE,
                have_rx=1,
                counter_deltas={"hello_ack_baseline_resync": 1},
                commit=TX_RAW,
                tx_len=0,
            ),
        ),
    ]
    out.append(
        scenario(
            "U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE",
            3,
            dual(),
            acts,
            [
                fin(
                    "ctrl",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 1},
                )
            ],
        )
    )

    # Halfopen / rehello via second controller peer (no force_state)
    def rehello_ctrl2(sid: str, family: int) -> dict:
        acts = hs_actions() + [
            mark("cell"),
            A(
                "init_peer",
                peer="ctrl2",
                role=ROLE_CTRL,
                expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
            ),
            step(
                "ctrl2",
                1100,
                E(
                    status=STATUS_OK,
                    state=ST_HSENT,
                    next_tx=1,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                    counters={"raw_accepts": 1},
                    tx=wire_hello(1, 0),
                ),
            ),
            forward(
                "ctrl2",
                "cell",
                E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
            ),
            step(
                "cell",
                1100,
                E(
                    status=STATUS_OK,
                    state=ST_HRECV,
                    gen=0,
                    cookie=0,
                    counter_deltas={"hello_halfopen_fence": 1},
                    commit=TX_RAW,
                    tx_len=0,
                ),
            ),
            forward("cell", "ctrl2", E(status=STATUS_OK, state=ST_HRECV, tx_len=0)),
            step(
                "cell",
                1100,
                E(
                    status=STATUS_OK,
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    commit=TX_RAW,
                    kind=KIND_ACK,
                    counters={"hello_halfopen_fence": 1},
                    tx=wire_ack(1, 2, COOKIE, 1),
                ),
            ),
            forward(
                "cell",
                "ctrl2",
                E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(1, 2, COOKIE, 1)),
            ),
            step(
                "ctrl2",
                1120,
                E(
                    status=STATUS_OK,
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 1},
                    tx_len=0,
                ),
            ),
        ]
        return scenario(
            sid,
            family,
            dual(),
            acts,
            [
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    counters={"hello_halfopen_fence": 1},
                ),
                fin(
                    "ctrl2",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 1},
                ),
            ],
        )

    out.append(rehello_ctrl2("U4-G-HALFOPEN-REHELLO", 4))
    out.append(rehello_ctrl2("U4-N-HELLO-ACTIVE-COOKIE-REJECT", 4))

    # Restart bootstrap / high ACK (force only as setup before protocol)
    def restart_boot(sid: str, last: int) -> dict:
        return scenario(
            sid,
            4 if "SEQ-DISCARD" not in sid else 9,
            dual(),
            hs_actions()
            + [
                A(
                    "force_rx_baseline",
                    peer="cell",
                    have=1,
                    last=last,
                    expect=E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        have_rx=1,
                        last_rx=last,
                        tx_len=0,
                    ),
                ),
                mark("cell"),
                A(
                    "init_peer",
                    peer="ctrl2",
                    role=ROLE_CTRL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                step(
                    "ctrl2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl2",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        gen=0,
                        cookie=0,
                        counter_deltas={"hello_bootstrap_epoch_restart": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        counters={"hello_bootstrap_epoch_restart": 1},
                        # Explicit ACK oracle: echo peer HELLO request_id=1
                        # (not request allocator / snapshot synthesis).
                        tx=wire_ack(1, 2, COOKIE, 1),
                    ),
                ),
                forward(
                    "cell",
                    "ctrl2",
                    E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(1, 2, COOKIE, 1)),
                ),
                step(
                    "ctrl2",
                    1120,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        have_rx=1,
                        commit=TX_RAW,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    counters={"hello_bootstrap_epoch_restart": 1},
                )
            ],
        )

    out.append(restart_boot("U4-G-RESTART-SEQ0-LAST0", 0))
    out.append(restart_boot("U4-G-RESTART-SEQ0-LAST-HIGH", 50))
    out.append(restart_boot("U4-N-SEQ-DISCARD-NO-NCL1-PEEK", 5))

    out.append(
        scenario(
            "U4-G-RESTART-ACK-HIGH-BASELINE",
            4,
            dual(),
            hs_actions()
            + [
                A(
                    "force_next_tx_seq",
                    peer="cell",
                    next_tx_seq=40,
                    expect=E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=40,
                        tx_len=0,
                    ),
                ),
                A(
                    "init_peer",
                    peer="ctrl2",
                    role=ROLE_CTRL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                mark("ctrl2"),
                step(
                    "ctrl2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl2",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        gen=0,
                        cookie=0,
                        next_tx=40,
                        counters={"hello_halfopen_fence": 1, "hello_bootstrap_epoch_restart": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        next_tx=41,
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        counters={"hello_halfopen_fence": 1, "hello_bootstrap_epoch_restart": 1},
                        tx=wire_ack(1, 2, COOKIE, 40),
                    ),
                ),
                forward(
                    "cell",
                    "ctrl2",
                    E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(1, 2, COOKIE, 40)),
                ),
                step(
                    "ctrl2",
                    1120,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        have_rx=1,
                        counter_deltas={"hello_ack_baseline_resync": 1},
                        commit=TX_RAW,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "ctrl2",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 1},
                )
            ],
        )
    )

    # CELL restart ACK0 regress
    out.append(
        scenario(
            "U4-G-CELL-RESTART-ACK0-RETRY",
            5,
            dual(),
            hs_actions()
            + [
                mark("ctrl"),
                A(
                    "force_rx_baseline",
                    peer="ctrl",
                    have=1,
                    last=7,
                    expect=E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        have_rx=1,
                        last_rx=7,
                        tx_len=0,
                    ),
                ),
                A(
                    "init_peer",
                    peer="cell2",
                    role=ROLE_CELL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                A(
                    "force_state",
                    peer="ctrl",
                    state=ST_LINK,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=1, cookie=COOKIE, tx_len=0),
                ),
                A(
                    "request_hello_now",
                    peer="ctrl",
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=1, cookie=COOKIE, tx_len=0),
                ),
                step(
                    "ctrl",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        have_rx=1,
                        last_rx=7,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(2, 1),
                    ),
                ),
                forward(
                    "ctrl",
                    "cell2",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(2, 1)),
                ),
                step(
                    "cell2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        burns=1,
                        have_rx=1,
                        counters={"hello_baseline_resync": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        tx=wire_ack(2, 1, COOKIE, 0),
                    ),
                ),
                forward(
                    "cell2",
                    "ctrl",
                    E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(2, 1, COOKIE, 0)),
                ),
                step(
                    "ctrl",
                    1120,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=0,
                        counter_deltas={"ncg1_reject_seq_regress": 1},
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    have_rx=0,
                    counters={"ncg1_reject_seq_regress": 1},
                )
            ],
        )
    )

    # CELL RX cold high HELLO inject
    out.append(
        scenario(
            "U4-G-CELL-RXCOLD-HIGH-HELLO",
            5,
            dual(),
            hs_actions()
            + [
                A(
                    "set_write_would_block",
                    peer="cell",
                    enable=1,
                    expect=E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                ),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=0,
                        notice_p=1,
                        counters={"ncg1_reject_seq_gap": 1, "continuity_notice_created": 1},
                        tx_len=0,
                    ),
                ),
                mark("cell"),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, tx_len=0),
                    seq_mode="abs",
                    seq=20,
                    msg_type=MSG_HELLO,
                    request_id=0x55,
                    body_hex=hx(hello_body()),
                ),
                step(
                    "cell",
                    1060,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        have_rx=1,
                        last_rx=20,
                        burns=2,
                        counter_deltas={"hello_baseline_resync": 1},
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_HRECV,
                    gen=0,
                    cookie=0,
                    have_rx=1,
                    last_rx=20,
                    burns=2,
                    counters={"hello_baseline_resync": 2},
                )
            ],
        )
    )

    # CTRL RX cold high ACK
    out.append(
        scenario(
            "U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK",
            6,
            dual(),
            hs_actions()
            + [
                mark("ctrl"),
                A(
                    "force_rx_baseline",
                    peer="ctrl",
                    have=0,
                    last=0,
                    expect=E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        have_rx=0,
                        tx_len=0,
                    ),
                ),
                A(
                    "force_state",
                    peer="ctrl",
                    state=ST_LINK,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=1, cookie=COOKIE, tx_len=0),
                ),
                A(
                    "request_hello_now",
                    peer="ctrl",
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=1, cookie=COOKIE, tx_len=0),
                ),
                A(
                    "force_next_tx_seq",
                    peer="cell",
                    next_tx_seq=15,
                    expect=E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=15,
                        tx_len=0,
                    ),
                ),
                step(
                    "ctrl",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        have_rx=0,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(2, 1),
                    ),
                ),
                forward(
                    "ctrl",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(2, 1)),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        gen=0,
                        cookie=0,
                        next_tx=15,
                        have_rx=1,
                        counters={"hello_halfopen_fence": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        next_tx=16,
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        counters={"hello_halfopen_fence": 1},
                        tx=wire_ack(2, 2, COOKIE, 15),
                    ),
                ),
                forward(
                    "cell",
                    "ctrl",
                    E(status=STATUS_OK, state=ST_ACT, tx=wire_ack(2, 2, COOKIE, 15)),
                ),
                step(
                    "ctrl",
                    1120,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        have_rx=1,
                        counter_deltas={"hello_ack_baseline_resync": 1},
                        commit=TX_RAW,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    have_rx=1,
                    commit=TX_RAW,
                    counters={"hello_ack_baseline_resync": 2},
                )
            ],
        )
    )

    # Continuity notice family
    out.append(
        scenario(
            "U4-G-CELL-CONTINUITY-RESET-SESSION",
            7,
            dual(),
            hs_actions()
            + [
                A(
                    "set_write_would_block",
                    peer="cell",
                    enable=1,
                    expect=E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                ),
                mark("cell"),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        notice_p=1,
                        have_rx=0,
                        counter_deltas={
                            "continuity_notice_created": 1,
                            "ncg1_reject_seq_gap": 1,
                        },
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    notice_p=1,
                    have_rx=0,
                    counters={"continuity_notice_created": 1, "ncg1_reject_seq_gap": 1},
                )
            ],
        )
    )

    out.append(
        scenario(
            "U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO",
            7,
            dual(),
            hs_actions()
            + [
                A(
                    "set_write_would_block",
                    peer="cell",
                    enable=1,
                    expect=E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                ),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        notice_p=1,
                        counters={"continuity_notice_created": 1},
                        tx_len=0,
                    ),
                ),
                mark("cell"),
                A(
                    "init_peer",
                    peer="ctrl2",
                    role=ROLE_CTRL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                step(
                    "ctrl2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl2",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        notice_p=0,
                        counter_deltas={"continuity_reset_notice_cancelled": 1},
                        burns=2,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_HRECV,
                    gen=0,
                    cookie=0,
                    notice_p=0,
                    burns=2,
                    counters={"continuity_reset_notice_cancelled": 1},
                )
            ],
        )
    )

    out.append(
        scenario(
            "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK",
            7,
            dual(),
            hs_actions()
            + [
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        notice_p=1,
                        counters={"continuity_notice_created": 1, "continuity_notice_accepted": 0},
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        tx_len=0,
                    ),
                ),
                mark("cell"),
                step(
                    "cell",
                    1060,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        notice_p=0,
                        commit=TX_RAW,
                        kind=KIND_RESET,
                        counter_deltas={"continuity_notice_accepted": 1},
                        tx=wire_reset(1, 1, COOKIE, 1),
                    ),
                ),
                # Post-fence (non-ACTIVE): CTRL_ERROR uses 0/0, not pre-fence pair (§7.4).
                # RX cold after gap → baseline via exact seq 0 (not SBR; PING+HELLO is binding fail).
                inject(
                    "cell",
                    TYPE_PING,
                    E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, tx_len=0),
                    seq_mode="fixed",
                    seq=0,
                    msg_type=MSG_HELLO,
                    request_id=9,
                    generation=0,
                    cookie=0,
                    body_hex=hx(hello_body()),
                ),
                step(
                    "cell",
                    1065,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=1,
                        last_rx=0,
                        counter_deltas={
                            "continuity_notice_accepted": 1,
                            "logical_rejects": 1,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 1,
                            "raw_accepts": 1,
                        },
                        commit=TX_RAW,
                        kind=KIND_RESET,
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1070,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=1,
                        last_rx=0,
                        next_tx=3,
                        commit=TX_RAW,
                        kind=KIND_CTRL_ERROR,
                        counter_deltas={
                            "continuity_notice_accepted": 1,
                            "logical_rejects": 1,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 2,
                            "raw_accepts": 2,
                        },
                        tx=wire_ctrl_error(0, 0, 0, 2, ERR_TYPE_BINDING, related=0),
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    commit=TX_RAW,
                    kind=KIND_CTRL_ERROR,
                    counters={
                        "continuity_notice_created": 1,
                        "continuity_notice_accepted": 1,
                        "logical_rejects": 1,
                        "ncl1_reject_type_binding": 1,
                        "raw_accepts": 3,
                        "tx_actions_submitted": 3,
                    },
                )
            ],
        )
    )

    # DUP HELLO
    out.append(
        scenario(
            "U4-G-DUP-HELLO-RECEIVED",
            1,
            dual(cell_cookies=[0xA1A1A1A1A1A1A1A1, 0xB2B2B2B2B2B2B2B2]),
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        burns=1,
                        have_rx=1,
                        last_rx=0,
                        counters={"hello_baseline_resync": 1},
                        tx_len=0,
                    ),
                ),
                mark("cell"),
                A(
                    "init_peer",
                    peer="ctrl2",
                    role=ROLE_CTRL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                step(
                    "ctrl2",
                    1050,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl2",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1050,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        burns=2,
                        have_rx=1,
                        last_rx=0,
                        counters={"hello_baseline_resync": 1},
                        tx=wire_ack(1, 1, 0xA1A1A1A1A1A1A1A1, 0),
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_HRECV,
                    gen=0,
                    cookie=0,
                    burns=2,
                    have_rx=1,
                    last_rx=0,
                    counters={"hello_baseline_resync": 1},
                )
            ],
        )
    )

    # Negative inject suite after HS
    def after_hs_inject(
        sid: str,
        family: int,
        inject_act: dict,
        step_exp: dict,
        final: dict,
        *,
        peers=None,
        prefix=None,
    ) -> dict:
        acts = (prefix or hs_actions()) + [mark("cell" if "cell" in str(peers or dual()) else "ctrl"), inject_act, step("cell" if inject_act["peer"] == "cell" else inject_act["peer"], 1055, step_exp)]
        # fix mark peer
        p = inject_act["peer"]
        acts = (prefix or hs_actions()) + [mark(p), inject_act, step(p, 1055, step_exp)]
        return scenario(sid, family, peers or dual(), acts, [final])

    # RX reserved UINT32_MAX + Cell TX sequence terminal exhaustion
    # (next_tx_seq==UINT32_MAX → both-direction cold, non-OK, no silent wrap).
    out.append(
        scenario(
            "U4-N-SEQ-U32-MAX",
            9,
            dual(),
            hs_actions()
            + [
                mark("cell"),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="abs",
                    seq=TX_SEQ_TERMINAL,
                    payload_hex="",
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=0,
                        notice_p=1,
                        counter_deltas={"ncg1_reject_seq_reserved": 1},
                        tx_len=0,
                    ),
                ),
                # Boundary: assign last legal TX sequence (UINT32_MAX-1).
                force_next_tx_seq(
                    "cell",
                    TX_SEQ_LEGAL_MAX,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=TX_SEQ_LEGAL_MAX,
                        have_rx=0,
                        notice_p=1,
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1060,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=TX_SEQ_TERMINAL,
                        have_rx=0,
                        notice_p=0,
                        commit=TX_RAW,
                        kind=KIND_RESET,
                        counter_deltas={
                            "ncg1_reject_seq_reserved": 1,
                            "continuity_notice_accepted": 1,
                            "tx_actions_submitted": 1,
                            "raw_accepts": 1,
                        },
                        tx=wire_reset(1, 1, COOKIE, TX_SEQ_LEGAL_MAX),
                    ),
                ),
                # next_tx_seq==UINT32_MAX: terminal exhaust — both cold, non-OK.
                step(
                    "cell",
                    1065,
                    E(
                        status=STATUS_CONTINUITY_LOST,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=0,
                        have_rx=0,
                        notice_p=0,
                        tx_len=0,
                    ),
                ),
                # No silent seq0 DATA continuation (idle Cell after exhaust).
                step(
                    "cell",
                    1070,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=0,
                        have_rx=0,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    next_tx=0,
                    have_rx=0,
                    counters={"ncg1_reject_seq_reserved": 1},
                )
            ],
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-SEQ-DUP",
            9,
            inject(
                "cell",
                TYPE_DATA,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx",
                payload_hex="",
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncg1_reject_seq_dup": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncg1_reject_seq_dup": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-STREAM-ID",
            9,
            inject(
                "cell",
                TYPE_DATA,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                stream_id=1,
                payload_hex="",
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncg1_reject_stream_id": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncg1_reject_stream_id": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-EMPTY-PING",
            1,
            inject(
                "cell",
                TYPE_PING,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                payload_hex="",
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncl1_reject_body_len": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_body_len": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-COOKIE-ZERO",
            1,
            inject(
                "cell",
                TYPE_PING,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_PING,
                request_id=7,
                gen_mode="active",
                cookie_mode="zero",
                body_hex=hx(ping_body(1)),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncl1_reject_session_mismatch": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_session_mismatch": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-SESS-ZERO",
            1,
            inject(
                "cell",
                TYPE_PING,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_PING,
                request_id=8,
                gen_mode="zero",
                cookie_mode="active",
                body_hex=hx(ping_body(2)),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncl1_reject_session_mismatch": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_session_mismatch": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-STALE-GEN",
            1,
            inject(
                "cell",
                TYPE_PING,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_PING,
                request_id=11,
                gen_mode="active_plus",
                generation=1,
                cookie_mode="active",
                body_hex=hx(ping_body(3)),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncl1_reject_session_mismatch": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_session_mismatch": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-STALE-COOKIE",
            1,
            inject(
                "cell",
                TYPE_PING,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_PING,
                request_id=12,
                gen_mode="active",
                cookie_mode="active_xor",
                cookie=1,
                body_hex=hx(ping_body(4)),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"ncl1_reject_session_mismatch": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_session_mismatch": 1},
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-HELLO-INVALID-ROLE",
            1,
            inject(
                "ctrl",
                TYPE_DATA,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_HELLO,
                request_id=9,
                body_hex=hx(hello_body()),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counter_deltas={"hello_invalid_role": 1},
                commit=TX_RAW,
                kind=KIND_PING,
                next_tx=2,
                tx=wire_ping(2, 1, COOKIE, 1, 1055),
            ),
            fin(
                "ctrl",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"hello_invalid_role": 1},
                commit=TX_RAW,
            ),
        )
    )

    out.append(
        after_hs_inject(
            "U4-N-SEQ-GAP",
            9,
            inject(
                "cell",
                TYPE_DATA,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=5,
                payload_hex="",
            ),
            E(
                status=STATUS_OK,
                state=ST_LINK,
                gen=0,
                cookie=0,
                have_rx=0,
                notice_p=1,
                counter_deltas={"ncg1_reject_seq_gap": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_LINK,
                gen=0,
                cookie=0,
                have_rx=0,
                notice_p=1,
                counters={"ncg1_reject_seq_gap": 1},
            ),
            prefix=hs_actions()
            + [
                A(
                    "set_write_would_block",
                    peer="cell",
                    enable=1,
                    expect=E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                )
            ],
        )
    )

    # HELLO bad bootstrap (cell only)
    out.append(
        scenario(
            "U4-N-HELLO-BAD-BOOTSTRAP",
            1,
            [peer("cell", ROLE_CELL)],
            [
                mark("cell"),
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, tx_len=0),
                    seq_mode="abs",
                    seq=0,
                    msg_type=MSG_HELLO,
                    request_id=3,
                    generation=1,
                    body_hex=hx(hello_body()),
                ),
                step(
                    "cell",
                    100,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        counter_deltas={"hello_invalid_bootstrap": 1},
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    counters={"hello_invalid_bootstrap": 1},
                )
            ],
        )
    )

    # BASELINE nonhello
    out.append(
        scenario(
            "U4-N-BASELINE-NONHELLO",
            9,
            [peer("ctrl", ROLE_CTRL)],
            [
                mark("ctrl"),
                inject(
                    "ctrl",
                    TYPE_PING,
                    E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, have_rx=0, tx_len=0),
                    seq_mode="abs",
                    seq=5,
                    payload_hex="",
                ),
                step(
                    "ctrl",
                    1005,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=0,
                        cookie=0,
                        have_rx=0,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        counter_deltas={"ncg1_reject_baseline": 1},
                        tx=wire_hello(1, 0),
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    have_rx=0,
                    next_tx=1,
                    commit=TX_RAW,
                    counters={"ncg1_reject_baseline": 1},
                )
            ],
        )
    )

    # ACK baseline nonmatch
    out.append(
        scenario(
            "U4-N-ACK-BASELINE-NONMATCH",
            9,
            [peer("ctrl", ROLE_CTRL)],
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        have_rx=0,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        hello_nz=1,
                        tx=wire_hello(1, 0),
                    ),
                ),
                mark("ctrl"),
                inject(
                    "ctrl",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_HSENT, have_rx=0, tx_len=0),
                    seq_mode="abs",
                    seq=9,
                    msg_type=MSG_HELLO_ACK,
                    req_mode="sole_hello_xor",
                    generation=1,
                    cookie=0x99,
                    body_hex=hx(hello_ack_body(0)),
                ),
                step(
                    "ctrl",
                    1005,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        have_rx=0,
                        counter_deltas={
                            "ncg1_reject_baseline": 1,
                            "hello_ack_baseline_resync": 0,
                        },
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    have_rx=0,
                    counters={
                        "ncg1_reject_baseline": 1,
                        "hello_ack_baseline_resync": 0,
                    },
                )
            ],
        )
    )

    # HELLO_OK cookie zero
    out.append(
        scenario(
            "U4-N-HELLO-OK-COOKIE-ZERO",
            1,
            [peer("ctrl", ROLE_CTRL)],
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        hello_nz=1,
                        tx=wire_hello(1, 0),
                    ),
                ),
                mark("ctrl"),
                inject(
                    "ctrl",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_HSENT, cookie=0, tx_len=0),
                    seq_mode="abs",
                    seq=0,
                    msg_type=MSG_HELLO_ACK,
                    req_mode="sole_hello",
                    generation=1,
                    cookie_mode="zero",
                    body_hex=hx(hello_ack_body(0)),
                ),
                step(
                    "ctrl",
                    1005,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        gen=0,
                        cookie=0,
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "ctrl",
                    state=ST_HSENT,
                    gen=0,
                    cookie=0,
                    next_tx=1,
                    commit=TX_RAW,
                    kind=KIND_HELLO,
                    counters={"raw_accepts": 1},
                )
            ],
        )
    )

    # COOKIE RNG fail: error HELLO_ACK (BUSY) held pending until correlated
    # delivery (dest==HELLO origin, source==responder). Then unestablished
    # CTRL_ERROR TX with exact 0/0 (not ever-active nonzero).
    out.append(
        scenario(
            "U4-N-COOKIE-RNG-FAIL",
            10,
            dual(cell_rng_fail=1),
            [
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        gen=0,
                        cookie=0,
                        have_rx=1,
                        last_rx=0,
                        burns=0,
                        counters={"hello_baseline_resync": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=1,
                        last_rx=0,
                        counters={"hello_baseline_resync": 1, "raw_accepts": 1},
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        tx=wire_ack(1, 0, 0, 0, result=2),  # BUSY
                    ),
                ),
                # Error ACK delivery: dest=ctrl (HELLO origin), source=cell.
                forward(
                    "cell",
                    "ctrl",
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        tx=wire_ack(1, 0, 0, 0, result=2),
                    ),
                ),
                step(
                    "ctrl",
                    1000,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        have_rx=1,
                        last_rx=0,
                        counters={"hello_ack_baseline_resync": 1},
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx_len=0,
                    ),
                ),
                # Unestablished (non-ACTIVE) CTRL_ERROR TX: exact 0/0 (§7.4).
                mark("cell"),
                inject(
                    "cell",
                    TYPE_PING,
                    E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=1,
                    msg_type=MSG_HELLO,
                    request_id=9,
                    generation=0,
                    cookie=0,
                    body_hex=hx(hello_body()),
                ),
                step(
                    "cell",
                    1010,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        counter_deltas={
                            "logical_rejects": 1,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 0,
                        },
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1020,
                    E(
                        status=STATUS_OK,
                        state=ST_LINK,
                        gen=0,
                        cookie=0,
                        next_tx=2,
                        commit=TX_RAW,
                        kind=KIND_CTRL_ERROR,
                        counter_deltas={
                            "logical_rejects": 1,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 1,
                            "raw_accepts": 1,
                        },
                        tx=wire_ctrl_error(0, 0, 0, 1, ERR_TYPE_BINDING, related=0),
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_LINK,
                    gen=0,
                    cookie=0,
                    have_rx=1,
                    counters={
                        "hello_baseline_resync": 1,
                        "logical_rejects": 1,
                        "ncl1_reject_type_binding": 1,
                        "raw_accepts": 2,
                        "tx_actions_submitted": 2,
                    },
                    commit=TX_RAW,
                    kind=KIND_CTRL_ERROR,
                )
            ],
        )
    )

    # CTRL_ERROR: no response-to-CTRL_ERROR loop; type-binding while ACTIVE emits
    # CTRL_ERROR with exact active gen/cookie (related_req=0).
    out.append(
        scenario(
            "U4-N-CTRL-ERROR-LOOP",
            10,
            dual(),
            hs_actions()
            + [
                mark("cell"),
                # CTRL_ERROR RX must not be answered with CTRL_ERROR.
                inject(
                    "cell",
                    TYPE_DATA,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=1,
                    msg_type=MSG_CTRL_ERROR,
                    gen_mode="active",
                    cookie_mode="active",
                    body_hex=hx(ctrl_error_body(3)),
                ),
                step(
                    "cell",
                    1055,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        counter_deltas={"logical_rejects": 1, "tx_actions_submitted": 0},
                        kind=KIND_ACK,
                        commit=TX_RAW,
                        tx_len=0,
                    ),
                ),
                # Type-binding reject (HELLO inside NCG1 PING) → enqueue CTRL_ERROR.
                inject(
                    "cell",
                    TYPE_PING,
                    E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=1,
                    msg_type=MSG_HELLO,
                    request_id=9,
                    generation=0,
                    cookie=0,
                    body_hex=hx(hello_body()),
                ),
                step(
                    "cell",
                    1060,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        counter_deltas={
                            "logical_rejects": 2,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 0,
                        },
                        kind=KIND_ACK,
                        commit=TX_RAW,
                        tx_len=0,
                    ),
                ),
                # Next step submits enqueued CTRL_ERROR (active pair exact).
                step(
                    "cell",
                    1065,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=1,
                        cookie=COOKIE,
                        next_tx=2,
                        commit=TX_RAW,
                        kind=KIND_CTRL_ERROR,
                        counter_deltas={
                            "logical_rejects": 2,
                            "ncl1_reject_type_binding": 1,
                            "tx_actions_submitted": 1,
                            "raw_accepts": 1,
                        },
                        tx=wire_ctrl_error(
                            0, 1, COOKIE, 1, ERR_TYPE_BINDING, related=0
                        ),
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=1,
                    cookie=COOKIE,
                    counters={
                        "logical_rejects": 2,
                        "ncl1_reject_type_binding": 1,
                        "raw_accepts": 2,
                        "tx_actions_submitted": 2,
                    },
                )
            ],
        )
    )

    # Stale RESET seq advance
    out.append(
        after_hs_inject(
            "U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE",
            8,
            inject(
                "cell",
                TYPE_RESET,
                E(status=STATUS_OK, state=ST_ACT, gen=1, cookie=COOKIE, tx_len=0),
                seq_mode="last_rx_plus",
                seq=1,
                msg_type=MSG_RESET,
                request_id=11,
                gen_mode="active_xor",
                generation=1,
                cookie_mode="active",
                body_hex=hx(reset_body()),
            ),
            E(
                status=STATUS_OK,
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                have_rx=1,
                counter_deltas={"ncl1_reject_session_mismatch": 1},
                tx_len=0,
            ),
            fin(
                "cell",
                state=ST_ACT,
                gen=1,
                cookie=COOKIE,
                counters={"ncl1_reject_session_mismatch": 1},
            ),
        )
    )

    # Stale RESET after rehello new session
    out.append(
        scenario(
            "U4-N-CONTINUITY-RESET-STALE-NEW-SESSION",
            8,
            dual(),
            hs_actions()
            + [
                mark("cell"),
                A(
                    "init_peer",
                    peer="ctrl2",
                    role=ROLE_CTRL,
                    expect=E(status=STATUS_OK, state=ST_LINK, gen=0, cookie=0, next_tx=0, tx_len=0),
                ),
                step(
                    "ctrl2",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HSENT,
                        next_tx=1,
                        commit=TX_RAW,
                        kind=KIND_HELLO,
                        tx=wire_hello(1, 0),
                    ),
                ),
                forward(
                    "ctrl2",
                    "cell",
                    E(status=STATUS_OK, state=ST_HSENT, tx=wire_hello(1, 0)),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_HRECV,
                        gen=0,
                        cookie=0,
                        counter_deltas={"hello_halfopen_fence": 1},
                        tx_len=0,
                    ),
                ),
                step(
                    "cell",
                    1100,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        commit=TX_RAW,
                        kind=KIND_ACK,
                        counters={"hello_halfopen_fence": 1},
                        # Explicit ACK oracle: echo peer HELLO request_id=1.
                        tx=wire_ack(1, 2, COOKIE, 1),
                    ),
                ),
                mark("cell"),
                inject(
                    "cell",
                    TYPE_RESET,
                    E(status=STATUS_OK, state=ST_ACT, gen=2, cookie=COOKIE, tx_len=0),
                    seq_mode="last_rx_plus",
                    seq=1,
                    msg_type=MSG_RESET,
                    request_id=9,
                    generation=1,
                    cookie=COOKIE,
                    body_hex=hx(reset_body()),
                ),
                step(
                    "cell",
                    1125,
                    E(
                        status=STATUS_OK,
                        state=ST_ACT,
                        gen=2,
                        cookie=COOKIE,
                        counter_deltas={"ncl1_reject_session_mismatch": 1},
                        tx_len=0,
                    ),
                ),
            ],
            [
                fin(
                    "cell",
                    state=ST_ACT,
                    gen=2,
                    cookie=COOKIE,
                    counters={"ncl1_reject_session_mismatch": 1, "hello_halfopen_fence": 1},
                )
            ],
        )
    )

    # Validate coverage
    ids = [s["id"] for s in out]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"duplicate scenario ids: {[i for i in ids if ids.count(i)>1]}")
    # Fix any expect with empty counter_deltas and None counters that fail require_rich
    for s in out:
        for a in s["actions"]:
            e = a.get("expect")
            if not e:
                continue
            if e.get("counters") is None:
                e.pop("counters", None)
            if e.get("counter_deltas") is None:
                e.pop("counter_deltas", None)
            if e.get("counter_deltas") == {}:
                e.pop("counter_deltas", None)
            # ensure still rich
            require_rich_expect(e, s["id"])
        for e in s["expect_final"]:
            if e.get("counters") is None:
                e.pop("counters", None)
            if e.get("counter_deltas") is None:
                e.pop("counter_deltas", None)
            require_rich_expect(e, s["id"] + " final")

    return out



def finalize_tx_hex(scenarios: list[dict]) -> None:
    """Require explicit tx descriptors + rebuild-identical hex for every TX."""
    missing = []
    for s in scenarios:
        try:
            validate_scenario_tx_causal(s)
        except Exception as ex:  # noqa: BLE001 — surface oracle failures
            missing.append(f"{s['id']} causal: {ex}")
        for i, a in enumerate(s["actions"]):
            e = a.get("expect") or {}
            tlen = int(e.get("tx_len") or 0)
            if tlen <= 0:
                if "tx" in e or "tx_hex" in e:
                    missing.append(f"{s['id']}[{i}] empty TX has tx/tx_hex")
                continue
            if "tx" not in e:
                missing.append(f"{s['id']}[{i}] missing tx descriptor")
                continue
            try:
                validate_tx_desc(e["tx"], where=f"{s['id']}[{i}]")
                rebuilt = encode_tx_desc(e["tx"])
            except Exception as ex:  # noqa: BLE001 — surface oracle failures
                missing.append(f"{s['id']}[{i}] encode fail: {ex}")
                continue
            if e.get("tx_hex") != rebuilt:
                missing.append(f"{s['id']}[{i}] tx_hex not rebuild-identical")
            if len(rebuilt) != tlen * 2:
                missing.append(f"{s['id']}[{i}] len mismatch")
    if missing:
        raise RuntimeError(
            "TX oracle incomplete (" + str(len(missing)) + "):\n  "
            + "\n  ".join(missing[:80])
        )


def multi_fault_pins() -> list[dict]:
    return [
        {"id": "U4-MF-STALE-GEN-COOKIE-RESERVED-RESET", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-BAD-REQ-RESERVED-HELLO", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-UNKNOWN-TYPE-BINDING", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-U32MAX-VALID-HELLO", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-STREAM-VALID-HELLO", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-GAP-VALID-HELLO", "kind": "multi_fault_precedence"},
        {"id": "U4-MF-NONMATCH-ACK-HIGH-SEQ", "kind": "multi_fault_precedence"},
    ]


def build_document() -> dict:
    ncl1 = load_ncl1_required()
    eng = engine_required_ids(ncl1)
    scenarios = build_engine_scenarios()
    finalize_tx_hex(scenarios)
    by = {s["id"]: s for s in scenarios}
    missing = [i for i in eng if i not in by]
    extra = [i for i in by if i not in eng]
    if missing or extra:
        raise RuntimeError(f"map mismatch missing={missing} extra={extra}")
    vectors = [by[i] for i in sorted(eng)]
    for s in vectors:
        if "assertion_key" in s:
            raise RuntimeError("assertion_key must not appear")
        for a in s["actions"]:
            if a["op"] in ("handshake_active", "step_pair", "quiet_drain", "quiet_drain_tx"):
                raise RuntimeError("macro ops forbidden in document")
    mf = multi_fault_pins()
    return {
        "format": FORMAT,
        "vector_count": len(vectors) + len(mf),
        "engine_required_id_count": 38,
        "engine_required_ids": sorted(eng),
        "pure_codec_only_ids": sorted(PURE_CODEC_ONLY_IDS),
        "ncl1_required_id_count": 46,
        "families": FAMILIES,
        "counter_fields": COUNTER_FIELDS,
        "notes": (
            "U4 machine-executable scenarios. Each action pins exact status, "
            "snapshot fields, counter deltas, and TX wire summary. No catalog "
            "keys; no state inequality; no macro loops. Generator does not "
            "import production C."
        ),
        "vectors": vectors + mf,
    }


def canonical_json(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


def write_vector(path: pathlib.Path) -> None:
    path.write_text(canonical_json(build_document()), encoding="utf-8")


def check(path: pathlib.Path) -> None:
    disk = path.read_text(encoding="utf-8")
    rebuilt = canonical_json(build_document())
    if disk != rebuilt:
        raise SystemExit("logical-session-u4-v1.json not rebuild-identical")
    doc = json.loads(disk)
    eng = set(engine_required_ids(load_ncl1_required()))
    behaviors = [v for v in doc["vectors"] if v.get("kind") == "engine_behavior"]
    if len(behaviors) != 38:
        raise SystemExit("need 38 engine behaviors")
    if set(doc["engine_required_ids"]) != eng:
        raise SystemExit("engine_required_ids drift")
    if any("assertion_key" in v for v in behaviors):
        raise SystemExit("assertion_key must be removed")
    for v in behaviors:
        blob = json.dumps(v)
        if "state_ne" in blob:
            raise SystemExit("state_ne forbidden")
        for op in ("handshake_active", "step_pair", "quiet_drain"):
            if f'"{op}"' in blob:
                raise SystemExit(f"macro {op} forbidden")
    action_expects = 0
    for v in behaviors:
        if not v.get("actions") or not v.get("expect_final"):
            raise SystemExit(f"{v['id']}: incomplete scenario")
        for e in v["expect_final"]:
            require_rich_expect(e, v["id"])
            if set(e.keys()) - {"peer"} <= {"state"}:
                raise SystemExit(f"{v['id']}: state-only final")
        for a in v["actions"]:
            if a["op"] in ("step", "inject", "drop_tx", "forward", "cell_continuity_loss"):
                if "expect" not in a:
                    raise SystemExit(f"{v['id']}: action missing expect")
                require_rich_expect(a["expect"], v["id"])
                action_expects += 1
    if action_expects < 38:
        raise SystemExit("too few action-level expects")
    print(
        "logical_session_u4_vector_gen check OK",
        len(behaviors),
        "scenarios action_expects=",
        action_expects,
    )


# ---- C fixture ----
MODE_MAP = {
    "fixed": 0,
    "abs": 0,
    "active": 1,
    "active_plus": 2,
    "active_xor": 3,
    "zero": 4,
    "last_rx": 5,
    "last_rx_plus": 6,
    "sole_hello": 7,
    "sole_hello_xor": 8,
}


def emit_c_fixture(json_path: pathlib.Path, out_path: pathlib.Path) -> None:
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    eng = doc["engine_required_ids"]
    pure = doc["pure_codec_only_ids"]
    behaviors = [v for v in doc["vectors"] if v.get("kind") == "engine_behavior"]
    cfields = doc["counter_fields"]
    # Hard-fail incomplete / non-rebuildable / non-semantic TX oracles at emit.
    for v in behaviors:
        validate_scenario_tx_causal(v)
        for i, a in enumerate(v.get("actions") or []):
            e = a.get("expect") or {}
            tlen = int(e.get("tx_len") or 0)
            if tlen <= 0:
                if "tx" in e or "tx_hex" in e:
                    raise RuntimeError(
                        f"emit {v.get('id')}[{i}]: empty TX must not carry tx/tx_hex"
                    )
                continue
            if "tx" not in e:
                raise RuntimeError(
                    f"emit {v.get('id')}[{i}]: non-empty TX requires tx descriptor"
                )
            rebuilt = encode_tx_desc(e["tx"])
            if e.get("tx_hex") != rebuilt:
                raise RuntimeError(
                    f"emit {v.get('id')}[{i}]: tx_hex not rebuild-identical "
                    "from explicit descriptor (synthesis forbidden)"
                )
            if len(rebuilt) != tlen * 2:
                raise RuntimeError(f"emit {v.get('id')}[{i}]: tx_len mismatch")
    blobs: list[bytes] = []
    bindex: dict[str, int] = {}

    def bid(b: bytes) -> int:
        k = b.hex()
        if k not in bindex:
            bindex[k] = len(blobs)
            blobs.append(b)
        return bindex[k]

    lines = [
        "/* Generated by tools/logical_session_u4_vector_gen.py — do not edit. */",
        "#ifndef NINLIL_LOGICAL_SESSION_U4_VECTOR_FIXTURE_H",
        "#define NINLIL_LOGICAL_SESSION_U4_VECTOR_FIXTURE_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
        f"#define NINLIL_LS_U4_ENGINE_REQUIRED_ID_COUNT ({len(eng)}u)",
        f"#define NINLIL_LS_U4_PURE_CODEC_ONLY_COUNT ({len(pure)}u)",
        f"#define NINLIL_LS_U4_BEHAVIOR_COUNT ({len(behaviors)}u)",
        f"#define NINLIL_LS_U4_COUNTER_FIELD_COUNT ({len(cfields)}u)",
        "#define NINLIL_LS_U4_PEER_MAX 4u",
        "#define NINLIL_LS_U4_COUNTER_DELTA_MAX 8u",
        "#define NINLIL_LS_U4_OP_STEP 2u",
        "#define NINLIL_LS_U4_OP_FORWARD 3u",
        "#define NINLIL_LS_U4_OP_DROP_TX 4u",
        "#define NINLIL_LS_U4_OP_INJECT 6u",
        "#define NINLIL_LS_U4_OP_MARK_BASELINE 7u",
        "#define NINLIL_LS_U4_OP_FORCE_STATE 8u",
        "#define NINLIL_LS_U4_OP_FORCE_RX 9u",
        "#define NINLIL_LS_U4_OP_FORCE_TX_SEQ 10u",
        "#define NINLIL_LS_U4_OP_FORCE_PING 11u",
        "#define NINLIL_LS_U4_OP_REQUEST_HELLO 12u",
        "#define NINLIL_LS_U4_OP_CELL_LOSS 13u",
        "#define NINLIL_LS_U4_OP_WRITE_BLOCK 14u",
        "#define NINLIL_LS_U4_OP_INIT_PEER 15u",
        "#define NINLIL_LS_U4_OP_SET_RNG_FAIL 16u",
        "#define NINLIL_LS_U4_MODE_FIXED 0u",
        "#define NINLIL_LS_U4_MODE_ACTIVE 1u",
        "#define NINLIL_LS_U4_MODE_ACTIVE_PLUS 2u",
        "#define NINLIL_LS_U4_MODE_ACTIVE_XOR 3u",
        "#define NINLIL_LS_U4_MODE_ZERO 4u",
        "#define NINLIL_LS_U4_MODE_LAST_RX 5u",
        "#define NINLIL_LS_U4_MODE_LAST_RX_PLUS 6u",
        "#define NINLIL_LS_U4_MODE_SOLE_HELLO 7u",
        "#define NINLIL_LS_U4_MODE_SOLE_HELLO_XOR 8u",
        "#define NINLIL_LS_U4_EF_STATUS (1u<<0)",
        "#define NINLIL_LS_U4_EF_STATE (1u<<1)",
        "#define NINLIL_LS_U4_EF_GEN (1u<<2)",
        "#define NINLIL_LS_U4_EF_COOKIE (1u<<3)",
        "#define NINLIL_LS_U4_EF_NEXT_TX (1u<<4)",
        "#define NINLIL_LS_U4_EF_HAVE_RX (1u<<5)",
        "#define NINLIL_LS_U4_EF_LAST_RX (1u<<6)",
        "#define NINLIL_LS_U4_EF_COMMIT (1u<<7)",
        "#define NINLIL_LS_U4_EF_KIND (1u<<8)",
        "#define NINLIL_LS_U4_EF_BURNS (1u<<9)",
        "#define NINLIL_LS_U4_EF_NOTICE_P (1u<<10)",
        "#define NINLIL_LS_U4_EF_NOTICE_A (1u<<11)",
        "#define NINLIL_LS_U4_EF_PING_Z (1u<<12)",
        "#define NINLIL_LS_U4_EF_HELLO_NZ (1u<<13)",
        "#define NINLIL_LS_U4_EF_TX_LEN (1u<<14)",
        "#define NINLIL_LS_U4_EF_TX_TYPE (1u<<15)",
        "#define NINLIL_LS_U4_EF_TX_SEQ (1u<<16)",
        "#define NINLIL_LS_U4_EF_TX_HEX (1u<<17)",
        "static const char *const NINLIL_LS_U4_ENGINE_REQUIRED_IDS[] = {",
    ]
    for i in eng:
        lines.append(f' "{i}",')
    lines += ["};", "static const char *const NINLIL_LS_U4_PURE_CODEC_ONLY_IDS[] = {"]
    for i in pure:
        lines.append(f' "{i}",')
    lines += ["};", "static const char *const NINLIL_LS_U4_COUNTER_FIELDS[] = {"]
    for f in cfields:
        lines.append(f' "{f}",')
    lines.append("};")

    # First pass: register all inject bodies and exact TX wire blobs.
    meta = []
    for v in behaviors:
        m = []
        for a in v["actions"]:
            mm: dict = {"tx_bi": -1, "tx_len": 0}
            if a["op"] == "inject":
                if "ncl1" in a:
                    body = bytes.fromhex(a["ncl1"].get("body_hex") or "")
                    mm["body_bi"] = bid(body) if body else -1
                    mm["body_len"] = len(body)
                else:
                    pb = bytes.fromhex(a.get("payload_hex") or "")
                    mm["payload_bi"] = bid(pb) if pb else -1
                    mm["payload_len"] = len(pb)
            exp = a.get("expect") or {}
            if exp.get("tx_hex"):
                tb = bytes.fromhex(exp["tx_hex"])
                mm["tx_bi"] = bid(tb)
                mm["tx_len"] = len(tb)
            m.append(mm)
        for e in v.get("expect_final") or []:
            if e.get("tx_hex"):
                bid(bytes.fromhex(e["tx_hex"]))
        meta.append(m)

    lines.append(f"#define NINLIL_LS_U4_BLOB_COUNT ({len(blobs)}u)")
    if blobs:
        for i, b in enumerate(blobs):
            lines.append(f"static const uint8_t ninlil_ls_u4_blob_{i}[] = {{")
            lines.append(",".join(f"0x{x:02x}u" for x in b))
            lines.append("};")
        lines.append("static const uint8_t *const ninlil_ls_u4_blobs[] = {")
        for i in range(len(blobs)):
            lines.append(f" ninlil_ls_u4_blob_{i},")
        lines.append("};")
        lines.append("static const size_t ninlil_ls_u4_blob_lens[] = {")
        for b in blobs:
            lines.append(f" {len(b)}u,")
        lines.append("};")
    else:
        lines.append("static const uint8_t *const ninlil_ls_u4_blobs[] = {0};")
        lines.append("static const size_t ninlil_ls_u4_blob_lens[] = {0};")

    lines += [
        "typedef struct ninlil_ls_u4_counter_delta { uint16_t field_index; int32_t delta; uint8_t is_abs; } ninlil_ls_u4_counter_delta_t;",
        "typedef struct ninlil_ls_u4_expect {",
        " uint32_t mask; uint32_t status; uint32_t state; uint32_t active_generation; uint64_t active_cookie;",
        " uint32_t next_tx_seq; int have_rx_seq; uint32_t last_rx_seq; uint32_t last_tx_commit; uint32_t last_tx_kind;",
        " uint32_t burned_generation_count; int continuity_notice_pending; int continuity_notice_raw_accepted;",
        " int sole_ping_request_id_zero; int sole_hello_request_id_nonzero;",
        " uint32_t tx_len; uint32_t tx_ncg1_type; uint32_t tx_sequence;",
        " int32_t tx_blob; /* full exact wire bytes index, or -1 */",
        " uint8_t n_counter; ninlil_ls_u4_counter_delta_t counters[NINLIL_LS_U4_COUNTER_DELTA_MAX];",
        " uint8_t peer;",
        "} ninlil_ls_u4_expect_t;",
        "typedef struct ninlil_ls_u4_action {",
        " uint8_t op; uint8_t peer; uint8_t peer_b; uint8_t ncg1_type; uint8_t seq_mode; uint8_t gen_mode;",
        " uint8_t cookie_mode; uint8_t req_mode; uint8_t has_ncl1; uint8_t ncl1_msg_type;",
        " uint32_t seq; uint32_t stream_id; uint32_t request_id; uint32_t generation;",
        " uint32_t u32_a; uint32_t u32_b; uint64_t now_ms; uint32_t now_delta_ms;",
        " uint64_t cookie; int32_t body_blob; uint32_t body_len; int32_t payload_blob; uint32_t payload_len;",
        " ninlil_ls_u4_expect_t expect; uint8_t has_expect;",
        "} ninlil_ls_u4_action_t;",
        "typedef struct ninlil_ls_u4_peer_pre { uint8_t used; uint8_t role; uint8_t rng_fail; uint8_t n_cookies; uint64_t cookies[8]; } ninlil_ls_u4_peer_pre_t;",
        "typedef struct ninlil_ls_u4_scenario {",
        " const char *id; int family; const char *family_name;",
        " ninlil_ls_u4_peer_pre_t peers[NINLIL_LS_U4_PEER_MAX];",
        " const ninlil_ls_u4_action_t *actions; uint32_t action_count;",
        " const ninlil_ls_u4_expect_t *expects; uint32_t expect_count;",
        "} ninlil_ls_u4_scenario_t;",
    ]

    def pack_expect(e: dict, peer_name: str | None = None) -> str:
        mask = 0
        status = int(e.get("status") or 0)
        state = int(e.get("state") or 0)
        gen = int(e.get("active_generation") or 0)
        cookie = int(e.get("active_cookie") or 0)
        next_tx = int(e.get("next_tx_seq") or 0)
        have = int(e.get("have_rx_seq") or 0)
        last_rx = int(e.get("last_rx_seq") or 0)
        commit = int(e.get("last_tx_commit") or 0)
        kind = int(e.get("last_tx_kind") or 0)
        burns = int(e.get("burned_generation_count") or 0)
        np = int(e.get("continuity_notice_pending") or 0)
        na = int(e.get("continuity_notice_raw_accepted") or 0)
        pz = int(e.get("sole_ping_request_id_zero") or 0)
        hz = int(e.get("sole_hello_request_id_nonzero") or 0)
        tl = int(e.get("tx_len") or 0)
        tt = int(e.get("tx_ncg1_type") or 0)
        ts = int(e.get("tx_sequence") or 0)
        tx_bi = -1
        if e.get("tx_hex"):
            tb = bytes.fromhex(e["tx_hex"])
            tx_bi = bid(tb)
            tl = len(tb)
            if len(tb) >= 26:
                tt = tb[5]
                ts = struct.unpack(">I", tb[12:16])[0]
            mask |= 1 << 17  # EF_TX_HEX
            mask |= 1 << 14  # EF_TX_LEN
            mask |= 1 << 15
            mask |= 1 << 16
        bits = [
            ("status", 0),
            ("state", 1),
            ("active_generation", 2),
            ("active_cookie", 3),
            ("next_tx_seq", 4),
            ("have_rx_seq", 5),
            ("last_rx_seq", 6),
            ("last_tx_commit", 7),
            ("last_tx_kind", 8),
            ("burned_generation_count", 9),
            ("continuity_notice_pending", 10),
            ("continuity_notice_raw_accepted", 11),
            ("sole_ping_request_id_zero", 12),
            ("sole_hello_request_id_nonzero", 13),
            ("tx_len", 14),
            ("tx_ncg1_type", 15),
            ("tx_sequence", 16),
        ]
        for k, b in bits:
            if k in e:
                mask |= 1 << b
        citems = []
        for k, v in (e.get("counters") or {}).items():
            citems.append((cfields.index(k), int(v), 1))
        for k, v in (e.get("counter_deltas") or {}).items():
            citems.append((cfields.index(k), int(v), 0))
        if len(citems) > 8:
            raise RuntimeError("too many counters")
        carr = []
        for i in range(8):
            if i < len(citems):
                fi, dv, ab = citems[i]
                carr.append(f"{{{fi}u,{dv},{ab}u}}")
            else:
                carr.append("{0u,0,0u}")
        peer_i = PEER.get(peer_name or e.get("peer") or "ctrl", 0)
        return (
            f"{{{mask}u,{status}u,{state}u,{gen}u,{cookie}ull,{next_tx}u,{have},{last_rx}u,"
            f"{commit}u,{kind}u,{burns}u,{np},{na},{pz},{hz},{tl}u,{tt}u,{ts}u,{tx_bi},"
            f"{len(citems)}u,{{{','.join(carr)}}},{peer_i}u}}"
        )

    empty_exp = pack_expect({"state": 0, "gen": 0, "cookie": 0, "tx_len": 0})  # will set has_expect=0

    def pack_action(a: dict, m: dict) -> str:
        op = OP[a["op"]]
        peer = PEER.get(a.get("peer") or a.get("frm") or "ctrl", 0)
        peer_b = PEER.get(a.get("to") or "cell", 1)
        ncg1 = int(a.get("ncg1_type") or 0)
        seq_mode = MODE_MAP.get(a.get("seq_mode") or "fixed", 0)
        gen_mode = cookie_mode = req_mode = 0
        has_ncl1 = ncl1_msg = 0
        seq = int(a.get("seq") or 0)
        stream = int(a.get("stream_id") or 0)
        req = gen = 0
        cookie = 0
        u32a = u32b = 0
        now_ms = int(a.get("now_ms") or 0)
        now_d = int(a.get("now_delta_ms") or 0)
        body_bi = -1
        body_len = 0
        pay_bi = -1
        pay_len = 0
        if a["op"] == "force_state":
            u32a = int(a.get("state") or 0)
        elif a["op"] == "force_rx_baseline":
            u32a = int(a.get("have") or 0)
            u32b = int(a.get("last") or 0)
        elif a["op"] == "force_next_tx_seq":
            u32a = int(a.get("next_tx_seq") or 0)
        elif a["op"] == "force_ping_eligible":
            # eligible_at_ms packed in cookie u64 field.
            cookie = int(a.get("eligible_at_ms") or a.get("cookie") or 0)
        elif a["op"] == "set_write_would_block":
            u32a = int(a.get("enable") or 0)
        elif a["op"] == "init_peer":
            u32a = int(a.get("role") or 0)
            peer = PEER.get(a.get("peer") or "ctrl2", 2)
        elif a["op"] == "set_rng_fail":
            u32a = int(a.get("fail") or 0)
        elif a["op"] == "inject":
            if "ncl1" in a:
                n = a["ncl1"]
                has_ncl1 = 1
                ncl1_msg = int(n.get("msg_type") or 0)
                gen_mode = MODE_MAP.get(n.get("gen_mode") or "fixed", 0)
                cookie_mode = MODE_MAP.get(n.get("cookie_mode") or "fixed", 0)
                req_mode = MODE_MAP.get(n.get("req_mode") or "fixed", 0)
                req = int(n.get("request_id") or 0)
                gen = int(n.get("generation") or 0)
                cookie = int(n.get("cookie") or 0)
                body_bi = int(m.get("body_bi", -1))
                body_len = int(m.get("body_len", 0))
            else:
                pay_bi = int(m.get("payload_bi", -1))
                pay_len = int(m.get("payload_len", 0))
        has_e = 1 if "expect" in a else 0
        exp = pack_expect(a["expect"], a.get("peer") or a.get("frm")) if has_e else empty_exp
        # for force/init with expect
        if "expect" in a:
            has_e = 1
            exp = pack_expect(a["expect"], a.get("peer") or a.get("frm"))
        return (
            f"{{{op}u,{peer}u,{peer_b}u,{ncg1}u,{seq_mode}u,{gen_mode}u,{cookie_mode}u,{req_mode}u,"
            f"{has_ncl1}u,{ncl1_msg}u,{seq}u,{stream}u,{req}u,{gen}u,{u32a}u,{u32b}u,{now_ms}ull,{now_d}u,"
            f"{cookie}ull,{body_bi},{body_len}u,{pay_bi},{pay_len}u,{exp},{has_e}u}}"
        )

    for vi, v in enumerate(behaviors):
        lines.append(f"static const ninlil_ls_u4_action_t ninlil_ls_u4_actions_{vi}[] = {{")
        for ai, a in enumerate(v["actions"]):
            lines.append(f" {pack_action(a, meta[vi][ai])},")
        lines.append("};")
        lines.append(f"static const ninlil_ls_u4_expect_t ninlil_ls_u4_expects_{vi}[] = {{")
        for e in v["expect_final"]:
            lines.append(f" {pack_expect(e, e['peer'])},")
        lines.append("};")

    lines.append("static const ninlil_ls_u4_scenario_t ninlil_ls_u4_scenarios[] = {")
    for vi, v in enumerate(behaviors):
        peers = [{}, {}, {}, {}]
        for p in v["precondition"]["peers"]:
            peers[PEER[p["name"]]] = p
        ps = []
        for pi in range(4):
            p = peers[pi]
            if not p:
                ps.append("{0u,0u,0u,0u,{0}}")
            else:
                cookies = (p.get("cookie_seq") or [COOKIE])[:8]
                padded = cookies + [0] * (8 - len(cookies))
                cinit = ",".join(f"{int(c)}ull" for c in padded)
                ps.append(
                    f"{{1u,{int(p['role'])}u,{int(p.get('rng_fail') or 0)}u,{len(cookies)}u,{{{cinit}}}}}"
                )
        lines.append(
            f' {{"{v["id"]}",{int(v["family"])},"{v["family_name"]}",{{{",".join(ps)}}},'
            f"ninlil_ls_u4_actions_{vi},{len(v['actions'])}u,"
            f"ninlil_ls_u4_expects_{vi},{len(v['expect_final'])}u}},"
        )
    lines.append("};")
    lines.append("#endif")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        good = td / "g.json"
        write_vector(good)
        check(good)
        a, b = td / "a.h", td / "b.h"
        emit_c_fixture(good, a)
        emit_c_fixture(good, b)
        if a.read_bytes() != b.read_bytes():
            raise SystemExit("emit non-deterministic")
        if b"ninlil_ls_u4_scenarios" not in a.read_bytes():
            raise SystemExit("missing scenarios")
        # schema mutations must fail check (rebuild)
        for label, mut in [
            ("drop_action_expect", lambda d: d["vectors"][0]["actions"][0].pop("expect", None)),
            ("state_only", lambda d: d["vectors"][0]["expect_final"].__setitem__(0, {"peer": "ctrl", "state": 4})),
            ("macro", lambda d: d["vectors"][0]["actions"].__setitem__(0, {"op": "handshake_active"})),
        ]:
            bad = json.loads(good.read_text(encoding="utf-8"))
            try:
                mut(bad)
            except Exception:
                pass
            p = td / f"{label}.json"
            p.write_text(json.dumps(bad, indent=2) + "\n", encoding="utf-8")
            try:
                check(p)
            except SystemExit:
                continue
            raise SystemExit(f"self-test expected fail: {label}")

        # Direct causal mutations: prove CausalTracker rejects without rebuild check.
        clean = json.loads(good.read_text(encoding="utf-8"))

        def eng(doc: dict, sid: str) -> dict:
            return next(
                v
                for v in doc["vectors"]
                if v.get("id") == sid and v.get("kind") == "engine_behavior"
            )

        def expect_causal_fail(label: str, mutator) -> None:
            doc = json.loads(json.dumps(clean))  # deep copy
            mutator(doc)
            try:
                for v in doc["vectors"]:
                    if v.get("kind") != "engine_behavior":
                        continue
                    validate_scenario_tx_causal(v)
                    for i, a in enumerate(v.get("actions") or []):
                        e = a.get("expect") or {}
                        if int(e.get("tx_len") or 0) > 0 and "tx" in e:
                            validate_tx_desc(e["tx"], where=f"{v['id']}[{i}]")
            except Exception:
                return
            raise SystemExit(f"self-test causal expected fail: {label}")

        def mut_halfopen_wrong_dest(doc: dict) -> None:
            v = eng(doc, "U4-G-HALFOPEN-REHELLO")
            a = v["actions"][17]
            if a.get("op") != "forward" or a.get("to") != "ctrl2":
                raise SystemExit("halfopen action17 shape drift")
            a["to"] = "ctrl"

        def mut_ack_no_hello_delivery(doc: dict) -> None:
            v = eng(doc, "U4-G-HELLO-OK")
            for a in v["actions"]:
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "ctrl"
                    and a.get("to") == "cell"
                ):
                    e = a.get("expect") or {}
                    if e.get("tx") and e["tx"].get("message_type") == MSG_HELLO:
                        e.clear()
                        e.update({"status": 0, "state": ST_HSENT, "tx_len": 0})
                        return
            raise SystemExit("no HELLO forward to strip")

        def mut_wrong_responder_inject(doc: dict) -> None:
            v = eng(doc, "U4-G-HELLO-OK")
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == MSG_HELLO
                ):
                    v["actions"].insert(
                        i + 1,
                        {
                            "op": "inject",
                            "peer": "ctrl",
                            "frm": "ctrl2",
                            "ncg1_type": TYPE_DATA,
                            "ncl1": {
                                "msg_type": MSG_HELLO_ACK,
                                "request_id": 1,
                                "generation": 1,
                                "cookie": COOKIE,
                                "body_hex": "0001000000000000",
                            },
                            "expect": {"status": 0, "state": ST_HSENT, "tx_len": 0},
                        },
                    )
                    return
            raise SystemExit("no HELLO forward for inject mutation")

        def mut_stale_origin_inject(doc: dict) -> None:
            v = eng(doc, "U4-G-HELLO-OK")
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "ctrl"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == MSG_HELLO
                ):
                    v["actions"].insert(
                        i + 1,
                        {
                            "op": "inject",
                            "peer": "cell",
                            "frm": "ctrl2",
                            "ncg1_type": TYPE_DATA,
                            "ncl1": {
                                "msg_type": MSG_HELLO,
                                "request_id": 1,
                                "generation": 0,
                                "cookie": 0,
                                "body_hex": "0001000100000000",
                            },
                            "expect": {"status": 0, "state": ST_HRECV, "tx_len": 0},
                        },
                    )
                    v["actions"].insert(
                        i + 2,
                        {
                            "op": "inject",
                            "peer": "ctrl",
                            "frm": "cell",
                            "ncg1_type": TYPE_DATA,
                            "ncl1": {
                                "msg_type": MSG_HELLO_ACK,
                                "request_id": 1,
                                "generation": 1,
                                "cookie": COOKIE,
                                "body_hex": "0001000000000000",
                            },
                            "expect": {"status": 0, "state": ST_HSENT, "tx_len": 0},
                        },
                    )
                    return
            raise SystemExit("no HELLO forward for stale-origin mutation")

        def mut_error_ack_wrong_dest(doc: dict) -> None:
            """Error HELLO_ACK forward dest must equal HELLO origin."""
            v = eng(doc, "U4-N-COOKIE-RNG-FAIL")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "cell"
                    and a.get("to") == "ctrl"
                    and tx
                    and tx.get("message_type") == MSG_HELLO_ACK
                    and int(tx.get("hello_ack_result") or 0) != HELLO_OK
                ):
                    a["to"] = "cell"  # wrong destination
                    return
            raise SystemExit("no error ACK forward to retarget")

        def mut_error_ack_wrong_source_inject(doc: dict) -> None:
            """Inject error ACK with wrong responder source must fail."""
            v = eng(doc, "U4-N-COOKIE-RNG-FAIL")
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == MSG_HELLO
                ):
                    v["actions"].insert(
                        i + 1,
                        {
                            "op": "inject",
                            "peer": "ctrl",
                            "frm": "ctrl2",  # wrong responder
                            "ncg1_type": TYPE_DATA,
                            "ncl1": {
                                "msg_type": MSG_HELLO_ACK,
                                "request_id": 1,
                                "generation": 0,
                                "cookie": 0,
                                "body_hex": "0000000000020000",  # BUSY
                            },
                            "expect": {"status": 0, "state": ST_HSENT, "tx_len": 0},
                        },
                    )
                    return
            raise SystemExit("no HELLO forward for error-ACK wrong-source inject")

        def mut_ctrl_error_wrong_active_pair(doc: dict) -> None:
            """ACTIVE CTRL_ERROR must use exact current gen/cookie pair."""
            v = eng(doc, "U4-N-CTRL-ERROR-LOOP")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == MSG_CTRL_ERROR
                    and int(tx.get("generation") or 0) != 0
                ):
                    tx["generation"] = 99
                    tx["session_cookie"] = COOKIE
                    # Keep hex stale so rebuild/semantic either fails hard.
                    return
            raise SystemExit("no active CTRL_ERROR TX to corrupt")

        def mut_ctrl_error_nonzero_nonactive(doc: dict) -> None:
            """Non-ACTIVE CTRL_ERROR must be 0/0 (not ever-active / pre-fence)."""
            v = eng(doc, "U4-N-COOKIE-RNG-FAIL")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == MSG_CTRL_ERROR
                    and int(tx.get("generation") or 0) == 0
                ):
                    # Wrong: inject pre-fence-looking nonzero while non-ACTIVE.
                    tx["generation"] = 1
                    tx["session_cookie"] = COOKIE
                    return
            raise SystemExit("no non-active CTRL_ERROR TX to corrupt")

        def mut_ctrl_error_continuity_prefence_pair(doc: dict) -> None:
            """Post-continuity CTRL_ERROR must not reuse pre-fence pair (§7.4 0/0)."""
            v = eng(doc, "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == MSG_CTRL_ERROR
                ):
                    tx["generation"] = 1
                    tx["session_cookie"] = COOKIE
                    return
            raise SystemExit("no continuity CTRL_ERROR TX to corrupt")

        def mut_reset_wrong_pair(doc: dict) -> None:
            """RESET must match ACTIVE or pre-fence exact pair (not mere nonzero)."""
            v = eng(doc, "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == MSG_RESET
                ):
                    tx["generation"] = 9
                    tx["session_cookie"] = 0x1111111111111111
                    return
            raise SystemExit("no RESET TX to corrupt pair")

        expect_causal_fail("halfopen ACK wrong destination", mut_halfopen_wrong_dest)
        expect_causal_fail("ACK without HELLO delivery", mut_ack_no_hello_delivery)
        expect_causal_fail("inject ACK wrong responder", mut_wrong_responder_inject)
        expect_causal_fail("stale origin after HELLO replace", mut_stale_origin_inject)
        expect_causal_fail("error ACK wrong destination", mut_error_ack_wrong_dest)
        expect_causal_fail(
            "error ACK inject wrong responder", mut_error_ack_wrong_source_inject
        )
        expect_causal_fail(
            "CTRL_ERROR wrong active pair", mut_ctrl_error_wrong_active_pair
        )
        expect_causal_fail(
            "CTRL_ERROR nonzero non-active", mut_ctrl_error_nonzero_nonactive
        )
        expect_causal_fail(
            "CTRL_ERROR post-continuity pre-fence pair",
            mut_ctrl_error_continuity_prefence_pair,
        )
        expect_causal_fail("RESET wrong gen/cookie pair", mut_reset_wrong_pair)

        # Semantic field mutations via validate_tx_desc directly.
        def expect_tx_fail(label: str, mut_tx) -> None:
            doc = json.loads(json.dumps(clean))
            v = eng(doc, "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                if int(e.get("tx_len") or 0) > 0 and "tx" in e:
                    mut_tx(e["tx"])
                    try:
                        validate_tx_desc(e["tx"], where="self-test")
                    except Exception:
                        return
                    raise SystemExit(f"self-test tx semantic expected fail: {label}")
            raise SystemExit(f"self-test: no TX for {label}")

        expect_tx_fail("stream_id non-zero", lambda tx: tx.__setitem__("stream_id", 1))
        expect_tx_fail(
            "sequence UINT32_MAX", lambda tx: tx.__setitem__("sequence", 0xFFFFFFFF)
        )
        expect_tx_fail(
            "frame/message binding", lambda tx: tx.__setitem__("frame_type", TYPE_PING)
        )

    print("logical_session_u4_vector_gen self-test OK")


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=("write", "check", "self-test", "emit-c-fixture"))
    p.add_argument("args", nargs="*")
    ns = p.parse_args(argv)
    if ns.command == "write":
        path = pathlib.Path(ns.args[0]) if ns.args else VECTOR_PATH
        write_vector(path)
        print("wrote", path)
        return 0
    if ns.command == "check":
        check(pathlib.Path(ns.args[0]) if ns.args else VECTOR_PATH)
        return 0
    if ns.command == "self-test":
        self_test()
        return 0
    if ns.command == "emit-c-fixture":
        emit_c_fixture(pathlib.Path(ns.args[0]), pathlib.Path(ns.args[1]))
        print("emitted", ns.args[1])
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
