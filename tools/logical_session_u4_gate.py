#!/usr/bin/env python3
"""U4 logical session structural/mutation gate.

Does not import production C. Mutation self-test runs the real checker on
temporary trees. Pins sole-owner API, step entry, zero-mutation time status,
cookie/jitter separation, object size composition, private source authority,
typed object (no unsigned-char type-pun), peer-scoped force_state, and exact
TX semantic oracle descriptors.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
H = REPO / "src" / "transport" / "logical_session.h"
C = REPO / "src" / "transport" / "logical_session.c"
LAYOUT = REPO / "src" / "transport" / "logical_session_layout.h"
U3_H = REPO / "src" / "transport" / "control_session.h"
U3_C = REPO / "src" / "transport" / "control_session.c"
U3_LAYOUT = REPO / "src" / "transport" / "control_session_layout.h"
PRIVATE = REPO / "cmake" / "ninlil_runtime_private_sources.cmake"
CMAKE = REPO / "CMakeLists.txt"
DOC23 = REPO / "docs" / "23-usb-radio-boundary.md"
VEC = REPO / "spec" / "vectors" / "logical-session-u4-v1.json"
GEN = REPO / "tools" / "logical_session_u4_vector_gen.py"
TEST_C = REPO / "tests" / "transport" / "logical_session_u4_test.c"
NCL1 = REPO / "spec" / "vectors" / "ncl1-u4-v1.json"

BANNED_INCLUDES = (
    "termios.h",
    "unistd.h",
    "fcntl.h",
    "pthread.h",
    "tinyusb.h",
    "tusb.h",
    "freertos/",
    "esp_",
    "vendor_specific",
    "product_specific",
)

REQUIRED_HEADER = (
    "ninlil_logical_session_init",
    "ninlil_logical_session_bind",
    "ninlil_logical_session_step",
    "ninlil_logical_session_snapshot",
    "ninlil_logical_session_unbind",
    "NINLIL_LOGICAL_SESSION_TIME_REGRESSED",
    "NINLIL_LOGICAL_SESSION_DEADLINE_OVERFLOW",
    "NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES",
    "ninlil_logical_session_cookie_rng_fn",
    "ninlil_logical_session_jitter_fn",
    "exact zero mutation",
    "never falls back",
    "Sole owner",
    "NINLIL_LOGICAL_SESSION_OBJECT_INIT",
    "logical_session_layout.h",
)

FORBIDDEN_HEADER = (
    "ninlil_logical_session_u3",
    "ninlil_logical_session_set_now_ms",
    "ninlil_logical_session_pump",
    "time_regressed_rejects",
    "deadline_overflow_rejects",
)

REQUIRED_SOURCE = (
    "ninlil_logical_session_step",
    "ninlil_ctrl_session_tracked_submit_tx",
    "ninlil_ctrl_session_tx_resolve",
    "ninlil_ctrl_session_pump",
    "ninlil_ctrl_session_take_rx",
    "ninlil_ctrl_session_logical_epoch_begin",
    "RAW_ACCEPTED_CURRENT_EPOCH",
    "ninlil_ncl1_decode",
    "ninlil_ncl1_encode",
    "ninlil_ncl1_check_reserved",
    "semantic_hello_bootstrap",
    "COOKIE_REDRAW_MAX",
    "&object->session",
    # P1-A TX sequence terminal exhaustion (§5.5.2)
    "apply_tx_seq_terminal_exhaust",
    # P1-B deadline overflow pure precheck + checked-add
    "deadline_overflow_pure",
    "add_u64_overflow",
    "max_deadline_add_ms",
)

FORCE_OPS = ("force_state", "force_rx_baseline", "force_next_tx_seq")
ST_ACT = 4

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
    0x01: (
        "hello_min_version",
        "hello_max_version",
        "hello_flags_supported",
        "hello_reserved",
    ),
    0x02: (
        "hello_ack_selected_version",
        "hello_ack_flags_selected",
        "hello_ack_result",
        "hello_ack_reserved",
    ),
    0x03: ("error_code", "error_reserved", "related_request_id"),
    0x10: ("opaque_echo_token",),
    0x11: ("opaque_echo_token",),
    0x12: (
        "reset_code",
        "reset_reserved0",
        "reset_reserved1",
        "reset_reserved2",
    ),
}


def fail(msg: str) -> None:
    print(f"logical_session_u4_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8")


def check_includes(text: str, label: str) -> None:
    for line in text.splitlines():
        m = re.match(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', line)
        if not m:
            continue
        inc = m.group(1)
        for ban in BANNED_INCLUDES:
            if ban in inc.lower():
                fail(f"{label} banned include {inc}")


def action_peer(a: dict) -> str | None:
    """Peer whose session authority the action mutates / forces."""
    op = a.get("op")
    if op == "forward":
        # Forward residual expect is on the source peer (frm).
        return a.get("frm") or a.get("from") or a.get("src") or a.get("peer")
    return a.get("peer")


def check_force_peer_scoped(v: dict) -> None:
    """force_* only after same peer completed real HELLO handshake path.

    Uses the same CausalTracker proof as validate_scenario_tx_causal /
    track_handshake_active: (origin, responder, request_id) HELLO triples,
    HELLO_ACK OK TX by responder, ACK delivery destination==origin, then
    origin step to ACTIVE. Fake expect.state / inject ACK error never count.
    """
    gen = _load_gen()
    for idx, a in enumerate(v["actions"]):
        op = a.get("op")
        peer = action_peer(a)
        if op not in FORCE_OPS:
            continue
        if not peer:
            fail(f"{v.get('id')}[{idx}]: {op} requires peer")
        # Only actions strictly before this force contribute authority.
        active = gen.track_handshake_active(v["actions"][:idx])
        if peer not in active:
            fail(
                f"{v.get('id')}[{idx}]: {op} on peer={peer!r} only allowed "
                "after that peer completed non-force HELLO handshake "
                "(origin/responder/request_id causal proof; not fake "
                "expect.state / inject ACK error / other-peer ACTIVE)"
            )


def _load_gen():
    import importlib.util

    spec = importlib.util.spec_from_file_location("logical_session_u4_vector_gen", GEN)
    if spec is None or spec.loader is None:
        fail("cannot load vector generator")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_tx_descriptor(tx: dict, where: str) -> None:
    """Full semantic oracle: ranges, binding, HELLO/ACK/PING semantics (no mask)."""
    gen = _load_gen()
    try:
        gen.validate_tx_desc(tx, where=where)
        rebuilt = gen.encode_tx_desc(tx)
    except Exception as ex:  # noqa: BLE001
        fail(f"{where}: tx semantic validation failed: {ex}")
    # Caller may also pin rebuild-identical against expect.tx_hex.
    return rebuilt


def check_layout_sentinel_compile() -> None:
    """layout.h alone must #error; parent header include must succeed."""
    compiler = shutil.which("cc")
    if compiler is None:
        fail("C compiler 'cc' not found for layout sentinel probe")
    with tempfile.TemporaryDirectory(prefix="u4-layout-sentinel-") as td:
        root = pathlib.Path(td)
        bad = root / "bad.c"
        good = root / "good.c"
        bad.write_text(
            '#include "logical_session_layout.h"\nint main(void){return 0;}\n',
            encoding="utf-8",
        )
        good.write_text(
            '#include "logical_session.h"\nint main(void){return 0;}\n',
            encoding="utf-8",
        )
        inc = [
            "-std=c11",
            "-Wall",
            "-Werror",
            "-I",
            str(REPO / "include"),
            "-I",
            str(REPO / "src" / "model"),
            "-I",
            str(REPO / "src" / "transport"),
        ]
        r_bad = subprocess.run(
            [compiler, *inc, "-c", str(bad), "-o", str(root / "bad.o")],
            capture_output=True,
            text=True,
        )
        if r_bad.returncode == 0:
            fail("logical_session_layout.h must #error when included alone")
        if "private" not in (r_bad.stderr or "").lower() and "LAYOUT" not in (
            r_bad.stderr or ""
        ):
            # Accept any compile failure, but prefer sentinel message.
            pass
        r_good = subprocess.run(
            [compiler, *inc, "-c", str(good), "-o", str(root / "good.o")],
            capture_output=True,
            text=True,
        )
        if r_good.returncode != 0:
            fail(
                "logical_session.h (with layout allow) must compile:\n"
                f"{r_good.stderr}"
            )
        # U3 layout sentinel
        bad3 = root / "bad3.c"
        good3 = root / "good3.c"
        bad3.write_text(
            '#include "control_session_layout.h"\nint main(void){return 0;}\n',
            encoding="utf-8",
        )
        good3.write_text(
            '#include "control_session.h"\nint main(void){return 0;}\n',
            encoding="utf-8",
        )
        r_bad3 = subprocess.run(
            [compiler, *inc, "-c", str(bad3), "-o", str(root / "bad3.o")],
            capture_output=True,
            text=True,
        )
        if r_bad3.returncode == 0:
            fail("control_session_layout.h must #error when included alone")
        r_good3 = subprocess.run(
            [compiler, *inc, "-c", str(good3), "-o", str(root / "good3.o")],
            capture_output=True,
            text=True,
        )
        if r_good3.returncode != 0:
            fail(
                "control_session.h (with layout allow) must compile:\n"
                f"{r_good3.stderr}"
            )


# Generic names that must not leak from layout/.c (OSS namespace hygiene).
BANNED_LS_GENERIC_NAMES = (
    r"(?<![A-Za-z0-9_])INFLIGHT_NONE(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])INFLIGHT_HELLO(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])INFLIGHT_PING(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])NOTICE_EMPTY(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])NOTICE_PENDING(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])NOTICE_ACCEPTED(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])TRACKED_NONE(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])TRACKED_ORDINARY(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])TRACKED_NOTICE(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])ACTION_META_BYTES(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])inflight_slot_t(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])tx_action_t(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])notice_slot_t(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])struct\s+inflight_slot(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])struct\s+tx_action(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])struct\s+notice_slot(?![A-Za-z0-9_])",
)

REQUIRED_LS_PREFIXED = (
    "NINLIL_LS_INFLIGHT_NONE",
    "NINLIL_LS_NOTICE_EMPTY",
    "NINLIL_LS_TRACKED_NONE",
    "ninlil_ls_inflight_slot_t",
    "ninlil_ls_tx_action_t",
    "ninlil_ls_notice_slot_t",
)


def check_ls_namespace(layout: str, c: str) -> None:
    """U4 private layout/constants must use NINLIL_LS_* / ninlil_ls_* only."""
    for tok in REQUIRED_LS_PREFIXED:
        if tok not in layout:
            fail(f"layout missing namespaced token {tok}")
    blob = layout + "\n" + c
    for pat in BANNED_LS_GENERIC_NAMES:
        m = re.search(pat, blob)
        if m:
            fail(
                "generic unprefixed private name leaks from U4 layout/source: "
                f"{m.group(0)!r}"
            )


def check_p1_tx_seq_and_deadline(c: str, h: str) -> None:
    """P1-A TX seq terminal + P1-B DEADLINE_OVERFLOW contracts (docs/23, docs/07)."""
    # P1-A: next_tx_seq==UINT32_MAX must call terminal exhaust (not silent wrap+OK).
    if "apply_tx_seq_terminal_exhaust" not in c:
        fail("P1-A: missing apply_tx_seq_terminal_exhaust")
    m = re.search(
        r"if\s*\(\s*s->next_tx_seq\s*==\s*UINT32_MAX\s*\)\s*\{(.*?)\}",
        c,
        re.S,
    )
    if not m:
        fail("P1-A: next_tx_seq==UINT32_MAX guard missing")
    body = m.group(1)
    if "apply_tx_seq_terminal_exhaust" not in body:
        fail("P1-A: UINT32_MAX path must call apply_tx_seq_terminal_exhaust")
    if "NINLIL_LOGICAL_SESSION_OK" in body and "CONTINUITY_LOST" not in body:
        fail("P1-A: UINT32_MAX path must not return OK alone")
    # Exhaust must cold both directions + controller rehello.
    ex = re.search(
        r"static ninlil_logical_session_status_t apply_tx_seq_terminal_exhaust"
        r"[\s\S]*?return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST\s*;",
        c,
    )
    if not ex:
        fail("P1-A: apply_tx_seq_terminal_exhaust body not found")
    ex_body = ex.group(0)
    if "rx_only_cold" not in ex_body:
        fail("P1-A: exhaust must RX-cold (rx_only_cold)")
    if "next_tx_seq = 0" not in ex_body and "next_tx_seq =0" not in ex_body:
        fail("P1-A: exhaust must TX-cold next_tx_seq=0")
    if "rehello_armed = 1" not in ex_body and "rehello_armed=1" not in ex_body:
        fail("P1-A: exhaust must arm Controller re-HELLO (rehello_armed = 1)")
    if "CONTINUITY_LOST" not in ex_body:
        fail("P1-A: exhaust must return CONTINUITY_LOST (non-OK)")

    # P1-B: pure precheck must cover more than PING slack alone.
    if "max_deadline_add_ms" not in c:
        fail("P1-B: max_deadline_add_ms required for pure ceiling")
    pure = re.search(
        r"static int deadline_overflow_pure[\s\S]*?return 0;\n\}",
        c,
    )
    if not pure:
        fail("P1-B: deadline_overflow_pure body missing")
    pb = pure.group(0)
    if "max_deadline_add_ms" not in pb:
        fail("P1-B: pure precheck must use max_deadline_add_ms ceiling")
    if "PING_DISPATCH_SLACK_MS" not in pb:
        fail("P1-B: pure precheck must still cover PING slack")
    if "REHELLO_AFTER_RESET_MS" not in pb:
        fail("P1-B: pure precheck must cover REHELLO_AFTER_RESET_MS")
    if "PONG_TIMEOUT_MS" not in pb:
        fail("P1-B: pure precheck must cover PONG_TIMEOUT_MS")
    if "PING_CADENCE_MS" not in pb:
        fail("P1-B: pure precheck must cover PING_CADENCE_MS")
    # Ban saturate-to-UINT64_MAX on deadline assignment paths.
    if re.search(
        r"rehello_deadline_ms\s*=\s*UINT64_MAX",
        c,
    ):
        fail("P1-B: rehello_deadline must not saturate to UINT64_MAX")
    if re.search(
        r"ping_eligible_at_ms\s*=\s*UINT64_MAX",
        c,
    ):
        fail("P1-B: ping_eligible_at must not saturate to UINT64_MAX")
    if re.search(
        r"hello_deadline_ms\s*=\s*UINT64_MAX",
        c,
    ):
        fail("P1-B: hello_deadline must not saturate to UINT64_MAX")
    # Ban raw wrap add for RESET rehello.
    if re.search(
        r"rehello_deadline_ms\s*=\s*s->now_ms\s*\+\s*NINLIL_LOGICAL_SESSION_REHELLO",
        c,
    ):
        fail("P1-B: raw u64 add for rehello_deadline forbidden (use checked-add)")
    if "DEADLINE_OVERFLOW" not in h:
        fail("P1-B: DEADLINE_OVERFLOW status required in header")
    if "exact zero mutation" not in h:
        fail("P1-B: zero-mutation contract comment required")


def check() -> None:
    if not H.is_file() or not C.is_file():
        fail("logical_session sources missing")
    if not LAYOUT.is_file():
        fail("logical_session_layout.h missing (typed complete layout)")
    h = read(H)
    c = read(C)
    layout = read(LAYOUT)
    check_ls_namespace(layout, c)
    check_includes(h, "header")
    check_includes(c, "source")

    for tok in REQUIRED_HEADER:
        if tok not in h:
            fail(f"header missing token: {tok}")
    for tok in FORBIDDEN_HEADER:
        if tok in h:
            fail(f"header must not expose: {tok}")
    for tok in REQUIRED_SOURCE:
        if tok not in c:
            fail(f"source missing token: {tok}")

    check_p1_tx_seq_and_deadline(c, h)

    # Sole-owner: no public U3 escape; step is sole drive.
    if re.search(r"ninlil_logical_session_u3\s*\(", h):
        fail("u3 accessor must not be public")
    if "ninlil_logical_session_set_now_ms" in h or "ninlil_logical_session_pump" in h:
        fail("set_now_ms/pump must not be public; use step only")

    # Cookie vs jitter: cookie_rng must not be called from jitter path.
    if "jitter_fn" not in h or "cookie_rng" not in h:
        fail("cookie_rng and jitter_fn contracts required")
    if "apply_hello_jitter" in c:
        m = re.search(
            r"apply_hello_jitter\(.*?\{(.*?)\n\}",
            c,
            re.S,
        )
        if m and "cookie_rng" in m.group(1):
            fail("jitter path must not call cookie_rng")

    # Object size composition
    if "NINLIL_CTRL_SESSION_OBJECT_BYTES + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES" not in h.replace(
        "\n", " "
    ) and "NINLIL_CTRL_SESSION_OBJECT_BYTES\n            + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES" not in h:
        if "U4_EXCLUSIVE_BYTES" not in h or "CTRL_SESSION_OBJECT_BYTES" not in h:
            fail("object ceiling must compose U3 + U4 exclusive")
    if "_Static_assert" not in c or "sizeof(struct ninlil_logical_session)" not in c:
        fail("source must static-assert sizeof against ceiling")

    # C11 typed object (U4 + embedded U3): no unsigned-char storage cast shell.
    if re.search(
        r"ninlil_logical_session_object\s*\{[^}]*unsigned\s+char\s+bytes\s*\[",
        h,
        re.S,
    ):
        fail("U4 object must not use unsigned char bytes[] storage shell")
    if "struct ninlil_logical_session session" not in h:
        fail("U4 object must embed typed struct ninlil_logical_session session")
    if "object->bytes" in c:
        fail("U4 source must not access object->bytes (type-pun path)")
    if "struct ninlil_logical_session" not in layout:
        fail("layout must define complete struct ninlil_logical_session")
    if "NINLIL_LOGICAL_SESSION_OBJECT_INIT" not in h:
        fail("OBJECT_INIT required for typed object zero-init")
    if "ninlil_ctrl_session_object_t u3_obj" not in layout:
        fail("U4 layout must embed typed U3 object member u3_obj")
    if "NINLIL_LOGICAL_SESSION_LAYOUT_ALLOW" not in h:
        fail("U4 header must define LAYOUT_ALLOW before layout include")
    if "NINLIL_LOGICAL_SESSION_LAYOUT_ALLOW" not in layout and "private" not in layout:
        fail("U4 layout must carry sentinel #error contract")
    if "#error" not in read(LAYOUT):
        fail("U4 layout must #error without LAYOUT_ALLOW")
    if not re.search(
        r"ninlil_logical_session_object_align\s*\([^)]*\)\s*\{[^}]*?"
        r"return\s+_Alignof\s*\(\s*struct\s+ninlil_logical_session\s*\)\s*;",
        c,
        re.S,
    ):
        fail("U4 object_align must return _Alignof(complete type)")

    # Embedded U3 must itself be typed (no char-array shell repeating the pattern).
    if not U3_H.is_file() or not U3_C.is_file() or not U3_LAYOUT.is_file():
        fail("embedded U3 control_session sources/layout missing")
    u3h = read(U3_H)
    u3c = read(U3_C)
    if re.search(
        r"ninlil_ctrl_session_object\s*\{[^}]*unsigned\s+char\s+bytes\s*\[",
        u3h,
        re.S,
    ):
        fail("embedded U3 object must not use unsigned char bytes[] storage shell")
    if "struct ninlil_ctrl_session session" not in u3h:
        fail("embedded U3 object must embed typed struct ninlil_ctrl_session session")
    if "object->bytes" in u3c:
        fail("embedded U3 must not access object->bytes (type-pun path)")
    if "&object->session" not in u3c:
        fail("embedded U3 init_object must use &object->session")
    if "NINLIL_CTRL_SESSION_OBJECT_INIT" not in u3h:
        fail("embedded U3 requires NINLIL_CTRL_SESSION_OBJECT_INIT")
    if "control_session_layout.h" not in u3h:
        fail("embedded U3 header must include control_session_layout.h")
    if not re.search(
        r"ninlil_ctrl_session_object_align\s*\([^)]*\)\s*\{[^}]*?"
        r"return\s+_Alignof\s*\(\s*struct\s+ninlil_ctrl_session\s*\)\s*;",
        u3c,
        re.S,
    ):
        fail("U3 object_align must return _Alignof(complete type)")
    if "#error" not in read(U3_LAYOUT):
        fail("U3 layout must #error without LAYOUT_ALLOW")

    check_layout_sentinel_compile()

    # Generator must not host synthesis path.
    gen_src = read(GEN)
    if re.search(r"def\s+_synthesize_tx_hex\b", gen_src):
        fail("generator must not define synthesis helper")
    if "bare tx_hex forbidden" not in gen_src:
        fail("generator must hard-fail bare tx_hex")
    if "encode_tx_desc" not in gen_src:
        fail("generator must encode only from explicit tx descriptors")

    # Private source authority
    priv = read(PRIVATE)
    if "src/transport/logical_session.c" not in priv:
        fail("logical_session.c missing from private source authority")

    # Docs + vector
    if not VEC.is_file():
        fail("logical-session-u4-v1.json missing")
    if "logical session" not in read(DOC23).lower() and "U4" not in read(DOC23):
        fail("docs/23 missing U4 context")

    # Vector check via generator
    r = subprocess.run(
        [sys.executable, str(GEN), "check", str(VEC)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"vector check failed: {r.stderr or r.stdout}")

    # Normal RX path must not use reserved-including helpers wholesale for step6
    if c.count("ninlil_ncl1_is_valid_hello_bootstrap") < 1:
        fail("bootstrap helper should be used for limited peek")
    if "semantic_hello_bootstrap" not in c:
        fail("normal path needs semantic_hello_bootstrap without reserved")
    if "ninlil_ncl1_check_reserved" not in c:
        fail("step7 reserved check required")

    # Host test: scenario bridge only
    if TEST_C.is_file():
        t = read(TEST_C)
        if re.search(r"==\s*0\s*\|\|\s*1\b", t):
            fail("test must not use always-true REQUIRE(... == 0 || 1)")
        if re.search(r"\bg_pass_marks\b", t):
            fail("test must not use g_pass_marks catalog coverage")
        if "run_all_scenarios" not in t or "run_scenario" not in t:
            fail("test must drive machine-executable scenarios via bridge")
        if "ninlil_ls_u4_scenarios" not in t:
            fail("test must consume fixture scenario table")
        if "check_expect_on_peer" not in t:
            fail("bridge must validate per-action expects")
        if "memcmp" not in t:
            fail("bridge must memcmp full expected TX wire bytes")
        if "gen2 > gen1" not in t and "gen2 == gen1 + 1u" not in t:
            fail("gen burn cancel test must assert strictly greater generation")
    if "TEST SEAM ONLY" not in h and "test seam" not in h.lower():
        fail("header must document test-seam (not public/runtime path)")

    # Vector must be scenario-complete with action-level expects + exact TX wire.
    vdoc = json.loads(read(VEC))
    behaviors = [v for v in vdoc["vectors"] if v.get("kind") == "engine_behavior"]
    if len(behaviors) != 38:
        fail("engine_behavior vectors must be 38")
    action_expects = 0
    tx_hex_n = 0
    tx_complete_n = 0
    genmod = _load_gen()
    for v in behaviors:
        if "assertion_key" in v:
            fail(f"{v.get('id')}: assertion_key forbidden")
        if not v.get("actions") or not v.get("expect_final") or not v.get("precondition"):
            fail(f"{v.get('id')}: missing scenario fields")
        check_force_peer_scoped(v)
        try:
            genmod.validate_scenario_tx_causal(v)
        except Exception as ex:  # noqa: BLE001
            fail(f"{v.get('id')}: causal TX oracle failed: {ex}")
        for ai, a in enumerate(v["actions"]):
            if a.get("op") in ("handshake_active", "step_pair", "quiet_drain", "quiet_drain_tx"):
                fail(f"{v.get('id')}: macro op forbidden")
            if a.get("op") in ("step", "forward", "drop_tx", "inject"):
                if "expect" not in a:
                    fail(f"{v.get('id')}: action missing expect")
                action_expects += 1
                if "state_ne" in a["expect"]:
                    fail(f"{v.get('id')}: state_ne forbidden")
                tlen = int(a["expect"].get("tx_len") or 0)
                if tlen > 0:
                    hx = a["expect"].get("tx_hex")
                    if not hx or len(hx) != tlen * 2:
                        fail(f"{v.get('id')}: non-empty TX requires exact tx_hex")
                    tx = a["expect"].get("tx")
                    if not tx:
                        fail(f"{v.get('id')}: non-empty TX requires explicit tx descriptor")
                    rebuilt = check_tx_descriptor(tx, f"{v.get('id')}[{ai}]")
                    if hx != rebuilt:
                        fail(
                            f"{v.get('id')}[{ai}]: tx_hex not rebuild-identical "
                            "under strict semantic encode"
                        )
                    tx_hex_n += 1
                    tx_complete_n += 1
        for e in v["expect_final"]:
            if "state_ne" in e:
                fail(f"{v.get('id')}: state_ne forbidden")
            if set(e.keys()) - {"peer"} <= {"state"}:
                fail(f"{v.get('id')}: state-only final forbidden")
            if not any(
                k in e
                for k in (
                    "state",
                    "active_generation",
                    "active_cookie",
                    "next_tx_seq",
                    "last_tx_commit",
                    "counters",
                    "counter_deltas",
                )
            ):
                fail(f"{v.get('id')}: expect_final lacks major exact fields")
    if action_expects < 38:
        fail("too few action-level expects")
    if tx_hex_n < 1:
        fail("expected at least one full exact tx_hex wire vector")
    if tx_complete_n != tx_hex_n:
        fail("every nonempty TX must have complete semantic descriptor")
    if tx_complete_n < 100:
        fail(f"expected dense TX oracle coverage, got {tx_complete_n}")

    print(
        "logical_session_u4_gate check OK "
        f"action_expects={action_expects} tx_complete={tx_complete_n}"
    )


def _copy_tree(root: pathlib.Path) -> None:
    for rel in (
        "src/transport",
        "cmake",
        "docs",
        "spec/vectors",
        "tools",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    shutil.copy2(H, root / "src/transport/logical_session.h")
    shutil.copy2(C, root / "src/transport/logical_session.c")
    shutil.copy2(LAYOUT, root / "src/transport/logical_session_layout.h")
    shutil.copy2(U3_H, root / "src/transport/control_session.h")
    shutil.copy2(U3_C, root / "src/transport/control_session.c")
    shutil.copy2(U3_LAYOUT, root / "src/transport/control_session_layout.h")
    shutil.copy2(PRIVATE, root / "cmake/ninlil_runtime_private_sources.cmake")
    shutil.copy2(CMAKE, root / "CMakeLists.txt")
    shutil.copy2(DOC23, root / "docs/23-usb-radio-boundary.md")
    shutil.copy2(VEC, root / "spec/vectors/logical-session-u4-v1.json")
    if NCL1.is_file():
        shutil.copy2(NCL1, root / "spec/vectors/ncl1-u4-v1.json")
    else:
        shutil.copy2(VEC, root / "spec/vectors/ncl1-u4-v1.json")
    shutil.copy2(GEN, root / "tools/logical_session_u4_vector_gen.py")
    shutil.copy2(
        REPO / "tools/logical_session_u4_gate.py",
        root / "tools/logical_session_u4_gate.py",
    )


def _run_check(tree: pathlib.Path) -> int:
    return subprocess.run(
        [sys.executable, str(tree / "tools/logical_session_u4_gate.py"), "check"],
        cwd=str(tree),
        capture_output=True,
        text=True,
    ).returncode


def self_test() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        _copy_tree(root)

        def expect_fail(label: str) -> None:
            if _run_check(root) == 0:
                fail(f"self-test: {label} should fail")

        # Mutation 1: remove step
        hpath = root / "src/transport/logical_session.h"
        text = hpath.read_text(encoding="utf-8")
        hpath.write_text(
            text.replace("ninlil_logical_session_step", "ninlil_logical_session_Xstep"),
            encoding="utf-8",
        )
        expect_fail("step rename")
        hpath.write_text(text, encoding="utf-8")

        # Mutation 2: reintroduce u3 accessor
        hpath.write_text(
            text + "\nninlil_ctrl_session_t *ninlil_logical_session_u3(void);\n",
            encoding="utf-8",
        )
        expect_fail("u3 accessor")
        hpath.write_text(text, encoding="utf-8")

        # Mutation 3: drop private source
        ppath = root / "cmake/ninlil_runtime_private_sources.cmake"
        ppath.write_text(
            ppath.read_text(encoding="utf-8").replace(
                "src/transport/logical_session.c\n", ""
            ),
            encoding="utf-8",
        )
        expect_fail("private authority drop")
        shutil.copy2(PRIVATE, ppath)

        # Mutation 4: revive unsigned-char object shell (U4)
        h_mut = text.replace(
            "struct ninlil_logical_session session;",
            "_Alignas(8) unsigned char bytes[NINLIL_LOGICAL_SESSION_OBJECT_BYTES];",
        )
        if h_mut == text:
            fail("self-test: could not rewrite object session member")
        hpath.write_text(h_mut, encoding="utf-8")
        expect_fail("U4 unsigned-char object shell revival")
        hpath.write_text(text, encoding="utf-8")

        # Mutation 4ns: revive generic unprefixed private names in layout
        lpath_ns = root / "src/transport/logical_session_layout.h"
        l_ns = lpath_ns.read_text(encoding="utf-8")
        l_mut = l_ns.replace("NINLIL_LS_INFLIGHT_NONE", "INFLIGHT_NONE", 1)
        if l_mut == l_ns:
            fail("self-test: could not demote NINLIL_LS_INFLIGHT_NONE")
        lpath_ns.write_text(l_mut, encoding="utf-8")
        expect_fail("generic INFLIGHT_NONE namespace leak")
        lpath_ns.write_text(l_ns, encoding="utf-8")

        l_mut2 = l_ns.replace("ninlil_ls_tx_action_t", "tx_action_t")
        if l_mut2 == l_ns:
            fail("self-test: could not demote ninlil_ls_tx_action_t")
        lpath_ns.write_text(l_mut2, encoding="utf-8")
        expect_fail("generic tx_action_t namespace leak")
        lpath_ns.write_text(l_ns, encoding="utf-8")

        # Mutation 4b: revive unsigned-char object shell (embedded U3)
        u3hpath = root / "src/transport/control_session.h"
        u3text = u3hpath.read_text(encoding="utf-8")
        u3mut = u3text.replace(
            "struct ninlil_ctrl_session session;",
            "_Alignas(8) unsigned char bytes[NINLIL_CTRL_SESSION_OBJECT_BYTES];",
        )
        if u3mut == u3text:
            fail("self-test: could not rewrite U3 object session member")
        u3hpath.write_text(u3mut, encoding="utf-8")
        expect_fail("embedded U3 unsigned-char object shell revival")
        u3hpath.write_text(u3text, encoding="utf-8")

        # Mutation 4c: revive U3 object->bytes type-pun path
        u3cpath = root / "src/transport/control_session.c"
        u3ctxt = u3cpath.read_text(encoding="utf-8")
        u3cmut = u3ctxt.replace("&object->session", "object->bytes")
        if u3cmut == u3ctxt:
            fail("self-test: could not rewrite U3 object->session")
        u3cpath.write_text(u3cmut, encoding="utf-8")
        expect_fail("embedded U3 object->bytes type-pun revival")
        u3cpath.write_text(u3ctxt, encoding="utf-8")

        # Mutation 5: revive synthesis helper in generator
        gpath = root / "tools/logical_session_u4_vector_gen.py"
        gtxt = gpath.read_text(encoding="utf-8")
        gpath.write_text(
            gtxt + "\ndef _synthesize_tx_hex(x):\n    return x\n",
            encoding="utf-8",
        )
        expect_fail("synthesis path revival")
        gpath.write_text(gtxt, encoding="utf-8")

        vpath = root / "spec/vectors/logical-session-u4-v1.json"
        clean_vec = vpath.read_text(encoding="utf-8")
        gate_path = root / "tools/logical_session_u4_gate.py"
        gate_txt = gate_path.read_text(encoding="utf-8")

        def with_stubbed_gen_check(body) -> None:
            # Disk-only force/descriptor mutations fail GEN rebuild-identical
            # first; stub that gate step so peer-scope / completeness logic runs.
            stubbed = gate_txt.replace(
                'if r.returncode != 0:\n        fail(f"vector check failed: {r.stderr or r.stdout}")',
                "if False:\n        fail('stub')",
                1,
            )
            if stubbed == gate_txt:
                fail("self-test: could not stub generator check")
            gate_path.write_text(stubbed, encoding="utf-8")
            try:
                body()
            finally:
                gate_path.write_text(gate_txt, encoding="utf-8")
                vpath.write_text(clean_vec, encoding="utf-8")

        def force_first_active(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"].insert(
                0,
                {
                    "op": "force_state",
                    "peer": "ctrl",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
            )

        def force_other_peer(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"].insert(
                1,
                {
                    "op": "force_state",
                    "peer": "cell",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
            )

        def expect_only_active_no_handshake(doc: dict) -> None:
            """Other-peer: ctrl claims ACTIVE via expect alone → force cell."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"] = [
                {
                    "op": "step",
                    "peer": "ctrl",
                    "now_ms": 1,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
                {
                    "op": "force_state",
                    "peer": "cell",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
            ] + v["actions"]

        def same_peer_fake_expect_active_force(doc: dict) -> None:
            """Same peer fake step expect ACTIVE must NOT authorize force_state."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"] = [
                {
                    "op": "step",
                    "peer": "ctrl",
                    "now_ms": 1,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
                {
                    "op": "force_state",
                    "peer": "ctrl",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
            ] + v["actions"]

        def force_from_own_expect_only(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"] = [
                {
                    "op": "force_state",
                    "peer": "ctrl",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                }
            ] + v["actions"]

        def drop_tx_field(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                if int(e.get("tx_len") or 0) > 0 and "tx" in e:
                    e["tx"].pop("request_id", None)
                    return
            fail("self-test: no TX to strip request_id")

        def flip_tx_hex(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                hx = e.get("tx_hex")
                if hx and len(hx) >= 2:
                    e["tx_hex"] = f"{int(hx[0:2], 16) ^ 1:02x}" + hx[2:]
                    return
            fail("self-test: no tx_hex to flip")

        def strip_tx_object(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                if int(e.get("tx_len") or 0) > 0 and "tx" in e:
                    del e["tx"]
                    return
            fail("self-test: no tx object to strip")

        def _load_tree_gen():
            import importlib.util

            gpath_local = root / "tools/logical_session_u4_vector_gen.py"
            spec = importlib.util.spec_from_file_location(
                "u4_gen_mut_selftest", gpath_local
            )
            if spec is None or spec.loader is None:
                fail("self-test: cannot load tree generator")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        def run_force_case(label: str, mutator) -> None:
            def body() -> None:
                doc = json.loads(clean_vec)
                mutator(doc)
                vpath.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
                if _run_check(root) == 0:
                    fail(f"self-test: {label} should fail")
                vpath.write_text(clean_vec, encoding="utf-8")

            with_stubbed_gen_check(body)

        run_force_case("force_state first action active", force_first_active)
        run_force_case("force_state other peer without history", force_other_peer)
        run_force_case(
            "expect-only active must not authorize other peer force",
            expect_only_active_no_handshake,
        )
        run_force_case(
            "same-peer fake expect ACTIVE must not authorize force",
            same_peer_fake_expect_active_force,
        )
        run_force_case(
            "force_state must not self-authorize via own expect.state",
            force_from_own_expect_only,
        )

        def run_semantic_case(label: str, mutator) -> None:
            """Prove CausalTracker / validate_tx_desc rejects mutation directly.

            Does not rely on generator rebuild-identical (canonical freshness)
            false positives. Canonical gen check is stubbed; validator is invoked
            in-process on the mutated document.
            """

            def body() -> None:
                genmod = _load_tree_gen()
                doc = json.loads(clean_vec)
                mutator(doc)
                rejected = False
                reject_msg = ""
                for v in doc.get("vectors") or []:
                    if v.get("kind") != "engine_behavior":
                        continue
                    try:
                        genmod.validate_scenario_tx_causal(v)
                        for i, a in enumerate(v.get("actions") or []):
                            e = a.get("expect") or {}
                            tlen = int(e.get("tx_len") or 0)
                            if tlen <= 0:
                                if "tx" in e or "tx_hex" in e:
                                    raise RuntimeError(
                                        f"{v.get('id')}[{i}]: empty TX has tx/tx_hex"
                                    )
                                continue
                            if "tx" not in e:
                                raise RuntimeError(
                                    f"{v.get('id')}[{i}]: missing tx descriptor"
                                )
                            genmod.validate_tx_desc(
                                e["tx"], where=f"{v.get('id')}[{i}]"
                            )
                            rebuilt = genmod.encode_tx_desc(e["tx"])
                            if e.get("tx_hex") != rebuilt:
                                raise RuntimeError(
                                    f"{v.get('id')}[{i}]: tx_hex not "
                                    "rebuild-identical under semantic encode"
                                )
                    except Exception as ex:  # noqa: BLE001 — expected reject
                        rejected = True
                        reject_msg = str(ex)
                        break
                if not rejected:
                    fail(
                        f"self-test: {label} was NOT rejected by causal/"
                        "semantic validator (would be a false-positive if "
                        "only canonical freshness failed)"
                    )
                # Also ensure gate completeness path fails under stubbed gen.
                vpath.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
                if _run_check(root) == 0:
                    fail(
                        f"self-test: {label} rejected by validator "
                        f"({reject_msg!r}) but gate check still passed"
                    )
                vpath.write_text(clean_vec, encoding="utf-8")

            with_stubbed_gen_check(body)

        run_semantic_case("tx request_id field deleted", drop_tx_field)
        run_semantic_case("tx_hex byte flipped", flip_tx_hex)
        run_semantic_case("missing tx descriptor", strip_tx_object)

        def first_tx(doc: dict) -> dict:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                if int(e.get("tx_len") or 0) > 0 and "tx" in e:
                    return e["tx"]
            fail("self-test: no TX in HELLO-OK")

        def mut_stream(doc: dict) -> None:
            first_tx(doc)["stream_id"] = 1

        def mut_seq_reserved(doc: dict) -> None:
            first_tx(doc)["sequence"] = 0xFFFFFFFF

        def mut_frame_binding(doc: dict) -> None:
            first_tx(doc)["frame_type"] = 0x01  # PING frame with HELLO msg

        def mut_hello_gen(doc: dict) -> None:
            first_tx(doc)["generation"] = 1

        def mut_u32_overflow(doc: dict) -> None:
            first_tx(doc)["request_id"] = 0x100000000

        def mut_ack_ok_selected0(doc: dict) -> None:
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if tx and tx.get("message_type") == 0x02 and tx.get("hello_ack_result") == 0:
                    tx["hello_ack_selected_version"] = 0
                    return
            fail("self-test: no HELLO_ACK OK to mutate")

        def mut_pong_no_ping(doc: dict) -> None:
            # Strip all PINGs but keep a PONG → causal fail.
            v = next(
                x for x in doc["vectors"] if x.get("id") == "U4-G-PING-PONG"
            )
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if tx and tx.get("message_type") == 0x10:
                    # Convert PING expect into empty TX so PONG has no source.
                    e.clear()
                    e.update({"status": 0, "state": 4, "tx_len": 0})

        def mut_ack_mismatched_peer(doc: dict) -> None:
            """ACK on cell without HELLO delivered to cell (wrong peer authority)."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            # Drop forward of HELLO to cell; keep cell ACK later → peer-scope fail.
            for a in v["actions"]:
                if a.get("op") == "forward" and a.get("frm") == "ctrl" and a.get("to") == "cell":
                    e = a.get("expect") or {}
                    if e.get("tx") and e["tx"].get("message_type") == 0x01:
                        e.clear()
                        e.update({"status": 0, "state": 2, "tx_len": 0})
                        return
            fail("self-test: no HELLO forward to strip")

        def mut_pong_mismatched_peer(doc: dict) -> None:
            """PONG from cell without PING delivered to cell."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-PING-PONG")
            for a in v["actions"]:
                if a.get("op") == "forward" and a.get("to") == "cell":
                    e = a.get("expect") or {}
                    tx = e.get("tx")
                    if tx and tx.get("message_type") == 0x10:
                        e.clear()
                        e.update({"status": 0, "state": 4, "tx_len": 0})
                        return
            fail("self-test: no PING forward to strip")

        def mut_ack_wrong_destination(doc: dict) -> None:
            """HELLO_ACK OK forwarded to non-origin peer."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and tx
                    and tx.get("message_type") == 0x02
                    and tx.get("hello_ack_result") == 0
                ):
                    # Origin is ctrl; deliver to cell instead (wrong destination).
                    a["to"] = "cell"
                    return
            fail("self-test: no ACK forward to retarget")

        def mut_ack_wrong_origin_req(doc: dict) -> None:
            """Cell ACK uses request_id never delivered from that HELLO pair."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and a.get("peer") == "cell"
                    and tx
                    and tx.get("message_type") == 0x02
                ):
                    tx["request_id"] = 99
                    # Keep hex stale so rebuild/semantic fails hard either way.
                    return
            fail("self-test: no cell ACK to corrupt request_id")

        def mut_restart_ack_to_wrong_controller(doc: dict) -> None:
            """After ctrl2 HELLO, ACK forward goes to original ctrl (wrong origin)."""
            v = next(
                x for x in doc["vectors"] if x.get("id") == "U4-G-RESTART-SEQ0-LAST0"
            )
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "cell"
                    and tx
                    and tx.get("message_type") == 0x02
                    and tx.get("generation") == 2
                ):
                    a["to"] = "ctrl"  # origin was ctrl2
                    return
            fail("self-test: no restart ACK forward to retarget")

        def mut_halfopen_ack_wrong_destination(doc: dict) -> None:
            """U4-G-HALFOPEN-REHELLO action17: ACK for ctrl2 HELLO delivered to ctrl.

            Must fail: first handshake's (ctrl,cell,req=1) is consumed and must
            not authorize wrong-destination delivery for the second HELLO.
            """
            v = next(
                x for x in doc["vectors"] if x.get("id") == "U4-G-HALFOPEN-REHELLO"
            )
            a = v["actions"][17]
            if a.get("op") != "forward" or a.get("to") != "ctrl2":
                fail("self-test: HALFOPEN action17 is not ACK forward to ctrl2")
            a["to"] = "ctrl"

        def mut_inject_ack_error_grants_active(doc: dict) -> None:
            """Inject HELLO_ACK error must not create handshake authority for force."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            v["actions"] = [
                {
                    "op": "inject",
                    "peer": "ctrl",
                    "frm": "cell",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x02,
                        "request_id": 1,
                        "generation": 0,
                        "cookie": 0,
                        "body_hex": "0000000000020000",
                    },
                    "expect": {"status": 0, "state": 1, "tx_len": 0},
                },
                {
                    "op": "force_state",
                    "peer": "ctrl",
                    "state": 4,
                    "expect": {"status": 0, "state": 4, "tx_len": 0},
                },
            ] + v["actions"]

        def mut_inject_ack_unrelated_req(doc: dict) -> None:
            """Inject HELLO_ACK OK with unrelated request_id must fail causal."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            inject_at = None
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == 0x01
                ):
                    inject_at = i + 1
                    break
            if inject_at is None:
                fail("self-test: no HELLO forward for inject unrelated")
            v["actions"].insert(
                inject_at,
                {
                    "op": "inject",
                    "peer": "ctrl",
                    "frm": "cell",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x02,
                        "request_id": 77,
                        "generation": 1,
                        "cookie": 0xC0FFEE0123456789,
                        "body_hex": "0001000000000000",
                    },
                    "expect": {"status": 0, "state": 2, "tx_len": 0},
                },
            )

        def mut_inject_ack_wrong_responder(doc: dict) -> None:
            """Inject ACK with wrong source responder (not the HELLO recipient)."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            inject_at = None
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == 0x01
                    and tx.get("request_id") == 1
                ):
                    inject_at = i + 1
                    break
            if inject_at is None:
                fail("self-test: no HELLO delivery for wrong-responder inject")
            # HELLO went to cell; inject claims responder=ctrl2 (wrong).
            v["actions"].insert(
                inject_at,
                {
                    "op": "inject",
                    "peer": "ctrl",
                    "frm": "ctrl2",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x02,
                        "request_id": 1,
                        "generation": 1,
                        "cookie": 0xC0FFEE0123456789,
                        "body_hex": "0001000000000000",
                    },
                    "expect": {"status": 0, "state": 2, "tx_len": 0},
                },
            )

        def mut_stale_origin_after_replace(doc: dict) -> None:
            """Second controller HELLO replaces outstanding; ACK inject to first origin fails.

            Proves completed/superseded (origin,responder,req) is not reusable.
            """
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-G-HELLO-OK")
            inject_at = None
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "ctrl"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == 0x01
                ):
                    inject_at = i + 1
                    break
            if inject_at is None:
                fail("self-test: no first HELLO forward for replace stale-origin")
            # ctrl2 HELLO same req supersedes ctrl outstanding.
            v["actions"].insert(
                inject_at,
                {
                    "op": "inject",
                    "peer": "cell",
                    "frm": "ctrl2",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x01,
                        "request_id": 1,
                        "generation": 0,
                        "cookie": 0,
                        "body_hex": "0001000100000000",
                    },
                    "expect": {"status": 0, "state": 3, "tx_len": 0},
                },
            )
            # Inject ACK OK claiming origin=ctrl (stale) with responder=cell.
            v["actions"].insert(
                inject_at + 1,
                {
                    "op": "inject",
                    "peer": "ctrl",
                    "frm": "cell",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x02,
                        "request_id": 1,
                        "generation": 1,
                        "cookie": 0xC0FFEE0123456789,
                        "body_hex": "0001000000000000",
                    },
                    "expect": {"status": 0, "state": 2, "tx_len": 0},
                },
            )

        def mut_error_ack_wrong_destination(doc: dict) -> None:
            """Error HELLO_ACK delivery dest must equal HELLO origin (not consume on TX)."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-N-COOKIE-RNG-FAIL")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("frm") == "cell"
                    and a.get("to") == "ctrl"
                    and tx
                    and tx.get("message_type") == 0x02
                    and int(tx.get("hello_ack_result") or 0) != 0
                ):
                    a["to"] = "cell"
                    return
            fail("self-test: no error ACK forward to retarget")

        def mut_error_ack_wrong_source_inject(doc: dict) -> None:
            """Inject error HELLO_ACK with wrong responder source must fail causal."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-N-COOKIE-RNG-FAIL")
            inject_at = None
            for i, a in enumerate(v["actions"]):
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "forward"
                    and a.get("to") == "cell"
                    and tx
                    and tx.get("message_type") == 0x01
                ):
                    inject_at = i + 1
                    break
            if inject_at is None:
                fail("self-test: no HELLO for error-ACK wrong-source inject")
            v["actions"].insert(
                inject_at,
                {
                    "op": "inject",
                    "peer": "ctrl",
                    "frm": "ctrl2",
                    "ncg1_type": 3,
                    "ncl1": {
                        "msg_type": 0x02,
                        "request_id": 1,
                        "generation": 0,
                        "cookie": 0,
                        "body_hex": "0000000000020000",
                    },
                    "expect": {"status": 0, "state": 2, "tx_len": 0},
                },
            )

        def mut_ctrl_error_wrong_active_pair(doc: dict) -> None:
            """ACTIVE CTRL_ERROR must equal current exact gen/cookie pair."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-N-CTRL-ERROR-LOOP")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == 0x03
                    and int(tx.get("generation") or 0) != 0
                ):
                    tx["generation"] = 99
                    return
            fail("self-test: no active CTRL_ERROR TX to corrupt")

        def mut_ctrl_error_nonzero_nonactive(doc: dict) -> None:
            """Non-ACTIVE CTRL_ERROR must be 0/0 (forbids ever-active nonzero)."""
            v = next(x for x in doc["vectors"] if x.get("id") == "U4-N-COOKIE-RNG-FAIL")
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == 0x03
                    and int(tx.get("generation") or 0) == 0
                ):
                    tx["generation"] = 1
                    tx["session_cookie"] = 0xC0FFEE0123456789
                    return
            fail("self-test: no non-active CTRL_ERROR TX to corrupt")

        def mut_ctrl_error_continuity_prefence(doc: dict) -> None:
            """Post-continuity CTRL_ERROR must not reuse pre-fence pair (§7.4 → 0/0)."""
            v = next(
                x
                for x in doc["vectors"]
                if x.get("id") == "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK"
            )
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if (
                    a.get("op") == "step"
                    and tx
                    and tx.get("message_type") == 0x03
                ):
                    tx["generation"] = 1
                    tx["session_cookie"] = 0xC0FFEE0123456789
                    return
            fail("self-test: no continuity CTRL_ERROR TX to corrupt")

        def mut_reset_wrong_pair(doc: dict) -> None:
            """RESET requires ACTIVE or pre-fence exact pair (not mere nonzero)."""
            v = next(
                x
                for x in doc["vectors"]
                if x.get("id") == "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK"
            )
            for a in v["actions"]:
                e = a.get("expect") or {}
                tx = e.get("tx")
                if a.get("op") == "step" and tx and tx.get("message_type") == 0x12:
                    tx["generation"] = 9
                    tx["session_cookie"] = 0x1111111111111111
                    return
            fail("self-test: no RESET TX to corrupt pair")

        def mut_align_constant_return(root_mut: pathlib.Path) -> None:
            p = root_mut / "src/transport/logical_session.c"
            t = p.read_text(encoding="utf-8")
            mut = t.replace(
                "return _Alignof(struct ninlil_logical_session);",
                "return NINLIL_LOGICAL_SESSION_OBJECT_ALIGN;",
            )
            if mut == t:
                fail("self-test: could not rewrite object_align")
            p.write_text(mut, encoding="utf-8")

        # Semantic/causal mutations: direct validator reject (not rebuild-identical).
        for label, mut in (
            ("stream_id non-zero", mut_stream),
            ("sequence UINT32_MAX reserved", mut_seq_reserved),
            ("frame/message binding break", mut_frame_binding),
            ("HELLO generation non-zero", mut_hello_gen),
            ("u32 overflow request_id", mut_u32_overflow),
            ("ACK OK selected_version=0", mut_ack_ok_selected0),
            ("PONG without PING echo source", mut_pong_no_ping),
            ("ACK without HELLO delivery to same peer", mut_ack_mismatched_peer),
            ("PONG without PING delivery to same peer", mut_pong_mismatched_peer),
            ("ACK OK forward wrong destination", mut_ack_wrong_destination),
            ("ACK request_id wrong origin pair", mut_ack_wrong_origin_req),
            ("restart ACK to wrong controller", mut_restart_ack_to_wrong_controller),
            ("halfopen ACK wrong destination (stale origin)", mut_halfopen_ack_wrong_destination),
            ("inject ACK unrelated request_id", mut_inject_ack_unrelated_req),
            ("inject ACK wrong responder source", mut_inject_ack_wrong_responder),
            ("stale origin after HELLO replace", mut_stale_origin_after_replace),
            ("error ACK wrong destination", mut_error_ack_wrong_destination),
            ("error ACK inject wrong responder", mut_error_ack_wrong_source_inject),
            ("CTRL_ERROR wrong active pair", mut_ctrl_error_wrong_active_pair),
            ("CTRL_ERROR nonzero non-active", mut_ctrl_error_nonzero_nonactive),
            ("CTRL_ERROR post-continuity pre-fence pair", mut_ctrl_error_continuity_prefence),
            ("RESET wrong gen/cookie pair", mut_reset_wrong_pair),
        ):
            run_semantic_case(label, mut)

        run_force_case(
            "inject HELLO_ACK error must not authorize force",
            mut_inject_ack_error_grants_active,
        )

        # Align API must not regress to floor constant alone.
        cpath = root / "src/transport/logical_session.c"
        c_clean = cpath.read_text(encoding="utf-8")
        mut_align_constant_return(root)
        if _run_check(root) == 0:
            fail("self-test: object_align constant-only return should fail")
        cpath.write_text(c_clean, encoding="utf-8")

        # P1-A source mutations: silent wrap / missing RX cold / OK return / no rehello.
        def expect_src_fail(label: str, mutator) -> None:
            cpath.write_text(c_clean, encoding="utf-8")
            t = cpath.read_text(encoding="utf-8")
            nt = mutator(t)
            if nt == t:
                fail(f"self-test: could not apply source mut {label}")
            cpath.write_text(nt, encoding="utf-8")
            if _run_check(root) == 0:
                fail(f"self-test: {label} should fail gate")
            cpath.write_text(c_clean, encoding="utf-8")

        expect_src_fail(
            "P1-A next_tx wrap to 0 + OK",
            lambda t: t.replace(
                "return apply_tx_seq_terminal_exhaust(s);",
                "fence_session_keep_tx_seq(s); s->next_tx_seq = 0u; "
                "return NINLIL_LOGICAL_SESSION_OK;",
            ),
        )
        expect_src_fail(
            "P1-A exhaust missing RX cold",
            lambda t: t.replace(
                "/* Matching RX cold (both directions; no half-reset). */\n"
                "    rx_only_cold(s);",
                "/* Matching RX cold removed by mutation. */",
            ),
        )
        expect_src_fail(
            "P1-A exhaust missing rehello",
            lambda t: t.replace(
                "s->rehello_armed = 1;\n"
                "        s->rehello_deadline_ms = s->now_ms; /* immediate re-HELLO */",
                "s->rehello_armed = 0;",
            ),
        )
        expect_src_fail(
            "P1-B remove max_deadline_add ceiling",
            lambda t: t.replace("max_deadline_add_ms", "max_deadline_add_ms_REMOVED", 1),
        )
        expect_src_fail(
            "P1-B revive rehello UINT64_MAX saturate",
            lambda t: t.replace(
                "if (add_u64_overflow(\n"
                "                    s->now_ms,\n"
                "                    NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS,\n"
                "                    &dl)\n"
                "                != 0) {\n"
                "                /* Pure precheck must reject the step before this path. */\n"
                "                return;\n"
                "            }\n"
                "            s->rehello_armed = 1;\n"
                "            s->rehello_deadline_ms = dl;",
                "s->rehello_armed = 1;\n"
                "            s->rehello_deadline_ms = UINT64_MAX;",
            ),
        )
        expect_src_fail(
            "P1-B revive raw rehello add wrap",
            lambda t: t.replace(
                "if (add_u64_overflow(\n"
                "                        s->now_ms,\n"
                "                        NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS,\n"
                "                        &dl)\n"
                "                    == 0) {\n"
                "                    s->rehello_armed = 1;\n"
                "                    s->rehello_deadline_ms = dl;\n"
                "                }",
                "s->rehello_armed = 1;\n"
                "                s->rehello_deadline_ms = s->now_ms\n"
                "                    + NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS;",
            ),
        )

        # Layout sentinel: remove #error from layout → compile probe must fail
        # the "alone include must error" check. Simulate by stripping sentinel.
        lpath = root / "src/transport/logical_session_layout.h"
        l_clean = lpath.read_text(encoding="utf-8")
        lpath.write_text(
            l_clean.replace(
                '#error "logical_session_layout.h is private; include logical_session.h only"',
                "/* sentinel removed */",
            ),
            encoding="utf-8",
        )
        if _run_check(root) == 0:
            fail("self-test: layout sentinel removal should fail")
        lpath.write_text(l_clean, encoding="utf-8")

    print("logical_session_u4_gate self-test OK")


def main(argv: list[str] | None = None) -> int:
    cmd = (argv or sys.argv[1:] or ["check"])[0]
    if cmd == "check":
        check()
        return 0
    if cmd == "self-test":
        self_test()
        return 0
    fail(f"unknown command {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
