#!/usr/bin/env python3
"""Documentation consistency / terminology gate for U0 radio-USB boundary freeze.

Locks Accepted ADR-0003 + docs/23 decisions without USB/SX1262 implementation code.
Structural, section/row-scoped checks (not soft global token presence). Self-test
mutates temporary copies of real docs and proves each mutation fails run_check.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

COMPONENT_ID = re.compile(r"\b(C[0-4]|A[12]|L1|P1|W1|H1|D1|K1)\b")
WIRE_ROW = re.compile(r"^(\d+)\s+(\d+)\s+(\S+)")
NEGATION_TOKENS = (
    "ない",
    "禁止",
    "未",
    "must not",
    "MUST NOT",
    "主張しない",
    "≠",
    "not equal",
    "not ",
    "ではなく",
    "否定",
    "forbidden",
    "do not",
    "Don't",
    "禁止する",
    "混同",
)

# Paths are resolved relative to a root so self-test can point at a temp tree.
class Paths:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.adr = root / "docs" / "adr" / "0003-radio-usb-dependency-direction.md"
        self.adr_index = root / "docs" / "adr" / "README.md"
        self.doc23 = root / "docs" / "23-usb-radio-boundary.md"
        self.doc_index = root / "docs" / "README.md"
        self.doc01 = root / "docs" / "01-architecture.md"
        self.doc05 = root / "docs" / "05-security-and-compliance.md"
        self.doc06 = root / "docs" / "06-versioning-and-compatibility.md"
        self.doc07 = root / "docs" / "07-testing-and-quality.md"
        self.doc09 = root / "docs" / "09-roadmap.md"
        self.doc15 = root / "docs" / "15-glossary.md"
        self.doc19 = root / "docs" / "19-m3-control-byte-stream-framing.md"
        self.doc21 = root / "docs" / "21-m3-esp-idf-durable-storage.md"
        self.doc22 = root / "docs" / "22-m3-owner-cell-agent-skeleton.md"
        self.changelog = root / "CHANGELOG.md"
        self.reviews_index = root / "docs" / "reviews" / "README.md"
        self.u0_self_review = (
            root
            / "docs"
            / "reviews"
            / "2026-07-16-u0-radio-usb-boundary-freeze-self-review.md"
        )
        self.owner_header = (
            root
            / "ports"
            / "esp-idf"
            / "include"
            / "ninlil_esp_idf"
            / "owner_task.h"
        )


P = Paths(REPO_ROOT)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def require_contains(text: str, needle: str, where: str) -> None:
    if needle not in text:
        fail(f"{where} must contain {needle!r}")


def require_regex(text: str, pattern: str, where: str) -> None:
    if re.search(pattern, text, flags=re.MULTILINE) is None:
        fail(f"{where} must match /{pattern}/")


def section_between(text: str, start_marker: str, end_marker: str | None, where: str) -> str:
    """Return body of a section starting at start_marker up to end_marker (exclusive)."""
    start = text.find(start_marker)
    if start < 0:
        fail(f"{where} missing section start {start_marker!r}")
    rest = text[start:]
    if end_marker is None:
        return rest
    end = rest.find(end_marker, len(start_marker))
    if end < 0:
        return rest
    return rest[:end]


def line_negated(line: str) -> bool:
    return any(tok in line for tok in NEGATION_TOKENS)


def parse_wire_offset_rows(section: str) -> dict[int, tuple[int, str]]:
    """Parse 'offset size field' rows from a wire-layout code block / section."""
    rows: dict[int, tuple[int, str]] = {}
    for raw in section.splitlines():
        line = raw.strip()
        m = WIRE_ROW.match(line)
        if not m:
            continue
        off = int(m.group(1))
        size = int(m.group(2))
        field = m.group(3)
        rows[off] = (size, field)
    return rows


def require_wire_row(
    rows: dict[int, tuple[int, str]],
    offset: int,
    size: int,
    field: str,
    where: str,
) -> None:
    if offset not in rows:
        fail(f"{where} missing wire row at offset {offset} (field {field!r})")
    got_size, got_field = rows[offset]
    if got_size != size or got_field != field:
        fail(
            f"{where} offset {offset}: expected size={size} field={field!r}, "
            f"got size={got_size} field={got_field!r}"
        )


def parse_target_ids(blob: str) -> list[str]:
    """Extract component IDs from an edge target list (commas, 'or', parentheticals)."""
    cleaned = re.sub(r"\([^)]*\)", " ", blob)
    cleaned = cleaned.replace(" or ", " , ")
    out: list[str] = []
    for part in re.split(r"[,/]", cleaned):
        m = COMPONENT_ID.search(part.strip())
        if m:
            out.append(m.group(1))
    return out


def parse_compile_dependency_edges(section: str) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Parse ADR §2 diagram edges: positive (-->) and forbidden (-X->)."""
    positive: set[tuple[str, str]] = set()
    forbidden: set[tuple[str, str]] = set()
    current: str | None = None
    # Component header line e.g. "C3 (NCL1 codec/session)  [portable private]"
    header_re = re.compile(
        r"^(C[0-4]|A[12]|L1|P1|W1|H1|D1|K1)\s*\(",
    )
    pos_re = re.compile(r"^\s*-->\s*(.+)$")
    neg_re = re.compile(r"^\s*-X->\s*(.+)$")

    in_code = False
    for raw in section.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            in_code = not in_code
            current = None
            continue
        if not in_code:
            continue
        hm = header_re.match(line.strip())
        if hm:
            current = hm.group(1)
            continue
        if current is None:
            continue
        pm = pos_re.match(line)
        if pm:
            for tid in parse_target_ids(pm.group(1)):
                positive.add((current, tid))
            continue
        nm = neg_re.match(line)
        if nm:
            for tid in parse_target_ids(nm.group(1)):
                forbidden.add((current, tid))
    return positive, forbidden


def parse_physical_tx_step_order(section: str) -> list[tuple[int, str]]:
    """Parse Normative TX steps as (step_number, component) in document order."""
    steps: list[tuple[int, str]] = []
    # Match "(1) W1 ..." style markers in the normative sequence block.
    for m in re.finditer(r"\((\d)\)\s*(W1|P1|H1|D1)\b", section):
        steps.append((int(m.group(1)), m.group(2)))
    return steps


def find_markdown_table_row(text: str, first_cell_pattern: str, where: str) -> str:
    """Return the full markdown table row whose first cell matches pattern.

    Row-scoped: never spans newlines (``\\s`` must not eat ``\\n`` between rows).
    """
    row_re = re.compile(
        rf"^\|\s*(?:{first_cell_pattern})\s*\|[^\n]*$",
        flags=re.MULTILINE,
    )
    m = row_re.search(text)
    if not m:
        fail(f"{where} missing table row matching first cell /{first_cell_pattern}/")
    return m.group(0)


def table_cells(row: str) -> list[str]:
    # | a | b | c | -> ['a','b','c']
    parts = row.strip().strip("|").split("|")
    return [p.strip() for p in parts]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_adr(paths: Paths) -> None:
    text = read_text(paths.adr)
    if "状態: Accepted" not in text and "状態:Accepted" not in text:
        fail("ADR-0003 must be Accepted")

    for needle in (
        "Portable logical Runtime",
        "Portable byte-stream contract",
        "NCL1 codec",
        "Composition / pump",
        "POSIX controller transport",
        "ESP USB CDC",
        "Physical Compliance",
        "Secure compact radio wire",
        "ninlil_radio_hal",
        "SX1262",
        "KGuard",
        "esp_tinyusb",
        "termios",
        "MUST NOT",
        "Compile / source dependency",
        "Runtime call / data flow",
        "immutable TX plan",
        "transmit-with-permit",
        "逆方向",
    ):
        require_contains(text, needle, "ADR-0003")

    for cid in ("C0", "C1", "C2", "C3", "C4", "A1", "A2", "P1", "W1", "H1", "D1"):
        if text.count(cid) < 2:
            fail(f"ADR-0003 component id {cid} must appear in diagram and table")

    # pinned esp_tinyusb path = path selection only; exact version/lock is U2
    require_contains(
        text,
        "path 選定のみ",
        "ADR-0003 esp_tinyusb path selection only",
    )
    require_contains(
        text,
        "exact version / lock は U2",
        "ADR-0003 esp_tinyusb exact version/lock is U2",
    )
    require_contains(
        text,
        "U0 は esp_tinyusb exact version を pin しない",
        "ADR-0003 U0 does not pin esp_tinyusb exact version",
    )

    check_adr_compile_edges(text)
    check_adr_physical_tx_order(text)


def check_adr_compile_edges(text: str) -> None:
    """Section-scoped parse of ADR §2 compile dependency edge set."""
    sec = section_between(
        text,
        "### 2. Compile / source dependency",
        "### 3. Runtime call / data flow",
        "ADR-0003 §2",
    )
    positive, forbidden = parse_compile_dependency_edges(sec)
    if not positive:
        fail("ADR-0003 §2: failed to parse any positive compile edges (-->)")

    # Critical portable stack edges (false-green if inverted to -X->)
    required_positive = {
        ("C3", "C2"),
        ("C0", "C1"),
        ("C4", "C2"),
        ("C4", "C3"),
        ("A1", "C1"),
        ("A2", "C1"),
        ("H1", "P1"),
        ("H1", "D1"),
    }
    for edge in sorted(required_positive):
        if edge not in positive:
            fail(f"ADR-0003 §2 missing required positive edge {edge[0]} --> {edge[1]}")
        if edge in forbidden:
            fail(
                f"ADR-0003 §2 edge {edge[0]} --> {edge[1]} must not also be "
                f"listed as -X-> forbidden"
            )

    # Explicit: C3 must depend on C2 (NCL1 on NCG1), never the reverse forbid
    if ("C3", "C2") in forbidden:
        fail("ADR-0003 §2 must not forbid C3 --> C2 (got C3 -X-> C2)")
    if ("C2", "C3") in positive:
        fail("ADR-0003 §2 must not claim C2 --> C3 (dependency direction inverted)")


def check_adr_physical_tx_order(text: str) -> None:
    """Section-scoped Normative physical TX order: W1 → P1 → H1 → D1."""
    if "#### 3.2 Physical RF TX path" not in text:
        fail("ADR-0003 missing '#### 3.2 Physical RF TX path' section")
    start = text.find("#### 3.2 Physical RF TX path")
    rest = text[start:]
    end_candidates = []
    for marker in ("#### 3.3", "### 4.", "## 4.", "## Consequences"):
        idx = rest.find(marker, 10)
        if idx > 0:
            end_candidates.append(idx)
    sec = rest[: min(end_candidates)] if end_candidates else rest[:3000]

    # Prefer the Normative code fence so the later summary table does not double-count.
    fence_steps: list[tuple[int, str]] = []
    fence = re.search(r"```text\n(.*?)```", sec, flags=re.DOTALL)
    if fence:
        fence_steps = parse_physical_tx_step_order(fence.group(1))
    steps = fence_steps if fence_steps else parse_physical_tx_step_order(sec)[:4]
    expected = [(1, "W1"), (2, "P1"), (3, "H1"), (4, "D1")]
    if steps != expected:
        fail(
            f"ADR-0003 §3.2 physical TX Normative step order must be {expected}, "
            f"got {steps}"
        )

    # Keyword order backup (plan before permit; permit before transmit; transmit before SPI)
    order_markers = [
        "immutable TX plan + exact frame bytes",
        "Physical Compliance Permit を発行",
        "transmit-with-permit",
        "SX1262 backend が SPI TX",
    ]
    positions: list[int] = []
    for m in order_markers:
        idx = sec.find(m)
        if idx < 0:
            fail(f"ADR-0003 §3.2 missing order marker {m!r}")
        positions.append(idx)
    if positions != sorted(positions):
        fail("ADR-0003 §3.2 physical TX order markers are not in Normative sequence")


def check_doc23(paths: Paths) -> None:
    text = read_text(paths.doc23)

    required_phrases = (
        "NCL1",
        "NCG1",
        "session_generation",
        "session_cookie",
        "request_id",
        "HELLO",
        "HELLO_ACK",
        "PING",
        "PONG",
        "RESET",
        "esp_tinyusb",
        "CDC-ACM",
        "termios",
        "poll",
        "non-custody",
        "backpressure",
        "Physical Compliance Permit",
        "sole physical TX edge",
        "unallocated",
        "Owner Task Join",
        "Network Join",
        "TASK_JOIN_ACK",
        "compile success must not equal HIL",
        "MAX_NCL1_BODY",
        "logical_magic",
        "memcpy",
        "Controller-only",
        "opaque_echo_token",
        "CTRL_ERROR",
        "SiteAssignment",
        "Required HIL",
        "payload ownership",
        "profile default",
        "multi-parent",
        "relay",
        "Network Attachment",
    )
    for needle in required_phrases:
        require_contains(text, needle, "docs/23")

    require_contains(text, "U0", "docs/23")
    for i in range(1, 8):
        if f"**U{i}**" not in text:
            fail(f"docs/23 missing slice marker **U{i}**")
    for i in range(1, 11):
        if f"**R{i}**" not in text:
            fail(f"docs/23 missing slice marker **R{i}**")

    check_doc23_r9_row(text)
    check_doc23_ncl1_layout(text)
    check_doc23_ncg1_sequence_policy(text)
    check_doc23_cookie_policy(text)
    check_doc23_hello_ack_body(text)
    check_doc23_halfopen_and_hello_table(text)
    check_doc23_type_matrix_and_validation(text)
    check_doc23_counters_and_liveness(text)
    check_doc23_reading_order_and_dx(text)

    for vid in (
        "RESET_SESSION",
        "U4-G-HELLO-OK",
        "U4-N-STALE-GEN",
        "U4-N-STALE-COOKIE",
        "U4-N-COOKIE-ZERO",
        "U4-N-SEQ-GAP",
        "U4-N-STREAM-ID",
        "U4-N-COOKIE-RNG-FAIL",
        "U4-N-CTRL-ERROR-LOOP",
        "U4-N-TYPE-BIND-PING-IN-DATA",
        "U4-N-TYPE-BIND-HELLO-IN-PING",
        "U4-G-HALFOPEN-REHELLO",
        "U4-G-HELLO-RETRY-NEXT-SEQ",
        "U4-G-ACKLOSS-LAST0-HALFOPEN",
        "U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE",
        "U4-G-RESTART-SEQ0-LAST0",
        "U4-G-RESTART-SEQ0-LAST-HIGH",
        "U4-G-RESTART-ACK-HIGH-BASELINE",
        "U4-G-CELL-RESTART-ACK0-RETRY",
        "U4-G-CELL-RXCOLD-HIGH-HELLO",
        "U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK",
        "U4-G-CELL-CONTINUITY-RESET-SESSION",
        "U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO",
        "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK",
        "U4-N-SEQ-U32-MAX",
        "U4-N-HELLO-RETRY-SEQ0-COLD",
        "U4-N-SEQ-DISCARD-NO-NCL1-PEEK",
        "U4-N-ACK-BASELINE-NONMATCH",
        "U4-N-BASELINE-NONHELLO",
        "U4-N-CONTINUITY-RESET-STALE-NEW-SESSION",
        "U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE",
        "U4-N-HELLO-INVALID-ROLE",
        "U4-N-HELLO-BAD-BOOTSTRAP",
        "BOOTSTRAP_EPOCH_RESTART",
        "SBR-HELLO",
        "SBR-ACK",
        "ncg1_reject_seq_reserved",
        "pre-fence snapshot",
        "continuity_reset_notice_cancelled",
        "fence once at detection/creation",
        "**`last_rx_seq` を前進**させる",
    ):
        require_contains(text, vid, "docs/23 vectors")

    require_contains(text, "logical_version", "docs/23")
    require_contains(text, "selected_control_version", "docs/23")
    require_contains(text, "別 domain", "docs/23 version domains")

    if "sender_unix_ms" in text and "廃止" not in text:
        fail("docs/23 must not reintroduce sender_unix_ms without abolition note")
    require_contains(text, "wall clock", "docs/23")
    require_contains(text, "opaque_echo_token", "docs/23")

    require_contains(text, "CTRL_ERROR への CTRL_ERROR 禁止", "docs/23")
    require_contains(text, "rate budget", "docs/23")

    require_contains(text, "parser", "docs/23 overflow")
    require_contains(text, "INVALID", "docs/23 overflow session")
    require_contains(text, "rx_overflow", "docs/23")

    require_contains(text, "Default entry 上限", "docs/23 queue table")
    require_contains(text, "Default byte 上限", "docs/23 queue table")
    require_contains(text, "16 entries", "docs/23")
    require_contains(text, "8192 bytes", "docs/23")
    require_contains(
        text,
        "exact 1 reserved entry",
        "docs/23 continuity-loss RESET fixed slot",
    )
    require_contains(
        text,
        "exact 30 NCL1 bytes",
        "docs/23 continuity-loss RESET slot byte bound",
    )

    for needle in (
        "O_NOCTTY",
        "DTR",
        "TIOCEXCL",
        "/dev/cu.",
        "udev",
        "EIO",
        "ENODEV",
    ):
        require_contains(text, needle, "docs/23 POSIX UX")

    require_contains(text, "immutable TX plan", "docs/23")
    require_contains(text, "SiteAssignment identity", "docs/23")
    require_contains(text, "SiteAssignment revision", "docs/23")
    require_contains(text, "SiteAssignment epoch", "docs/23")
    require_contains(text, "consume 拒否", "docs/23")

    require_contains(text, "node_fingerprint", "docs/23 must state removal")
    require_contains(text, "採用しない", "docs/23 node_fingerprint policy")

    for st in (
        "DISCONNECTED",
        "LINK_UP_NO_SESSION",
        "HELLO_SENT",
        "HELLO_RECEIVED",
        "SESSION_ACTIVE",
    ):
        require_contains(text, st, "docs/23 state machine")

    require_contains(text, "Compile / source dependency", "docs/23")
    require_contains(text, "Runtime call / data flow", "docs/23")
    for cid in ("C0", "C1", "C3", "C4", "A1", "A2", "P1", "W1", "H1", "D1"):
        require_contains(text, cid, "docs/23 component set")

    require_contains(text, "主張しない", "docs/23 non-claims")
    require_contains(text, "forbidden claims", "docs/23")
    # U1 may land as host implementation candidate; still forbid complete/HIL lies.
    require_contains(text, "SX1262 production code 未実装", "docs/23")
    require_contains(text, "U1 implementation candidate", "docs/23 U1 honesty")
    require_contains(text, "Required HIL", "docs/23 Required HIL pending")
    require_contains(
        text,
        "assignment/custody/security protocol is complete",
        "docs/23 forbidden list",
    )

    scan_positive_forbidden_claims(text, "docs/23")

    require_contains(text, "Network Attachment / Join", "docs/23 §14")
    require_contains(text, "multi-parent", "docs/23 §14")
    require_contains(text, "relay", "docs/23 §14")
    require_contains(text, "Required host gate", "docs/23 vectors")
    require_contains(text, "U4 実装 PR", "docs/23 vectors")

    # U0 ESP-IDF pin only; esp_tinyusb is path selection only; exact lock is U2
    require_contains(text, "v5.5.3", "docs/23 ESP-IDF pin v5.5.3")
    require_contains(text, "path 選定", "docs/23 esp_tinyusb path selection wording")
    require_contains(
        text,
        "exact version と lock を固定",
        "docs/23 esp_tinyusb exact version/lock deferred to U2",
    )
    # Soft global "U2" alone is not enough; ban claiming U0 pins exact esp_tinyusb version.
    sec31 = section_between(text, "### 3.1 Cell Agent", "### 3.2", "docs/23 §3.1")
    if re.search(r"esp_tinyusb.*exact version.*U0", sec31) and "固定しない" not in sec31:
        fail("docs/23 §3.1 must not claim U0 pins esp_tinyusb exact version")

    # §5.2 rule 1: session-breaking ≠ physical Link down
    check_doc23_session_vs_link_down(text)

    # Required HIL: U1 and U7 must be Linux AND macOS (not OR)
    hil = section_between(
        text,
        "#### U1–U7 acceptance と **Required HIL**",
        "### 10.2",
        "docs/23 §10.1 Required HIL",
    )
    u1_row = find_markdown_table_row(hil, r"U1", "docs/23 U1 HIL row")
    require_contains(
        u1_row,
        "Linux および macOS",
        "docs/23 U1 Required HIL Linux AND macOS",
    )
    if "Linux または macOS" in u1_row:
        fail("docs/23 U1 HIL must not weaken to Linux OR macOS")
    u7_row = find_markdown_table_row(hil, r"U7", "docs/23 U7 HIL row")
    require_contains(
        u7_row,
        "Linux および macOS",
        "docs/23 U7 Required HIL Linux AND macOS",
    )
    if "Linux または macOS" in u7_row:
        fail("docs/23 U7 HIL must not weaken to Linux OR macOS")
    require_contains(u7_row, "30 min", "docs/23 U7 soak ≥30 min")

    # Overflow recovery must remain enabled
    ov = section_between(text, "### 4.5 USB RX overflow", "### 5.", "docs/23 §4.5")
    require_contains(ov, "RX-only", "docs/23 §4.5 RX-only sequence cold on overflow")
    require_contains(ov, "有限回復", "docs/23 §4.5 finite recovery after overflow")
    require_contains(
        ov,
        "overflow 後に回復 path を無効化してよい実装は禁止",
        "docs/23 §4.5 ban disabling overflow recovery",
    )


def check_doc23_session_vs_link_down(text: str) -> None:
    """§5.2 rule 1: do not call RX overflow/RESET 'Link down'; allow HELLO without re-Link."""
    sec = section_between(
        text,
        "### 5.2 session_generation 規則",
        "### 5.3",
        "docs/23 §5.2",
    )
    # Must separate physical link down from session-breaking events.
    require_contains(sec, "session-breaking", "docs/23 §5.2 session-breaking events")
    require_contains(sec, "物理 Link down", "docs/23 §5.2 physical Link down")
    require_contains(
        sec,
        "RX overflow / parser fence / RESET 受理を「Link down」と呼ばない",
        "docs/23 §5.2 ban calling overflow/RESET Link down",
    )
    require_contains(
        sec,
        "物理 re-Link up を必須としない",
        "docs/23 §5.2 HELLO recovery without re-Link up",
    )
    # Forbidden lumping that treats overflow as Link down in rule 1.
    bad = (
        "**Link down**（unplug、open 失敗、fatal stream error、RX overflow fence、明示 RESET 受理）"
    )
    if bad in sec:
        fail(
            "docs/23 §5.2 must not lump RX overflow/RESET under Link down: "
            f"found {bad!r}"
        )


def check_doc23_r9_row(text: str) -> None:
    """R9 dependency is checked on the R-series table row only (not global phrase)."""
    row = find_markdown_table_row(text, r"\*\*R9\*\*", "docs/23 R9 table")
    cells = table_cells(row)
    if len(cells) < 3:
        fail(f"docs/23 R9 row must have ≥3 columns, got {cells!r}")
    dep_cell = cells[2]
    # Exact minimum dependency set in the dependency column
    if "R4 + R5 + R7" not in dep_cell:
        fail(
            "docs/23 R9 table dependency column must contain 'R4 + R5 + R7' "
            f"(row-scoped); got {dep_cell!r}"
        )
    for need in ("R4", "R5", "R7"):
        if need not in dep_cell:
            fail(f"docs/23 R9 dependency column missing {need}: {dep_cell!r}")
    # Weakening to R4-only in this cell must fail even if prose elsewhere keeps phrase
    if re.search(r"R4\s+only", dep_cell) and "R5" not in dep_cell:
        fail("docs/23 R9 dependency must not be weakened to R4 only")


def check_doc23_ncl1_layout(text: str) -> None:
    """Structural NCL1 header rows: cookie@16, body_length@24, HEADER=26, BODY=998."""
    sec = section_between(text, "### 7.2 NCL1 header", "### 7.3", "docs/23 §7.2")
    rows = parse_wire_offset_rows(sec)
    require_wire_row(rows, 0, 4, "logical_magic", "docs/23 §7.2")
    require_wire_row(rows, 12, 4, "session_generation", "docs/23 §7.2")
    require_wire_row(rows, 16, 8, "session_cookie", "docs/23 §7.2")
    require_wire_row(rows, 24, 2, "body_length", "docs/23 §7.2")
    require_contains(sec, "4e 43 4c 31", "docs/23 §7.2")
    require_contains(sec, "`NCL1_HEADER_BYTES`", "docs/23 §7.2")
    require_contains(sec, "**26**", "docs/23 §7.2 NCL1_HEADER_BYTES")
    require_contains(sec, "`MAX_NCL1_BODY`", "docs/23 §7.2")
    require_contains(sec, "**998**", "docs/23 §7.2 MAX_NCL1_BODY")
    require_contains(sec, "`MAX_NCL1_MESSAGE`", "docs/23 §7.2")
    require_contains(sec, "**1024**", "docs/23 §7.2 MAX_NCL1_MESSAGE")
    require_contains(sec, "1024 - 26", "docs/23 §7.2 body formula")
    require_contains(sec, "26 + body_length", "docs/23 §7.2 length rule")
    require_contains(sec, "header が唯一の wire authority", "docs/23 §7.2 cookie authority")
    if "**1006**" in sec:
        fail("docs/23 §7.2 must not retain old MAX_NCL1_BODY **1006**")
    if re.search(r"`NCL1_HEADER_BYTES`\s*\|\s*\*?\*?18\*?\*?", sec):
        fail("docs/23 §7.2 must not set NCL1_HEADER_BYTES to 18")


def check_doc23_ncg1_sequence_policy(text: str) -> None:
    """§5.5.2–5.5.3: directional epochs + authority + SBR + BOOTSTRAP_EPOCH_RESTART."""
    sec = section_between(
        text,
        "#### 5.5.2 NCG1 `sequence`",
        "### 5.6",
        "docs/23 §5.5.2",
    )
    for b in (
        "NCG1 に sequence field は無い",
        "sequence field は無い",
        "NCG1 sequence は無い",
    ):
        if b in sec:
            fail(f"docs/23 §5.5.2 must not claim sequence absence: {b!r}")

    require_contains(sec, "offset 12", "docs/23 §5.5.2 sequence offset")
    require_contains(sec, "u32 BE", "docs/23 §5.5.2 sequence type")
    require_contains(sec, "docs/19", "docs/23 §5.5.2 docs/19 cross-ref")
    require_contains(sec, "stream_or_cell_id", "docs/23 §5.5.2")
    require_contains(
        sec,
        "**exact `0`** = sole bootstrap/control stream",
        "docs/23 §5.5.2 stream_or_cell_id exact 0 sole stream",
    )
    require_contains(sec, "送信 MUST `0`", "docs/23 §5.5.2 TX must send 0")
    require_contains(sec, "方向別 epoch", "docs/23 §5.5.2 directional epochs")
    require_contains(sec, "local RX だけ cold", "docs/23 §5.5.2 RX-only cold principle")
    require_contains(sec, "TX+RX 双方 cold", "docs/23 §5.5.2 dual cold on link/restart")

    for needle in (
        "割当 authority",
        "初期値",
        "increment",
        "0 扱い",
        "duplicate",
        "gap",
        "wrap",
        "parser reset",
        "link reconnect",
        "session fence",
        "UINT32_MAX",
        "SESSION_ACTIVE",
        "next_tx_seq",
        "have_rx_seq",
        "sequence epoch",
        "exact `sequence=0`",
        "デッドロック",
        "HELLO",
        "Sequence reset authority",
        "BOOTSTRAP_EPOCH_RESTART",
        "SBR-HELLO",
        "SBR-ACK",
    ):
        require_contains(sec, needle, f"docs/23 §5.5.2 policy {needle}")

    require_contains(sec, "fail-closed", "docs/23 §5.5.2 gap/wrap fail-closed")
    require_contains(
        sec,
        "control session INVALID",
        "docs/23 §5.5.2 gap session INVALID",
    )
    # UINT32_MAX reserved terminal: TX ban + RX before SBR/BOOTSTRAP + no last+1 wrap
    require_contains(
        sec,
        "UINT32_MAX` は予約 terminal",
        "docs/23 §5.5.2 UINT32_MAX reserved terminal",
    )
    require_contains(sec, "送信禁止", "docs/23 §5.5.2 UINT32_MAX TX forbidden")
    require_contains(
        sec,
        "ncg1_reject_seq_reserved",
        "docs/23 §5.5.2 reserved sequence counter",
    )
    require_contains(
        sec,
        "SBR / `BOOTSTRAP_EPOCH_RESTART` / 通常 exact0 baseline",
        "docs/23 §5.5.2 reserved before SBR/BOOTSTRAP/baseline",
    )
    require_contains(
        sec,
        "last_rx_seq + 1` の u32 wrap",
        "docs/23 §5.5.2 ban last+1 wrap",
    )
    # Gap/overflow must be RX-only cold, not dual cold of TX.
    require_contains(
        sec,
        "local RX sequence epoch cold のみ",
        "docs/23 §5.5.2 gap RX-only cold",
    )
    require_contains(
        sec,
        "local TX `next_tx_seq` **継続**",
        "docs/23 §5.5.2 gap TX continues",
    )
    # RESET_PARSER: separate TX-accept and RX rows; each end RX-only + local TX continues
    rp_tx = find_markdown_table_row(
        sec,
        r"`RESET_PARSER`\s+\*\*送信 accept\*\*（自端）",
        "docs/23 §5.5.2 RESET_PARSER TX-accept authority row",
    )
    rp_tx_cells = table_cells(rp_tx)
    if len(rp_tx_cells) < 3:
        fail(f"docs/23 §5.5.2 RESET_PARSER TX row too short: {rp_tx!r}")
    require_contains(rp_tx_cells[1], "継続", "docs/23 §5.5.2 RESET_PARSER TX-accept local TX continues")
    require_contains(rp_tx_cells[2], "cold", "docs/23 §5.5.2 RESET_PARSER TX-accept local RX cold")
    rp_rx = find_markdown_table_row(
        sec,
        r"`RESET_PARSER`\s+\*\*受信\*\*（自端）",
        "docs/23 §5.5.2 RESET_PARSER RX authority row",
    )
    rp_rx_cells = table_cells(rp_rx)
    if len(rp_rx_cells) < 3:
        fail(f"docs/23 §5.5.2 RESET_PARSER RX row too short: {rp_rx!r}")
    require_contains(rp_rx_cells[1], "継続", "docs/23 §5.5.2 RESET_PARSER RX local TX continues")
    require_contains(rp_rx_cells[2], "cold", "docs/23 §5.5.2 RESET_PARSER RX local RX cold")
    # RESET_LINK: session immediate INVALID; sequence cold on observed reopen
    rl_row = find_markdown_table_row(
        sec,
        r"`RESET_LINK`\s+送信 accept / 受信",
        "docs/23 §5.5.2 RESET_LINK authority row",
    )
    require_contains(rl_row, "即 INVALID", "docs/23 §5.5.2 RESET_LINK session immediate INVALID")
    require_contains(
        rl_row,
        "観測した link reopen",
        "docs/23 §5.5.2 RESET_LINK sequence colds on reopen",
    )
    require_contains(sec, "Attachment", "docs/23 §5.5.2 Attachment boundary")
    require_contains(sec, "未割当", "docs/23 §5.5.2 non-zero IDs unallocated")
    require_contains(
        sec,
        "gap 直前の `last_rx_seq+1` を期待し続けてはならない",
        "docs/23 §5.5.2 post-gap next expectation",
    )
    # HELLO timeout authority row: next_tx_seq, not cold→seq0.
    hello_retry_row = find_markdown_table_row(
        sec,
        r".*HELLO_ACK timeout retry.*",
        "docs/23 §5.5.2 HELLO_ACK timeout authority row",
    )
    hello_cells = table_cells(hello_retry_row)
    if len(hello_cells) < 2:
        fail(f"docs/23 §5.5.2 HELLO timeout row too short: {hello_retry_row!r}")
    tx_cell = hello_cells[1]
    require_contains(
        tx_cell,
        "cold しない",
        "docs/23 §5.5.2 HELLO timeout TX cell does not cold",
    )
    require_contains(
        tx_cell,
        "next_tx_seq",
        "docs/23 §5.5.2 HELLO timeout TX cell uses next_tx_seq",
    )
    if "cold → 0" in tx_cell:
        fail(
            "docs/23 §5.5.2 HELLO timeout TX cell must not cold→0: "
            f"{tx_cell!r}"
        )
    require_contains(
        tx_cell,
        "seq1",
        "docs/23 §5.5.2 next HELLO after seq0 is seq1 (TX cell)",
    )
    # RESET_SESSION must continue both sequences (row-scoped).
    reset_sess_row = find_markdown_table_row(
        sec,
        r"`RESET_SESSION`",
        "docs/23 §5.5.2 RESET_SESSION authority row",
    )
    reset_cells = table_cells(reset_sess_row)
    if len(reset_cells) < 3:
        fail(f"docs/23 §5.5.2 RESET_SESSION row too short: {reset_sess_row!r}")
    for idx, label in ((1, "TX"), (2, "RX")):
        cell = reset_cells[idx]
        require_contains(
            cell,
            "cold しない",
            f"docs/23 §5.5.2 RESET_SESSION {label} cell does not cold",
        )
        if "cold → 0" in cell:
            fail(
                f"docs/23 §5.5.2 RESET_SESSION {label} cell must not cold→0: "
                f"{cell!r}"
            )
    require_contains(
        sec,
        "双方 sequence を無条件 0",
        "docs/23 §5.5.2 ban unconditional dual sequence zero",
    )

    # §5.5.3 semantic baseline resync + BOOTSTRAP
    boot = section_between(
        text,
        "#### 5.5.3 Semantic baseline resync",
        "### 5.6",
        "docs/23 §5.5.3",
    )
    require_contains(boot, "Valid HELLO bootstrap", "docs/23 §5.5.3 valid HELLO")
    require_contains(boot, "atomic", "docs/23 §5.5.3 atomic accept/fence")
    require_contains(
        boot,
        "atomic accept",
        "docs/23 §5.5.3 atomic accept phrase (SBR/BOOTSTRAP)",
    )
    require_contains(boot, "無条件最終 discard", "docs/23 §5.5.3 no unconditional discard")
    require_contains(boot, "NCL1", "docs/23 §5.5.3 NCL1 peek")
    require_contains(boot, "type **`DATA`**", "docs/23 §5.5.3 DATA type")
    require_contains(boot, "SBR-HELLO", "docs/23 §5.5.3 SBR-HELLO")
    require_contains(boot, "SBR-ACK", "docs/23 §5.5.3 SBR-ACK")
    require_contains(boot, "BOOTSTRAP_EPOCH_RESTART", "docs/23 §5.5.3 BOOTSTRAP")
    # SBR table must atomic-accept (not reject) any sequence for the two cases.
    sbr_hello_row = find_markdown_table_row(boot, r"\*\*SBR-HELLO\*\*", "docs/23 §5.5.3 SBR-HELLO row")
    require_contains(sbr_hello_row, "atomic accept", "docs/23 §5.5.3 SBR-HELLO atomic accept")
    if "reject" in sbr_hello_row.lower() and "atomic accept" not in sbr_hello_row:
        fail("docs/23 §5.5.3 SBR-HELLO must atomic accept, not bare reject")
    sbr_ack_row = find_markdown_table_row(boot, r"\*\*SBR-ACK\*\*", "docs/23 §5.5.3 SBR-ACK row")
    require_contains(sbr_ack_row, "atomic accept", "docs/23 §5.5.3 SBR-ACK atomic accept")
    require_contains(boot, "error ACK も matching", "docs/23 §5.5.3 error ACK matching")
    require_contains(boot, "非 HELLO / 非 matching HELLO_ACK", "docs/23 §5.5.3 non-HELLO ban")

    bad_retry = (
        "local sequence epoch cold + cancel prior HELLO inflight\n"
        "       + re-send valid HELLO at sequence=0"
    )
    if bad_retry in text:
        fail(
            "docs/23 must not prescribe same-process HELLO timeout cold+seq0 retry "
            f"(deadlock with Cell last_rx_seq=0): found {bad_retry!r}"
        )


def check_doc23_cookie_policy(text: str) -> None:
    """Cookie generation fail-closed + all-active header match (not body-only)."""
    gen = section_between(
        text,
        "#### 5.2.1 session_cookie 生成",
        "### 5.3",
        "docs/23 §5.2.1",
    )
    require_contains(gen, "CSPRNG", "docs/23 §5.2.1")
    require_contains(gen, "承認済み", "docs/23 §5.2.1 approved random")
    require_contains(gen, "cryptographic random", "docs/23 §5.2.1 cryptographic source")
    require_contains(gen, "fail-closed", "docs/23 §5.2.1")
    require_contains(gen, "HELLO_OK", "docs/23 §5.2.1")
    require_contains(gen, "出してはならない", "docs/23 §5.2.1 no HELLO_OK without RNG")
    require_contains(gen, "durable counter", "docs/23 §5.2.1 durable ban label")
    require_contains(gen, "U4 では代替として認めない", "docs/23 §5.2.1 no durable alt")
    require_contains(
        gen,
        "「entropy または単調カウンタ混合」は禁止",
        "docs/23 §5.2.1 explicit ban of entropy/counter mix",
    )
    for line in gen.splitlines():
        if "entropy または単調カウンタ混合" in line and "禁止" not in line:
            fail(
                "docs/23 §5.2.1 must not prescribe ambiguous entropy/counter mix "
                f"as method: {line!r}"
            )

    perm = section_between(
        text,
        "### 7.4 session_generation / session_cookie / request_id 許可表",
        "## 8.",
        "docs/23 §7.4",
    )
    require_contains(perm, "PING_BODY", "docs/23 §7.4")
    require_contains(perm, "PONG_BODY", "docs/23 §7.4")
    require_contains(perm, "RESET_BODY", "docs/23 §7.4")
    require_contains(perm, "active と一致", "docs/23 §7.4 active cookie match")
    require_contains(perm, "全 active message", "docs/23 §7.4 all-active cookie requirement")
    require_contains(
        perm,
        "cookie を HELLO_ACK にしか載せない設計は **U4 では禁止**",
        "docs/23 §7.4 body-only cookie ban",
    )


def check_doc23_hello_ack_body(text: str) -> None:
    """HELLO_ACK body is 8 bytes; cookie not in body; OK ≠ unused convention."""
    sec = section_between(text, "### 8.4 HELLO / HELLO_ACK", "### 8.5", "docs/23 §8.4")
    require_contains(sec, "HELLO_ACK body", "docs/23 §8.4")
    if "body_length exact **16**" in sec:
        fail("docs/23 §8.4 must not keep HELLO_ACK body_length exact **16**")
    require_contains(sec, "body_length exact **8**", "docs/23 §8.4 HELLO_ACK body length")
    require_contains(sec, "cookie は **含めない**", "docs/23 §8.4 no body cookie")
    require_contains(
        sec,
        "規約上の「未使用/未確立」値 0 ではない",
        "docs/23 §8.4 HELLO_OK cookie convention text",
    )
    require_contains(sec, "CSPRNG", "docs/23 §8.4")
    pong = section_between(text, "### 8.2 PING / PONG", "### 8.3", "docs/23 §8.2")
    require_contains(pong, "body_length exact **8**", "docs/23 §8.2")


def check_doc23_role_matrix(sec: str) -> None:
    """Exact-parse each role-matrix row cell (HELLO C-only … RESET/CTRL both)."""
    require_contains(sec, "送信 role matrix", "docs/23 §5.6 role matrix heading")
    # Expected: message | Controller TX | Cell TX | note
    expected: dict[str, tuple[str, str]] = {
        r"`HELLO`": ("**のみ**", "✗"),
        r"`HELLO_ACK`": ("✗", "**のみ**"),
        r"`PING_BODY`": ("**のみ**", "✗"),
        r"`PONG_BODY`": ("✗", "**のみ**"),
        r"`RESET_BODY`": ("**双方可**", "**双方可**"),
        r"`CTRL_ERROR`": ("**双方可**", "**双方可**"),
    }
    for first, (ctrl, cell) in expected.items():
        row = find_markdown_table_row(sec, first, f"docs/23 §5.6 role matrix {first}")
        cells = table_cells(row)
        if len(cells) < 3:
            fail(f"docs/23 §5.6 role matrix row too short for {first}: {row!r}")
        ctrl_cell, cell_cell = cells[1], cells[2]
        if ctrl_cell != ctrl:
            fail(
                f"docs/23 §5.6 role matrix {first} Controller TX cell "
                f"must be exact {ctrl!r}, got {ctrl_cell!r}"
            )
        if cell_cell != cell:
            fail(
                f"docs/23 §5.6 role matrix {first} Cell TX cell "
                f"must be exact {cell!r}, got {cell_cell!r}"
            )
        # Explicit bans for common false-greens
        if first == r"`HELLO`" and "双方可" in cell_cell:
            fail("docs/23 §5.6 HELLO must not allow Cell TX")
        if first == r"`RESET_BODY`" and ("✗" in cell_cell or "禁止" in cell_cell):
            fail(
                "docs/23 §5.6 RESET_BODY Cell TX must remain 双方可, "
                f"got {cell_cell!r}"
            )
        if first == r"`RESET_BODY`" and ("✗" in ctrl_cell or "禁止" in ctrl_cell):
            fail(
                "docs/23 §5.6 RESET_BODY Controller TX must remain 双方可, "
                f"got {ctrl_cell!r}"
            )


def check_doc23_halfopen_and_hello_table(text: str) -> None:
    """Half-open / reverse-ACK / RX-only-cold recovery + HELLO SM must be deadlock-free."""
    sec = section_between(text, "### 5.6 状態機械", "## 6.", "docs/23 §5.6")
    for needle in (
        "Valid HELLO bootstrap",
        "session_generation=0",
        "session_cookie=0",
        "HELLO を active cookie / active generation 一致検査で拒否してはならない",
        "half-open recovery",
        "HELLO_RECEIVED",
        "next_tx_seq",
        "BOOTSTRAP_EPOCH_RESTART",
        "SBR-HELLO",
        "SBR-ACK",
        "デッドロック禁止",
        "hello_invalid_role",
        "hello_invalid_bootstrap",
        "duplicate valid HELLO",
        "送信 role matrix",
    ):
        require_contains(sec, needle, f"docs/23 §5.6 {needle}")

    # Role matrix: exact per-row cell parse (false-green if soft global only)
    check_doc23_role_matrix(sec)

    # HELLO_SENT timeout path: must use next_tx_seq without cold
    require_contains(
        sec,
        "sequence epoch を **cold しない**",
        "docs/23 §5.6 HELLO_SENT timeout no cold",
    )
    require_contains(
        sec,
        "re-send valid HELLO at **`next_tx_seq`**",
        "docs/23 §5.6 HELLO_SENT retry next_tx_seq",
    )
    require_contains(
        sec,
        "SBR-ACK",
        "docs/23 §5.6 HELLO_SENT reverse ACK path",
    )

    half = section_between(
        text,
        "#### 5.6.1 Half-open / reverse-ACK",
        "#### 5.6.2",
        "docs/23 §5.6.1",
    )
    require_contains(half, "Controller process restart", "docs/23 §5.6.1 restart")
    require_contains(half, "HELLO_ACK 喪失", "docs/23 §5.6.1 ack loss")
    require_contains(half, "USB 物理 link down", "docs/23 §5.6.1 no physical down")
    require_contains(
        half,
        "active cookie 一致検査で HELLO を拒否すると **回復不能デッドロック**",
        "docs/23 §5.6.1 deadlock ban",
    )
    require_contains(half, "last_rx_seq=0", "docs/23 §5.6.1 last_rx_seq=0 ACK-loss case")
    require_contains(half, "BOOTSTRAP_EPOCH_RESTART", "docs/23 §5.6.1 bootstrap restart")
    require_contains(half, "next_tx_seq", "docs/23 §5.6.1 next_tx_seq retry")
    require_contains(half, "seq1", "docs/23 §5.6.1 seq1 after seq0")
    # Reverse ACK / high baseline recovery (false-green if deleted)
    require_contains(half, "SBR-ACK", "docs/23 §5.6.1 SBR-ACK reverse recovery")
    require_contains(half, "SBR-HELLO", "docs/23 §5.6.1 SBR-HELLO peer-continuation")
    require_contains(half, "RX-only cold", "docs/23 §5.6.1 RX-only cold recovery")
    require_contains(half, "reverse ACK", "docs/23 §5.6.1 reverse ACK wording")
    require_contains(
        half,
        "exact0 だけで永久拒否",
        "docs/23 §5.6.1 ban exact0-only reverse reject",
    )
    require_contains(
        half,
        "唯一の必須脱出口にしない",
        "docs/23 §5.6.1 RESET_LINK not sole exit",
    )
    # Cell continuity-loss notice order (exact)
    require_contains(half, "pre-fence snapshot", "docs/23 §5.6.1 pre-fence snapshot")
    require_contains(
        half,
        "Cell continuity-loss 通知順序",
        "docs/23 §5.6.1 continuity-loss order heading",
    )
    require_contains(
        half,
        "高優先 `RESET_SESSION` notice を最大 1 件だけ作成",
        "docs/23 §5.6.1 max one RESET_SESSION notice",
    )
    require_contains(
        half,
        "local fence は絶対に戻さない",
        "docs/23 §5.6.1 WOULD_BLOCK does not reverse local fence",
    )
    require_contains(
        half,
        "他の旧 session message",
        "docs/23 §5.6.1 ban other old-session TX after fence",
    )
    require_contains(
        half,
        "物理 re-Link up を必須脱出口にしない",
        "docs/23 §5.6.1 no physical re-Link required",
    )
    # P1-A: pending continuity-loss RESET notice lifecycle (exact)
    require_contains(
        half,
        "Pending Cell continuity-loss RESET notice lifecycle",
        "docs/23 §5.6.1 pending notice lifecycle heading",
    )
    require_contains(
        half,
        "fence once at detection/creation",
        "docs/23 §5.6.1 fence once at detection/creation",
    )
    require_contains(
        half,
        "通常 `RESET_SESSION` 送信 accept の sender fence を再実行してはならない",
        "docs/23 §5.6.1 raw-adapter TX accept must not re-fence",
    )
    require_contains(
        half,
        "not-yet-raw-adapter-accepted",
        "docs/23 §5.6.1 cancel not-yet-accepted notice",
    )
    require_contains(
        half,
        "continuity_reset_notice_cancelled++",
        "docs/23 §5.6.1 cancel counter",
    )
    require_contains(
        half,
        "strict FIFO",
        "docs/23 §5.6.1 already-accepted strict FIFO",
    )
    require_contains(
        half,
        "reorder 禁止",
        "docs/23 §5.6.1 no reorder after accept",
    )
    require_contains(
        half,
        "cancel before raw-adapter accept",
        "docs/23 §5.6.1 cancel consumes no NCG1 sequence phrase",
    )
    require_contains(
        half,
        "NCG1 sequence を消費しない",
        "docs/23 §5.6.1 cancel no sequence consume",
    )
    # Fair-delivery
    require_contains(half, "Fair-delivery", "docs/23 §5.6.1 fair-delivery")
    require_contains(half, "単なる link up は delivery 保証ではない", "docs/23 §5.6.1 link-up not delivery")
    require_contains(half, "無限 packet loss", "docs/23 §5.6.1 no infinite-loss claim")
    require_contains(half, "継続的に read/write", "docs/23 §5.6.1 continuous USB stream")
    require_contains(half, "少なくとも一組", "docs/23 §5.6.1 HELLO/ACK pair delivery")
    require_contains(half, "hello_retry_max", "docs/23 §5.6.1 retry delay cap")
    require_contains(half, "有限時間", "docs/23 §5.6.1 finite recovery under assumption")

    vec = section_between(
        text,
        "#### 5.6.2 HELLO 遷移ベクトル",
        "## 6.",
        "docs/23 §5.6.2",
    )
    for vid in (
        "U4-G-ACKLOSS-LAST0-HALFOPEN",
        "U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE",
        "U4-G-RESTART-SEQ0-LAST0",
        "U4-G-RESTART-SEQ0-LAST-HIGH",
        "U4-G-RESTART-ACK-HIGH-BASELINE",
        "U4-G-CELL-RESTART-ACK0-RETRY",
        "U4-G-CELL-RXCOLD-HIGH-HELLO",
        "U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK",
        "U4-G-CELL-CONTINUITY-RESET-SESSION",
        "U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO",
        "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK",
        "U4-N-SEQ-U32-MAX",
        "U4-G-HELLO-RETRY-NEXT-SEQ",
        "U4-N-HELLO-RETRY-SEQ0-COLD",
        "U4-N-SEQ-DISCARD-NO-NCL1-PEEK",
        "U4-N-ACK-BASELINE-NONMATCH",
        "U4-N-BASELINE-NONHELLO",
        "U4-N-CONTINUITY-RESET-STALE-NEW-SESSION",
        "U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE",
    ):
        require_contains(vec, vid, f"docs/23 §5.6.2 vector {vid}")

    for bad in (
        "SESSION_ACTIVE 中の HELLO は active cookie 不一致で reject して session 維持",
        "HELLO は active cookie と一致する場合のみ受理",
        "SESSION_ACTIVE 中の valid HELLO を reject し旧 session を維持",
    ):
        if bad in text:
            fail(f"docs/23 must not prescribe HELLO active-cookie false reject: {bad!r}")

    require_contains(
        sec,
        "旧 session を明示 fence",
        "docs/23 §5.6 ACTIVE HELLO fences old session",
    )


def check_doc23_type_matrix_and_validation(text: str) -> None:
    """Closed NCG1↔NCL1 matrix (not typical) + exact validation order."""
    mat = section_between(
        text,
        "### 7.3 message_type catalog",
        "### 7.4",
        "docs/23 §7.3",
    )
    if "典型 NCG1 type" in mat:
        fail("docs/23 §7.3 must not use soft '典型 NCG1 type' wording")
    require_contains(mat, "Closed exact binding matrix", "docs/23 §7.3 closed matrix")
    require_contains(mat, "独立した数値名前空間", "docs/23 §7.3 namespace separation")
    require_contains(mat, "ncl1_reject_type_binding", "docs/23 §7.3 binding counter")
    require_contains(mat, "ERR_TYPE_BINDING", "docs/23 §7.3 binding error")
    # Exact allowed bindings appear in matrix prose/table
    require_contains(mat, "`PING_BODY`", "docs/23 §7.3 PING_BODY")
    require_contains(mat, "`HELLO`", "docs/23 §7.3 HELLO")
    require_contains(mat, "PING_BODY` inside NCG1 `DATA`", "docs/23 §7.3 ping-in-data reject")
    require_contains(
        mat,
        "`HELLO` / `HELLO_ACK` / `CTRL_ERROR` inside NCG1 `PING`",
        "docs/23 §7.3 hello-in-ping reject",
    )

    # Table-row scoped: HELLO allowed only under DATA (not PING).
    hello_row = find_markdown_table_row(mat, r"`HELLO`\s+0x01", "docs/23 §7.3.2 HELLO matrix row")
    cells = table_cells(hello_row)
    # cells: [label, PING, PONG, DATA, RESET, other]
    if len(cells) < 5:
        fail(f"docs/23 §7.3.2 HELLO matrix row has too few cells: {hello_row!r}")
    if "**✓**" not in cells[3] and "✓" not in cells[3]:
        fail("docs/23 §7.3.2 HELLO must be allowed under NCG1 DATA (row-scoped)")
    if "✗" not in cells[1] and "x" not in cells[1].lower():
        fail("docs/23 §7.3.2 HELLO must NOT be allowed under NCG1 PING (row-scoped)")

    val = section_between(text, "### 8.1 共通 validation", "### 8.2", "docs/23 §8.1")
    require_contains(val, "この順", "docs/23 §8.1 ordered validation")
    # Order markers must appear in increasing positions
    steps = [
        "1. **NCG1 framing / stream / sequence**",
        "2. **NCL1 最低長 / header / version / flags / length**",
        "3. **`message_type` 判明**",
        "4. **exact NCG1-type binding**",
        "5. **body layout**",
        "6. **generation / cookie / request_id**",
        "7. **reserved**",
    ]
    positions: list[int] = []
    for s in steps:
        idx = val.find(s)
        if idx < 0:
            fail(f"docs/23 §8.1 missing validation step {s!r}")
        positions.append(idx)
    if positions != sorted(positions):
        fail("docs/23 §8.1 validation steps are not in required order")
    require_contains(
        val,
        "type binding より前に state/cookie で落として HELLO half-open を潰してはならない",
        "docs/23 §8.1 half-open ordering guard",
    )
    require_contains(val, "BOOTSTRAP_EPOCH_RESTART", "docs/23 §8.1 bootstrap peek exception")
    require_contains(val, "SBR-HELLO", "docs/23 §8.1 SBR-HELLO peek")
    require_contains(val, "SBR-ACK", "docs/23 §8.1 SBR-ACK peek")
    require_contains(val, "atomic accept", "docs/23 §8.1 atomic accept for SBR")
    require_contains(val, "無条件最終 discard", "docs/23 §8.1 ban unconditional seq discard")
    require_contains(
        val,
        "non-HELLO / non-matching ACK は baseline にしない",
        "docs/23 §8.1 non-HELLO baseline ban",
    )
    # UINT32_MAX reserved before SBR/BOOTSTRAP
    require_contains(val, "予約 terminal", "docs/23 §8.1 reserved terminal step")
    require_contains(val, "UINT32_MAX", "docs/23 §8.1 UINT32_MAX in validation")
    require_contains(
        val,
        "ncg1_reject_seq_reserved",
        "docs/23 §8.1 reserved counter on reject",
    )
    require_contains(
        val,
        "SBR / `BOOTSTRAP_EPOCH_RESTART` / 通常 baseline",
        "docs/23 §8.1 reserved before SBR/BOOTSTRAP/baseline",
    )
    # Position: reserved terminal prose must appear before SBR-HELLO mention in step 1
    reserved_idx = val.find("予約 terminal")
    sbr_idx = val.find("SBR-HELLO")
    if reserved_idx < 0 or sbr_idx < 0 or reserved_idx > sbr_idx:
        fail("docs/23 §8.1 reserved terminal must be specified before SBR-HELLO path")

    reset = section_between(text, "### 8.3 RESET", "### 8.4", "docs/23 §8.3")
    require_contains(reset, "no-ack", "docs/23 §8.3 no-ack")
    require_contains(reset, "専用 ACK message は存在しない", "docs/23 §8.3 no dedicated ack")
    require_contains(reset, "re-HELLO", "docs/23 §8.3 re-HELLO")
    require_contains(reset, "local", "docs/23 §8.3 local fence/timer")
    require_contains(reset, "双方", "docs/23 §8.3 both roles may send RESET")
    require_contains(
        reset,
        "inflight map へ入れない",
        "docs/23 §8.3 RESET request_id not in inflight map",
    )
    require_contains(
        reset,
        "sequence 継続",
        "docs/23 §8.3 RESET_SESSION does not cold sequence",
    )
    require_contains(
        reset,
        "RX parser + RX sequence epoch のみ cold",
        "docs/23 §8.3 RESET_PARSER each-end RX-only cold",
    )
    require_contains(
        reset,
        "各端の local TX は継続",
        "docs/23 §8.3 RESET_PARSER each-end local TX continues",
    )
    require_contains(
        reset,
        "session 即 INVALID",
        "docs/23 §8.3 RESET_LINK session immediate INVALID",
    )
    require_contains(
        reset,
        "観測した link reopen",
        "docs/23 §8.3 RESET_LINK colds on reopen",
    )
    require_contains(
        reset,
        "唯一の必須脱出口にしない",
        "docs/23 §8.3 RESET_LINK not sole required exit",
    )
    require_contains(
        reset,
        "pre-fence snapshot",
        "docs/23 §8.3 continuity-loss pre-fence snapshot ref",
    )
    require_contains(
        reset,
        "pre-fence snapshot は送信権限だけ",
        "docs/23 §8.3 pre-fence authority is sender-only",
    )
    require_contains(
        reset,
        "sequence validation/accept が先",
        "docs/23 §8.3 stale RESET sequence validation first",
    )
    require_contains(
        reset,
        "`last_rx_seq` を前進させたうえで",
        "docs/23 §8.3 continuous stale advances last_rx_seq",
    )
    require_contains(
        reset,
        "sequence を rollback しない",
        "docs/23 §8.3 stale must not roll sequence back",
    )
    require_contains(
        reset,
        "新 session を fence しない",
        "docs/23 §8.3 stale reset must not fence a new session",
    )
    require_contains(
        reset,
        "stale RESET に SBR/baseline 特権なし",
        "docs/23 §8.3 stale RESET no SBR/baseline privilege",
    )
    require_contains(
        reset,
        "raw-adapter TX accept で通常 `RESET_SESSION` sender fence を再実行しない",
        "docs/23 §8.3 pending notice fence once on TX accept",
    )
    require_contains(
        reset,
        "continuity_reset_notice_cancelled++",
        "docs/23 §8.3 cancel counter on HELLO",
    )
    # Row-scoped RESET_PARSER / RESET_LINK
    rp_row = find_markdown_table_row(reset, r"0x02", "docs/23 §8.3 RESET_PARSER row")
    require_contains(rp_row, "`RESET_PARSER`", "docs/23 §8.3 RESET_PARSER name")
    require_contains(rp_row, "送信端", "docs/23 §8.3 RESET_PARSER TX-accept end")
    require_contains(rp_row, "受信端", "docs/23 §8.3 RESET_PARSER RX end")
    require_contains(rp_row, "local TX", "docs/23 §8.3 RESET_PARSER local TX continues")
    rl_row = find_markdown_table_row(reset, r"0x03", "docs/23 §8.3 RESET_LINK row")
    require_contains(rl_row, "`RESET_LINK`", "docs/23 §8.3 RESET_LINK name")
    require_contains(rl_row, "即 INVALID", "docs/23 §8.3 RESET_LINK immediate INVALID row")
    require_contains(rl_row, "双方 cold", "docs/23 §8.3 RESET_LINK dual cold on reopen")

    # §7.4 RESET_BODY cookie column must match active ≠0 (not allow cookie=0).
    perm = section_between(
        text,
        "### 7.4 session_generation / session_cookie / request_id 許可表",
        "## 8.",
        "docs/23 §7.4",
    )
    reset_row = find_markdown_table_row(
        perm,
        r"`RESET_BODY`（\*\*peer が SESSION_ACTIVE 中に送る通常 RESET\*\*）",
        "docs/23 §7.4 RESET_BODY row",
    )
    reset_cells = table_cells(reset_row)
    # | message | generation | cookie | request_id |
    if len(reset_cells) < 3:
        fail(f"docs/23 §7.4 RESET_BODY row too short: {reset_row!r}")
    cookie_cell = reset_cells[2]
    if "active と一致" not in cookie_cell and "pre-fence snapshot" not in cookie_cell:
        fail(
            "docs/23 §7.4 RESET_BODY cookie column must require active match "
            f"or pre-fence snapshot, got {cookie_cell!r}"
        )
    if "0 許可" in cookie_cell or "cookie=0" in cookie_cell:
        fail("docs/23 §7.4 RESET_BODY must not allow cookie=0 while active")
    # Continuity-loss RESET row must exist with pre-fence snapshot
    cont_row = find_markdown_table_row(
        perm,
        r"`RESET_BODY`（\*\*Cell continuity-loss 通知; §5\.6\.1\*\*）",
        "docs/23 §7.4 RESET continuity-loss row",
    )
    require_contains(
        cont_row,
        "pre-fence snapshot",
        "docs/23 §7.4 continuity-loss uses pre-fence snapshot",
    )
    require_contains(
        perm,
        "受信側に stale 許可例外はない",
        "docs/23 §7.4 receiver has no stale reset exception",
    )
    require_contains(
        perm,
        "新 session / current session を fence してはならない",
        "docs/23 §7.4 stale reset cannot fence new session",
    )
    require_contains(
        perm,
        "sequence validation/accept が先",
        "docs/23 §7.4 stale sequence validation first",
    )
    require_contains(
        perm,
        "**`last_rx_seq` を前進**させる",
        "docs/23 §7.4 continuous stale advances last_rx_seq",
    )
    require_contains(
        perm,
        "sequence を rollback してはならない",
        "docs/23 §7.4 must not roll sequence back",
    )
    require_contains(
        perm,
        "SBR / `BOOTSTRAP_EPOCH_RESTART` / baseline 特権はない",
        "docs/23 §7.4 stale RESET no SBR/baseline privilege",
    )
    require_contains(
        perm,
        "active mismatch と non-active drop の両方",
        "docs/23 §7.4 stale rules apply active and non-active",
    )


def check_doc23_counters_and_liveness(text: str) -> None:
    """Private structured counter catalog + monotonic liveness profile defaults."""
    ctr = section_between(
        text,
        "### 8.10 Structured counter",
        "### 8.11",
        "docs/23 §8.10",
    )
    require_contains(ctr, "u64", "docs/23 §8.10 u64")
    require_contains(ctr, "saturating", "docs/23 §8.10 saturating")
    require_contains(ctr, "snapshot", "docs/23 §8.10 snapshot")
    require_contains(ctr, "reset", "docs/23 §8.10 reset policy")
    # HELLO success must NOT reset counters (row/phrase scoped).
    require_contains(
        ctr,
        "HELLO 成功では reset しない",
        "docs/23 §8.10 no counter reset on HELLO success",
    )
    if "HELLO 成功で reset する" in ctr or "HELLO 成功で counter を 0" in ctr:
        fail("docs/23 §8.10 must not reset counters on HELLO success")
    for name in (
        "rx_overflow",
        "ncl1_reject_type_binding",
        "ncl1_reject_unknown_message_type",
        "hello_halfopen_fence",
        "hello_bootstrap_epoch_restart",
        "hello_baseline_resync",
        "hello_ack_baseline_resync",
        "hello_retry",
        "pong_miss",
        "ping_dispatch_miss",
        "liveness_fail",
        "session_fence_inflight_dropped",
        "continuity_reset_notice_cancelled",
        "ncg1_reject_seq_reserved",
        "ncg1_reject_seq_gap",
    ):
        require_contains(ctr, name, f"docs/23 §8.10 counter {name}")

    live = section_between(
        text,
        "### 8.11 Liveness / HELLO retry profile default",
        "## 9.",
        "docs/23 §8.11",
    )
    require_contains(live, "monotonic clock のみ", "docs/23 §8.11 monotonic only")
    if "wall clock" in live and "禁止" not in live:
        fail("docs/23 §8.11 must ban wall clock for liveness")
    require_contains(live, "wall clock", "docs/23 §8.11 wall clock ban mention")
    require_contains(live, "禁止", "docs/23 §8.11 ban")
    for param in (
        "ping_cadence",
        "ping_dispatch_slack",
        "pong_timeout",
        "pong_miss_threshold",
        "hello_retry_initial",
        "hello_retry_max",
        "hello_backoff_multiplier",
        "hello_retry_jitter",
        "hello_retry_unlimited_while_link_up",
        "rehello_after_reset_delay",
    ):
        require_contains(live, param, f"docs/23 §8.11 param {param}")
    require_contains(live, "**5000 ms**", "docs/23 §8.11 ping_cadence default")
    # Row-scoped: ping_dispatch_slack value must be **1000 ms** (not only elsewhere).
    slack_row = find_markdown_table_row(
        live,
        r"`ping_dispatch_slack`",
        "docs/23 §8.11 ping_dispatch_slack row",
    )
    require_contains(
        slack_row,
        "**1000 ms**",
        "docs/23 §8.11 ping_dispatch_slack default row-scoped",
    )
    if "**60000 ms**" in slack_row or "60000" in slack_row:
        fail("docs/23 §8.11 ping_dispatch_slack must not be 60000")
    require_contains(live, "**2000 ms**", "docs/23 §8.11 pong_timeout default")
    require_contains(live, "**3**", "docs/23 §8.11 miss threshold")
    retry_row = find_markdown_table_row(
        live,
        r"`hello_retry_unlimited_while_link_up`",
        "docs/23 §8.11 hello_retry_unlimited row",
    )
    require_contains(retry_row, "**true**", "docs/23 §8.11 hello_retry_unlimited true")
    if "**false**" in retry_row:
        fail("docs/23 §8.11 hello_retry_unlimited_while_link_up must not be false")
    require_contains(live, "U7 HIL/soak", "docs/23 §8.11 U7 update path")
    require_contains(live, "half-open", "docs/23 §8.11 half-open path")
    require_contains(live, "fair-delivery", "docs/23 §8.11 fair-delivery assumption")
    require_contains(live, "継続的に read/write", "docs/23 §8.11 continuous USB R/W")
    require_contains(live, "少なくとも一組", "docs/23 §8.11 HELLO/ACK pair in finite tries")
    require_contains(live, "無限 packet loss", "docs/23 §8.11 no infinite-loss recovery claim")
    require_contains(live, "retry を止めない", "docs/23 §8.11 retry continues under loss")
    require_contains(live, "同時 inflight 最大 1", "docs/23 §8.11 PING max inflight 1")
    require_contains(live, "次 PING を重ねない", "docs/23 §8.11 no stacked PING")
    require_contains(live, "PONG を受理した時点", "docs/23 §8.11 cadence base PONG accept")
    require_contains(live, "pong_timeout` 満了", "docs/23 §8.11 cadence base timeout")
    require_contains(live, "MUST dispatch/accept", "docs/23 §8.11 MUST dispatch")
    require_contains(live, "ping_dispatch_slack", "docs/23 §8.11 dispatch slack")
    require_contains(
        live,
        "永遠に PING しない実装は不適合",
        "docs/23 §8.11 never-PING is nonconformant",
    )
    require_contains(live, "WOULD_BLOCK", "docs/23 §8.11 WOULD_BLOCK until deadline")
    require_contains(live, "ping_dispatch_miss", "docs/23 §8.11 dispatch miss counter")
    # dispatch miss must fence + re-HELLO (false-green if deleted)
    require_contains(live, "local session fence", "docs/23 §8.11 dispatch miss fence")
    require_contains(
        live,
        "next_tx_seq` で re-HELLO",
        "docs/23 §8.11 dispatch miss re-HELLO",
    )
    require_contains(
        live,
        "dispatch miss 後に fence/re-HELLO を省略して ACTIVE を維持する実装は不適合",
        "docs/23 §8.11 ban omit fence after dispatch miss",
    )


def check_doc23_reading_order_and_dx(text: str) -> None:
    """§1 reading order + DX fixes (queue name, L1 layer, Network Join policy)."""
    sec1 = section_between(text, "## 1. 位置付けと非主張", "## 2.", "docs/23 §1")
    require_contains(sec1, "開発者向け読み順", "docs/23 §1 reading order")
    require_contains(sec1, "ADR-0003", "docs/23 §1 points at ADR")
    require_contains(sec1, "half-open", "docs/23 §1 mentions half-open path")

    require_contains(
        text,
        "Host→device write intent queue",
        "docs/23 host→device queue name",
    )
    if "Host host→device" in text:
        fail("docs/23 must not keep 'Host host→device' typo")

    require_contains(
        text,
        "Cell Agent local composition layer",
        "docs/23 L1 composition layer name",
    )
    # Avoid reintroducing plane collision as the L1 title in the component table
    row = find_markdown_table_row(text, r"L1", "docs/23 L1 component row")
    if "local plane" in row and "ではない" not in row:
        fail(f"docs/23 L1 row must not bare-name 'local plane' as a product plane: {row!r}")

    join = section_between(text, "## 11.", "## 12.", "docs/23 §11")
    require_contains(join, "単一 state として使わない", "docs/23 §11 Network Join policy")
    # Match the natural Normative note (avoid a brittle alternate phrasing).
    # Actual prose: 「Network Join」という単一 state / 用語は docs/03 に存在しない
    require_contains(join, "docs/03 に存在しない", "docs/23 §11 docs/03 non-existence note")
    require_contains(join, "存在するかのように引用しない", "docs/23 §11 no false existence cite")
    require_contains(join, "Site Membership / Attachment", "docs/23 §11 concrete terms")


def check_doc19_sequence_field(paths: Paths) -> None:
    """docs/19 §4 wire layout must keep sequence at offset 12; U4 policy pointer."""
    text = read_text(paths.doc19)
    layout = section_between(text, "## 4. Wire layout", "## 5.", "docs/19 §4")
    rows = parse_wire_offset_rows(layout)
    require_wire_row(rows, 0, 4, "magic", "docs/19 §4")
    require_wire_row(rows, 8, 4, "stream_or_cell_id", "docs/19 §4")
    require_wire_row(rows, 12, 4, "sequence", "docs/19 §4")
    require_wire_row(rows, 16, 2, "payload_length", "docs/19 §4")
    require_contains(text, "23-usb-radio-boundary.md", "docs/19 U4 sequence policy ref")
    require_contains(text, "5.5.2", "docs/19 U4 §5.5.2 pointer")


def scan_positive_forbidden_claims(text: str, where: str) -> None:
    """Fail on bare completion lies; allow lines that clearly negate the claim."""
    positive_forbidden = (
        "USB series 完成済み",
        "SX1262 production complete",
        "M3 complete / field-ready",
        "compile success = HIL PASS",
    )
    for line in text.splitlines():
        for claim in positive_forbidden:
            if claim in line and not line_negated(line):
                fail(f"{where} positive forbidden claim without negation: {claim!r} in {line!r}")


def check_forbidden_across_docs(paths: Paths) -> None:
    """Scan key docs for bare completion lies about USB/radio production."""
    files = [
        paths.doc23,
        paths.adr,
        paths.doc01,
        paths.doc05,
        paths.doc06,
        paths.doc07,
        paths.doc09,
        paths.doc15,
    ]
    bad_res = (
        re.compile(r"USB production (code )?実装済み"),
        re.compile(r"SX1262 production (code )?実装済み"),
        re.compile(r"secure radio wire version\s*=\s*1"),
        re.compile(r"compile success\s*=\s*HIL PASS"),
    )
    for path in files:
        text = read_text(path)
        try:
            rel = str(path.relative_to(paths.root))
        except ValueError:
            rel = str(path)
        for line_no, line in enumerate(text.splitlines(), 1):
            if line_negated(line):
                continue
            for rx in bad_res:
                m = rx.search(line)
                if m:
                    fail(
                        f"{rel}:{line_no} matches forbidden production claim "
                        f"/{rx.pattern}/: {m.group(0)!r}"
                    )


def check_indexes_and_crossrefs(paths: Paths) -> None:
    require_contains(read_text(paths.adr_index), "0003-radio-usb-dependency-direction.md", "adr README")
    di = read_text(paths.doc_index)
    require_contains(di, "23-usb-radio-boundary.md", "docs README")
    require_contains(di, "0003-radio-usb-dependency-direction.md", "docs README")
    require_contains(di, "PR #80", "docs README")

    d01 = read_text(paths.doc01)
    require_contains(d01, "ADR-0003", "docs/01")
    require_contains(d01, "Physical Compliance", "docs/01")
    require_contains(d01, "sole", "docs/01")
    require_contains(d01, "immutable", "docs/01")

    d05 = read_text(paths.doc05)
    require_contains(d05, "NIN-CMP-013", "docs/05")
    require_contains(d05, "NIN-CMP-001", "docs/05")
    require_contains(d05, "unallocated", "docs/05")
    require_contains(d05, "SiteAssignment", "docs/05")
    require_contains(d05, "NIN-CMP-001`〜`NIN-CMP-013", "docs/05 milestone table")
    require_contains(d05, "sole", "docs/05")
    require_contains(d05, "transmit-with-permit", "docs/05")

    d06 = read_text(paths.doc06)
    require_contains(d06, "23-usb-radio-boundary.md", "docs/06")
    require_contains(d06, "unallocated", "docs/06")
    require_contains(d06, "logical_version", "docs/06")
    require_contains(d06, "別 domain", "docs/06")
    require_contains(d06, "NCL1", "docs/06")
    require_contains(d06, "NCL1_HEADER_BYTES=26", "docs/06 NCL1 header size")
    require_contains(d06, "MAX_NCL1_BODY=998", "docs/06 max body")
    require_contains(d06, "private minimal", "docs/06 private minimal catalog")
    require_contains(
        d06,
        "complete / public",
        "docs/06 complete/public control protocol unallocated",
    )

    d09 = read_text(paths.doc09)
    require_contains(d09, "U0:", "docs/09")
    require_contains(d09, "U1–U7", "docs/09")
    require_contains(d09, "R1–R10", "docs/09")
    require_contains(d09, "PR #80", "docs/09")
    require_contains(d09, "Required HIL", "docs/09")
    require_contains(d09, "multi-parent", "docs/09")
    require_contains(d09, "session_cookie", "docs/09")
    require_contains(d09, "CSPRNG", "docs/09 cookie RNG")

    d15 = read_text(paths.doc15)
    require_contains(d15, "Owner Task Join ACK", "docs/15")
    require_contains(d15, "Physical Compliance Permit", "docs/15")
    require_contains(d15, "NCL1", "docs/15")
    require_contains(d15, "TASK_JOIN_ACK", "docs/15")
    require_contains(d15, "session_cookie", "docs/15")
    require_contains(d15, "NCL1 header", "docs/15 cookie wire location")
    require_contains(d15, "単一 state として使わない", "docs/15 Network Join glossary")
    require_contains(d15, "umbrella", "docs/15 Network Join umbrella/non-claim")

    require_contains(read_text(paths.doc19), "23-usb-radio-boundary.md", "docs/19")
    d22 = read_text(paths.doc22)
    require_contains(d22, "Owner Task Join", "docs/22")
    require_contains(d22, "Network Join", "docs/22")
    require_contains(d22, "TASK_JOIN_ACK", "docs/22")

    d07 = read_text(paths.doc07)
    require_contains(d07, "radio_usb_boundary_docs_gate", "docs/07")
    require_contains(d07, "Required HIL", "docs/07")
    require_contains(d07, "MAX_BODY=998", "docs/07 gate body max")
    require_contains(d07, "HEADER_BYTES=26", "docs/07 gate header bytes")

    # U0 self-review record + index
    rev_idx = read_text(paths.reviews_index)
    require_contains(
        rev_idx,
        "2026-07-16-u0-radio-usb-boundary-freeze-self-review.md",
        "docs/reviews README U0 self-review",
    )
    u0r = read_text(paths.u0_self_review)
    require_contains(u0r, "Half-open", "U0 self-review half-open")
    require_contains(u0r, "BOOTSTRAP_EPOCH_RESTART", "U0 self-review bootstrap restart")
    require_contains(u0r, "ping_dispatch_slack", "U0 self-review ping dispatch")
    # F1 disposition column must remain 採用 (self-review table row scoped).
    f1_row = find_markdown_table_row(u0r, r"F1", "U0 self-review F1 row")
    f1_cells = table_cells(f1_row)
    # | ID | source | finding | disposition | ...
    if len(f1_cells) < 4:
        fail(f"U0 self-review F1 row too short: {f1_row!r}")
    if f1_cells[3].strip() != "**採用**":
        fail(
            "U0 self-review F1 disposition (column 4) must be **採用**, "
            f"got {f1_cells[3]!r}"
        )
    require_contains(u0r, "Fable", "U0 self-review Fable source")
    require_contains(u0r, "未実装", "U0 self-review honesty unimplemented")
    require_contains(u0r, "不採用", "U0 self-review records rejections")
    require_contains(u0r, "security", "U0 self-review non-security scope",)


def check_join_disambiguation(paths: Paths) -> None:
    text = read_text(paths.doc22)
    if "Owner Task Join" not in text:
        fail("docs/22 must disambiguate Owner Task Join")
    hdr = read_text(paths.owner_header)
    if "NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK" not in hdr:
        fail("owner_task.h must still define JOIN_ACK (docs-only slice; no C rename)")
    if "NINLIL_ESP_IDF_OWNER_LC_TASK_JOIN_ACK" in hdr:
        fail("owner_task.h must not rename to TASK_JOIN_ACK in this docs-only slice")


# Concrete layers that may accompany umbrella/non-claim "Network Join".
_NETWORK_JOIN_CONCRETE = re.compile(
    r"(Site\s+Membership|Membership|Attachment|Control\s+HELLO)",
    re.IGNORECASE,
)
# Vocabulary policy / definition lines (glossary, §11, CHANGELOG notes).
_NETWORK_JOIN_VOCAB_POLICY = re.compile(
    r"(単一\s*state|umbrella|併記|docs/03\s*に|存在しない|"
    r"語彙|non-claim|非主張|曖昧)",
)


def check_network_join_vocabulary(paths: Paths) -> None:
    """Reject bare 'Network Join' as a sole success/state label across U0 docs.

    Policy (docs/15, docs/23 §11): never use Network Join as a single state.
    Umbrella / non-claim uses must co-mention Attachment / Membership /
    Control HELLO (etc.). Negations and vocabulary definitions are allowed.
    Also forbid false existence cites of the form Network Join(docs/03).
    """
    files = [
        paths.adr,
        paths.doc23,
        paths.doc15,
        paths.doc09,
        paths.doc21,
        paths.doc22,
        paths.doc05,
        paths.changelog,
    ]
    false_cite = re.compile(r"Network\s+Join\s*[（(]\s*docs/03")
    for path in files:
        if not path.is_file():
            # Optional in temp trees (e.g. self-test without CHANGELOG/doc21).
            if path in (paths.changelog, paths.doc21):
                continue
            fail(f"missing required file: {path}")
        try:
            rel = str(path.relative_to(paths.root))
        except ValueError:
            rel = str(path)
        text = read_text(path)
        for line_no, line in enumerate(text.splitlines(), 1):
            if "Network Join" not in line and "Network\u00a0Join" not in line:
                continue
            if false_cite.search(line):
                fail(
                    f"{rel}:{line_no} false existence cite of Network Join via "
                    f"docs/03 (docs/03 does not define that term): {line!r}"
                )
            # Negation / non-claim / confusion-warning lines are fine.
            if line_negated(line):
                continue
            # Explicit vocabulary policy / glossary rows.
            if _NETWORK_JOIN_VOCAB_POLICY.search(line):
                continue
            # Umbrella uses that already co-mention concrete layers.
            if _NETWORK_JOIN_CONCRETE.search(line):
                continue
            fail(
                f"{rel}:{line_no} bare 'Network Join' without concrete co-mention "
                f"(Attachment/Membership/Control HELLO) or allowed "
                f"negation/vocab policy: {line!r}"
            )


def check_no_usb_radio_production_sources(paths: Paths) -> None:
    """Honesty: SX1262 unfinished; U1 may be candidate only; series not complete."""
    text23 = read_text(paths.doc23)
    if "SX1262 production code 未実装" not in text23:
        fail("docs/23 must state SX1262 production code is not implemented")
    if "U1 implementation candidate" not in text23:
        fail("docs/23 must state U1 is implementation candidate (not complete)")
    if "Required HIL" not in text23:
        fail("docs/23 must keep Required HIL language")
    for line in text23.splitlines():
        if re.search(r"\bU1 complete\b", line) and "名乗らない" not in line and not line_negated(line):
            if "ではない" not in line and "pending" not in line.lower():
                fail(f"docs/23 bare U1 complete claim: {line!r}")


def run_check(paths: Paths | None = None) -> None:
    paths = paths or P
    check_adr(paths)
    check_doc23(paths)
    check_doc19_sequence_field(paths)
    check_forbidden_across_docs(paths)
    check_indexes_and_crossrefs(paths)
    check_join_disambiguation(paths)
    check_network_join_vocabulary(paths)
    check_no_usb_radio_production_sources(paths)
    print(
        "radio_usb_boundary_docs_gate ok: "
        "adr=0003 doc=23 slices=U0-U7,R1-R10 "
        "compile_edges tx_order=W1>P1>H1>D1 "
        "ncl1_header=26 max_body=998 cookie_header "
        "ncg1_seq_u4 stream0 bootstrap_epoch_restart "
        "halfopen next_tx_seq type_matrix counters "
        "liveness ping_dispatch_slack "
        "r9_row_scoped network_join_vocab "
        "terms=NCL1,OwnerTaskJoin,CompliancePermit,unallocated,"
        "ControllerOnly,SiteAssignment,RequiredHIL"
    )


# ---------------------------------------------------------------------------
# Self-test mutators
# ---------------------------------------------------------------------------


def _copy_docs_tree(dst_root: pathlib.Path) -> None:
    rels = [
        "docs/adr/0003-radio-usb-dependency-direction.md",
        "docs/adr/README.md",
        "docs/23-usb-radio-boundary.md",
        "docs/README.md",
        "docs/01-architecture.md",
        "docs/05-security-and-compliance.md",
        "docs/06-versioning-and-compatibility.md",
        "docs/07-testing-and-quality.md",
        "docs/09-roadmap.md",
        "docs/15-glossary.md",
        "docs/19-m3-control-byte-stream-framing.md",
        "docs/21-m3-esp-idf-durable-storage.md",
        "docs/22-m3-owner-cell-agent-skeleton.md",
        "docs/reviews/README.md",
        "docs/reviews/2026-07-16-u0-radio-usb-boundary-freeze-self-review.md",
        "ports/esp-idf/include/ninlil_esp_idf/owner_task.h",
        "CHANGELOG.md",
    ]
    for rel in rels:
        src = REPO_ROOT / rel
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _expect_fail(label: str, paths: Paths, mutator: Callable[[Paths], None]) -> None:
    mutator(paths)
    try:
        run_check(paths)
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail the checker (false green)")


def _mut_adr_invert_c3_to_c2(paths: Paths) -> None:
    """False-green target (a): C3 --> C2 becomes C3 -X-> C2 in ADR §2 only."""
    text = read_text(paths.adr)
    sec_start = text.find("### 2. Compile / source dependency")
    sec_end = text.find("### 3. Runtime call / data flow", sec_start)
    if sec_start < 0 or sec_end < 0:
        fail("mutator setup: ADR §2 markers missing")
    head, mid, tail = text[:sec_start], text[sec_start:sec_end], text[sec_end:]
    # Only flip the C3 block's positive edge to C2 (keep table prose).
    pattern = re.compile(
        r"(C3 \(NCL1 codec/session\)\s*\[portable private\]\n)"
        r"(  --> C2\n)",
    )
    new_mid, n = pattern.subn(r"\1  -X-> C2\n", mid, count=1)
    if n != 1:
        fail("mutator setup: could not locate C3 --> C2 in ADR §2 diagram")
    paths.adr.write_text(head + new_mid + tail, encoding="utf-8")


def _mut_doc19_delete_sequence_row(paths: Paths) -> None:
    """False-green target (b): delete offset-12 sequence row from docs/19 §4."""
    text = read_text(paths.doc19)
    layout_start = text.find("## 4. Wire layout")
    layout_end = text.find("## 5.", layout_start)
    if layout_start < 0 or layout_end < 0:
        fail("mutator setup: docs/19 §4 markers missing")
    head, mid, tail = text[:layout_start], text[layout_start:layout_end], text[layout_end:]
    new_mid, n = re.subn(
        r"^12\s+4\s+sequence[^\n]*\n",
        "",
        mid,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        fail("mutator setup: could not delete sequence row in docs/19 §4")
    paths.doc19.write_text(head + new_mid + tail, encoding="utf-8")


def _mut_doc23_delete_cookie_row(paths: Paths) -> None:
    """False-green target (c): delete offset-16 session_cookie row from §7.2."""
    text = read_text(paths.doc23)
    start = text.find("### 7.2 NCL1 header")
    end = text.find("### 7.3", start)
    if start < 0 or end < 0:
        fail("mutator setup: docs/23 §7.2 markers missing")
    head, mid, tail = text[:start], text[start:end], text[end:]
    new_mid, n = re.subn(
        r"^16\s+8\s+session_cookie[^\n]*\n(?:[^\n]*\n)?",
        "",
        mid,
        count=1,
        flags=re.MULTILINE,
    )
    # session_cookie may span two lines in the layout block
    if n != 1:
        new_mid, n = re.subn(
            r"^16\s+8\s+session_cookie.*(?:\n(?!\d+\s+\d+\s).*)*",
            "",
            mid,
            count=1,
            flags=re.MULTILINE,
        )
    if n != 1:
        fail("mutator setup: could not delete session_cookie row in docs/23 §7.2")
    paths.doc23.write_text(head + new_mid + tail, encoding="utf-8")


def _mut_adr_invert_tx_permit_before_wire(paths: Paths) -> None:
    """False-green target (d): reverse W1/P1 order to Permit→wire in §3.2."""
    text = read_text(paths.adr)
    start = text.find("#### 3.2 Physical RF TX path")
    if start < 0:
        fail("mutator setup: ADR §3.2 missing")
    # Find end of the code block sequence
    end = text.find("## Consequences", start)
    if end < 0:
        end = start + 2500
    head, mid, tail = text[:start], text[start:end], text[end:]
    # Swap step numbers/components: (1)W1 <-> (2)P1 markers and keyword order
    swapped = mid
    swapped = swapped.replace("(1) W1", "(1) P1_TMP", 1)
    swapped = swapped.replace("(2) P1", "(2) W1", 1)
    swapped = swapped.replace("(1) P1_TMP", "(1) P1", 1)
    # Also reverse the prose markers that the order checker uses
    m1 = "immutable TX plan + exact frame bytes"
    m2 = "Physical Compliance Permit を発行"
    if m1 in swapped and m2 in swapped and swapped.find(m1) < swapped.find(m2):
        swapped = swapped.replace(m1, "@@M1@@", 1).replace(m2, m1, 1).replace("@@M1@@", m2, 1)
    if swapped == mid:
        fail("mutator setup: ADR §3.2 TX order swap had no effect")
    paths.adr.write_text(head + swapped + tail, encoding="utf-8")


def _mut_doc23_matrix_hello_data_to_ping(paths: Paths) -> None:
    """(a) matrix: HELLO allowed under DATA → under PING instead (row-scoped)."""
    text = read_text(paths.doc23)
    old = "| `HELLO` 0x01 | ✗ | ✗ | **✓** | ✗ | ✗ |"
    new = "| `HELLO` 0x01 | **✓** | ✗ | ✗ | ✗ | ✗ |"
    if old not in text:
        fail("mutator setup: HELLO matrix DATA-allow row missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_hello_retry_unlimited_to_false(paths: Paths) -> None:
    """(b) hello_retry_unlimited_while_link_up true → false (table row)."""
    text = read_text(paths.doc23)
    old = "| `hello_retry_unlimited_while_link_up` | **true** |"
    new = "| `hello_retry_unlimited_while_link_up` | **false** |"
    if old not in text:
        fail("mutator setup: hello_retry_unlimited true row missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_active_hello_reject_keep_session(paths: Paths) -> None:
    """(c) SESSION_ACTIVE valid HELLO → reject + keep old session (invert)."""
    text = read_text(paths.doc23)
    # Corrupt the SESSION_ACTIVE half-open fence requirement in §5.6.
    old = "旧 session を明示 fence（active gen/cookie 無効化、inflight 全破棄、"
    new = (
        "SESSION_ACTIVE 中の valid HELLO を reject し旧 session を維持"
        "（active gen/cookie 無効化せず、inflight 全破棄せず、"
    )
    if old not in text:
        fail("mutator setup: ACTIVE HELLO fence phrase missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_seq_gap_keep_session(paths: Paths) -> None:
    """(d) sequence gap → session keep (invert fail-closed)."""
    text = read_text(paths.doc23)
    sec_start = text.find("#### 5.5.2 NCG1 `sequence`")
    sec_end = text.find("### 5.6", sec_start)
    if sec_start < 0 or sec_end < 0:
        fail("mutator setup: §5.5.2 markers missing")
    head, mid, tail = text[:sec_start], text[sec_start:sec_end], text[sec_end:]
    old = (
        "→ **fail-closed**: 当該 frame reject + **control session INVALID** + "
        "**local RX sequence epoch cold のみ**（local TX `next_tx_seq` **継続**）+ counter"
    )
    new = (
        "→ **session 維持**: 当該 frame reject + **control session 維持** + "
        "sequence epoch 維持 + counter"
    )
    if old not in mid:
        fail("mutator setup: sequence gap fail-closed phrase missing in §5.5.2")
    paths.doc23.write_text(head + mid.replace(old, new, 1) + tail, encoding="utf-8")


def _mut_doc23_reset_body_cookie_allow_zero(paths: Paths) -> None:
    """(e) RESET_BODY cookie allow 0 (invert active match)."""
    text = read_text(paths.doc23)
    sec_start = text.find("### 7.4 session_generation / session_cookie / request_id 許可表")
    sec_end = text.find("## 8.", sec_start)
    if sec_start < 0 or sec_end < 0:
        fail("mutator setup: §7.4 markers missing")
    head, mid, tail = text[:sec_start], text[sec_start:sec_end], text[sec_end:]
    old = (
        "| `RESET_BODY`（**peer が SESSION_ACTIVE 中に送る通常 RESET**） | "
        "受信側 **active と一致 ≠ 0** | 受信側 **active と一致 ≠ 0** | **≠ 0** |"
    )
    new = (
        "| `RESET_BODY`（**peer が SESSION_ACTIVE 中に送る通常 RESET**） | "
        "受信側 **active と一致 ≠ 0** | cookie=0 許可 | **≠ 0** |"
    )
    if old not in mid:
        fail("mutator setup: RESET_BODY active cookie row missing in §7.4")
    paths.doc23.write_text(head + mid.replace(old, new, 1) + tail, encoding="utf-8")


def _mut_doc23_hello_success_resets_counters(paths: Paths) -> None:
    """(f) HELLO success resets counters (invert)."""
    text = read_text(paths.doc23)
    sec_start = text.find("### 8.10 Structured counter")
    sec_end = text.find("### 8.11", sec_start)
    if sec_start < 0 or sec_end < 0:
        fail("mutator setup: §8.10 markers missing")
    head, mid, tail = text[:sec_start], text[sec_start:sec_end], text[sec_end:]
    old = "session fence や **HELLO 成功では reset しない**（累積観測）"
    new = "session fence や **HELLO 成功で reset する**（累積を捨てる）"
    if old not in mid:
        fail("mutator setup: HELLO success no-reset phrase missing in §8.10")
    paths.doc23.write_text(head + mid.replace(old, new, 1) + tail, encoding="utf-8")


def _mut_u0_self_review_f1_to_reject(paths: Paths) -> None:
    """(g) self-review F1 disposition 採用 → 不採用 (column-scoped)."""
    text = read_text(paths.u0_self_review)
    # Only flip the disposition cell of the F1 row (4th column).
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    found = False
    for line in lines:
        if re.match(r"^\|\s*F1\s*\|", line) and not found:
            cells = table_cells(line.rstrip("\n"))
            if len(cells) >= 4 and cells[3].strip() == "**採用**":
                cells[3] = "**不採用**"
                line = "| " + " | ".join(cells) + " |\n"
                found = True
        out.append(line)
    if not found:
        fail("mutator setup: F1 disposition **採用** row missing")
    paths.u0_self_review.write_text("".join(out), encoding="utf-8")


def _mut_doc23_r9_row_only_r4(paths: Paths) -> None:
    """False-green target (e): weaken only the R9 table row; keep other R4+R5+R7."""
    text = read_text(paths.doc23)
    row = find_markdown_table_row(text, r"\*\*R9\*\*", "mutator R9")
    if "R4 + R5 + R7" not in row:
        fail("mutator setup: R9 row missing R4 + R5 + R7")
    new_row = row.replace("R4 + R5 + R7", "R4 only", 1)
    paths.doc23.write_text(text.replace(row, new_row, 1), encoding="utf-8")
    after = read_text(paths.doc23)
    r9_after = find_markdown_table_row(after, r"\*\*R9\*\*", "mutator R9 verify")
    if "R4 only" not in r9_after:
        fail("mutator setup: R9 row was not weakened")
    # Prose / acceptance elsewhere must still mention full R4+R5+R7 (any spacing)
    outside = after.replace(r9_after, "", 1)
    if not re.search(r"R4\s*\+\s*R5\s*\+\s*R7", outside):
        fail(
            "mutator setup: expected non-R9-row R4+R5+R7 phrase to remain "
            "(proves row-scoped check, not global token)"
        )



def _mut_doc23_sbr_atomic_accept_to_reject(paths: Paths) -> None:
    """False-green: BOOTSTRAP/SBR atomic accept -> reject."""
    t = read_text(paths.doc23)
    # Flip SBR-HELLO row action from atomic accept to reject
    old = "当該 **任意 sequence** を新 RX baseline として **atomic accept**"
    new = "当該 **任意 sequence** を新 RX baseline として **reject**"
    if old not in t:
        fail("mutator setup: SBR atomic accept phrase missing")
    paths.doc23.write_text(t.replace(old, new), encoding="utf-8")


def _mut_doc23_ackloss_next_tx_to_cold_seq0(paths: Paths) -> None:
    """False-green: ACKLOSS path next_tx_seq -> cold seq0."""
    t = read_text(paths.doc23)
    row_old = (
        "| **同一 link / 同一 process の HELLO_ACK timeout retry** | **cold しない**。"
        "`next_tx_seq` のまま次 HELLO（初回 seq0 受理後の次は **seq1**） | 変更なし"
    )
    row_new = (
        "| **同一 link / 同一 process の HELLO_ACK timeout retry** | **cold → 0**。"
        "次 HELLO は **seq0** | 変更なし"
    )
    if row_old not in t:
        fail("mutator setup: HELLO_ACK timeout authority row missing")
    paths.doc23.write_text(t.replace(row_old, row_new), encoding="utf-8")


def _mut_doc23_reset_session_to_cold(paths: Paths) -> None:
    """False-green: RESET_SESSION continues sequences -> cold both."""
    t = read_text(paths.doc23)
    # Authority table RESET_SESSION row
    old = (
        "| `RESET_SESSION` | **cold しない**（双方 sequence 継続） | **cold しない** | "
        "INVALID → `LINK_UP_NO_SESSION` | session だけ fence。Controller は `next_tx_seq` で re-HELLO |"
    )
    new = (
        "| `RESET_SESSION` | **cold → 0** | **cold → 0** | "
        "INVALID → `LINK_UP_NO_SESSION` | session fence + sequence cold |"
    )
    if old not in t:
        fail("mutator setup: RESET_SESSION authority row missing")
    paths.doc23.write_text(t.replace(old, new), encoding="utf-8")


def _mut_doc23_ping_slack_1000_to_60000(paths: Paths) -> None:
    """False-green: ping_dispatch_slack 1000 -> 60000 while leaving 1000 elsewhere."""
    t = read_text(paths.doc23)
    # Only change the slack table row value; leave other **1000 ms** if any, or inject one.
    live_marker = "| `ping_dispatch_slack` | **1000 ms** |"
    if live_marker not in t:
        fail("mutator setup: ping_dispatch_slack 1000 row missing")
    # Ensure another **1000 ms** remains outside the row for false-global checks
    t2 = t.replace(live_marker, "| `ping_dispatch_slack` | **60000 ms** |", 1)
    if "**1000 ms**" not in t2:
        # inject decoy 1000 outside the slack row so a global token check would false-green
        hdr = "### 8.11 Liveness / HELLO retry profile default（monotonic clock only）\n"
        if hdr not in t2:
            fail("mutator setup: §8.11 header missing for decoy inject")
        t2 = t2.replace(
            hdr,
            hdr + "\ndecoy **1000 ms** remains elsewhere\n",
            1,
        )
    paths.doc23.write_text(t2, encoding="utf-8")


def _mut_doc23_dispatch_miss_drop_fence_rehello(paths: Paths) -> None:
    """False-green: delete dispatch miss fence/reHELLO requirements."""
    t = read_text(paths.doc23)
    old = (
        "→ `ping_dispatch_miss++` + **local session fence** → `LINK_UP_NO_SESSION` + "
        "`liveness_fail++` + Controller は **`next_tx_seq` で re-HELLO**（§5.6; sequence cold しない）。"
        "**SESSION_ACTIVE のまま永遠に PING しない実装は不適合。** "
        "**dispatch miss 後に fence/re-HELLO を省略して ACTIVE を維持する実装は不適合。**"
    )
    new = (
        "→ `ping_dispatch_miss++` のみ。session は ACTIVE 維持してよい。"
        "**SESSION_ACTIVE のまま永遠に PING しない実装は不適合。**"
    )
    if old not in t:
        fail("mutator setup: dispatch miss fence/reHELLO prose missing")
    paths.doc23.write_text(t.replace(old, new), encoding="utf-8")


def _mut_doc23_u1_hil_and_to_or(paths: Paths) -> None:
    """False-green: U1 Required HIL Linux AND -> OR."""
    t = read_text(paths.doc23)
    # Only flip U1 row; leave U7 as AND if present
    old = (
        "**Required HIL（U1 完了主張時）:** **Linux および macOS** の **両方**で "
        "**実 USB CDC 列挙 + explicit path open/read/write/close**（片方 OS のみでは U1 complete を名乗らない）"
    )
    new = (
        "**Required HIL（U1 完了主張時）:** **Linux または macOS** のいずれかで "
        "**実 USB CDC 列挙 + explicit path open/read/write/close**"
    )
    if old not in t:
        fail("mutator setup: U1 HIL AND phrase missing")
    paths.doc23.write_text(t.replace(old, new), encoding="utf-8")


def _mut_doc23_overflow_recovery_disabled(paths: Paths) -> None:
    """False-green: disable overflow recovery path."""
    t = read_text(paths.doc23)
    old = (
        "(7) **有限回復**は §5.6.1（Controller 検出なら即 `next_tx_seq` HELLO、Cell 検出なら "
        "RESET_SESSION 通知 + peer HELLO の **SBR-HELLO**）。"
        "**overflow 後に回復 path を無効化してよい実装は禁止**"
    )
    new = (
        "(7) overflow 後の session 回復は **任意**。**overflow 後に回復 path を無効化してよい**"
    )
    if old not in t:
        fail("mutator setup: overflow recovery ban missing")
    paths.doc23.write_text(t.replace(old, new), encoding="utf-8")


def _mut_doc23_drop_reverse_ack_baseline_recovery(paths: Paths) -> None:
    """False-green: delete reverse ACK / SBR-ACK baseline recovery."""
    t = read_text(paths.doc23)
    # Remove SBR-ACK mentions from §5.6.1 while leaving other content
    if "SBR-ACK" not in t:
        fail("mutator setup: SBR-ACK missing")
    t2 = t.replace("SBR-ACK", "ACK_DROP_MARKER")
    # Also drop reverse ACK permanent reject ban
    t2 = t2.replace("exact0 だけで永久拒否", "exact0 のみを推奨")
    t2 = t2.replace("reverse ACK", "forward-only ACK path")
    t2 = t2.replace("U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE", "U4-G-ACKLOSS-REVERSE-REMOVED")
    paths.doc23.write_text(t2, encoding="utf-8")


def _replace_role_row_cell(
    paths: Paths,
    message_pattern: str,
    column: int,
    value: str,
) -> None:
    text = read_text(paths.doc23)
    sec = section_between(text, "### 5.6 状態機械", "## 6.", "mutator role matrix")
    row = find_markdown_table_row(sec, message_pattern, "mutator role matrix row")
    cells = table_cells(row)
    if len(cells) < 4:
        fail(f"mutator setup: role row too short: {row!r}")
    cells[column] = value
    new_row = "| " + " | ".join(cells) + " |"
    paths.doc23.write_text(text.replace(row, new_row, 1), encoding="utf-8")


def _mut_doc23_role_hello_cell_allowed(paths: Paths) -> None:
    """False-green: allow Cell to send HELLO."""
    _replace_role_row_cell(paths, r"`HELLO`", 2, "**双方可**")


def _mut_doc23_role_reset_cell_forbidden(paths: Paths) -> None:
    """False-green: forbid Cell from sending RESET_BODY."""
    _replace_role_row_cell(paths, r"`RESET_BODY`", 2, "✗")


def _mut_doc23_seq_u32_max_allow_sbr(paths: Paths) -> None:
    """False-green: turn the reserved terminal into an SBR-acceptable value."""
    text = read_text(paths.doc23)
    old = "wire 上 **`sequence == UINT32_MAX` は予約 terminal**。**送信禁止**"
    new = "wire 上 **`sequence == UINT32_MAX` は通常値**。**SBR なら送信・受信可**"
    if old not in text:
        fail("mutator setup: UINT32_MAX terminal rule missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_link_down_lump_overflow(paths: Paths) -> None:
    """False-green: redefine overflow/reset as physical Link down."""
    text = read_text(paths.doc23)
    old = "**(b) session-breaking events（物理 link は up のまま）:**"
    new = "**(b) Link down（RX overflow / RESET も物理 link down と同じ）:**"
    if old not in text:
        fail("mutator setup: session invalidation trigger heading missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_continuity_drop_prefence(paths: Paths) -> None:
    """False-green: remove the one-shot pre-fence credential snapshot."""
    text = read_text(paths.doc23)
    if "pre-fence snapshot" not in text:
        fail("mutator setup: pre-fence snapshot missing")
    paths.doc23.write_text(
        text.replace("pre-fence snapshot", "post-fence missing credential"),
        encoding="utf-8",
    )


def _mut_doc23_reset_parser_tx_also_cold(paths: Paths) -> None:
    """False-green: RESET_PARSER send-accept also colds local TX."""
    text = read_text(paths.doc23)
    old = (
        "| `RESET_PARSER` **送信 accept**（自端） | **継続** | "
        "**cold → baseline 待ち**（**自端 local RX parser/epoch のみ**） |"
    )
    new = (
        "| `RESET_PARSER` **送信 accept**（自端） | **cold → 0** | "
        "**cold → baseline 待ち**（TX+RX双方） |"
    )
    if old not in text:
        fail("mutator setup: RESET_PARSER send-accept row missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_adr_esp_tinyusb_exact_version_u0(paths: Paths) -> None:
    """False-green: claim U0 pins the esp_tinyusb component version."""
    text = read_text(paths.adr)
    old = "**path 選定のみ**; managed component の **exact version / lock は U2**"
    new = "**path と managed component exact version / lock を U0 で固定済み**; U2 は不要"
    if old not in text:
        fail("mutator setup: ADR esp_tinyusb U2 pin statement missing")
    paths.adr.write_text(text.replace(old, new, 1), encoding="utf-8")


def _mut_doc23_allow_stale_reset_to_fence_new_session(paths: Paths) -> None:
    """False-green: let an old continuity notice fence a newer active session."""
    text = read_text(paths.doc23)
    old = "**受信側に stale 許可例外はない:**"
    new = "**受信側は stale notice を新 session にも適用してよい:**"
    if old not in text:
        fail("mutator setup: stale RESET receiver ban missing")
    text = text.replace(old, new, 1)
    text = text.replace(
        "**新 session を fence してはならない**",
        "**新 session も fence してよい**",
        1,
    )
    paths.doc23.write_text(text, encoding="utf-8")


def _mut_doc23_notice_slot_unbounded(paths: Paths) -> None:
    """False-green: remove the fixed one-entry/byte bound for continuity notice."""
    text = read_text(paths.doc23)
    old = "**exact 1 reserved entry** | **exact 30 NCL1 bytes**"
    new = "**unbounded entries** | **unbounded bytes**"
    if old not in text:
        fail("mutator setup: fixed continuity notice slot missing")
    paths.doc23.write_text(text.replace(old, new, 1), encoding="utf-8")




def _mut_doc23_continuity_tx_accept_refence(paths: Paths) -> None:
    """P1-A false-green: allow raw-adapter TX accept to re-run RESET_SESSION sender fence."""
    text = read_text(paths.doc23)
    # Corrupt all fence-once / no-re-fence anchors the checker requires.
    anchors = [
        (
            "fence once at detection/creation",
            "fence again at raw-adapter TX accept",
        ),
        (
            "通常 `RESET_SESSION` 送信 accept の sender fence を再実行してはならない",
            "通常 `RESET_SESSION` 送信 accept の sender fence を raw-adapter TX accept 時にも再実行してよい",
        ),
        (
            "raw-adapter TX accept で通常 `RESET_SESSION` sender fence を再実行しない",
            "raw-adapter TX accept で通常 `RESET_SESSION` sender fence を再実行する",
        ),
    ]
    changed = False
    for old, new in anchors:
        if old in text:
            text = text.replace(old, new)
            changed = True
    if not changed:
        fail("mutator setup: fence-once raw-adapter ban anchors missing")
    paths.doc23.write_text(text, encoding="utf-8")


def _mut_doc23_continuity_cancel_on_hello_missing(paths: Paths) -> None:
    """P1-A false-green: keep an unsent old notice across valid HELLO recovery."""
    text = read_text(paths.doc23)
    anchors = [
        ("not-yet-raw-adapter-accepted", "pending-unsent-old-notice"),
        ("continuity_reset_notice_cancelled++", "continuity_reset_notice_ignored++"),
        ("atomic cancel", "leave pending"),
    ]
    changed = False
    for old, new in anchors:
        if old in text:
            text = text.replace(old, new)
            changed = True
    if not changed:
        fail("mutator setup: cancel-on-HELLO lifecycle anchors missing")
    paths.doc23.write_text(text, encoding="utf-8")


def _mut_doc23_stale_reset_no_seq_advance(paths: Paths) -> None:
    """P1-B false-green: claim continuous stale RESET must not advance last_rx_seq."""
    text = read_text(paths.doc23)
    # Destroy exact phrases the checker requires (must not leave them as substrings).
    anchors = [
        (
            "**連続 stale RESET**（`have_rx_seq` かつ `seq == last_rx_seq + 1`）は sequence 段で "
            "**accept** し **`last_rx_seq` を前進**させる。",
            "**連続 stale RESET** は sequence 段で reject し last_rx_seq を更新しない"
            "（state/sequence とも不変）。",
        ),
        (
            "**`last_rx_seq` を前進**させる",
            "**`last_rx_seq` を更新しない**",
        ),
        (
            "`last_rx_seq` を前進させたうえで",
            "`last_rx_seq` を据え置いたうえで",
        ),
        (
            "連続なら `last_rx_seq` 前進",
            "連続でも `last_rx_seq` 据え置き",
        ),
        (
            "連続 seq なら `last_rx_seq` 前進",
            "連続 seq でも `last_rx_seq` 据え置き",
        ),
    ]
    changed = False
    for old, new in anchors:
        if old in text:
            text = text.replace(old, new)
            changed = True
    if not changed:
        fail("mutator setup: continuous stale last_rx_seq advance rule missing")
    paths.doc23.write_text(text, encoding="utf-8")


def run_self_test() -> None:
    run_check(P)

    mutations: list[tuple[str, Callable[[Paths], None]]] = [
        # --- Required false-green closures (a–e) ---
        ("adr_compile_c3_to_c2_inverted", _mut_adr_invert_c3_to_c2),
        ("doc19_wire_sequence_row_deleted", _mut_doc19_delete_sequence_row),
        ("doc23_ncl1_cookie_row_deleted", _mut_doc23_delete_cookie_row),
        ("adr_tx_order_permit_before_wire", _mut_adr_invert_tx_permit_before_wire),
        ("doc23_r9_row_deps_r4_only_keep_global_phrase", _mut_doc23_r9_row_only_r4),
        # --- Existing regressions ---
        (
            "adr_not_accepted",
            lambda p: p.adr.write_text(
                read_text(p.adr).replace("状態: Accepted", "状態: Proposed", 1),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_ncl1",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("NCL1", "NXX1"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_sole_tx_edge",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("sole physical TX edge", "a physical TX edge"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_siteassignment_epoch",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("SiteAssignment epoch", "SiteAssignment ep0ch"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_ctrl_error_ban",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "CTRL_ERROR への CTRL_ERROR 禁止",
                    "CTRL_ERROR への応答は任意",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_required_hil",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("Required HIL", "Optional lab"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_max_body",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("**998**", "**9999**"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_header_bytes_26",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "| `NCL1_HEADER_BYTES` | **26** |",
                    "| `NCL1_HEADER_BYTES` | **18** |",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_seq_policy_claim_absent",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "#### 5.5.2 NCG1 `sequence`（存在確認と USB U4 exact policy）",
                    "#### 5.5.2 NCG1 `sequence`（存在確認と USB U4 exact policy）\n\n"
                    "logical request_id と NCG1 に sequence field は無い。\n",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_seq_drop_stream_id_zero",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "**exact `0`** = sole bootstrap/control stream",
                    "**any u32** = sole bootstrap/control stream",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_cookie_rng_not_fail_closed",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "とき **`HELLO_OK` を出してはならない**（fail-closed）",
                    "とき **`HELLO_OK` を cookie=0 で出してよい**（fail-open）",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_hello_ack_body_back_to_16",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "body_length exact **8**。\n\n"
                    "**HELLO_OK 時と error 時の header 規約",
                    "body_length exact **16**。\n\n"
                    "**HELLO_OK 時と error 時の header 規約",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_active_cookie_ban",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "cookie を HELLO_ACK にしか載せない設計は **U4 では禁止**",
                    "cookie を HELLO_ACK にしか載せない設計は **U4 では許容**",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc05_drop_cmp013",
            lambda p: p.doc05.write_text(
                read_text(p.doc05).replace("NIN-CMP-013", "NIN-CMP-0XX"),
                encoding="utf-8",
            ),
        ),
        (
            "doc06_drop_logical_version_domain",
            lambda p: p.doc06.write_text(
                read_text(p.doc06).replace("logical_version", "log_ver"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_positive_usb_complete_lie",
            lambda p: p.doc23.write_text(
                read_text(p.doc23) + "\n\nUSB series 完成済み\n",
                encoding="utf-8",
            ),
        ),
        (
            "owner_header_premature_rename",
            lambda p: p.owner_header.write_text(
                read_text(p.owner_header).replace(
                    "NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK",
                    "NINLIL_ESP_IDF_OWNER_LC_TASK_JOIN_ACK",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "adr_drop_compile_section",
            lambda p: p.adr.write_text(
                read_text(p.adr).replace(
                    "Compile / source dependency",
                    "Build-time notes",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_opaque_token",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("opaque_echo_token", "sender_unix_ms_token"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_controller_only",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("Controller-only", "Either-side"),
                encoding="utf-8",
            ),
        ),
        # --- Fable half-open / matrix / counters / liveness / review ---
        (
            "doc23_drop_halfopen_recovery",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "half-open recovery",
                    "link-down-only recovery",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_matrix_soft_typical",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "Closed exact binding matrix",
                    "典型 NCG1 type matrix",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_validation_order_swap",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "4. **exact NCG1-type binding**",
                    "4. **generation / cookie / request_id (moved early)**",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_type_binding_counter",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "ncl1_reject_type_binding",
                    "ncl1_reject_misc",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_ping_cadence",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("ping_cadence", "ping_sometimes"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_drop_reading_order",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace("開発者向け読み順", "参考リンク"),
                encoding="utf-8",
            ),
        ),
        (
            "doc23_restore_host_host_typo",
            lambda p: p.doc23.write_text(
                read_text(p.doc23).replace(
                    "Host→device write intent queue",
                    "Host host→device write intent queue",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "doc06_drop_private_minimal_vs_public",
            lambda p: p.doc06.write_text(
                read_text(p.doc06).replace("private minimal", "all control"),
                encoding="utf-8",
            ),
        ),
        (
            "u0_self_review_unindexed",
            lambda p: p.reviews_index.write_text(
                read_text(p.reviews_index).replace(
                    "2026-07-16-u0-radio-usb-boundary-freeze-self-review.md",
                    "2026-07-16-u0-MISSING.md",
                ),
                encoding="utf-8",
            ),
        ),
        (
            "bare_network_join_success_claim",
            lambda p: p.adr.write_text(
                read_text(p.adr) + "\n\nNetwork Join 成功\n",
                encoding="utf-8",
            ),
        ),
        # --- Independent final NO-GO false-green closures (a–g) ---
        (
            "doc23_matrix_hello_data_to_ping",
            _mut_doc23_matrix_hello_data_to_ping,
        ),
        (
            "doc23_hello_retry_unlimited_true_to_false",
            _mut_doc23_hello_retry_unlimited_to_false,
        ),
        (
            "doc23_active_hello_reject_keep_session",
            _mut_doc23_active_hello_reject_keep_session,
        ),
        (
            "doc23_seq_gap_keep_session",
            _mut_doc23_seq_gap_keep_session,
        ),
        (
            "doc23_reset_body_cookie_allow_zero",
            _mut_doc23_reset_body_cookie_allow_zero,
        ),
        (
            "doc23_hello_success_resets_counters",
            _mut_doc23_hello_success_resets_counters,
        ),
        (
            "u0_self_review_f1_adopt_to_reject",
            _mut_u0_self_review_f1_to_reject,
        ),
        # --- Independent NO-GO false-green closures (directional epoch / SBR / HIL) ---
        (
            "doc23_sbr_atomic_accept_to_reject",
            _mut_doc23_sbr_atomic_accept_to_reject,
        ),
        (
            "doc23_ackloss_next_tx_to_cold_seq0",
            _mut_doc23_ackloss_next_tx_to_cold_seq0,
        ),
        (
            "doc23_reset_session_to_cold",
            _mut_doc23_reset_session_to_cold,
        ),
        (
            "doc23_ping_slack_1000_to_60000_keep_other_1000",
            _mut_doc23_ping_slack_1000_to_60000,
        ),
        (
            "doc23_dispatch_miss_drop_fence_rehello",
            _mut_doc23_dispatch_miss_drop_fence_rehello,
        ),
        (
            "doc23_u1_hil_and_to_or",
            _mut_doc23_u1_hil_and_to_or,
        ),
        (
            "doc23_overflow_recovery_disabled",
            _mut_doc23_overflow_recovery_disabled,
        ),
        (
            "doc23_drop_reverse_ack_baseline_recovery",
            _mut_doc23_drop_reverse_ack_baseline_recovery,
        ),
        # --- Root QA false-green closures ---
        (
            "doc23_role_hello_cell_allowed",
            _mut_doc23_role_hello_cell_allowed,
        ),
        (
            "doc23_role_reset_cell_forbidden",
            _mut_doc23_role_reset_cell_forbidden,
        ),
        (
            "doc23_seq_u32_max_allow_sbr",
            _mut_doc23_seq_u32_max_allow_sbr,
        ),
        (
            "doc23_link_down_lump_overflow",
            _mut_doc23_link_down_lump_overflow,
        ),
        (
            "doc23_continuity_drop_prefence",
            _mut_doc23_continuity_drop_prefence,
        ),
        (
            "doc23_reset_parser_tx_also_cold",
            _mut_doc23_reset_parser_tx_also_cold,
        ),
        (
            "adr_esp_tinyusb_exact_version_u0",
            _mut_adr_esp_tinyusb_exact_version_u0,
        ),
        (
            "doc23_allow_stale_reset_to_fence_new_session",
            _mut_doc23_allow_stale_reset_to_fence_new_session,
        ),
        (
            "doc23_notice_slot_unbounded",
            _mut_doc23_notice_slot_unbounded,
        ),
        # --- P1-A / P1-B U0 docs freezes ---
        (
            "doc23_continuity_tx_accept_refence",
            _mut_doc23_continuity_tx_accept_refence,
        ),
        (
            "doc23_continuity_cancel_on_hello_missing",
            _mut_doc23_continuity_cancel_on_hello_missing,
        ),
        (
            "doc23_stale_reset_no_seq_advance",
            _mut_doc23_stale_reset_no_seq_advance,
        ),
    ]

    print("radio_usb_boundary_docs_gate self-test: running mutations...")
    for label, mutator in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _copy_docs_tree(root)
            paths = Paths(root)
            _expect_fail(label, paths, mutator)

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _copy_docs_tree(root)
        (root / "docs" / "23-usb-radio-boundary.md").unlink()
        paths = Paths(root)
        try:
            run_check(paths)
            fail("self-test missing docs/23 did not fail")
        except GateFailure as e:
            print(f"  self-test mutation 'missing_doc23' correctly failed: {e}")

    print(
        f"radio_usb_boundary_docs_gate self-test ok: "
        f"{len(mutations) + 1} mutations each fail the real checker"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: radio_usb_boundary_docs_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "check":
            run_check()
            return 0
        run_self_test()
        return 0
    except GateFailure as e:
        print(f"radio_usb_boundary_docs_gate FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
