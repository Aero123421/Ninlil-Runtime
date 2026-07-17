#!/usr/bin/env python3
"""R2 PCP Normative freeze — structural semantic docs + header gate.

Checkers scope into algorithm/table/action blocks and require real verbs,
ordering, and closed outcomes. Marker-only leftovers must not greenwash.
Does not claim R2 body / legal / RF / HIL / re-review GO.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC24 = "docs/24-r2-physical-compliance-permit-authority.md"
ADR4 = "docs/adr/0004-r2-durable-permit-authority.md"
DOC23 = "docs/23-usb-radio-boundary.md"
HDR = "src/radio/pcp_authority.h"
PLATFORM = "include/ninlil/platform.h"
CONSUMER_C = "tests/radio/pcp_r2_consumer_compile_test.c"
STATS_STATIC_C = "tests/radio/pcp_r2_stats_width_static.c"

# Closed 24×u64 stats contract (order == offset/8). Docs/header/consumer must match.
STATS_FIELDS: list[str] = [
    "issue_ok",
    "issue_deny",
    "validate_ok",
    "validate_deny",
    "validate_error",
    "consume_ok",
    "consume_denied",
    "consume_fenced",
    "consume_error",
    "advance_ok",
    "advance_nop",
    "revoke_ok",
    "recover_ok",
    "recover_fail",
    "fence_set",
    "storage_commit_unknown",
    "fifo_out_of_order",
    "reentry_reject",
    "alias_reject",
    "gc_erased",
    "reserved_zero_0",
    "reserved_zero_1",
    "reserved_zero_2",
    "reserved_zero_3",
]
assert len(STATS_FIELDS) == 24


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read(root: pathlib.Path, rel: str) -> str:
    p = root / rel
    if not p.is_file():
        fail(f"missing {rel}")
    return p.read_text(encoding="utf-8")


def extract_fenced_after(doc: str, start_pat: str, label: str) -> str:
    """Extract first ```text ... ``` body after a heading/start match."""
    m = re.search(start_pat, doc, re.M)
    if not m:
        fail(f"cannot find start of {label}")
    rest = doc[m.end() :]
    m2 = re.search(r"```text\n(.*?)```", rest, re.S)
    if not m2:
        fail(f"missing ```text block for {label}")
    return m2.group(1)


# ---- stats parse + closed docs/header/consumer ----

def parse_stats_struct_fields(hdr: str) -> list[tuple[str, str]]:
    """Return [(ctype, name), ...] from typedef struct ninlil_pcp_r2_stats."""
    m = re.search(
        r"typedef\s+struct\s+ninlil_pcp_r2_stats\s*\{(.*?)\}\s*ninlil_pcp_r2_stats_t\s*;",
        hdr,
        re.S,
    )
    if not m:
        fail("cannot parse typedef struct ninlil_pcp_r2_stats")
    body = m.group(1)
    fields: list[tuple[str, str]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("/*") or line.startswith("//") or line.startswith("*"):
            continue
        fm = re.match(r"(uint\d+_t)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
        if not fm:
            fail(f"stats struct non-uintN_t field line: {line!r}")
        fields.append((fm.group(1), fm.group(2)))
    return fields


def check_stats_closed(hdr: str, doc: str, consumer: str) -> None:
    """Field set/order/type/offset/width closed across header, docs, consumer."""
    fields = parse_stats_struct_fields(hdr)
    if len(fields) != 24:
        fail(f"stats must have exactly 24 fields, got {len(fields)}")
    names = [n for _, n in fields]
    if names != STATS_FIELDS:
        fail(f"stats field set/order mismatch: got {names}")
    for ctype, name in fields:
        if ctype != "uint64_t":
            fail(f"stats field {name} must be uint64_t, got {ctype}")

    if "STATS_FIELDS_24_U64" not in doc:
        fail("docs missing STATS_FIELDS_24_U64 marker")
    for i, name in enumerate(STATS_FIELDS):
        off = i * 8
        # docs table row: | i | off | name | uint64_t |
        if not re.search(
            rf"\|\s*{i}\s*\|\s*{off}\s*\|\s*{re.escape(name)}\s*\|\s*uint64_t\s*\|",
            doc,
        ):
            fail(f"docs stats table missing row i={i} off={off} {name}")

    if "sizeof(ninlil_pcp_r2_stats_t) == 192u" not in hdr:
        fail("header missing sizeof stats == 192u assert")
    if "_Alignof(ninlil_pcp_r2_stats_t) == 8u" not in hdr:
        fail("header missing alignof stats == 8u assert")

    for i, name in enumerate(STATS_FIELDS):
        off = i * 8
        # offsetof assert present
        if not re.search(
            rf"offsetof\(\s*ninlil_pcp_r2_stats_t\s*,\s*{re.escape(name)}\s*\)\s*==\s*{off}u",
            hdr,
        ):
            fail(f"header missing offsetof({name})=={off}u")
        # width assert: sizeof(((T*)0)->field) == sizeof(uint64_t)
        width_pat = (
            rf"sizeof\(\s*\(\s*\(\s*ninlil_pcp_r2_stats_t\s*\*\s*\)\s*0\s*\)\s*->"
            rf"\s*{re.escape(name)}\s*\)\s*==\s*sizeof\(\s*uint64_t\s*\)"
        )
        if not re.search(width_pat, hdr):
            fail(f"header missing sizeof width assert for {name}")
        # consumer must independently lock offsetof + width (not rely on header only)
        if not re.search(
            rf"offsetof\(\s*ninlil_pcp_r2_stats_t\s*,\s*{re.escape(name)}\s*\)\s*==\s*{off}u",
            consumer,
        ):
            fail(f"consumer missing offsetof({name})=={off}u")
        if not re.search(width_pat, consumer):
            fail(f"consumer missing sizeof width assert for {name}")

    if "sizeof(ninlil_pcp_r2_stats_t) == 192u" not in consumer:
        fail("consumer missing sizeof stats == 192u")


# ---- header ----

def check_header_complete(hdr: str) -> None:
    need = [
        "typedef struct ninlil_pcp_error",
        "typedef struct ninlil_pcp_r2_stats",
        "struct ninlil_pcp {",
        "NINLIL_PCP_OBJECT_INIT",
        "ninlil_pcp_object_size",
        "ninlil_pcp_bind_storage",
        "ninlil_pcp_validate",
        "ninlil_pcp_r2_stats_t *out_stats",
        "NINLIL_PCP_STAGE_GC",
        "((ninlil_pcp_stage_t)11u)",
        "sizeof(ninlil_pcp_r2_stats_t) == 192u",
    ]
    for t in need:
        if t not in hdr:
            fail(f"header missing {t}")
    if re.search(
        r"ninlil_pcp_bind_(?:storage|clock|entropy)\s*\([^;]*void\s*\*\s*user",
        hdr,
    ):
        fail("bind_* must not take void *user")
    if "void *out_stats" in hdr:
        fail("stats must not use void*")
    stages = {
        "NONE": 0,
        "INIT": 1,
        "BIND": 2,
        "RECOVER": 3,
        "PUBLISH": 4,
        "ISSUE": 5,
        "VALIDATE": 6,
        "CONSUME": 7,
        "ADVANCE": 8,
        "REVOKE": 9,
        "SHUTDOWN": 10,
        "GC": 11,
    }
    for name, val in stages.items():
        pat = rf"#define\s+NINLIL_PCP_STAGE_{name}\s+\(\(ninlil_pcp_stage_t\){val}u\)"
        if not re.search(pat, hdr):
            fail(f"header stage {name}!={val}")


def check_docs_stage_table(doc: str) -> None:
    expected = {
        "NONE": 0,
        "INIT": 1,
        "BIND": 2,
        "RECOVER": 3,
        "PUBLISH": 4,
        "ISSUE": 5,
        "VALIDATE": 6,
        "CONSUME": 7,
        "ADVANCE": 8,
        "REVOKE": 9,
        "SHUTDOWN": 10,
        "GC": 11,
    }
    for name, val in expected.items():
        if not re.search(rf"NINLIL_PCP_STAGE_{name}\s*\|\s*{val}\b", doc):
            fail(f"docs stage table missing {name}={val}")
    if "STAGE_TABLE_COMPLETE 0..11 includes GC=11" not in doc:
        fail("docs missing STAGE_TABLE_COMPLETE marker")


# ---- scoped algorithm/table checkers ----

def check_algorithm_a_block(doc: str) -> None:
    """Scope ### 5.1 fenced algorithm; require real call-sites before := defs.

    Marker definitions alone (SEMANTIC_SYNC_* := ...) must not greenwash.
    Actual loop must invoke the sync verbs on advanced_any / partial-fail.
    """
    body = extract_fenced_after(
        doc,
        r"^### 5\.1 Algorithm A",
        "Algorithm A",
    )
    if "A4 loop:" not in body:
        fail("Algorithm A missing A4 loop:")

    # Split call region (A0..A4 actions) from definition region (A5 / :=)
    def_pos = -1
    for needle in (
        "SEMANTIC_SYNC_RAM_TRUST_FROM_META :=",
        "SEMANTIC_SYNC_RAM_TRUST_FROM_META:=",
        ":= ram_trust_epoch/now",
    ):
        p = body.find(needle)
        if p >= 0 and (def_pos < 0 or p < def_pos):
            def_pos = p
    call_region = body[: def_pos if def_pos >= 0 else len(body)]

    # Call-sites only: exclude pure definition lines even if they appear early
    call_lines = [
        ln
        for ln in call_region.splitlines()
        if ":=" not in ln and not ln.strip().startswith("SEMANTIC_SYNC_RAM_TRUST_FROM_META :=")
    ]
    call_text = "\n".join(call_lines)

    # At least two advanced_any → sync-from-meta call-sites in the loop body
    calls = re.findall(
        r"if advanced_any:\s*SEMANTIC_SYNC_RAM_TRUST_FROM_META;\s*clear ram_validate",
        call_text,
    )
    if len(calls) < 2:
        fail(
            "Algorithm A loop must invoke SEMANTIC_SYNC_RAM_TRUST_FROM_META "
            f"on advanced_any at least twice (found {len(calls)} in call region)"
        )

    # partial-fail path must sync to S in call region (not only define it)
    if not re.search(
        r"SEMANTIC_SYNC_RAM_TRUST_TO_S;\s*clear ram_validate",
        call_text,
    ):
        fail("Algorithm A partial-fail path must SEMANTIC_SYNC_RAM_TRUST_TO_S in loop")

    if "PROGRESS_CONTINUE" not in call_text:
        fail("Algorithm A missing PROGRESS_CONTINUE in loop")

    # last_consumed advance action inside loop
    if not re.search(
        r"last_consumed_seq\s*=\s*head|last_consumed\s*=\s*head",
        call_text,
    ):
        fail("Algorithm A must advance last_consumed in loop")

    # put REVOKED action inside loop (actual durable mutation verb)
    if not re.search(r"put\s+REVOKED", call_text):
        fail("Algorithm A loop must put REVOKED")

    # Definitions must still exist (for implementers) but are not substitutes
    if "ram_trust_epoch/now ← meta.last_trusted_*" not in body:
        fail("Algorithm A missing RAM←meta definition")
    if "ram_trust_epoch/now ← S" not in body:
        fail("Algorithm A missing RAM←S definition")


def check_publish_block(doc: str) -> None:
    """Scope publish 手順 fenced block; require full-scan loop actions.

    Marker PUBLISH_FULL_NAMESPACE_SCAN alone is insufficient: must have
    iter_open(empty), loop iter_next with KEY_*, foreign fence action, and
    closed outcomes (foreign / iss_count / meta_count / EMPTY iff).
    """
    # Heading ends with `:**` (colon inside bold), not `**:`
    m = re.search(
        r"\*\*publish 手順[^\n]*:\*\*\s*\n+```text\n(.*?)```",
        doc,
        re.S,
    )
    if not m:
        fail("missing publish 手順 ```text block")
    body = m.group(1)

    if "PUBLISH_FULL_NAMESPACE_SCAN" not in body:
        fail("publish block missing PUBLISH_FULL_NAMESPACE_SCAN label")

    # Actual open empty prefix (action verb, not comment)
    if not re.search(
        r"iter_open\(\s*prefix\s*=\s*empty bytes_view length 0\s*\)",
        body,
    ):
        fail("publish scan must iter_open empty prefix (action)")

    # Actual loop
    if not re.search(r"loop iter_next\s*:", body):
        fail("publish scan must have loop iter_next:")

    loop_m = re.search(
        r"loop iter_next\s*:(.*?)iter_close",
        body,
        re.S,
    )
    if not loop_m:
        fail("publish loop must end with iter_close")
    loop = loop_m.group(1)

    for tok in ("KEY_META", "KEY_ISS", "KEY_FOREIGN"):
        if tok not in loop:
            fail(f"publish loop missing {tok}")

    # Foreign handling must set foreign=1 + FOREIGN_KEY (not ignore)
    if not re.search(
        r"KEY_FOREIGN\s*→\s*foreign\s*=\s*1\s*;\s*reason\s*=\s*FOREIGN_KEY",
        loop,
    ):
        fail("publish KEY_FOREIGN must set foreign=1; reason=FOREIGN_KEY")
    if re.search(
        r"KEY_FOREIGN\s*→\s*ignore",
        loop,
        re.I,
    ):
        fail("publish KEY_FOREIGN must not ignore foreign keys")

    # Closed outcomes after loop (structural order verbs)
    if not re.search(r"if foreign:\s*rollback;\s*F_k", body):
        fail("publish must rollback F_k on foreign")
    if not re.search(r"if iss_count\s*>\s*0:\s*rollback;\s*F_k", body):
        fail("publish must reject iss_count>0 as non-EMPTY")
    if not re.search(r"if meta_count\s*>\s*0:\s*rollback", body):
        fail("publish must reject existing meta")
    if "EMPTY iff meta_count==0 AND iss_count==0 AND foreign==0" not in body:
        fail("publish EMPTY definition must match recover")


def check_recover_block(doc: str) -> None:
    """Scope §12 recover fenced algorithm; MODE_A empty-prefix + foreign fence."""
    text = extract_fenced_after(
        doc,
        r"^## 12\. `recover_storage`",
        "recover_storage",
    )
    if "CANONICAL_SCAN_MODE_A:" not in text:
        fail("recover missing CANONICAL_SCAN_MODE_A:")

    mode_a = re.search(
        r"CANONICAL_SCAN_MODE_A:(.*?)(?:R-S2|for each iter_next)",
        text,
        re.S,
    )
    if not mode_a:
        fail("cannot scope CANONICAL_SCAN_MODE_A block")
    ma = mode_a.group(1)
    if not re.search(
        r"iter_open\(\s*prefix\s*=\s*empty bytes_view length 0\s*\)",
        ma,
    ):
        fail("CANONICAL_SCAN_MODE_A must iter_open empty prefix")
    if re.search(r'iter_open\(\s*prefix\s*=\s*"iss/"\s*\)', ma):
        fail("CANONICAL_SCAN_MODE_A must not open iss/ prefix")

    # KEY_FOREIGN fence action in R-S2 body (not marker-only comment)
    if not re.search(
        r"KEY_FOREIGN:\s*else\s*\n\s*→ reason=FOREIGN_KEY; fence_bits\|=CORRUPT; F_k; goto CLEANUP_FAIL",
        text,
    ):
        fail("recover KEY_FOREIGN must fence CORRUPT (action)")
    if re.search(
        r"KEY_FOREIGN:[^\n]*\n\s*→\s*ignore foreign",
        text,
        re.I,
    ):
        fail("recover KEY_FOREIGN must not ignore foreign keys")


def check_open_table_row(doc: str) -> None:
    """Parse §13 open table row; OK+NULL cell must reject, not adopt.

    Marker OPEN_OK_NULL_REJECT kept while cell outcome becomes adopt → FAIL.
    """
    m = re.search(
        r"^\|\s*open\s*\|([^|\n]+)\|([^|\n]+)\|([^|\n]+)\|([^|\n]+)\|([^|\n]+)\|",
        doc,
        re.M,
    )
    if not m:
        fail("missing open row in storage shape table")
    ok_nonnull = m.group(1).strip()
    ok_null = m.group(2).strip()

    if "adopt" not in ok_nonnull.lower():
        fail("open OK+non-NULL should adopt handle")

    # OK+NULL must reject / CORRUPT and must not say adopt as outcome
    if re.search(r"\badopt\b", ok_null, re.I) and "禁止" not in ok_null:
        fail("open OK+NULL cell must not adopt (actual outcome)")
    if not re.search(r"REJECT_OK_NULL|CORRUPT", ok_null):
        fail("open OK+NULL cell must REJECT/CORRUPT")
    # Marker must live in the cell itself (scope to actual table outcome)
    if "OPEN_OK_NULL_REJECT" not in ok_null:
        fail("open OK+NULL cell must contain OPEN_OK_NULL_REJECT")


def check_e3_action(doc: str) -> None:
    body = extract_fenced_after(doc, r"^#### 5\.3\.2 E-body", "E-body")
    if not re.search(
        r"while M_live\.outstanding_count > 0:\s*\n"
        r"(?:.*\n){0,8}?\s*put REVOKED; outstanding--; last_consumed=head",
        body,
    ):
        if not re.search(
            r"while M_live\.outstanding_count > 0:\s*\n"
            r"(?:.*\n){0,8}?\s*put REVOKED; outstanding--; last_consumed=head",
            doc,
        ):
            fail("E3 must put REVOKED inside while outstanding")


def check_i14(doc: str) -> None:
    m = re.search(
        r"EQUATION:\s*next_issue_seq\s*==\s*last_consumed_seq\s*([+-])\s*(\d+)",
        doc,
    )
    if not m or m.group(1) != "+" or m.group(2) != "1":
        fail("I14 must be last_consumed_seq + 1")


def check_commit_unknown(doc: str) -> None:
    if "never CONSUME_DENIED" not in doc:
        fail("COMMIT_UNKNOWN must never CONSUME_DENIED")
    if "CONSUME_FENCED" not in doc:
        fail("COMMIT_UNKNOWN needs CONSUME_FENCED")


def check_validate_stage(doc: str) -> None:
    if "validate_stage_value=7" not in doc:
        fail("validate_stage_value=7 missing")
    if re.search(r"NULL/STRUCT/ALIAS[^\n]*\*\*8\*\*", doc):
        fail("validate stage must not be 8")
    if not re.search(r"NULL/STRUCT/ALIAS[^\n]*\*\*7\*\*", doc):
        fail("validate stage rows must use **7**")


def check_fresh_epoch(doc: str) -> None:
    if not re.search(r"S\.epoch\s*!=\s*M_snap\.last_trusted_epoch_id", doc):
        fail("new_epoch must use !=")
    if "not-all-zero" not in doc:
        fail("fresh epoch not-all-zero missing")


def check_unknown_no_volatile_s(doc: str) -> None:
    if "S を参照してはならない" not in doc and "揮発" not in doc:
        fail("UNKNOWN recovery must forbid volatile S")
    if not re.search(r"close\s*\(\s*handle\s*\)", doc):
        fail("UNKNOWN recovery must close(handle)")
    if "ram_trust_epoch := meta.last_trusted_epoch_id" not in doc:
        fail("post-recover RAM must rebuild from durable meta")


def check_crc(doc: str) -> None:
    gold = {
        "G0": f"{zlib.crc32(b'') & 0xFFFFFFFF:08x}",
        "G1": f"{zlib.crc32(b'123456789') & 0xFFFFFFFF:08x}",
        "G2": f"{zlib.crc32(b'abc') & 0xFFFFFFFF:08x}",
        "G3": f"{zlib.crc32(bytes(196)) & 0xFFFFFFFF:08x}",
        "G4": f"{zlib.crc32(bytes(228)) & 0xFFFFFFFF:08x}",
        "G5": f"{zlib.crc32((0x31504350).to_bytes(4, 'little') + bytes(192)) & 0xFFFFFFFF:08x}",
        "G6": f"{zlib.crc32(b'iss/0000000000000001') & 0xFFFFFFFF:08x}",
    }
    for gid, hx in gold.items():
        if hx not in doc.lower():
            fail(f"CRC {gid} missing {hx}")


def check_header_path(doc: str) -> None:
    if "src/radio/pcp_authority.h" not in doc:
        fail("docs must cite src/radio/pcp_authority.h")


def check_chapters(doc: str, doc23: str) -> None:
    for n in range(0, 16):
        if not re.search(rf"^## {n}\. ", doc, re.M):
            fail(f"missing ## {n}.")
    if "§14" not in doc23:
        fail("docs/23 must reference §14")


def run_check(root: pathlib.Path | None = None) -> None:
    root = root or REPO
    doc = read(root, DOC24)
    hdr = read(root, HDR)
    doc23 = read(root, DOC23)
    # Consumer may live only in REPO (not copied for doc-only mutations).
    consumer_path = root / CONSUMER_C
    if consumer_path.is_file():
        consumer = consumer_path.read_text(encoding="utf-8")
    else:
        consumer = read(REPO, CONSUMER_C)
    _ = read(root, ADR4)
    _ = read(root, PLATFORM)

    check_header_complete(hdr)
    check_stats_closed(hdr, doc, consumer)
    check_docs_stage_table(doc)
    check_header_path(doc)
    check_i14(doc)
    check_commit_unknown(doc)
    check_e3_action(doc)
    check_algorithm_a_block(doc)
    check_publish_block(doc)
    check_recover_block(doc)
    check_open_table_row(doc)
    check_validate_stage(doc)
    check_fresh_epoch(doc)
    check_unknown_no_volatile_s(doc)
    check_crc(doc)
    check_chapters(doc, doc23)
    if "GO 禁止" not in doc and "GO 主張禁止" not in doc:
        fail("must forbid re-review GO")


def _mut(path: pathlib.Path, old: str, new: str, all_occ: bool) -> None:
    t = path.read_text(encoding="utf-8")
    if old not in t:
        raise RuntimeError(f"anchor missing: {old[:120]!r}")
    path.write_text(
        t.replace(old, new) if all_occ else t.replace(old, new, 1),
        encoding="utf-8",
    )


def _compile_with_header_root(hdr_root: pathlib.Path, src_rel: str, out_name: str) -> int:
    """Compile a C TU against hdr_root's src/radio (mutated header) + repo includes.

    Returns compiler returncode (0 == success).
    """
    import subprocess

    src = REPO / src_rel
    out = hdr_root / out_name
    cmd = [
        "cc",
        "-std=c11",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-c",
        str(src),
        "-o",
        str(out),
        f"-I{hdr_root / 'src' / 'radio'}",
        f"-I{REPO / 'src' / 'radio'}",
        f"-I{REPO / 'include'}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode


def run_self_test() -> None:
    """Mutations destroy actual actions or field widths; markers may remain.

    Stats width mutations also require consumer compile + static TU to FAIL
    (padding must not greenwash uint8_t narrowing while sizeof==192).
    """
    # (name, rel, old, new, all_occ, require_compile_fail)
    mutations: list[tuple[str, str, str, str, bool, bool]] = [
        # --- stats width: any field → uint8_t must fail check + compile ---
        (
            "M_stats_issue_ok_u8",
            HDR,
            "    uint64_t issue_ok;",
            "    uint8_t issue_ok;",
            False,
            True,
        ),
        (
            "M_stats_reserved_zero_0_u8",
            HDR,
            "    uint64_t reserved_zero_0;",
            "    uint8_t reserved_zero_0;",
            False,
            True,
        ),
        (
            "M_stats_consume_fenced_u8",
            HDR,
            "    uint64_t consume_fenced;",
            "    uint8_t consume_fenced;",
            False,
            True,
        ),
        # --- 4 false-green killers (markers kept, actions destroyed) ---
        (
            "A_actual_sync_removed",
            DOC24,
            "if advanced_any: SEMANTIC_SYNC_RAM_TRUST_FROM_META; clear ram_validate",
            "if advanced_any: clear ram_validate  // sync call removed, marker def kept",
            True,
            False,
        ),
        (
            "publish_actual_loop_removed",
            DOC24,
            "         iter_open(prefix = empty bytes_view length 0)\n"
            "         // REQUIRED empty-prefix; FORBIDDEN sole iss/ scan\n"
            "         meta_count=0; iss_count=0; foreign=0\n"
            "         loop iter_next:\n"
            "           OK:\n"
            "             KEY_META → meta_count++; value validate CRC (if present → not empty)\n"
            "             KEY_ISS  → iss_count++\n"
            "             KEY_FOREIGN → foreign=1; reason=FOREIGN_KEY\n"
            "           NOT_FOUND → end\n"
            "           other → map §7.8; CLEANUP_FAIL\n"
            "         iter_close",
            "         // PUBLISH_FULL_NAMESPACE_SCAN marker kept; actual loop removed\n"
            "         meta_count=0; iss_count=0; foreign=0\n"
            "         // assume empty without iterator",
            False,
            False,
        ),
        (
            "open_actual_adopt_marker_kept",
            DOC24,
            "| open | adopt handle | **REJECT_OK_NULL→CORRUPT/F_k**（adopt 禁止） SEMANTIC: OPEN_OK_NULL_REJECT | map §7.1 | **close exactly once** then F_k CORRUPT | F_k; close if handle |",
            "| open | adopt handle | **OK+NULL → adopt handle** SEMANTIC: OPEN_OK_NULL_REJECT | map §7.1 | **close exactly once** then F_k CORRUPT | F_k; close if handle |",
            False,
            False,
        ),
        (
            "publish_foreign_actual_ignore",
            DOC24,
            "             KEY_FOREIGN → foreign=1; reason=FOREIGN_KEY",
            "             KEY_FOREIGN → ignore foreign key; continue",
            False,
            False,
        ),
        # --- existing action mutations ---
        (
            "M_E3_put_revoked_deleted",
            DOC24,
            "      put REVOKED; outstanding--; last_consumed=head",
            "      // put REVOKED deleted; outstanding--; last_consumed=head",
            False,
            False,
        ),
        (
            "M_recover_iss_scan",
            DOC24,
            "     iter_open(prefix = empty bytes_view length 0)\n"
            "     // REQUIRED: empty-prefix full namespace scan\n"
            "     // FORBIDDEN as sole scan: iter_open(\"iss/\") without full-namespace pass",
            "     iter_open(prefix = \"iss/\")\n"
            "     // REQUIRED: iss-only scan\n"
            "     // full-namespace pass not required",
            False,
            False,
        ),
        (
            "M_foreign_ignore_recover",
            DOC24,
            "       KEY_FOREIGN: else\n"
            "         → reason=FOREIGN_KEY; fence_bits|=CORRUPT; F_k; goto CLEANUP_FAIL",
            "       KEY_FOREIGN: else\n"
            "         → ignore foreign key; continue",
            False,
            False,
        ),
        (
            "SEM_I14_plus2",
            DOC24,
            "EQUATION: next_issue_seq == last_consumed_seq + 1",
            "EQUATION: next_issue_seq == last_consumed_seq + 2",
            False,
            False,
        ),
        (
            "SEM_CRC",
            DOC24,
            "cbf43926",
            "deadbeef",
            True,
            False,
        ),
        (
            "SEM_COMMIT",
            DOC24,
            "never CONSUME_DENIED",
            "always CONSUME_DENIED",
            False,
            False,
        ),
        (
            "M_validate_stage_8",
            DOC24,
            "validate_stage_value=7",
            "validate_stage_value=8",
            False,
            False,
        ),
        (
            "M_fresh_eq",
            DOC24,
            "S.epoch != M_snap.last_trusted_epoch_id",
            "S.epoch == M_snap.last_trusted_epoch_id",
            False,
            False,
        ),
        (
            "M_stage_gc_docs",
            DOC24,
            "| NINLIL_PCP_STAGE_GC | 11 |",
            "| NINLIL_PCP_STAGE_GC | 10 |",
            False,
            False,
        ),
    ]
    copies = [
        DOC24,
        ADR4,
        DOC23,
        HDR,
        PLATFORM,
        "include/ninlil/version.h",
        CONSUMER_C,
        STATS_STATIC_C,
    ]
    for name, rel, old, new, allo, need_compile_fail in mutations:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            for p in copies:
                s = REPO / p
                d = root / p
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d)
            try:
                _mut(root / rel, old, new, allo)
            except RuntimeError as e:
                fail(f"self-test {name}: {e}")
            check_failed = False
            try:
                run_check(root)
            except GateFailure:
                check_failed = True
            if not check_failed:
                fail(f"self-test {name}: check unexpectedly passed (false-green)")
            if need_compile_fail:
                rc_cons = _compile_with_header_root(
                    root, CONSUMER_C, "consumer_mut.o"
                )
                if rc_cons == 0:
                    fail(
                        f"self-test {name}: consumer compile unexpectedly "
                        "passed (padding greenwash)"
                    )
                rc_static = _compile_with_header_root(
                    root, STATS_STATIC_C, "stats_static_mut.o"
                )
                if rc_static == 0:
                    fail(
                        f"self-test {name}: stats static TU unexpectedly "
                        "passed (padding greenwash)"
                    )
                print(
                    f"self-test {name}: fail as expected "
                    f"(check+consumer+static rc={rc_cons},{rc_static})"
                )
            else:
                print(f"self-test {name}: fail as expected")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: pcp_r2_docs_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            run_check()
            print(
                "pcp_r2_docs_gate ok: scoped action-block parse "
                "+ stats 24×u64 closed (docs/header/consumer)"
            )
        else:
            run_self_test()
            print("pcp_r2_docs_gate self-test ok")
        return 0
    except GateFailure as e:
        print(f"pcp_r2_docs_gate FAIL: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # pragma: no cover
        print(f"pcp_r2_docs_gate ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
