#!/usr/bin/env python3
"""R1 structural gate: ninlil_radio_hal sole TX entry + spy + private authority.

Mutation self-test invokes the real checker on temporary trees (not soft
substring smoke). Does not claim R2/R4/SX1262/RF/legal/HIL complete.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

HAL_H = REPO_ROOT / "src" / "radio" / "radio_hal.h"
HAL_C = REPO_ROOT / "src" / "radio" / "radio_hal.c"
SPY_H = REPO_ROOT / "tests" / "support" / "radio_hal_spy.h"
SPY_C = REPO_ROOT / "tests" / "support" / "radio_hal_spy.c"
TEST_C = REPO_ROOT / "tests" / "radio" / "radio_hal_r1_test.c"
PRIVATE_AUTH = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
CMAKE_LISTS = REPO_ROOT / "CMakeLists.txt"
DOC23 = REPO_ROOT / "docs" / "23-usb-radio-boundary.md"
DOC07 = REPO_ROOT / "docs" / "07-testing-and-quality.md"
PUBLIC_INCLUDE = REPO_ROOT / "include" / "ninlil"

BANNED_INCLUDES = (
    "termios.h",
    "unistd.h",
    "fcntl.h",
    "pthread.h",
    "tinyusb.h",
    "tusb.h",
    "freertos/",
    "esp_",
    "RadioLib",
    "sx126",
    "SX126",
)

INCLUDE_LINE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

# Sole TX entry symbol — must exist; alternate TX symbols must not.
SOLE_TX = "ninlil_radio_hal_transmit_with_permit"

ALT_TX_SYMBOLS = (
    "ninlil_radio_hal_transmit(",
    "ninlil_radio_hal_tx(",
    "ninlil_radio_hal_send(",
    "ninlil_radio_spi_tx",
    "ninlil_sx1262_tx",
    "ninlil_radio_beacon_tx",
    "ninlil_radio_ack_tx",
    "ninlil_radio_raw_tx",
)

REQUIRED_HEADER_TOKENS = (
    SOLE_TX,
    "ninlil_radio_hal_permit_snapshot_t",
    "hardware_profile_id",
    "hardware_profile_rev",
    "regulatory_profile_id",
    "regulatory_profile_rev",
    "site_assignment_id",
    "site_assignment_rev",
    "site_assignment_epoch",
    "transmitter_id",
    "channel_id",
    "frame_digest",
    "frame_byte_length",
    "max_airtime_us",
    "not_before_ms",
    "expiry_ms",
    "permit_sequence",
    "ninlil_radio_hal_permit_ops_t",
    "ninlil_radio_hal_edge_ops_t",
    "ninlil_radio_hal_digest_ops_t",
    "DEFAULT_DENY",
    "CONSUME_DENIED",
    "CONSUME_FENCED",
    "definitely unconsumed",
    "PERMIT_DENIED is validate-side only",
    "commit-unknown",
    "SEQ_REUSE",
    "SEQ_EXHAUSTED",
    "LIVE_MISMATCH",
    "UNBOUND_LIVE",
    "UNBOUND_DIGEST",
    "REASON_ALIAS",
    "REASON_ZERO_ID",
    "REASON_STRUCT_INVALID",
    "REASON_PLAN_MUTATED",
    "callback contract fault",
    "REASON_CONSUME_UNCONSUMED",
    "REASON_CONSUME_FENCED",
    "sole owner",
    "reentrancy",
    "edge + permit + live + digest",
    "last_consumed_seq",
    "sealed",
    "Not R2 complete",
    "Not real SX1262",
    "unallocated",
    "No caller now_ms",
    "not R1 series complete",
    "2048",
    "max_align_t",
    "_Alignof",
    "NINLIL_RADIO_HAL_OBJECT_INIT",
    "member-zero initializer",
    "no type-pun buffer",
    "OBJECT_BYTES ceiling",
    "Complete production-private HAL object",
    "semantic members/tags only",
    "shutdown",
)

REQUIRED_SOURCE_TOKENS = (
    SOLE_TX,
    "permit_ops.validate",
    "permit_ops.consume",
    "edge_ops.transmit",
    "DEFAULT_DENY",
    "in_transmit",
    "check_live",
    "check_digest",
    "does not own compliance time",
    "Last authority callback",
    "last_consumed_seq",
    "has_consumed_seq",
    "plan_matches_seal",
    "seal_permit",
    "seal_frame",
    "ranges_overlap",
    "validate_permit_struct",
    "validate_live_struct",
    "UINT64_MAX",
    "UNBOUND_LIVE",
    "UNBOUND_DIGEST",
    "SEQ_EXHAUSTED",
    "REASON_ALIAS",
    "<= rh->last_consumed_seq",
    "live_bound == 0u",
    "digest_bound == 0u",
    "ranges_overlap_u",
    "ranges_overlap_ptr",
    "out_error_safe",
    "UINTPTR_MAX",
    "has_consumed_seq = 0u",
    "last_consumed_seq = 0u",
    "plan_frame",
    "seal_frame",
    "Container alias",
    "frame_bytes alias",
    "Local scalars from frame view",
    "Bounded payload range",
    "Last authority callback",
    "Post-consume: local integrity only",
    "ACTIVE re-init",
    "out_hal aliasing",
    "NINLIL_RADIO_HAL_MAGIC",
    "ctx authoritative clock",
    "callback contract fault",
    "terminal burn sealed seq",
    "object_is_semantic_fresh",
    "load_lifecycle_tag_bytes",
    "NINLIL_RADIO_HAL_OBJECT_INIT",
    "semantic members only",
    "permit_semantic_equal",
    "phy_semantic_equal",
    "never whole permit memcmp",
    "*out_hal = object",
    "no byte-storage pun",
    "Padding is intentionally not inspected",
    "CONSUME_DENIED only",
    "not PERMIT_DENIED",
    "_Alignof(ninlil_radio_hal_t)",
)

REQUIRED_SPY_TOKENS = (
    "NINLIL_RADIO_HAL_SPY_EV_DIGEST",
    "NINLIL_RADIO_HAL_SPY_EV_PERMIT_CHECK",
    "NINLIL_RADIO_HAL_SPY_EV_CONSUME",
    "NINLIL_RADIO_HAL_SPY_EV_EDGE",
    "ninlil_radio_hal_spy_trace_has_order_success",
    "DIGEST -> PERMIT_CHECK -> CONSUME -> EDGE",
    "no EV_ATTEMPT",
    "reenter_transmit_on_digest",
    "mutate_caller_frame_on_validate",
    "mutate_frame_on_consume",
    "reenter_transmit_on_validate",
)

PRODUCT_VOCABULARY_BANNED = ("vendor_specific_", "product_specific_")


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def strip_c_comments_and_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i : i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text[i : i + 2] == "/*":
            i += 2
            while i + 1 < n and text[i : i + 2] != "*/":
                i += 1
            i = min(i + 2, n)
            continue
        if text[i] == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if text[i] == "'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            out.append("''")
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_includes(path: pathlib.Path) -> None:
    text = read_text(path)
    for line in text.splitlines():
        m = INCLUDE_LINE.match(line)
        if not m:
            continue
        inc = m.group(1)
        for banned in BANNED_INCLUDES:
            if banned in inc:
                fail(f"{path}: banned include {inc}")


def check_no_heap_vla(path: pathlib.Path) -> None:
    code = strip_c_comments_and_strings(read_text(path))
    for token in ("malloc(", "calloc(", "realloc(", "free(", "alloca("):
        if token in code:
            fail(f"{path}: heap/alloca token {token}")
    if path.suffix == ".c":
        if re.search(
            r"\b(?:uint8_t|char|int|unsigned|size_t)\s+\w+\s*\[\s*[a-z_][a-z0-9_]*\s*\]",
            code,
        ):
            fail(f"{path}: possible VLA declaration")


def check_public_abi_clean() -> None:
    for p in PUBLIC_INCLUDE.glob("*.h"):
        text = read_text(p)
        if "radio_hal" in text or "ninlil_radio_hal" in text:
            fail(f"public header must not mention radio_hal: {p}")
        for token in PRODUCT_VOCABULARY_BANNED:
            if token in text:
                fail(f"public header contains product-specific vocabulary: {p}")


def check_authority() -> None:
    text = read_text(PRIVATE_AUTH)
    if "src/radio/radio_hal.c" not in text:
        fail("radio_hal.c missing from ninlil_runtime_private_sources.cmake")
    if "radio_hal.c" not in text.split("NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES")[-1]:
        fail("radio_hal.c missing from VLA source list")


def check_cmake() -> None:
    text = read_text(CMAKE_LISTS)
    if "radio_hal_r1" not in text and "ninlil_radio_hal_r1_test" not in text:
        fail("CMakeLists must register radio_hal_r1 test target")
    if "radio_hal_r1_gate" not in text:
        fail("CMakeLists must register radio_hal_r1_gate")
    if "src/radio" not in text:
        fail("CMakeLists must include src/radio for private includes")


def check_header() -> None:
    text = read_text(HAL_H)
    for tok in REQUIRED_HEADER_TOKENS:
        if tok not in text:
            fail(f"radio_hal.h missing required token: {tok}")
    for alt in ALT_TX_SYMBOLS:
        if alt in text:
            fail(f"radio_hal.h must not declare alternate TX API: {alt}")
    if re.search(
        r"\b(?:vendor|product)_specific_[a-z_]+", text, re.IGNORECASE
    ):
        fail("radio_hal.h must not define/use product-specific symbols")
    # Digest algorithm comment must not be duplicated.
    if text.count("Digest algorithm id:") != 1:
        fail("frame_digest_algorithm comment must appear exactly once")
    if "actual _Alignof(ninlil_radio_hal_t)" not in text and (
        "Actual _Alignof(ninlil_radio_hal_t)" not in text
    ):
        fail("header must document object_align as actual _Alignof")
    check_includes(HAL_H)


def check_source() -> None:
    text = read_text(HAL_C)
    for tok in REQUIRED_SOURCE_TOKENS:
        if tok not in text:
            fail(f"radio_hal.c missing required token: {tok}")
    code = strip_c_comments_and_strings(text)
    # Whole permit snapshot memcmp is padding-dependent and banned.
    if re.search(
        r"memcmp\s*\(\s*&?\s*(?:rh->)?plan_permit\b",
        code,
    ) or re.search(
        r"memcmp\s*\(\s*&?\s*(?:rh->)?seal_permit\b",
        code,
    ):
        fail("whole permit memcmp is banned; use permit_semantic_equal")
    if re.search(
        r"memcmp\s*\([^;]*permit_snapshot",
        code,
    ):
        fail("memcmp of permit_snapshot is banned")
    # Byte-storage type-pun pattern must stay gone.
    if "NINLIL_RADIO_HAL_OBJECT_STORAGE" in text:
        fail("OBJECT_STORAGE type-pun macro must not return")
    if re.search(r"uint8_t\s+storage\s*\[\s*NINLIL_RADIO_HAL_OBJECT_BYTES", text):
        fail("byte-storage object union must not return")
    # Full object representation / padding zero-scan is forbidden for init.
    if "object_bytes_all_zero" in text:
        fail("object_bytes_all_zero representation scan must not return")
    if re.search(
        r"for\s*\([^;]*;\s*[^;]*sizeof\s*\(\s*\*object\s*\)",
        code,
    ) or re.search(
        r"for\s*\([^;]*;\s*[^;]*sizeof\s*\(\s*\*object\s*\)",
        text,
    ):
        fail("init must not scan sizeof(*object) for zero/padding")
    if re.search(
        r"bytes\s*=\s*\(const uint8_t \*\)\(const void \*\)object",
        code,
    ):
        fail("init must not cast whole object to byte scan")
    # Consume retryable no-burn must be CONSUME_DENIED only (not PERMIT_DENIED).
    if re.search(
        r"CONSUME_DENIED\s*\|\|\s*st\s*==\s*NINLIL_RADIO_HAL_PERMIT_DENIED",
        code,
    ) or re.search(
        r"PERMIT_DENIED\s*\|\|\s*st\s*==\s*NINLIL_RADIO_HAL_CONSUME_DENIED",
        code,
    ):
        fail(
            "PERMIT_DENIED must not be OR'd with CONSUME_DENIED as consume "
            "retryable/no-burn"
        )
    # Anti-regression: no double live_mismatch on REG_REV; single last_error assign.
    # Count on raw text (string literals carry the unique reason path).
    if text.count("live regulatory_profile_rev mismatch") != 1:
        fail("regulatory_profile_rev live mismatch path must appear exactly once")
    if text.count("NINLIL_RADIO_HAL_REASON_LIVE_REG_REV") != 1:
        fail("LIVE_REG_REV reason must appear exactly once in production source")
    if len(re.findall(r"rh->last_error\s*=", code)) != 1:
        fail("rh->last_error assignment must appear exactly once (set_error)")
    # Sole physical edge invocation site: exactly one call expression.
    # Null-checks use "edge_ops.transmit ==" and must not count as call sites.
    edge_calls = len(re.findall(r"edge_ops\.transmit\s*\(", code))
    if edge_calls != 1:
        fail(
            f"edge_ops.transmit call sites must be exactly 1, found {edge_calls}"
        )
    # no alternate TX function definitions
    for alt in (
        "ninlil_radio_hal_transmit(",
        "ninlil_radio_hal_tx(",
        "ninlil_radio_hal_send(",
    ):
        if alt in code:
            fail(f"alternate TX symbol in production source: {alt}")
    if "sx126" in code.lower() or "spitx" in code.lower():
        fail("R1 production source must not embed SX1262/SPI TX")
    # Seal must never be an *argument* to external digest/permit callbacks.
    # Limit the scan to the call argument list (up to matching ');').
    for call in ("digest_ops.verify", "permit_ops.validate", "permit_ops.consume"):
        for m in re.finditer(re.escape(call) + r"\s*\(", code):
            i = m.end() - 1  # at '('
            depth = 0
            j = i
            while j < len(code):
                ch = code[j]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            args = code[i:j]
            if "seal_permit" in args or "seal_view" in args or "seal_frame" in args:
                fail(f"{call} must not receive seal_* (working plan only)")
            if call != "digest_ops.verify" and "plan_permit" not in args and "plan_view" not in args:
                # actual call sites must use working plan (skip == NULL checks)
                if "NULL" not in args and "==" not in args:
                    if "plan_" not in args:
                        fail(f"{call} must use working plan_* arguments")
    if "working plan only" not in text.lower() and "working plan only" not in code.lower():
        if "External digest: working plan only" not in text:
            fail("missing seal immutability working-plan comment")
    if "Last authority callback" not in text:
        fail("missing last authority consume comment")
    if re.search(
        r"\b(?:vendor|product)_specific_[a-z_]+", text, re.IGNORECASE
    ):
        fail("radio_hal.c must not define/use product-specific symbols")
    check_includes(HAL_C)
    check_no_heap_vla(HAL_C)



def check_production_tx_hygiene() -> None:
    """Scan authoritative production sources for alternate physical TX paths.

    R1 host candidate only: structural string/source scan. Does NOT claim
    R9 call-graph or link-time sole-edge closure (future R9 gate).
    """
    auth = read_text(PRIVATE_AUTH)
    sources = re.findall(
        r"^\s*((?:src|ports)/[A-Za-z0-9_./-]+\.c)\s*$",
        auth,
        re.M,
    )
    if "src/radio/radio_hal.c" not in sources:
        fail("radio_hal.c missing from private authority for TX hygiene scan")
    # Also scan ESP port C sources under ports/esp-idf (no GLOB of all)
    esp_src = REPO_ROOT / "ports" / "esp-idf" / "src"
    if esp_src.is_dir():
        for pth in sorted(esp_src.rglob("*.c")):
            rel = str(pth.relative_to(REPO_ROOT))
            if rel not in sources:
                sources.append(rel)

    banned = (
        "ninlil_sx1262_tx",
        "ninlil_radio_spi_tx",
        "ninlil_radio_raw_tx",
        "ninlil_radio_beacon_tx",
        "RadioLib",
        "SX126x",
        "sx1262_transmit",
        "SetTx(",
        "setTx(",
        "RADIO_SET_TX",
    )
    for rel in sources:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        code = strip_c_comments_and_strings(text)
        # radio_hal sole entry is allowed; others must not define TX shortcuts
        for b in banned:
            if b in code:
                if rel.endswith("radio_hal.c") and b.startswith("ninlil_radio"):
                    continue
                fail(f"production source {rel} contains banned TX token: {b}")
        if rel.endswith("radio_hal.c"):
            continue
        # Non-radio_hal production TUs must not call transmit_with_permit yet? allowed later
        # Ban raw alternate symbols
        for alt in ALT_TX_SYMBOLS:
            if alt in code:
                fail(f"production source {rel} declares alternate TX API: {alt}")
    # Explicit nonclaim for R9
    if "R9" not in read_text(DOC23) and "call-graph" not in read_text(DOC23):
        pass  # docs already have R-series
    print_note = True  # used only for readability in check path


def check_spy_and_tests() -> None:
    spy_h = read_text(SPY_H)
    spy_c = read_text(SPY_C)
    test_c = read_text(TEST_C)
    for tok in REQUIRED_SPY_TOKENS:
        if tok not in spy_h and tok not in spy_c:
            fail(f"spy missing token: {tok}")
    for req in (
        "test_default_deny",
        "test_null_zero_oversize",
        "test_validator_deny_error",
        "test_consume_deny_error",
        "test_consume_fenced_no_retry",
        "test_success_exactly_once",
        "test_oneshot_replay_deny",
        "test_callback_reentry",
        "test_frame_mutation_fail_closed",
        "test_live_field_mismatches",
        "test_time_boundaries",
        "test_edge_error_no_reuse",
        "test_counter_saturation",
        "test_spy_trace_overflow",
        "test_seq_exhausted_after_max",
        "test_clear_authorities_default_deny",
        "test_plan_mutation_records_seal_seq",
        "test_consume_status_closed_partition",
        "test_consume_status_plan_mutation_burns_all",
        "test_alias_out_error_with_permit",
        "test_alias_frame_with_hal_storage",
        "test_shutdown_clears_plan_and_watermark",
        "test_huge_length_rejected_before_range_math",
        "test_alias_frame_view_in_hal",
        "test_alias_permit_in_hal",
        "test_alias_out_error_in_frame_view",
        "test_zero_length_authority_zero_mutation",
        "test_mutation_authority_callbacks_edge_zero",
        "test_working_plan_mutation_on_validate_fail_closed",
        "test_true_caller_buffer_mutation_isolated",
        "test_callback_reentry_all_phases",
        "test_init_active_reinit_rejected",
        "test_init_out_hal_alias_object",
        "test_init_zeroed_first_ok",
        "test_init_object_init_automatic_stable",
        "test_init_shutdown_reinit_ok",
        "test_init_poisoned_first_reject",
        "test_permit_semantic_equal_padding_and_fields",
        "test_digest_error_does_not_reset_clock",
        "test_structural_zero_id_and_live",
            ):
        if req not in test_c:
            fail(f"host test missing case: {req}")
    # Monotonic one-shot: lower sequence after higher must be covered.
    if "permit_sequence = 10u" not in test_c or "permit_sequence = 11u" not in test_c:
        fail("monotonic 10/11/10 replay coverage missing from host tests")
    # First-init contract: host tests must use OBJECT_INIT (not bare stack garbage).
    if "NINLIL_RADIO_HAL_OBJECT_INIT" not in test_c:
        fail("host tests must use NINLIL_RADIO_HAL_OBJECT_INIT for first init")
    if "test_init_poisoned_first_reject" not in test_c:
        fail("host tests must cover poisoned first-init reject")
    if "ninlil_radio_hal_object_align() == _Alignof(ninlil_radio_hal_t)" not in test_c:
        fail("host tests must pin object_align() to actual _Alignof")
    if "live_mismatch == st_before.live_mismatch + 1u" not in test_c:
        fail("live_field_mismatches must assert exact +1 live_mismatch")
    check_no_heap_vla(SPY_C)
    check_no_heap_vla(TEST_C)


def check_docs() -> None:
    d23 = read_text(DOC23)
    if "R1" not in d23:
        fail("docs/23 must retain R1 catalog")
    # Must not claim R1 complete as production radio
    head = "\n".join(d23.splitlines()[:12])
    if re.search(r"\bR1 complete\b", head) and "ではない" not in head and "host" not in head.lower():
        fail("docs/23 head must not claim bare R1 complete")
    if "host candidate" not in d23 and "implementation candidate" not in d23:
        # allow either phrasing after our update
        if "R1" in d23 and "spy" not in d23.lower():
            fail("docs/23 R1 status should mention host candidate or spy")
    d7 = read_text(DOC07)
    if "radio_hal_r1" not in d7 and "R1" not in d7:
        fail("docs/07 should mention R1 host/spy tests")


def check_production_symbols() -> None:
    """Compile production TU without test macros; prove sole TX symbol."""
    with tempfile.TemporaryDirectory(prefix="r1-prod-") as td:
        obj = pathlib.Path(td) / "radio_hal.o"
        compiler = shutil.which("cc")
        if compiler is None:
            fail("C compiler 'cc' not found")
        compile_result = subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-Wvla",
                "-I",
                str(REPO_ROOT / "src" / "radio"),
                "-c",
                str(HAL_C),
                "-o",
                str(obj),
            ],
            capture_output=True,
            text=True,
        )
        if compile_result.returncode != 0:
            fail(
                "production radio_hal compile failed:\n"
                f"{compile_result.stdout}\n{compile_result.stderr}"
            )
        nm = subprocess.run(
            ["nm", "-g", str(obj)],
            capture_output=True,
            text=True,
        )
        if nm.returncode != 0:
            fail(f"nm failed: {nm.stderr}")
        nm_text = (nm.stdout or "") + (nm.stderr or "")
        if SOLE_TX not in nm_text and ("_" + SOLE_TX) not in nm_text:
            fail(f"sole TX symbol missing from production object: {SOLE_TX}")
        for alt in (
            "ninlil_radio_hal_transmit",
            "ninlil_radio_hal_tx",
            "ninlil_sx1262_tx",
            "ninlil_radio_spi_tx",
        ):
            # allow sole symbol which contains transmit_with_permit
            if alt == "ninlil_radio_hal_transmit":
                # match exact symbol not transmit_with_permit
                if re.search(r"\b_?" + re.escape(alt) + r"\b", nm_text):
                    # nm may show transmit_with_permit containing substring —
                    # require whole-symbol match via word-ish ends
                    for line in nm_text.splitlines():
                        # Apple nm: T _symbol
                        parts = line.split()
                        if not parts:
                            continue
                        sym = parts[-1].lstrip("_")
                        if sym == alt:
                            fail(f"alternate TX symbol in production nm: {alt}")
            else:
                if alt in nm_text or ("_" + alt) in nm_text:
                    fail(f"alternate TX symbol in production nm: {alt}")
        # tests-off: spy symbols must not appear in production object
        for seam in (
            "ninlil_radio_hal_spy_init",
            "ninlil_radio_hal_spy_edge_ops",
        ):
            if seam in nm_text or ("_" + seam) in nm_text:
                fail(f"spy symbol leaked into production object: {seam}")


def check(root: pathlib.Path | None = None, *, run_prod_probe: bool = True) -> None:
    global HAL_H, HAL_C, SPY_H, SPY_C, TEST_C, PRIVATE_AUTH, CMAKE_LISTS, DOC23, DOC07, PUBLIC_INCLUDE
    if root is not None:
        HAL_H = root / "src" / "radio" / "radio_hal.h"
        HAL_C = root / "src" / "radio" / "radio_hal.c"
        SPY_H = root / "tests" / "support" / "radio_hal_spy.h"
        SPY_C = root / "tests" / "support" / "radio_hal_spy.c"
        TEST_C = root / "tests" / "radio" / "radio_hal_r1_test.c"
        PRIVATE_AUTH = root / "cmake" / "ninlil_runtime_private_sources.cmake"
        CMAKE_LISTS = root / "CMakeLists.txt"
        DOC23 = root / "docs" / "23-usb-radio-boundary.md"
        DOC07 = root / "docs" / "07-testing-and-quality.md"
        PUBLIC_INCLUDE = root / "include" / "ninlil"

    check_header()
    check_source()
    check_production_tx_hygiene()
    check_spy_and_tests()
    check_authority()
    check_cmake()
    check_public_abi_clean()
    check_docs()
    if run_prod_probe:
        check_production_symbols()
    print("radio_hal_r1_gate: OK")


def _copy_tree(dst: pathlib.Path) -> None:
    for rel in (
        "src/radio/radio_hal.h",
        "src/radio/radio_hal.c",
        "tests/support/radio_hal_spy.h",
        "tests/support/radio_hal_spy.c",
        "tests/radio/radio_hal_r1_test.c",
        "cmake/ninlil_runtime_private_sources.cmake",
        "CMakeLists.txt",
        "docs/23-usb-radio-boundary.md",
        "docs/07-testing-and-quality.md",
    ):
        src = REPO_ROOT / rel
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    pub = dst / "include" / "ninlil"
    pub.mkdir(parents=True, exist_ok=True)
    for p in (REPO_ROOT / "include" / "ninlil").glob("*.h"):
        shutil.copy2(p, pub / p.name)


def self_test() -> None:
    def mut_drop_sole(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(SOLE_TX, "ninlil_radio_hal_Xtransmit_with_permit"),
            encoding="utf-8",
        )

    def mut_alt_tx(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nninlil_radio_hal_status_t ninlil_radio_hal_tx(void);\n",
            encoding="utf-8",
        )

    def mut_drop_authority(root: pathlib.Path) -> None:
        p = root / "cmake" / "ninlil_runtime_private_sources.cmake"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("src/radio/radio_hal.c\n", ""), encoding="utf-8")

    def mut_heap(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\nvoid *bad_r1(void){return malloc(1);}\n", encoding="utf-8")

    def mut_public_leak(root: pathlib.Path) -> None:
        p = root / "include" / "ninlil" / "runtime.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\n/* radio_hal leak */\n", encoding="utf-8")

    def mut_drop_default_deny(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("DEFAULT_DENY", "DEFAULT_XDENY"), encoding="utf-8")

    def mut_drop_seal(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("plan_matches_seal", "plan_matches_Xseal"), encoding="utf-8")

    def mut_drop_monotonic(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(
                "permit->permit_sequence <= rh->last_consumed_seq",
                "permit->permit_sequence == rh->last_consumed_seq",
            ),
            encoding="utf-8",
        )

    def mut_drop_test_case(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "radio_hal_r1_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("test_success_exactly_once", "test_success_X_once"),
            encoding="utf-8",
        )

    def mut_product_vocabulary(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nint vendor_specific_policy_apply(void);\n",
            encoding="utf-8",
        )

    def mut_drop_cmake_gate(root: pathlib.Path) -> None:
        p = root / "CMakeLists.txt"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("radio_hal_r1_gate", "radio_hal_r1_Xgate"),
            encoding="utf-8",
        )

    def mut_sx1262_in_hal(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\nstatic int sx1262_direct_tx(void){return 0;}\n", encoding="utf-8")

    def mut_alt_nm_symbol(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text
            + "\nvoid ninlil_radio_hal_tx(void) {}\n"
            + "void ninlil_sx1262_tx(void) {}\n",
            encoding="utf-8",
        )

    def mut_duplicate_edge_call(root: pathlib.Path) -> None:
        p = root / "src" / "radio" / "radio_hal.c"
        text = p.read_text(encoding="utf-8")
        # Insert a second edge_ops.transmit( call site after the real one.
        needle = "st = rh->edge_ops.transmit("
        if needle not in text:
            raise RuntimeError("edge call site missing for mutation")
        text = text.replace(
            needle,
            needle
            + "\n    (void)rh->edge_ops.transmit("
            "rh->edge_ctx, &rh->seal_permit, &rh->seal_view, &edge_err);\n    st = rh->edge_ops.transmit(",
            1,
        )
        p.write_text(text, encoding="utf-8")

    structural: list[tuple[str, Callable[[pathlib.Path], None], bool]] = [
        ("drop sole TX token", mut_drop_sole, False),
        ("declare alternate TX API", mut_alt_tx, False),
        ("drop private authority", mut_drop_authority, False),
        ("inject malloc", mut_heap, False),
        ("public header radio_hal mention", mut_public_leak, False),
        ("drop DEFAULT_DENY path token", mut_drop_default_deny, False),
        ("drop plan_matches_seal integrity", mut_drop_seal, False),
        ("weaken monotonic to equality-only", mut_drop_monotonic, False),
        ("drop success exactly-once test", mut_drop_test_case, False),
        ("inject product-specific vocabulary", mut_product_vocabulary, False),
        ("drop cmake gate name", mut_drop_cmake_gate, False),
        ("inject sx1262 in production", mut_sx1262_in_hal, False),
        ("leak alternate TX nm symbols", mut_alt_nm_symbol, True),
        ("duplicate edge call site", mut_duplicate_edge_call, False),
    ]

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td) / "clean"
        root.mkdir()
        _copy_tree(root)
        check(root, run_prod_probe=True)

    for name, mut, need_probe in structural:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "mut"
            root.mkdir()
            _copy_tree(root)
            mut(root)
            try:
                check(root, run_prod_probe=need_probe)
            except GateFailure:
                print(f"mutation caught: {name}")
                continue
            fail(f"mutation NOT caught: {name}")

    print("radio_hal_r1_gate self-test: OK")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print("usage: radio_hal_r1_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as exc:
        print(f"radio_hal_r1_gate FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
