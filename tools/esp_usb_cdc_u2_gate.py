#!/usr/bin/env python3
"""U2 ESP CDC packaging / dependency / source gates.

Path-injectable checker so self-test mutates temp trees and invokes the *real*
check() logic (mutation coverage, not soft substring prints).

Does not claim U2 HIL complete.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ESP_TINYUSB_PIN = "2.1.1"
POSIX_USB_SOURCE = "ports/posix/usb_serial/ninlil_posix_usb_serial.c"


@dataclass
class Paths:
    root: pathlib.Path

    @property
    def component_yml(self) -> pathlib.Path:
        return (
            self.root
            / "ports"
            / "esp-idf"
            / "components"
            / "ninlil"
            / "idf_component.yml"
        )

    @property
    def port_authority(self) -> pathlib.Path:
        return self.root / "cmake" / "ninlil_esp_idf_port_sources.cmake"

    @property
    def backend(self) -> pathlib.Path:
        return self.root / "ports" / "esp-idf" / "src" / "esp_idf_usb_cdc.c"

    @property
    def port_header(self) -> pathlib.Path:
        return (
            self.root
            / "ports"
            / "esp-idf"
            / "include"
            / "ninlil_esp_idf"
            / "usb_cdc.h"
        )

    @property
    def c1_header(self) -> pathlib.Path:
        return self.root / "src" / "transport" / "byte_stream.h"

    @property
    def smoke_main(self) -> pathlib.Path:
        return self.root / "ports" / "esp-idf" / "smoke_app" / "main" / "main.c"

    @property
    def smoke_sdk(self) -> pathlib.Path:
        return self.root / "ports" / "esp-idf" / "smoke_app" / "sdkconfig.defaults"

    @property
    def smoke_lock(self) -> pathlib.Path:
        return self.root / "ports" / "esp-idf" / "smoke_app" / "dependencies.lock"

    @property
    def hil_lock(self) -> pathlib.Path:
        return self.root / "ports" / "esp-idf" / "hil_app" / "dependencies.lock"

    @property
    def workflow(self) -> pathlib.Path:
        return self.root / ".github" / "workflows" / "esp-idf.yml"

    @property
    def doc23(self) -> pathlib.Path:
        return self.root / "docs" / "23-usb-radio-boundary.md"


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def strip_c_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0:
                break
            out.append("\n")
            i = j + 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                break
            out.append("\n" * text[i : j + 2].count("\n"))
            i = j + 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


# Driver / blocking / I/O APIs forbidden while holding s_mux (portCRITICAL).
# Real structural scan — marker-only order checks must not false-green these.
# Direct driver/FIFO APIs + known production wrappers that may call them.
# Calling wrappers under s_mux is the same class of bug as direct TinyUSB calls.
_CRITICAL_BANNED_CALL = re.compile(
    r"\b(?:"
    r"tinyusb_[A-Za-z0-9_]+|"
    r"tud_[A-Za-z0-9_]+|"
    r"esp_tusb_[A-Za-z0-9_]+|"
    r"esp_tx_fifo_soft_clear|"
    r"esp_rx_fifo_soft_flush|"
    r"esp_tx_queue|"
    r"esp_physical_snapshot|"
    r"esp_drv_install|"
    r"esp_cdc_init|"
    r"esp_wait_callbacks_drained|"
    r"wait_callbacks_drained|"
    r"drain_tx_nonblocking|"
    r"ninlil_usb_cdc_orch_install|"
    r"ninlil_usb_cdc_orch_teardown|"
    r"soft_tx_clear_holding_io|"
    r"soft_rx_flush_holding_io|"
    r"unbound_rx_fifo_drain_drop(?:_holding_io)?|"
    r"io_lock|"
    r"io_unlock|"
    r"xSemaphoreTake|"
    r"xSemaphoreGive|"
    r"vTaskDelay|"
    r"tinyusb_cdcacm_[A-Za-z0-9_]+|"
    r"tinyusb_driver_[A-Za-z0-9_]+"
    r")\s*\("
)

_ENTER_CRITICAL = re.compile(r"\bportENTER_CRITICAL\s*\(")
_EXIT_CRITICAL = re.compile(r"\bportEXIT_CRITICAL\s*\(")
_PERSIST_CORE_CALL = re.compile(r"\bpersist_(?:open|teardown)_error\s*\(")
_BRANCH_BRACE_KW = frozenset({"if", "else", "for", "while", "do", "switch"})


def _skip_string(code: str, i: int) -> int:
    """Skip a "..." or '...' string starting at i. Returns index past close."""
    quote = code[i]
    i += 1
    n = len(code)
    while i < n:
        if code[i] == "\\":
            i += 2
            continue
        if code[i] == quote:
            return i + 1
        i += 1
    return n


def _skip_paren_group(code: str, open_i: int) -> int:
    """open_i points at '('; return index past matching ')'."""
    depth = 0
    i = open_i
    n = len(code)
    while i < n:
        ch = code[i]
        if ch in "\"'":
            i = _skip_string(code, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _ident_before(code: str, end_i: int) -> str:
    """Identifier immediately before end_i (end_i is exclusive)."""
    j = end_i - 1
    while j >= 0 and code[j] in " \t\n\r":
        j -= 1
    if j < 0:
        return ""
    end = j + 1
    if not (code[j].isalnum() or code[j] == "_"):
        return ""
    while j >= 0 and (code[j].isalnum() or code[j] == "_"):
        j -= 1
    return code[j + 1 : end]


def _is_branch_brace(code: str, brace_i: int) -> bool:
    """True if '{' is an if/else/for/while/do/switch body (not bare/function)."""
    j = brace_i - 1
    while j >= 0 and code[j] in " \t\n\r":
        j -= 1
    if j < 0:
        return False
    if code[j] == ")":
        # Walk back over balanced (...) of the condition, then keyword.
        depth = 0
        k = j
        while k >= 0:
            ch = code[k]
            if ch in "\"'":
                # strings rare in reverse; stop conservatively
                break
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k < 0:
            return False
        return _ident_before(code, k) in _BRANCH_BRACE_KW
    # else / do
    return _ident_before(code, j + 1) in _BRANCH_BRACE_KW


def _is_persist_function_definition(code: str, call_i: int) -> bool:
    """True if call_i is 'static void persist_*(' definition, not a call site."""
    window = code[max(0, call_i - 96) : call_i]
    return re.search(r"(?:^|[\s;{}])(?:static\s+)?void\s*$", window) is not None


def check_no_driver_api_in_critical(code: str, where: str = "backend") -> None:
    """Reject TinyUSB / soft-FIFO / blocking waits while s_mux is held.

    Branch-aware conservative scanner (not a lexical ENTER/EXIT stack):

    Production uses multi-exit patterns:
      portENTER_CRITICAL(...);
      if (...) { portEXIT_CRITICAL(...); return; }
      ...
      portEXIT_CRITICAL(...);

    A naive stack treats the second EXIT as orphan. Instead:

    - Track held depth on the current linear scan path.
    - On ``{`` that is an if/else/for/while/do/switch body, save held and
      **restore** it at the matching ``}`` (branch does not poison fallthrough).
    - Bare / function ``{`` does not restore (nested scope keeps held).
    - When outermost function body closes, reset held.
    - While held > 0, any banned driver/I-O call is a hard fail (markers alone
      cannot false-green a real call under CRITICAL).

    Enforces s_mux depth-0 driver contract after I/O mutex introduction.
    """
    _walk_smux_contracts(code, where, check_driver_banned=True, check_persist=False)


def check_persist_core_mutation_under_smux(
    code: str, where: str = "backend"
) -> None:
    """Every persist_open/teardown_error *call* must run under s_mux.

    Core last_error / first_teardown_error mutation is a race if done outside
    the spinlock. Marker-only checks are insufficient — real call sites are
    scanned with the same branch-aware held model as driver APIs.
    Definitions of persist_* helpers are skipped.
    """
    _walk_smux_contracts(code, where, check_driver_banned=False, check_persist=True)


def _walk_smux_contracts(
    code: str,
    where: str,
    *,
    check_driver_banned: bool,
    check_persist: bool,
) -> None:
    n = len(code)
    i = 0
    held = 0
    # Pair helpers: esp_state_lock() only ENTER, esp_state_unlock() only EXIT.
    cross_fn_held = 0
    fn_enters = 0
    fn_exits = 0
    brace_frames: list[tuple[int, bool]] = []
    persist_calls_under = 0
    persist_calls_total = 0

    while i < n:
        ch = code[i]
        if ch in "\"'":
            i = _skip_string(code, i)
            continue

        m_enter = _ENTER_CRITICAL.match(code, i)
        if m_enter is not None:
            paren_open = m_enter.end() - 1
            if paren_open < 0 or code[paren_open] != "(":
                paren_open = code.find("(", m_enter.start())
            i = _skip_paren_group(code, paren_open)
            held += 1
            fn_enters += 1
            continue

        m_exit = _EXIT_CRITICAL.match(code, i)
        if m_exit is not None:
            paren_open = m_exit.end() - 1
            if paren_open < 0 or code[paren_open] != "(":
                paren_open = code.find("(", m_exit.start())
            if held > 0:
                held -= 1
            elif cross_fn_held > 0:
                cross_fn_held -= 1
            else:
                line = code.count("\n", 0, i) + 1
                fail(
                    f"{where}: portEXIT_CRITICAL with no held ENTER on this "
                    f"path (~line {line}); scanner/branch model bug or real "
                    f"unmatched EXIT"
                )
            fn_exits += 1
            i = _skip_paren_group(code, paren_open)
            continue

        if check_persist:
            m_persist = _PERSIST_CORE_CALL.match(code, i)
            if m_persist is not None:
                if not _is_persist_function_definition(code, i):
                    persist_calls_total += 1
                    if held <= 0:
                        line = code.count("\n", 0, i) + 1
                        fail(
                            f"{where}: {m_persist.group(0)!r} call outside s_mux "
                            f"(held={held}; ~line {line}). Core diagnosis "
                            f"mutation must be under portENTER_CRITICAL"
                        )
                    persist_calls_under += 1
                paren_open = m_persist.end() - 1
                if paren_open < 0 or code[paren_open] != "(":
                    paren_open = code.find("(", m_persist.start())
                i = _skip_paren_group(code, paren_open)
                continue

        if check_driver_banned and held > 0:
            bm = _CRITICAL_BANNED_CALL.match(code, i)
            if bm is not None:
                line = code.count("\n", 0, i) + 1
                fail(
                    f"{where}: driver/I-O/blocking call {bm.group(0)!r} while "
                    f"s_mux held (portENTER_CRITICAL depth {held}; ~line {line}). "
                    f"s_mux depth must be 0 for TinyUSB/software-FIFO APIs"
                )

        if ch == "{":
            is_branch = _is_branch_brace(code, i)
            brace_frames.append((held, is_branch))
            i += 1
            continue

        if ch == "}":
            if brace_frames:
                saved_held, is_branch = brace_frames.pop()
                if is_branch:
                    if held > saved_held:
                        line = code.count("\n", 0, i) + 1
                        fail(
                            f"{where}: branch body ends with s_mux held deeper "
                            f"than entry (held={held} > saved={saved_held}; "
                            f"~line {line}) — conditional lock leak"
                        )
                    held = saved_held
                if not brace_frames:
                    if held > 0 and fn_exits == 0 and fn_enters > 0:
                        cross_fn_held += held
                    elif held > 0:
                        line = code.count("\n", 0, i) + 1
                        fail(
                            f"{where}: function ends with s_mux still held "
                            f"(depth {held}; ~line {line})"
                        )
                    held = 0
                    fn_enters = 0
                    fn_exits = 0
            i += 1
            continue

        i += 1

    if held > 0 or cross_fn_held > 0:
        fail(
            f"{where}: file ends with unmatched s_mux hold "
            f"(held={held} cross_fn_held={cross_fn_held})"
        )
    if check_persist:
        if persist_calls_total < 1:
            fail(
                f"{where}: expected persist_open_error/persist_teardown_error "
                f"call sites (found {persist_calls_total})"
            )
        if persist_calls_under != persist_calls_total:
            fail(
                f"{where}: not all persist_* calls under s_mux "
                f"({persist_calls_under}/{persist_calls_total})"
            )


def _strip_yaml_comments(text: str) -> str:
    """Remove full-line and trailing # comments outside quotes (minimal)."""
    out: list[str] = []
    for line in text.splitlines():
        in_sq = False
        in_dq = False
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == "#" and not in_sq and not in_dq:
                cut = i
                break
            i += 1
        out.append(line[:cut].rstrip())
    return "\n".join(out) + "\n"


def manifest_esp_tinyusb_version(text: str) -> str | None:
    """
    Structural parse of idf_component.yml dependencies.espressif/esp_tinyusb.version.
    Indentation-based (stdlib only; no PyYAML required).
    """
    body = _strip_yaml_comments(text)
    lines = body.splitlines()
    # Find top-level dependencies:
    i = 0
    n = len(lines)
    while i < n:
        if re.match(r"^dependencies:\s*$", lines[i]):
            i += 1
            break
        i += 1
    else:
        return None
    # Under dependencies, find espressif/esp_tinyusb or esp_tinyusb key
    while i < n:
        line = lines[i]
        if line and not line.startswith(" ") and not line.startswith("\t"):
            # left top-level
            break
        m = re.match(
            r"^  (?:espressif/)?esp_tinyusb:\s*$",
            line,
        )
        if m:
            i += 1
            while i < n:
                sub = lines[i]
                if sub and not sub.startswith("    ") and not sub.startswith("\t\t"):
                    # sibling under dependencies or less indent
                    if re.match(r"^  \S", sub) or (
                        sub and not sub.startswith(" ")
                    ):
                        break
                vm = re.match(
                    r'^    version:\s*[\"\']?([^\"\'#\s]+)[\"\']?\s*$',
                    sub,
                )
                if vm:
                    return vm.group(1)
                i += 1
            return None
        i += 1
    return None


def check_manifest_pin(paths: Paths) -> None:
    text = read_text(paths.component_yml)
    ver = manifest_esp_tinyusb_version(text)
    if ver is None:
        fail(
            "idf_component.yml missing structural dependencies."
            "espressif/esp_tinyusb.version"
        )
    # Accept "==2.1.1" form only (exact pin).
    if ver != f"=={ESP_TINYUSB_PIN}" and ver != ESP_TINYUSB_PIN:
        fail(
            f"idf_component.yml esp_tinyusb version must be =={ESP_TINYUSB_PIN}, "
            f"got {ver!r}"
        )
    # Normalize: require == form in production file for clarity
    if ver == ESP_TINYUSB_PIN:
        # bare 2.1.1 without == is too loose for Component Manager exact pin
        fail(
            f"idf_component.yml esp_tinyusb version must use exact == form "
            f"(=={ESP_TINYUSB_PIN})"
        )
    if ver.startswith("^") or ver.startswith("~"):
        fail("esp_tinyusb must not use floating ^/~ version")


def lock_esp_tinyusb_version(text: str) -> str | None:
    """Extract version under dependencies.espressif/esp_tinyusb (structural)."""
    # YAML-ish: find block starting with "  espressif/esp_tinyusb:" then
    # the first non-nested "version:" at 4-space indent of that component.
    m = re.search(
        r"(?m)^  espressif/esp_tinyusb:\s*\n((?:    .*\n)+)",
        text,
    )
    if not m:
        return None
    block = m.group(1)
    # Prefer component-level version (4 spaces), not nested dependency versions
    # which are more indented.
    for line in block.splitlines():
        vm = re.match(r"^    version:\s*[\"']?([^\"'\s]+)[\"']?\s*$", line)
        if vm:
            return vm.group(1)
    return None


def check_lock(path: pathlib.Path, label: str) -> None:
    if not path.is_file():
        fail(
            f"missing committed {label} dependencies.lock ({path}); "
            "generate with official espressif/idf:v5.5.3 Docker"
        )
    text = path.read_text(encoding="utf-8")
    ver = lock_esp_tinyusb_version(text)
    if ver is None:
        fail(f"{label} lock missing structural espressif/esp_tinyusb version")
    if ver != ESP_TINYUSB_PIN:
        fail(
            f"{label} lock esp_tinyusb version drift: got {ver!r}, "
            f"want {ESP_TINYUSB_PIN!r}"
        )


def check_authority(paths: Paths) -> None:
    text = read_text(paths.port_authority)
    for rel in (
        "ports/esp-idf/src/usb_cdc_ring_logic.c",
        "ports/esp-idf/src/usb_cdc_state_logic.c",
        "ports/esp-idf/src/usb_cdc_orch_logic.c",
        "ports/esp-idf/src/esp_idf_usb_cdc.c",
    ):
        if rel not in text:
            fail(f"port authority missing {rel}")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if re.search(r"file\s*\(\s*GLOB", code, flags=re.IGNORECASE):
            fail("port authority must not use file(GLOB)")
    if POSIX_USB_SOURCE in text:
        fail("ESP port authority must not include U1 POSIX usb_serial source")


def check_backend_hygiene(paths: Paths) -> None:
    text = read_text(paths.backend)
    code = strip_c_comments(text)
    if re.search(r"\besp_tusb_init_console\s*\(", code):
        fail("A2 backend must not call esp_tusb_init_console")
    if re.search(r"\bESP_LOG[A-Z]*\s*\(", code):
        fail("A2 backend must not ESP_LOG")
    if re.search(r"\bprintf\s*\(", code):
        fail("A2 backend must not printf")
    if "NINLIL_POSIX_USB_SERIAL_FORCE" in code:
        fail("target backend must not include U1 FORCE test macros")
    if re.search(r"\blink_anchor\b", code):
        fail("target backend must not define link_anchor testing smell")
    if "tusb_cdc_acm.h" in text and "tinyusb_cdc_acm.h" not in text:
        fail("backend must use modern tinyusb_cdc_acm.h")
    if "not hard-ISR" not in text and "not ISR" not in text:
        fail("backend must document TinyUSB callback context (task, not hard-ISR)")
    if "TEARDOWN_PENDING" not in text and "TEARDOWN_PENDING" not in read_text(
        paths.port_header
    ):
        fail("teardown-pending lifecycle must be documented/implemented")
    # Production close must share host-testable orch teardown authority.
    if not re.search(r"\bninlil_usb_cdc_orch_teardown\s*\(", code):
        fail(
            "production backend must call ninlil_usb_cdc_orch_teardown "
            "(shared injectable teardown authority)"
        )
    if not re.search(r"\bninlil_usb_cdc_orch_install\s*\(", code):
        fail("production backend must call ninlil_usb_cdc_orch_install")
    if not re.search(r"\bninlil_usb_cdc_once_claim_create\s*\(", code):
        fail(
            "production backend must use ninlil_usb_cdc_once_claim_create "
            "for lifecycle mutex once-init"
        )
    # try_begin_teardown result must not be discarded (P0: free foreign reservation).
    if re.search(
        r"\(void\)\s*ninlil_usb_cdc_global_try_begin_teardown\s*\(",
        code,
    ):
        fail(
            "production must not ignore try_begin_teardown result "
            "(void cast forbidden)"
        )
    if not re.search(
        r"if\s*\(\s*!\s*ninlil_usb_cdc_global_try_begin_teardown\s*\(",
        code,
    ):
        fail(
            "production close must branch on !try_begin_teardown "
            "(fail-closed when TEARING claim fails)"
        )
    if not re.search(r"\bninlil_usb_cdc_closed_idle_close_policy\s*\(", code):
        fail(
            "production close must use closed_idle_close_policy "
            "(idempotent without freeing foreign reservation)"
        )
    # A) poll must owner-check before TX drain (no wrong-owner TX progress).
    if "U2-POLL-OWNER-BEFORE-TX" not in text:
        fail("backend must mark U2-POLL-OWNER-BEFORE-TX ordering")
    poll_m = re.search(
        r"ninlil_esp_idf_usb_cdc_poll\s*\([\s\S]*?\n\}",
        text,
    )
    if poll_m is None:
        fail("could not locate ninlil_esp_idf_usb_cdc_poll for ordering check")
    poll_body = poll_m.group(0)
    own_i = poll_body.find("ninlil_usb_cdc_core_check_owner")
    drain_i = poll_body.find("drain_tx_nonblocking")
    if own_i < 0 or drain_i < 0 or own_i > drain_i:
        fail(
            "poll must call check_owner before drain_tx_nonblocking "
            "(wrong-owner must not TX)"
        )
    # B) soft clear before leave (inflight held across soft clear).
    if "U2-CB-SOFT-CLEAR-BEFORE-LEAVE" not in text:
        fail("backend must mark U2-CB-SOFT-CLEAR-BEFORE-LEAVE ordering")
    # C) install rollback uses wait_callbacks_drained injection path.
    if "wait_callbacks_drained" not in text and "esp_wait_callbacks_drained" not in text:
        fail("backend must wire wait_callbacks_drained into driver ops")

    if "esp_state_lock" not in text:
        fail("backend must provide state_lock for orch core/global updates")
    # Persistent service: V1 close must not call cdc deinit/uninstall success path.
    if re.search(r"tinyusb_cdcacm_deinit\s*\(", strip_c_comments(text)):
        # allow only in unused/stub functions named *_unused
        code_no_unused = re.sub(
            r"static int esp_cdc_deinit_unused[\s\S]*?^}",
            "",
            text,
            flags=re.M,
        )
        code_no_unused = re.sub(
            r"static int esp_drv_uninstall_unused[\s\S]*?^}",
            "",
            code_no_unused,
            flags=re.M,
        )
        if re.search(r"tinyusb_cdcacm_deinit\s*\(", strip_c_comments(code_no_unused)):
            fail("V1 production path must not call tinyusb_cdcacm_deinit (persistent service)")
    if re.search(r"tinyusb_driver_uninstall\s*\(", strip_c_comments(text)):
        code_no_unused = re.sub(
            r"static int esp_drv_uninstall_unused[\s\S]*?^}",
            "",
            text,
            flags=re.M,
        )
        if re.search(r"tinyusb_driver_uninstall\s*\(", strip_c_comments(code_no_unused)):
            fail("V1 production path must not call tinyusb_driver_uninstall (persistent service)")
    if not re.search(r"\bninlil_usb_cdc_init_ranges_may_claim\s*\(", code):
        fail("production init must use init_ranges_may_claim (range overlap)")
    if "device_event_handler" in text and re.search(
        r"TINYUSB_DEFAULT_CONFIG\s*\(\s*device_event_handler\s*,\s*self\s*\)",
        text,
    ):
        fail("device event arg must not be caller storage (use NULL + s_live)")
    if not re.search(r"TINYUSB_DEFAULT_CONFIG\s*\(\s*device_event_handler\s*,\s*NULL\s*\)", text):
        fail("device event callback arg must be NULL (storage-free)")

    def _fn_span(src: str, name: str) -> str:
        # Prefer definition (opening brace), skip prototypes ending in ';'.
        for m in re.finditer(rf"static void {name}\s*\(", src):
            j = src.find("{", m.end())
            semi = src.find(";", m.end())
            if j < 0:
                continue
            if semi >= 0 and semi < j:
                continue  # prototype
            i = m.start()
            depth = 0
            k = j
            while k < len(src):
                if src[k] == "{":
                    depth += 1
                elif src[k] == "}":
                    depth -= 1
                    if depth == 0:
                        return src[i : k + 1]
                k += 1
            fail(f"unbalanced braces in {name}")
        fail(f"could not locate definition of {name}")
        return ""

    # Unbound physical seq always bumps (even when s_live is NULL).
    if "U2-UNBOUND-SEQ-BUMP" not in text:
        fail("backend must mark U2-UNBOUND-SEQ-BUMP for unbound physical events")
    dev_body = _fn_span(text, "device_event_handler")
    bump_i = dev_body.find("ninlil_usb_cdc_global_bump_physical_seq")
    null_i = dev_body.find("self == NULL")
    if bump_i < 0 or null_i < 0 or bump_i > null_i:
        fail(
            "device_event_handler must bump physical_event_seq under lock "
            "before s_live==NULL early path"
        )
    line_body = _fn_span(text, "cdc_line_state_changed")
    lbump = line_body.find("ninlil_usb_cdc_global_bump_physical_seq")
    lnull = line_body.find("self == NULL")
    if lbump < 0 or lnull < 0 or lbump > lnull:
        fail(
            "cdc_line_state_changed must bump physical_event_seq before "
            "s_live==NULL early path"
        )

    # Reconcile: capture seq before hardware snapshot (not after).
    if "U2-RECONCILE-SEQ-BEFORE-SNAPSHOT" not in text:
        fail("backend must mark U2-RECONCILE-SEQ-BEFORE-SNAPSHOT ordering")
    rec_body = _fn_span(text, "reconcile_physical_after_bind")
    rseq = rec_body.find("physical_event_seq")
    rsnap = rec_body.find("esp_physical_snapshot")
    if rseq < 0 or rsnap < 0 or rseq > rsnap:
        fail(
            "reconcile must capture physical_event_seq before "
            "esp_physical_snapshot (stale snapshot must not win)"
        )

    # Unbound RX drain/drop for persistent CDC service.
    if "U2-UNBOUND-RX-DRAIN" not in text:
        fail("backend must mark U2-UNBOUND-RX-DRAIN for unbound RX FIFO drop")
    if not re.search(r"\bunbound_rx_fifo_drain_drop_holding_io\s*\(", text):
        fail(
            "backend must define/call unbound_rx_fifo_drain_drop_holding_io "
            "(I/O mutex held; s_mux depth 0)"
        )
    rx_body = _fn_span(text, "cdc_rx_callback")
    if "U2-RX-IO-FIRST" not in rx_body and "U2-RX-IO-FIRST" not in text:
        fail("backend must mark U2-RX-IO-FIRST (I/O mutex before s_mux in RX)")
    io_i = rx_body.find("io_lock")
    mux_i = rx_body.find("portENTER_CRITICAL")
    if io_i < 0 or mux_i < 0 or io_i > mux_i:
        fail(
            "cdc_rx_callback must call io_lock before first portENTER_CRITICAL "
            "(serialize pre-dispatch with open flush / close soft clear)"
        )
    m_null = re.search(
        r"self\s*==\s*NULL[\s\S]{0,320}?return\s*;",
        rx_body,
    )
    if m_null is None or not re.search(
        r"\bunbound_rx_fifo_drain_drop_holding_io\s*\(", m_null.group(0)
    ):
        fail(
            "cdc_rx_callback s_live==NULL path must call "
            "unbound_rx_fifo_drain_drop_holding_io before return"
        )

    # I/O mutex + flush-before-publish + close unpublish-first.
    if "U2-IO-MUTEX" not in text:
        fail("backend must mark U2-IO-MUTEX for firmware-lifetime USB I/O lock")
    if "U2-FLUSH-BEFORE-PUBLISH" not in text:
        fail("backend must mark U2-FLUSH-BEFORE-PUBLISH open ordering")
    if "U2-CLOSE-UNPUBLISH-FIRST" not in text:
        fail("backend must mark U2-CLOSE-UNPUBLISH-FIRST close ordering")
    if not re.search(r"\bensure_io_mutex\s*\(", text):
        fail("backend must define ensure_io_mutex (once-safe I/O mutex)")
    open_m = re.search(
        r"ninlil_esp_idf_usb_cdc_open\s*\([\s\S]*?\n\}",
        text,
    )
    if open_m is None:
        fail("could not locate ninlil_esp_idf_usb_cdc_open for publish order")
    open_body = open_m.group(0)
    orch_i = open_body.find("ninlil_usb_cdc_orch_install")
    flush_i = open_body.find("U2-FLUSH-BEFORE-PUBLISH")
    # s_live = self publish must be after orch_install and flush marker.
    live_assigns = [
        m.start() for m in re.finditer(r"\bs_live\s*=\s*self\s*;", open_body)
    ]
    if orch_i < 0 or flush_i < 0 or not live_assigns:
        fail(
            "open must call orch_install, mark U2-FLUSH-BEFORE-PUBLISH, "
            "and assign s_live=self"
        )
    early_publish = [i for i in live_assigns if i < orch_i]
    if early_publish:
        fail(
            "open must not assign s_live=self before orch_install "
            "(service ensure window must stay unbound for callbacks)"
        )
    # Success-path publish after flush marker (and after orch_install).
    success_publish = [i for i in live_assigns if i > flush_i and i > orch_i]
    if not success_publish:
        fail(
            "open must publish s_live=self only after orch_install + "
            "flush-before-publish (no early s_live during service ensure)"
        )
    soft_rx_i = open_body.find("soft_rx_flush_holding_io")
    if soft_rx_i < 0 or soft_rx_i > success_publish[0]:
        fail(
            "open flush-before-publish must soft_rx_flush_holding_io "
            "before s_live publish"
        )
    close_m = re.search(
        r"ninlil_esp_idf_usb_cdc_close\s*\([\s\S]*?\n\}",
        text,
    )
    if close_m is None:
        fail("could not locate ninlil_esp_idf_usb_cdc_close")
    close_body = close_m.group(0)
    cup = close_body.find("U2-CLOSE-UNPUBLISH-FIRST")
    unpub = close_body.find("s_live = NULL")
    drain_i = close_body.find("wait_callbacks_drained")
    if cup < 0 or unpub < 0 or drain_i < 0 or not (cup < unpub < drain_i):
        fail(
            "close must unpublish s_live under marker before "
            "wait_callbacks_drained / soft clear"
        )

    # P1A: real structural scan — no driver FIFO / wrappers / blocking under s_mux.
    # Marker-only checks must not false-green real calls inside CRITICAL.
    check_no_driver_api_in_critical(code, where="esp_idf_usb_cdc.c")
    # Core diagnosis mutation race class: every persist_* call under s_mux.
    if "U2-PERSIST-UNDER-SMUX" not in text:
        fail("backend must mark U2-PERSIST-UNDER-SMUX for core diagnosis")
    check_persist_core_mutation_under_smux(code, where="esp_idf_usb_cdc.c")

    # s_live publish only on success bind (READY+BOUND+flush path).
    if "U2-SLIVE-SUCCESS-ONLY" not in text:
        fail("backend must mark U2-SLIVE-SUCCESS-ONLY s_live publish invariant")
    open_assigns = list(
        re.finditer(r"\bs_live\s*=\s*self\s*;", open_body)
    )
    for m in open_assigns:
        # Only allowed after flush-before-publish marker in open body.
        if m.start() < open_body.find("U2-FLUSH-BEFORE-PUBLISH"):
            fail("open must not assign s_live=self before flush-before-publish")
        if m.start() < open_body.find("U2-SLIVE-SUCCESS-ONLY"):
            # allow marker after site; require nearby success comment/path
            pass
    if open_body.count("s_live = self") != 1:
        fail(
            "open must have exactly one s_live=self (success bind only; "
            f"found {open_body.count('s_live = self')})"
        )
    # close must not re-publish s_live=self
    if re.search(r"\bs_live\s*=\s*self\s*;", close_body):
        fail("close must not re-publish s_live=self (success-bind-only invariant)")
    if "U2-CLOSE-FENCE-FAILCLOSED" not in text:
        fail("backend must mark U2-CLOSE-FENCE-FAILCLOSED for non-OK fence")
    fence_i = close_body.find("ninlil_usb_cdc_core_begin_close_fence")
    fence_ok = close_body.find("st != NINLIL_BYTE_STREAM_OK", fence_i)
    teardown_claim = close_body.find(
        "ninlil_usb_cdc_global_try_begin_teardown", fence_i
    )
    if fence_i < 0 or fence_ok < 0 or teardown_claim < 0 or not (
        fence_i < fence_ok < teardown_claim
    ):
        fail(
            "close must fail-closed on any non-OK begin_close_fence before "
            "global PARKING claim"
        )
    if "U2-OPEN-PUBLISH-VALIDATE-POISON" not in text:
        fail(
            "backend must mark U2-OPEN-PUBLISH-VALIDATE-POISON "
            "(fence+PARKING+POISONED keep live_storage; no clear-only)"
        )
    poison_i = open_body.find("U2-OPEN-PUBLISH-VALIDATE-POISON")
    if poison_i >= 0:
        poison_span = open_body[poison_i : poison_i + 900]
        if "clear_live_storage" in poison_span:
            fail(
                "open publish-validate fail path must not clear_live_storage "
                "(retain overlap evidence via POISONED+live_storage)"
            )
        if "teardown_fail" not in poison_span:
            fail(
                "open publish-validate fail must call global teardown_fail "
                "(POISONED with retained reservation)"
            )

    # Poll deadline: call-entry tick + recheck before extra I/O + HZ budget.
    if "U2-POLL-CALL-ENTRY-TICK" not in text:
        fail("backend must mark U2-POLL-CALL-ENTRY-TICK (call-entry deadline)")
    if "U2-POLL-RECHECK-BEFORE-IO" not in text:
        fail("backend must mark U2-POLL-RECHECK-BEFORE-IO after delay")
    poll_body = re.search(
        r"ninlil_esp_idf_usb_cdc_poll\s*\([\s\S]*?\n\}",
        text,
    )
    if poll_body is None:
        fail("could not locate ninlil_esp_idf_usb_cdc_poll")
    pb = poll_body.group(0)
    entry_i = pb.find("U2-POLL-CALL-ENTRY-TICK")
    entry_tick_i = pb.find("entry_tick")
    first_drain = pb.find("drain_tx_nonblocking")
    if entry_i < 0 or entry_tick_i < 0 or first_drain < 0 or entry_tick_i > first_drain:
        fail(
            "poll must capture entry_tick (call-entry) before first "
            "drain_tx_nonblocking"
        )
    if "poll_required_ticks_hz" not in pb and "ninlil_usb_cdc_poll_required_ticks_hz" not in pb:
        fail("poll must use ninlil_usb_cdc_poll_required_ticks_hz (arbitrary HZ)")
    # Code-only (comments may mention portTICK_PERIOD_MS as forbidden).
    pb_code = strip_c_comments(pb)
    if re.search(r"\bportTICK_PERIOD_MS\b", pb_code):
        fail(
            "poll must not use portTICK_PERIOD_MS for budget "
            "(use configTICK_RATE_HZ via poll_required_ticks_hz)"
        )
    recheck_i = pb.find("U2-POLL-RECHECK-BEFORE-IO")
    # After first drain, remaining drain_tx must be preceded by recheck marker.
    second_drain = pb.find("drain_tx_nonblocking", first_drain + 1)
    if second_drain >= 0 and (recheck_i < 0 or recheck_i > second_drain):
        fail(
            "poll loop must recheck deadline (U2-POLL-RECHECK-BEFORE-IO) "
            "before any additional drain_tx_nonblocking"
        )

    # P1: init must not memset storage before lifecycle/reservation guard.
    if "U2-INIT-GUARD-BEFORE-MEMSET" not in text:
        fail("backend must mark U2-INIT-GUARD-BEFORE-MEMSET ordering")
    if not re.search(
        r"\bninlil_usb_cdc_init_ranges_may_claim\s*\(", code
    ) and not re.search(r"\bninlil_usb_cdc_init_storage_may_wipe\s*\(", code):
        fail("production init must call init_ranges_may_claim (or may_wipe)")
    init_m = re.search(
        r"ninlil_esp_idf_usb_cdc_init\s*\([\s\S]*?\n\}",
        text,
    )
    if init_m is None:
        fail("could not locate ninlil_esp_idf_usb_cdc_init for ordering check")
    init_body = init_m.group(0)
    guard_i = init_body.find("U2-INIT-GUARD-BEFORE-MEMSET")
    may_i = init_body.find("ninlil_usb_cdc_init_ranges_may_claim")
    if may_i < 0:
        may_i = init_body.find("ninlil_usb_cdc_init_storage_may_wipe")
    # First wipe of object storage (not local error structs).
    memset_i = init_body.find("memset(self")
    if memset_i < 0:
        memset_i = init_body.find("memset(storage")
    if guard_i < 0 or may_i < 0 or memset_i < 0:
        fail("init must contain guard marker, range claim, and storage memset")
    if not (guard_i < may_i < memset_i):
        fail(
            "init must order: guard marker → ranges_may_claim → memset "
            "(reinit must not wipe live reservation storage)"
        )
    ensure_i = init_body.find("ensure_lifecycle_mutex")
    if ensure_i < 0 or ensure_i > may_i:
        fail("init must ensure_lifecycle_mutex before range claim/memset")


def check_header_and_c1(paths: Paths) -> None:
    hdr = read_text(paths.port_header)
    if "TEARDOWN_PENDING" not in hdr:
        fail("port usb_cdc.h must document TEARDOWN_PENDING")
    if "link_anchor" in hdr:
        fail("port header must not expose link_anchor")
    c1 = read_text(paths.c1_header)
    if "endpoint_token" not in c1:
        fail("C1 open must use endpoint_token")
    if "LINK_LISTENING" not in c1:
        fail("C1 must define LINK_LISTENING")
    if "generation_rx_discard_bytes" not in c1:
        fail("C1 stats must include generation_rx_discard_bytes")
    if "tx_driver_stale_accepted" not in c1:
        fail("C1 stats must include tx_driver_stale_accepted")
    if "init / reinit contract" not in hdr and "reinit" not in hdr.lower():
        fail("port usb_cdc.h must document init/reinit contract")


def check_smoke(paths: Paths) -> None:
    main = read_text(paths.smoke_main)
    if "ninlil_esp_idf/usb_cdc.h" not in main:
        fail("smoke main must include usb_cdc.h")
    if "ninlil_esp_idf_usb_cdc_init_object" not in main:
        fail("smoke main must call real init_object (not link_anchor)")
    if "link_anchor" in main:
        fail("smoke main must not use link_anchor")
    if "esp_tusb_init_console" in main:
        fail("smoke must not redirect console to control CDC")
    sdk = read_text(paths.smoke_sdk)
    if "CONFIG_TINYUSB_CDC_ENABLED=y" not in sdk:
        fail("smoke sdkconfig.defaults must enable TINYUSB CDC")


def check_workflow(paths: Paths) -> None:
    text = read_text(paths.workflow)
    if "esp_usb_cdc_u2_gate" not in text and "esp_tinyusb" not in text:
        fail("esp-idf.yml must exercise U2 gates")
    # Prefer Python gate over raw comment-sensitive grep for console ban.
    if "esp_usb_cdc_u2_gate.py" not in text:
        fail("esp-idf.yml must invoke tools/esp_usb_cdc_u2_gate.py")


def check_docs(paths: Paths) -> None:
    text = read_text(paths.doc23)
    if "TEARDOWN_PENDING" not in text and "teardown" not in text.lower():
        fail("docs/23 must document teardown fail-closed")
    if re.search(r"\bU2 complete\b", text):
        for line in text.splitlines():
            if re.search(r"\bU2 complete\b", line):
                if (
                    "ではない" not in line
                    and "pending" not in line.lower()
                    and "名乗" not in line
                ):
                    fail(f"docs/23 bare U2 complete claim: {line!r}")


def check(paths: Paths | None = None) -> None:
    p = paths or Paths(REPO_ROOT)
    check_manifest_pin(p)
    check_lock(p.smoke_lock, "smoke_app")
    check_lock(p.hil_lock, "hil_app")
    check_authority(p)
    check_backend_hygiene(p)
    check_header_and_c1(p)
    check_smoke(p)
    check_workflow(p)
    check_docs(p)
    print(
        "esp_usb_cdc_u2_gate ok: "
        f"esp_tinyusb=={ESP_TINYUSB_PIN}, locks structural, A2 hygiene, "
        "TEARDOWN_PENDING, no link_anchor"
    )


def _copy_repo_subset(dst_root: pathlib.Path) -> Paths:
    """Copy only files the gate reads into a temp tree."""
    paths = Paths(REPO_ROOT)
    mapping = [
        paths.component_yml,
        paths.port_authority,
        paths.backend,
        paths.port_header,
        paths.c1_header,
        paths.smoke_main,
        paths.smoke_sdk,
        paths.smoke_lock,
        paths.hil_lock,
        paths.workflow,
        paths.doc23,
    ]
    for src in mapping:
        rel = src.relative_to(REPO_ROOT)
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return Paths(dst_root)


def _expect_fail(label: str, mutator: Callable[[Paths], None]) -> None:
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        p = _copy_repo_subset(root)
        mutator(p)
        try:
            check(p)
        except GateFailure as e:
            print(f"  self-test mutation {label!r} correctly failed: {e}")
            return
        fail(f"self-test mutation {label!r} did not fail the real checker")


def self_test() -> None:
    check()  # clean tree must pass first

    def mut_float_pin(p: Paths) -> None:
        t = p.component_yml.read_text(encoding="utf-8")
        # Change production dependency to ==2.1.2 but leave comment with ==2.1.1
        t2 = t.replace(
            f'version: "=={ESP_TINYUSB_PIN}"',
            'version: "==2.1.2"',
            1,
        )
        if f"=={ESP_TINYUSB_PIN}" not in t2:
            t2 = t2 + f"\n# decoy comment still mentions =={ESP_TINYUSB_PIN}\n"
        else:
            # ensure a comment decoy remains
            t2 = t2.replace(
                "# U2: exact pin",
                f"# U2: exact pin decoy =={ESP_TINYUSB_PIN} must not false-green",
                1,
            )
        p.component_yml.write_text(t2, encoding="utf-8")

    def mut_console(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        p.backend.write_text(
            t + "\nvoid _bad(void){ (void)esp_tusb_init_console(0); }\n",
            encoding="utf-8",
        )

    def mut_posix(p: Paths) -> None:
        t = p.port_authority.read_text(encoding="utf-8")
        p.port_authority.write_text(
            t + f"\n    {POSIX_USB_SOURCE}\n", encoding="utf-8"
        )

    def mut_drop_listening(p: Paths) -> None:
        t = p.c1_header.read_text(encoding="utf-8")
        p.c1_header.write_text(
            t.replace("LINK_LISTENING", "LINK_XLISTENING"), encoding="utf-8"
        )

    def mut_lock_drift(p: Paths) -> None:
        t = p.smoke_lock.read_text(encoding="utf-8")
        # Structural version field under esp_tinyusb only.
        t2 = re.sub(
            r"(?m)^(  espressif/esp_tinyusb:\n(?:    .*\n)*?    version:\s*)"
            + re.escape(ESP_TINYUSB_PIN),
            r"\g<1>9.9.9",
            t,
            count=1,
        )
        if t2 == t:
            # Fallback line replace of component-level version.
            t2 = t.replace(
                f"    version: {ESP_TINYUSB_PIN}",
                "    version: 9.9.9",
                1,
            )
        p.smoke_lock.write_text(t2, encoding="utf-8")

    def mut_link_anchor_smoke(p: Paths) -> None:
        t = p.smoke_main.read_text(encoding="utf-8")
        p.smoke_main.write_text(
            t + "\nninlil_esp_idf_usb_cdc_link_anchor();\n", encoding="utf-8"
        )

    def mut_drop_orch_teardown(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        # Remove production shared-teardown authority call (false-green if unchecked).
        t2 = re.sub(
            r"\bninlil_usb_cdc_orch_teardown\s*\(",
            "ninlil_usb_cdc_orch_teardown_REMOVED(",
            t,
            count=1,
        )
        if t2 == t:
            fail("self-test could not locate orch_teardown call to mutate")
        p.backend.write_text(t2, encoding="utf-8")

    def mut_void_try_begin_teardown(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = re.sub(
            r"if\s*\(\s*!\s*ninlil_usb_cdc_global_try_begin_teardown\s*\(",
            "if ((void)ninlil_usb_cdc_global_try_begin_teardown(",
            t,
            count=1,
        )
        # Also force a void cast form the gate rejects.
        if "try_begin_teardown" not in t2:
            fail("self-test could not mutate try_begin_teardown")
        t2 = t2.replace(
            "ninlil_usb_cdc_global_try_begin_teardown",
            "ninlil_usb_cdc_global_try_begin_teardown",
            0,
        )
        # Inject explicit void cast of the call as a decoy production bug.
        if "(void)ninlil_usb_cdc_global_try_begin_teardown" not in t2:
            t2 = t2.replace(
                "ninlil_usb_cdc_global_try_begin_teardown(&s_global, id)",
                "(void)ninlil_usb_cdc_global_try_begin_teardown(&s_global, id)",
                1,
            )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_poll_drain_before_owner(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        # Strip ordering marker and swap first check_owner block with a
        # drain-first decoy so structural poll order fails.
        t2 = t.replace("U2-POLL-OWNER-BEFORE-TX", "U2-POLL-TX-BEFORE-OWNER-BUG")
        # Force drain_tx_nonblocking to appear before check_owner in poll.
        t2 = re.sub(
            r"(ninlil_esp_idf_usb_cdc_poll\s*\([\s\S]*?)"
            r"(portENTER_CRITICAL\(&s_mux\);\s*"
            r"if\s*\(\s*!\s*ninlil_usb_cdc_core_check_owner)",
            r"\1did_drain = drain_tx_nonblocking(self, owner, out_error);\n"
            r"    \2",
            t2,
            count=1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_soft_clear_leave_order(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace(
            "U2-CB-SOFT-CLEAR-BEFORE-LEAVE",
            "U2-CB-LEAVE-BEFORE-SOFT-CLEAR-BUG",
        )
        p.backend.write_text(t2, encoding="utf-8")

    _expect_fail("float_esp_tinyusb_pin", mut_float_pin)
    _expect_fail("console_on_control_cdc", mut_console)
    _expect_fail("posix_in_esp_authority", mut_posix)
    _expect_fail("drop_c1_listening", mut_drop_listening)
    _expect_fail("lock_version_drift", mut_lock_drift)
    _expect_fail("smoke_link_anchor", mut_link_anchor_smoke)
    _expect_fail("drop_orch_teardown_call", mut_drop_orch_teardown)
    _expect_fail("void_try_begin_teardown", mut_void_try_begin_teardown)
    def mut_init_memset_before_guard(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace(
            "U2-INIT-GUARD-BEFORE-MEMSET",
            "U2-INIT-MEMSET-BEFORE-GUARD-BUG",
        )
        # Also force a memset-before-may_wipe order failure if marker alone is skipped.
        t2 = re.sub(
            r"(ninlil_esp_idf_usb_cdc_init\s*\([\s\S]*?)"
            r"(if\s*\(\s*!ensure_lifecycle_mutex)",
            r"\1(void)memset(storage, 0, sizeof(ninlil_esp_idf_usb_cdc_t));\n"
            r"    \2",
            t2,
            count=1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    _expect_fail("poll_drain_before_owner", mut_poll_drain_before_owner)
    _expect_fail("soft_clear_leave_order_marker", mut_soft_clear_leave_order)
    def mut_drop_unbound_seq_bump_order(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        # Remove marker and first bump in device_event_handler.
        t2 = t.replace("U2-UNBOUND-SEQ-BUMP", "U2-UNBOUND-SEQ-REMOVED", 1)
        t2 = t2.replace(
            "(void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);",
            "/* physical seq bump removed */",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_reconcile_snapshot_before_seq(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace(
            "U2-RECONCILE-SEQ-BEFORE-SNAPSHOT",
            "U2-RECONCILE-SNAPSHOT-BEFORE-SEQ-BUG",
        )
        # Invert order: snapshot first, then seq capture.
        t2 = t2.replace(
            "captured_seq = s_global.physical_event_seq;\n"
            "    portEXIT_CRITICAL(&s_mux);\n\n"
            "    esp_physical_snapshot(NULL, &attached, &dtr);",
            "esp_physical_snapshot(NULL, &attached, &dtr);\n"
            "    portENTER_CRITICAL(&s_mux);\n"
            "    captured_seq = s_global.physical_event_seq;\n"
            "    portEXIT_CRITICAL(&s_mux);",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_drop_unbound_rx_drain(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-UNBOUND-RX-DRAIN", "U2-UNBOUND-RX-DRAIN-REMOVED")
        t2 = t2.replace(
            "unbound_rx_fifo_drain_drop_holding_io",
            "unbound_rx_fifo_drain_drop_holding_io_REMOVED",
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_early_s_live_publish(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-FLUSH-BEFORE-PUBLISH", "U2-EARLY-PUBLISH-BUG")
        # Re-introduce early s_live before orch_install (classic race).
        t2 = t2.replace(
            "ninlil_usb_cdc_global_set_live_storage(&s_global, &sr);\n"
            "    portEXIT_CRITICAL(&s_mux);\n\n"
            "    self->owner_task = xTaskGetCurrentTaskHandle();\n\n"
            "    st = ninlil_usb_cdc_orch_install(",
            "ninlil_usb_cdc_global_set_live_storage(&s_global, &sr);\n"
            "    s_live = self;\n"
            "    portEXIT_CRITICAL(&s_mux);\n\n"
            "    self->owner_task = xTaskGetCurrentTaskHandle();\n\n"
            "    st = ninlil_usb_cdc_orch_install(",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_rx_mux_before_io(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-RX-IO-FIRST", "U2-RX-MUX-FIRST-BUG")
        t2 = t2.replace(
            "if (!io_lock()) {\n"
            "        return;\n"
            "    }\n\n"
            "    portENTER_CRITICAL(&s_mux);\n"
            "    self = s_live;",
            "portENTER_CRITICAL(&s_mux);\n"
            "    self = s_live;\n"
            "    if (!io_lock()) {\n"
            "        portEXIT_CRITICAL(&s_mux);\n"
            "        return;\n"
            "    }",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_drop_io_mutex_marker(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-IO-MUTEX", "U2-IO-MUTEX-REMOVED")
        t2 = t2.replace("ensure_io_mutex", "ensure_io_mutex_REMOVED")
        p.backend.write_text(t2, encoding="utf-8")

    def mut_close_soft_before_unpublish(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace(
            "U2-CLOSE-UNPUBLISH-FIRST", "U2-CLOSE-SOFT-BEFORE-UNPUBLISH-BUG"
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_soft_clear_inside_critical_keep_markers(p: Paths) -> None:
        """False-green class: markers intact, real driver call under s_mux."""
        t = p.backend.read_text(encoding="utf-8")
        # Inject into device_event_handler first critical section after bump.
        needle = (
            "(void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);\n"
            "    self = s_live;"
        )
        if needle not in t:
            fail("mutator setup: device_event bump/self pattern missing")
        t2 = t.replace(
            needle,
            "(void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);\n"
            "    esp_tx_fifo_soft_clear(NULL); /* injected under s_mux */\n"
            "    self = s_live;",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_wrapper_under_critical_keep_markers(p: Paths) -> None:
        """Indirect wrapper under s_mux (drain/wait/snapshot) must not pass."""
        t = p.backend.read_text(encoding="utf-8")
        needle = (
            "(void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);\n"
            "    self = s_live;"
        )
        if needle not in t:
            fail("mutator setup: device_event bump/self for wrapper inject")
        t2 = t.replace(
            needle,
            "(void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);\n"
            "    (void)wait_callbacks_drained(self); /* wrapper under s_mux */\n"
            "    self = s_live;",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def expect_branch_conditional_lock_leak() -> None:
        """held>saved on branch close must fail (not silent restore)."""
        snippet = """
void sample(void) {
    if (cond) {
        portENTER_CRITICAL(&s_mux);
        /* no EXIT — conditional lock would be dropped by naive restore */
    }
    (void)0;
}
"""
        try:
            check_no_driver_api_in_critical(snippet, where="branch-leak-self-test")
        except GateFailure as e:
            print(
                f"  self-test mutation 'branch_conditional_lock_leak' "
                f"correctly failed: {e}"
            )
            return
        fail(
            "self-test mutation 'branch_conditional_lock_leak' did not fail "
            "(branch restore false-green)"
        )

    def mut_poison_s_live_republish(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-SLIVE-SUCCESS-ONLY", "U2-SLIVE-POISON-REPUBLISH-BUG")
        # Force a second s_live=self in open failure path.
        t2 = t2.replace(
            "if (s_global.state == NINLIL_USB_CDC_BIND_POISONED) {\n"
            "            self->owner_task = xTaskGetCurrentTaskHandle();\n"
            "        }",
            "if (s_global.state == NINLIL_USB_CDC_BIND_POISONED) {\n"
            "            s_live = self;\n"
            "            self->owner_task = xTaskGetCurrentTaskHandle();\n"
            "        }",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    def mut_persist_call_outside_smux_keep_marker(p: Paths) -> None:
        """Race regression class: marker stays, real persist_* call leaves s_mux."""
        t = p.backend.read_text(encoding="utf-8")
        old = (
            "if (!ninlil_usb_cdc_global_try_begin_install(&s_global, id)) {\n"
            "        /* U2-PERSIST-UNDER-SMUX: core diagnosis mutation under s_mux */\n"
            "        persist_open_error(\n"
            "            &self->core,\n"
            "            NINLIL_BYTE_STREAM_BUSY,\n"
            "            NINLIL_BYTE_STREAM_STAGE_USB_STACK,\n"
            "            \"logical Control CDC bind busy or service poisoned\",\n"
            "            out_error);\n"
            "        portEXIT_CRITICAL(&s_mux);\n"
            "        (void)xSemaphoreGive(s_lifecycle);\n"
            "        return NINLIL_BYTE_STREAM_BUSY;\n"
            "    }"
        )
        new = (
            "if (!ninlil_usb_cdc_global_try_begin_install(&s_global, id)) {\n"
            "        /* U2-PERSIST-UNDER-SMUX: core diagnosis mutation under s_mux */\n"
            "        portEXIT_CRITICAL(&s_mux);\n"
            "        persist_open_error(\n"
            "            &self->core,\n"
            "            NINLIL_BYTE_STREAM_BUSY,\n"
            "            NINLIL_BYTE_STREAM_STAGE_USB_STACK,\n"
            "            \"logical Control CDC bind busy or service poisoned\",\n"
            "            out_error);\n"
            "        (void)xSemaphoreGive(s_lifecycle);\n"
            "        return NINLIL_BYTE_STREAM_BUSY;\n"
            "    }"
        )
        if old not in t:
            fail("mutator setup: try_begin_install persist_open_error block missing")
        p.backend.write_text(t.replace(old, new, 1), encoding="utf-8")

    def mut_poll_drop_recheck_before_io(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace("U2-POLL-RECHECK-BEFORE-IO", "U2-POLL-NO-RECHECK-BUG")
        p.backend.write_text(t2, encoding="utf-8")

    def mut_poll_use_period_ms(p: Paths) -> None:
        t = p.backend.read_text(encoding="utf-8")
        t2 = t.replace(
            "ninlil_usb_cdc_poll_required_ticks_hz(\n"
            "        timeout_ms, (uint32_t)configTICK_RATE_HZ);",
            "ninlil_usb_cdc_poll_required_ticks(\n"
            "        timeout_ms, (uint32_t)portTICK_PERIOD_MS);",
            1,
        )
        p.backend.write_text(t2, encoding="utf-8")

    _expect_fail("init_memset_before_guard", mut_init_memset_before_guard)
    _expect_fail("unbound_seq_bump_order", mut_drop_unbound_seq_bump_order)
    _expect_fail("reconcile_snapshot_before_seq", mut_reconcile_snapshot_before_seq)
    _expect_fail("drop_unbound_rx_drain", mut_drop_unbound_rx_drain)
    _expect_fail("early_s_live_publish", mut_early_s_live_publish)
    _expect_fail("rx_mux_before_io", mut_rx_mux_before_io)
    _expect_fail("drop_io_mutex", mut_drop_io_mutex_marker)
    _expect_fail("close_soft_before_unpublish", mut_close_soft_before_unpublish)
    _expect_fail(
        "soft_clear_inside_critical_keep_markers",
        mut_soft_clear_inside_critical_keep_markers,
    )
    _expect_fail(
        "wrapper_under_critical_keep_markers",
        mut_wrapper_under_critical_keep_markers,
    )
    expect_branch_conditional_lock_leak()
    _expect_fail("poison_s_live_republish", mut_poison_s_live_republish)
    _expect_fail(
        "persist_call_outside_smux_keep_marker",
        mut_persist_call_outside_smux_keep_marker,
    )
    _expect_fail("poll_drop_recheck_before_io", mut_poll_drop_recheck_before_io)
    _expect_fail("poll_use_period_ms", mut_poll_use_period_ms)
    print("esp_usb_cdc_u2_gate self-test ok")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print("usage: esp_usb_cdc_u2_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "self-test":
            self_test()
        else:
            check()
    except GateFailure as e:
        print(f"esp_usb_cdc_u2_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
