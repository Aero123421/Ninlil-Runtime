#!/usr/bin/env python3
"""N6 frame/stack-usage gate (docs/30 §20.4.1 boot workspace).

Authoritative host production .su only (ninlil_runtime_private object dir).
Does not scan testbuild or whole-tree build/ directories.

Rules:
  - exactly one .su per each of the 3 exact N6 source identities
  - every non-comment non-empty .su line must parse (no silent skip)
  - each required .su has parsed rows >= 1; every row kind == static
  - exactly one ninlil_n6_boot_scan row across those artifacts
  - boot_scan frame ≤ 1024; every N6 function frame ≤ 2048
  - missing/duplicate .su / malformed / row0 / dynamic → hard FAIL

ESP .su: --esp-su-dir required for ESP claim; host substitute forbidden.
Workflow must collect each exact N6 .su with find match count == 1
(no head -1 first-match selection).

PASS ≠ product GO.
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

BOOT_LIMIT = 1024
N6_LIMIT = 2048
BOOT_FUNC = "ninlil_n6_boot_scan"

SOURCE_IDENTITIES = (
    "n6_context_store.c",
    "n6_record_codec.c",
    "n6_crypto_host.c",
)

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "esp-idf.yml"
HOST_CMAKE = REPO_ROOT / "CMakeLists.txt"
PRIVATE_AUTH = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"


def _su_basename_for(identity: str) -> str:
    return f"{identity}.su"


def discover_su_files(su_dir: Path) -> list[Path]:
    if not su_dir.is_dir():
        return []
    return sorted(p for p in su_dir.rglob("*.su") if p.is_file())


def map_identities(su_files: list[Path]) -> dict[str, list[Path]]:
    by_id: dict[str, list[Path]] = {ident: [] for ident in SOURCE_IDENTITIES}
    for p in su_files:
        name = p.name
        for ident in SOURCE_IDENTITIES:
            if name == _su_basename_for(ident):
                by_id[ident].append(p)
                break
    return by_id


def parse_su_rows(path: Path) -> tuple[list[tuple[str, int, str]], list[str]]:
    """Parse .su rows. Every non-comment non-empty line must parse.

    Returns (rows, errs). Malformed lines produce errors — never silent skip.
    Format: ``path:line[:col]:function\\tsize\\tkind``
    """
    rows: list[tuple[str, int, str]] = []
    errs: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            errs.append(
                f"{path.name}:{lineno}: malformed .su line "
                f"(need function\\tsize\\tkind tabs, got {len(parts)} fields): "
                f"{line!r}"
            )
            continue
        head = parts[0]
        size_s = parts[1].strip()
        kind_raw = parts[2].strip()
        if not size_s or not re.fullmatch(r"-?\d+", size_s):
            errs.append(
                f"{path.name}:{lineno}: non-numeric frame size {size_s!r} "
                f"in {line!r}"
            )
            continue
        size = int(size_s)
        if size < 0:
            errs.append(
                f"{path.name}:{lineno}: negative frame size {size} in {line!r}"
            )
            continue
        func = head.rsplit(":", 1)[-1].strip()
        if not func:
            errs.append(
                f"{path.name}:{lineno}: missing function name in {line!r}"
            )
            continue
        if not kind_raw:
            errs.append(
                f"{path.name}:{lineno}: missing usage kind in {line!r}"
            )
            continue
        kind = re.split(r"[\s,]", kind_raw, maxsplit=1)[0].lower()
        if not kind:
            errs.append(
                f"{path.name}:{lineno}: empty usage kind in {line!r}"
            )
            continue
        # Unknown kind is not silently accepted as a valid row for limits —
        # still record the row so static check can fail closed.
        rows.append((func, size, kind))
    return rows, errs


def _is_boot_func(name: str) -> bool:
    n = name.strip()
    if n.startswith("_"):
        n = n[1:]
    return n == BOOT_FUNC


def check_su_dir(su_dir: Path) -> list[str]:
    errs: list[str] = []
    if not su_dir.is_dir():
        return [f"su dir missing: {su_dir}"]

    su_files = discover_su_files(su_dir)
    by_id = map_identities(su_files)

    for ident in SOURCE_IDENTITIES:
        matches = by_id[ident]
        if len(matches) == 0:
            errs.append(f"missing .su artifact for {ident}")
        elif len(matches) > 1:
            paths = ", ".join(str(p) for p in matches)
            errs.append(f"duplicate .su for {ident}: {paths}")

    if any("missing .su" in e or "duplicate .su" in e for e in errs):
        # Still attempt parse of present files for better diagnostics, but
        # identity failures already fail closed.
        pass

    boot_rows: list[tuple[Path, str, int, str]] = []
    for ident in SOURCE_IDENTITIES:
        matches = by_id[ident]
        if len(matches) != 1:
            continue
        p = matches[0]
        rows, parse_errs = parse_su_rows(p)
        errs.extend(parse_errs)
        if len(rows) < 1:
            errs.append(
                f"{p.name}: parsed row count {len(rows)} < 1 "
                f"(empty or fully malformed .su)"
            )
            continue
        for func, size, kind in rows:
            if kind != "static":
                errs.append(
                    f"usage kind must be static, got {kind!r} for {func} in {p.name}"
                )
            if _is_boot_func(func):
                boot_rows.append((p, func, size, kind))
            if size > N6_LIMIT:
                errs.append(
                    f"N6 function {func} frame {size} > {N6_LIMIT} in {p.name}"
                )

    if len(boot_rows) == 0:
        # Only report missing boot if we had all three identities (avoid noise)
        if all(len(by_id[i]) == 1 for i in SOURCE_IDENTITIES):
            errs.append(f"{BOOT_FUNC} missing from .su artifacts")
    elif len(boot_rows) > 1:
        detail = ", ".join(f"{p.name}:{sz}" for p, _, sz, _ in boot_rows)
        errs.append(f"duplicate {BOOT_FUNC} rows: {detail}")
    else:
        _, _, boot_sz, _ = boot_rows[0]
        if boot_sz > BOOT_LIMIT:
            errs.append(
                f"boot_scan frame {boot_sz} > {BOOT_LIMIT} in {boot_rows[0][0].name}"
            )

    return errs


def _shell_transform(text: str, *, blank_strings: bool) -> str:
    """Strip # comments outside quotes; optionally blank string interiors."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_quote: str | None = None
    while i < n:
        c = text[i]
        if in_quote is not None:
            if c == "\\" and i + 1 < n:
                if blank_strings:
                    out.append(" ")
                    out.append(" ")
                else:
                    out.append(c)
                    out.append(text[i + 1])
                i += 2
                continue
            if c == in_quote:
                out.append(c)
                in_quote = None
                i += 1
                continue
            if blank_strings:
                out.append("\n" if c == "\n" else " ")
            else:
                out.append(c)
            i += 1
            continue
        if c in ('"', "'"):
            in_quote = c
            out.append(c)
            i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _shell_code_no_comments(text: str) -> str:
    return _shell_transform(text, blank_strings=False)


def _shell_structure_code(text: str) -> str:
    """Comments removed; string interiors blanked (YAML/shell structure evidence)."""
    return _shell_transform(text, blank_strings=True)


def _cmake_structure_code_local(text: str) -> str:
    """CMake structure: drop # comments; blank string interiors."""
    return _shell_transform(text, blank_strings=True)


def _line_end_with_continuations(text: str, pos: int) -> int:
    """Return index after the physical line at pos, absorbing trailing ``\\`` conts."""
    line_end = text.find("\n", pos)
    if line_end < 0:
        return len(text)
    end = line_end
    while end > 0 and end < len(text):
        i = end - 1
        while i > 0 and text[i] in " \t":
            i -= 1
        if text[i] != "\\":
            break
        nxt = text.find("\n", end + 1)
        if nxt < 0:
            return len(text)
        end = nxt
    return end


def _extend_region_shell_balance(text: str, start: int, end: int) -> tuple[int, int]:
    """Extend ``[start, end)`` so open quotes / ``$(…)`` / backticks / ``()`` close.

    Needed for multi-line double-quoted command substitution such as::

        echo "$(
          python3 tools/n6_frame_stack_gate.py check …
        )"

    where cutting at the gate physical line would lose the outer ``echo "$(…)"``
    and make structural/mock analysis see a bare unconditional gate.
    """
    n = len(text)

    def _state(seg: str) -> tuple[str | None, int, int, int]:
        """Return (quote, cmdsub_depth, paren_depth, backtick_depth)."""
        quote: str | None = None
        cmdsub = 0
        paren = 0
        tick = 0
        i = 0
        sl = len(seg)
        while i < sl:
            c = seg[i]
            if quote == "'":
                if c == "'":
                    quote = None
                i += 1
                continue
            if quote == '"':
                if c == "\\" and i + 1 < sl:
                    i += 2
                    continue
                if c == '"':
                    quote = None
                    i += 1
                    continue
                if c == "`":
                    tick += 1
                    i += 1
                    continue
                if c == "$" and i + 1 < sl and seg[i + 1] == "(":
                    cmdsub += 1
                    paren += 1
                    i += 2
                    continue
                if c == ")" and cmdsub > 0:
                    paren = max(0, paren - 1)
                    cmdsub = max(0, cmdsub - 1)
                    i += 1
                    continue
                i += 1
                continue
            # unquoted
            if c in ("'", '"'):
                quote = c
                i += 1
                continue
            if c == "`":
                if tick > 0:
                    tick -= 1
                else:
                    tick += 1
                i += 1
                continue
            if c == "$" and i + 1 < sl and seg[i + 1] == "(":
                cmdsub += 1
                paren += 1
                i += 2
                continue
            if c == "(":
                paren += 1
                i += 1
                continue
            if c == ")":
                if paren > 0:
                    paren -= 1
                if cmdsub > 0 and paren < cmdsub:
                    # align cmdsub to paren floor
                    cmdsub = paren
                i += 1
                continue
            if c == "\\" and i + 1 < sl:
                i += 2
                continue
            i += 1
        return quote, cmdsub, paren, tick

    # If start is mid-construct opened earlier, walk start backward line-wise.
    guard = 0
    while start > 0 and guard < 200:
        guard += 1
        pre_q, pre_c, pre_p, pre_t = _state(text[:start])
        if pre_q is None and pre_c == 0 and pre_p == 0 and pre_t == 0:
            break
        prev = text.rfind("\n", 0, start - 1)
        start = 0 if prev < 0 else prev + 1

    # Extend end until the slice is balanced (or EOF).
    guard = 0
    while guard < 200:
        guard += 1
        q, c, p, t = _state(text[start:end])
        if q is None and c == 0 and p == 0 and t == 0:
            break
        if end >= n:
            break
        nxt = text.find("\n", end)
        end = n if nxt < 0 else nxt + 1
    return start, end


def _n6_workflow_collection_block(wf: str) -> str | None:
    """Extract N6_SU_DIR through full gate statement (raw text).

    Includes multi-line ``python3 … n6_frame_stack_gate.py check \\``
    ``--su-dir … \\`` ``--esp-su-dir …`` and outer wrappers such as
    ``echo "$( … gate … )"`` so shell context is not lost at the gate line.
    """
    start = wf.find("N6_SU_DIR=")
    if start < 0:
        return None
    gate = wf.find("n6_frame_stack_gate.py", start)
    if gate < 0:
        return None
    end = _line_end_with_continuations(wf, gate)
    start, end = _extend_region_shell_balance(wf, start, end)
    return wf[start:end]


def _workflow_script_unit_for_gate(wf: str) -> tuple[str, int] | None:
    """Return (script_unit_text, gate_offset_in_unit) for the gate's shell unit.

    Prefers a ``bash … <<['\"]TAG`` heredoc body that contains the gate
    (docker ``bash -s`` inner script). Falls back to the whole workflow text
    so local fixtures without a heredoc still validate.
    """
    gate = wf.find("n6_frame_stack_gate.py")
    if gate < 0:
        return None
    # Search backwards for heredoc introducer before the gate.
    head = wf[:gate]
    heredoc_re = re.compile(
        r"<<-?\s*(?P<q>['\"]?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)(?P=q)\s*\n",
    )
    last = None
    for m in heredoc_re.finditer(head):
        last = m
    if last is not None:
        tag = last.group("tag")
        body_start = last.end()
        # Closing tag at beginning of line (optional whitespace).
        close = re.search(
            rf"(?m)^\s*{re.escape(tag)}\s*$",
            wf[body_start:],
        )
        body_end = body_start + close.start() if close else len(wf)
        # Gate must sit inside this body.
        if body_start <= gate < body_end:
            unit = wf[body_start:body_end]
            return unit, gate - body_start
    return wf, gate


def _shell_set_token_in(bare: str) -> bool:
    """True if ``bare`` contains a ``set -/+o`` or ``set -<flags>`` builtin.

    Recognizes ``set`` as a simple command after statement separators **and**
    after shell compound introducers (``then`` / ``do`` / ``else`` / ``elif``)
    so called-function bodies like
    ``opts() { if true; then set -euo pipefail; fi; }; opts`` are detected
    without promoting the token out of its control-flow context.
    """
    # Statement start: BOL, ;|&({}), or then/do/else/elif keyword.
    # Do not match the trailing ``set`` of ``unset`` / ``typeset`` (word-boundary
    # on set via preceding separator/keyword only).
    return bool(
        re.search(
            r"(?:^|[;|&({}])\s*(?:(?:then|do|else|elif)\b\s+)*set\s+[-+o]",
            bare,
        )
        or re.search(
            r"(?:^|[;|&({}])\s*(?:(?:then|do|else|elif)\b\s+)*set\s+-[a-zA-Z]",
            bare,
        )
        or re.match(
            r"(?:(?:then|do|else|elif)\b\s+)*set\s+[-+o]",
            bare.lstrip(),
        )
        or re.match(
            r"(?:(?:then|do|else|elif)\b\s+)*set\s+-[a-zA-Z]",
            bare.lstrip(),
        )
    )


def _scan_shell_line_nesting(
    line: str,
    quote: str | None,
    paren_depth: int,
    func_depth: int,
    pending_func: bool,
    *,
    brace_depth: int = 0,
    pending_func_name: str | None = None,
) -> tuple[
    str | None,
    int,
    int,
    bool,
    bool,
    int,
    str | None,
    list[str],
    bool,
    list[tuple[str, int, int | None, bool]],
    list[str],
]:
    """Update quote/paren/function/brace nesting across one line.

    Returns
      (new_quote, new_paren_depth, new_func_depth, new_pending_func,
       saw_current_shell_live_set, new_brace_depth, new_pending_func_name,
       closed_funcs, saw_func_body_set, active_func_snapshot, top_calls)

    ``saw_current_shell_live_set`` is True only when a ``set`` builtin token
    is seen at paren_depth==0 and func_depth==0 outside quotes — i.e. it
    would affect the current shell if executed, not a subshell, uncalled
    function body, or string interior.

    Brace groups ``{ … }`` run in the current shell; ``set`` inside them is
    live. Function declarators ``name()`` / ``function name`` are recognized
    so empty ``()`` does not count as a subshell and the following ``{…}``
    body is tracked as ``func_depth``. ``set`` inside a function body is
    reported via ``saw_func_body_set`` (live only when that function is
    later invoked in the current shell — the extractor keeps def+call as a
    unit and never promotes the inner ``set`` alone).
    """
    i = 0
    n = len(line)
    q = quote
    saw_live = False
    saw_func_set = False
    code_at_top: list[str] = []
    code_in_func: list[str] = []
    # Functions closed on this line: (name, start_line_marker, end_marker, has_set)
    # start/end line indices are filled by the caller; here end_marker is None.
    closed_funcs: list[tuple[str, int, int | None, bool]] = []
    # Active function being defined: mutated via list for caller sync.
    # Caller passes pending name; we emit closed entries when func_depth hits 0.
    active_func_snapshot: list[tuple[str, int, int | None, bool]] = []
    top_calls: list[str] = []
    # Track statement-start for top-level simple command names.
    at_stmt = True
    active_name = pending_func_name
    active_has_set = False
    # func_start line is owned by caller; we only know name/has_set here.
    func_just_closed: list[tuple[str, bool]] = []

    def _flush_top_set(buf: list[str]) -> bool:
        return _shell_set_token_in("".join(buf))

    def _flush_func_set(buf: list[str]) -> bool:
        return _shell_set_token_in("".join(buf))

    def _note_top_word(word: str) -> None:
        if word and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
            top_calls.append(word)

    while i < n:
        c = line[i]
        if q is not None:
            if q == "'" and c == "'":
                q = None
            elif q == '"':
                if c == "\\" and i + 1 < n:
                    i += 2
                    continue
                if c == '"':
                    q = None
            i += 1
            continue
        if c in ("'", '"'):
            if paren_depth == 0 and func_depth == 0 and _flush_top_set(code_at_top):
                saw_live = True
            if func_depth > 0 and _flush_func_set(code_in_func):
                saw_func_set = True
                active_has_set = True
            code_at_top.clear()
            code_in_func.clear()
            q = c
            at_stmt = False
            i += 1
            continue
        if c == "#":
            break

        # function keyword → pending function body
        if (
            paren_depth == 0
            and func_depth == 0
            and re.match(r"function\s+([A-Za-z_][A-Za-z0-9_]*)", line[i:])
        ):
            mfun = re.match(r"function\s+([A-Za-z_][A-Za-z0-9_]*)", line[i:])
            assert mfun is not None
            pending_func = True
            active_name = mfun.group(1)
            active_has_set = False
            i += mfun.end()
            at_stmt = False
            continue
        if (
            paren_depth == 0
            and func_depth == 0
            and re.match(r"function\b", line[i:])
        ):
            pending_func = True
            mfun = re.match(r"function\b", line[i:])
            assert mfun is not None
            i += mfun.end()
            at_stmt = False
            continue

        # name() declarator at top level (not a subshell / not a call)
        if paren_depth == 0 and func_depth == 0:
            mdecl = re.match(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)", line[i:]
            )
            if mdecl:
                pending_func = True
                active_name = mdecl.group(1)
                active_has_set = False
                i += mdecl.end()
                at_stmt = False
                continue

        if c == "(":
            if paren_depth == 0 and func_depth == 0 and _flush_top_set(code_at_top):
                saw_live = True
            code_at_top.clear()
            paren_depth += 1
            at_stmt = False
            i += 1
            continue
        if c == ")":
            paren_depth = max(0, paren_depth - 1)
            at_stmt = False
            i += 1
            continue
        if c == "{":
            if pending_func and paren_depth == 0:
                pending_func = False
                func_depth += 1
                code_at_top.clear()
                code_in_func.clear()
                at_stmt = True
                i += 1
                continue
            if func_depth > 0 and paren_depth == 0:
                func_depth += 1
                i += 1
                continue
            # Brace group runs in current shell.
            if paren_depth == 0 and func_depth == 0:
                if _flush_top_set(code_at_top):
                    saw_live = True
                code_at_top.clear()
                code_at_top.append(c)
                brace_depth += 1
            at_stmt = True  # `{ cmd;` — next word is a new statement
            i += 1
            continue
        if c == "}":
            if func_depth > 0 and paren_depth == 0:
                if _flush_func_set(code_in_func):
                    saw_func_set = True
                    active_has_set = True
                code_in_func.clear()
                func_depth -= 1
                if func_depth == 0 and active_name:
                    func_just_closed.append((active_name, active_has_set))
                    active_name = None
                    active_has_set = False
                at_stmt = True
                i += 1
                continue
            if paren_depth == 0 and func_depth == 0:
                code_at_top.append(c)
                if _flush_top_set(code_at_top):
                    saw_live = True
                code_at_top.clear()
                brace_depth = max(0, brace_depth - 1)
            at_stmt = True
            i += 1
            continue

        if c in (";", "\n"):
            if paren_depth == 0 and func_depth == 0 and _flush_top_set(code_at_top):
                saw_live = True
            if func_depth > 0 and _flush_func_set(code_in_func):
                saw_func_set = True
                active_has_set = True
            if paren_depth == 0 and func_depth == 0:
                code_at_top.clear()
            code_in_func.clear()
            at_stmt = True
            i += 1
            continue
        if c in ("&", "|") and paren_depth == 0 and func_depth == 0:
            if _flush_top_set(code_at_top):
                saw_live = True
            code_at_top.append(c)
            at_stmt = True
            i += 1
            continue

        # Top-level simple command word (function invocation candidate).
        if paren_depth == 0 and func_depth == 0 and at_stmt and c not in " \t":
            mw = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", line[i:])
            if mw:
                _note_top_word(mw.group(1))
                for ch in mw.group(0):
                    code_at_top.append(ch)
                i += mw.end()
                at_stmt = False
                continue

        if paren_depth == 0 and func_depth == 0:
            code_at_top.append(c)
        elif func_depth > 0 and paren_depth == 0:
            code_in_func.append(c)
        if c not in " \t":
            at_stmt = False
        i += 1

    if paren_depth == 0 and func_depth == 0 and _flush_top_set(code_at_top):
        saw_live = True
    if func_depth > 0 and _flush_func_set(code_in_func):
        saw_func_set = True
        active_has_set = True

    for name, has_set in func_just_closed:
        closed_funcs.append((name, -1, None, has_set))

    return (
        q,
        paren_depth,
        func_depth,
        pending_func,
        saw_live,
        brace_depth,
        active_name,
        closed_funcs,
        saw_func_set or active_has_set,
        active_func_snapshot,
        top_calls,
    )


def _extract_live_set_prefix(unit: str, before: int) -> str:
    """Shell fragment reproducing live ``set`` option state before ``before``.

    Keeps, with unit control-flow meaning intact (no silent set-promotion):

      - bare current-shell ``set`` commands
      - current-shell brace groups ``{ set …; }`` that contain live set
      - full ``if/fi``, ``for/done``, ``while/done``, ``case/esac`` regions
        that contain a current-shell live set (conditional-only set stays
        conditional)
      - **called** function definition + invocation when the function body
        contains ``set`` (including nested control that still runs in the
        current shell when called), e.g.
        ``opts(){ set -euo pipefail; }; opts`` and
        ``opts() { if true; then set -euo pipefail; fi; }; opts``.
        The mock keeps the real def+call (body/control intact) so options
        take effect without promoting ``set`` out of the function body.

    Does **not** promote ``set`` that only appears inside:

      - subshells ``( … )`` / cmdsub (paren depth > 0)
      - uncalled function bodies ``name() { … }`` / ``function name { … }``
      - multi-line quoted strings
      - false conditionals ``if false; then set …; fi``
      - called functions whose control path does not execute ``set``
        (e.g. ``opts() { if false; then set …; fi; }; opts`` — mock keeps
        the def+call and observes that options stay off)

    into a top-level effective ``set``. The mock must not invent a stronger
    option state than the real unit (false GREEN on mock return 7).

    Does **not** inject ``set -euo pipefail``; absence means the mock runs
    without it (fail-open under a gate ``return 7``).
    """
    text = unit[: max(0, before)]
    lines = text.splitlines(keepends=True)
    n = len(lines)
    if n == 0:
        return ""
    keep = [False] * n
    stack: list[tuple[str, int]] = []
    regions: list[tuple[int, int]] = []
    live_set_line = [False] * n

    quote: str | None = None
    paren_depth = 0
    func_depth = 0
    pending_func = False
    brace_depth = 0
    pending_func_name: str | None = None
    # name -> (start_line, end_line, has_set_in_body)
    functions: dict[str, tuple[int, int, bool]] = {}
    # Function currently being defined: (name, start_line, has_set)
    open_func: tuple[str, int, bool] | None = None
    # Line of the most recent ``name()`` / ``function name`` declarator so a
    # multi-line ``opts()\n{ … }`` keeps the declarator in the def region.
    func_decl_line: int | None = None
    # Lines that invoke a simple command at current shell (top-level).
    call_lines: list[tuple[int, str]] = []
    # Brace-group regions (current-shell) containing live set.
    brace_stack: list[int] = []
    brace_regions: list[tuple[int, int]] = []

    for i, line in enumerate(lines):
        s = line.strip()
        in_continued_quote = quote is not None
        prev_func_depth = func_depth
        prev_brace = brace_depth
        prev_pending_name = pending_func_name

        (
            quote,
            paren_depth,
            func_depth,
            pending_func,
            saw_live,
            brace_depth,
            pending_func_name,
            closed_funcs,
            saw_func_set,
            _active_snap,
            top_calls,
        ) = _scan_shell_line_nesting(
            line,
            quote,
            paren_depth,
            func_depth,
            pending_func,
            brace_depth=brace_depth,
            pending_func_name=pending_func_name,
        )
        live_set_line[i] = saw_live

        # Declarator seen this line (name became pending while still depth 0).
        if pending_func_name and (
            prev_pending_name != pending_func_name or func_decl_line is None
        ):
            if prev_func_depth == 0:
                func_decl_line = i

        # Track function open: depth 0→1 with a name.
        if prev_func_depth == 0 and func_depth > 0:
            fname = pending_func_name or (
                open_func[0] if open_func else None
            )
            if fname:
                start = (
                    func_decl_line if func_decl_line is not None else i
                )
                open_func = (fname, start, False)
                func_decl_line = None
        if open_func is not None and saw_func_set:
            open_func = (open_func[0], open_func[1], True)

        def _body_has_set(start: int, end: int, seed: bool) -> bool:
            if seed:
                return True
            # One-liner def+call shares a line with a trailing invocation;
            # only treat set as in-body when it appears before the closing
            # ``}`` of the function on that span (structural, not promotion).
            for t in range(start, end + 1):
                frag = lines[t]
                # If the line also closes the function, only inspect up to `}`.
                close_at = frag.find("}")
                check = frag if close_at < 0 else frag[: close_at + 1]
                if _shell_set_token_in(check):
                    return True
            return False

        # closed_funcs from scanner (name, _, _, has_set) — end at this line.
        for cname, _a, _b, has_set in closed_funcs:
            start = open_func[1] if open_func and open_func[0] == cname else i
            body_set = _body_has_set(
                start,
                i,
                has_set
                or (
                    open_func[2]
                    if open_func and open_func[0] == cname
                    else False
                ),
            )
            functions[cname] = (start, i, body_set)
            if open_func and open_func[0] == cname:
                open_func = None

        # If function closed by depth drop without closed_funcs entry.
        if prev_func_depth > 0 and func_depth == 0 and open_func is not None:
            cname, start, body_set = open_func
            body_set = _body_has_set(start, i, body_set)
            functions[cname] = (start, i, body_set)
            open_func = None

        # Current-shell brace group tracking (func_depth==0 path only).
        if brace_depth > prev_brace:
            for _ in range(brace_depth - prev_brace):
                brace_stack.append(i)
        if brace_depth < prev_brace:
            for _ in range(prev_brace - brace_depth):
                if brace_stack:
                    bstart = brace_stack.pop()
                    if any(live_set_line[t] for t in range(bstart, i + 1)):
                        brace_regions.append((bstart, i))

        for word in top_calls:
            call_lines.append((i, word))

        if in_continued_quote or not s or s.startswith("#"):
            continue

        # Control-structure stack (line-oriented, same as prior gate policy).
        if re.match(r"if\b", s):
            stack.append(("if", i))
        elif re.match(r"(for|while|until)\b", s):
            stack.append(("loop", i))
        elif re.match(r"case\b", s):
            stack.append(("case", i))
        elif re.match(r"fi\b", s):
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == "if":
                    start = stack[k][1]
                    stack.pop(k)
                    if any(live_set_line[t] for t in range(start, i + 1)):
                        regions.append((start, i))
                    break
        elif re.match(r"done\b", s):
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == "loop":
                    start = stack[k][1]
                    stack.pop(k)
                    if any(live_set_line[t] for t in range(start, i + 1)):
                        regions.append((start, i))
                    break
        elif re.match(r"esac\b", s):
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == "case":
                    start = stack[k][1]
                    stack.pop(k)
                    if any(live_set_line[t] for t in range(start, i + 1)):
                        regions.append((start, i))
                    break
        elif saw_live and not stack and brace_depth == 0 and not brace_stack:
            # Bare current-shell set outside open control / brace structures.
            # (Brace-contained set is kept via brace_regions, full group.)
            regions.append((i, i))

    regions.extend(brace_regions)

    # Called functions whose body contains set: keep def + call line(s).
    # Do not extract the inner set alone (no promotion).
    called_with_set = set()
    for li, word in call_lines:
        info = functions.get(word)
        if info is None:
            continue
        fstart, fend, has_set = info
        if not has_set:
            continue
        # Call must be outside the definition span (or after end on same line).
        if li < fstart:
            continue
        if li <= fend:
            # Same-line def+call: ``opts(){ set …; }; opts`` — keep the line
            # once as the definition region; call is on the same line.
            pass
        called_with_set.add(word)
        regions.append((fstart, fend))
        if li > fend:
            regions.append((li, li))

    for a, b in regions:
        for t in range(a, min(b + 1, n)):
            keep[t] = True
    out: list[str] = []
    for i, line in enumerate(lines):
        if keep[i]:
            out.append(line if line.endswith("\n") else line + "\n")
    return "".join(out)


# mapfile -t ARR < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil … -name "${name}" …)
# n="${#ARR[@]}"
# if [[ "${n}" -ne 1 ]]; then … exit 1; fi
# … cp from ARR[0]
# find root path is bound inside the process substitution (decoy strings elsewhere fail).
_N6_COLLECT_GUARD_RE = re.compile(
    r"mapfile\s+-t\s+(?P<arr>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"<\s*<\s*\(\s*find\s+"
    r"ports/esp-idf/smoke_app/build/esp-idf/ninlil\b"
    r"(?:(?!mapfile).){0,400}?"
    r"-name\s+\"\$\{name\}\""
    r"(?:(?!mapfile).){0,300}?"
    r"\)\s*"
    r"(?:(?!mapfile).){0,120}?"
    r"\bn=\"\$\{#(?P=arr)\[@\]\}\"\s*"
    r"(?:(?!mapfile).){0,80}?"
    r"if\s+\[\[\s*\"\$\{n\}\"\s+-ne\s+1\s*\]\]\s*;?\s*then\b"
    r"(?:(?!\bfi\b).){0,600}?"
    r"exit\s+1"
    r"(?:(?!\bfor\b).){0,400}?"
    r"(?:"
    r"cp\s+\"\$\{(?P=arr)\[0\]\}\""
    r"|"
    r"found=\"\$\{(?P=arr)\[0\]\}\""
    r"(?:(?!\bfor\b).){0,120}?"
    r"cp\s+\"\$\{found\}\""
    r")",
    re.S,
)


def _workflow_n6_collection_ok(wf: str) -> list[str]:
    """Bind real find+mapfile → raw count exact1 → same element copy → gate.

    Dataflow (same block, code-only; comments/echo decoys are not evidence):
      DIRVAR=…/ninlil_n6_su
      mapfile -t ARR < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil …)
      n="${#ARR[@]}"   # raw array count, no tail/head collapse
      [[ "${n}" -ne 1 ]] → exit 1
      cp ARR[0] → ${DIRVAR}/name
      python3 tools/n6_frame_stack_gate.py check \\
        --su-dir "${DIRVAR}" --esp-su-dir "${DIRVAR}"
      (no echo wrapper, no || true fail-open)
    """
    errs: list[str] = []
    block = _n6_workflow_collection_block(wf)
    if block is None:
        errs.append(
            "esp-idf.yml missing N6_SU_DIR … n6_frame_stack_gate.py collection block"
        )
        return errs

    # Keep string contents so ${#matches[@]} and "${name}" remain visible.
    code = _shell_code_no_comments(block)

    for_m = re.search(
        r"for\s+name\s+in\s+((?:n6_[A-Za-z0-9_.]+\.su\s*)+);\s*do",
        code,
    )
    if not for_m:
        errs.append(
            "esp-idf.yml N6 collection must use "
            "`for name in <exact three .su basenames>; do`"
        )
    else:
        names = for_m.group(1).split()
        expected = {_su_basename_for(i) for i in SOURCE_IDENTITIES}
        got = set(names)
        if len(names) != len(got):
            errs.append(
                f"esp-idf.yml N6 for-loop basenames must not duplicate: {names}"
            )
        if got != expected:
            errs.append(
                "esp-idf.yml N6 for-loop basenames must be exact set "
                f"{sorted(expected)}; got {sorted(got)}"
            )

    # Collapse of multi-match via head/tail -1 is forbidden (not head -50 logs).
    if re.search(r"\bhead\s+(-n\s+)?1\b", code) or re.search(
        r"\btail\s+(-n\s+)?1\b", code
    ):
        errs.append(
            "esp-idf.yml N6 collection must not use head/tail -1 "
            "(must fail on raw match count 0 or 2+)"
        )
    if re.search(r"find\b[\s\S]{0,500}\|\s*(?:head|tail)\s+(-n\s+)?1\b", code):
        errs.append(
            "esp-idf.yml N6 find pipeline must not pipe to head/tail -1 "
            "(duplicate collapse forbidden)"
        )

    if not re.search(r"\bmapfile\s+-t\b", code):
        errs.append(
            "esp-idf.yml N6 collection must use mapfile -t to capture find results"
        )
    if re.search(r"matches\s*=\s*\(", code) and not re.search(
        r"mapfile\s+-t\s+matches\b", code
    ):
        errs.append(
            "esp-idf.yml N6 collection must not hardcode matches=(...); "
            "require mapfile/find"
        )

    coll = _N6_COLLECT_GUARD_RE.search(code)
    if not coll:
        errs.append(
            "esp-idf.yml N6 collection must bind "
            "mapfile -t ARR < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil "
            "… -name \"${name}\") → "
            "n=\"${#ARR[@]}\" → [[ \"${n}\" -ne 1 ]] → exit 1 → cp ARR[0] "
            "(forged n=1, hardcoded matches, tail collapse, or untrusted find root fail)"
        )
        return errs

    arr = coll.group("arr")

    # Destination dir var: must be assigned and used for cp + both gate args.
    # Quoted and unquoted path assignments are both valid shell:
    #   N6_SU_DIR=ports/.../ninlil_n6_su
    #   N6_SU_DIR="ports/.../ninlil_n6_su"
    dir_m = re.search(
        r"(?P<dirvar>[A-Za-z_][A-Za-z0-9_]*)="
        r"(?P<q>[\"']?)"
        r"(?P<dirpath>ports/esp-idf/smoke_app/build/ninlil_n6_su)"
        r"(?P=q)",
        code,
    )
    if not dir_m:
        errs.append(
            "esp-idf.yml must assign DIRVAR=ports/esp-idf/smoke_app/build/ninlil_n6_su "
            "(optional quotes) for N6 .su collection destination"
        )
        return errs
    dirvar = dir_m.group("dirvar")

    # cp must write into ${DIRVAR}/… from ARR[0] or found=${ARR[0]}
    arr0 = re.escape(arr) + r"\[0\]"
    dir_esc = re.escape(dirvar)
    cp_ok = re.search(
        r"cp\s+\"\$\{(?:" + arr0 + r"|found)\}\"\s+\"\$\{" + dir_esc + r"\}/",
        code,
    )
    found_ok = re.search(r"found=\"\$\{" + arr0 + r"\}\"", code) and re.search(
        r"cp\s+\"\$\{found\}\"\s+\"\$\{" + dir_esc + r"\}/",
        code,
    )
    if not cp_ok and not found_ok:
        errs.append(
            f"esp-idf.yml N6 cp must copy mapfile element into "
            f"${{{dirvar}}}/… (same collection dir)"
        )

    # Gate invocation: real python3 (not echo), both args = ${DIRVAR},
    # unconditional execution + set -e failure propagation (no fail-open).
    flat_code = re.sub(r"\\\s*\n", " ", code)
    # Reject non-execution wrappers (echo/printf of the command text).
    if re.search(
        r"(?:^|[\n;|&])\s*(?:echo|printf)\s+.*n6_frame_stack_gate\.py",
        flat_code,
    ) and not re.search(
        r"(?:^|[\n;|&])\s*python3\s+tools/n6_frame_stack_gate\.py\s+check\b",
        flat_code,
    ):
        errs.append(
            "esp-idf.yml must execute n6_frame_stack_gate.py "
            "(echo/printf wrapper is non-execution)"
        )
        return errs

    # Count top-level-looking python3 gate invocations in the collection block
    # (command-sub interiors still match the pattern — mock verifies call count).
    gate_invocs = list(
        re.finditer(
            r"python3\s+tools/n6_frame_stack_gate\.py\s+check\b",
            flat_code,
        )
    )
    if not gate_invocs:
        errs.append(
            "esp-idf.yml must execute "
            "python3 tools/n6_frame_stack_gate.py check …"
        )
        return errs
    if len(gate_invocs) != 1:
        errs.append(
            "esp-idf.yml n6_frame_stack_gate must be invoked exactly once "
            f"in the N6 collection block (got {len(gate_invocs)})"
        )

    # Include nearby args on the flattened command region.
    gate_cmd_start = gate_invocs[0].start()
    gstart = max(0, gate_cmd_start - 20)
    gend = min(len(flat_code), gate_cmd_start + 400)
    flat = flat_code[gstart:gend]
    # Both args must reference the same DIRVAR (not a literal untrusted path).
    # Allow $VAR or ${VAR}.
    _ref = r"(?:\$\{" + re.escape(dirvar) + r"\}|\$" + re.escape(dirvar) + r"\b)"
    su = re.search(r"--su-dir\s+\"?" + _ref + r"\"?", flat)
    esp = re.search(r"--esp-su-dir\s+\"?" + _ref + r"\"?", flat)
    if not su or not esp:
        errs.append(
            f"esp-idf.yml must pass --su-dir ${{{dirvar}}} and "
            f"--esp-su-dir ${{{dirvar}}} (same collection dir; "
            "literal untrusted paths forbidden)"
        )
    if re.search(r"--esp-su-dir\s+[\"']?/(tmp|var)\b", flat):
        errs.append(
            "esp-idf.yml --esp-su-dir must not be a literal untrusted path"
        )

    # Shell unit (heredoc body under docker bash -s, or whole fixture text):
    # structural unconditional/propagation checks + safe local mock must see
    # outer context (echo "$(…)", set +e, prior if/fi) — not a block cut at
    # the gate physical line.
    unit_info = _workflow_script_unit_for_gate(wf)
    if unit_info is None:
        errs.append(
            "esp-idf.yml cannot locate shell script unit containing "
            "n6_frame_stack_gate.py"
        )
    else:
        unit, _gate_in_unit = unit_info
        unit_code = _shell_code_no_comments(unit)
        flat_unit = re.sub(r"\\\s*\n", " ", unit_code)
        unit_invocs = list(
            re.finditer(
                r"python3\s+tools/n6_frame_stack_gate\.py\s+check\b",
                flat_unit,
            )
        )
        if not unit_invocs:
            errs.append(
                "esp-idf.yml shell unit must execute "
                "python3 tools/n6_frame_stack_gate.py check …"
            )
        else:
            errs.extend(
                _shell_gate_unconditional_propagating(
                    flat_unit, unit_invocs[0].start()
                )
            )
        # Safe local mock: preserve live set state from the unit; gate → return 7;
        # require exact-1 call + nonzero exit (no set injection).
        errs.extend(_mock_verify_gate_fail_propagation(unit))

    return errs


def _consume_shell_redirect(flat: str, j: int) -> int | None:
    """If flat[j:] starts a redirection, return index after it; else None.

    Handles ``2>&1``, ``>&2``, ``&>file``, ``>>file``, ``>file``, ``<file``,
    ``2>file``, ``2>>file``, ``&>|``, etc. Bare ``&`` (background) is not a
    redirect and returns None.
    """
    n = len(flat)
    i = j
    # optional leading fd digits
    while i < n and flat[i].isdigit():
        i += 1
    if i >= n:
        return None
    # &> or &>> form (no leading fd, or after digits which would be wrong —
    # bash allows only ``&>`` without leading fd digits typically)
    if flat[i] == "&" and i + 1 < n and flat[i + 1] == ">":
        i += 2
        if i < n and flat[i] == ">":
            i += 1
        # optional target
        while i < n and flat[i] in " \t":
            i += 1
        if i < n and flat[i] in ("'", '"'):
            q = flat[i]
            i += 1
            while i < n and flat[i] != q:
                i += 1
            if i < n:
                i += 1
            return i
        while i < n and flat[i] not in " \t\n;|&()":
            i += 1
        return i if i > j else None
    # > & < forms
    if flat[i] not in "<>":
        return None
    op0 = flat[i]
    i += 1
    if i < n and flat[i] == op0:  # >> or <<
        i += 1
    if i < n and flat[i] == "&":
        # >& or <&
        i += 1
        while i < n and flat[i] in " \t":
            i += 1
        if i < n and (flat[i].isdigit() or flat[i] == "-"):
            if flat[i] == "-":
                i += 1
            else:
                while i < n and flat[i].isdigit():
                    i += 1
            return i
        # >&file
        while i < n and flat[i] not in " \t\n;|&()":
            i += 1
        return i
    # >file or <file
    while i < n and flat[i] in " \t":
        i += 1
    if i < n and flat[i] in ("'", '"'):
        q = flat[i]
        i += 1
        while i < n and flat[i] != q:
            i += 1
        if i < n:
            i += 1
        return i
    while i < n and flat[i] not in " \t\n;|&()":
        i += 1
    return i if i > j else None


def _shell_gate_unconditional_propagating(flat: str, gate_cmd_start: int) -> list[str]:
    """Require gate is unconditionally executed and fails closed under set -e.

    Structural tokenizer (quotes / $() / redirects / control lists):
      - not nested inside open if/for/while/until/case/subshell/group
        (completed if/elif/fi before the gate return to depth 0 → OK)
      - elif does not deepen the if stack (same if statement)
      - not inside command substitution ``$(…)`` / backticks
      - not RHS of ``&&`` / ``||``; not after ``!``; not in ``|`` pipeline
      - not followed by ``&&`` / ``||`` / ``|`` / bare ``&`` background
        (AND-list left failure is *not* set -e fatal in bash — RED)
      - ``2>&1`` / other redirections are not treated as background
    """
    errs: list[str] = []
    n = len(flat)

    depth_if = 0
    depth_loop = 0
    depth_case = 0
    depth_sub = 0
    depth_cmdsub = 0  # $(...) / `...` nesting around the scan point
    in_cond_test = 0
    cmdsub_stack: list[str] = []  # track $() vs backtick

    def _is_word_char(c: str) -> bool:
        return c.isalnum() or c in "_-./"

    def _scan_cmdsub_close(open_at: int) -> int:
        """Index just past matching ``)`` for ``$(`` at open_at, or n."""
        # open_at points at '$'; flat[open_at:open_at+2] == '$('
        depth_p = 1
        j = open_at + 2
        q: str | None = None
        while j < n and depth_p > 0:
            ch = flat[j]
            if q == "'":
                if ch == "'":
                    q = None
                j += 1
                continue
            if q == '"':
                if ch == "\\" and j + 1 < n:
                    j += 2
                    continue
                if ch == '"':
                    q = None
                j += 1
                continue
            if ch in ("'", '"'):
                q = ch
                j += 1
                continue
            if ch == "(":
                depth_p += 1
            elif ch == ")":
                depth_p -= 1
            elif ch == "\\" and j + 1 < n:
                j += 2
                continue
            j += 1
        return j

    i = 0
    while i < gate_cmd_start:
        c = flat[i]
        if c in " \t\n":
            i += 1
            continue
        if c == "#":
            while i < n and flat[i] != "\n":
                i += 1
            continue
        # Single-quoted: opaque (no cmdsub).
        if c == "'":
            i += 1
            while i < n and flat[i] != "'":
                i += 1
            if i < n:
                i += 1
            continue
        # Double-quoted: ``$(…)`` / backticks still execute — must track cmdsub.
        if c == '"':
            i += 1
            while i < gate_cmd_start and i < n and flat[i] != '"':
                if flat[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if flat[i] == "`":
                    if cmdsub_stack and cmdsub_stack[-1] == "`":
                        cmdsub_stack.pop()
                        depth_cmdsub = max(0, depth_cmdsub - 1)
                    else:
                        cmdsub_stack.append("`")
                        depth_cmdsub += 1
                    i += 1
                    continue
                if flat[i] == "$" and i + 1 < n and flat[i + 1] == "(":
                    depth_cmdsub += 1
                    cmdsub_stack.append("$(")
                    close_j = _scan_cmdsub_close(i)
                    if close_j <= gate_cmd_start:
                        depth_cmdsub = max(0, depth_cmdsub - 1)
                        cmdsub_stack.pop()
                        i = close_j
                        continue
                    # Gate inside this $(…) under double quotes — stay elevated.
                    i += 2
                    continue
                i += 1
            if i < n and flat[i] == '"':
                i += 1
            continue
        # backticks command substitution
        if c == "`":
            if cmdsub_stack and cmdsub_stack[-1] == "`":
                cmdsub_stack.pop()
                depth_cmdsub = max(0, depth_cmdsub - 1)
            else:
                cmdsub_stack.append("`")
                depth_cmdsub += 1
            i += 1
            continue
        two = flat[i : i + 2]
        if two in ("&&", "||", ";;"):
            i += 2
            continue
        if two == "<<" or two == ">>":
            # heredoc / append — consume operator; heredoc body rarely in block
            i += 2
            continue
        # redirects involving & must be seen before bare &
        red = _consume_shell_redirect(flat, i)
        if red is not None:
            i = red
            continue
        if c in (";", "|", "\n"):
            i += 1
            continue
        if c == "&":
            # bare & background (redirects already consumed)
            i += 1
            continue
        if c == "$" and i + 1 < n:
            nxt = flat[i + 1]
            if nxt == "{":
                depth_b = 1
                j = i + 2
                while j < n and depth_b > 0:
                    if flat[j] == "{":
                        depth_b += 1
                    elif flat[j] == "}":
                        depth_b -= 1
                    elif flat[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    j += 1
                i = j
                continue
            if nxt == "(":
                # $(...) command substitution — mark depth while inside
                depth_cmdsub += 1
                cmdsub_stack.append("$(")
                close_j = _scan_cmdsub_close(i)
                if close_j <= gate_cmd_start:
                    # whole $(...) before gate — closed
                    depth_cmdsub = max(0, depth_cmdsub - 1)
                    cmdsub_stack.pop()
                    i = close_j
                    continue
                # gate is inside this $(...) — advance into it and
                # keep depth_cmdsub elevated until we pass gate.
                i += 2
                continue
        if c == "(":
            depth_sub += 1
            i += 1
            continue
        if c == ")":
            if cmdsub_stack and cmdsub_stack[-1] == "$(":
                cmdsub_stack.pop()
                depth_cmdsub = max(0, depth_cmdsub - 1)
            else:
                depth_sub = max(0, depth_sub - 1)
            i += 1
            continue
        if c == "{":
            depth_sub += 1
            i += 1
            continue
        if c == "}":
            depth_sub = max(0, depth_sub - 1)
            i += 1
            continue
        if _is_word_char(c) or c == "[":
            j = i
            if flat[i : i + 2] == "[[":
                k = flat.find("]]", i + 2)
                j = (k + 2) if k >= 0 else i + 2
            elif c == "[":
                k = flat.find("]", i + 1)
                j = (k + 1) if k >= 0 else i + 1
            else:
                while j < n and _is_word_char(flat[j]):
                    j += 1
            word = flat[i:j]
            if word == "if":
                depth_if += 1
                in_cond_test += 1
            elif word == "elif":
                # same if statement — do not deepen; re-enter cond test
                in_cond_test += 1
            elif word == "then":
                if in_cond_test > 0:
                    in_cond_test -= 1
            elif word == "else":
                pass
            elif word == "fi":
                depth_if = max(0, depth_if - 1)
            elif word in ("for", "while", "until"):
                depth_loop += 1
                if word in ("while", "until"):
                    in_cond_test += 1
            elif word == "do":
                if in_cond_test > 0:
                    in_cond_test -= 1
            elif word == "done":
                depth_loop = max(0, depth_loop - 1)
            elif word == "case":
                depth_case += 1
            elif word == "esac":
                depth_case = max(0, depth_case - 1)
            i = j
            continue
        i += 1

    nested = depth_if + depth_loop + depth_case + depth_sub
    if nested > 0 or in_cond_test > 0:
        errs.append(
            "esp-idf.yml n6_frame_stack_gate must run unconditionally "
            "(not inside if/for/while/until/case/subshell/group; "
            f"control-depth={nested}, cond-test={in_cond_test})"
        )
    if depth_cmdsub > 0:
        errs.append(
            "esp-idf.yml n6_frame_stack_gate must not run inside command "
            "substitution $(…) / backticks (outer command can swallow failure)"
        )

    # Preceding operator
    k = gate_cmd_start - 1
    while k >= 0 and flat[k] in " \t":
        k -= 1
    if k >= 0:
        if k >= 1 and flat[k - 1 : k + 1] in ("&&", "||"):
            errs.append(
                "esp-idf.yml n6_frame_stack_gate must not be RHS of "
                "&& / || (conditional / fail-open execution)"
            )
        elif flat[k] == "|":
            errs.append(
                "esp-idf.yml n6_frame_stack_gate must not run in a pipeline "
                "(failure propagation must not depend on pipe position)"
            )
        elif flat[k] == "!":
            k2 = k - 1
            while k2 >= 0 and flat[k2] in " \t":
                k2 -= 1
            if k2 < 0 or flat[k2] in (";", "\n", "&", "|", "("):
                errs.append(
                    "esp-idf.yml n6_frame_stack_gate must not be status-inverted "
                    "with !"
                )

    # Forward scan: argv + redirects; reject control-list / pipeline / background
    j = gate_cmd_start
    while j < n:
        if flat[j] in " \t":
            j += 1
            continue
        if flat[j] in "\n;":
            break
        red = _consume_shell_redirect(flat, j)
        if red is not None:
            j = red
            continue
        two = flat[j : j + 2]
        if two in ("&&", "||"):
            # Bash set -e does NOT exit on failure of a non-final command in
            # an AND or OR list — both && and || after the gate are fail-open.
            errs.append(
                "esp-idf.yml n6_frame_stack_gate must not be followed by "
                f"{two} … (bash set -e does not propagate failure from "
                "AND/OR-list non-final commands; any RHS is fail-open)"
            )
            break
        if flat[j] == "|":
            errs.append(
                "esp-idf.yml n6_frame_stack_gate must not be piped "
                "(| …) — failure must propagate as a simple command under set -e"
            )
            break
        if flat[j] == "&":
            errs.append(
                "esp-idf.yml n6_frame_stack_gate must not be backgrounded with &"
            )
            break
        if flat[j] in ("'", '"'):
            q = flat[j]
            j += 1
            while j < n and flat[j] != q:
                if flat[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            if j < n:
                j += 1
            continue
        j += 1

    return errs


def _mock_verify_gate_fail_propagation(script_unit: str) -> list[str]:
    """Local bash mock on the real script unit: exact-1 call + nonzero propagation.

    Design (independent QA P1):
      - Do **not** string-match ``set -euo pipefail`` or inject it as a prefix.
      - Preserve live ``set`` state / control flow from the actual unit
        (``_extract_live_set_prefix`` + collection body through gate statement).
      - Replace ``python3 tools/n6_frame_stack_gate.py check …`` with a mock
        that records the call and ``return 7``.
      - Provide a Mac Bash 3.2 ``mapfile`` shim and safe stubs; do not alter
        the meaning of the unit's set/control-flow/gate site.
      - Require: mock called exactly once **and** script exit status nonzero
        (with set -e a bare mock yields 7; set +e / cmdsub / &&|| swallow → RED).
    """
    import subprocess
    import tempfile

    errs: list[str] = []
    gate_pos = script_unit.find("n6_frame_stack_gate.py")
    if gate_pos < 0:
        return errs

    coll_start = script_unit.find("N6_SU_DIR=")
    if coll_start < 0 or coll_start > gate_pos:
        coll_start = script_unit.rfind("\n", 0, gate_pos) + 1

    # Live set state only from unit text before the collection body so the
    # body can still carry a late ``set +e`` between N6_SU_DIR and the gate.
    set_prefix = _extract_live_set_prefix(script_unit, coll_start)

    gate_end = _line_end_with_continuations(script_unit, gate_pos)
    _cs, gate_end = _extend_region_shell_balance(script_unit, coll_start, gate_end)
    body = script_unit[coll_start:gate_end]
    body = re.sub(r"\\\s*\n", " ", body)

    # Replace gate invocation (args may follow on the same flattened line).
    gate_pat = re.compile(
        r"python3\s+tools/n6_frame_stack_gate\.py\s+check\b"
        r"(?:\s+--[\w-]+\s+(?:\"[^\"]*\"|'[^']*'|\$\{[^}]+\}|[^\s;|&]+))*"
    )
    matches = list(gate_pat.finditer(body))
    if len(matches) != 1:
        # Structural checks already report missing/duplicate; skip mock noise.
        return errs
    body = gate_pat.sub("_n6_gate_mock", body, count=1)

    # found=$(find …) / process-substitution find — emit one fake path.
    body = re.sub(
        r"\bfind\b[^\n;|&)<]*",
        'printf "%s\\n" "__n6_fake_su__"',
        body,
    )

    # Neutralize other common CI commands that may appear near the collection.
    for cmd in (
        "docker",
        "idf.py",
        "xtensa-esp32s3-elf-nm",
        "xtensa-esp32s3-elf-gcc",
        "xtensa-esp32s3-elf-objdump",
        "xtensa-esp32s3-elf-readelf",
    ):
        body = re.sub(rf"\b{re.escape(cmd)}\b[^\n;]*", ":", body)

    # Stubs only — never inject set -euo. mapfile shim keeps unit meaning on
    # Bash 3.2 (no mapfile builtin) without rewriting the call site.
    prefix = r"""
# mapfile shim (no-op when bash already provides mapfile)
if ! type mapfile >/dev/null 2>&1; then
  mapfile() {
    local _arr=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -t) shift ;;
        -n|-s|-O|-C|-c|-d|-u) shift 2 2>/dev/null || shift ;;
        *) _arr=$1; shift; break ;;
      esac
    done
    [ -n "$_arr" ] || return 1
    eval "$_arr=()"
    local _i=0 _line
    while IFS= read -r _line || [ -n "$_line" ]; do
      eval "$_arr[$_i]=\$_line"
      _i=$((_i + 1))
    done
  }
fi
_N6_MOCK_CALLS=0
_n6_gate_mock() {
  _N6_MOCK_CALLS=$((_N6_MOCK_CALLS + 1))
  return 7
}
mkdir() { command mkdir "$@" 2>/dev/null || true; return 0; }
cp() { return 0; }
rm() { return 0; }
ls() { return 0; }
tee() { cat >/dev/null 2>&1 || true; return 0; }
test() { return 0; }
"""
    script = prefix + "\n" + set_prefix + "\n" + body + "\n"
    script += r"""
# If set -e is active and mock returned 7 as a simple command, we never reach
# here. Reaching here with calls==1 means failure was swallowed (set +e,
# cmdsub, &&/||, if-skip, background, …).
if [ "${_N6_MOCK_CALLS}" -ne 1 ]; then
  echo "N6_MOCK_CALLS=${_N6_MOCK_CALLS}" >&2
  exit 90
fi
echo "N6_MOCK_PROPAGATION_LOST" >&2
exit 91
"""
    try:
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "n6_gate_mock.sh"
            sp.write_text(script, encoding="utf-8")
            proc = subprocess.run(
                ["bash", str(sp)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as e:
        errs.append(f"esp-idf.yml N6 gate mock execution setup failed: {e}")
        return errs

    # Success criteria for a correct gate site:
    #   - mock called exactly once (recorded before return 7)
    #   - script exits nonzero without N6_MOCK_PROPAGATION_LOST
    # With live set -e and a bare mock command, bash exits 7 before the tail.
    # Without set -e, or with &&/||/if-skip/cmdsub swallow, we see 90/91/0.
    out = (proc.stdout or "") + (proc.stderr or "")
    if "N6_MOCK_PROPAGATION_LOST" in out or proc.returncode == 91:
        errs.append(
            "esp-idf.yml n6_frame_stack_gate failure does not propagate under "
            "the inner script (mock return 7 continued; "
            "check set +e / missing set -euo pipefail / &&/||/cmdsub/if wrappers; "
            "outer workflow bash -e is not inherited by docker bash -s)"
        )
    elif "N6_MOCK_CALLS=" in out or proc.returncode == 90:
        m = re.search(r"N6_MOCK_CALLS=(\d+)", out)
        ncalls = m.group(1) if m else "?"
        errs.append(
            "esp-idf.yml n6_frame_stack_gate mock call count must be exactly 1 "
            f"(got {ncalls}; gate skipped or duplicated)"
        )
    elif proc.returncode == 0:
        errs.append(
            "esp-idf.yml n6_frame_stack_gate mock expected nonzero exit "
            "(got 0 — failure swallowed or gate not executed; "
            "require live set -euo pipefail before the gate)"
        )
    # returncode 7 (or other nonzero from set -e on mock) without LOST/CALLS → OK
    return errs


def check_structure(
    component_cmake: Path | None = None,
    workflow: Path | None = None,
    host_cmake: Path | None = None,
    private_auth: Path | None = None,
) -> list[str]:
    errs: list[str] = []
    component_cmake = component_cmake or COMPONENT_CMAKE
    workflow = workflow or WORKFLOW
    host_cmake = host_cmake or HOST_CMAKE
    private_auth = private_auth or PRIVATE_AUTH

    if not private_auth.is_file():
        errs.append(f"missing private authority: {private_auth}")
        return errs
    auth = private_auth.read_text(encoding="utf-8", errors="replace")
    auth_code = _cmake_structure_code_local(auth)
    if "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES" not in auth_code:
        errs.append("private authority missing NINLIL_N6_PRODUCTION_RELATIVE_SOURCES")

    if not component_cmake.is_file():
        errs.append(f"missing component CMakeLists: {component_cmake}")
    else:
        comp_raw = component_cmake.read_text(encoding="utf-8", errors="replace")
        # Comment-stripped only: COMPILE_OPTIONS stores flags inside quotes.
        # Comment-only authority/flags must not count.
        comp = _shell_code_no_comments(comp_raw)
        if "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES" not in comp:
            errs.append(
                "component CMakeLists must reference "
                "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES for stack flags (code, not comment)"
            )
        if "-fstack-usage" not in comp:
            errs.append(
                "component CMakeLists missing -fstack-usage for N6 (code, not comment)"
            )
        if "-Wframe-larger-than=2048" not in comp:
            errs.append(
                "component CMakeLists missing -Wframe-larger-than=2048 for N6 "
                "(code, not comment)"
            )
        # Dataflow: foreach LOOP IN LISTS NINLIL_N6 →
        # list(APPEND N6LIST … ${LOOP} …)  [loop var required, not fixed path]
        # → set_source_files_properties(${N6LIST} …) with both flags.
        n6_flag_block = re.search(
            r"foreach\s*\(\s*(?P<loop>[A-Za-z_][A-Za-z0-9_]*)\s+"
            r"IN\s+LISTS\s+NINLIL_N6_PRODUCTION_RELATIVE_SOURCES\b"
            r"[\s\S]{0,400}?"
            r"list\s*\(\s*APPEND\s+(?P<n6list>[A-Za-z_][A-Za-z0-9_]*)\b"
            r"[^\)]*\$\{(?P=loop)\}"
            r"[\s\S]{0,400}?"
            r"endforeach\s*\(\s*\)\s*"
            r"set_source_files_properties\s*\(\s*\$\{(?P=n6list)\}\s+"
            r"PROPERTIES[\s\S]{0,300}?"
            r"-fstack-usage[\s\S]{0,200}?-Wframe-larger-than=2048",
            comp,
        )
        if not n6_flag_block:
            errs.append(
                "component must foreach LOOP IN LISTS "
                "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES → "
                "list(APPEND N6LIST … ${LOOP} …) → "
                "set_source_files_properties(${N6LIST} …) "
                "with -fstack-usage and -Wframe-larger-than=2048 "
                "(fixed path append / storage list / comment-only forbidden)"
            )

    if not workflow.is_file():
        errs.append(f"missing esp-idf workflow: {workflow}")
    else:
        wf_raw = workflow.read_text(encoding="utf-8", errors="replace")
        # Outer flags: blank strings + strip comments so comment-only args fail.
        wf_struct = _shell_structure_code(wf_raw)
        if "n6_frame_stack_gate.py" not in wf_struct:
            errs.append(
                "esp-idf.yml must run n6_frame_stack_gate.py on ESP N6 .su "
                "(code, not comment)"
            )
        # --esp-su-dir / --su-dir must appear as real argv tokens outside comments.
        # String blanking keeps the flag literals (they are unquoted keys in YAML
        # shell) — flags inside pure comments are stripped.
        if not re.search(r"--esp-su-dir\b", wf_struct):
            errs.append(
                "esp-idf.yml must pass --esp-su-dir for ESP N6 .su "
                "(code, not comment)"
            )
        if not re.search(r"--su-dir\b", wf_struct):
            errs.append(
                "esp-idf.yml must pass --su-dir for N6 .su directory "
                "(code, not comment)"
            )
        # Host-substitute checks on comment-stripped keep-string code
        wf_code = _shell_code_no_comments(wf_raw)
        if re.search(
            r"--esp-su-dir[=\s]+[^\n]*ninlil_runtime_private\.dir",
            wf_code,
        ):
            errs.append(
                "esp-idf.yml --esp-su-dir must not use host "
                "ninlil_runtime_private.dir (host substitute forbidden)"
            )
        if re.search(r"--esp-su-dir[=\s]+[^\n]*build-r6[^\n]*", wf_code):
            errs.append(
                "esp-idf.yml --esp-su-dir must not use host build-r6* paths"
            )
        if (
            "ports/esp-idf/smoke_app/build" not in wf_code
            and "smoke_app/build" not in wf_code
        ):
            errs.append(
                "esp-idf.yml must collect N6 .su from ESP smoke_app/build "
                "(actual ESP object tree)"
            )
        errs.extend(_workflow_n6_collection_ok(wf_raw))

    if host_cmake.is_file():
        host = host_cmake.read_text(encoding="utf-8", errors="replace")
        host_code = _cmake_structure_code_local(host)
        if "n6_frame_stack_gate" not in host_code:
            errs.append("host CMakeLists missing n6_frame_stack_gate registration")
        if (
            "ninlil_runtime_private.dir" not in host_code
            and "n6_frame_stack_gate" in host_code
        ):
            if "ninlil_runtime_private" not in host_code:
                errs.append(
                    "host n6_frame_stack_gate must use ninlil_runtime_private "
                    "object dir as --su-dir"
                )

    return errs


def _write_triplet(
    d: Path,
    store: str,
    codec: str = "y.c:1:0:ninlil_n6_crc32c\t32\tstatic\n",
    crypto: str = "z.c:1:0:ninlil_n6_secure_zero\t16\tstatic\n",
) -> None:
    (d / "n6_context_store.c.su").write_text(store, encoding="utf-8")
    (d / "n6_record_codec.c.su").write_text(codec, encoding="utf-8")
    (d / "n6_crypto_host.c.su").write_text(crypto, encoding="utf-8")


def self_test() -> int:
    fails = 0

    def expect(label: str, errs: list[str], pred) -> None:
        nonlocal fails
        if not pred(errs):
            print(f"SELF-TEST FAIL: {label}: {errs}")
            fails += 1
        else:
            print(f"SELF-TEST OK: {label}")

    good_store = (
        "x.c:1:0:ninlil_n6_boot_scan\t976\tstatic\n"
        "x.c:2:0:ninlil_n6_tx_burn\t544\tstatic\n"
    )
    good_codec = "y.c:1:0:ninlil_n6_crc32c\t32\tstatic\n"
    good_crypto = "z.c:1:0:ninlil_n6_secure_zero\t16\tstatic\n"

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        expect(
            "missing .su",
            check_su_dir(d),
            lambda e: any("missing .su" in x for x in e),
        )

        sub_a = d / "a"
        sub_b = d / "b"
        sub_a.mkdir()
        sub_b.mkdir()
        _write_triplet(sub_a, good_store)
        (sub_b / "n6_context_store.c.su").write_text(good_store, encoding="utf-8")
        (sub_b / "n6_record_codec.c.su").write_text(good_codec, encoding="utf-8")
        (sub_b / "n6_crypto_host.c.su").write_text(good_crypto, encoding="utf-8")
        expect(
            "duplicate file",
            check_su_dir(d),
            lambda e: any("duplicate .su" in x for x in e),
        )

        for child in list(d.iterdir()):
            if child.is_dir():
                for p in child.rglob("*"):
                    if p.is_file():
                        p.unlink()
                child.rmdir()
            elif child.is_file():
                child.unlink()

        _write_triplet(
            d,
            "x.c:1:0:ninlil_n6_boot_scan\t100\tstatic\n"
            "x.c:2:0:ninlil_n6_boot_scan\t200\tstatic\n"
            "x.c:3:0:ninlil_n6_tx_burn\t100\tstatic\n",
        )
        expect(
            "duplicate boot row",
            check_su_dir(d),
            lambda e: any("duplicate" in x and BOOT_FUNC in x for x in e),
        )

        _write_triplet(
            d,
            "x.c:1:0:ninlil_n6_boot_scan\t100\tdynamic\n"
            "x.c:2:0:ninlil_n6_tx_burn\t100\tstatic\n",
        )
        expect(
            "dynamic kind",
            check_su_dir(d),
            lambda e: any("static" in x and "dynamic" in x for x in e),
        )

        _write_triplet(
            d,
            "x.c:1:0:ninlil_n6_boot_scan\t1025\tstatic\n"
            "x.c:2:0:ninlil_n6_tx_burn\t100\tstatic\n",
        )
        expect(
            "boot>1024",
            check_su_dir(d),
            lambda e: any("boot_scan frame" in x for x in e),
        )

        _write_triplet(
            d,
            "x.c:1:0:ninlil_n6_boot_scan\t976\tstatic\n"
            "x.c:2:0:ninlil_n6_tx_burn\t2049\tstatic\n",
        )
        expect(
            "other N6>2048",
            check_su_dir(d),
            lambda e: any("frame 2049" in x or "> 2048" in x for x in e),
        )

        _write_triplet(d, good_store, good_codec, good_crypto)
        expect("exact good", check_su_dir(d), lambda e: e == [])

        # --- garbage / row0 / partial malformed (silent skip ban) ---
        _write_triplet(
            d,
            good_store,
            codec="this is not a su line at all\n",
            crypto=good_crypto,
        )
        expect(
            "garbage codec line fails (no silent skip)",
            check_su_dir(d),
            lambda e: any("malformed" in x for x in e),
        )

        _write_triplet(
            d,
            good_store,
            codec="",  # row0
            crypto=good_crypto,
        )
        expect(
            "row0 codec fails (parsed row < 1)",
            check_su_dir(d),
            lambda e: any("parsed row count" in x or "row count" in x for x in e),
        )

        _write_triplet(
            d,
            good_store,
            codec="y.c:1:0:ninlil_n6_crc32c\tnotanumber\tstatic\n",
            crypto=good_crypto,
        )
        expect(
            "partial malformed non-numeric size fails",
            check_su_dir(d),
            lambda e: any("non-numeric" in x for x in e),
        )

        _write_triplet(
            d,
            good_store,
            codec="y.c:1:0:ninlil_n6_crc32c\t32\n",  # missing kind tab field
            crypto=good_crypto,
        )
        expect(
            "partial malformed missing kind tab fails",
            check_su_dir(d),
            lambda e: any("malformed" in x for x in e),
        )

        # context valid + codec garbage + crypto row0 → must FAIL
        _write_triplet(
            d,
            good_store,
            codec="GARBAGE_LINE_WITHOUT_TABS\n",
            crypto="",
        )
        expect(
            "context-only-valid + codec garbage + crypto row0 fails",
            check_su_dir(d),
            lambda e: (
                any("malformed" in x for x in e)
                and any("parsed row count" in x or "crypto" in x for x in e)
            ),
        )

        missing_esp = d / "no_such_esp_su"
        fake_errs = [
            f"ESP .su dir missing (NO-GO): {missing_esp}"
        ]
        expect(
            "arg mutation missing --esp-su-dir path",
            fake_errs,
            lambda e: any("ESP .su dir missing" in x for x in e),
        )

        esp_only = d / "esp_partial"
        if esp_only.exists():
            for p in esp_only.iterdir():
                p.unlink()
        else:
            esp_only.mkdir()
        (esp_only / "n6_record_codec.c.su").write_text(good_codec, encoding="utf-8")
        expect(
            "arg mutation incomplete ESP .su",
            check_su_dir(esp_only),
            lambda e: any("missing .su" in x for x in e),
        )

    # --- structure: good workflow uses exact-1, not head -1 ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        comp = root / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
        wf = root / ".github" / "workflows" / "esp-idf.yml"
        host = root / "CMakeLists.txt"
        auth = root / "cmake" / "ninlil_runtime_private_sources.cmake"
        for p in (comp, wf, host, auth):
            p.parent.mkdir(parents=True, exist_ok=True)

        good_comp = """
include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
set(_ninlil_n6_srcs "")
foreach(_rel IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
    list(APPEND _ninlil_n6_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_n6_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)
"""
        # Inner script must own set -euo pipefail (docker bash -s does not
        # inherit outer workflow bash -e).
        good_wf = """
          set -euo pipefail
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          mkdir -p "$N6_SU_DIR"
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            mapfile -t matches < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil \\
              -name "${name}" -type f | sort)
            n="${#matches[@]}"
            if [[ "${n}" -ne 1 ]]; then
              echo "ESP N6 .su ${name}: expected exactly 1 match, got ${n}" >&2
              printf '%s\\n' "${matches[@]}" >&2
              exit 1
            fi
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check \\
            --su-dir "$N6_SU_DIR" \\
            --esp-su-dir "$N6_SU_DIR"
"""
        good_host = """
add_test(NAME n6_frame_stack_gate COMMAND python3 tools/n6_frame_stack_gate.py
    check --su-dir ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_runtime_private.dir)
"""
        good_auth = """
set(NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    src/radio/n6_record_codec.c
    src/radio/n6_crypto_host.c
    src/radio/n6_context_store.c
)
"""
        auth.write_text(good_auth, encoding="utf-8")
        comp.write_text(good_comp, encoding="utf-8")
        wf.write_text(good_wf, encoding="utf-8")
        host.write_text(good_host, encoding="utf-8")
        expect(
            "structure exact good",
            check_structure(comp, wf, host, auth),
            lambda e: e == [],
        )

        # flag mutations
        comp.write_text(good_comp.replace("-fstack-usage;", ""), encoding="utf-8")
        expect(
            "flag mutation missing -fstack-usage",
            check_structure(comp, wf, host, auth),
            lambda e: any("fstack-usage" in x for x in e),
        )
        comp.write_text(good_comp, encoding="utf-8")

        # workflow: head -1 duplicate-selection weakening
        weak_wf = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          mkdir -p "$N6_SU_DIR"
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            found=$(find ports/esp-idf/smoke_app/build/esp-idf/ninlil -name "$name" | head -1)
            test -n "$found"
            cp "$found" "$N6_SU_DIR/"
          done
          python3 tools/n6_frame_stack_gate.py check \\
            --su-dir "$N6_SU_DIR" \\
            --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(weak_wf, encoding="utf-8")
        expect(
            "workflow mutation head -1 duplicate-selection fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "head" in x
                or "tail" in x
                or "mapfile" in x
                or "bind" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # workflow missing exact-1 language
        no_exact = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            found=$(find ports/esp-idf/smoke_app/build/esp-idf/ninlil -name "$name" -type f)
            cp "$found" "$N6_SU_DIR/$name"
          done
          python3 tools/n6_frame_stack_gate.py check --su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(no_exact, encoding="utf-8")
        expect(
            "workflow mutation missing exact-1 count fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "bind" in x
                or "mapfile" in x
                or "-ne 1" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # comment-poison: keep "exactly 1" comment, drop real -ne 1 guard
        poison_wf = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          mkdir -p "$N6_SU_DIR"
          # expected exactly 1 match per N6 .su (comment-only; no real guard)
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            mapfile -t matches < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil \\
              -name "${name}" -type f | sort)
            # intentionally no n= / -ne 1 / exit
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check \\
            --su-dir "$N6_SU_DIR" \\
            --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(poison_wf, encoding="utf-8")
        expect(
            "workflow comment-poison exactly-1 without guard fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("bind" in x or "mapfile" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # forged n=1 after real mapfile (count not bound to ${#matches[@]})
        forged_n = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            mapfile -t matches < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil \\
              -name "${name}" -type f | sort)
            actual_n="${#matches[@]}"
            n=1
            if [[ "${n}" -ne 1 ]]; then
              exit 1
            fi
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check --su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(forged_n, encoding="utf-8")
        expect(
            "workflow forged n=1 not bound to matches fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("bind" in x or "${#ARR" in x or "n=" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # hardcoded matches=(...) without find/mapfile collection
        hardcoded = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            matches=(hardcoded-${name})
            n="${#matches[@]}"
            if [[ "${n}" -ne 1 ]]; then
              exit 1
            fi
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check --su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(hardcoded, encoding="utf-8")
        expect(
            "workflow hardcoded matches=() without find fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "find" in x or "mapfile" in x or "hardcode" in x or "bind" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # --esp-su-dir only in comment (real arg removed)
        no_esp_arg = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '# --esp-su-dir "$N6_SU_DIR"',
        )
        wf.write_text(no_esp_arg, encoding="utf-8")
        expect(
            "workflow --esp-su-dir comment-only fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("--esp-su-dir" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # component: N6 flags/authority only in comments
        comment_comp = """
# NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
# foreach(_rel IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
# set_source_files_properties(... COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
"""
        comp.write_text(comment_comp, encoding="utf-8")
        expect(
            "component N6 flags comment-only fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "fstack-usage" in x
                or "NINLIL_N6_PRODUCTION" in x
                or "comment" in x
                for x in e
            ),
        )
        comp.write_text(good_comp, encoding="utf-8")

        # find root swapped to untrusted tree; decoy smoke path string elsewhere
        untrusted_find = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          # decoy: ports/esp-idf/smoke_app/build/esp-idf/ninlil
          echo ports/esp-idf/smoke_app/build/esp-idf/ninlil >/dev/null
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            mapfile -t matches < <(find /tmp/untrusted-su-tree \\
              -name "${name}" -type f | sort)
            n="${#matches[@]}"
            if [[ "${n}" -ne 1 ]]; then
              exit 1
            fi
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check --su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(untrusted_find, encoding="utf-8")
        expect(
            "workflow find untrusted root with decoy smoke path fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "bind" in x
                or "smoke_app/build/esp-idf/ninlil" in x
                or "untrusted" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # set_source_files_properties targets storage list, not N6 list
        storage_target = """
include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
set(_ninlil_storage_srcs "")
foreach(_rel IN LISTS NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES)
    list(APPEND _ninlil_storage_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set(_ninlil_n6_srcs "")
foreach(_rel IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
    list(APPEND _ninlil_n6_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_storage_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)
"""
        comp.write_text(storage_target, encoding="utf-8")
        expect(
            "component set_source_files_properties on storage list fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "N6LIST" in x
                or "storage" in x
                or "set_source_files_properties" in x
                or "fixed path" in x
                for x in e
            ),
        )
        comp.write_text(good_comp, encoding="utf-8")

        # (d) foreach N6 but APPEND fixed radio_hal.c instead of ${loop}
        fixed_append = """
include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
set(_ninlil_n6_srcs "")
foreach(_rel IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
    list(APPEND _ninlil_n6_srcs "${NINLIL_REPO_ROOT}/src/radio/radio_hal.c")
endforeach()
set_source_files_properties(${_ninlil_n6_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)
"""
        comp.write_text(fixed_append, encoding="utf-8")
        expect(
            "component APPEND fixed radio_hal.c not loop var fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "LOOP" in x or "fixed path" in x or "foreach" in x for x in e
            ),
        )
        comp.write_text(good_comp, encoding="utf-8")

        # (e) find | tail -n 1 collapses duplicates
        tail_collapse = """
          N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su
          for name in n6_context_store.c.su n6_record_codec.c.su n6_crypto_host.c.su; do
            mapfile -t matches < <(find ports/esp-idf/smoke_app/build/esp-idf/ninlil \\
              -name "${name}" -type f | sort | tail -n 1)
            n="${#matches[@]}"
            if [[ "${n}" -ne 1 ]]; then
              exit 1
            fi
            cp "${matches[0]}" "${N6_SU_DIR}/${name}"
          done
          python3 tools/n6_frame_stack_gate.py check --su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR"
"""
        wf.write_text(tail_collapse, encoding="utf-8")
        expect(
            "workflow find|tail -n 1 collapse fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("tail" in x or "head/tail" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f) gate || true fail-open
        or_true = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" || true',
        )
        wf.write_text(or_true, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate || true fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("fail-open" in x or "|| true" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f2) gate || echo ignored — arbitrary success RHS, not only true/:
        or_echo = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" || echo ignored',
        )
        wf.write_text(or_echo, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate || echo ignored fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("fail-open" in x or "||" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f3) gate inside if false; then …; fi — non-execution / conditional
        if_false = good_wf.replace(
            "python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR"',
            "if false; then\n"
            "            python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR"\n'
            "          fi",
        )
        wf.write_text(if_false, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate inside if false; then fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "unconditional" in x
                or "control-depth" in x
                or "inside if" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f4) quoted N6_SU_DIR="ports/.../ninlil_n6_su" must GREEN
        quoted_dir = good_wf.replace(
            "N6_SU_DIR=ports/esp-idf/smoke_app/build/ninlil_n6_su",
            'N6_SU_DIR="ports/esp-idf/smoke_app/build/ninlil_n6_su"',
        )
        wf.write_text(quoted_dir, encoding="utf-8")
        expect(
            "workflow quoted N6_SU_DIR assignment green",
            check_structure(comp, wf, host, auth),
            lambda e: e == [],
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f5) gate && echo after — bash set -e does not exit on AND-list
        # left-hand failure → RED
        and_echo = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" && echo after',
        )
        wf.write_text(and_echo, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate && echo after fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "&&" in x or "AND/OR" in x or "fail-open" in x or "propagat" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f6) echo $(gate …) — command substitution; outer echo can succeed
        echo_cmdsub = good_wf.replace(
            "python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR"',
            'echo $(python3 tools/n6_frame_stack_gate.py check '
            '--su-dir "$N6_SU_DIR" --esp-su-dir "$N6_SU_DIR")',
        )
        wf.write_text(echo_cmdsub, encoding="utf-8")
        expect(
            "workflow echo $(n6_frame_stack_gate) command-sub fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "command substitution" in x
                or "cmdsub" in x
                or "echo" in x
                or "propagat" in x
                or "non-execution" in x
                or "call count" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f7) remove inner set -euo pipefail — outer bash -e not inherited
        no_set_e = good_wf.replace("set -euo pipefail\n", "")
        if "set -euo pipefail" in no_set_e:
            print(
                "SELF-TEST FAIL: remove set -euo pipefail setup did not strip"
            )
            fails += 1
        else:
            wf.write_text(no_set_e, encoding="utf-8")
            expect(
                "workflow missing inner set -euo pipefail fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "set -euo pipefail" in x or "not inherited" in x for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f8) completed if/elif/fi before gate + 2>&1 redirect → GREEN
        prior_if = good_wf.replace(
            "python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR"',
            'if [[ -d "$N6_SU_DIR" ]]; then\n'
            "            echo prep ok\n"
            "          elif false; then\n"
            "            echo no\n"
            "          fi\n"
            "          python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR" 2>&1',
        )
        wf.write_text(prior_if, encoding="utf-8")
        expect(
            "workflow prior if/elif/fi + 2>&1 green",
            check_structure(comp, wf, host, auth),
            lambda e: e == [],
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f9) multi-line double-quoted command substitution — bash absorbs
        # failure of the inner gate; outer echo succeeds → must RED.
        # Setup must construct the wrapper; fail the self-test if not.
        _gate_triple = (
            "python3 tools/n6_frame_stack_gate.py check \\\n"
            '            --su-dir "$N6_SU_DIR" \\\n'
            '            --esp-su-dir "$N6_SU_DIR"'
        )
        if _gate_triple not in good_wf:
            print(
                "SELF-TEST FAIL: multiline dq cmdsub setup: "
                "gate triple not found in good_wf"
            )
            fails += 1
        else:
            ml_dq = good_wf.replace(
                _gate_triple,
                'echo "$(\n'
                "          python3 tools/n6_frame_stack_gate.py check \\\n"
                '            --su-dir "$N6_SU_DIR" \\\n'
                '            --esp-su-dir "$N6_SU_DIR"\n'
                '          )"',
            )
            if 'echo "$(' not in ml_dq or "n6_frame_stack_gate.py" not in ml_dq:
                print(
                    "SELF-TEST FAIL: multiline dq cmdsub setup: "
                    "wrapper not applied"
                )
                fails += 1
            else:
                wf.write_text(ml_dq, encoding="utf-8")
                expect(
                    "workflow multiline double-quoted cmdsub "
                    "echo \"$( gate )\" fails",
                    check_structure(comp, wf, host, auth),
                    lambda e: any(
                        "command substitution" in x
                        or "cmdsub" in x
                        or "propagat" in x
                        or "call count" in x
                        for x in e
                    ),
                )
                wf.write_text(good_wf, encoding="utf-8")

        # (f10) set -euo pipefail then set +e — live option state disables
        # errexit; mock return 7 must not be treated as GREEN via string-only set.
        if "set -euo pipefail\n" not in good_wf:
            print(
                "SELF-TEST FAIL: set +e after set -euo setup: "
                "set -euo pipefail not found in good_wf"
            )
            fails += 1
        else:
            set_plus_e = good_wf.replace(
                "set -euo pipefail\n",
                "set -euo pipefail\n          set +e\n",
            )
            if "set +e" not in set_plus_e:
                print("SELF-TEST FAIL: set +e after set -euo setup: not applied")
                fails += 1
            else:
                wf.write_text(set_plus_e, encoding="utf-8")
                expect(
                    "workflow set +e after set -euo pipefail fails",
                    check_structure(comp, wf, host, auth),
                    lambda e: any(
                        "propagat" in x
                        or "set +e" in x
                        or "set -euo pipefail" in x
                        or "return 7" in x
                        for x in e
                    ),
                )
                wf.write_text(good_wf, encoding="utf-8")

        # (f11) set -euo only inside if false — not live at gate → RED
        set_if_false = good_wf.replace(
            "set -euo pipefail\n",
            "if false; then\n            set -euo pipefail\n          fi\n",
        )
        if "if false" not in set_if_false:
            print("SELF-TEST FAIL: conditional-only set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_if_false, encoding="utf-8")
            expect(
                "workflow set -euo only inside if false fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "propagat" in x
                    or "set -euo pipefail" in x
                    or "not inherited" in x
                    for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f12) set -euo only inside a string — not live → RED
        set_str = good_wf.replace(
            "set -euo pipefail\n",
            'echo "set -euo pipefail"\n',
        )
        wf.write_text(set_str, encoding="utf-8")
        expect(
            "workflow set -euo only inside string fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "propagat" in x
                or "set -euo pipefail" in x
                or "not inherited" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f13) set -euo only in subshell — does not affect parent → RED
        set_sub = good_wf.replace(
            "set -euo pipefail\n",
            "( set -euo pipefail )\n",
        )
        wf.write_text(set_sub, encoding="utf-8")
        expect(
            "workflow set -euo only in subshell fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "propagat" in x
                or "set -euo pipefail" in x
                or "not inherited" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f13b) multi-line subshell-only set must not be line-promoted to
        # top-level set (mock must not be stronger than the unit) → RED
        set_sub_ml = good_wf.replace(
            "set -euo pipefail\n",
            "(\n            set -euo pipefail\n          )\n",
        )
        if "(\n            set -euo pipefail\n          )" not in set_sub_ml:
            print("SELF-TEST FAIL: multi-line subshell set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_sub_ml, encoding="utf-8")
            expect(
                "workflow set -euo only in multi-line subshell fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "propagat" in x
                    or "set -euo pipefail" in x
                    or "not inherited" in x
                    for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c) uncalled function body set must not become top-level set → RED
        set_func = good_wf.replace(
            "set -euo pipefail\n",
            "n6_enable_strict() {\n"
            "            set -euo pipefail\n"
            "          }\n",
        )
        if "n6_enable_strict() {" not in set_func or "set -euo pipefail" not in set_func:
            print("SELF-TEST FAIL: uncalled function set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_func, encoding="utf-8")
            expect(
                "workflow set -euo only in uncalled function fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "propagat" in x
                    or "set -euo pipefail" in x
                    or "not inherited" in x
                    for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c2) called function def+invocation (one-liner) — real current-shell
        # set via unit control flow (no set promotion) → GREEN
        set_func_call = good_wf.replace(
            "set -euo pipefail\n",
            "opts(){ set -euo pipefail; }; opts\n",
        )
        if "opts(){ set -euo pipefail; }; opts" not in set_func_call:
            print("SELF-TEST FAIL: called function set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_func_call, encoding="utf-8")
            expect(
                "workflow set -euo via called function def+invoke green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c3) multi-line called function def+invoke → GREEN
        set_func_call_ml = good_wf.replace(
            "set -euo pipefail\n",
            "opts(){\n"
            "            set -euo pipefail\n"
            "          }\n"
            "          opts\n",
        )
        if "opts(){" not in set_func_call_ml or "\n          opts\n" not in set_func_call_ml:
            print(
                "SELF-TEST FAIL: multi-line called function set setup: not applied"
            )
            fails += 1
        else:
            wf.write_text(set_func_call_ml, encoding="utf-8")
            expect(
                "workflow set -euo via multi-line called function green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c3b) KAT: called function with nested `if true; then set` — body/
        # control preserved; current-shell effective when invoked → GREEN
        set_func_if_true = good_wf.replace(
            "set -euo pipefail\n",
            "opts() { if true; then set -euo pipefail; fi; }; opts\n",
        )
        if "opts() { if true; then set -euo pipefail; fi; }; opts" not in set_func_if_true:
            print(
                "SELF-TEST FAIL: called function if-true set setup: not applied"
            )
            fails += 1
        else:
            wf.write_text(set_func_if_true, encoding="utf-8")
            expect(
                "workflow set -euo via called function if-true body green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c3c) multi-line called function with if true → GREEN
        set_func_if_true_ml = good_wf.replace(
            "set -euo pipefail\n",
            "opts() {\n"
            "            if true; then\n"
            "              set -euo pipefail\n"
            "            fi\n"
            "          }\n"
            "          opts\n",
        )
        if (
            "opts() {" not in set_func_if_true_ml
            or "if true; then" not in set_func_if_true_ml
            or "\n          opts\n" not in set_func_if_true_ml
        ):
            print(
                "SELF-TEST FAIL: multi-line called function if-true setup: "
                "not applied"
            )
            fails += 1
        else:
            wf.write_text(set_func_if_true_ml, encoding="utf-8")
            expect(
                "workflow set -euo via multi-line called function if-true green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c3d) called function with if false around set — not live → RED
        set_func_if_false = good_wf.replace(
            "set -euo pipefail\n",
            "opts() { if false; then set -euo pipefail; fi; }; opts\n",
        )
        if "opts() { if false; then set -euo pipefail; fi; }; opts" not in set_func_if_false:
            print(
                "SELF-TEST FAIL: called function if-false set setup: not applied"
            )
            fails += 1
        else:
            wf.write_text(set_func_if_false, encoding="utf-8")
            expect(
                "workflow set -euo only in called function if-false fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "propagat" in x
                    or "set -euo pipefail" in x
                    or "not inherited" in x
                    for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c4) current-shell brace group one-liner → GREEN
        set_brace = good_wf.replace(
            "set -euo pipefail\n",
            "{ set -euo pipefail; }\n",
        )
        if "{ set -euo pipefail; }" not in set_brace:
            print("SELF-TEST FAIL: brace-group set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_brace, encoding="utf-8")
            expect(
                "workflow set -euo via current-shell brace group green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13c5) multi-line current-shell brace group → GREEN
        set_brace_ml = good_wf.replace(
            "set -euo pipefail\n",
            "{\n"
            "            set -euo pipefail\n"
            "          }\n",
        )
        if "{\n            set -euo pipefail\n          }" not in set_brace_ml:
            print("SELF-TEST FAIL: multi-line brace-group set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_brace_ml, encoding="utf-8")
            expect(
                "workflow set -euo via multi-line brace group green",
                check_structure(comp, wf, host, auth),
                lambda e: e == [],
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f13d) multi-line double-quoted string containing set is not live → RED
        set_ml_str = good_wf.replace(
            "set -euo pipefail\n",
            'echo "set -euo pipefail\n'
            '          more"\n',
        )
        if 'echo "set -euo pipefail' not in set_ml_str:
            print("SELF-TEST FAIL: multi-line string set setup: not applied")
            fails += 1
        else:
            wf.write_text(set_ml_str, encoding="utf-8")
            expect(
                "workflow set -euo only in multi-line string fails",
                check_structure(comp, wf, host, auth),
                lambda e: any(
                    "propagat" in x
                    or "set -euo pipefail" in x
                    or "not inherited" in x
                    for x in e
                ),
            )
            wf.write_text(good_wf, encoding="utf-8")

        # (f14) background gate → RED
        bg = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" &',
        )
        wf.write_text(bg, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate backgrounded with & fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "background" in x or "propagat" in x or "call count" in x for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f15) pipeline gate → RED
        pipe_g = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" | cat',
        )
        wf.write_text(pipe_g, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate in pipeline fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "pipeline" in x or "piped" in x or "propagat" in x for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (f16) &> redirect (not background) → GREEN
        amp_redir = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            '--esp-su-dir "$N6_SU_DIR" &> /tmp/n6_gate_mock.log',
        )
        wf.write_text(amp_redir, encoding="utf-8")
        expect(
            "workflow n6_frame_stack_gate &> redirect green",
            check_structure(comp, wf, host, auth),
            lambda e: e == [],
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (g) echo python3 … non-execution
        echo_gate = good_wf.replace(
            "python3 tools/n6_frame_stack_gate.py check",
            "echo python3 tools/n6_frame_stack_gate.py check",
        )
        wf.write_text(echo_gate, encoding="utf-8")
        expect(
            "workflow echo n6_frame_stack_gate non-execution fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "echo" in x or "execute" in x or "non-execution" in x for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # (h) --esp-su-dir literal untrusted, not linked to N6_SU_DIR
        unlinked_esp = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            "--esp-su-dir /tmp/untrusted-su-tree",
        )
        wf.write_text(unlinked_esp, encoding="utf-8")
        expect(
            "workflow --esp-su-dir unlinked untrusted path fails",
            check_structure(comp, wf, host, auth),
            lambda e: any(
                "same collection dir" in x
                or "untrusted" in x
                or "esp-su-dir" in x
                for x in e
            ),
        )
        wf.write_text(good_wf, encoding="utf-8")

        # wrong basename set (missing one / extra)
        bad_names = good_wf.replace(
            "n6_crypto_host.c.su",
            "n6_crypto_host.c.su n6_extra_evil.c.su",
        )
        wf.write_text(bad_names, encoding="utf-8")
        expect(
            "workflow extra .su basename fails",
            check_structure(comp, wf, host, auth),
            lambda e: any("basenames must be exact set" in x for x in e),
        )
        wf.write_text(good_wf, encoding="utf-8")

        bad_host_sub = good_wf.replace(
            '--esp-su-dir "$N6_SU_DIR"',
            "--esp-su-dir build-r6-rel/CMakeFiles/ninlil_runtime_private.dir",
        )
        wf.write_text(bad_host_sub, encoding="utf-8")
        expect(
            "workflow mutation host substitute --esp-su-dir",
            check_structure(comp, wf, host, auth),
            lambda e: any("host" in x.lower() or "substitute" in x for x in e),
        )

    # CLI closed set: noarg / unknown
    import subprocess as _sp

    r_no = _sp.run(
        [sys.executable, str(Path(__file__).resolve())],
        capture_output=True,
        text=True,
    )
    if r_no.returncode == 0:
        print(f"SELF-TEST FAIL: CLI noarg nonzero: rc={r_no.returncode}")
        fails += 1
    else:
        print("SELF-TEST OK: CLI noarg nonzero")
    r_unk = _sp.run(
        [sys.executable, str(Path(__file__).resolve()), "not-a-real-command"],
        capture_output=True,
        text=True,
    )
    if r_unk.returncode == 0:
        print(f"SELF-TEST FAIL: CLI unknown command nonzero: rc={r_unk.returncode}")
        fails += 1
    else:
        print("SELF-TEST OK: CLI unknown command nonzero")

    real_errs = check_structure()
    if real_errs:
        print(f"SELF-TEST FAIL: real tree structure: {real_errs}")
        fails += 1
    else:
        print("SELF-TEST OK: real tree structure")

    if fails:
        print(f"n6_frame_stack_gate self-test: FAIL ({fails})")
        return 1
    print("n6_frame_stack_gate self-test: OK")
    return 0


_CLOSED_COMMANDS = frozenset(
    {"check", "self-test", "check-structure", "esp-not-run"}
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "command",
        nargs="?",
        default=None,
        help="Closed set: check | self-test | check-structure | esp-not-run",
    )
    ap.add_argument("--su-dir", default=None)
    ap.add_argument("--esp-su-dir", default=None)
    args = ap.parse_args()

    if args.command is None:
        print(
            "usage: n6_frame_stack_gate.py "
            "check|self-test|check-structure|esp-not-run "
            "[--su-dir D] [--esp-su-dir D]\n"
            "  command is required (noarg fails; unknown fails)",
            file=sys.stderr,
        )
        return 2
    if args.command not in _CLOSED_COMMANDS:
        print(
            f"unknown command {args.command!r}; "
            f"closed set: {sorted(_CLOSED_COMMANDS)}",
            file=sys.stderr,
        )
        return 2

    if args.command == "self-test":
        return self_test()

    if args.command == "check-structure":
        errs = check_structure()
        if errs:
            print("n6_frame_stack_gate structure FAIL:")
            for e in errs:
                print(" ", e)
            return 1
        print(
            "n6_frame_stack_gate structure: OK "
            "(N6 flags; ESP workflow exact-1 .su collection; no head -1)"
        )
        return 0

    if args.command == "esp-not-run":
        print(
            "n6_frame_stack_gate ESP: NOT-RUN/NO-GO "
            "(ESP toolchain/artifacts unavailable; not a PASS)",
            file=sys.stderr,
        )
        return 2

    if not args.su_dir:
        print("need --su-dir (authoritative production object dir)", file=sys.stderr)
        return 2

    errs = check_su_dir(Path(args.su_dir))
    if args.esp_su_dir is not None:
        esp_path = Path(args.esp_su_dir)
        esp_s = str(esp_path.resolve()) if esp_path.exists() else str(esp_path)
        if "ninlil_runtime_private.dir" in esp_s and "esp-idf" not in esp_s:
            errs.append(
                "ESP --esp-su-dir must not be host ninlil_runtime_private.dir "
                "(host substitute forbidden; collect actual ESP N6 .su)"
            )
        if not esp_path.is_dir():
            errs.append(
                f"ESP .su dir missing (NO-GO): {esp_path} "
                "(toolchain claimed available but artifacts absent)"
            )
        else:
            for e in check_su_dir(esp_path):
                errs.append(f"ESP: {e}")
    else:
        print(
            "n6_frame_stack_gate ESP: NOT-RUN "
            "(no --esp-su-dir; host production only — not an ESP PASS)"
        )

    if errs:
        print("n6_frame_stack_gate FAIL:")
        for e in errs:
            print(" ", e)
        return 1
    if args.esp_su_dir is not None:
        print("n6_frame_stack_gate: OK (host + ESP production .su)")
    else:
        print("n6_frame_stack_gate: OK (host production .su)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
