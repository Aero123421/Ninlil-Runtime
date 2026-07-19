#!/usr/bin/env python3
"""N6 GCC 13 Release compile-command authority gate (host production).

check --src-root ROOT --compile-commands PATH [--verbose-log PATH]

Authority selects production TUs only when output is the exact path:
  <compile_commands build root>/CMakeFiles/ninlil_runtime_private.dir/src/radio/<base>.o
  (suffix-only / external-prefix absolute paths are RED, not production)

compile_commands.json path and its parent build directory:
  raw ``..`` forbidden; every path component lstat'd; symlinks RED;
  build directory is the sole authority base for entry.directory.

entry.directory (production candidates):
  raw ``..`` forbidden; full-component lstat; symlinks RED;
  relative forms bind only under the compile_commands parent build dir
  (never cwd / src_root guess); canonical directory must equal that build dir.

entry.file / argv -c / entry.output / argv -o:
  raw ``..`` components are RED before any resolve;
  source / -c: every path component is lstat'd; symlinks are RED;
  source must bind to exact src_root/<rel> (regular non-symlink file);
  relative -c/-o use only the verified entry.directory;
  -c exact-one; -o exact-one; entry.output ≡ argv -o (identity).

Outputs (production authority vs exact testbuild out-of-authority):
  raw ``..`` RED; entry.output / argv -o disagreement RED;
  every *existing* path component is lstat'd — symlinks RED even on
  testbuild prefixes; missing components after a clean prefix are allowed
  only long enough to classify exact ``build_root`` testbuild and ignore it
  (CI may compile production-only while compile_commands still lists
  ``ninlil_n6_store_testbuild``). Exact production outputs remain fail-closed:
  all components must exist and be non-symlink. Suffix-only / external-prefix
  absolute paths stay ``ambiguous`` RED (never silent testbuild skip).

Compiler: argv0 basename gcc-13, or argv0 in {ccache,sccache} + argv1 gcc-13.
All -O* tokens must be exactly ['-O2']. Required flags include -Wall -Wextra
-Wpedantic -pedantic-errors -DNDEBUG plus frame flags. No -Wno-*.

Optional --verbose-log: Ninja ``[n/m] `` prefix only is stripped; each production
TU must appear as exactly one fully-parsed compile command; same flag/source/-c/-o
rules as compile_commands (no substring fallback). Relative -c/-o in the log use
the verified production entry.directory only.

self-test: synthetic false-greens. PASS ≠ product GO.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat as stmod
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

N6_SRC: tuple[str, ...] = (
    "src/radio/n6_context_store.c",
    "src/radio/n6_record_codec.c",
    "src/radio/n6_crypto_host.c",
)

REQUIRED_FLAGS: tuple[str, ...] = (
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-pedantic-errors",
    "-DNDEBUG",
    "-Werror",
    "-Wvla",
    "-fstack-usage",
    "-Wframe-larger-than=2048",
    "-maccumulate-outgoing-args",
)

PROD_DIR_MARKER = "CMakeFiles/ninlil_runtime_private.dir/src/radio/"
TESTBUILD_DIR_MARKER = "CMakeFiles/ninlil_n6_store_testbuild.dir/src/radio/"
ALLOWED_WRAPPERS = frozenset({"ccache", "sccache"})

# Strict Ninja status prefix only: "[12/345] " (no other decorations).
_RE_NINJA_PREFIX = re.compile(r"^\[\d+/\d+\]\s+")


def _raw_has_dotdot(path_str: str) -> bool:
    """True if any path component is ``..`` (before resolve)."""
    if not isinstance(path_str, str) or not path_str:
        return False
    # Normalize separators for component scan only; do not resolve.
    norm = path_str.replace("\\", "/")
    return ".." in norm.split("/")


def _lstat_walk_parts(
    start: Path, parts: Sequence[str], *, where: str
) -> tuple[Path | None, str | None]:
    """Walk start/parts with lstat; reject symlink/missing on every component."""
    leaf, err, complete = _lstat_walk_parts_allow_missing(
        start, parts, where=where
    )
    if err is not None:
        return None, err
    if not complete:
        # Preserve historical fail-closed wording for full-existence walks.
        return None, f"{where}: missing path component: {leaf}"
    return leaf, None


def _lstat_walk_parts_allow_missing(
    start: Path, parts: Sequence[str], *, where: str
) -> tuple[Path | None, str | None, bool]:
    """Walk start/parts with lstat on every existing component.

    Symlink / ``..`` / non-ENOENT lstat errors are hard RED.
    When a component is missing, remaining parts are joined without requiring
    existence and ``complete=False`` is returned so callers may classify exact
    testbuild-out-of-authority paths that CI has not materialized yet.
    Existing prefix components remain fail-closed (symlink RED).
    Returns (path, err, complete).
    """
    cur = start
    try:
        st0 = os.lstat(cur)
    except OSError as e:
        return None, f"{where}: lstat start failed: {e}", False
    if stmod.S_ISLNK(st0.st_mode):
        return None, f"{where}: symlink forbidden at start: {cur}", False
    missing = False
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None, f"{where}: path traversal forbidden", False
        if missing:
            cur = cur / part
            continue
        nxt = cur / part
        try:
            st = os.lstat(nxt)
        except FileNotFoundError:
            missing = True
            cur = nxt
            continue
        except OSError as e:
            return None, f"{where}: lstat failed: {e}", False
        if stmod.S_ISLNK(st.st_mode):
            return None, f"{where}: symlink forbidden: {nxt}", False
        cur = nxt
    return cur, None, not missing


def _bind_path_under(
    base: Path, path_str: str, *, where: str, require_regular_leaf: bool
) -> tuple[Path | None, str | None]:
    """Bind path_str relative to base or absolute, no ``..``, no symlink.

    Returns the non-followed leaf Path (lstat-walked). Caller may compare
    resolve() results for identity when needed.
    """
    leaf, err, complete = _bind_path_under_allow_missing(
        base, path_str, where=where
    )
    if err is not None:
        return None, err
    if not complete:
        return None, f"{where}: missing path component: {leaf}"
    assert leaf is not None

    if require_regular_leaf:
        try:
            st = os.lstat(leaf)
        except OSError as e:
            return None, f"{where}: leaf lstat failed: {e}"
        if not stmod.S_ISREG(st.st_mode):
            return None, f"{where}: not a regular file: {leaf}"
        if stmod.S_ISLNK(st.st_mode):
            return None, f"{where}: leaf is symlink: {leaf}"
    return leaf, None


def _bind_path_under_allow_missing(
    base: Path, path_str: str, *, where: str
) -> tuple[Path | None, str | None, bool]:
    """Bind path_str relative to base or absolute; allow trailing missing comps.

    Existing components: full lstat, symlink RED. Missing trailing components
    yield complete=False with the intended joined Path for classification.
    """
    if not isinstance(path_str, str) or not path_str.strip():
        return None, f"{where}: empty path", False
    if _raw_has_dotdot(path_str):
        return None, f"{where}: raw path traversal (..): {path_str!r}", False
    if _raw_has_dotdot(str(base)):
        return None, f"{where}: base path traversal: {base}", False

    p = Path(path_str)
    if p.is_absolute():
        parts = p.parts
        anchor = Path(parts[0])
        return _lstat_walk_parts_allow_missing(anchor, parts[1:], where=where)
    return _lstat_walk_parts_allow_missing(
        base, Path(path_str).parts, where=where
    )


def _bind_output_path(
    path_str: str,
    *,
    rel_base: Path | None,
    where: str,
) -> tuple[Path | None, str | None, bool]:
    """Bind entry.output / argv -o for classify-then-authority.

    Absolute from FS root; relative only from rel_base (never cwd guess).
    complete=False means a clean existing prefix had a missing component —
    exact build_root testbuild may still be ignored; production may not.
    """
    if not isinstance(path_str, str) or not path_str.strip():
        return None, f"{where}: empty path", False
    if Path(path_str).is_absolute():
        return _bind_path_under_allow_missing(
            Path(Path(path_str).anchor), path_str, where=where
        )
    if rel_base is None:
        return None, f"{where}: relative path without bound base", False
    return _bind_path_under_allow_missing(rel_base, path_str, where=where)


def _canon_identity(path: Path) -> Path:
    """realpath after non-symlink walk already done on the path."""
    return Path(os.path.realpath(path))


def _bind_abs_or_rel(
    path_str: str,
    *,
    rel_base: Path | None,
    where: str,
    require_regular_leaf: bool,
) -> tuple[Path | None, str | None]:
    """Bind absolute from FS root, or relative only from rel_base (never cwd guess)."""
    if not isinstance(path_str, str) or not path_str.strip():
        return None, f"{where}: empty path"
    if Path(path_str).is_absolute():
        return _bind_path_under(
            Path(Path(path_str).anchor),
            path_str,
            where=where,
            require_regular_leaf=require_regular_leaf,
        )
    if rel_base is None:
        return None, f"{where}: relative path without bound base"
    return _bind_path_under(
        rel_base,
        path_str,
        where=where,
        require_regular_leaf=require_regular_leaf,
    )


def _tokenize_command(entry: dict[str, Any]) -> list[str]:
    if "arguments" in entry and entry["arguments"] is not None:
        args = entry["arguments"]
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("arguments must be a list of strings")
        return list(args)
    cmd = entry.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("entry missing command/arguments")
    return shlex.split(cmd, posix=True)


def _outputs_from_argv(argv: Sequence[str]) -> list[str]:
    outs: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "-o":
            if i + 1 >= len(argv):
                raise ValueError("dangling -o")
            outs.append(argv[i + 1])
            i += 2
            continue
        if tok.startswith("-o") and len(tok) > 2:
            outs.append(tok[2:])
        i += 1
    return outs


def _c_operands(argv: Sequence[str]) -> list[str]:
    ops: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "-c":
            if i + 1 >= len(argv):
                raise ValueError("dangling -c")
            ops.append(argv[i + 1])
            i += 2
            continue
        i += 1
    return ops


def _classify_output(out_canon: Path, leaf_o: str, *, build_root: Path) -> str:
    """Classify already-validated output by exact path under build_root.

    Production and testbuild require full identity with
    ``build_root / <marker><leaf>.o``. Suffix-only matches (e.g. absolute
    ``/evil/CMakeFiles/ninlil_runtime_private.dir/src/radio/<leaf>.o`` while
    compile_commands build root is legitimate) are ``ambiguous``, never
    production/testbuild — closes external-prefix false-GREEN.
    """
    if ".." in out_canon.parts:
        return "traversal"
    expected_prod = build_root / (PROD_DIR_MARKER + leaf_o)
    expected_test = build_root / (TESTBUILD_DIR_MARKER + leaf_o)
    if out_canon == expected_prod:
        return "production"
    if out_canon == expected_test:
        return "testbuild"
    return "ambiguous"


def _is_gcc13(argv: Sequence[str]) -> bool:
    if not argv:
        return False
    b0 = Path(argv[0]).name
    if b0 == "gcc-13":
        return True
    if b0 in ALLOWED_WRAPPERS and len(argv) >= 2 and Path(argv[1]).name == "gcc-13":
        return True
    return False


def check_argv_flags(rel: str, argv: Sequence[str]) -> list[str]:
    errs: list[str] = []
    if not argv:
        return [f"{rel}: empty compile argv"]
    if not _is_gcc13(argv):
        errs.append(
            f"{rel}: compiler must be argv0=gcc-13 or "
            f"argv0 in {{ccache,sccache}}+argv1=gcc-13 "
            f"(got argv0={argv[0]!r}"
            f"{(', argv1=' + repr(argv[1])) if len(argv) > 1 else ''})"
        )
    tokens = list(argv)
    token_set = set(tokens)
    opt_tokens = [t for t in tokens if t.startswith("-O")]
    if opt_tokens != ["-O2"]:
        errs.append(
            f"{rel}: optimisation tokens must be exactly ['-O2'], "
            f"found {opt_tokens!r}"
        )
    for flag in REQUIRED_FLAGS:
        if flag not in token_set:
            errs.append(f"{rel}: missing required flag {flag}")
    wno = sorted({t for t in tokens if t.startswith("-Wno-")})
    if wno:
        errs.append(f"{rel}: warning suppression forbidden: {', '.join(wno)}")
    return errs


def _bind_src_root_file(src_root: Path, rel: str) -> tuple[Path | None, str | None]:
    """src_root + rel: full component lstat, regular leaf, return realpath identity."""
    if _raw_has_dotdot(rel):
        return None, f"{rel}: src path traversal"
    leaf, err = _bind_path_under(
        src_root, rel, where=rel, require_regular_leaf=True
    )
    if err is not None:
        return None, err
    assert leaf is not None
    try:
        return _canon_identity(leaf), None
    except OSError as e:
        return None, f"{rel}: resolve failed: {e}"


def _bind_directory_path(
    path_str: str, *, base_for_relative: Path | None, where: str
) -> tuple[Path | None, str | None]:
    """Bind a directory path: no raw ``..``, no symlink components, leaf is dir.

    Absolute paths walk from FS root. Relative paths require base_for_relative
    and walk from that base only (never cwd / src_root guess).
    Returns canonical path of the verified directory.
    """
    if not isinstance(path_str, str) or not path_str.strip():
        return None, f"{where}: empty directory"
    if _raw_has_dotdot(path_str):
        return None, f"{where}: raw path traversal (..): {path_str!r}"
    leaf, err = _bind_abs_or_rel(
        path_str,
        rel_base=base_for_relative,
        where=where,
        require_regular_leaf=False,
    )
    if err is not None or leaf is None:
        return None, err or f"{where}: directory bind failed"
    try:
        st = os.lstat(leaf)
    except OSError as e:
        return None, f"{where}: lstat failed: {e}"
    if stmod.S_ISLNK(st.st_mode):
        return None, f"{where}: symlink forbidden: {leaf}"
    if not stmod.S_ISDIR(st.st_mode):
        return None, f"{where}: not a directory: {leaf}"
    try:
        return _canon_identity(leaf), None
    except OSError as e:
        return None, f"{where}: resolve failed: {e}"


def _bind_compile_commands_and_build(
    path: Path,
) -> tuple[Path | None, Path | None, str | None]:
    """Bind compile_commands.json and its parent build directory.

    compile_commands path: raw ``..`` forbidden; every component lstat'd;
    leaf must be a regular non-symlink file.
    Parent build directory: same walk rules; leaf must be a directory;
    returned as canonical path. Relative CLI paths bind from cwd only
    (after cwd itself is non-symlink-checked) — never from src_root.
    Returns (cc_leaf, build_dir_canon, err).
    """
    path_str = os.fspath(path)
    if not isinstance(path_str, str) or not path_str.strip():
        return None, None, "compile_commands: empty path"
    if _raw_has_dotdot(path_str):
        return None, None, f"compile_commands: raw path traversal (..): {path_str!r}"

    p = Path(path_str)
    if p.is_absolute():
        cc_leaf, err = _bind_abs_or_rel(
            path_str,
            rel_base=None,
            where="compile_commands",
            require_regular_leaf=True,
        )
    else:
        try:
            cwd = Path(os.getcwd())
        except OSError as e:
            return None, None, f"compile_commands: cwd unavailable: {e}"
        if _raw_has_dotdot(str(cwd)):
            return None, None, f"compile_commands: cwd has raw ..: {cwd}"
        try:
            st_cwd = os.lstat(cwd)
        except OSError as e:
            return None, None, f"compile_commands: cwd lstat failed: {e}"
        if stmod.S_ISLNK(st_cwd.st_mode):
            return None, None, f"compile_commands: cwd is symlink: {cwd}"
        # Relative CLI path: bind only from non-symlink cwd (never src_root).
        cc_leaf, err = _bind_abs_or_rel(
            path_str,
            rel_base=cwd,
            where="compile_commands",
            require_regular_leaf=True,
        )
    if err is not None or cc_leaf is None:
        return None, None, err or "compile_commands: bind failed"

    # Parent was intermediate-lstat'd while walking to the file; re-bind as dir
    # via absolute walk so the build root is independently authority-checked.
    parent = cc_leaf.parent
    parent_str = os.fspath(parent)
    if _raw_has_dotdot(parent_str):
        return None, None, f"compile_commands build root raw ..: {parent_str!r}"
    if not Path(parent_str).is_absolute():
        # Should not happen after absolute/cwd-relative bind; refuse ambiguous.
        return None, None, f"compile_commands build root not absolute: {parent_str}"
    build_dir, berr = _bind_directory_path(
        parent_str,
        base_for_relative=None,
        where="compile_commands build root (parent)",
    )
    if berr is not None or build_dir is None:
        return None, None, berr or "compile_commands build root bind failed"
    return cc_leaf, build_dir, None


def check_compile_commands(
    path: Path, *, src_root: Path, verbose_log: Path | None = None
) -> list[str]:
    errs: list[str] = []
    # Bind src_root itself (no symlink root).
    try:
        if src_root.is_symlink():
            return [f"src_root is a symlink: {src_root}"]
        src_root = Path(os.path.realpath(src_root))
    except OSError as e:
        return [f"src_root resolve failed: {e}"]

    # Authority: compile_commands itself + parent build root (no symlink / ..).
    cc_leaf, build_root, berr = _bind_compile_commands_and_build(path)
    if berr is not None or cc_leaf is None or build_root is None:
        return [berr or "compile_commands build root bind failed"]
    try:
        data = json.loads(cc_leaf.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return [f"compile_commands load failed: {e}"]
    if not isinstance(data, list):
        return ["compile_commands must be a JSON array"]

    expected_files: dict[str, Path] = {}
    for rel in N6_SRC:
        fp, ferr = _bind_src_root_file(src_root, rel)
        if ferr is not None or fp is None:
            errs.append(ferr or f"{rel}: bind failed")
            continue
        expected_files[rel] = fp

    # rel -> production (argv, out_canon, entry_directory_canon==build_root)
    # directory is verified exact-match to compile_commands parent build root.
    prod: dict[str, list[tuple[list[str], Path, Path]]] = {
        rel: [] for rel in N6_SRC
    }

    for entry in data:
        if not isinstance(entry, dict):
            errs.append("compile_commands entry not object")
            continue
        file_field = entry.get("file")
        directory = entry.get("directory")
        if not isinstance(file_field, str) or not isinstance(directory, str):
            continue

        # Bind file first enough to know if this is an N6 production candidate
        # (absolute or relative-to-bound-dir after directory check).
        # Directory is mandatory authority for any N6 match.

        # --- entry.directory: bind + exact build_root match (always for N6) ---
        dir_err: str | None = None
        dir_canon: Path | None = None
        if _raw_has_dotdot(directory):
            dir_err = f"entry.directory raw path traversal (..): {directory!r}"
        else:
            dir_canon, derr = _bind_directory_path(
                directory,
                base_for_relative=build_root,  # relative dirs only vs build root
                where="entry.directory",
            )
            if derr is not None or dir_canon is None:
                dir_err = derr or "entry.directory bind failed"
            elif dir_canon != build_root:
                dir_err = (
                    f"entry.directory canonical mismatch: {dir_canon} "
                    f"!= compile_commands build root {build_root}"
                )

        # Bind file field (absolute preferred for matching expected sources).
        if _raw_has_dotdot(file_field):
            for rel in expected_files:
                if Path(file_field).name == Path(rel).name:
                    errs.append(
                        f"{rel}: raw file path traversal (..): {file_field!r}"
                    )
                    if dir_err is not None:
                        errs.append(f"{rel}: {dir_err}")
            continue

        # Relative file requires a valid directory base; absolute may still match.
        if Path(file_field).is_absolute():
            file_leaf, ferr = _bind_abs_or_rel(
                file_field,
                rel_base=None,
                where="entry.file",
                require_regular_leaf=True,
            )
        elif dir_canon is not None and dir_err is None:
            file_leaf, ferr = _bind_abs_or_rel(
                file_field,
                rel_base=dir_canon,
                where="entry.file",
                require_regular_leaf=True,
            )
        else:
            file_leaf, ferr = None, "entry.file relative without valid entry.directory"
        if ferr is not None or file_leaf is None:
            for rel in N6_SRC:
                if Path(file_field).name == Path(rel).name:
                    if ferr:
                        errs.append(f"{rel}: {ferr}")
                    if dir_err is not None:
                        errs.append(f"{rel}: {dir_err}")
            continue
        try:
            file_canon = _canon_identity(file_leaf)
        except OSError:
            continue
        matched_rel: str | None = None
        for rel, exp in expected_files.items():
            if file_canon == exp:
                matched_rel = rel
                break
        if matched_rel is None:
            continue  # not one of our exact sources

        # N6 match: directory MUST bind exact to build_root (absolute file/-c/-o
        # cannot greenwash a swapped/traversal/symlink directory).
        if dir_err is not None or dir_canon is None:
            errs.append(
                f"{matched_rel}: {dir_err or 'entry.directory unbound'}"
            )
            continue

        try:
            argv = _tokenize_command(entry)
        except ValueError as e:
            errs.append(f"{matched_rel}: {e}")
            continue
        # -c exact-one + same source
        try:
            cops = _c_operands(argv)
        except ValueError as e:
            errs.append(f"{matched_rel}: {e}")
            continue
        if len(cops) != 1:
            errs.append(
                f"{matched_rel}: expected exact-one -c operand, found {len(cops)}"
            )
            continue
        if _raw_has_dotdot(cops[0]):
            errs.append(
                f"{matched_rel}: raw -c path traversal (..): {cops[0]!r}"
            )
            continue
        c_leaf, cerr = _bind_abs_or_rel(
            cops[0],
            rel_base=dir_canon,
            where=f"{matched_rel}: -c",
            require_regular_leaf=True,
        )
        if cerr is not None or c_leaf is None:
            errs.append(cerr or f"{matched_rel}: -c bind failed")
            continue
        try:
            c_canon = _canon_identity(c_leaf)
        except OSError as e:
            errs.append(f"{matched_rel}: -c operand resolve failed: {e}")
            continue
        if c_canon != expected_files[matched_rel]:
            errs.append(
                f"{matched_rel}: -c operand is not exact src_root source "
                f"({c_canon} vs {expected_files[matched_rel]})"
            )
            continue
        # outputs
        out_field = entry.get("output")
        try:
            argv_outs = _outputs_from_argv(argv)
        except ValueError as e:
            errs.append(f"{matched_rel}: {e}")
            continue
        if len(argv_outs) != 1:
            errs.append(
                f"{matched_rel}: expected exact-one -o output, found {len(argv_outs)}"
            )
            continue
        if not isinstance(out_field, str) or not out_field.strip():
            errs.append(f"{matched_rel}: entry.output missing")
            continue
        if _raw_has_dotdot(out_field) or _raw_has_dotdot(argv_outs[0]):
            errs.append(
                f"{matched_rel}: raw output path traversal (..): "
                f"output={out_field!r} -o={argv_outs[0]!r}"
            )
            continue
        # Bind outputs: absolute from FS root; relative from verified directory.
        # Allow trailing missing components only for classify-then-skip of exact
        # build_root testbuild (production remains fail-closed below).
        out_leaf, oerr, out_complete = _bind_output_path(
            out_field,
            rel_base=dir_canon,
            where=f"{matched_rel}: output",
        )
        if oerr is not None or out_leaf is None:
            errs.append(oerr or f"{matched_rel}: output bind failed")
            continue
        o_argv_leaf, oaerr, o_complete = _bind_output_path(
            argv_outs[0],
            rel_base=dir_canon,
            where=f"{matched_rel}: -o",
        )
        if oaerr is not None or o_argv_leaf is None:
            errs.append(oaerr or f"{matched_rel}: -o bind failed")
            continue
        try:
            if out_complete:
                out_canon = _canon_identity(out_leaf)
            else:
                out_canon = out_leaf
            if o_complete:
                o_argv_canon = _canon_identity(o_argv_leaf)
            else:
                o_argv_canon = o_argv_leaf
        except OSError as e:
            errs.append(f"{matched_rel}: output resolve failed: {e}")
            continue
        if out_canon != o_argv_canon:
            errs.append(
                f"{matched_rel}: entry.output and argv -o disagree "
                f"({out_canon} vs {o_argv_canon})"
            )
            continue
        leaf_o = Path(matched_rel).name + ".o"
        kind = _classify_output(out_canon, leaf_o, build_root=build_root)
        if kind == "traversal":
            errs.append(f"{matched_rel}: output path traversal: {out_canon}")
            continue
        if kind == "ambiguous":
            errs.append(
                f"{matched_rel}: output not production/testbuild: {out_canon}"
            )
            continue
        if kind == "testbuild":
            # Exact build_root testbuild is out of authority even when CI has
            # not materialized the object dir (production-only builds).
            # Symlink on any *existing* prefix already RED above.
            continue
        # Production: every output path component must exist (fail-closed).
        if not out_complete or not o_complete:
            missing = out_leaf if not out_complete else o_argv_leaf
            errs.append(
                f"{matched_rel}: missing path component: {missing}"
            )
            continue
        # dir_canon is already exact-matched to build_root; out_canon exact prod
        prod[matched_rel].append((argv, out_canon, dir_canon))

    for rel in N6_SRC:
        if rel not in expected_files:
            continue
        lst = prod[rel]
        if not lst:
            errs.append(
                f"{rel}: no production compile entry "
                f"(need output …/{PROD_DIR_MARKER}{Path(rel).name}.o)"
            )
            continue
        if len(lst) != 1:
            errs.append(
                f"{rel}: expected exactly one production compile entry, "
                f"found {len(lst)}"
            )
        for argv, _out, _dir in lst:
            errs.extend(check_argv_flags(rel, argv))

    if verbose_log is not None:
        errs.extend(
            _check_verbose_log(
                verbose_log,
                prod,
                src_root=src_root,
                expected_files=expected_files,
            )
        )
    return errs


def _strip_ninja_prefix(line: str) -> str:
    """Strip exact Ninja ``[n/m] `` prefix only; no other decoration handling."""
    return _RE_NINJA_PREFIX.sub("", line, count=1)


def _check_verbose_log(
    log_path: Path,
    prod: dict[str, list[tuple[list[str], Path, Path]]],
    *,
    src_root: Path,  # noqa: ARG001 — kept for call-site stability
    expected_files: dict[str, Path],
) -> list[str]:
    """Strict actual-command authority — no substring fallback.

    Real Ninja ``cmake --build … --verbose`` lines typically have:
      -c <absolute source>
      -o CMakeFiles/.../foo.c.o   (relative to entry.directory)

    Relative -c / -o are resolved against the compile_commands entry.directory
    already validated for that production TU (not cwd guess, not suffix match).
    """
    errs: list[str] = []
    if not log_path.is_file():
        return [f"verbose log missing: {log_path}"]
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [f"verbose log read failed: {e}"]

    lines = text.splitlines()
    for rel in N6_SRC:
        if not prod.get(rel):
            continue
        if rel not in expected_files:
            continue
        exp_src = expected_files[rel]
        exp_out = prod[rel][0][1]
        entry_dir = prod[rel][0][2]
        matching: list[tuple[int, list[str]]] = []
        for idx, ln in enumerate(lines):
            stripped = _strip_ninja_prefix(ln.strip())
            if not stripped:
                continue
            try:
                toks = shlex.split(stripped, posix=True)
            except ValueError:
                continue
            if not toks:
                continue
            # exact-one -c
            try:
                cops = _c_operands(toks)
                oouts = _outputs_from_argv(toks)
            except ValueError:
                continue
            if len(cops) != 1 or len(oouts) != 1:
                continue
            if _raw_has_dotdot(cops[0]) or _raw_has_dotdot(oouts[0]):
                continue
            # Bind -c/-o: absolute from FS root; relative only from verified
            # production entry.directory (never cwd / src_root guess).
            c_leaf, cerr = _bind_abs_or_rel(
                cops[0],
                rel_base=entry_dir,
                where=f"{rel} verbose -c",
                require_regular_leaf=True,
            )
            if cerr is not None or c_leaf is None:
                continue
            try:
                c_canon = _canon_identity(c_leaf)
            except OSError:
                continue
            if c_canon != exp_src:
                continue
            o_leaf, oerr = _bind_abs_or_rel(
                oouts[0],
                rel_base=entry_dir,
                where=f"{rel} verbose -o",
                require_regular_leaf=False,
            )
            if oerr is not None or o_leaf is None:
                continue
            try:
                o_canon = _canon_identity(o_leaf)
            except OSError:
                continue
            if o_canon != exp_out:
                continue
            matching.append((idx, toks))

        if len(matching) == 0:
            errs.append(
                f"{rel}: verbose log missing exact-one production compile command "
                f"(gcc-13, exact -c source, exact -o production output)"
            )
            continue
        if len(matching) != 1:
            errs.append(
                f"{rel}: verbose log expected exact-one production compile command, "
                f"found {len(matching)}"
            )
            continue
        _idx, toks = matching[0]
        fe = check_argv_flags(rel + " (verbose)", toks)
        errs.extend(fe)
    return errs


def _base_ok_argv(compiler: str = "gcc-13", *, wrapper: str | None = None) -> list[str]:
    head: list[str] = []
    if wrapper:
        head.append(wrapper)
    head.append(compiler)
    return head + [
        "-O2",
        "-DNDEBUG",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-pedantic-errors",
        "-Werror",
        "-Wvla",
        "-fstack-usage",
        "-Wframe-larger-than=2048",
        "-maccumulate-outgoing-args",
    ]


def _write_tree(
    root: Path,
    items: Sequence[tuple[str, Sequence[str], str, str]],
) -> Path:
    """items: (rel, argv_without_c_o, output_rel_to_build, directory_name).

    Creates src files + compile_commands under root.
    """
    src = root / "src" / "radio"
    src.mkdir(parents=True, exist_ok=True)
    build = root / "build"
    build.mkdir(parents=True, exist_ok=True)
    for rel in N6_SRC:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("/*x*/\n", encoding="utf-8")
    arr = []
    for rel, argv, out_rel, _dn in items:
        # For synthetic tests use absolute paths under root/build
        if not str(out_rel).startswith(str(root)):
            out_abs = build / out_rel
        else:
            out_abs = Path(out_rel)
        out_abs.parent.mkdir(parents=True, exist_ok=True)
        out_abs.write_bytes(b"")
        full_argv = list(argv) + [
            "-c",
            str((root / rel).resolve()),
            "-o",
            str(out_abs.resolve()),
        ]
        arr.append(
            {
                "directory": str(build.resolve()),
                "file": str((root / rel).resolve()),
                "output": str(out_abs.resolve()),
                "arguments": full_argv,
            }
        )
    cc = build / "compile_commands.json"
    cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
    return cc


def self_test() -> int:
    fails = 0
    ok_n = 0
    red_n = 0

    def fail(msg: str) -> None:
        nonlocal fails
        fails += 1
        print(f"SELF-TEST FAIL: {msg}")

    def ok(msg: str) -> None:
        nonlocal ok_n
        ok_n += 1
        print(f"SELF-TEST OK: {msg}")

    def red_ok(msg: str) -> None:
        nonlocal red_n, ok_n
        red_n += 1
        ok_n += 1
        print(f"SELF-TEST OK: {msg}")

    # Temp under repo workspace so absolute lstat walks do not hit OS intermediate
    # symlinks (e.g. macOS /var → /private/var) while still rejecting project
    # directory symlinks/traversal under the same strict walk.
    _ws = Path(__file__).resolve().parents[1]
    _tmp_base = _ws / ".tmp_n6_gcc13_selftest"
    _tmp_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="n6_gcc13_cc_", dir=str(_tmp_base)) as td:
        root = Path(td)

        def make(
            name: str,
            specs: list[tuple[str, list[str], str]],
        ) -> tuple[Path, Path]:
            """specs: (rel, argv_base, out_kind) out_kind prod|test|other"""
            r = root / name
            r.mkdir()
            items: list[tuple[str, Sequence[str], str, str]] = []
            for rel, argv, kind in specs:
                if kind == "prod":
                    out = PROD_DIR_MARKER + Path(rel).name + ".o"
                elif kind == "test":
                    out = TESTBUILD_DIR_MARKER + Path(rel).name + ".o"
                else:
                    out = f"other/{Path(rel).name}.o"
                items.append((rel, argv, out, "build"))
            cc = _write_tree(r, items)
            return r, cc

        # GREEN production only
        r, cc = make(
            "good",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        e = check_compile_commands(cc, src_root=r)
        if e:
            fail(f"GREEN production red: {e}")
        else:
            ok("production-only GREEN")

        # GREEN production+testbuild
        specs: list[tuple[str, list[str], str]] = []
        for rel in N6_SRC:
            specs.append((rel, _base_ok_argv(), "prod"))
            specs.append((rel, ["clang", "-O0"], "test"))
        r, cc = make("both", specs)
        e = check_compile_commands(cc, src_root=r)
        if e:
            fail(f"GREEN both red: {e}")
        else:
            ok("production+testbuild GREEN")

        # GREEN: production objects exist; exact testbuild listed in
        # compile_commands but object dirs never created (CI production-only).
        r = root / "prod_absent_testbuild"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("/*x*/\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr: list[dict[str, Any]] = []
        for rel in N6_SRC:
            src_abs = str((r / rel).resolve())
            prod_out = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            prod_out.parent.mkdir(parents=True, exist_ok=True)
            prod_out.write_bytes(b"")
            test_out = build / (TESTBUILD_DIR_MARKER + Path(rel).name + ".o")
            # Intentionally do NOT create test_out or its parent dirs.
            prod_argv = _base_ok_argv() + [
                "-c",
                src_abs,
                "-o",
                str(prod_out.resolve()),
            ]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": str(prod_out.resolve()),
                    "arguments": prod_argv,
                }
            )
            # Relative -o form as CMake often records; path not on disk.
            test_rel_o = TESTBUILD_DIR_MARKER + Path(rel).name + ".o"
            test_argv = ["clang", "-O0", "-c", src_abs, "-o", test_rel_o]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": test_rel_o,
                    "arguments": test_argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if e:
            fail(f"GREEN prod+absent-testbuild red (false-RED CI): {e}")
        else:
            ok("production+absent_exact_testbuild_output GREEN")

        # RED: only exact testbuild entries, objects also absent → still no prod.
        r = root / "absent_testbuild_only"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("/*x*/\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr = []
        for rel in N6_SRC:
            src_abs = str((r / rel).resolve())
            test_rel_o = TESTBUILD_DIR_MARKER + Path(rel).name + ".o"
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": test_rel_o,
                    "arguments": [
                        "clang",
                        "-O0",
                        "-c",
                        src_abs,
                        "-o",
                        test_rel_o,
                    ],
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        blob = " ".join(e)
        if not e:
            fail("absent_testbuild_only: expected RED missing production, got GREEN")
        elif "no production compile entry" not in blob:
            fail(f"absent_testbuild_only: RED but missing no-production: {e}")
        else:
            red_ok("absent_exact_testbuild_only (no objects) still RED missing production")

        # RED: symlink in *existing* testbuild output prefix remains RED even
        # when production is present (do not weaken all output lstat checks).
        r = root / "testbuild_symlink_prefix"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("/*x*/\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr = []
        # Real directory that the symlink will point at (must exist for link).
        real_tb_parent = build / "real_testbuild_parent"
        real_tb_parent.mkdir(parents=True, exist_ok=True)
        # CMakeFiles/ is real; ninlil_n6_store_testbuild.dir is a symlink.
        cmake_files = build / "CMakeFiles"
        cmake_files.mkdir(parents=True, exist_ok=True)
        tb_link = cmake_files / "ninlil_n6_store_testbuild.dir"
        if tb_link.exists() or tb_link.is_symlink():
            tb_link.unlink()
        tb_link.symlink_to(real_tb_parent, target_is_directory=True)
        for rel in N6_SRC:
            src_abs = str((r / rel).resolve())
            prod_out = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            prod_out.parent.mkdir(parents=True, exist_ok=True)
            prod_out.write_bytes(b"")
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": str(prod_out.resolve()),
                    "arguments": _base_ok_argv()
                    + ["-c", src_abs, "-o", str(prod_out.resolve())],
                }
            )
            test_rel_o = TESTBUILD_DIR_MARKER + Path(rel).name + ".o"
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": test_rel_o,
                    "arguments": [
                        "clang",
                        "-O0",
                        "-c",
                        src_abs,
                        "-o",
                        test_rel_o,
                    ],
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        blob = " ".join(e).lower()
        if not e:
            fail(
                "TESTBUILD_SYMLINK_PREFIX: production present + symlink in "
                "existing testbuild output prefix GREEN (false-GREEN)"
            )
        elif "symlink" not in blob:
            fail(f"TESTBUILD_SYMLINK_PREFIX: RED but missing symlink: {e}")
        else:
            red_ok("TESTBUILD_SYMLINK_PREFIX existing testbuild output prefix RED")

        # RED: absent exact-looking testbuild path with entry.output / -o disagree
        r = root / "absent_testbuild_disagree"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("/*x*/\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr = []
        for rel in N6_SRC:
            src_abs = str((r / rel).resolve())
            prod_out = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            prod_out.parent.mkdir(parents=True, exist_ok=True)
            prod_out.write_bytes(b"")
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": str(prod_out.resolve()),
                    "arguments": _base_ok_argv()
                    + ["-c", src_abs, "-o", str(prod_out.resolve())],
                }
            )
            out_a = TESTBUILD_DIR_MARKER + Path(rel).name + ".o"
            out_b = TESTBUILD_DIR_MARKER + "alt_" + Path(rel).name + ".o"
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": src_abs,
                    "output": out_a,
                    "arguments": ["clang", "-O0", "-c", src_abs, "-o", out_b],
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e or "disagree" not in " ".join(e):
            fail(
                f"absent_testbuild_output_argv_disagree: expected disagree RED, "
                f"got {e}"
            )
        else:
            red_ok("absent_testbuild entry.output/-o disagree RED")

        # GREEN ccache
        r, cc = make(
            "ccache",
            [(rel, _base_ok_argv(wrapper="ccache"), "prod") for rel in N6_SRC],
        )
        e = check_compile_commands(cc, src_root=r)
        if e:
            fail(f"GREEN ccache red: {e}")
        else:
            ok("ccache GREEN")

        # GREEN: good compile_commands + matching verbose log (absolute -c/-o)
        r, cc = make(
            "good_log",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        log_path = r / "build" / "n6-compile.log"
        log_lines: list[str] = []
        data = json.loads(cc.read_text(encoding="utf-8"))
        for i, entry in enumerate(data, start=1):
            argv = entry["arguments"]
            log_lines.append(
                f"[{i}/{len(data)}] " + " ".join(shlex.quote(a) for a in argv)
            )
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r, verbose_log=log_path)
        if e:
            fail(f"GREEN verbose log red: {e}")
        else:
            ok("verbose_log GREEN")

        # GREEN: realistic Ninja verbose form — absolute -c, relative -o
        # (cmake --build <ninja> --verbose on production TUs).
        r, cc = make(
            "ninja_rel_o",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        log_path = r / "build" / "n6-compile.log"
        data = json.loads(cc.read_text(encoding="utf-8"))
        log_lines = []
        for i, entry in enumerate(data, start=1):
            argv = list(entry["arguments"])
            # Rebuild argv with absolute -c and directory-relative -o.
            try:
                c_ops = _c_operands(argv)
                o_ops = _outputs_from_argv(argv)
            except ValueError as ex:
                fail(f"ninja_rel_o fixture setup: {ex}")
                c_ops, o_ops = [], []
            if len(c_ops) != 1 or len(o_ops) != 1:
                fail("ninja_rel_o fixture: expected one -c and one -o")
                continue
            # Strip old -c/-o pair tokens and re-append realistic forms.
            rebuilt: list[str] = []
            skip_next = False
            for t in argv:
                if skip_next:
                    skip_next = False
                    continue
                if t == "-c" or t == "-o":
                    skip_next = True
                    continue
                if t.startswith("-o") and len(t) > 2:
                    continue
                rebuilt.append(t)
            src_abs = str(Path(c_ops[0]).resolve())
            # Real Ninja: -o CMakeFiles/ninlil_runtime_private.dir/src/radio/foo.c.o
            out_rel = PROD_DIR_MARKER + Path(entry["file"]).name + ".o"
            rebuilt.extend(["-c", src_abs, "-o", out_rel])
            # Ninja rarely quotes path components without spaces.
            log_lines.append(f"[{i}/{len(data)}] " + " ".join(rebuilt))
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r, verbose_log=log_path)
        if e:
            fail(f"GREEN ninja relative -o red (false-RED regression): {e}")
        else:
            ok("verbose_log_ninja_relative_output GREEN")

        # --- Directory authority RED: absolute file/-c/-o cannot greenwash ---
        def _load_cc(cc_p: Path) -> list[dict[str, Any]]:
            return json.loads(cc_p.read_text(encoding="utf-8"))

        def _write_cc(cc_p: Path, arr: list[dict[str, Any]]) -> None:
            cc_p.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")

        # 1) raw directory traversal with absolute everything else
        r, cc = make(
            "dir_trav",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        arr = _load_cc(cc)
        for ent in arr:
            ent["directory"] = "../attacker-controlled"
        _write_cc(cc, arr)
        e = check_compile_commands(cc, src_root=r)
        blob = " ".join(e)
        if not e:
            fail("DIR_TRAVERSAL: absolute source/output + '../attacker' dir GREEN (false-GREEN)")
        elif "traversal" not in blob and ".." not in blob:
            fail(f"DIR_TRAVERSAL: RED but missing traversal: {e}")
        else:
            red_ok("DIR_TRAVERSAL entry.directory RED")

        # 2) directory symlink to real build root (absolute file/-c/-o)
        r, cc = make(
            "dir_symlink",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        build_real = (r / "build").resolve()
        link = r / "build_link"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(build_real, target_is_directory=True)
        arr = _load_cc(cc)
        for ent in arr:
            ent["directory"] = str(link)
        _write_cc(cc, arr)
        e = check_compile_commands(cc, src_root=r)
        blob = " ".join(e).lower()
        if not e:
            fail("DIR_SYMLINK: directory symlink GREEN (false-GREEN)")
        elif "symlink" not in blob:
            fail(f"DIR_SYMLINK: RED but missing symlink: {e}")
        else:
            red_ok("DIR_SYMLINK entry.directory RED")

        # 3) directory canonical mismatch (other real dir, absolute file/-c/-o)
        r, cc = make(
            "dir_mismatch",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        other = r / "other_build"
        other.mkdir()
        arr = _load_cc(cc)
        for ent in arr:
            ent["directory"] = str(other.resolve())
        _write_cc(cc, arr)
        e = check_compile_commands(cc, src_root=r)
        blob = " ".join(e).lower()
        if not e:
            fail("DIR_MISMATCH: other directory + absolute paths GREEN (false-GREEN)")
        elif "mismatch" not in blob and "build root" not in blob:
            fail(f"DIR_MISMATCH: RED but missing mismatch: {e}")
        else:
            red_ok("DIR_MISMATCH entry.directory RED")

        # 4) compile_commands.json path itself is a symlink → RED
        r, cc = make(
            "cc_symlink",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        cc_link = r / "compile_commands_via_symlink.json"
        if cc_link.exists() or cc_link.is_symlink():
            cc_link.unlink()
        cc_link.symlink_to(cc.resolve())
        e = check_compile_commands(cc_link, src_root=r)
        blob = " ".join(e).lower()
        if not e:
            fail("CC_SYMLINK: compile_commands path symlink GREEN (false-GREEN)")
        elif "symlink" not in blob:
            fail(f"CC_SYMLINK: RED but missing symlink: {e}")
        else:
            red_ok("CC_SYMLINK compile_commands path RED")

        mutations: list[tuple[str, list[tuple[str, list[str], str]], tuple[str, ...]]] = [
            (
                "testbuild_only",
                [(rel, _base_ok_argv(), "test") for rel in N6_SRC],
                ("no production compile entry",),
            ),
            (
                "gcc12",
                [(rel, _base_ok_argv("gcc-12"), "prod") for rel in N6_SRC],
                ("compiler must be",),
            ),
            (
                "clang_wrap",
                [(rel, ["clang", "gcc-13"] + _base_ok_argv()[1:], "prod") for rel in N6_SRC],
                ("compiler must be",),
            ),
            (
                "no_O2",
                [
                    (rel, [t for t in _base_ok_argv() if t != "-O2"], "prod")
                    for rel in N6_SRC
                ],
                ("exactly ['-O2']",),
            ),
            (
                "O5",
                [(rel, _base_ok_argv() + ["-O5"], "prod") for rel in N6_SRC],
                ("exactly ['-O2']",),
            ),
            (
                "dup_O2",
                [(rel, _base_ok_argv() + ["-O2"], "prod") for rel in N6_SRC],
                ("exactly ['-O2']",),
            ),
            (
                "Wno",
                [(rel, _base_ok_argv() + ["-Wno-error"], "prod") for rel in N6_SRC],
                ("warning suppression",),
            ),
            (
                "output_ambiguous",
                [(rel, _base_ok_argv(), "other") for rel in N6_SRC],
                ("not production/testbuild",),
            ),
        ]
        for flag in REQUIRED_FLAGS:
            mutations.append(
                (
                    f"drop_{flag.lstrip('-').replace('=', '_')}",
                    [
                        (rel, [t for t in _base_ok_argv() if t != flag], "prod")
                        for rel in N6_SRC
                    ],
                    ("missing required flag", flag),
                )
            )

        # production missing one + only test for that one
        mutations.append(
            (
                "prod_missing_store",
                [
                    (
                        rel,
                        _base_ok_argv(),
                        "prod" if rel != "src/radio/n6_context_store.c" else "test",
                    )
                    for rel in N6_SRC
                ],
                ("no production compile entry", "n6_context_store"),
            )
        )

        for name, specs_m, needles in mutations:
            r, cc = make(name, specs_m)
            e = check_compile_commands(cc, src_root=r)
            if not e:
                fail(f"{name}: expected RED, got GREEN")
                continue
            blob = " ".join(e)
            if not any(n in blob for n in needles):
                fail(f"{name}: RED but missing {needles}: {e}")
            else:
                red_ok(f"{name} RED ({needles[0]})")

        # output vs -o mismatch
        r = root / "out_mismatch"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("x\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr = []
        for rel in N6_SRC:
            out_a = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            out_b = build / (PROD_DIR_MARKER + "alt_" + Path(rel).name + ".o")
            out_a.parent.mkdir(parents=True, exist_ok=True)
            out_a.write_bytes(b"")
            out_b.parent.mkdir(parents=True, exist_ok=True)
            out_b.write_bytes(b"")
            argv = _base_ok_argv() + [
                "-c",
                str((r / rel).resolve()),
                "-o",
                str(out_b.resolve()),
            ]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": str((r / rel).resolve()),
                    "output": str(out_a.resolve()),
                    "arguments": argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e or "disagree" not in " ".join(e):
            fail(f"output_argv_mismatch: expected disagree RED, got {e}")
        else:
            red_ok("output_argv_mismatch RED")

        # suffix-only false path (wrong src_root file content path)
        r = root / "suffix"
        r.mkdir()
        decoy = r / "decoy" / "src" / "radio"
        decoy.mkdir(parents=True)
        real = r / "src" / "radio"
        real.mkdir(parents=True)
        for rel in N6_SRC:
            (r / rel).write_text("real\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        arr = []
        for rel in N6_SRC:
            decoy_f = r / "decoy" / rel
            decoy_f.parent.mkdir(parents=True, exist_ok=True)
            decoy_f.write_text("decoy\n", encoding="utf-8")
            out_a = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            out_a.parent.mkdir(parents=True, exist_ok=True)
            out_a.write_bytes(b"")
            argv = _base_ok_argv() + [
                "-c",
                str(decoy_f.resolve()),
                "-o",
                str(out_a.resolve()),
            ]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": str(decoy_f.resolve()),
                    "output": str(out_a.resolve()),
                    "arguments": argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail("suffix_only: expected RED, got GREEN")
        else:
            red_ok("suffix_only_path RED")

        # --- BAD_ACTUAL_LOG: clang + -Wno-error with all required flags as tokens ---
        r, cc = make(
            "bad_actual_log",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        log_path = r / "build" / "n6-compile.log"
        data = json.loads(cc.read_text(encoding="utf-8"))
        bad_lines: list[str] = []
        for i, entry in enumerate(data, start=1):
            # Same -c/-o as good entry but clang + -Wno-error; required flags present.
            src = entry["arguments"][entry["arguments"].index("-c") + 1]
            out = entry["arguments"][entry["arguments"].index("-o") + 1]
            bad_argv = (
                ["clang"]
                + [t for t in _base_ok_argv()[1:]]  # flags without gcc-13
                + ["-Wno-error", "-c", src, "-o", out]
            )
            bad_lines.append(
                f"[{i}/{len(data)}] " + " ".join(shlex.quote(a) for a in bad_argv)
            )
        log_path.write_text("\n".join(bad_lines) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r, verbose_log=log_path)
        blob = " ".join(e)
        if not e:
            fail("BAD_ACTUAL_LOG: expected RED (clang+-Wno-error), got GREEN")
        elif "compiler must be" not in blob and "warning suppression" not in blob:
            fail(f"BAD_ACTUAL_LOG: RED but missing compiler/Wno: {e}")
        else:
            red_ok("BAD_ACTUAL_LOG clang+-Wno-error RED")

        # --- SOURCE SYMLINK ---
        r = root / "symlink_src"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("real\n", encoding="utf-8")
        # Replace store with symlink to codec
        store = r / "src/radio/n6_context_store.c"
        target = r / "src/radio/n6_record_codec.c"
        store.unlink()
        store.symlink_to(target)
        build = r / "build"
        build.mkdir()
        arr = []
        for rel in N6_SRC:
            out_a = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            out_a.parent.mkdir(parents=True, exist_ok=True)
            out_a.write_bytes(b"")
            # Point at the (symlink) path for store
            fpath = (r / rel).resolve() if rel != "src/radio/n6_context_store.c" else store
            # For symlink case, compile_commands often records the symlink path string
            fstr = str(store) if rel == "src/radio/n6_context_store.c" else str((r / rel).resolve())
            argv = _base_ok_argv() + ["-c", fstr, "-o", str(out_a.resolve())]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": fstr,
                    "output": str(out_a.resolve()),
                    "arguments": argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail("SYMLINK_SOURCE: expected RED, got GREEN")
        elif "symlink" not in " ".join(e).lower():
            fail(f"SYMLINK_SOURCE: RED but missing symlink: {e}")
        else:
            red_ok("SYMLINK_SOURCE RED")

        # --- SOURCE TRAVERSAL (.. in raw file/-c) ---
        r = root / "trav_src"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("real\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        # Nested dir so relative ../../src/radio/file.c from build/nested reaches src
        nested = build / "nested"
        nested.mkdir()
        arr = []
        for rel in N6_SRC:
            out_a = build / (PROD_DIR_MARKER + Path(rel).name + ".o")
            out_a.parent.mkdir(parents=True, exist_ok=True)
            out_a.write_bytes(b"")
            # Raw path with .. components that would resolve to real source
            trav = f"../../{rel}"
            argv = _base_ok_argv() + [
                "-c",
                trav,
                "-o",
                str(out_a.resolve()),
            ]
            arr.append(
                {
                    "directory": str(nested.resolve()),
                    "file": trav,
                    "output": str(out_a.resolve()),
                    "arguments": argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail("TRAVERSAL_SOURCE: expected RED, got GREEN")
        elif "traversal" not in " ".join(e).lower() and ".." not in " ".join(e):
            fail(f"TRAVERSAL_SOURCE: RED but missing traversal: {e}")
        else:
            red_ok("TRAVERSAL_SOURCE RED")

        # --- OUTPUT TRAVERSAL ---
        r = root / "trav_out"
        r.mkdir()
        for rel in N6_SRC:
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text("real\n", encoding="utf-8")
        build = r / "build"
        build.mkdir()
        # Place a production-looking output via .. escape
        real_out_dir = build / PROD_DIR_MARKER
        real_out_dir.mkdir(parents=True, exist_ok=True)
        arr = []
        for rel in N6_SRC:
            leaf = Path(rel).name + ".o"
            real_out = real_out_dir / leaf
            real_out.write_bytes(b"")
            # Raw -o with .. that still ends at production path
            trav_o = f"../build/{PROD_DIR_MARKER}{leaf}"
            argv = _base_ok_argv() + [
                "-c",
                str((r / rel).resolve()),
                "-o",
                trav_o,
            ]
            arr.append(
                {
                    "directory": str(build.resolve()),
                    "file": str((r / rel).resolve()),
                    "output": trav_o,
                    "arguments": argv,
                }
            )
        cc = build / "compile_commands.json"
        cc.write_text(json.dumps(arr, indent=2) + "\n", encoding="utf-8")
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail("TRAVERSAL_OUTPUT: expected RED, got GREEN")
        elif "traversal" not in " ".join(e).lower() and ".." not in " ".join(e):
            fail(f"TRAVERSAL_OUTPUT: RED but missing traversal: {e}")
        else:
            red_ok("TRAVERSAL_OUTPUT RED")

        # --- EXTERNAL_PREFIX: legitimate directory/build_root, absolute -o/output
        # outside build_root that only suffix-matches production marker → must RED.
        # P1 false-GREEN when _classify_output used endswith() instead of exact
        # build_root / CMakeFiles/ninlil_runtime_private.dir/src/radio/<leaf>.o.
        r, cc = make(
            "evil_prefix_out",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        evil_base = r / "evil"
        arr = _load_cc(cc)
        for ent in arr:
            leaf = Path(ent["output"]).name
            evil_out = evil_base / (PROD_DIR_MARKER + leaf)
            evil_out.parent.mkdir(parents=True, exist_ok=True)
            evil_out.write_bytes(b"")
            evil_abs = str(evil_out.resolve())
            argv = list(ent["arguments"])
            # Replace sole -o operand with external absolute path; keep -c/src.
            rebuilt_argv: list[str] = []
            skip_next = False
            for t in argv:
                if skip_next:
                    skip_next = False
                    continue
                if t == "-o":
                    skip_next = True
                    continue
                if t.startswith("-o") and len(t) > 2:
                    continue
                rebuilt_argv.append(t)
            rebuilt_argv.extend(["-o", evil_abs])
            ent["output"] = evil_abs
            ent["arguments"] = rebuilt_argv
            # directory stays legitimate build root (make() already set it)
        _write_cc(cc, arr)
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail(
                "EXTERNAL_PREFIX_OUT: absolute output outside build_root with "
                "production suffix GREEN (false-GREEN)"
            )
        else:
            blob = " ".join(e).lower()
            # Must not be silently treated as production; ambiguous / not prod / no prod
            if (
                "not production/testbuild" not in blob
                and "no production compile entry" not in blob
            ):
                fail(
                    f"EXTERNAL_PREFIX_OUT: RED but missing output classification: {e}"
                )
            else:
                red_ok("EXTERNAL_PREFIX_OUT absolute production-suffix outside build_root RED")

        # Companion: external absolute path with testbuild suffix must not be
        # excluded as testbuild (only exact build_root testbuild is out-of-authority).
        r, cc = make(
            "evil_prefix_testbuild",
            [(rel, _base_ok_argv(), "prod") for rel in N6_SRC],
        )
        evil_base = r / "evil_tb"
        arr = _load_cc(cc)
        for ent in arr:
            leaf = Path(ent["output"]).name
            evil_out = evil_base / (TESTBUILD_DIR_MARKER + leaf)
            evil_out.parent.mkdir(parents=True, exist_ok=True)
            evil_out.write_bytes(b"")
            evil_abs = str(evil_out.resolve())
            argv = list(ent["arguments"])
            rebuilt_argv = []
            skip_next = False
            for t in argv:
                if skip_next:
                    skip_next = False
                    continue
                if t == "-o":
                    skip_next = True
                    continue
                if t.startswith("-o") and len(t) > 2:
                    continue
                rebuilt_argv.append(t)
            rebuilt_argv.extend(["-o", evil_abs])
            ent["output"] = evil_abs
            ent["arguments"] = rebuilt_argv
        _write_cc(cc, arr)
        e = check_compile_commands(cc, src_root=r)
        if not e:
            fail(
                "EXTERNAL_PREFIX_TESTBUILD: outside build_root testbuild-suffix "
                "treated as out-of-authority then missing-prod only? got GREEN"
            )
        else:
            blob = " ".join(e).lower()
            # Must RED via ambiguous classification (not silent testbuild skip alone
            # without reporting the bad output when it was the only entry).
            if (
                "not production/testbuild" not in blob
                and "no production compile entry" not in blob
            ):
                fail(
                    f"EXTERNAL_PREFIX_TESTBUILD: RED but unexpected reasons: {e}"
                )
            else:
                red_ok(
                    "EXTERNAL_PREFIX_TESTBUILD absolute testbuild-suffix "
                    "outside build_root RED"
                )

    if fails:
        print(f"n6_gcc13_release_compile_gate self-test: FAIL ({fails})")
        return 1
    print(
        "n6_gcc13_release_compile_gate self-test: OK "
        f"[GREEN_keep≈{ok_n - red_n}; RED_cases={red_n}; "
        "src_root+production output+gcc-13 -O2 authority; "
        "strict verbose log; dir/cc/src symlink+traversal RED; PASS≠GO]"
    )
    return 0


def run_check(
    compile_commands: Path, src_root: Path, verbose_log: Path | None
) -> int:
    errs = check_compile_commands(
        compile_commands, src_root=src_root, verbose_log=verbose_log
    )
    if errs:
        print("n6_gcc13_release_compile_gate FAIL:")
        for e in errs:
            print(" ", e)
        return 1
    print(
        "n6_gcc13_release_compile_gate: OK "
        f"({len(N6_SRC)} production TUs; src_root exact; gcc-13; "
        "unique -O2; required flags; strict verbose log; PASS≠GO)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="n6_gcc13_release_compile_gate")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--src-root", type=Path, required=True)
    c.add_argument("--compile-commands", type=Path, required=True)
    c.add_argument("--verbose-log", type=Path, default=None)
    sub.add_parser("self-test")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 1
    if args.command == "check":
        return run_check(args.compile_commands, args.src_root, args.verbose_log)
    if args.command == "self-test":
        return self_test()
    return 1


if __name__ == "__main__":
    sys.exit(main())
