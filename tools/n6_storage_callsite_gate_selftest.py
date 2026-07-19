#!/usr/bin/env python3
"""Self-test corpus for n6_storage_callsite_gate (SHA-256 pin authority).

Loaded only by ``n6_storage_callsite_gate.self_test`` / ``self-test`` CLI.
Not part of the production check path. Missing this module ⇒ self-test fail-closed.

Authority under test is exact accepted-source path/hash pins + docs/07 table
match. This is NOT a C semantic coverage suite and does NOT run real-compiler
fixtures as authority evidence. Known historical false-green C shapes are
included only to prove that any source-byte change makes check_tree RED via
the pin authority (setup failure is FAIL, never silent pass).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Core import (same pattern as historical selftest loader)
# ---------------------------------------------------------------------------


def _core():
    mod = sys.modules.get("n6_storage_callsite_gate")
    if mod is not None and hasattr(mod, "check_tree"):
        return mod
    main = sys.modules.get("__main__")
    if (
        main is not None
        and getattr(main, "__file__", None)
        and str(main.__file__).endswith("n6_storage_callsite_gate.py")
    ):
        sys.modules.setdefault("n6_storage_callsite_gate", main)
        return main
    import n6_storage_callsite_gate as g  # type: ignore

    return g


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

Mutator = Callable[[bytes], bytes]


def _must_change(orig: bytes, mut: bytes, name: str) -> bytes:
    if mut == orig:
        raise RuntimeError(f"mutation {name} did not change bytes (setup failure)")
    if not mut:
        raise RuntimeError(f"mutation {name} produced empty bytes (setup failure)")
    return mut


def _flip_one_byte(data: bytes) -> bytes:
    if not data:
        raise RuntimeError("empty file cannot single-byte mutate")
    b = bytearray(data)
    # Prefer a non-newline interior byte so we do not only touch trailing NL.
    idx = min(len(b) // 2, len(b) - 1)
    b[idx] = (b[idx] + 1) % 256
    return bytes(b)


def _append_comment(data: bytes, tag: str) -> bytes:
    return data + f"\n/* n6_pin_mut:{tag} */\n".encode("utf-8")


def _write_tree_with_files(
    root: Path,
    files: dict[str, bytes],
    *,
    docs_text: str | None = None,
) -> None:
    for rel, blob in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
    if docs_text is not None:
        dp = root / "docs" / "07-testing-and-quality.md"
        dp.parent.mkdir(parents=True, exist_ok=True)
        dp.write_text(docs_text, encoding="utf-8")


def _docs_with_manifest(rows: list[tuple[str, str]], g) -> str:
    """Minimal docs/07 body with the Normative accepted-manifest table markers."""
    lines = [
        "# 07. Testing and Quality",
        "",
        "### N6 storage callsite gate",
        "",
        g.DOCS_MANIFEST_BEGIN,
        "",
        "| Path | SHA-256 |",
        "| --- | --- |",
    ]
    for path, digest in rows:
        lines.append(f"| `{path}` | `{digest}` |")
    lines.extend(["", g.DOCS_MANIFEST_END, ""])
    return "\n".join(lines)


def _load_real_pins(src_root: Path, g) -> tuple[dict[str, bytes], str, list[tuple[str, str]]]:
    """Load real pinned file bytes + real docs text + code manifest rows."""
    code_map = g.accepted_manifest_map()
    files: dict[str, bytes] = {}
    for rel, expected in code_map.items():
        path, err = g.safe_relpath(src_root, rel, rel)
        if err is not None:
            raise RuntimeError(f"cannot load pin {rel}: {err}")
        assert path is not None
        data, rerr = g.read_bytes_bounded(
            path, max_bytes=g.MAX_PINNED_FILE_BYTES, where=rel
        )
        if rerr is not None:
            raise RuntimeError(f"cannot read pin {rel}: {rerr}")
        assert data is not None
        got = g.sha256_bytes(data)
        if got != expected:
            raise RuntimeError(
                f"real tree pin mismatch before self-test {rel}: "
                f"got={got} expected={expected}"
            )
        files[rel] = data
    docs_path, derr = g.safe_relpath(src_root, g.DOCS07_REL.as_posix(), "docs/07")
    if derr is not None:
        raise RuntimeError(f"cannot load docs/07: {derr}")
    assert docs_path is not None
    raw, rerr = g.read_bytes_bounded(
        docs_path, max_bytes=g.MAX_PINNED_FILE_BYTES, where="docs/07"
    )
    if rerr is not None:
        raise RuntimeError(f"cannot read docs/07: {rerr}")
    assert raw is not None
    docs_text = raw.decode("utf-8")
    docs_map, perr = g.parse_docs_manifest_table(docs_text)
    if perr is not None:
        raise RuntimeError(f"docs/07 manifest parse: {perr}")
    assert docs_map is not None
    pair_errs = g.check_manifest_pair_exact(code_map, docs_map)
    if pair_errs:
        raise RuntimeError("docs/code manifest mismatch before self-test: " + "; ".join(pair_errs))
    rows = list(g.ACCEPTED_SOURCE_MANIFEST)
    return files, docs_text, rows


def _expect_red(errs: list[str], name: str, *needles: str) -> str | None:
    if not errs:
        return f"{name}: stayed GREEN (expected RED)"
    joined = "\n".join(errs)
    for n in needles:
        if n in joined or any(n.lower() in e.lower() for e in errs):
            return None
    return (
        f"{name}: RED but missing expected evidence "
        f"(want one of {needles!r}): {errs[:5]}"
    )


def _expect_green(errs: list[str], name: str) -> str | None:
    if errs:
        return f"{name}: went RED (expected GREEN): {errs[:8]}"
    return None


# ---------------------------------------------------------------------------
# Known historical false-green *content* shapes (authority = bytes only)
# ---------------------------------------------------------------------------
# These patterns previously fooled the mini C semantic parser. Under pin
# authority they are RED solely because source bytes differ from the accepted
# hash. They are not "semantic coverage" and are not compile-fixture authority.


def _mut_multi_declarator(data: bytes) -> bytes:
    # Multi-declarator raw ops-ish shape (parser historically missed 2nd id).
    return _must_change(
        data,
        data
        + b"\n/* mut multi-declarator */\n"
        + b"static ninlil_storage_ops_t *a, *b;\n"
        + b"static void n6_mut_multi(void) { (void)a; (void)b; b->begin(0,0,0,0); }\n",
        "multi_declarator",
    )


def _mut_anonymous_promoted(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut anonymous promoted aggregate */\n"
        + b"struct { ninlil_storage_ops_t ops; } n6_mut_anon;\n"
        + b"static void n6_mut_anon_fn(void) { n6_mut_anon.ops.begin(0,0,0,0); }\n",
        "anonymous_promoted",
    )


def _mut_tag_shadow(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut tag shadow */\n"
        + b"struct n6_mut_tag { int x; };\n"
        + b"typedef struct n6_mut_tag ninlil_storage_ops_t;\n"
        + b"static void n6_mut_tag_fn(ninlil_storage_ops_t *p) { (void)p; }\n",
        "tag_shadow",
    )


def _mut_consume_conditional(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut consume runtime conditional */\n"
        + b"static int n6_mut_consume_cond(int c) {\n"
        + b"  if (c) { /* skip real consume */ return 0; }\n"
        + b"  return n6_rx_consume_ticket_pair(0,0,0);\n"
        + b"}\n",
        "consume_conditional",
    )


def _mut_pending_shadow(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut pending_copy shadow substring */\n"
        + b"static void n6_mut_pending_shadow(void) {\n"
        + b"  char pending_copy_shadow[8];\n"
        + b"  (void)pending_copy_shadow;\n"
        + b"}\n",
        "pending_shadow",
    )


def _mut_securezero_n2(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut secure_zero n/2 */\n"
        + b"void ninlil_n6_secure_zero_mut_n2(void *p, size_t n) {\n"
        + b"  volatile uint8_t *vp = (volatile uint8_t *)p;\n"
        + b"  for (size_t i = 0; i < (n / 2u); ++i) vp[i] = 0;\n"
        + b"}\n",
        "securezero_n2",
    )


def _mut_securezero_stride(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut secure_zero stride */\n"
        + b"void ninlil_n6_secure_zero_mut_stride(void *p, size_t n) {\n"
        + b"  volatile uint8_t *vp = (volatile uint8_t *)p;\n"
        + b"  for (size_t i = 0; i < n; i += 2u) vp[i] = 0;\n"
        + b"}\n",
        "securezero_stride",
    )


def _mut_securezero_unreachable(data: bytes) -> bytes:
    return _must_change(
        data,
        data
        + b"\n/* mut secure_zero unreachable */\n"
        + b"void ninlil_n6_secure_zero_mut_unreach(void *p, size_t n) {\n"
        + b"  volatile uint8_t *vp = (volatile uint8_t *)p;\n"
        + b"  if (0) { for (size_t i = 0; i < n; ++i) vp[i] = 0; }\n"
        + b"  (void)vp; (void)n;\n"
        + b"}\n",
        "securezero_unreachable",
    )


KNOWN_FALSE_GREEN_MUTATIONS: list[tuple[str, str, Mutator]] = [
    # (name, target_rel_key, mutator) — target_rel_key is "store" or "crypto"
    ("fg_multi_declarator", "store", _mut_multi_declarator),
    ("fg_anonymous_promoted", "store", _mut_anonymous_promoted),
    ("fg_tag_shadow", "store", _mut_tag_shadow),
    ("fg_consume_conditional", "store", _mut_consume_conditional),
    ("fg_pending_shadow", "store", _mut_pending_shadow),
    ("fg_securezero_n2", "crypto", _mut_securezero_n2),
    ("fg_securezero_stride", "crypto", _mut_securezero_stride),
    ("fg_securezero_unreachable", "crypto", _mut_securezero_unreachable),
]


# ---------------------------------------------------------------------------
# Self-test runner
# ---------------------------------------------------------------------------


def run_self_test(src_root: Path) -> int:
    g = _core()
    src_root = Path(src_root).resolve()
    t0 = time.perf_counter()
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

    # --- 0) real tree GREEN (exact manifest) ---
    try:
        files, docs_text, rows = _load_real_pins(src_root, g)
    except Exception as ex:  # noqa: BLE001
        fail(f"mutation setup / load real pins: {ex}")
        print(f"n6_storage_callsite_gate self-test: FAIL ({fails})")
        return 1

    real_errs = g.check_tree(src_root)
    msg = _expect_green(real_errs, "real_tree_exact_manifest")
    if msg:
        fail(msg)
    else:
        ok("exact accepted manifest GREEN on real tree")

    # Diagnostic helper smoke (not authority).
    d_empty = g.check_store_text("")
    if not d_empty:
        fail("check_store_text diagnostic: empty text should report")
    else:
        ok("check_store_text diagnostic flags empty text")
    d_ok = g.check_store_text("/* diagnostic only */\nint x;\n")
    if d_ok:
        fail(f"check_store_text diagnostic false-red on tiny text: {d_ok}")
    else:
        ok("check_store_text diagnostic accepts tiny non-empty text")

    store_rel = g.STORE_REL.as_posix()
    header_rel = g.HEADER_REL.as_posix()
    crypto_rel = g.CRYPTO_REL.as_posix()
    pin_paths = [store_rel, header_rel, crypto_rel]
    for rel in pin_paths:
        if rel not in files:
            fail(f"missing expected pin path in load: {rel}")
            print(f"n6_storage_callsite_gate self-test: FAIL ({fails})")
            return 1

    with tempfile.TemporaryDirectory(prefix="n6_scg_pin_") as td:
        tdir = Path(td)

        # --- 1) single-byte mutation on each of 3 pinned files → RED ---
        for rel in pin_paths:
            name = f"single_byte_{Path(rel).name}"
            mroot = tdir / name
            try:
                mutated_files = dict(files)
                mutated_files[rel] = _must_change(
                    files[rel], _flip_one_byte(files[rel]), name
                )
                _write_tree_with_files(mroot, mutated_files, docs_text=docs_text)
            except Exception as ex:  # noqa: BLE001
                fail(f"mutation {name} setup: {ex}")
                continue
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "sha256 mismatch", rel)
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED (pin hash)")

        # --- 2) missing file ---
        name = "missing_store"
        mroot = tdir / name
        try:
            subset = {k: v for k, v in files.items() if k != store_rel}
            _write_tree_with_files(mroot, subset, docs_text=docs_text)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "missing", store_rel)
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 3) extra path in code pin only (docs still 3) ---
        name = "extra_path_code_only"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            extra_rel = "src/radio/n6_mut_extra_pin.c"
            (mroot / extra_rel).parent.mkdir(parents=True, exist_ok=True)
            (mroot / extra_rel).write_bytes(b"/* extra */\n")
            extra_hash = g.sha256_bytes(b"/* extra */\n")
            bad_manifest = list(g.ACCEPTED_SOURCE_MANIFEST) + [(extra_rel, extra_hash)]
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(mroot, manifest=bad_manifest)
            msg = _expect_red(errs, name, "manifest set mismatch", "only in code")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 4) wrong path in code pin (rename one path) ---
        name = "wrong_path_code_pin"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            wrong_manifest = []
            for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                if path == store_rel:
                    wrong_manifest.append(("src/radio/n6_context_store_WRONG.c", digest))
                else:
                    wrong_manifest.append((path, digest))
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(mroot, manifest=wrong_manifest)
            msg = _expect_red(
                errs, name, "manifest set mismatch", "missing path", "WRONG"
            )
            if msg:
                # also accept sha256/missing on wrong path
                if errs:
                    red_ok(f"{name} RED ({errs[0]})")
                else:
                    fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 5) wrong hash in code pin (docs still correct) ---
        name = "wrong_hash_code_pin"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            bad_hash = "0" * 64
            wrong_manifest = []
            for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                if path == store_rel:
                    wrong_manifest.append((path, bad_hash))
                else:
                    wrong_manifest.append((path, digest))
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(mroot, manifest=wrong_manifest)
            msg = _expect_red(errs, name, "manifest hash mismatch", "sha256 mismatch")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 6) docs table hash mismatch (code pins correct) ---
        name = "docs_hash_mismatch"
        mroot = tdir / name
        try:
            bad_rows = []
            for path, digest in rows:
                if path == store_rel:
                    bad_rows.append((path, "f" * 64))
                else:
                    bad_rows.append((path, digest))
            bad_docs = _docs_with_manifest(bad_rows, g)
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "manifest hash mismatch")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 7) docs missing a path (extra in code) ---
        name = "docs_missing_path"
        mroot = tdir / name
        try:
            bad_rows = [(p, h) for p, h in rows if p != crypto_rel]
            bad_docs = _docs_with_manifest(bad_rows, g)
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "manifest set mismatch")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 8) docs extra path ---
        name = "docs_extra_path"
        mroot = tdir / name
        try:
            bad_rows = list(rows) + [("src/radio/n6_docs_extra.c", "a" * 64)]
            bad_docs = _docs_with_manifest(bad_rows, g)
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "manifest set mismatch", "only in docs")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 8b) docs marker duplication / uppercase hash are noncanonical ---
        name = "docs_duplicate_marker"
        mroot = tdir / name
        try:
            bad_docs = docs_text + "\n" + g.DOCS_MANIFEST_BEGIN + "\n"
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "exactly once")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        name = "docs_uppercase_hash"
        mroot = tdir / name
        try:
            upper_hash = rows[0][1].upper()
            if upper_hash == rows[0][1]:
                raise RuntimeError("selected digest has no alphabetic hex to uppercase")
            bad_docs = docs_text.replace(rows[0][1], upper_hash, 1)
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "manifest", "no path/hash rows")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 9) pin update one-side only: code hash updated to match mutated disk,
        #     docs still old → RED ---
        name = "pin_update_code_only"
        mroot = tdir / name
        try:
            mutated = _must_change(
                files[store_rel], _append_comment(files[store_rel], "code_only"), name
            )
            mfiles = dict(files)
            mfiles[store_rel] = mutated
            new_hash = g.sha256_bytes(mutated)
            code_only_manifest = []
            for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                if path == store_rel:
                    code_only_manifest.append((path, new_hash))
                else:
                    code_only_manifest.append((path, digest))
            # docs still has old hashes (from original docs_text)
            _write_tree_with_files(mroot, mfiles, docs_text=docs_text)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(mroot, manifest=code_only_manifest)
            msg = _expect_red(errs, name, "manifest hash mismatch")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 10) pin update docs only (disk+code old, docs new) ---
        name = "pin_update_docs_only"
        mroot = tdir / name
        try:
            mutated = _must_change(
                files[store_rel], _append_comment(files[store_rel], "docs_only_ref"), name
            )
            # Disk stays original; only docs claims new hash of mutated content.
            new_hash = g.sha256_bytes(mutated)
            bad_rows = []
            for path, digest in rows:
                if path == store_rel:
                    bad_rows.append((path, new_hash))
                else:
                    bad_rows.append((path, digest))
            bad_docs = _docs_with_manifest(bad_rows, g)
            _write_tree_with_files(mroot, files, docs_text=bad_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "manifest hash mismatch")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 11) symlink RED ---
        name = "symlink_store"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            target = mroot / store_rel
            shadow = mroot / "src" / "radio" / "n6_context_store.c.real"
            shutil.move(str(target), str(shadow))
            os.symlink(shadow.name, target)
            if not target.is_symlink():
                raise RuntimeError("symlink not created")
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "symlink")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 12) non-regular (directory where file expected) ---
        name = "nonregular_store"
        mroot = tdir / name
        try:
            mfiles = {k: v for k, v in files.items() if k != store_rel}
            _write_tree_with_files(mroot, mfiles, docs_text=docs_text)
            d = mroot / store_rel
            d.mkdir(parents=True, exist_ok=True)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, name, "not a regular file", "missing")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 13) oversize ---
        name = "oversize_store"
        mroot = tdir / name
        try:
            mfiles = dict(files)
            # Keep other files real; store oversized vs a tiny bound.
            mfiles[store_rel] = b"A" * 64
            _write_tree_with_files(mroot, mfiles, docs_text=docs_text)
            # Also re-pin code+docs to the small content so only size bound fires,
            # OR leave pins wrong — either way must be RED. Prefer pure oversize:
            # skip_docs + manifest matching the small content, max_bytes tiny.
            small_hash = g.sha256_bytes(mfiles[store_rel])
            tiny_manifest = []
            for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                if path == store_rel:
                    tiny_manifest.append((path, small_hash))
                else:
                    tiny_manifest.append((path, digest))
            # docs must match code for this case
            tiny_docs = _docs_with_manifest(tiny_manifest, g)
            (mroot / g.DOCS07_REL).write_text(tiny_docs, encoding="utf-8")
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(
                mroot, manifest=tiny_manifest, max_bytes=16
            )
            msg = _expect_red(errs, name, "too large", "grew past bound")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 14) invalid path (traversal in code pin) ---
        name = "invalid_path_traversal"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            bad_manifest = [
                ("../etc/passwd", g.ACCEPTED_SOURCE_MANIFEST[0][1]),
                g.ACCEPTED_SOURCE_MANIFEST[1],
                g.ACCEPTED_SOURCE_MANIFEST[2],
            ]
            # docs will mismatch set too; either evidence is fine
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(
                mroot, manifest=bad_manifest, skip_docs=True
            )
            msg = _expect_red(
                errs, name, "traversal", "forbidden", "missing path", "absolute"
            )
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 14b) import-compatible store override is authority-forbidden ---
        name = "store_override_forbidden"
        mroot = tdir / name
        try:
            _write_tree_with_files(mroot, files, docs_text=docs_text)
            override = mroot / store_rel
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g.check_tree(mroot, store_path=override)
            msg = _expect_red(errs, name, "override is forbidden")
            if msg:
                fail(msg)
            else:
                red_ok(f"{name} RED")

        # --- 15) known false-green content mutations → RED via pin (bytes) ---
        for fg_name, target, mutator in KNOWN_FALSE_GREEN_MUTATIONS:
            rel = store_rel if target == "store" else crypto_rel
            mroot = tdir / fg_name
            try:
                mfiles = dict(files)
                mfiles[rel] = mutator(files[rel])
                _write_tree_with_files(mroot, mfiles, docs_text=docs_text)
            except Exception as ex:  # noqa: BLE001
                fail(f"mutation {fg_name} setup: {ex}")
                continue
            errs = g.check_tree(mroot)
            msg = _expect_red(errs, fg_name, "sha256 mismatch", rel)
            if msg:
                fail(msg)
            else:
                red_ok(
                    f"{fg_name} RED via source-byte pin "
                    f"(historical false-green shape; not semantic proof)"
                )

        # --- 16) full simultaneous pin update GREEN (docs+code+disk) ---
        name = "simultaneous_pin_update_green"
        mroot = tdir / name
        try:
            mfiles = dict(files)
            mfiles[store_rel] = _must_change(
                files[store_rel],
                _append_comment(files[store_rel], "simultaneous_ok"),
                name,
            )
            new_hash = g.sha256_bytes(mfiles[store_rel])
            new_manifest = []
            for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                if path == store_rel:
                    new_manifest.append((path, new_hash))
                else:
                    new_manifest.append((path, digest))
            new_docs = _docs_with_manifest(new_manifest, g)
            _write_tree_with_files(mroot, mfiles, docs_text=new_docs)
        except Exception as ex:  # noqa: BLE001
            fail(f"mutation {name} setup: {ex}")
        else:
            errs = g._check_tree_with_policy(mroot, manifest=new_manifest)
            msg = _expect_green(errs, name)
            if msg:
                fail(msg)
            else:
                ok(f"{name} GREEN (docs+code+disk co-update)")

        # --- 17) RX index errata structural mutations stay RED even with
        # pin+docs co-update. These are order/condition/return/dimension
        # attacks (not mere SEMANTIC marker scrub counts).
        def _co_update_store(name: str, mutator) -> None:
            nonlocal red_n, ok_n, fails
            mroot = tdir / name
            try:
                orig = files[store_rel]
                mut = mutator(orig)
                mut = _must_change(orig, mut, name)
                mfiles = dict(files)
                mfiles[store_rel] = mut
                new_hash = g.sha256_bytes(mut)
                new_manifest = []
                for path, digest in g.ACCEPTED_SOURCE_MANIFEST:
                    if path == store_rel:
                        new_manifest.append((path, new_hash))
                    else:
                        new_manifest.append((path, digest))
                new_docs = _docs_with_manifest(new_manifest, g)
                _write_tree_with_files(mroot, mfiles, docs_text=new_docs)
            except Exception as ex:  # noqa: BLE001
                fail(f"mutation {name} setup: {ex}")
                return
            errs = g._check_tree_with_policy(mroot, manifest=new_manifest)
            msg = _expect_red(errs, name, "rx-index-errata structural")
            if msg:
                fail(msg)
            else:
                red_ok(
                    f"{name} RED via structural errata gate "
                    f"(pin co-update does not greenwash)"
                )

        def mut_window_order_reverse(data: bytes) -> bytes:
            # Move first rx_boot_floor[idx] load before the range guard.
            s = data.decode("utf-8")
            guard = "if (!n6_lane_idx_in_range(idx))"
            load = "boot_floor = slot->rx_boot_floor[idx];"
            # Only touch the window helper region.
            sig = "static int n6_rx_precheck_window("
            p0 = s.find(sig)
            if p0 < 0:
                raise RuntimeError("window missing")
            p1 = s.find("ninlil_n6_status_t ninlil_n6_rx_precheck(", p0)
            region = s[p0:p1]
            if guard not in region or load not in region:
                raise RuntimeError("window guard/load missing")
            region2 = region.replace(load, "/*moved*/", 1)
            region2 = region2.replace(
                guard, load + "\n    " + guard, 1
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_window_cond_zero(data: bytes) -> bytes:
            return data.replace(
                b"if (!n6_lane_idx_in_range(idx))",
                b"if (0 && !n6_lane_idx_in_range(idx))",
                1,  # first is window
            )

        def mut_precheck_cond_invert(data: bytes) -> bytes:
            # Invert only the precheck public path occurrence (2nd overall
            # after window, or the one after idx = n6_lane_idx(lane_kind)).
            s = data.decode("utf-8")
            sig = "ninlil_n6_status_t ninlil_n6_rx_precheck("
            p0 = s.find(sig)
            p1 = s.find("ninlil_n6_status_t ninlil_n6_rx_admit_after_aead(", p0)
            region = s[p0:p1]
            old = "if (!n6_lane_idx_in_range(idx))"
            new = "if (n6_lane_idx_in_range(idx))"
            if old not in region:
                raise RuntimeError("precheck guard missing")
            region2 = region.replace(old, new, 1)
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_tx_order_reverse(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "ninlil_n6_status_t ninlil_n6_tx_burn("
            p0 = s.find(sig)
            p1 = s.find("ninlil_n6_status_t ninlil_n6_tx_lease_release(", p0)
            region = s[p0:p1]
            guard = "if (!n6_lane_idx_in_range(idx))"
            access = "if (slot->tx_ram_next[idx] >= slot->tx_ram_limit[idx])"
            if guard not in region or access not in region:
                raise RuntimeError("tx guard/access missing")
            # Place a synthetic early access before the guard.
            region2 = region.replace(
                guard,
                "slot->tx_ram_next[idx];\n    " + guard,
                1,
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_admit_drop_fence_return(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "ninlil_n6_status_t ninlil_n6_rx_admit_after_aead("
            p0 = s.find(sig)
            if p0 < 0:
                raise RuntimeError("admit missing")
            # Within admit, neuter the first range-fail block's CORRUPT return.
            body_start = s.find("{", p0)
            # Find range guard then strip fence/consume/return CORRUPT once.
            g = s.find("if (!n6_lane_idx_in_range(idx))", p0)
            if g < 0:
                raise RuntimeError("admit range guard missing")
            chunk = s[g : g + 450]
            chunk2 = chunk
            for frag in (
                "n6_enter_fenced(n6);",
                "n6_rx_consume_ticket_pair(n6, i, ticket, &tok);",
                "return NINLIL_N6_CORRUPT;",
            ):
                if frag not in chunk2:
                    raise RuntimeError(f"admit range block missing {frag}")
                chunk2 = chunk2.replace(frag, "/*stripped*/", 1)
            return (s[:g] + chunk2 + s[g + 450 :]).encode("utf-8")

        def mut_admit_layer_relax(data: bytes) -> bytes:
            return data.replace(
                b"if (!n6_lane_ok_for_slot(slot, tok.lane_kind))",
                b"if (0 && !n6_lane_ok_for_slot(slot, tok.lane_kind))",
                1,
            )

        def mut_bare_3_dimension(data: bytes) -> bytes:
            # Force one array back to magic 3.
            old = b"uint64_t rx_boot_floor[N6_PRIVATE_NAMED_LANE_COUNT];"
            new = b"uint64_t rx_boot_floor[3];"
            if old not in data:
                raise RuntimeError("rx_boot_floor named dimension missing")
            return data.replace(old, new, 1)

        def mut_drop_static_assert_boot(data: bytes) -> bytes:
            # Remove the rx_boot_floor static assert block (line-ish region).
            s = data.decode("utf-8")
            needle = 'sizeof(((n6_slot_t *)0)->rx_boot_floor)'
            p = s.find(needle)
            if p < 0:
                raise RuntimeError("boot_floor static assert missing")
            # Expand to enclosing _Static_assert( ... );
            a = s.rfind("_Static_assert", 0, p)
            b = s.find(";", p)
            if a < 0 or b < 0:
                raise RuntimeError("static assert bounds")
            return (s[:a] + "/*assert removed*/" + s[b + 1 :]).encode("utf-8")

        def mut_drop_cu_validate(data: bytes) -> bytes:
            s = data.decode("utf-8")
            if "n6_cu_validate_array_posts" not in s:
                raise RuntimeError("cu validate missing")
            return s.replace(
                "n6_cu_validate_array_posts",
                "n6_cu_validate_array_posts_REMOVED",
                1,
            ).encode("utf-8")

        def mut_cu_bare3(data: bytes) -> bytes:
            # Re-introduce bare magic if any residual path is added later;
            # also corrupt apply to use lane_idx < 3u if present after rename.
            s = data.decode("utf-8")
            if "n6_apply_cu_post" not in s:
                raise RuntimeError("apply missing")
            # Force a forbidden bare check into apply body for structural RED.
            sig = "static ninlil_n6_status_t n6_apply_cu_post("
            p0 = s.find(sig)
            if p0 < 0:
                p0 = s.find("n6_apply_cu_post(")
            brace = s.find("{", p0)
            return (
                s[: brace + 1]
                + "\n    if (0) { if (e->lane_idx < 3u) { (void)e; } }\n"
                + s[brace + 1 :]
            ).encode("utf-8")

        def mut_in_range_ge_minus1(data: bytes) -> bytes:
            # Independent audit GREEN_FALSE (a): relax central helper to idx>=-1.
            s = data.decode("utf-8")
            old = "return idx >= 0 && idx < (int)N6_PRIVATE_NAMED_LANE_COUNT;"
            new = "return idx >= -1 && idx < (int)N6_PRIVATE_NAMED_LANE_COUNT;"
            if old not in s:
                raise RuntimeError("in_range return form missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_lane_ok_default_return1(data: bytes) -> bytes:
            # Independent audit GREEN_FALSE (b): default deny → return 1.
            s = data.decode("utf-8")
            # Prefer the definition (after recover_cu), not any earlier decl noise.
            sig = "static int n6_lane_ok_for_slot("
            p0 = s.rfind(sig)
            if p0 < 0:
                raise RuntimeError("lane_ok missing")
            brace = s.find("{", p0)
            if brace < 0:
                raise RuntimeError("lane_ok brace missing")
            depth = 0
            j = brace
            while j < len(s):
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            region = s[p0 : j + 1]
            if "return 0;" not in region:
                raise RuntimeError("lane_ok return 0 missing")
            idx = region.rfind("return 0;")
            region2 = region[:idx] + "return 1;" + region[idx + len("return 0;") :]
            return (s[:p0] + region2 + s[j + 1 :]).encode("utf-8")

        def mut_static_assert_comment_only(data: bytes) -> bytes:
            # Independent audit GREEN_FALSE (c): comment-out asserts, leave sizeof
            # tokens only inside // comments (block wrap fails if cluster has */).
            s = data.decode("utf-8")
            marker = "/* SEMANTIC: N6_PRIVATE_NAMED_LANE_COUNT_STATIC_ASSERT */"
            p = s.find(marker)
            if p < 0:
                raise RuntimeError("static assert cluster marker missing")
            end = s.find("/* Boot pack", p)
            if end < 0:
                raise RuntimeError("boot pack marker missing")
            cluster = s[p:end]
            lines: list[str] = []
            for line in cluster.splitlines(True):
                if not line.strip() or line.lstrip().startswith("//"):
                    lines.append(line)
                    continue
                if line.endswith("\n"):
                    lines.append("// " + line)
                else:
                    lines.append("// " + line)
            return (s[:p] + "".join(lines) + s[end:]).encode("utf-8")

        def mut_guard_into_if0(data: bytes) -> bytes:
            # Independent audit GREEN_FALSE (d): move exact window guard into if(0){}.
            s = data.decode("utf-8")
            sig = "static int n6_rx_precheck_window("
            p0 = s.find(sig)
            p1 = s.find("ninlil_n6_status_t ninlil_n6_rx_precheck(", p0)
            region = s[p0:p1]
            guard = "if (!n6_lane_idx_in_range(idx))"
            g = region.find(guard)
            if g < 0:
                raise RuntimeError("window guard missing")
            # Find the guard's brace block
            brace = region.find("{", g)
            if brace < 0:
                raise RuntimeError("window guard brace missing")
            depth = 0
            j = brace
            while j < len(region):
                if region[j] == "{":
                    depth += 1
                elif region[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            block = region[g : j + 1]
            # Remove live guard and reinsert inside if(0)
            region2 = region[:g] + "if (0) {\n    " + block + "\n    }\n" + region[j + 1 :]
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_precheck_guard_into_if0(data: bytes) -> bytes:
            # Independent audit: public precheck guard moved into if(0){...}.
            s = data.decode("utf-8")
            sig = "ninlil_n6_status_t ninlil_n6_rx_precheck("
            p0 = s.find(sig)
            p1 = s.find("ninlil_n6_status_t ninlil_n6_rx_admit_after_aead(", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("precheck bounds missing")
            region = s[p0:p1]
            guard = "if (!n6_lane_idx_in_range(idx))"
            g = region.find(guard)
            if g < 0:
                raise RuntimeError("precheck guard missing")
            brace = region.find("{", g)
            if brace < 0:
                raise RuntimeError("precheck guard brace missing")
            depth = 0
            j = brace
            while j < len(region):
                if region[j] == "{":
                    depth += 1
                elif region[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            block = region[g : j + 1]
            region2 = (
                region[:g] + "if (0) {\n    " + block + "\n    }\n" + region[j + 1 :]
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_cu_validate_if0_and(data: bytes) -> bytes:
            # Independent audit: deaden apply CU validate with if(0 && ...).
            s = data.decode("utf-8")
            old = "if (n6_cu_validate_array_posts(n6) != NINLIL_N6_OK)"
            new = "if (0 && n6_cu_validate_array_posts(n6) != NINLIL_N6_OK)"
            # Mutate first in apply (may appear in recover too — mutate all apply
            # by replacing only the first occurrence inside apply body).
            sig = "static ninlil_n6_status_t n6_apply_cu_post("
            p0 = s.find(sig)
            if p0 < 0:
                p0 = s.find("n6_apply_cu_post(")
            p1 = s.find("static ninlil_n6_status_t n6_cu_rb_close_corrupt(", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("apply bounds")
            region = s[p0:p1]
            if old not in region:
                raise RuntimeError("apply validate if missing")
            region2 = region.replace(old, new, 1)
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_cu_range_if0_and(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("cu validate bounds")
            region = s[p0:p1]
            old = "if (!n6_lane_idx_in_range(expected))"
            new = "if (0 && !n6_lane_idx_in_range(expected))"
            if old not in region:
                raise RuntimeError("cu range guard missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode("utf-8")

        def mut_cu_layer_if0_and(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("cu validate bounds")
            region = s[p0:p1]
            old = "if (!n6_lane_ok_for_slot(s, e->lane_kind))"
            new = "if (0 && !n6_lane_ok_for_slot(s, e->lane_kind))"
            if old not in region:
                raise RuntimeError("cu layer guard missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode("utf-8")

        def mut_cu_preflight_if0_and(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = "if (n6_cu_preflight_plan(n6) != NINLIL_N6_OK)"
            new = "if (0 && n6_cu_preflight_plan(n6) != NINLIL_N6_OK)"
            if old not in s:
                raise RuntimeError("preflight if missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_recover_no_cu_or(data: bytes) -> bytes:
            # P1 residual: OR bypasses preflight for live=1 n_keys=0.
            s = data.decode("utf-8")
            old = "if (n6->cu.live == 0 && n6->cu.n_keys == 0u)"
            new = "if (n6->cu.live == 0 || n6->cu.n_keys == 0u)"
            if old not in s:
                raise RuntimeError("true no-CU AND missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_recover_no_cu_live_only(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = "if (n6->cu.live == 0 && n6->cu.n_keys == 0u)"
            new = "if (n6->cu.live == 0)"
            if old not in s:
                raise RuntimeError("true no-CU AND missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_recover_no_cu_nkeys_only(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = "if (n6->cu.live == 0 && n6->cu.n_keys == 0u)"
            new = "if (n6->cu.n_keys == 0u)"
            if old not in s:
                raise RuntimeError("true no-CU AND missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_recover_no_cu_if0_and(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = "if (n6->cu.live == 0 && n6->cu.n_keys == 0u)"
            new = "if (0 && n6->cu.live == 0 && n6->cu.n_keys == 0u)"
            if old not in s:
                raise RuntimeError("true no-CU AND missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_live_relax(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_preflight_plan("
            p0 = s.find(sig)
            p1 = s.find("/* SEMANTIC: N6_CU_ARRAY_POST_INTEGRITY */", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("preflight bounds")
            region = s[p0:p1]
            old = "n6->cu.live != 1"
            new = "n6->cu.live != 0"
            if old not in region:
                raise RuntimeError("live!=1 missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        def mut_preflight_live_if0_and(data: bytes) -> bytes:
            # Keep the desired predicate text, but make the whole guard dead.
            s = data.decode("utf-8")
            old = "if (n6 == NULL || n6->cu.live != 1)"
            new = "if (0 && (n6 == NULL || n6->cu.live != 1))"
            if old not in s:
                raise RuntimeError("preflight live predicate missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_nkeys_relax(data: bytes) -> bytes:
            # <1u → <0u: unsigned n_keys never fails lower bound.
            s = data.decode("utf-8")
            old = "n6->cu.n_keys < 1u || n6->cu.n_keys > NINLIL_N6_CU_PLAN_MAX_KEYS"
            new = "n6->cu.n_keys < 0u || n6->cu.n_keys > NINLIL_N6_CU_PLAN_MAX_KEYS"
            if old not in s:
                raise RuntimeError("n_keys bound missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_phase_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = (
                "n6->cu.phase != N6_CU_PHASE_NONE\n"
                "        && n6->cu.phase != N6_CU_PHASE_NEED_CLOSE_OLD\n"
                "        && n6->cu.phase != N6_CU_PHASE_NEED_OPEN\n"
                "        && n6->cu.phase != N6_CU_PHASE_READ_CLASSIFY"
            )
            new = (
                "n6->cu.phase != N6_CU_PHASE_NONE\n"
                "        && n6->cu.phase != N6_CU_PHASE_NEED_CLOSE_OLD\n"
                "        && n6->cu.phase != N6_CU_PHASE_NEED_OPEN"
            )
            if old not in s:
                raise RuntimeError("phase domain missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_pending_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = (
                "if (n6->cu.pending_install != 0 && n6->cu.pending_install != 1) {\n"
                "        return NINLIL_N6_CORRUPT;\n"
                "    }"
            )
            new = "/* pending_install boolean dropped */"
            if old not in s:
                raise RuntimeError("pending_install boolean missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_op_drop_delete(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = "if (e->op != N6_CU_OP_PUT && e->op != N6_CU_OP_DELETE)"
            new = "if (e->op != N6_CU_OP_PUT)"
            if old not in s:
                raise RuntimeError("op domain missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_preflight_klen_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            old = (
                "if (e->klen > NINLIL_N6_LANE_KEY_BYTES) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }"
            )
            new = "/* klen bound dropped */"
            if old not in s:
                raise RuntimeError("klen bound missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_validate_side_tx_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("validate bounds")
            region = s[p0:p1]
            old = (
                "if (s->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX) {\n"
                "                return NINLIL_N6_CORRUPT;\n"
                "            }"
            )
            new = "/* TX side check dropped */"
            if old not in region:
                raise RuntimeError("TX side check missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        def mut_validate_side_tx_if0_and(data: bytes) -> bytes:
            # Keep the desired side predicate text, but make the check dead.
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("validate bounds")
            region = s[p0:p1]
            old = "if (s->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX)"
            new = "if (0 && s->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX)"
            if old not in region:
                raise RuntimeError("TX side check missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        def mut_validate_key_memcmp_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            region = s[p0:p1]
            old = (
                "if (memcmp(e->key, canon_key, NINLIL_N6_LANE_KEY_BYTES) != 0) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }"
            )
            new = "/* key memcmp dropped */"
            if old not in region:
                raise RuntimeError("key memcmp missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        def mut_validate_post_u64_order_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            region = s[p0:p1]
            old = (
                "if (!(e->post_u64_b < e->post_u64_a)) {\n"
                "                return NINLIL_N6_CORRUPT;\n"
                "            }"
            )
            new = "/* post_u64 order dropped */"
            if old not in region:
                raise RuntimeError("post_u64 order missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        def mut_validate_slot_range_drop(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            region = s[p0:p1]
            old = (
                "if (e->slot_index >= n6->slot_count) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }"
            )
            new = "/* slot_index range dropped */"
            if old not in region:
                raise RuntimeError("slot range missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        # --- rule7b residual P2: complete live if-predicate pin co-update RED ---
        def _cu_val_repl(data: bytes, old: str, new: str, what: str) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("cu validate bounds")
            region = s[p0:p1]
            if old not in region:
                raise RuntimeError(f"{what} missing")
            return (s[:p0] + region.replace(old, new, 1) + s[p1:]).encode(
                "utf-8"
            )

        # Independent re-audit 7 minimal GREEN_FALSE reproductions (must RED):
        def mut_validate_op_old_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->op != N6_CU_OP_PUT || e->old_present != 1)",
                "if (0 && (e->op != N6_CU_OP_PUT || e->old_present != 1))",
                "op+old_present",
            )

        def mut_validate_vlen_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->old_vlen != NINLIL_N6_TX_VALUE_BYTES\n"
                "            || e->prop_vlen != NINLIL_N6_TX_VALUE_BYTES)",
                "if (0 && (e->old_vlen != NINLIL_N6_TX_VALUE_BYTES\n"
                "            || e->prop_vlen != NINLIL_N6_TX_VALUE_BYTES))",
                "exact 68B vlen",
            )

        def mut_validate_live_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->live == 0u)",
                "if (s->live != 0u)",
                "live==0",
            )

        def mut_validate_tx_old_decode_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_decode_n6tx_value(e->old_val, e->old_vlen, &old_tv)\n"
                "                != NINLIL_N6_CODEC_OK)",
                "if (ninlil_n6_decode_n6tx_value(e->old_val, e->old_vlen, &old_tv)\n"
                "                == NINLIL_N6_CODEC_OK)",
                "TX old decode",
            )

        def mut_validate_tx_binding_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(old_tv.binding_digest_prefix16, s->binding_digest32, 16u)\n"
                "                    != 0\n"
                "                || memcmp(prop_tv.binding_digest_prefix16, s->binding_digest32,\n"
                "                       16u)\n"
                "                    != 0)",
                "if (memcmp(old_tv.binding_digest_prefix16, s->binding_digest32, 16u)\n"
                "                    == 0\n"
                "                || memcmp(prop_tv.binding_digest_prefix16, s->binding_digest32,\n"
                "                       16u)\n"
                "                    == 0)",
                "TX binding",
            )

        def mut_validate_tx_ns_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(old_tv.ns_fingerprint12, s->ns_fingerprint12, 12u) != 0\n"
                "                || memcmp(prop_tv.ns_fingerprint12, s->ns_fingerprint12, 12u)\n"
                "                    != 0)",
                "if (memcmp(old_tv.ns_fingerprint12, s->ns_fingerprint12, 12u) == 0\n"
                "                || memcmp(prop_tv.ns_fingerprint12, s->ns_fingerprint12, 12u)\n"
                "                    == 0)",
                "TX ns",
            )

        def mut_validate_tx_value_side_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_tv.alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX\n"
                "                || prop_tv.alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX)",
                "if (old_tv.alloc_side == NINLIL_N6_ALLOC_OUTBOUND_TX\n"
                "                || prop_tv.alloc_side == NINLIL_N6_ALLOC_OUTBOUND_TX)",
                "TX value alloc_side",
            )

        # Remaining predicate groups: if0 / invert / drop / relax coverage.
        def mut_validate_post_filter_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->post != N6_CU_POST_TX_LIMIT && e->post != N6_CU_POST_RX_ACCEPT)",
                "if (0 && (e->post != N6_CU_POST_TX_LIMIT && e->post != N6_CU_POST_RX_ACCEPT))",
                "post filter",
            )

        def mut_validate_post_filter_drop(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->post != N6_CU_POST_TX_LIMIT && e->post != N6_CU_POST_RX_ACCEPT) {\n"
                "            continue;\n"
                "        }",
                "/* post filter dropped */",
                "post filter block",
            )

        def mut_validate_op_old_drop(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->op != N6_CU_OP_PUT || e->old_present != 1) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }",
                "/* op+old_present dropped */",
                "op+old_present block",
            )

        def mut_validate_op_old_relax(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->op != N6_CU_OP_PUT || e->old_present != 1)",
                "if (e->op != N6_CU_OP_PUT)",
                "op+old_present",
            )

        def mut_validate_vlen_drop(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->old_vlen != NINLIL_N6_TX_VALUE_BYTES\n"
                "            || e->prop_vlen != NINLIL_N6_TX_VALUE_BYTES) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }",
                "/* exact 68B vlen dropped */",
                "exact 68B vlen block",
            )

        def mut_validate_canary_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->canary0 != N6_CANARY || s->canary1 != N6_CANARY)",
                "if (s->canary0 == N6_CANARY || s->canary1 == N6_CANARY)",
                "canary",
            )

        def mut_validate_canary_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->canary0 != N6_CANARY || s->canary1 != N6_CANARY)",
                "if (0 && (s->canary0 != N6_CANARY || s->canary1 != N6_CANARY))",
                "canary",
            )

        def mut_validate_live_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->live == 0u)",
                "if (0 && s->live == 0u)",
                "live==0",
            )

        def mut_validate_side_rx_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX)",
                "if (0 && s->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX)",
                "RX slot side",
            )

        def mut_validate_side_rx_drop(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX) {\n"
                "                return NINLIL_N6_CORRUPT;\n"
                "            }",
                "/* RX side check dropped */",
                "RX slot side block",
            )

        def mut_validate_side_tx_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (s->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX)",
                "if (s->alloc_side == NINLIL_N6_ALLOC_OUTBOUND_TX)",
                "TX slot side",
            )

        def mut_validate_slot_range_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (e->slot_index >= n6->slot_count)",
                "if (0 && e->slot_index >= n6->slot_count)",
                "slot_index range",
            )

        def mut_validate_lane_idx_eq_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if ((int)e->lane_idx != expected)",
                "if ((int)e->lane_idx == expected)",
                "lane_idx==expected",
            )

        def mut_validate_encode_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_encode_lane_key(\n"
                "                &lk, canon_key, sizeof(canon_key), &canon_klen)\n"
                "            != NINLIL_N6_CODEC_OK)",
                "if (ninlil_n6_encode_lane_key(\n"
                "                &lk, canon_key, sizeof(canon_key), &canon_klen)\n"
                "            == NINLIL_N6_CODEC_OK)",
                "encode",
            )

        def mut_validate_encode_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_encode_lane_key(\n"
                "                &lk, canon_key, sizeof(canon_key), &canon_klen)\n"
                "            != NINLIL_N6_CODEC_OK)",
                "if (0 && ninlil_n6_encode_lane_key(\n"
                "                &lk, canon_key, sizeof(canon_key), &canon_klen)\n"
                "            != NINLIL_N6_CODEC_OK)",
                "encode",
            )

        def mut_validate_canon_klen_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (canon_klen != NINLIL_N6_LANE_KEY_BYTES\n"
                "            || e->klen != NINLIL_N6_LANE_KEY_BYTES)",
                "if (0 && (canon_klen != NINLIL_N6_LANE_KEY_BYTES\n"
                "            || e->klen != NINLIL_N6_LANE_KEY_BYTES))",
                "canonical key length",
            )

        def mut_validate_canon_klen_drop(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (canon_klen != NINLIL_N6_LANE_KEY_BYTES\n"
                "            || e->klen != NINLIL_N6_LANE_KEY_BYTES) {\n"
                "            return NINLIL_N6_CORRUPT;\n"
                "        }",
                "/* canonical key length dropped */",
                "canonical key length block",
            )

        def mut_validate_key_memcmp_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(e->key, canon_key, NINLIL_N6_LANE_KEY_BYTES) != 0)",
                "if (0 && memcmp(e->key, canon_key, NINLIL_N6_LANE_KEY_BYTES) != 0)",
                "key memcmp",
            )

        def mut_validate_key_memcmp_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(e->key, canon_key, NINLIL_N6_LANE_KEY_BYTES) != 0)",
                "if (memcmp(e->key, canon_key, NINLIL_N6_LANE_KEY_BYTES) == 0)",
                "key memcmp",
            )

        def mut_validate_tx_prop_decode_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_decode_n6tx_value(e->prop_val, e->prop_vlen, &prop_tv)\n"
                "                != NINLIL_N6_CODEC_OK)",
                "if (ninlil_n6_decode_n6tx_value(e->prop_val, e->prop_vlen, &prop_tv)\n"
                "                == NINLIL_N6_CODEC_OK)",
                "TX prop decode",
            )

        def mut_validate_tx_keygen_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_tv.key_generation != s->key_generation\n"
                "                || prop_tv.key_generation != s->key_generation)",
                "if (old_tv.key_generation == s->key_generation\n"
                "                || prop_tv.key_generation == s->key_generation)",
                "TX key_generation",
            )

        def mut_validate_tx_epoch_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_tv.membership_epoch != s->membership_epoch\n"
                "                || prop_tv.membership_epoch != s->membership_epoch)",
                "if (old_tv.membership_epoch == s->membership_epoch\n"
                "                || prop_tv.membership_epoch == s->membership_epoch)",
                "TX membership_epoch",
            )

        def mut_validate_tx_post_u64_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_tv.reserved_exclusive != e->post_u64_b\n"
                "                || prop_tv.reserved_exclusive != e->post_u64_a)",
                "if (old_tv.reserved_exclusive == e->post_u64_b\n"
                "                || prop_tv.reserved_exclusive == e->post_u64_a)",
                "TX post_u64 exclusive",
            )

        def mut_validate_tx_post_u64_order_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (!(e->post_u64_b < e->post_u64_a))",
                "if ((e->post_u64_b < e->post_u64_a))",
                "TX post_u64 order",
            )

        def mut_validate_rx_old_decode_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_decode_n6rx_value(e->old_val, e->old_vlen, &old_rv)\n"
                "                != NINLIL_N6_CODEC_OK)",
                "if (ninlil_n6_decode_n6rx_value(e->old_val, e->old_vlen, &old_rv)\n"
                "                == NINLIL_N6_CODEC_OK)",
                "RX old decode",
            )

        def mut_validate_rx_prop_decode_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (ninlil_n6_decode_n6rx_value(e->prop_val, e->prop_vlen, &prop_rv)\n"
                "                != NINLIL_N6_CODEC_OK)",
                "if (ninlil_n6_decode_n6rx_value(e->prop_val, e->prop_vlen, &prop_rv)\n"
                "                == NINLIL_N6_CODEC_OK)",
                "RX prop decode",
            )

        def mut_validate_rx_keygen_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_rv.key_generation != s->key_generation\n"
                "                || prop_rv.key_generation != s->key_generation)",
                "if (old_rv.key_generation == s->key_generation\n"
                "                || prop_rv.key_generation == s->key_generation)",
                "RX key_generation",
            )

        def mut_validate_rx_binding_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(old_rv.binding_digest_prefix16, s->binding_digest32, 16u)\n"
                "                    != 0\n"
                "                || memcmp(prop_rv.binding_digest_prefix16, s->binding_digest32,\n"
                "                       16u)\n"
                "                    != 0)",
                "if (memcmp(old_rv.binding_digest_prefix16, s->binding_digest32, 16u)\n"
                "                    == 0\n"
                "                || memcmp(prop_rv.binding_digest_prefix16, s->binding_digest32,\n"
                "                       16u)\n"
                "                    == 0)",
                "RX binding",
            )

        def mut_validate_rx_epoch_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_rv.membership_epoch != s->membership_epoch\n"
                "                || prop_rv.membership_epoch != s->membership_epoch)",
                "if (old_rv.membership_epoch == s->membership_epoch\n"
                "                || prop_rv.membership_epoch == s->membership_epoch)",
                "RX membership_epoch",
            )

        def mut_validate_rx_ns_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (memcmp(old_rv.ns_fingerprint12, s->ns_fingerprint12, 12u) != 0\n"
                "                || memcmp(prop_rv.ns_fingerprint12, s->ns_fingerprint12, 12u)\n"
                "                    != 0)",
                "if (memcmp(old_rv.ns_fingerprint12, s->ns_fingerprint12, 12u) == 0\n"
                "                || memcmp(prop_rv.ns_fingerprint12, s->ns_fingerprint12, 12u)\n"
                "                    == 0)",
                "RX ns",
            )

        def mut_validate_rx_value_side_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_rv.alloc_side != NINLIL_N6_ALLOC_INBOUND_RX\n"
                "                || prop_rv.alloc_side != NINLIL_N6_ALLOC_INBOUND_RX)",
                "if (old_rv.alloc_side == NINLIL_N6_ALLOC_INBOUND_RX\n"
                "                || prop_rv.alloc_side == NINLIL_N6_ALLOC_INBOUND_RX)",
                "RX value alloc_side",
            )

        def mut_validate_rx_post_u64_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (prop_rv.accept_reserved_through != e->post_u64_a\n"
                "                || e->post_u64_b != 0u)",
                "if (prop_rv.accept_reserved_through == e->post_u64_a\n"
                "                || e->post_u64_b == 0u)",
                "RX post_u64",
            )

        def mut_validate_rx_order_invert(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_rv.accept_reserved_through\n"
                "                > prop_rv.accept_reserved_through)",
                "if (old_rv.accept_reserved_through\n"
                "                < prop_rv.accept_reserved_through)",
                "RX order",
            )

        def mut_validate_rx_order_if0(data: bytes) -> bytes:
            return _cu_val_repl(
                data,
                "if (old_rv.accept_reserved_through\n"
                "                > prop_rv.accept_reserved_through)",
                "if (0 && old_rv.accept_reserved_through\n"
                "                > prop_rv.accept_reserved_through)",
                "RX order",
            )

        def mut_validate_post_tx_branch_invert(data: bytes) -> bytes:
            # Both TX branch selectors (slot-side + decode/identity) must flip;
            # a single-site invert leaves the other live pin and stays GREEN.
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            if p0 < 0 or p1 < 0:
                raise RuntimeError("cu validate bounds")
            region = s[p0:p1]
            old = "if (e->post == N6_CU_POST_TX_LIMIT)"
            new = "if (e->post != N6_CU_POST_TX_LIMIT)"
            if region.count(old) < 2:
                raise RuntimeError("post TX branch sites missing")
            return (s[:p0] + region.replace(old, new) + s[p1:]).encode("utf-8")

        def mut_recover_preflight_after_open(data: bytes) -> bytes:
            # Move first preflight if after n6_cu_open_storage (order RED).
            s = data.decode("utf-8")
            sig = "ninlil_n6_status_t ninlil_n6_recover_cu("
            p0 = s.find(sig)
            if p0 < 0:
                raise RuntimeError("recover_cu missing")
            # Extract function body roughly via next top-level-ish marker.
            p1 = s.find("static n6_slot_t *n6_find_handle(", p0)
            if p1 < 0:
                p1 = s.find("/* Free slot:", p0)
            region = s[p0:p1] if p1 > 0 else s[p0:]
            guard = "if (n6_cu_preflight_plan(n6) != NINLIL_N6_OK)"
            open_call = "st = n6_cu_open_storage(n6);"
            g = region.find(guard)
            o = region.find(open_call)
            if g < 0 or o < 0 or g >= o:
                raise RuntimeError("preflight/open order not as expected")
            # Find preflight if-block end
            brace = region.find("{", g)
            depth = 0
            j = brace
            while j < len(region):
                if region[j] == "{":
                    depth += 1
                elif region[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            block = region[g : j + 1]
            region2 = region[:g] + "/* preflight moved */" + region[j + 1 :]
            # Re-insert after open_call line
            o2 = region2.find(open_call)
            if o2 < 0:
                raise RuntimeError("open lost after move")
            insert_at = o2 + len(open_call)
            region2 = region2[:insert_at] + "\n        " + block + region2[insert_at:]
            end = p1 if p1 > 0 else len(s)
            return (s[:p0] + region2 + s[end:]).encode("utf-8")

        def mut_cu_drop_key_encode(data: bytes) -> bytes:
            s = data.decode("utf-8")
            if "ninlil_n6_encode_lane_key" not in s:
                raise RuntimeError("encode_lane_key missing")
            # Only strip from validate body
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            region = s[p0:p1]
            if "ninlil_n6_encode_lane_key" not in region:
                raise RuntimeError("validate encode missing")
            region2 = region.replace(
                "ninlil_n6_encode_lane_key", "ninlil_n6_encode_lane_key_REMOVED", 1
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_cu_drop_tx_decode(data: bytes) -> bytes:
            s = data.decode("utf-8")
            sig = "static ninlil_n6_status_t n6_cu_validate_array_posts("
            p0 = s.find(sig)
            p1 = s.find("/* Force-close once", p0)
            region = s[p0:p1]
            if "ninlil_n6_decode_n6tx_value" not in region:
                raise RuntimeError("tx decode missing")
            region2 = region.replace(
                "ninlil_n6_decode_n6tx_value",
                "ninlil_n6_decode_n6tx_value_REMOVED",
                1,
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        def mut_lane_idx_ack_to_2(data: bytes) -> bytes:
            # ACK mapping return 1 → 2 (exact semantic RED).
            s = data.decode("utf-8")
            sig = "static int n6_lane_idx("
            p0 = s.rfind(sig)
            if p0 < 0:
                raise RuntimeError("n6_lane_idx missing")
            brace = s.find("{", p0)
            depth = 0
            j = brace
            while j < len(s):
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            region = s[p0 : j + 1]
            # Only change ACK branch return 1, not other returns.
            ack = "if (lane_kind == NINLIL_N6_LANE_HOP_ACK)"
            a = region.find(ack)
            if a < 0:
                raise RuntimeError("ACK if missing")
            r = region.find("return 1;", a)
            if r < 0:
                raise RuntimeError("ACK return 1 missing")
            region2 = region[:r] + "return 2;" + region[r + len("return 1;") :]
            return (s[:p0] + region2 + s[j + 1 :]).encode("utf-8")

        def mut_lane_idx_swap_returns(data: bytes) -> bytes:
            # Swap DATA/E2E return 0 with ACK return 1 (branch association RED).
            # Independent counts of predicates/returns still look "complete".
            s = data.decode("utf-8")
            sig = "static int n6_lane_idx("
            p0 = s.rfind(sig)
            if p0 < 0:
                raise RuntimeError("n6_lane_idx missing")
            brace = s.find("{", p0)
            depth = 0
            j = brace
            while j < len(s):
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            region = s[p0 : j + 1]
            data_if = "if (lane_kind == NINLIL_N6_LANE_HOP_DATA"
            ack = "if (lane_kind == NINLIL_N6_LANE_HOP_ACK)"
            d = region.find(data_if)
            a = region.find(ack)
            if d < 0 or a < 0:
                raise RuntimeError("lane_idx ifs missing")
            r0 = region.find("return 0;", d)
            r1 = region.find("return 1;", a)
            if r0 < 0 or r1 < 0 or r0 >= a:
                raise RuntimeError("lane_idx return association missing")
            # Place holders then swap.
            region2 = region.replace("return 0;", "return __SWAP1__;", 1)
            region2 = region2.replace("return 1;", "return 0;", 1)
            region2 = region2.replace("return __SWAP1__;", "return 1;", 1)
            if region2 == region:
                raise RuntimeError("swap did not change")
            return (s[:p0] + region2 + s[j + 1 :]).encode("utf-8")

        def mut_lane_ok_hop_add_e2e(data: bytes) -> bytes:
            # Expand HOP predicate to admit E2E (exact predicate RED).
            s = data.decode("utf-8")
            old = (
                "return lane_kind == NINLIL_N6_LANE_HOP_DATA\n"
                "            || lane_kind == NINLIL_N6_LANE_HOP_ACK;"
            )
            new = (
                "return lane_kind == NINLIL_N6_LANE_HOP_DATA\n"
                "            || lane_kind == NINLIL_N6_LANE_HOP_ACK\n"
                "            || lane_kind == NINLIL_N6_LANE_E2E;"
            )
            if old not in s:
                raise RuntimeError("HOP return form missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_static_assert_or_1(data: bytes) -> bytes:
            # 1 || original_expr — tautology false-green.
            s = data.decode("utf-8")
            old = (
                "(sizeof(((n6_slot_t *)0)->rx_boot_floor) / sizeof(uint64_t))\n"
                "        == (size_t)N6_PRIVATE_NAMED_LANE_COUNT"
            )
            new = (
                "1 || (sizeof(((n6_slot_t *)0)->rx_boot_floor) / sizeof(uint64_t))\n"
                "        == (size_t)N6_PRIVATE_NAMED_LANE_COUNT"
            )
            if old not in s:
                raise RuntimeError("boot_floor static assert expr missing")
            return s.replace(old, new, 1).encode("utf-8")

        def mut_markers_into_string(data: bytes) -> bytes:
            # Move required live range guard into a string only (lexical mask RED).
            s = data.decode("utf-8")
            sig = "static int n6_rx_precheck_window("
            p0 = s.find(sig)
            p1 = s.find("ninlil_n6_status_t ninlil_n6_rx_precheck(", p0)
            region = s[p0:p1]
            guard = "if (!n6_lane_idx_in_range(idx))"
            if guard not in region:
                raise RuntimeError("window guard missing")
            # Replace live guard with always-false if + stash text in a string.
            region2 = region.replace(
                guard,
                'static const char *const _fake = "if (!n6_lane_idx_in_range(idx))";\n'
                "    if (0)",
                1,
            )
            return (s[:p0] + region2 + s[p1:]).encode("utf-8")

        structural_mutators = (
            ("struct_window_order_reverse", mut_window_order_reverse),
            ("struct_window_cond_relax", mut_window_cond_zero),
            ("struct_precheck_cond_invert", mut_precheck_cond_invert),
            ("struct_tx_order_reverse", mut_tx_order_reverse),
            ("struct_admit_drop_fence_return", mut_admit_drop_fence_return),
            ("struct_admit_layer_relax", mut_admit_layer_relax),
            ("struct_bare3_dimension", mut_bare_3_dimension),
            ("struct_drop_static_assert", mut_drop_static_assert_boot),
            ("struct_drop_cu_validate", mut_drop_cu_validate),
            ("struct_cu_bare3", mut_cu_bare3),
            # Independent audit GREEN_FALSE + pin co-update must RED:
            ("struct_in_range_ge_minus1", mut_in_range_ge_minus1),
            ("struct_lane_ok_default_return1", mut_lane_ok_default_return1),
            ("struct_static_assert_comment_only", mut_static_assert_comment_only),
            ("struct_precheck_guard_into_if0", mut_precheck_guard_into_if0),
            ("struct_cu_validate_if0_and", mut_cu_validate_if0_and),
            ("struct_cu_range_if0_and", mut_cu_range_if0_and),
            ("struct_cu_layer_if0_and", mut_cu_layer_if0_and),
            ("struct_guard_into_if0", mut_guard_into_if0),
            ("struct_cu_preflight_if0_and", mut_cu_preflight_if0_and),
            ("struct_cu_drop_key_encode", mut_cu_drop_key_encode),
            ("struct_cu_drop_tx_decode", mut_cu_drop_tx_decode),
            # Exact semantic / predicate / assert / lexical mask RED:
            ("struct_lane_idx_ack_to_2", mut_lane_idx_ack_to_2),
            ("struct_lane_idx_swap_returns", mut_lane_idx_swap_returns),
            ("struct_lane_ok_hop_add_e2e", mut_lane_ok_hop_add_e2e),
            ("struct_static_assert_or_1", mut_static_assert_or_1),
            ("struct_markers_into_string", mut_markers_into_string),
            # P1 recover true-no-CU + CU preflight/validate exact-predicate RED
            # (pin co-update must not greenwash OR-bypass / relax / drop):
            ("struct_recover_no_cu_or", mut_recover_no_cu_or),
            ("struct_recover_no_cu_live_only", mut_recover_no_cu_live_only),
            ("struct_recover_no_cu_nkeys_only", mut_recover_no_cu_nkeys_only),
            ("struct_recover_no_cu_if0_and", mut_recover_no_cu_if0_and),
            ("struct_recover_preflight_after_open", mut_recover_preflight_after_open),
            ("struct_preflight_live_relax", mut_preflight_live_relax),
            ("struct_preflight_live_if0_and", mut_preflight_live_if0_and),
            ("struct_preflight_nkeys_relax", mut_preflight_nkeys_relax),
            ("struct_preflight_phase_drop", mut_preflight_phase_drop),
            ("struct_preflight_pending_drop", mut_preflight_pending_drop),
            ("struct_preflight_op_drop_delete", mut_preflight_op_drop_delete),
            ("struct_preflight_klen_drop", mut_preflight_klen_drop),
            ("struct_validate_side_tx_drop", mut_validate_side_tx_drop),
            ("struct_validate_side_tx_if0_and", mut_validate_side_tx_if0_and),
            ("struct_validate_slot_range_drop", mut_validate_slot_range_drop),
            ("struct_validate_key_memcmp_drop", mut_validate_key_memcmp_drop),
            ("struct_validate_post_u64_order_drop", mut_validate_post_u64_order_drop),
            # rule7b residual P2: full live if-predicate pin co-update RED
            # (independent re-audit 7 minimal + remaining predicate groups):
            ("struct_validate_op_old_if0", mut_validate_op_old_if0),
            ("struct_validate_vlen_if0", mut_validate_vlen_if0),
            ("struct_validate_live_invert", mut_validate_live_invert),
            ("struct_validate_tx_old_decode_invert", mut_validate_tx_old_decode_invert),
            ("struct_validate_tx_binding_invert", mut_validate_tx_binding_invert),
            ("struct_validate_tx_ns_invert", mut_validate_tx_ns_invert),
            ("struct_validate_tx_value_side_invert", mut_validate_tx_value_side_invert),
            ("struct_validate_post_filter_if0", mut_validate_post_filter_if0),
            ("struct_validate_post_filter_drop", mut_validate_post_filter_drop),
            ("struct_validate_op_old_drop", mut_validate_op_old_drop),
            ("struct_validate_op_old_relax", mut_validate_op_old_relax),
            ("struct_validate_vlen_drop", mut_validate_vlen_drop),
            ("struct_validate_canary_invert", mut_validate_canary_invert),
            ("struct_validate_canary_if0", mut_validate_canary_if0),
            ("struct_validate_live_if0", mut_validate_live_if0),
            ("struct_validate_side_rx_if0", mut_validate_side_rx_if0),
            ("struct_validate_side_rx_drop", mut_validate_side_rx_drop),
            ("struct_validate_side_tx_invert", mut_validate_side_tx_invert),
            ("struct_validate_slot_range_if0", mut_validate_slot_range_if0),
            ("struct_validate_lane_idx_eq_invert", mut_validate_lane_idx_eq_invert),
            ("struct_validate_encode_invert", mut_validate_encode_invert),
            ("struct_validate_encode_if0", mut_validate_encode_if0),
            ("struct_validate_canon_klen_if0", mut_validate_canon_klen_if0),
            ("struct_validate_canon_klen_drop", mut_validate_canon_klen_drop),
            ("struct_validate_key_memcmp_if0", mut_validate_key_memcmp_if0),
            ("struct_validate_key_memcmp_invert", mut_validate_key_memcmp_invert),
            ("struct_validate_tx_prop_decode_invert", mut_validate_tx_prop_decode_invert),
            ("struct_validate_tx_keygen_invert", mut_validate_tx_keygen_invert),
            ("struct_validate_tx_epoch_invert", mut_validate_tx_epoch_invert),
            ("struct_validate_tx_post_u64_invert", mut_validate_tx_post_u64_invert),
            ("struct_validate_tx_post_u64_order_invert", mut_validate_tx_post_u64_order_invert),
            ("struct_validate_rx_old_decode_invert", mut_validate_rx_old_decode_invert),
            ("struct_validate_rx_prop_decode_invert", mut_validate_rx_prop_decode_invert),
            ("struct_validate_rx_keygen_invert", mut_validate_rx_keygen_invert),
            ("struct_validate_rx_binding_invert", mut_validate_rx_binding_invert),
            ("struct_validate_rx_epoch_invert", mut_validate_rx_epoch_invert),
            ("struct_validate_rx_ns_invert", mut_validate_rx_ns_invert),
            ("struct_validate_rx_value_side_invert", mut_validate_rx_value_side_invert),
            ("struct_validate_rx_post_u64_invert", mut_validate_rx_post_u64_invert),
            ("struct_validate_rx_order_invert", mut_validate_rx_order_invert),
            ("struct_validate_rx_order_if0", mut_validate_rx_order_if0),
            ("struct_validate_post_tx_branch_invert", mut_validate_post_tx_branch_invert),
        )
        for st_name, mutator in structural_mutators:
            _co_update_store(st_name, mutator)

        # --- Direct _mask_c_lexical unit checks (not structural mutation count) ---
        sample = (
            "int x; // line comment keep\n"
            "/* block\ncomment */ int y;\n"
            'const char *s = "quote\\"in";\n'
            "char c = '\\'';\n"
            "if (x) { y = 1; }\n"
        )
        masked = g._mask_c_lexical(sample)
        if len(masked) != len(sample):
            fail(
                f"mask_c_lexical length mismatch: {len(masked)} vs {len(sample)}"
            )
        else:
            ok("mask_c_lexical length-preserving")
        if "line comment" in masked or "block" in masked.replace("\n", ""):
            # comment text must be blanked (spaces), not present as words
            if "comment" in masked and "line comment keep" in masked:
                fail("mask_c_lexical left line comment text")
            elif "block" in masked and "comment */" in sample and "*/" not in masked:
                # check comments blanked: non-newline comment chars are spaces
                pass
        # Explicit: comment content positions become spaces
        if "// line" in sample:
            idx = sample.index("//")
            if not all(masked[i] in " \n" for i in range(idx, sample.index("\n", idx))):
                fail("mask_c_lexical did not blank line comment")
            else:
                ok("mask_c_lexical blanks line comment")
        if "/*" in sample:
            b0 = sample.index("/*")
            b1 = sample.index("*/") + 2
            if not all(masked[i] in " \n" for i in range(b0, b1)):
                fail("mask_c_lexical did not blank block comment")
            else:
                ok("mask_c_lexical blanks block comment")
        # String with escaped quote must be fully blanked including escapes
        sq = sample.index('"')
        # find closing quote after escape
        sq_end = sample.index('";', sq)
        if not all(masked[i] == " " for i in range(sq, sq_end + 1)):
            fail("mask_c_lexical did not blank escaped string")
        else:
            ok("mask_c_lexical blanks escaped string")
        # Char with escaped quote
        cq = sample.index("char c")
        cq0 = sample.index("'", cq)
        cq1 = sample.index("';", cq0)
        if not all(masked[i] == " " for i in range(cq0, cq1 + 1)):
            fail("mask_c_lexical did not blank escaped char")
        else:
            ok("mask_c_lexical blanks escaped char")
        # Live tokens remain; string-only tokens must not.
        if "if" not in masked or "{" not in masked or "}" not in masked:
            fail("mask_c_lexical removed live brace/token code")
        else:
            ok("mask_c_lexical keeps live brace/paren/tokens")
        # Newlines preserved at same indices
        if [i for i, c in enumerate(sample) if c == "\n"] != [
            i for i, c in enumerate(masked) if c == "\n"
        ]:
            fail("mask_c_lexical newline positions changed")
        else:
            ok("mask_c_lexical preserves newline positions")

    # Structural RED mutations: 85 (43 prior + 42 rule7b complete-predicate pins).
    _STRUCT_RED_N = 85
    elapsed = time.perf_counter() - t0
    if fails:
        print(
            f"n6_storage_callsite_gate self-test: FAIL ({fails}) "
            f"in {elapsed:.3f}s [ok={ok_n} red_ok={red_n}]"
        )
        return 1
    print(
        "n6_storage_callsite_gate self-test: OK "
        f"in {elapsed:.3f}s "
        f"[authority=accepted SHA-256 pin + brace-aware rx-index structural; "
        f"pinned_paths={len(g.ACCEPTED_SOURCE_MANIFEST)}; "
        f"RED_cases≈{red_n}; GREEN_keep=real+simultaneous; "
        f"known_false_green_byte_RED={len(KNOWN_FALSE_GREEN_MUTATIONS)}; "
        f"rx_index_structural_RED={_STRUCT_RED_N}; "
        f"mask_c_lexical_direct_OK; "
        f"no compiler fixtures as authority; "
        f"PASS is not C semantic proof / human review / product GO]"
    )
    return 0
