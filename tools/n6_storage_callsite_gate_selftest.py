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

    # Counts for summary (honest).
    # RED cases: 3 single-byte + 9 manifest/file/docs mismatches +
    # 2 one-sided pin updates + 5 policy cases (including the
    # authority-forbidden store override) + 8 historical false-greens
    # = 3 + 9 + 2 + 5 + 8 = 27 designed RED cases.
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
        f"[authority=accepted SHA-256 pin; "
        f"pinned_paths={len(g.ACCEPTED_SOURCE_MANIFEST)}; "
        f"RED_cases≈{red_n}; GREEN_keep=real+simultaneous; "
        f"known_false_green_byte_RED={len(KNOWN_FALSE_GREEN_MUTATIONS)}; "
        f"no compiler fixtures as authority; "
        f"PASS is not C semantic proof / human review / product GO]"
    )
    return 0
