#!/usr/bin/env python3
"""R5 LAB_ONLY profile loader structural + semantic gate + mutation self-test."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC29 = "docs/29-r5-lab-only-profile-loader.md"
ADR9 = "docs/adr/0009-r5-lab-only-profile-loader.md"
# R4 owns docs/28 + ADR-0008 — R5 must not reclaim those numbers.
DOC07 = "docs/07-testing-and-quality.md"
DOC09 = "docs/09-roadmap.md"
DOC23 = "docs/23-usb-radio-boundary.md"
HDR = "src/radio/profile_loader.h"
SRC = "src/radio/profile_loader.c"
PRIVATE = "cmake/ninlil_runtime_private_sources.cmake"
TEST = "tests/radio/profile_r5_test.c"
PUBLIC_RUNTIME = "include/ninlil/runtime.h"
CMAKELISTS = "CMakeLists.txt"


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read(root: pathlib.Path, rel: str) -> str:
    p = root / rel
    if not p.is_file():
        fail(f"missing {rel}")
    return p.read_text(encoding="utf-8")


def check_docs(root: pathlib.Path) -> None:
    doc = read(root, DOC29)
    adr = read(root, ADR9)
    need = [
        "SEMANTIC: R5_HOST_CANDIDATE_ONLY",
        "SEMANTIC: LAB_ONLY_FAIL_CLOSED",
        "SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME",
        "SEMANTIC: NO_JAPAN_PRODUCTION_NUMERIC_CLAIM",
        "SEMANTIC: R2_DURABLE_SCHEMA1_UNCHANGED",
        "SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY",
        "SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC",
        "LAB_ONLY",
        "controller_term",
        "assignment_digest",
        "permit_bind_generation",
        "SiteAssignment",
        "frame_digest_algorithm",
        "R2_ASSIGNMENT_GENERATION_SYNC",
        "Japan",
        "re-review GO",
        "FIELD",
        "docs/29",
        "ADR-0009",
    ]
    for tok in need:
        if tok not in doc and tok not in adr:
            fail(f"docs missing {tok}")
    if "Accepted" not in adr:
        fail("ADR-0009 must be Accepted")
    if re.search(r"R5 complete|FIELD production ready|Japan production numeric", doc + adr, re.I):
        # allow "not" claims only
        for bad in (
            "R5 complete である",
            "FIELD 完成",
            "Japan production RegulatoryProfile 数値を確定",
        ):
            if bad in doc or bad in adr:
                fail(f"forbidden completion claim: {bad}")
    # must explicitly nonclaim
    for tok in (
        "R5 complete ではない",
        "FIELD / PRODUCTION",
        "Japan",
    ):
        if tok not in doc:
            fail(f"docs/29 must nonclaim with {tok!r}")

    d7 = read(root, DOC07)
    if "profile_r5" not in d7:
        fail("docs/07 must document profile_r5")
    d9 = read(root, DOC09)
    if "R5" not in d9 or "LAB_ONLY" not in d9:
        fail("docs/09 must mention R5 LAB_ONLY")
    d23 = read(root, DOC23)
    if "profile_loader" not in d23 and "R5" not in d23:
        fail("docs/23 must still catalog R5")


def check_source(root: pathlib.Path) -> None:
    h = read(root, HDR)
    c = read(root, SRC)
    pcp_h = read(root, "src/radio/pcp_authority.h")
    pcp_c = read(root, "src/radio/pcp_authority.c")
    priv = read(root, PRIVATE)
    test = read(root, TEST)
    cm = read(root, CMAKELISTS)
    pub = read(root, PUBLIC_RUNTIME)
    blob = h + c + pcp_h + pcp_c

    for tok in (
        "SEMANTIC: R5_HOST_CANDIDATE_ONLY",
        "SEMANTIC: LAB_ONLY_FAIL_CLOSED",
        "SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME",
        "SEMANTIC: NO_JAPAN_PRODUCTION_NUMERIC_CLAIM",
        "SEMANTIC: R2_DURABLE_SCHEMA1_UNCHANGED",
        "SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY",
        "SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC",
        "NINLIL_R5_APPROVAL_LAB_ONLY",
        "ninlil_r5_issue",
        "ninlil_r5_compose_issue_bind",
        "ninlil_r5_issue_with_bind",
        "ninlil_r5_permit_validate",
        "ninlil_r5_permit_consume",
        "ninlil_pcp_commit_live_binding",
        "ninlil_pcp_set_assignment_generation",
        "ninlil_pcp_get_assignment_generation",
        "SEMANTIC: COMMIT_LIVE_SAME_GEN_EXACT_ONLY",
        "same_gen_live",
        "controller_term",
        "assignment_digest",
        "permit_bind_generation",
        "NINLIL_R5_BIND_FRAME_DIGEST_ALG",
    ):
        if tok not in blob:
            fail(f"source missing {tok}")
    if "ninlil_pcp_commit_live_binding" not in c:
        fail("R5 must call ninlil_pcp_commit_live_binding")
    if "docs/28-r5" in h or "docs/28-r5" in c or "ADR-0008" in h or "ADR-0008" in c:
        fail("R5 must not reference docs/28 or ADR-0008 (R4 namespace)")
    if "docs/29-r5" not in h and "docs/29-r5" not in c:
        fail("R5 sources must cite docs/29")

    if "profile_loader.c" not in priv:
        fail("private sources must list profile_loader.c")
    if priv.count("profile_loader.c") < 2:
        fail("profile_loader.c must be in both private lists")
    if "profile_r5" not in cm or "ninlil_profile_r5_test" not in cm:
        fail("CMakeLists must wire profile_r5")
    if "static int test_full_bind_mismatch_matrix(void)" not in test:
        fail("test must include full bind mismatch matrix")
    if "test_full_bind_mismatch_matrix()" not in test:
        fail("main must call full bind mismatch matrix")
    if "static int test_issue_bind_mismatch_matrix(void)" not in test:
        fail("test must include issue-time bind mismatch matrix")
    if "test_issue_bind_mismatch_matrix()" not in test:
        fail("main must call issue-time bind mismatch matrix")
    if "profile_r5_golden_profiles.h" not in test:
        fail("tests must include profile_r5_golden_profiles.h")
    if "k_r5_golden_hw_v1" not in test:
        fail("tests must reference k_r5_golden_hw_v1")
    if "k_r5_golden_reg_v1" not in test:
        fail("tests must reference k_r5_golden_reg_v1")
    if "(void)memcpy(e->hw_doc, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES);" not in test:
        fail("env_setup must load golden HW fixture by name")
    if "(void)memcpy(e->reg_doc, k_r5_golden_reg_v1, NINLIL_R5_REG_DOC_BYTES);" not in test:
        fail("env_setup must load golden REG fixture by name")
    # effective/expiry operator correctness is enforced by runtime mutation
    # self-tests (token-only check is insufficient).
    if "test_activate_assignment_channel_phy_revalidate()" not in test:
        fail("main must call activate assignment channel/PHY revalidate test")
    if "test_issue_profile_effective_expiry_boundaries()" not in test:
        fail("main must call issue profile effective/expiry boundary test")
    if "assign_ch" not in c or "assign_phy" not in c:
        fail("activate must distinct CHANNEL vs PHY diagnostics for assignment REG")
    if "NINLIL_R5_BIND_CHANNEL" not in c or "NINLIL_R5_BIND_PHY" not in c:
        fail("activate assignment revalidate must set BIND_CHANNEL and BIND_PHY")
    if "NAME profile_r5_golden_oracle\n" not in cm and "NAME profile_r5_golden_oracle\r\n" not in cm:
        # exact CTest name line (not *_DISABLED)
        if not re.search(r"NAME profile_r5_golden_oracle\s*$", cm, re.M):
            fail("CMakeLists must register profile_r5_golden_oracle CTest")
    oracle = read(root, "tools/profile_r5_golden_oracle.py")
    # Anchors match reconstruct+byte-identical oracle (not legacy field-only fail strings).
    for tok in (
        "def reconstruct_hw",
        "def reconstruct_reg",
        "HW_PROFILE_ID = id_pattern(0x10)",
        "DEVICE_MODEL_ID = id_pattern(0x11)",
        "RADIO_SKU_ID = id_pattern(0x12)",
        "ANTENNA_MODEL_ID = id_pattern(0x13)",
        "REG_PROFILE_ID = id_pattern(0x20)",
        "REGION_CODE = 0x4C4142",
        "SERVICE_CATEGORY = 1",
        "committed_hw != expect_hw",
        "committed_reg != expect_reg",
        "hw array not byte-identical to reconstructed golden",
        "reg array not byte-identical to reconstructed golden",
        "K_R5_GOLDEN_HW_CRC32 mismatch",
        "K_R5_GOLDEN_REG_CRC32 mismatch",
    ):
        if tok not in oracle:
            fail(f"golden oracle missing reconstruct-oracle token: {tok}")
    for legacy in (
        'fail("hw profile_id exact")',
        'fail("reg profile_id exact")',
        'fail("device_model_id exact")',
        'fail("radio_sku_id exact")',
        'fail("antenna_model_id exact")',
    ):
        if legacy in oracle:
            fail(f"oracle still has legacy anchor {legacy!r}; sync to reconstruct style")
    if not re.search(r"NAME profile_r5_golden_oracle\s*$", cm, re.M):
        fail("CMake must wire profile_r5_golden_oracle test by name")
    if "test_dynamic_rebind_e2e()" not in test:
        fail("main must call dynamic rebind e2e")
    if "test_r2_assignment_generation_sync()" not in test:
        fail("main must call R2 generation sync test")
    if "test_permit_out_error_alias_no_passthrough()" not in test:
        fail("main must call permit out_error alias no-passthrough test")
    if "test_permit_frame_container_alias_order()" not in test:
        fail("main must call permit frame container alias-order test")
    if "test_permit_alias_zero_mutation_matrix()" not in test:
        fail("main must call permit alias zero-mutation matrix test")
    if "owner_snap_unchanged" not in test or "P_OWNER_PERMIT" not in test:
        fail("permit alias matrix must full-owner-snap and cover owner↔permit")
    if "P_COMPOSITE_OWNER_PERMIT_AND_ERR" not in test:
        fail("permit composite must alias out_error to same owner as permit")
    if "test_frame_oversize_alias_vs_struct()" not in test:
        fail("main must call frame oversize ALIAS-vs-STRUCT test")
    if "test_bind_load_assign_alias_zero_mutation()" not in test:
        fail("main must call bind/load/assign ALIAS zero-mutation test")
    if "test_profile_doc_oversize_alias_vs_struct()" not in test:
        fail("main must call profile doc oversize ALIAS-vs-STRUCT test")
    if "test_fence_pending_blocks_rebind()" not in test:
        fail("main must call fence_pending blocks rebind test")
    if "FENCE_PENDING_BLOCKS_REBIND" not in test:
        fail("fence rebind test must declare FENCE_PENDING_BLOCKS_REBIND semantic")
    if "fence_pend" not in c:
        fail("bind_pcp/bind_site/activate must reject with fence_pend when pending")
    # bind_pcp and bind_site_assignment must gate fence_pending before mutation
    if "ninlil_r5_bind_pcp" in c and c.count("fence_pend") < 2:
        fail("fence_pend diagnostic must appear for multiple bind APIs")
    for marker in (
        "BIND_PCP_OWNER_OUT_ERROR",
        "LOAD_HW_OWNER_OUT_ERROR",
        "LOAD_REG_OWNER_OUT_ERROR",
        "BIND_ASSIGN_OWNER_OUT_ERROR",
        "PCP_FULL_SNAP",
        "pcp_snap_unchanged",
    ):
        if marker not in test:
            fail(f"bind/load/assign alias test missing marker {marker}")
    if "r5_frame_alias_check_len" not in c:
        fail("frame alias checks must use capped length helper")
    if "r5_doc_alias_check_len" not in c:
        fail("profile doc alias checks must use capped length helper")
    if "NINLIL_RADIO_HAL_REASON_OVERSIZE" not in c:
        fail("permit disjoint oversize must use REASON_OVERSIZE not ALIAS")
    if "Global R5 ALIAS rejection contract" not in c:
        fail("source must document global ALIAS zero-mutation contract")
    if "NINLIL_R5_HW_DOC_BYTES" not in c or "NINLIL_R5_REG_DOC_BYTES" not in c:
        fail("doc alias cap must reference HW/REG expected sizes")
    # bind_pcp / load / assign ALIAS branches must not call r5_set_error/sat_inc
    for api_name, pattern in (
        (
            "bind_pcp",
            r"ninlil_r5_bind_pcp\([\s\S]*?return NINLIL_R5_ALIAS;\s*\}",
        ),
        (
            "load_hardware",
            r"ninlil_r5_load_hardware_profile\([\s\S]*?return NINLIL_R5_ALIAS;\s*\}",
        ),
        (
            "load_regulatory",
            r"ninlil_r5_load_regulatory_profile\([\s\S]*?return NINLIL_R5_ALIAS;\s*\}",
        ),
        (
            "bind_site",
            r"ninlil_r5_bind_site_assignment\([\s\S]*?return NINLIL_R5_ALIAS;\s*\}",
        ),
    ):
        m = re.search(pattern, c)
        if not m:
            fail(f"missing ALIAS early-return in {api_name}")
        # First ALIAS return block in each API must be mutation-free
        blk = m.group(0)
        # Only inspect text before first ALIAS return (early branch)
        early = blk.split("return NINLIL_R5_ALIAS;")[0]
        if "r5_set_error" in early or "r5_sat_inc" in early:
            fail(f"{api_name} ALIAS branch must not set_error/sat_inc")
    # Alias reject branches must return ALIAS without stats (owner zero-mutation).
    alias_blocks = re.findall(
        r"if \(r5_permit_alias_reject\([\s\S]*?"
        r"return NINLIL_RADIO_HAL_INVALID_ARGUMENT;\s*\}",
        c,
    )
    if len(alias_blocks) < 2:
        fail("expected validate+consume permit alias reject paths")
    for blk in alias_blocks:
        if "r5_sat_inc" in blk:
            fail("permit alias reject path must not increment stats")
        if "NINLIL_RADIO_HAL_REASON_ALIAS" not in blk:
            fail("permit alias reject must set REASON_ALIAS")
    if "ZERO mutation of owner" not in c and "zero mutation of owner" not in c:
        fail("permit alias path must document zero owner mutation")
    if "test_bind_pcp_lifecycle()" not in test:
        fail("main must call bind_pcp lifecycle test")
    if "test_activate_profile_identity_full_struct()" not in test:
        fail("main must call activate full-struct identity test")
    if "test_r5_api_alias_output_order_named()" not in test:
        fail("main must call named R5 alias/output-order cases")
    if "test_compose_issue_owner_input_alias()" not in test:
        fail("main must call compose/issue owner↔input alias test")
    if "test_issue_wrapper_alias_before_compose()" not in test:
        fail("main must call ninlil_r5_issue wrapper alias gate test")
    if "test_compose_issue_composite_alias()" not in test:
        fail("main must call compose/issue composite alias test")
    if "test_compose_issue_out_error_owner_last_error_alias()" not in test:
        fail("main must call out_error↔owner.last_error sole-alias test")
    if "&e.r5->last_error" not in test and "&r5->last_error" not in test:
        fail("alias test must use out_error = &owner.last_error")
    if "r5, sizeof(*r5), out_error, sizeof(*out_error)" not in c:
        fail("compose/issue gates must explicitly reject r5↔out_error")
    if "test_bind_pcp_transactional_preserve()" not in test:
        fail("main must call bind_pcp transactional preserve test")
    if "test_r5_pcp_commit_reentry_guard()" not in test:
        fail("main must call R5 commit_live reentry guard test")
    if "r5_pcp_commit_live_guarded" not in c:
        fail("R5 must guard commit_live with in_api")
    if "zero mutation" not in c and "zero mutation of owner" not in c:
        fail("issue/compose alias gates must claim zero mutation")
    if "r5_return_alias" in c:
        fail("issue/compose alias path must not use write_owner/write_out helper")
    if "NINLIL_R5_OBJECT_BYTES" not in test or "owner_snap" not in test:
        fail("alias tests must full-snapshot ninlil_r5_t via object ceiling")
    if "memcmp(s->bytes, r5, s->nbytes)" not in test and "memcmp(s->bytes, r5" not in test:
        # accept either form of full object memcmp in owner_snap_unchanged
        if "s->bytes" not in test or "s->nbytes" not in test:
            fail("owner_snap must memcmp full r5 object representation")
    if "same-object" not in h and "Not process-restart" not in h:
        fail("fence_target_generation must be documented as RAM same-object only")
    pcp_c = read(root, "src/radio/pcp_authority.c")
    if "live, sizeof(*live), out_error" not in pcp_c and "out_error, sizeof(*out_error), live" not in pcp_c:
        # accept either arg order in pcp_ranges_overlap call
        if "sizeof(*live)" not in pcp_c or "out_error" not in pcp_c:
            fail("commit_live must reject live↔out_error alias")
    pcp_test = read(root, "tests/radio/pcp_r2_authority_test.c")
    if "COMMIT_LIVE_SAME_GEN_EXACT_ONLY" not in pcp_test:
        fail("R2 test must cover COMMIT_LIVE_SAME_GEN_EXACT_ONLY")
    if "reopen_recover_from_storage" not in pcp_test:
        fail("R2 same-gen test must reopen/recover durable state")
    if "pcp_owner_snap_unchanged" not in pcp_test:
        fail("R2 commit_live alias test must full-snap owner for zero-mutation")
    if "NINLIL_TEST_STORAGE_OP_COUNT" not in pcp_test:
        fail("R2 commit_live alias must check all storage op call counts")
    if "interior" not in pcp_test or "3-way composite" not in pcp_test:
        fail("R2 commit_live alias must cover interior + 3-way composite")
    # commit_live ALIAS path must not sat_inc before return
    if re.search(
        r"ninlil_pcp_commit_live_binding\([\s\S]{0,800}?return NINLIL_PCP_ALIAS",
        pcp_c,
    ):
        early = re.search(
            r"ninlil_pcp_commit_live_binding\([\s\S]*?if \(!pcp_guard_active",
            pcp_c,
        )
        if early and "pcp_sat_inc" in early.group(0):
            fail("commit_live must not sat_inc before alias return / guard")

    if "T_EXPECT_LAB_ONLY" not in test:
        fail("tests must use independent expected constants")
    # production magic must not be the test expected oracle alone
    if "NINLIL_R5_HW_MAGIC" in test and "T_EXPECT" not in test:
        fail("tests must not solely reuse production constants as oracle")
    if "ninlil_r5_" in pub:
        fail("public runtime.h must not expose r5")
    if re.search(r"\b(float|double)\b", c):
        fail("no float/double in profile_loader.c")
    if "malloc" in c or "alloca" in c or "VLA" in c:
        # allow comments only if careful — ban identifiers
        if re.search(r"\bmalloc\b|\bcalloc\b|\brealloc\b|\balloca\b", c):
            fail("no heap/alloca")
    # Forbidden completion claims in production headers/sources.
    for bad in (
        "Japan production RegulatoryProfile complete",
        "FIELD production ready",
        "R5 complete.",
        "R5 series complete",
    ):
        if bad in h or bad in c:
            fail(f"forbidden claim in source: {bad}")
    if "Not FIELD/PRODUCTION/Japan legal/HIL complete." not in h:
        fail("header must retain nonclaim sentence")

    # LAB_ONLY fail-closed: exact reject-all-but-LAB branch required.
    # Mutations that widen the accept set (e.g. && != DEPLOYMENT) break this token.
    if "if (approval != NINLIL_R5_APPROVAL_LAB_ONLY)" not in c:
        fail("must fail-closed on approval != LAB_ONLY exactly")
    if "NINLIL_R5_APPROVAL_LAB_ONLY" not in c:
        fail("load path must reference LAB_ONLY")
    # ensure non-LAB rejection path
    if "NINLIL_R5_REASON_NOT_LAB_ONLY" not in c:
        fail("must emit NOT_LAB_ONLY reason")
    # R2 not bypassed
    if "ninlil_pcp_issue" not in c or "ninlil_pcp_validate" not in c:
        fail("R5 must call R2 issue/validate")
    if "ninlil_pcp_consume" not in c:
        fail("R5 must call R2 consume")
    if "ninlil_airtime_lora_us" not in c:
        fail("R5 must hand off to R3 airtime")
    # Full bind matrix must compare U5 fields (exact tokens).
    for tok in (
        "if (a->controller_term != b->controller_term)",
        "return NINLIL_R5_BIND_CONTROLLER_TERM;",
        "if (!r5_digest_equal(a->assignment_digest, b->assignment_digest))",
        "return NINLIL_R5_BIND_ASSIGNMENT_DIGEST;",
        "if (a->permit_bind_generation != b->permit_bind_generation)",
        "return NINLIL_R5_BIND_PERMIT_GEN;",
    ):
        if tok not in c:
            fail(f"full bind compare missing {tok}")


def check_r2_schema_unchanged(root: pathlib.Path) -> None:
    pcp_h = read(root, "src/radio/pcp_authority.h")
    if "NINLIL_PCP_META_VALUE_BYTES ((size_t)200u)" not in pcp_h:
        fail("R2 meta 200 must remain")
    if "NINLIL_PCP_ISSUED_VALUE_BYTES ((size_t)232u)" not in pcp_h:
        fail("R2 issued 232 must remain")
    if "NINLIL_PCP_SCHEMA_VERSION ((uint16_t)1u)" not in pcp_h:
        fail("R2 schema 1 must remain")



def compile_and_run_mutation(name: str, rel: str, old: str, new: str) -> None:
    """Catch semantic defects only via successful configure+build + failing tests."""
    with tempfile.TemporaryDirectory() as td:
        troot = pathlib.Path(td) / "repo"
        shutil.copytree(
            REPO,
            troot,
            ignore=shutil.ignore_patterns(
                "build", ".git", "cmake-build*", "*.o", "*.a", "install*"
            ),
        )
        path = troot / rel
        text = path.read_text(encoding="utf-8")
        if old not in text:
            fail(f"runtime-mutation setup missing {name}: {old!r}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        bdir = pathlib.Path(td) / "build"
        conf = subprocess.run(
            [
                "cmake", "-S", str(troot), "-B", str(bdir),
                "-DCMAKE_BUILD_TYPE=Release", "-DNINLIL_BUILD_TESTS=ON",
            ],
            capture_output=True, text=True,
        )
        if conf.returncode != 0:
            fail(
                f"mutation must still configure (compile-fail not a catch): {name}\n"
                f"{conf.stderr[-500:]}"
            )
        build = subprocess.run(
            ["cmake", "--build", str(bdir), "-j", "4", "--target", "ninlil_profile_r5_test"],
            capture_output=True, text=True,
        )
        if build.returncode != 0:
            fail(
                f"mutation must still build (compile-fail not a catch): {name}\n"
                f"{build.stderr[-800:]}"
            )
        run = subprocess.run(
            [str(bdir / "ninlil_profile_r5_test")],
            capture_output=True, text=True,
        )
        if run.returncode == 0:
            fail(f"runtime mutation NOT caught (tests still pass): {name}")
        print(f"mutation caught (runtime): {name}")


def run_oracle_fixture_crc_mutation() -> None:
    """Change golden HW profile_id interior byte + recompute CRC; oracle must FAIL."""

    def crc32(data: bytes) -> int:
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
        return crc ^ 0xFFFFFFFF

    with tempfile.TemporaryDirectory() as td:
        troot = pathlib.Path(td) / "repo"
        shutil.copytree(
            REPO,
            troot,
            ignore=shutil.ignore_patterns(
                "build", ".git", "cmake-build*", "*.o", "*.a", "install*"
            ),
        )
        hpath = troot / "tests/radio/profile_r5_golden_profiles.h"
        h = hpath.read_text(encoding="utf-8")
        m = re.search(
            r"static const uint8_t k_r5_golden_hw_v1\[(\d+)\] = \{([^}]+)\}", h
        )
        if not m:
            fail("oracle fixture mutation: missing k_r5_golden_hw_v1")
        n = int(m.group(1))
        vals = [
            int(x.strip().rstrip("u"), 0)
            for x in m.group(2).split(",")
            if x.strip()
        ]
        if len(vals) != n or n < 128:
            fail("oracle fixture mutation: bad hw array")
        # Flip interior of profile_id (offset 8) and recompute CRC at 124.
        vals[8] = vals[8] ^ 0x5A
        body = bytes(vals[:124])
        new_crc = crc32(body)
        vals[124] = new_crc & 0xFF
        vals[125] = (new_crc >> 8) & 0xFF
        vals[126] = (new_crc >> 16) & 0xFF
        vals[127] = (new_crc >> 24) & 0xFF
        arr = ", ".join(f"0x{v:02x}u" for v in vals)
        new_block = f"static const uint8_t k_r5_golden_hw_v1[{n}] = {{ {arr} }}"
        h2 = h[: m.start()] + new_block + h[m.end() :]
        # Keep macro CRC in sync so only reconstruct mismatch fails.
        h2 = re.sub(
            r"#define K_R5_GOLDEN_HW_CRC32\s+0x[0-9a-fA-F]+u?",
            f"#define K_R5_GOLDEN_HW_CRC32 0x{new_crc:08x}u",
            h2,
            count=1,
        )
        hpath.write_text(h2, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(troot / "tools" / "profile_r5_golden_oracle.py")],
            cwd=str(troot),
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            fail("oracle fixture CRC mutation NOT caught (oracle still OK)")
        print("mutation caught (oracle): fixture_interior_id_crc_recalc")

def run_self_test() -> None:
    mutations: list[tuple[str, str, str, str, bool]] = [
        (
            "drop_lab_only_fail_closed_marker",
            DOC29,
            "SEMANTIC: LAB_ONLY_FAIL_CLOSED",
            "SEMANTIC: LAB_ALLOWS_FIELD",
            False,
        ),
        (
            "claim_r5_complete",
            DOC29,
            "R5 complete ではない",
            "R5 complete である",
            False,
        ),
        (
            "allow_deployment_approved",
            SRC,
            "if (approval != NINLIL_R5_APPROVAL_LAB_ONLY)",
            "if (approval != NINLIL_R5_APPROVAL_LAB_ONLY && approval != NINLIL_R5_APPROVAL_DEPLOYMENT_APPROVED)",
            False,
        ),
        (
            "remove_profile_loader_from_private",
            PRIVATE,
            "    src/radio/profile_loader.c\n",
            "",
            False,
        ),
        (
            "drop_bind_matrix_test",
            TEST,
            "static int test_full_bind_mismatch_matrix(void)",
            "static int test_full_bind_mismatch_matrix_disabled(void)",
            False,
        ),
        (
            "drop_activate_assign_ch_check",
            SRC,
            "if (r5->assignment.channel_id < cand_reg.channel_id_min\n"
            "            || r5->assignment.channel_id > cand_reg.channel_id_max) {\n"
            "            r5_sat_inc(&r5->stats.activate_deny);\n"
            "            r5_set_error(\n"
            "                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,\n"
            "                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_RANGE,\n"
            "                NINLIL_R5_BIND_CHANNEL, \"assign_ch\");\n"
            "            return NINLIL_R5_PROFILE_DENIED;\n"
            "        }",
            "/* mutation: channel assign check removed */",
            False,
        ),
        (
            "drop_activate_assign_phy_check",
            SRC,
            "if (!r5_phy_in_reg(&cand_reg, &r5->assignment.phy)) {\n"
            "            r5_sat_inc(&r5->stats.activate_deny);\n"
            "            r5_set_error(\n"
            "                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,\n"
            "                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_RANGE,\n"
            "                NINLIL_R5_BIND_PHY, \"assign_phy\");\n"
            "            return NINLIL_R5_PROFILE_DENIED;\n"
            "        }",
            "/* mutation: phy assign check removed */",
            False,
        ),
        (
            "drop_golden_profiles_include",
            TEST,
            '#include "profile_r5_golden_profiles.h"',
            "/* golden profiles include removed */",
            False,
        ),
        (
            "drop_golden_hw_array_ref",
            TEST,
            "(void)memcpy(e->hw_doc, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES);",
            "(void)memcpy(e->hw_doc, k_r5_golden_hw_MISSING, NINLIL_R5_HW_DOC_BYTES);",
            False,
        ),
        (
            "drop_golden_reg_array_ref",
            TEST,
            "(void)memcpy(e->reg_doc, k_r5_golden_reg_v1, NINLIL_R5_REG_DOC_BYTES);",
            "(void)memcpy(e->reg_doc, k_r5_golden_reg_MISSING, NINLIL_R5_REG_DOC_BYTES);",
            False,
        ),
        (
            "drop_oracle_reconstruct_compare",
            "tools/profile_r5_golden_oracle.py",
            "if committed_hw != expect_hw:\n"
            '        fail(f"hw array not byte-identical to reconstructed golden ({len(committed_hw)} vs {len(expect_hw)})")',
            "pass  # mutation: reconstruct compare removed",
            False,
        ),
        (
            "drop_ctest_golden_oracle_wire",
            CMAKELISTS,
            "NAME profile_r5_golden_oracle",
            "NAME profile_r5_golden_oracle_DISABLED",
            False,
        ),
        (
            "drop_controller_term_bind",
            SRC,
            "if (a->controller_term != b->controller_term) {\n"
            "        return NINLIL_R5_BIND_CONTROLLER_TERM;\n"
            "    }",
            "if (0) {\n"
            "        return NINLIL_R5_BIND_CONTROLLER_TERM;\n"
            "    }",
            False,
        ),
        (
            "remove_r3_handoff",
            SRC,
            "ast = ninlil_airtime_lora_us(&plan->airtime_in, &air);",
            "ast = NINLIL_AIRTIME_OK; (void)memset(&air, 0, sizeof(air)); air.airtime_us = 1000u;",
            False,
        ),
        (
            "japan_claim_in_header",
            HDR,
            "Not FIELD/PRODUCTION/Japan legal/HIL complete.",
            "Japan production RegulatoryProfile complete.",
            False,
        ),
    ]

    for name, rel, old, new, _allo in mutations:
        with tempfile.TemporaryDirectory() as td:
            troot = pathlib.Path(td) / "repo"
            shutil.copytree(
                REPO,
                troot,
                ignore=shutil.ignore_patterns(
                    "build",
                    ".git",
                    "cmake-build*",
                    "*.o",
                    "*.a",
                ),
            )
            path = troot / rel
            text = path.read_text(encoding="utf-8")
            if old not in text:
                fail(f"self-test setup missing anchor for {name}: {old!r}")
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(troot / "tools" / "profile_r5_gate.py"), "check"],
                cwd=str(troot),
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                fail(f"mutation NOT caught: {name}\n{proc.stdout}\n{proc.stderr}")
            print(f"mutation caught: {name}")
    # Semantic runtime mutations (build+run) — must fail profile_r5_test.
    # Compile/configure failure alone is NOT accepted as a catch.
    compile_and_run_mutation(
        "drop_frame_digest_alg_compare",
        SRC,
        "if (a->frame_digest_algorithm != b->frame_digest_algorithm) {\n"
        "        return NINLIL_R5_BIND_FRAME_DIGEST_ALG;\n"
        "    }",
        "if (0) {\n"
        "        return NINLIL_R5_BIND_FRAME_DIGEST_ALG;\n"
        "    }",
    )
    compile_and_run_mutation(
        "allow_same_gen_site_mutation",
        SRC,
        "&& cand.permit_bind_generation <= r5->assignment.permit_bind_generation)",
        "&& 0 && cand.permit_bind_generation <= r5->assignment.permit_bind_generation)",
    )
    # Comparison-operator mutations: configure+build MUST succeed; only
    # profile_r5_test runtime failure counts as caught.
    compile_and_run_mutation(
        "runtime_drop_effective_lt",
        SRC,
        "if (plan->not_before_ms < r5->reg.effective_not_before_ms) {",
        "if (0 && plan->not_before_ms < r5->reg.effective_not_before_ms) {",
    )
    compile_and_run_mutation(
        "runtime_effective_lt_to_le",
        SRC,
        "if (plan->not_before_ms < r5->reg.effective_not_before_ms) {",
        "if (plan->not_before_ms <= r5->reg.effective_not_before_ms) {",
    )
    compile_and_run_mutation(
        "runtime_effective_lt_to_gt",
        SRC,
        "if (plan->not_before_ms < r5->reg.effective_not_before_ms) {",
        "if (plan->not_before_ms > r5->reg.effective_not_before_ms) {",
    )
    compile_and_run_mutation(
        "runtime_drop_expiry_gt",
        SRC,
        "&& plan->expiry_ms > r5->reg.profile_expiry_ms) {",
        "&& 0 && plan->expiry_ms > r5->reg.profile_expiry_ms) {",
    )
    compile_and_run_mutation(
        "runtime_expiry_gt_to_ge",
        SRC,
        "&& plan->expiry_ms > r5->reg.profile_expiry_ms) {",
        "&& plan->expiry_ms >= r5->reg.profile_expiry_ms) {",
    )
    compile_and_run_mutation(
        "runtime_expiry_zero_guard_flip",
        SRC,
        "if (r5->reg.profile_expiry_ms != 0u\n"
        "        && plan->expiry_ms > r5->reg.profile_expiry_ms) {",
        "if (r5->reg.profile_expiry_ms == 0u\n"
        "        && plan->expiry_ms > r5->reg.profile_expiry_ms) {",
    )
    compile_and_run_mutation(
        "runtime_drop_activate_channel_check",
        SRC,
        "if (r5->assignment.channel_id < cand_reg.channel_id_min\n"
        "            || r5->assignment.channel_id > cand_reg.channel_id_max) {\n"
        "            r5_sat_inc(&r5->stats.activate_deny);\n"
        "            r5_set_error(\n"
        "                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,\n"
        "                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_RANGE,\n"
        "                NINLIL_R5_BIND_CHANNEL, \"assign_ch\");\n"
        "            return NINLIL_R5_PROFILE_DENIED;\n"
        "        }",
        "/* channel check disabled for mutation */",
    )
    # Fixture interior ID change with recalculated CRC must fail oracle.
    run_oracle_fixture_crc_mutation()


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print("usage: profile_r5_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            check_docs(REPO)
            check_source(REPO)
            check_r2_schema_unchanged(REPO)
            print("profile_r5_gate: OK")
            return 0
        run_self_test()
        print("profile_r5_gate self-test: OK")
        return 0
    except GateFailure as e:
        print(f"profile_r5_gate FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
