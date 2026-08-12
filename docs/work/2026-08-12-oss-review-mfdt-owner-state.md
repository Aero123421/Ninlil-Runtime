# OSS review: MFDT owner-local volatile state

Date: 2026-08-12

## Scope and classification

This tranche addresses only the mutable state named by OR-21 in the MFDT
engine, prototype spine, Host runtime seam, target allocator, ESP store, and
page encoder. The files are private and non-installed, but their roles differ:

| Former state | Path classification | Resolution |
| --- | --- | --- |
| Active-record and NRC1 scratch in `mfdt_v1_engine.c` | Production engine path on Host and ESP | Bound to the existing exact 65,536-byte caller workspace. Each engine now has disjoint record/NRC1 regions. |
| Spine storage, lazy pointer, and preallocation flag in `mfdt_v1_spine.c` | Default-OFF private prototype and ESP target-smoke path | Replaced by explicit caller-owned `ninlil_mfdt_v1_spine_ctx_t` lifecycle. The ESP smoke allocates one context at startup and frees it after zeroization. |
| Dual endpoint workspaces/engines and busy flag in `mfdt_v1_runtime_seam.c` | Host/lab-only two-endpoint seam | Moved into a caller-owned seam context with same-owner busy rejection and complete-context zeroization. |
| Allocation-failure switch and call counter in `mfdt_v1_target_alloc.c` | Host test instrumentation, not a production contract | Deleted. Host and ESP retain only their platform allocator adapters; no process-global test control remains. |
| ESP binding, transaction context, read-back pointer and OLD-snapshot pool in `mfdt_v1_store_esp.c` | Default-OFF ESP production adapter | Embedded in the exact caller-owned lab-store owner. Bind/unbind now take that owner explicitly; finalization releases bulk and zeroizes the complete owner. |
| ESP raw-CU diagnostic latch and unavailable HIL enable flag in `mfdt_v1_hil_gate.c` | Private diagnostic / release gate | Raw class moved into the store owner. The unavailable promotion authority is a constant OFF result, not mutable process state. |
| MANIFEST_PAGE digest scratch in `mfdt_v1_wire.c` | Production wire encoder | Deleted. The exact final `page_out` is reused in-place with supported final-entry alias and fail-before-mutation overlap validation. |

Session binding no longer mutates an implicit spine/seam.  Applying negotiated
configuration now requires an explicit spine owner.  The public Runtime MFDT
path continues to use its existing instance-local runtime owner rather than
the private prototype spine.

## Invariants

- No installed/public header, public symbol, ABI value, wire byte, storage key,
  or storage encoding changed.
- The measured `sizeof` values are: workspace 65,536 bytes, private lab store
  116,840 bytes, engine 232 bytes, pipeline 2,208 bytes, and spine context
  184,952 bytes. They remain under their existing hard footprint ceilings.
  Separately, the physical record plus NRC1 regions inside the workspace are
  35,216 + 15,024 = 50,240 bytes. Their canonical value maxima are
  35,211 + 15,020 = 50,231 bytes; neither is external process scratch.
- A busy owner returns the existing private `ERR_BUSY`/seam busy result before
  mutation.  A different owner remains usable and unchanged.
- Engine, spine, and Host seam finalizers overwrite every byte of the
  caller-owned handle/scratch covered by their lifecycle. Slot engines retain
  the five caller-declared region lengths, so accepted capacities above the
  minimum are also wiped in full rather than leaving their tails behind.
- The allocator adapter split keeps ESP-IDF SDK includes under `ports/esp-idf/`;
  it does not add an allocator policy or a new test framework.
- A second ESP store owner can hold an independent transaction on another
  media handle while the first is active. Same-owner bind/begin reentry returns
  `ERR_BUSY` before changing any owner byte. The raw CU class is owner-local.
- `ninlil_mfdt_v1_encode_page` has no mutable static scratch. Back-to-back
  calls with separate outputs are independent; the exact `page_out + 92`
  entries alias is supported and every other overlap is rejected before
  output/length mutation.

## Verification

- Earlier ownerization checkpoint, fresh normal MFDT suite: **29/29 PASS**,
  including Host acceptance runner,
  install-symbol boundary, footprint, ESP DRAM self-test, Host profile boundary,
  and ESP map-proof dry-run.
- Public Runtime MFDT capability/isolation test: **1/1 PASS**.
- Earlier checkpoint, fresh ASan/UBSan MFDT suite: **29/29 PASS**. The public Runtime capability
  test also passed separately in that sanitizer build (**1/1 PASS**).
- After the ESP-store/page-encoder closure, a fresh MFDT-only Release build
  passed **31/31**, and a fresh ASan/UBSan build passed **31/31**. This includes
  the owner-state gate and its mutation self-test.
- The owner-local ESP CU test proves two simultaneous owners/media, same-owner
  rebind and begin `BUSY` with complete-byte no-mutation, owner isolation, and
  complete-byte zeroization after `fini`. The wire KAT proves byte-exact output,
  exact final-entry alias, two back-to-back independent outputs, and overlap /
  page-shape / canonical-entry semantic-invalid fail-before-mutation.
- `mfdt_v1_owner_state_gate.py` reports **0 mutable static objects** across the
  private MFDT production `.c` / `.h` authority and the ESP-IDF MFDT adapter
  sources. It applies C11 trigraph/newline normalization and line splicing
  before classifying `static`, and rejects token-paste operators rather than
  guessing their expansion. Its fail-closed self-test rejects renamed
  page scratch, indented cache, detached pointer-owner, parenthesized
  initializer, parenthesized array bound, function-pointer object, const
  pointer object, postfix attributes, macro-wrapped, line-spliced and
  trigraph-spliced statics, plus `##` and `%:%:` token-paste formation. The
  parser covers **13 mutations** and the full repository walker independently
  rejects **3 mutations**, including line-spliced and token-pasted forms.
- ESP target-smoke and store-adapter translation units strict C11: **PASS**. An actual no-flash
  ESP-IDF 5.5.3 / ESP32-S3 Xtensa ELF build and live-callpath map proof passed;
  the corrected GNU ld one-/two-line parser reported MFDT
  `bss_total=0`, `rows=0`, `objs=6` against the 49,152-byte ceiling. The final
  `.dram0.bss` contains general ESP BSS rows (the parser is not empty); the six
  live MFDT objects contribute no BSS after ownerization. Map-proof dry-run and
  DRAM-budget negative self-test also pass. The target smoke now binds its own
  spine/store owner to the retained Storage Port handle and finalizes it before
  returning.
- The installed-symbol boundary in both fresh 31-test matrices passed: the
  source-private MFDT owner/lifecycle seams remain outside the public install.
- Explicit tests prove two engine workspaces and two spine contexts are
  disjoint, busy same-owner entry makes no state change, session mutation has
  no implicit cross-owner effect, and engine/spine/seam finalization leaves
  every checked byte zero.
- A fresh normal and ASan/UBSan slot-contract build each pass **2/2**. The
  contract test binds five disjoint regions at minimum+8-byte capacities,
  rehydrates an active/NRC1 record, verifies that the recorded capacities
  survive recovery, and then requires every byte including all five tails to
  be zero immediately after `engine_fini`.
- Private header C++17 smoke from the earlier checkpoint: **PASS**.
- Targeted removed-global/source scan and `git diff --check`: **PASS**.
- Target allocator OOM injection: **LOCAL_NOT_RUN**. Startup/bind failure must
  remain fail-closed, but this review does not claim a target allocator fault
  result that the current test harness does not produce.

## Nonclaims

This closes the named MFDT production mutable-state portion of OR-21, including
the ESP durable store and page encoder. The separate RRMP serial-owner tranche
has also removed its legacy implicit bind pointer and is recorded independently.
An older broad `build-oss-all-private` snapshot also enables unrelated
private feature combinations; there, `mfdt_v1_runtime_owner_private` and
`mfdt_v1_runtime_sidecar_fault_private` stop at Runtime create with
`NINLIL_E_UNSUPPORTED`. Both pass in the fresh MFDT-only Release and sanitizer
matrices above, so the shared-snapshot result is recorded separately and is not
used as MFDT evidence. The ESP result includes a final no-flash ESP-IDF ELF and
map proof, but not device execution, physical power-cut HIL, RF soak,
implementation-complete promotion, or release-support claim. ADR-0021 remains Accepted
specification / implementation incomplete and the feature remains default-OFF.
