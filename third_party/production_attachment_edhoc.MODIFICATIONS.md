# PA-S1a vendor ledger

- libedhoc `v1.15.1` is pinned at
  `008ce0584e6cfa41aa6319f530b6c254c8abfc3e`; zcbor is pinned at
  `d3093b5684f62268c7f27f8a5079f166772619de`.
- Every file below `third_party/production_attachment_edhoc/` is byte-for-byte
  upstream. `production_attachment_edhoc.allowlist` is the exact path/blob
  SHA-256 authority and `production_attachment_edhoc_vendor_gate.py` checks it
  offline.
- Ninlil-owned build configuration is
  `src/runtime/production_attachment_v1/edhoc_config.h`: logging disabled and
  custom memory backend required. It is outside the vendored tree.
- The fixed explicit-owner allocator is Ninlil source. The process-global
  libedhoc hook adapter exists only in the Host test so this candidate does not
  choose a Runtime/Composition ownership model.
- `zcbor_common.c` retains `-Werror`, VLA rejection, and stack usage. Its
  upstream float/integer representation punning uses `-fno-strict-aliasing`
  on Host and ESP-IDF instead of rewriting pinned source bytes.
- Excluded: upstream helpers, crypto providers, tests, examples, CMake
  superbuild, credentials, carrier, install/confirm, and all LAB code.

This is a PA-S1a dependency candidate only. It is not PA-S2 crypto evidence,
not an EDHOC session owner, and not a Production Attachment completion claim.
