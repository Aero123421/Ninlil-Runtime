# Production Attachment PA-S3b1 NAR1 admitted-reassembly candidate review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: private strict NAR1 codec and post-cookie/admitted single-record owner  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `53634a9cea35002bb65b9a6a21780f4bd355d65d`
- 21-file reviewed implementation/spec input manifest SHA-256 (the sorted
  per-file SHA-256 lines below; post-review README, work and review ledgers
  excluded):
  `8a3fe750e3b908105e6d70e1de0ea9e30a1879cbb234c42304290dd3182c2d22`
- ESP ELF SHA-256:
  `98f3f063a76a215657f21db52a91076157615f2015d785563236c445fb68223c`
- ESP BIN SHA-256:
  `b0b3adc187e6112c7a3655788dedbef193a30810bbf99505db6e4aed31fd1a6c`

```text
10c8f633a45dfc11ca4b71923d142e62b2ba1e4eaa242b0142096539c9d21ac4  CMakeLists.txt
f812c8e0650d3faedcfd5e7f29b3172290a59ef7616a0223d5b7aa8617145513  docs/35-production-attachment-edhoc-profile.md
87ae0cf826b69e4cad30a430ee3eaaee05d88a5f1bdb428985e638d7b0c40104  docs/adr/0023-production-attachment-edhoc-profile.md
d5e78f405a51f069f69b7c5301479937231ecc87eeb84f4c565d33fa4e41c1f2  ports/esp-idf/components/ninlil/CMakeLists.txt
dc4c1cd8ac04fbff48ffc6b63418d8a959a80a78e20e89862154f62c7cba085b  ports/esp-idf/components/ninlil/Kconfig
c1f857ea8b9f19b3b3166d3a29ce6f19f2efbc5dd1e119638faf88db5565ff4e  ports/esp-idf/smoke_app/main/CMakeLists.txt
7137da44cdf78fb66589ab650f735aea933b7135e428928814aaa9fdfef48258  ports/esp-idf/smoke_app/main/main.c
d796e91d9ece110dcb35bdc6970347cb505578904f457bbb3d41b0715542c0b0  ports/esp-idf/smoke_app/sdkconfig.defaults.pa_s3_nar1_on
74993eed4878633cb73e7849b463617bfafaab0b6f9dbdc989ee23050cfbf506  spec/protocol-magic-registry-v1.json
95639924765712d34d5667ab48efe32aeb2d2d5cb6e7af27180d3c8480184fac  spec/vectors/production-attachment-edhoc-v1.json
03e45ed12522f187ede387ee3b9964ac355050de5f81d00c4685af649607053c  src/runtime/production_attachment_v1/pa_s3_nar1_reassembly.c
c7c8fb6ba4cc7e0fec7dd98fbd77a35ba7c7199ca25a3fc1da0e9f5ea5007b52  src/runtime/production_attachment_v1/pa_s3_nar1_reassembly.h
16283f28125e9bf28d90a1b6b49bedce5bae5097988413662d874835c931a3b8  tests/radio/production_attachment_edhoc_vector_test.c
1681381b3c4332b3e60cf22de75b746d0bb94d67c6bcac0f8307c113eb420d6a  tests/runtime/production_attachment_v1_nar1_reassembly_test.c
3906bd13c64e308b8466c57ac9f6329fea13eb77d8209563a1dc466b0181b0e8  tools/production_attachment_edhoc_composition.py
9f5e29eb5bb6aca3deab22fff0d064f9b40150bee3715ef83a3843eb6dd84556  tools/production_attachment_edhoc_expected_model.py
964522121f2040127a1f7701aca4cdc3851966b0008fe9f4b9680ad94eb0fec9  tools/production_attachment_edhoc_gate.mjs
4d7c890fab327ff2ebc141b3da70ce9cc60127d99520fbb4cca0868fd15ed089  tools/production_attachment_edhoc_gate.py
06c33a3b1614cb4b403472135df7b603312e726bc61dc22f96b1370244b80361  tools/production_attachment_edhoc_independent_authority.py
fca954139c4656f2733c264a394e04a550b3ebb324518d7575dde5318cc235c3  tools/production_attachment_edhoc_schema_authority.py
c071d097e210cb70f2048705a266555add7af6dfb32fe929b6d27cc6e16a6bbf  tools/production_attachment_edhoc_vendor_gate.py
```

## Accepted candidate evidence

- one caller-owned fixed owner retains one 600-byte record buffer and 5-bit
  received mask; it stores no packet slots and permits only serialized calls
  from its exact owner context;
- full NAR1 framing, canonical count/index/offset/payload shape and CRC are
  checked before owner mutation; mixed tuples, source mismatch and conflicting
  duplicates terminally wipe the partial record;
- completion publishes exactly once only after outer SHA-256, inner NAC1
  structure/CRC and inner-to-outer session, generation and sequence binding;
  caller output after the exact record remains unchanged;
- exact duplicates leave the complete owner and caller output unchanged, make
  no progress, and the remaining fragment still reaches exact delivery;
- Host evidence covers one through five fragments, every exact 124-byte final
  boundary, all 120 five-fragment orders, lifecycle and alias failures,
  corrupted owner shape, terminal wipe, close zeroization and two-owner
  isolation;
- deletion-equivalent mutation evidence rejects 12 newly covered NAC1
  structural predicates, all 12 externally observable NAR1 semantic parser
  predicates, completion digest/tuple guards and the OPEN full-mask guard. A
  one-byte actual input rejects the short-span lower-guard deletion under ASan;
- the complete-length lower bound remains a read-reviewed parse-before-mutation
  invariant. Its isolated deletion is not externally distinguishable because
  same-call NAC1 completion validation also rejects it, so no mutation claim is
  made for that internal ordering;
- focused Host CTest passes **8/8**, independent vector/Python/Node/registry/
  vendor checks pass **10/10**, and ASan/UBSan passes **3/3**;
- feature-OFF/tests-OFF exposes neither a PA-S3b1 target nor an installed
  Runtime symbol; Host-runtime-OFF builds only the explicit private archive;
- the fresh ESP-IDF v5.5.3 ESP32-S3 opt-in image links the same source. Its
  three owner functions are `GLOBAL HIDDEN`, with a maximum source frame of
  **176 B** under the 2048-byte ceiling. Host source maximum is **240 B**.

The Ponytail review found no generic reassembly framework, packet-slot layer,
heap, VLA, task, store, public ABI/DTO, new wire format or parallel authority.
Redundant standalone kind and fragment-count range comparisons were removed;
`sequence_ok` and exact `count = ceil(length / 124)` remain the single
executable authorities.

## Status boundary

This GO accepts only the private/default-OFF/uninstalled PA-S3b1 strict NAR1
post-admission single-record candidate. The ESP artifact was compiled and
linked but not flashed or executed. The caller-supplied source digest is only a
Host-test identity. Live locator ownership, cookie/HMAC/challenge, carrier
admission, anti-amplification quota, timeout/retry, RF ingress/TX, EDHOC message
owner, NAC1 live handoff, Composition/NIAF activation, availability, PA-S3 as a
whole, PA-S4 through PA-S6, Join and physical HIL remain open. ADR-0023 and the
full Identity/Attachment feature remain **Proposed**.
