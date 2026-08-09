# PA-S1a private EDHOC dependency candidate

Date: 2026-08-10  
Status: **Host candidate / ESP32-S3 compile-only; PA-S1 through PA-S6 remain open**

Independent review: **GO — P0=0 / P1=0 / P2=0 / P3=0**. See
[`../reviews/2026-08-10-production-attachment-pa-s1a-review.md`](../reviews/2026-08-10-production-attachment-pa-s1a-review.md).

## Scope

This change admits the smallest reviewed source boundary required to test the
libedhoc custom-memory backend. It is a private `EXCLUDE_FROM_ALL` Host target
and an explicit default-OFF ESP component option. It adds no installed target,
public header/API/DTO, wire record, storage, credential resolver, carrier,
Composition connection, NIAF use, or LAB source.

## Fixed input

- libedhoc `v1.15.1`, commit `008ce0584e6cfa41aa6319f530b6c254c8abfc3e`
- zcbor commit `d3093b5684f62268c7f27f8a5079f166772619de`
- 43 adopted translation units: eight libedhoc core, 32 generated CBOR, and
  three zcbor runtime units. Headers and license files are retained only as
  their compile/license closure.
- `third_party/production_attachment_edhoc.allowlist` is the path/blob SHA-256
  authority. The offline vendor gate rejects added, missing, or modified files,
  translation-unit drift, installed target drift, and public-header leakage.

## Memory boundary and Host evidence

`pa_s1_edhoc_allocator` is a caller-owned two-slot × 64-byte, max-aligned,
zeroizing arena. This is trace-derived only: the M1 Host path has one live,
32-byte allocation; the second slot covers the allocator's direct lifecycle
check rather than setting a production ceiling. It has explicit owner
arguments; no Runtime global owner is introduced. The unavoidable context-free
upstream hook is confined to the test-only M1 adapter. The Host test runs
actual `edhoc_message_1_compose` with test-only deterministic callbacks,
proves one observed custom allocation and cleanup, sweeps its observed
failpoint, and checks alignment, zero-size, out-of-order free, zeroization,
reentry rejection, and restart. The direct allocator check fills both slots,
rejects a third allocation, frees slot 0 before slot 1 (non-LIFO), and checks
the exact 64-byte maximum succeeds, 65 bytes fails, and each complete 64-byte
slot is zero immediately after its free. This is not cryptographic correctness
evidence.

Normal and ASan/UBSan focused suites each pass 6/6. The explicit ESP32-S3
opt-in compiles all 43 upstream translation units plus the allocator; 44
stack-usage records have a maximum frame of 320 bytes. The resulting ELF is
`3c2019ccb739cd01468ccbf269bb763e1ff53da5a675a08263cb6df4c3395ce9`.

## Non-claims / next boundary

PA-S2 platform crypto, credentials, direct carrier, cold multi-hop, EDHOC
owner, message 4, exporter, Attachment install, NIAF/Composition activation,
target execution, and HIL are not implemented. A later tranche must select the
sole serialized platform Attachment owner before moving the test adapter hook
into any Runtime integration.
