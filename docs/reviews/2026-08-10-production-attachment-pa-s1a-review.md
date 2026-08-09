# Production Attachment PA-S1a dependency/allocator review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: private EDHOC dependency admission and bounded allocator candidate  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `e2075d746050e4756abafe07707612be13d8a42a`
- 115-file reviewed implementation/vendor input manifest SHA-256 (post-review
  ledgers excluded):
  `aad7843929888b1038b643ac725b7f684839bdb752b0d6f1b9aa37404979f2f5`
- libedhoc: `v1.15.1`, commit
  `008ce0584e6cfa41aa6319f530b6c254c8abfc3e`
- zcbor: `d3093b5684f62268c7f27f8a5079f166772619de`

The PA-S0 vector repair was reviewed separately and is not part of this
verdict.

## Accepted candidate evidence

- the shipped 99-file vendor set matches the fixed upstream path and bytes
  exactly; licenses, dependency inventory, notices, component hashes, and the
  43-upstream-TU allow-list agree;
- the Host candidate is default-OFF, `EXCLUDE_FROM_ALL`, uninstalled, and does
  not add a public header or ABI;
- an actual `edhoc_message_1_compose` path uses the custom-memory hooks and
  observes one live 32-byte allocation and its cleanup;
- the two-slot harness proves 0-byte and 64-byte success, 65-byte and third
  allocation rejection, max alignment, non-LIFO release, both-slot full
  zeroization, failpoint behavior, serialized reentry rejection, and reuse;
- the symbol gate rejects EDHOC, zcbor, generated CBOR, Ninlil PA-S1a, and any
  private/public defined-symbol overlap on Mach-O and ELF forms;
- Host normal and ASan/UBSan focused suites each pass **6/6**;
- the explicit ESP-IDF v5.5.3 ESP32-S3 opt-in compiles all 43 upstream TUs and
  the allocator, records 44 stack-usage files, and has maximum frame **320 B**;
- ESP ELF SHA-256:
  `3c2019ccb739cd01468ccbf269bb763e1ff53da5a675a08263cb6df4c3395ce9`;
- ESP BIN SHA-256:
  `489e9649f7598aebc6be041ef842a05ebe1505f69ce2e01f2ac13a8b3ead849b`.

Only upstream `zcbor_common.c` uses `-fno-strict-aliasing`; `-Werror`, `-Wvla`,
and stack-usage output remain enabled. The review found no unnecessary layer
or duplicate owner under the Ponytail criterion.

## Status boundary

This GO accepts a private PA-S1a dependency/allocator candidate only. PA-S1 as
a whole remains open. No production crypto/credential provider, EDHOC session
owner, carrier, wire, storage, NIAF or Composition connection, Join, target
execution, HIL, field/legal evidence, or release support is claimed. ADR-0023
and the full Identity/Attachment feature remain **Proposed**.
