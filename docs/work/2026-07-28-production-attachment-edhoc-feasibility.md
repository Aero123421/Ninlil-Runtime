# Production Attachment EDHOC feasibility record

Date: 2026-07-28  
Status: **investigation only — dependency not adopted, production attachment not implemented**

## Purpose

This record evaluates whether Ninlil can replace the LAB-only join handshake
with a standards-based authenticated key exchange without inventing a new
cryptographic protocol. It is evidence for a later Proposed production
Attachment ADR. It does not accept a dependency, reserve a wire format, or
make an Attachment, M4, M5, Hop/E2E install, Wi-Fi, or radio completion claim.

## Standards baseline

- [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html) is the EDHOC
  protocol authority.
- [RFC 9529](https://www.rfc-editor.org/rfc/rfc9529.html) supplies
  implementation traces.
- The candidate profile is EDHOC method 3, cipher suite 2, Raw Public Keys in
  CCS identified by `kid`, with message 4 required.
- No private or unregistered EAD label is proposed. Attachment installation
  and confirmation remain a separate protected Ninlil exchange after EDHOC.
- A future profile must support both RFC-required suites 2 and 3 or document a
  precise interoperability boundary; selecting suite 2 for the first target
  does not silently redefine RFC conformance.

## Candidate implementation snapshot

Candidate: [`kamil-kielbasa/libedhoc`](https://github.com/kamil-kielbasa/libedhoc)  
Release: `v1.15.1`  
Commit: `008ce0584e6cfa41aa6319f530b6c254c8abfc3e`  
Published: 2026-07-09  
License: MIT

Pinned submodule inputs inspected in the temporary checkout:

| Dependency | Commit | License/use |
| --- | --- | --- |
| zcbor | `d3093b5684f62268c7f27f8a5079f166772619de` | Apache-2.0; CBOR codec runtime |
| Mbed TLS | `edb8fec9882084344a314368ac7fd957a187519c` | feasibility test crypto only; Ninlil must use its pinned platform crypto provider |
| Unity | `73237c5d224169c7b4d2ec8321f9ac92e8071708` | upstream tests only |
| compact25519 | `1ed9c87ab6ed3bcbbb783289ea14e077a40ef127` | upstream non-suite-2 helpers; not required by the proposed suite-2 runtime slice |

The dependency gate must also freeze the corresponding license texts before
vendoring.

## Reproduced build and test evidence

Temporary read-only source checkout:

```text
$TMPDIR/tmp.4DvKhOyAlh/libedhoc
```

The location is not a release artifact and must not be referenced by CI.

### Portable core compile

A minimal build compiled only:

- the eight libedhoc core translation units;
- the generated EDHOC CBOR backends;
- the three zcbor runtime translation units.

It excluded the upstream example crypto helpers and the upstream dependency
superbuild. AppleClang 21 compiled all **44 objects** and linked the static
archive with C11, `-Werror`, conversion, shadow, cast-alignment, prototype, and
stack-protector warnings enabled.

Result: **PASS**.

### Upstream functional and sanitizer suite

The upstream full module suite was rebuilt with:

- AppleClang 21;
- ASan and UBSan;
- heap memory backend;
- upstream and Mbed TLS warning-as-error disabled only because their test
  sources emit new AppleClang 21 diagnostics.

Result: **750 tests, 0 failures, 0 ignored; ASan/UBSan PASS**.

Disabling third-party test `-Werror` is not evidence that Ninlil production
sources may relax warnings. The minimal core compile above remained
warning-as-error clean.

### Default stack backend rejection

The same suite with the upstream default stack backend failed under UBSan:

```text
library/edhoc_message_4.c:640:
variable length array bound evaluates to non-positive value 0
```

An empty `PLAINTEXT_4` can therefore create a zero-length VLA through
`EDHOC_MEM_ALLOC`. Ninlil must not ship the upstream stack backend. The heap
backend also does not satisfy the Portable Core bounded-allocation contract.

### Custom allocator contract

The upstream suite was then rebuilt with
`CONFIG_LIBEDHOC_MEM_BACKEND=2`. Its custom-memory tests add allocation
balance, zero-initialization, selected-allocation failure, full-handshake
balance, and failure at every allocation point.

Result: **756 tests, 0 failures, 0 ignored; ASan/UBSan PASS**.

This proves that the library's custom-allocation call paths and cleanup paths
can run without the VLA or heap backend. It does not yet prove the size,
concurrency, or zeroization guarantees of a Ninlil allocator; those remain an
integration acceptance requirement.

## Required integration boundary

If the candidate is accepted later, Ninlil must:

1. vendor exact reviewed core, generated CBOR, and zcbor sources rather than
   importing the upstream superbuild, which also builds unrelated crypto and
   test targets;
2. use a Ninlil-owned bounded, zeroizing custom allocator with a single
   serialized Attachment owner and explicit exhaustion result;
3. prove the allocator's slot count, largest allocation, maximum simultaneous
   allocation, zero-size behavior, alignment, out-of-order free handling,
   zeroization, reentry, and restart behavior by tests and target evidence;
4. provide Host OpenSSL 3 and ESP-IDF Mbed TLS/PSA suite-2 adapters through the
   existing private crypto boundary; never use example key storage;
5. pin credentials to accepted device and authority identities, require
   message 4, and forbid application key persistence before responder
   confirmation;
6. derive directional Hop and E2E traffic secrets with distinct private EDHOC
   exporter labels and context that commits to the final Attachment install
   digest;
7. perform a separate protected `ATTACH_INSTALL` / `ATTACH_CONFIRM`
   transaction that installs all local directional contexts atomically or
   fences them all;
8. always perform a fresh EDHOC handshake after restart for the first
   production profile. Same-context resume remains unsupported until a
   separately accepted M5 proof exists;
9. add RFC 9529, mutation, loss/reorder/duplicate, join-storm, storage-fault,
   allocator-exhaustion, Host cross-provider, ESP target-executed, and physical
   bearer HIL gates;
10. run a fresh independent security review before changing any production
    support state.

## Current decision

The library is a credible implementation candidate, and its heap-backed
functional suite is green. It is **not yet acceptable as-is** because the
default VLA backend violates the bounded Portable Core contract and the
upstream CMake dependency surface is too broad. Adoption requires the exact
custom-memory and crypto-provider boundary above, a Proposed ADR, independent
review, and implementation evidence.

## Proposed implementation order

This order is informative until a production Attachment ADR is accepted.

1. Freeze the Attachment scope, identity authority, pre-attachment carrier,
   EDHOC profile, exporter labels, install digest, and no-resume restart rule.
2. Pin and vendor the minimal libedhoc + zcbor source set with license,
   source-manifest, public-symbol, and upstream-diff gates.
3. Implement the bounded custom-memory owner and exhaustively test every
   allocation failure before wiring platform crypto.
4. Implement Host OpenSSL 3 and ESP-IDF Mbed TLS/PSA adapters and reproduce
   RFC 9529 plus cross-provider exporter equality.
5. Implement the bounded pre-attachment carrier independently from NFL1 and
   post-attachment NRW1/NWB1, including loss, reorder, duplicate, timeout,
   admission pressure, and join-storm controls.
6. Implement the EDHOC owner and credential resolver with message 4 required,
   no EAD extension, one active handshake per peer, and fixed global capacity.
7. Implement protected Attachment install/confirm and one atomic durable
   transaction for local identity, authority, active Attachment, two Hop
   directions, and two E2E directions.
8. Connect only opaque accepted tokens to T1c/N6; keep every LAB minting path
   outside production source and package manifests.
9. Add restart, power-loss, COMMIT_UNKNOWN, stale install, authority rotation,
   partial context, and credential replacement recovery matrices.
10. Complete Host fault/fuzz/soak, ESP target-executed tests, then physical
    Wi-Fi, USB, and radio HIL before changing the support matrix.
