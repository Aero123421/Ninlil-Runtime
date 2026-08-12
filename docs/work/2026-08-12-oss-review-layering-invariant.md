# 2026-08-12 OSS review layering invariant closure

## Scope and authority

This tranche closes OR-19 against the dependency rule in
`docs/01-architecture.md` and Accepted ADR-0003. It changes no public ABI,
wire format, storage format, or feature maturity.

Compile/source dependencies and runtime call flow remain distinct. In
particular, the R9 radio edge under `src/radio/` may depend on the portable
SX1262 PHY behind the radio HAL; ADR-0003 explicitly permits H1 -> D1. The
platform-specific Wi-Fi and crypto adapter translation units are also not
portable Core.

## Fresh audit before change

The current tree had these actual violations:

1. `src/runtime/mfdt_v1/mfdt_v1_target_alloc.c` directly included
   `esp_heap_caps.h` and selected ESP allocation with `ESP_PLATFORM`.
2. `src/runtime/route_relay_v1/rrmp_util.c` directly included either OpenSSL
   or mbedTLS and selected the provider with platform macros.
3. The private composition layer includes Fabric's implementation API, while
   `src/transport/fabric_v1/fabric_rrmp_select_hook.h` included an RRMP
   Runtime header in the reverse direction. Together these formed a Runtime
   <-> Transport source cycle.

The earlier RRMP owner-scratch tranche had already removed
`esp_heap_caps.h` from `rrmp_core.c`.

## Minimal closure

- Keep the generic MFDT allocation contract private and move only its ESP
  implementation to `ports/esp-idf/src`; Host keeps a plain C allocation
  implementation.
- Keep RRMP codec/core provider-agnostic and move only SHA-256 primitive
  adapters to Host/ESP port translation units selected by the existing source
  authorities.
- Put the optional Fabric -> RRMP notification behind an opaque,
  instance-local private callback. The upper composition/Runtime side may
  depend on Fabric, but Transport no longer imports a Runtime/RRMP header, so
  the reverse edge and cycle are gone.
- Add one stdlib-only include/source-authority gate. It resolves first-party
  includes across Public, Contract, Model, Runtime, Transport, and Radio,
  rejects every edge outside the declared direction or an exact existing
  private seam, rejects platform SDK headers from portable Core, checks the
  exact adapter source split, and carries negative self-tests for each
  violation class. Runtime composition may depend on the private Fabric
  abstraction as stated above.

The portable-header and direction rule is fail-closed rather than an SDK-name
denylist. Public headers may use ISO C and other public Ninlil headers; model
may additionally use model-private headers; Runtime may additionally use
model/Runtime-private headers. The only portable-to-Transport/Radio exceptions
are the three exact C4 glue edges already named above (`composition_v1.c` to
Fabric private API and `c4_c5_lab_wire.h` to its USB/radio path contracts).
Transport-to-Model/Radio and Radio-to-Model seams are likewise enumerated by
exact source/target pair rather than granting either directory blanket access.
An arbitrary repository-local header is therefore not an escape hatch.
The small set of existing platform-dependent Transport/Radio adapter files is
also enumerated exactly; every other file in those trees is portable and may
use only ISO C plus its declared first-party edges. Headers under `ports/` and
`drivers/` resolve into the same layer map and are allowed only for the two
exact existing D1 PHY seams. Unknown sibling/upward edges and every other
system/vendor header are rejected by default. Macro-expanded/non-literal include directives are
also rejected, so the literal allowlist cannot be bypassed through a local
macro. Self-tests include ESP-IDF, lwIP/POSIX sockets and
threads/files, Windows, Apple, Android, crypto SDK, and an unknown future
vendor header. Additional source mutations cover Runtime-to-Transport,
Model-to-Radio/Transport, Radio-to-Runtime/RRMP, and
Transport-to-Model/Radio; direct `.c` inclusion, POSIX/ESP headers in portable
Radio/Transport files, and a direct `ports/` header are also RED. This avoids both a new platform SDK
bypass and a first-party upward or unregistered sibling edge merely because
its name was not anticipated.

The gate intentionally does not create a new layer framework or split every
source into a new CMake target. Existing explicit source authorities remain
the build truth.

## Verification boundary

Focused Host tests cover normal private Runtime/Composition and RRMP paths;
the gate self-test proves representative SDK and cross-layer mutations fail.
ESP source authority and dry-run/map gates cover adapter selection, while a
fresh physical ESP build remains separate evidence.

Fresh normal and ASan/UBSan Fabric/RRMP two-instance isolation tests PASS.
The CTest-registered layering check/self-test are 2/2 PASS after the expanded
platform matrix. The check keeps a 30-second bound; the mutation-heavy
self-test has a 180-second bound so a parallel full suite cannot turn host
contention into a false timeout. This remains a concrete
include/source-authority guard; it
does not claim to be a general-purpose build-graph theorem prover.
