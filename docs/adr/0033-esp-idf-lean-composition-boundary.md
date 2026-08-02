# ADR-0033: ESP-IDF lean composition boundary

- Status: Proposed
- Date: 2026-08-02
- Scope: ADR-0029 item 6, ESP32-S3 software composition only
- Depends on: ADR-0017, ADR-0025, ADR-0029, ADR-0032

## Context

ADR-0032 already provides the single public Runtime/Fabric owner. The ESP-IDF
tree also contains clock, execution, entropy, flash storage and USB CDC ports,
an ESP Wi-Fi packet-link candidate, and an SX1262 R9 physical candidate. They
are not at the same boundary:

- Wi-Fi already implements a Fabric packet-link, but its configuration and
  lifecycle header are private and its provisioning helper is HIL-only;
- SX1262 R9 reaches PHY TX/RX through the permit sole edge, but there is no
  ESP radio packet-link, and ADR-0017 forbids NFL1 radio send/receive until the
  NFL1-to-NRW1 mapping is Accepted; and
- USB CDC implements `ninlil_byte_stream_t`. It has no Fabric framing,
  custody, Receipt, or ApplicationData meaning.

Treating all three as interchangeable links would therefore create a false
contract. Adding another generic transport manager, callback registry, plugin
system, or dependency-injection graph would also duplicate ADR-0032.

## Decision

### 1. There is no second public owner

`ninlil_composition_v1_t` remains the only Runtime/Fabric composition owner.
The ESP application owns platform and transport objects and drives them from
one FreeRTOS task. No ESP helper owns a background Ninlil pump task.

This ADR proposes **no new public C type or symbol**. Until this ADR is
Accepted, it does not promote the state of any existing ESP port header. The
item-6 target application uses only the existing surfaces from:

- `ninlil/composition_v1.h` and `ninlil/fabric_v1.h`;
- `ninlil_esp_idf/clock.h`, `ninlil_esp_idf/execution.h`,
  `ninlil_esp_idf/entropy.h`, `ninlil_port/esp_storage.h`, and
  `ninlil_port/esp_storage_flash.h`; and
- `ninlil/byte_stream.h` plus `ninlil_esp_idf/usb_cdc.h`.

In particular, a header residing under `ports/esp-idf/include` does not by
itself promote a production-private radio or owner candidate into supported
V1 SDK API. Applications must not include `src/**`, `drivers/**`, a Wi-Fi
private header, or an HIL application header.

The first implementation slice may package `composition_v1` and its public
Fabric implementation into the ESP-IDF component and add public-only target
examples and gates. It must not invent an umbrella handle to make the private
Wi-Fi or radio candidates appear public.

### 2. Per-transport boundary and application-owned state

| Path | Application retains through close | V1 composition meaning |
| --- | --- | --- |
| Common | allocator, clock, execution, entropy, storage, Tx gate and origin-authorization pointees; composition PSRAM workspace; borrowed Runtime/Fabric handles | Portable API plus existing ESP port candidates; item-6 target-build boundary |
| USB CDC | `ninlil_esp_idf_usb_cdc_object_t`, `ninlil_byte_stream_t`, endpoint token and application parser buffers | Existing ESP port candidate; raw control/provisioning/diagnostic byte stream only; never a Fabric link |
| Wi-Fi | provision and credential source, M4 attachment carrier, TLS/STA/adapter workspaces, adapter and Fabric registration | Existing implementation candidate; not installed API until a separate Accepted public-facade amendment |
| SX1262 | flash binding, compliance/permit authority, bus, backend, PHY, R9 edge, HAL, profile, IRQ latch and future Fabric registration | Physical candidate only; Fabric registration forbidden until the RF mapping prerequisite is Accepted |

The ESP helper layer does not own credentials, keys, regulatory profiles,
site assignments, Join policy, or application service descriptors. HIL NVS
layout and serial commands are not promoted into an OSS provisioning API.

The current bootloader-RNG entropy adapter is boot-global and must be retired
before Wi-Fi/SX1262 RF or ADC initialization. It therefore cannot be silently
retained as the live Runtime entropy provider in a combined image. A combined
transport facade is blocked until an RF-safe public entropy provider or an
Accepted phase-separated entropy contract exists.

### 3. Exact owner order

All operations below occur on the same non-zero execution owner.

Construction is:

1. initialize application-owned allocator, execution, clock, suitable
   entropy, flash storage, Tx gate, and origin authorization;
2. call `ninlil_composition_v1_workspace_required`, reserve aligned PSRAM,
   then create the composition and borrow its Runtime and Fabric handles;
3. register zero or more application Services on the borrowed Runtime;
4. initialize and optionally open USB CDC as an independent control stream;
5. create each supported packet-link port, start bounded port stepping, and
   register it with the borrowed Fabric through its sole public registration
   operation only after that port reports registration-ready; and
6. continue the bounded owner loop.

The owner loop performs at most one call per enabled work class per outer
iteration, in this order:

1. Wi-Fi port step, when a future public facade is active;
2. SX1262 owner/PHY poll, when a future mapped radio facade is active;
3. USB poll with timeout zero, when USB is open; and
4. `ninlil_composition_v1_step` once with caller-supplied bounded budgets.

There is no loop-until-idle inside a helper. Work reported pending is handled
by a later outer iteration. This makes ingress visible before Fabric work;
new egress may wait one outer iteration, which is bounded and intentional.
USB bytes are delivered only to the application's control parser and are not
inserted into Runtime or Fabric by this order.

Graceful shutdown is:

1. stop admitting new application submissions and control commands;
2. logically close USB CDC and stop using its stream;
3. begin unregister for every Fabric packet-link; while any unregister is
   pending, continue one bounded port step and one bounded composition step
   per outer iteration, and allow already-admitted callbacks;
4. after registration removal completes, drain and destroy each Wi-Fi/radio
   port using its own contract;
5. call composition `close_begin`, bounded `close_poll`, then `destroy`;
6. release the composition workspace and unbind storage; and
7. retire clock/execution/entropy states only after every borrower is gone.

Composition close must not begin while a link registration remains. A radio
bus that returns `SHUTDOWN_REBOOT_REQUIRED` remains allocated and immutable
until reboot; no cleanup path may reuse or zero it. An uncertain durability
or port result is preserved and never translated into Application success.

### 4. One firmware may expose multiple capabilities

The ESP layer adds no single-role selector. One Runtime may register multiple
Services, and the application may receive actuator commands while publishing
events and periodic measurements. Service count and behavior remain governed
by the public Runtime contract, not by transport choice.

Endpoint, relay, and parent engine features may coexist in one firmware when
their existing Kconfig dependencies are enabled. A relay engine is not an
application Service and does not replace the Runtime role. Wi-Fi, future RF,
and USB may also coexist, but USB remains control-plane and an unavailable
transport does not disable unrelated Services.

The acceptance fixture for this rule uses one Runtime instance with at least
three Services: command receive, event publish, and request/periodic sensor
data. It drives them concurrently through one owner loop. No application- or
product-specific word enters portable Core, Fabric, wire, or storage schema.

### 5. Wi-Fi and radio publication stop conditions

The ESP Wi-Fi implementation may become a public facade only after a short
Accepted amendment fixes its public config/value types, status catalog, opaque
workspace, registration handle, and exact create/register/step/unregister/
close/destroy allowlist. That facade must wrap the current sole Fabric
registration path; it must not expose raw packet-link operations, private M4
capabilities, ESP native handles, or HIL NVS records.

The SX1262 implementation must not expose a Fabric facade until all of these
are true:

1. a separate ADR Accepts the exact bidirectional NFL1-to-NRW1 mapping, all
   supported/unsupported message kinds, fragmentation rules, and KATs;
2. the adapter implements one bounded Fabric packet-link over the existing
   permit/HAL/R9/PHY sole edge and does not mint RF authorization;
3. the combined image has an RF-safe entropy contract; and
4. Host loss/reorder/duplicate/restart tests pass before target promotion.

Until then, SX1262 can be built and tested as a physical candidate, but any
attempt to expose it to Fabric remains unsupported and calls the RF TX path
zero times. Full NFL1 bytes are not sent as an ad-hoc radio fallback.

### 6. ESP32-S3 resource and build gates

The item-6 software tranche is accepted only by the pinned ESP-IDF 5.5.3
ESP32-S3 build and these fail-closed gates:

1. `composition_v1.c`, the public Fabric wrapper, and required private Fabric
   implementation appear exactly once in the component archive and final ELF;
2. an application includes only public headers and links a live
   create/step/close path; private Wi-Fi/radio headers remain unreachable;
3. the Profile-1 composition workspace is at most 256 KiB, is aligned using
   `workspace_required`, and is verified in external PSRAM at runtime; it is
   absent from task stacks and internal DRAM/BSS;
4. before create, the largest external-PSRAM block covers the composition
   workspace plus every simultaneously reserved port workspace; there is no
   generic-heap or internal-DRAM fallback;
5. linker-map parsing finds all required sections and leaves at least 64 KiB
   of internal DRAM headroom after static data/BSS; a zero-match parse fails;
6. the new composition/owner glue has no VLA and no frame above 2 KiB; the
   retained application call chain plus a 4 KiB margin fits the configured
   main-task stack. Existing Wi-Fi 8 KiB and R9 16 KiB TU ceilings remain;
7. existing Wi-Fi allocator, USB object/ring, storage PSRAM, SX1262 sole-edge,
   private-symbol, and public-include gates remain green; and
8. a combined feature build proves simultaneous compilation. It does not
   claim that blocked Wi-Fi/radio public paths executed.

Large state is static or caller-owned workspace, never an automatic local in
`app_main`. Runtime allocation probes and linker-map evidence are both
required; either one alone is insufficient.

### 7. Host-testable pure logic

Any ordering reducer introduced for a reference application stays private and
contains only lifecycle states, completion flags, budgets, and next actions.
It contains no FreeRTOS, lwIP, TinyUSB, SPI, GPIO, native handle, wire codec, or
storage-record type. Host tests cover:

- partial construction rollback at every stage;
- registration conflict and unregister backpressure;
- one-call-per-class budget accounting and pending-work propagation;
- USB independence from Fabric success/custody;
- wrong owner, re-entry, close-before-unregister, and stale handle rejection;
- radio `UNSUPPORTED/TX 0` before mapping acceptance; and
- `SHUTDOWN_REBOOT_REQUIRED` immutable-object behavior.

These tests prove orchestration only. Physical USB, access-point, RF,
power-cut, regulatory, and field evidence remain `NOT_RUN` until actually
executed and recorded.

## Consequences

- The immediate ESP tranche is implementable without another framework or
  public ABI expansion.
- USB can support setup and diagnostics beside many Runtime Services without
  being misreported as a reliable application bearer.
- Wi-Fi promotion is a bounded public-facade decision rather than leakage of
  a private HIL configuration.
- Radio integration remains honest about its missing mapping, entropy, legal,
  and physical prerequisites.

## Current implementation evidence

The first software slice is implemented without accepting this ADR or
claiming target runtime/HIL completion:

- Host and ESP-IDF consume one explicit Fabric/Composition source authority;
- the ESP component archive contains each required Fabric/Composition object
  exactly once, and all eight Composition symbols are retained in the final
  ESP32-S3 ELF/map;
- a C11 target translation unit includes only
  `ninlil/composition_v1.h`, checks the Profile-1 workspace contract, and
  exercises every public API validation path;
- default, all-private-feature, Wi-Fi HIL, and SX1262 radio HIL images compile
  and link under the pinned ESP-IDF 5.5.3 container; and
- the tests-OFF installed Host package drives two Composition-owned
  Runtime/Fabric instances through ApplicationData and a verified Receipt in
  normal and ASan/UBSan builds.

The target probe deliberately does not fake a successful create. A live
target `create/step/close` path still requires a FULL-capable durable flash
provider and external-PSRAM runtime checks. The Wi-Fi public facade, Accepted
NFL1-to-NRW1 mapping and radio packet-link, RF-safe combined entropy contract,
independent review, and physical USB/AP/RF/power-cut evidence also remain
open. Therefore the ADR stays **Proposed** and every physical result stays
`NOT_RUN`.

## Non-goals

- A transport plugin manager, service locator, background pump, or generic
  dependency graph.
- A new wire format, storage schema, Join model, provisioning schema, or
  application vocabulary.
- Publishing private Wi-Fi, RF permit, fragmentation, relay, or HIL types.
- Treating target compile/link, Host simulation, or map placement as physical
  HIL or regulatory acceptance.
