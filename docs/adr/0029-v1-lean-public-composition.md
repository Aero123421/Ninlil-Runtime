# ADR-0029: V1 Lean Public Composition Boundary

- Status: **Accepted**
- Date: 2026-08-02
- Accepted: 2026-08-02
- Specification review: independent re-review GO, P0=0 / P1=0 / P2=0
- Scope: Ninlil 0.1 public SDK composition

Acceptance evidence:
[first review](../reviews/2026-08-02-v1-lean-public-composition-first-review.md)
and [repair re-review](../reviews/2026-08-02-v1-lean-public-composition-rereview.md).

## Context

The public Foundation Runtime is installable and usable through
`Ninlil::runtime`. Fabric, Wi-Fi, relay/multi-parent, radio fragmentation and
multi-frame transfer also have private software candidates, but publishing all
of them as independent packages before V1 creates a larger API and acceptance
system than an application needs.

V1 needs one clear application API, one transport-composition boundary, and
reference Host/ESP32 ports. Applications should describe services, targets and
delivery requirements. They should not operate chunk engines, relay state
machines or parent failover internals.

ADR-0028 remains a possible long-term modularization plan. It is not a V1
release prerequisite and no eight-module promotion is implied by this ADR.

## Decision

### 1. Application contract remains the Foundation Runtime

Applications use the existing public operations:

- create and step a Runtime;
- register one or more Services on the same Runtime;
- submit ApplicationData to explicit targets;
- receive deliveries and complete them with Application evidence;
- query/list transaction state.

No transport-specific word, route, parent, frame or radio detail is added to
the Foundation application API.

### 2. V1 adds one portable composition module

V1 publishes one experimental portable module, `fabric_v1`, which implements
the existing `ninlil_bearer_ops_t` contract. Its Host CMake target is
`Ninlil::fabric_v1` and its public header root is `ninlil/fabric_v1.h`.

The minimum public surface is limited to:

- opaque instance lifecycle and caller-owned workspace sizing;
- access to its `ninlil_bearer_ops_t`;
- bounded packet-link registration and removal;
- bounded path-policy and authority installation/removal;
- `step`, graceful close and link/metrics inspection;
- the packet-link provider contract required by reference ports.

Test seams, codec helpers, storage-record internals and implementation utility
functions are not public.

The exact public opaque types are `ninlil_fabric_v1_t` and
`ninlil_fabric_link_registration_v1_t`. The public value types are
`ninlil_fabric_config_v1_t`, `ninlil_fabric_link_descriptor_v1_t`,
`ninlil_fabric_policy_candidate_v1_t`, `ninlil_fabric_path_policy_v1_t`,
`ninlil_fabric_authority_binding_v1_t`, `ninlil_fabric_link_metrics_v1_t`,
`ninlil_fabric_packet_view_v1_t`, `ninlil_fabric_link_completion_v1_t`,
`ninlil_fabric_link_state_v1_t`, and
`ninlil_fabric_packet_link_ops_v1_t`. Their layouts are the v1 layouts fixed
by ADR-0017's exact type catalog; the private object/registration names are
replaced by the two opaque public names. No private helper type is imported.

The public status is `ninlil_fabric_status_t` with macros
`NINLIL_FABRIC_OK=0`, `NINLIL_FABRIC_INVALID_ARGUMENT=1`,
`NINLIL_FABRIC_WRONG_THREAD=2`, `NINLIL_FABRIC_REENTRANT=3`,
`NINLIL_FABRIC_CLOSED=4`, `NINLIL_FABRIC_CONFLICT=5`,
`NINLIL_FABRIC_UNSUPPORTED=6`, `NINLIL_FABRIC_CORRUPT=7`,
`NINLIL_FABRIC_COMMIT_UNKNOWN=8`, `NINLIL_FABRIC_DENIED=9`,
`NINLIL_FABRIC_UNAVAILABLE=10`, `NINLIL_FABRIC_CAPACITY=11`, and
`NINLIL_FABRIC_WOULD_BLOCK=12`. Link and completion statuses retain the exact
ADR-0017 v1 names and values.

The complete first-tranche public function allowlist is:

```text
ninlil_fabric_v1_workspace_required
ninlil_fabric_v1_create
ninlil_fabric_v1_bearer_ops
ninlil_fabric_v1_register_link
ninlil_fabric_v1_unregister_begin
ninlil_fabric_v1_unregister_poll
ninlil_fabric_v1_policy_put
ninlil_fabric_v1_policy_remove
ninlil_fabric_v1_policy_snapshot
ninlil_fabric_v1_authority_put
ninlil_fabric_v1_authority_remove
ninlil_fabric_v1_authority_snapshot
ninlil_fabric_v1_link_snapshot
ninlil_fabric_v1_link_availability_update
ninlil_fabric_v1_metrics_snapshot
ninlil_fabric_v1_step
ninlil_fabric_v1_close_begin
ninlil_fabric_v1_close_poll
ninlil_fabric_v1_destroy
```

The v1 bounds are 16 registered links, 64 policies, 64 authority bindings, 64
active attempts, and 8 candidates per policy. `workspace_required` is the sole
authority for bytes/alignment; profile 1 currently requires 198656 bytes. The
caller owns the workspace until successful `destroy` and must not move or
reuse it earlier. `create` copies the three platform vtables; their `user`
contexts remain caller-owned and must outlive Fabric. Link registration copies
the descriptor and provider vtable; the provider `user` context must outlive
unregistration/close. The returned Bearer ops and registration handles are
borrowed from the Fabric instance and expire at destroy. Packet views and
received bytes are callback-scoped borrows. Snapshot outputs are caller-owned
copies.

`create` captures the non-zero execution owner. Except for the pure
`workspace_required`, every public operation is owner-context-only and rejects
re-entry from a provider callback. `WRONG_THREAD` and `REENTRANT` perform no
storage mutation, provider call, transport I/O, or application callback.
`close_begin` starts bounded draining; only `step` progresses retained tokens.
`close_poll` reports done only after the outer Bearer is closed, all tokens and
received loans are released, providers are closed, and storage is closed.
`destroy` before that point returns `WOULD_BLOCK`; successful destroy zeroes
the owned object region.

The public wrapper maps each existing private candidate result one-to-one. It
does not catch, retry, downgrade, mask unknown values, or translate a transport
result into Application success. Private codec/projection, dispatch-release,
trigger-release, workspace-proof, hash and test symbols are not declared by
the public header, are non-public and outside the ABI guarantee, and must not
be called directly. Because V1 ships a static archive, forcing every hidden
private global to a local archive symbol is not a V1 goal; that does not make
such implementation symbols supported API.

The module is experimental under the package 0.x policy. A breaking public
change requires a package minor-version change; wire and storage versions do
not change implicitly with the package version.

### 3. Platform transports are ports, not new application models

After the portable Fabric tranche is accepted:

- POSIX TCP/TLS Wi-Fi is exported as a Host reference port linked to Fabric;
- ESP-IDF exposes public ESP32 composition helpers for Wi-Fi, SX1262 and USB;
- platform credentials, sockets, GPIO/SPI and task ownership remain in their
  respective port layers.

The portable Core does not import OpenSSL, ESP-IDF, lwIP or radio drivers.

### 4. Reliability engines remain internal in V1

Multi-frame transfer, radio fragmentation, relay/multi-parent routing and
radio-to-Fabric mapping are Runtime/Fabric implementation engines. They may be
enabled by a reviewed Runtime/port configuration, but V1 does not publish
their internal state-machine APIs as separate SDKs.

A separate public module is added only when an external caller use case cannot
be expressed through Runtime, Fabric, or a platform port. Internal test access
is not sufficient justification.

Before V1 software completion, a small `composition_v1` owner must connect
these internal engines without exposing them. It is part of `Ninlil::runtime`,
not a separately versioned package. Its only public responsibility is to:

- accept the ordinary Runtime configuration and a platform template;
- create/recover internal sidecars before opening the Runtime Bearer;
- install the Fabric Bearer into the Runtime platform copy;
- drive Runtime, Fabric and enabled internal engines with one bounded step;
- close them in reverse order and preserve restart fences.

The composition owner never accepts raw chunks, route-state structs or parent
state-machine commands from an Application. Attachment/session and route
installation arrive through their canonical management paths. The exact
`composition_v1` C types and symbols must be fixed in a short normative
amendment before its implementation; absence of that amendment or any use of
private headers by an installed consumer blocks V1 completion.

Its mandatory public-only acceptance paths are:

1. ApplicationData larger than one packet is split, reassembled, applied once,
   Receipted and terminalized after a cold restart.
2. An RF link with a smaller MTU exercises fragmentation/reassembly without
   exposing fragments to the Application.
3. Relay forwarding and multi-parent switch preserve the transaction identity,
   create a new attempt when required, and never report success from custody
   or path availability alone.

### 5. Ownership and bounded execution

Runtime and Fabric are instance-local. Two Runtime/Fabric pairs in one process
must not share mutable singleton state. Each instance has one execution owner;
callbacks are not invoked concurrently by the library. Work per `step` call is
bounded, and caller-owned/static workspace limits remain explicit.

### 6. Honest completion boundary

Software acceptance never implies physical radio, Wi-Fi access-point,
power-cut, regulatory or field acceptance. Those remain separate HIL evidence.

## V1 implementation order

1. Publish and install `fabric_v1` without changing the Foundation ABI.
2. Prove a tests-OFF installed consumer with two independent instances:
   public submit -> Fabric -> peer Runtime callback -> Application Receipt.
3. Publish the POSIX Wi-Fi reference port and repeat the same path over real
   TCP/TLS, including reconnect and restart cases.
4. Publish the Linux/macOS POSIX USB serial reference port and its installed
   byte-stream consumer.
5. Add the public-only Runtime composition owner and its large-data,
   fragmentation and relay/multi-parent Host paths.
6. Publish the ESP-IDF composition helpers and run ESP32-S3 build/map gates.
7. Run physical Host USB, ESP USB, Wi-Fi and SX1262 HIL. Record unrun cases as
   `NOT_RUN`.

Only the current item is implemented at a time. Later items do not require
future-only public types in an earlier tranche.

## Acceptance for the first tranche

The Fabric tranche is accepted only when all of the following are true:

1. A tests-OFF clean install exports `Ninlil::fabric_v1` and only public
   headers are needed by the consumer.
2. The installed consumer creates two isolated Fabric instances, registers a
   bounded direct packet link on each, and completes a real public Runtime
   transaction and reverse Receipt.
3. Duplicate delivery invokes the Application callback exactly once. Loss and
   backpressure never terminalize as success. Wrong-thread/re-entry causes
   mutation, callback and I/O count zero. Restart does not duplicate an effect
   and fences an uncertain send until reconciliation. After close, no callback
   occurs and draining remains bounded.
4. Normal strict-warning and ASan/UBSan Host runs pass on the scoped tests.
5. Default Foundation-only consumers remain source and ABI compatible.
6. No private `src/**` include directory or test helper appears in the install
   tree or exported target.

Physical HIL is not required to accept the portable Fabric module, and the
portable result must not be reported as physical-path completion.

The tests-OFF installed consumer proves the two-instance happy path and package
purity. The five negative groups in item 3 are module-owned focused tests; they
are not copied into one oversized external-consumer executable.

## Consequences

- V1 has a small, understandable SDK surface.
- Applications stay independent of Wi-Fi, LoRa, relay and fragmentation
  mechanics.
- Internal engines can evolve without creating multiple premature public
  ABIs.
- ADR-0028 and its conservative manifest may continue to describe future
  optional-module work, but their eight-module promotion is not on the V1
  critical path.

## Non-goals

- Declaring `RELEASE_SUPPORTED` before platform and HIL gates pass.
- Publishing raw MFDT, RRMP, FRAG or codec state machines.
- Adding a general plugin framework, dynamic loader, dependency injection
  container or new schema solely for possible future use.
- Claiming automatic route or parent policy that is not exercised by the
  shipped Runtime/port composition.
