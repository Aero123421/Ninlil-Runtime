# ADR-0036: V1 USB bridge and LAB binding

- Status: Proposed
- Date: 2026-08-03
- Scope: ADR-0034 Controller-to-parent USB leg and ADR-0035 binding payload
- Depends on: ADR-0010, ADR-0034, ADR-0035 and NCG1
- Amends: ADR-0035 exact binding layout and the R6 private fresh-install
  provenance/allocation authority for this LAB profile only
- Keeps: every installed Runtime, Fabric and Composition ABI

## Context

V1 needs one usable path from a Linux/macOS application, through one
USB-connected ESP32-S3 + SX1262, to one of two direct RF peers. The existing
NCG1 codec and POSIX/ESP USB ports already provide the bounded byte stream.
U5 assignment, U6 custody, relay and automatic Join are outside ADR-0034.

The USB board is the radio half of the Controller Runtime endpoint, not a
third logical endpoint or relay. It therefore uses the same Controller Runtime
identity as the host-side Controller process. V1 has only Controller-to-peer
and peer-to-Controller security contexts. A physically separate carrier,
relay or multi-parent parent is V2 work.

The Linux/macOS process is the sole owner of the Controller Foundation Runtime,
Fabric and Composition. The USB board creates none of those objects. It is a
private, delegated radio adapter for that same endpoint identity and exchanges
only validated binding commands and complete NFL1 packets with the host.

## Decision

### 1. One private bridge

`NVB1` (Ninlil V1 USB Bridge) is a private payload carried only by NCG1
`DATA`. It adds no public symbol, installed header, plugin manager, transport
registry, background task or USB-as-Fabric-link abstraction. One bounded
bridge step is called from the existing outer loop.

NCG1 is fixed to `version=1`, `type=DATA`, `flags=0` and
`stream_or_cell_id=0`. Each physical-link generation starts TX/RX sequence at
zero and then increments by exactly one. Duplicate, gap, regression or wrap
fences the bridge. Recovery requires a new, strictly different physical
`link_generation`.

Every raw read/write is ticketed with the generation observed before I/O. If
the link or generation differs after I/O, bytes are not processed and the
post-I/O generation is itself fenced. It cannot be adopted on the next step;
recovery requires one further physical-link generation. This prevents bytes
possibly accepted by a reconnecting stream from sharing sequence or operation
IDs with a freshly reset bridge.

Sequence `UINT32_MAX` is never emitted or accepted. After successfully
emitting or accepting `UINT32_MAX-1`, that direction is exhausted; another
frame in that direction requires a new physical-link generation. An incoming
`UINT32_MAX` fences before NVB1 processing and does not advance sequence.

After NCG1 framing/CRC acceptance, sequence is validated before NVB1. An exact
sequence is consumed even when later fixed-field or NVB1 semantic validation
fails. A sequence mismatch does not advance. This sequence advancement is the
only mutation allowed before NVB1 semantic acceptance.

### 2. NVB1 envelope

All integers are unsigned big-endian. One envelope is 16..1024 bytes and never
spans NCG1 frames.

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `NVB1` |
| 4 | 1 | version, exactly `1` |
| 5 | 1 | kind |
| 6 | 2 | flags, zero |
| 8 | 8 | non-zero operation ID, unique in this link generation |
| 16 | 0..1008 | kind payload |

| Kind | Value | Direction | Payload |
| --- | ---: | --- | --- |
| `BINDING_SET` | 1 | Controller to board | exact LAB binding below |
| `FABRIC_PACKET` | 2 | either | one complete NFL1 Application or Receipt |
| `STATUS` | 3 | response | exact 16-byte local status |
| `BOARD_INFO` | 4 | board to Controller | exact 32-byte boot clock anchor |

Unknown version/kind/flags, zero operation ID, wrong direction or wrong length
is rejected before binding/work-slot, Storage, RF or Runtime mutation. The
already accepted NCG1 sequence advancement in section 1 is the sole exception.

`STATUS` payload is `code:u32`, `reserved_zero:u32` and
`pair_generation:u64`. Closed codes are `INSTALLED=1`, `ACCEPTED_LOCAL=2`,
`REJECTED=3`, `BUSY=4`, `STORAGE_UNKNOWN=5`, `UNSUPPORTED=6` and
`REPROVISION_REQUIRED=7`. It copies the request operation ID and is emitted at
most once. `STATUS` proves only local USB handling; it is never an Application
Receipt or RF delivery result.

Each side owns IDs for requests it originates. Its private bridge allocator
starts at `1` in every physical-link generation and assigns the next exact ID
only when a request enters a work slot. Received requests must therefore use
the next exact inbound request ID. Reuse, gap, regression or `UINT64_MAX`
fences before work mutation. `STATUS` only echoes a received request ID and
does not consume either request allocator. After allocating or accepting
`UINT64_MAX-1`, that request direction is exhausted until a new generation.

A received STATUS resolves only the exact outstanding local ID. Unknown,
duplicate and wrong-direction STATUS messages are rejected without releasing
another operation or fencing an otherwise continuous link. This bounded
monotonic rule proves uniqueness without an unbounded seen-ID set.

`BOARD_INFO` is the only one-way NVB1 notification. Its payload is
`clock_epoch_id[16]`, `clock_now_ms:u64`, `clock_trust:u32` and
`reserved_zero:u32`. The epoch is non-zero, trust is exactly `TRUSTED`, and
reserved bits are zero. The board emits it exactly once at the start of every
physical link generation, before accepting `BINDING_SET`. It consumes the
normal outbound NCG1 sequence and outbound NVB1 operation ID, but has no
`STATUS` response and occupies no request slot. The Controller must
successfully apply the anchor before the bridge allows construction or
submission of the boot's LAB binding. A failed anchor handoff fences that
physical-link generation. It uses the epoch and sampled time to configure the
Controller clock view; the USB boundary remains
trusted-local and this notification is not an authenticated network-time
protocol.

The board firmware does not compile a Controller or peer Runtime ID. When its
provisioner starts in USB-parent mode, the first valid binding derives the
local Runtime ID from the binding's already-validated `controller_side`.
When it starts in peer mode, it derives the local Runtime ID from the opposite
endpoint. That ID becomes immutable for the rest of the boot. A Controller may
then accept one additional pair naming the same Controller Runtime; a peer may
accept only its first pair. A malformed binding, inconsistent Service
directions, local clock-epoch mismatch, failed generation/secret floor, or
failed Storage/N6 admission does not publish an identity. These two explicit
boot profiles are bounded LAB bootstrap, not automated Join, field
reassignment or hardware identity.

`INSTALLED` carries the exact accepted binding `pair_generation`; every other
STATUS carries zero. Provisioning results map exactly as follows:

- success -> `INSTALLED`;
- commit outcome unknown -> `STORAGE_UNKNOWN`;
- generation/secret floor violation, definite Storage/N6 failure or any
  fenced provisioner ->
  `REPROVISION_REQUIRED`;
- non-fencing capacity or invalid provisioner state -> `BUSY`;
- malformed or semantically invalid incoming binding -> `REJECTED`.

### 3. Exact single-frame LAB binding

The `BINDING_SET` payload is 557..966 bytes. It binds exactly one Controller
Runtime/Application pair to one RF peer and contains one to three Services.
The installed Runtime may expose more Services; this is only the V1 radio-pair
limit.

The fixed header is 420 bytes:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | format version, `1` |
| 1 | 1 | Service row count, `1..3` |
| 2 | 2 | flags, zero |
| 4 | 8 | pair generation, `1..UINT32_MAX` |
| 12 | 120 | endpoint A identity |
| 132 | 120 | endpoint B identity |
| 252 | 16 | radio site-domain ID |
| 268 | 8 | non-zero radio membership epoch |
| 276 | 4 | A-to-B Hop context ID |
| 280 | 4 | A-to-B E2E context ID |
| 284 | 32 | A-to-B Hop traffic secret |
| 316 | 32 | A-to-B E2E traffic secret |
| 348 | 4 | B-to-A Hop context ID |
| 352 | 4 | B-to-A E2E context ID |
| 356 | 32 | B-to-A Hop traffic secret |
| 388 | 32 | B-to-A E2E traffic secret |

Each endpoint identity is exactly 120 bytes: Runtime ID 16, Application
instance ID 16, device ID 16, installation ID 16, site ID 16, binding epoch 8,
membership epoch 8, identity flags 4, clock epoch ID 16 and clock trust 4.
Foundation presence validation is reused exactly. Runtime/Application/clock
IDs are non-zero and clock trust is TRUSTED or UNCERTAIN.

Endpoint A has the lexicographically smaller Runtime ID; equal Runtime IDs are
rejected. Each endpoint has its own non-zero boot-local clock epoch ID; the two
IDs may differ and no clock value is compared across them. A DesiredState
deadline stays in the Controller endpoint's epoch. A peer Receipt keeps that
deadline unchanged and carries evidence time in the peer endpoint's epoch.
Consequently peer evidence alone cannot prove the Controller deadline when the
epochs differ: the Controller Runtime applies its existing trusted ingress-time
fallback and otherwise reports an indeterminate deadline verdict. Fabric
admission, availability, attestation, authority leases, mapper expiry and
rollback checks use only the local endpoint clock. The USB board and host
Controller process still use the same Controller endpoint identity and clock
anchor. Service rows identify that endpoint consistently:

- DesiredState is DOWNLINK from Controller to peer; and
- EventFact is UPLINK from peer to Controller.

Contradictory rows are rejected. A bound board accepts the payload only when
its Runtime ID is A or B and its local clock epoch, radio site-domain and
membership epoch match. An unbound diagnostic board accepts only the endpoint
selected by its explicit USB-parent or peer boot profile, and publishes that
identity only after durable provisioning succeeds. In the operational bridge,
the USB parent is the Controller endpoint. A peer may be connected temporarily
for provisioning, but it cannot act as the Controller bridge for this pair. A
third carrier ID is not inferred.

Rows are sorted by ascending unique slot. Each row is 134 fixed bytes followed
by three 1..16-byte UTF-8/opaque text IDs:

| Relative offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | Service slot, `1..31` |
| 1 | 1 | flow: `1=A-to-B`, `2=B-to-A` |
| 2..4 | 3 | namespace/service/schema lengths, each `1..16` |
| 5 | 1 | zero |
| 6 | 8 | non-zero descriptor revision |
| 14 | 32 | non-zero descriptor SHA-256 digest |
| 46 | 2 | non-zero schema major |
| 48 | 2 | schema minor |
| 50 | 4 | EventFact or DesiredState family |
| 54 | 4 | UPLINK=1 or DOWNLINK=2 |
| 58 | 2 | Fabric APPLICATION=1 |
| 60 | 2 | zero |
| 62 | 8 | evidence grace milliseconds |
| 70 | 32 | Service identity digest |
| 102 | 32 | canonical V1 path-policy digest |
| 134 | variable | namespace, service and schema bytes |

The decoder recomputes the existing Service identity digest and rejects
duplicate identities/slots, unsorted rows, trailing bytes, unsupported
family/direction/class, invalid endpoint shape, context ID 0/`UINT32_MAX` and
zero secrets. EventFact evidence grace is zero. DesiredState grace is retained
and is `0..60000` ms; its Runtime descriptor always advertises the fixed,
non-zero 60000 ms maximum, including when the exact binding row selects zero.

`pair_binding_digest` is SHA-256 of the exact binding payload. It is the
provisioning/storage identity and the Hop `attachment_id` input. Fabric
`attachment_binding_digest` and the R7 E2E `e2e_security_id` instead use:

`SHA-256("NINLIL-V1-LAB-E2E-ID" || binding[0..275] ||
binding[280..283] || binding[352..355] || binding[420..end])`.

That logical projection includes the version/count/flags/generation,
endpoints, site, membership, both E2E context IDs and every Service row. It
excludes both Hop context IDs and all four traffic secrets. Therefore a Hop
rotation can never silently change E2E identity, and secret bytes are not used
as an identity. For each direction the owner passes these identities through
the existing canonical R7 Hop/E2E binding digest functions before installing
the resulting directional digest into N6. Reprovision still replaces all four
children together in V1; independent Hop rotation remains V2.

The private policy builder keeps ADR-0035's single candidate and recomputes the
existing canonical digest. IDs are deterministic:

- path ID: first 16 bytes of SHA-256(`NINLIL-V1-LAB-PATH-ID` || endpoint A
  Runtime ID || endpoint B Runtime ID || pair generation u64 || flow u8);
- policy ID: first 16 bytes of SHA-256(`NINLIL-V1-LAB-POLICY-ID` || the same
  common material || Service slot || Service identity digest).

Policy revision and authority term equal pair generation; assignment epoch is
its exact u32 value. Authority ID is the Controller Runtime ID.

`path_selection_epoch` is not binding metadata. It remains the sender Fabric's
durable, monotonically allocated dispatch epoch. The compact NRA1 body does not
carry it. An outbound Application correlation therefore copy-owns the complete
NFL1, including its exact path-selection epoch. A peer reconstructs an inbound
Application with the authenticated pair generation as a local canonical epoch;
Fabric forward admission does not use that field as authority. If the peer
later emits a Receipt, its compact Receipt is decoded at the original sender
against that sender's retained NFL1, restoring the exact original epoch. No
pair builder, USB payload or caller may set or predict a sender Fabric epoch.

The policy and RF descriptor are closed rather than caller-selected:
direction `FORWARD`, traffic class `APPLICATION`, scope `TARGET_RUNTIME`,
capabilities `SLEEP_COMPATIBLE | UNICAST | RESERVATION | REGULATED_RF |
EVIDENCE`, all four security flags, latency/cost class `0`, minimum packet
bytes `587`, authority mode `BOUND_REQUIRED`, deadline guard `0`, and one
candidate with rank `1`, reservation units `1`, flags/reserved `0`. The RF
descriptor has send+receive directions, maximum packet/transfer bytes `760`,
reservation capacity `1`, NFL1 peer version/capability `1`, and no custody or
broadcast capability. Any differing value or canonical digest is rejected.

There is one logical RF registration for each distinct flow present in a pair,
not one registration per Service. Its instance ID is that flow's derived path
ID. Rows with the same flow share the registration. The local descriptor pins
the other endpoint as authenticated peer, the Controller Runtime as attachment
authority, the logical E2E identity as attachment binding, and the local
endpoint clock epoch for attestation and availability. Descriptor,
configuration, security-profile, security-binding and attestation identities
are deterministic SHA-256 domain-separated derivations of the exact binding
digest, logical E2E identity, path ID, local Runtime ID and peer Runtime ID;
their revisions/epochs equal pair generation and expiries are `UINT64_MAX` for
this boot-only LAB attachment. The private builder is the sole implementation
of those derivations and byte-exact KATs pin every result before acceptance.

The common descriptor derivation input is the following exact concatenation:

`pair_binding_digest[32] || e2e_security_id[32] || path_id[16] ||
local_runtime_id[16] || peer_runtime_id[16] || pair_generation:u64be`.

The descriptor digest, security binding digest, attestation digest and
configuration digest are respectively SHA-256 of the ASCII tag
`NINLIL-V1-LAB-RF-DESCRIPTOR`, `NINLIL-V1-LAB-RF-SECURITY-BINDING`,
`NINLIL-V1-LAB-RF-ATTESTATION` or
`NINLIL-V1-LAB-RF-CONFIGURATION`, followed by that common input. The security
profile ID is the first 16 bytes of SHA-256 of
`NINLIL-V1-LAB-RF-SECURITY-PROFILE` followed by the same input. Tags have no
terminating NUL on input. `security_binding_digest` uses that derived value;
`attachment_binding_digest` is the exact already-derived
`e2e_security_id`. Configuration identity implicitly fixes ADR-0034's V1 LAB
radio profile; changing that profile requires a new derivation tag/ADR rather
than silently reusing this descriptor.

Each Service gets one deterministic authority binding ID derived from the pair
ID, pair generation, Service slot and Service identity digest. Its target is
the forward-flow target endpoint, authority ID is the Controller Runtime,
authority term/assignment epoch/revision are the exact pair generation, owner
scope is the first 16 bytes of the stable pair ID, and its 200-byte canonical
owner tuple is a fixed versioned projection of the binding, endpoints, flow,
slot, policy and logical E2E identity with the unused tail zero. The local
endpoint clock epoch and `UINT64_MAX` lease are used on each side. A
Receipt uses this retained original forward authority and policy; no reverse
binding is synthesized and no peer timestamp is rewritten into the Controller
clock.

The authority binding ID is the first 16 bytes of SHA-256 over the non-NUL
ASCII tag `NINLIL-V1-LAB-AUTHORITY-ID`, followed by `pair_id[32]`, pair
generation u64be, Service slot u8 and Service identity digest `[32]`. The exact
200-byte owner tuple is:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII `NVO1` |
| 4 | 1 | version `1` |
| 5 | 1 | original Application flow |
| 6 | 1 | Service slot |
| 7 | 1 | zero |
| 8 | 8 | pair generation u64be |
| 16 | 16 | Controller Runtime ID |
| 32 | 16 | forward source Runtime ID |
| 48 | 16 | forward target Runtime ID |
| 64 | 16 | forward target Application ID |
| 80 | 16 | policy ID |
| 96 | 32 | canonical policy digest |
| 128 | 32 | logical E2E security ID |
| 160 | 32 | Service identity digest |
| 192 | 8 | zero |

The existing Fabric owner-tuple SHA-256 helper computes its digest; no second
tuple encoding or product-selected owner bytes are allowed.

R7 uses LAB, the explicit radio site/membership, the binding digest and pair
generation. Hop and E2E stable IDs are the same Controller/peer Runtime pair.
DesiredState deadline clock is the Controller clock; EventFact has no deadline
clock. Receipt evidence clock/trust comes from the target endpoint. A local
clock identity mismatch disables the pair until fresh reprovisioning.

### 4. Fresh N6 provisioning without same-context resume

The V1 owner has exactly four fixed pair slots. Stable pair ID is:

`SHA-256("NINLIL-V1-LAB-PAIR-ID" || A Runtime ID || A Application ID || B Runtime ID || B Application ID)`.

Its 36-byte Storage key is ASCII `NLB1` followed by pair ID. The value is the
exact binding payload in the private `ninlil.v1.lab` schema-1 namespace. A
malformed record, duplicate key or more than four records at boot fences all V1
RF traffic. At most two pairs may be active on the USB parent and one on a
peer; the four-record limit retains generation floors for inactive pairs.

V1 does not implement M5 or same-context resume. Boot reads every `NLB1`
record only to recover each pair's generation floor and one global maximum
radio-membership floor, zeroizes the read scratch and leaves RF disabled. A
binding may be accepted only when its generation is strictly greater than
that pair's floor and its radio membership epoch is strictly greater than the
global maximum from every stored pair. The first accepted binding fixes that
value as `boot_radio_membership_epoch`; every pair activated later in the same
boot must use the exact same value. A differing value is rejected. This keeps
the shared local receiver/layer allocator namespace fresh across every pair,
not merely within one pair.

The first accepted provisioning command in a boot performs one bounded FULL
transaction that enumerates and erases every record in the dedicated
`ninlil.n6.v1` namespace before the N6 owner is bound or booted. Empty is valid.
Definite reset failure leaves RF disabled; `COMMIT_UNKNOWN` requires restart.
A later command in the same provisioning boot never resets the namespace
again. Numeric context IDs may start again at the allocator floor only under
the new `boot_radio_membership_epoch`. All four secrets must differ from the
prior binding. Equal/lower floors and generation `UINT32_MAX` are
`REPROVISION_REQUIRED`.

After reset, the owner initializes the existing N6 engine with exactly eight
slots, binds the board's accepted local identity, binds one class-D sample from
the existing R2 authority clock, and runs an empty `boot_scan`.

R6 normally gives each receiver sole allocation authority. A receiver-first
exchange would add a three-pass provisioning protocol before this V1 can move
one packet. For this private LAB profile only, the trusted-local Controller is
the allocator coordinator for the fresh, empty N6 namespace and chooses all
four context IDs in the exact binding. This explicitly amends receiver-sole
allocation authority. The V1 owner validates the A/B endpoint mapping:
A-to-B IDs belong to endpoint B and B-to-A IDs belong to endpoint A. N6 then
checks its generic local shape (`inbound receiver == local`, `outbound receiver
!= local`), namespace collision and next valid allocator floor. No such
coordinator authority exists after the first install, outside this LAB owner,
or for a non-empty namespace.

The trusted LAB USB binding owner then mints four private, single-use
accepted-install tokens per pair: outbound/inbound Hop and outbound/inbound
E2E. The token is an opaque incomplete private type. Only this owner may mint
it and only the N6 verifier/consumer may consume it, exactly once. On consume,
N6 copies and owns every field of the existing install capsule before any
mutation, validates it through the normal N6 checks, and zeroizes the claim.
A malformed token, failed verification or second consume performs no Storage
or context mutation. Raw provenance values are never caller-selectable. The
production raw-capsule APIs remain fail-closed and the public ABI is unchanged.

The private adapter is intentionally one fixed ABI rather than a framework.
The accepted authority claim is exactly 32 bytes (`abi:u16`, `size:u16`,
`reserved:u32`, `clock_epoch_id:16`, `now_ms:u64`). The accepted install claim
is exactly 128 bytes (`abi:u16`, `size:u16`, `reserved:u32`, followed by the
layer/direction/allocation side, context ID, membership epoch, key generation,
binding digest, traffic secret, local node ID and receiver node ID). Each has
one exact-size ops table and one `consume` callback. The owner never exposes a
raw trust boolean or caller-owned byte span. Hop and E2E use the same claim
shape and distinct accepted entry points; the entry point fixes the required
layer before durable work.

These callbacks are not a new cryptographic proof system. Their trust boundary
is the source-controlled, private V1 provisioning owner, which accepts only a
decoded binding and a direct typed class-D R2 result from the same local call
chain. A CI callsite gate fixes all four `*_accepted` production calls to that
one owner; adding another production caller requires this ADR and the gate to
change together. Tests may provide local tokens only from `tests/`.

The N6 subset is deliberately bounded. Two pairs require eight live contexts
and at most 28 durable rows, below the ESP per-namespace limit of 32. The board
uses at most four namespaces: local Runtime state when present, `ninlil.pcp.v1`,
`ninlil.n6.v1` and `ninlil.v1.lab`; the ESP production configuration is raised
only to its existing hard maximum of four. This does not claim the unrestricted
128-slot N6 profile to be ESP-ready.

Each N6 context install is FULL. After all four installs for a pair succeed,
one FULL transaction writes its exact `NLB1` value; only then is the pair
published. A definite or unknown failure after any N6 install fences the V1
owner, shuts down N6 to zeroize every live key/handle, and requires
restart/reprovision instead of rollback. Pair replacement
while active is unsupported. A second peer can be added in the same boot
without reset; if its install fails, all V1 RF is fenced. Reprovision, fence and
close zeroize keys and temporary binding bytes. USB disconnect fences USB
operations but does not stop an already active pair in the same boot.

### 5. Application and Receipt flow

`FABRIC_PACKET` admits only:

- Application with 1..128 payload bytes, zero evidence and an exact active
  Service match; or
- Receipt with zero payload/evidence and an existing non-terminal correlation.

With the V1 16-byte text-ID cap, an Application is at most 760 bytes and a
Receipt at most 632 bytes, below the 1008-byte NVB1 payload ceiling;
segmentation is not used. On downlink the parent validates NFL1, maps it to
NRA1 and starts the RF operation. On uplink it reconstructs NFL1 from the
authenticated binding and forwards it to the Controller application. A
correlated NFL1 Receipt is then mapped back to RF. USB write/decode/STATUS and
RF-byte reception are never APPLIED.

The bridge owns one binding-work slot and four packet-work slots. Inbound work
is released by exactly one downstream handoff result or link fence. Outbound
work is released by matching STATUS, local timeout or link fence. STATUS ends
only the USB operation; the radio mapping owns its separate maximum-four
Application correlations until exact Receipt, terminal Runtime result, timeout
or restart releases them.

The private bridge executes binding install and Fabric handoff synchronously
from its bounded `step`; callbacks must not re-enter the same bridge. A Fabric
handoff returns one of `ACCEPTED_LOCAL`, `REJECTED`, `BUSY` or `UNSUPPORTED`
and never claims RF delivery. A missing handoff returns `UNSUPPORTED`. At most
one complete NCG1 frame awaits raw-stream acceptance, so five outstanding
operations do not require five packet copies. While a response cannot be
queued, the bridge stops reading instead of growing another queue.

The complete private bridge object is fixed at no more than 6144 bytes. If a
local deadline expires before its request reaches raw-stream acceptance, the
slot completes as timeout and the current generation fences: the already
allocated request ID cannot be skipped safely. A timeout after raw acceptance
does not fence; a late STATUS is ignored and the next request ID remains valid.
Raw receive scratch and unused residual tails are zeroized before returning
from a step that handled bytes. Parser payload/window are fully zeroized after
an accepted or rejected complete frame and on every fence; an incomplete frame
retains only the exact prefix required by the next step.

The board configuration also has one fixed installed-pair handoff, not a
registry. It is required before `BINDING_SET` can mutate Storage. After a
successful durable install it receives the immutable binding bytes and the
four copied N6 handles, copies any needed values before returning, and cannot
reject or retain the borrowed binding pointer. A missing provisioner or
installed-pair handoff returns `UNSUPPORTED` without provisioning.

### 6. Linux/macOS Controller adapter

The Controller process uses one private, caller-owned USB Fabric adapter. It
wraps the existing host-side NVB1 bridge and exposes one Fabric packet-link
port for each distinct `selected_path_id` in the installed bindings. The V1
bound is two direct peer bindings and four path ports, matching the fixed
USB-board pair capacity. It does
not create a second Runtime or Fabric, add an installed API, parse application
configuration, start a background thread or turn USB into a new public Fabric
kind. The Linux/macOS outer loop performs one bounded USB step and one bounded
Composition step.

The adapter is inactive until the host has accepted `BOARD_INFO`, submitted an
exact binding and received `INSTALLED` for that binding. It then registers the
descriptor, policy and authority records derived by the existing LAB Fabric
builders. Runtime output enters the adapter only through the registered Fabric
packet-link operation, with the original selected path and Foundation
`TxPermit`. The adapter validates the permit against its trusted Controller
clock and exact attempt before the NVB1 request is retained. The existing
durable Fabric attempt authority remains the one-shot replay authority; the
adapter retains only its bounded live permit/token state and never mints a
replacement permit.

Each RF registration passes through Fabric's existing private volatile
RF-mapping gate immediately after the exact binding-derived link is
registered. Only those binding-derived path IDs are approved; registration or
approval failure aborts activation. No public arbitrary-RF approval surface is
added.

There are at most four retained outbound USB operations and one inbound NFL1
loan per distinct path. `ACCEPTED_LOCAL` becomes Fabric transport completion,
not Application success. USB timeout, link fence or an unknown completion is
lost/unknown; a definite remote rejection is a definite transport failure.
An inbound packet is copied only after NFL1 decode and exact active path match,
then returned from `receive_next`; release zeroizes that path's one receive
slot. Backpressure returns `BUSY`/`WOULD_BLOCK` without another queue.

The repository's completed V1 Controller executable is specified as a LAB
diagnostic, not a daemon or deployment manager. It uses the existing
Composition, POSIX USB serial and SQLite providers, consumes an exact
application-neutral binding, and reports transaction/Receipt results. Its
default connection-probe mode stops after clock verification, binding apply,
Composition creation and Fabric registration. Binding inventory or
key-management UX remains an application concern and is not implemented as a
second Ninlil framework.

The same executable provides one optional diagnostic submission:

```text
--send-binding 1|2 --send-service SLOT --payload-hex HEX
```

The three options are all-or-none. The binding number is its one-based command
line order; `SLOT` must identify one DesiredState row whose flow leaves the
Controller; and `HEX` is an even-length 1..128-byte ApplicationData value. The
default invocation remains the connection probe. Send mode registers only that
exact Runtime Service, uses a CSPRNG idempotency key, generation 1, VERIFIED
required evidence, and the existing bounded timeout as the public API's
relative effect-deadline duration. It then drives the existing USB and
Composition steps until the transaction is terminal. It exits successfully
and prints a single
application-neutral `SATISFIED` summary only for a satisfied transaction with
VERIFIED evidence. Timeout, rejection, another terminal outcome or cleanup
failure exits nonzero. It never prints the payload, binding, key material or
derived secrets.

The process-local wait bound uses the POSIX monotonic clock. After activation,
USB/Fabric request deadlines and bridge steps use the Controller's anchored
trusted clock, which is also the `TxPermit` clock; a request may not compare a
deadline from one clock domain with `now` from the other. All pre-activation
requests are complete before this transition. Before a successful one-shot
process closes USB, it drains both the pending bridge response and the POSIX
byte-stream TX ring so the peer can observe the terminal local status.

This is deliberately a one-shot physical-path diagnostic. It is not a daemon,
command language, application configuration layer, Service discovery system or
deployment manager. Applications that need continuous submission, EventFact
consumption or their own result presentation use the installed Runtime API and
their own process lifecycle.

The Host acceptance path for this diagnostic is one continuous execution, not
a collection of mocked hand-offs. A separate Controller process opens a real
PTY through the public POSIX USB port and submits through the public Runtime.
The PTY bytes enter the fixed USB board owner, the resulting NFL1 packet crosses
the existing NRA1/NRW1/R7/R9/SX1262-spy path, and a peer Runtime invokes its
Application callback. That peer Runtime must generate VERIFIED Receipt evidence
through the same radio path in reverse; the USB parent returns it to the
Controller, whose transaction becomes satisfied and whose process exits zero.
The test may replace only physical USB and RF propagation with PTY and SX1262
bus spies. It may not synthesize the Receipt, bypass either Runtime, or add a
general simulation framework.

The connection probe prints `READY` only after registered links are quiesced
and Composition has completed its normative close/destroy sequence. A bounded
cleanup failure exits nonzero without releasing owner resources early.

The executable does not use the tests-only POSIX LAB platform. Its private
Host provider set is fixed to one owner thread, the existing SQLite port,
OpenSSL 3 CSPRNG entropy and a monotonic clock view anchored to the USB
parent's accepted `BOARD_INFO`. The clock keeps the parent's exact epoch and advances its sampled
time only by local monotonic elapsed time; rollback, overflow or a changed
anchor fails closed. The V1 LAB mapping and diagnostic submission path require
1..128-byte ApplicationData payloads, while the Service descriptor supplies
the portable upper bound of 128 bytes. Its LAB TxGate validates the resulting
complete logical bearer message against the fixed 760-byte packet ceiling for
both Application and Receipt. The Controller diagnostic
originates DesiredState only, so its required origin
authorization provider rejects Controller-origin EventFact instead of adding a
general policy engine. These are not installed providers or general policy
APIs. This LAB executable uses the Foundation small-profile store and therefore
requires the incomplete Domain schema 1 Runtime binding to remain disabled;
the build rejects that unsupported option combination instead of failing later
during Runtime creation.

Because an exact binding contains traffic secrets, the diagnostic reads it
only when the path's final component is a non-symlink regular file with one
link, owned by the effective user and with no group/other permissions. It
accepts only the exact binding size range and never prints binding contents or
derived secrets.

### 7. Fixed board owner

The USB board has one private, caller-owned `V1 LAB board owner`. It owns the
NVB1 bridge, the single SX1262 packet-link and two fixed pair slots. It does
not create a second Foundation Runtime or Fabric, publish a plugin API, start a
background task or allocate from the heap. The application calls one bounded
owner step from the same task that owns the USB byte stream and radio path.

The owner is initialized only with already-bound platform dependencies: the
trusted clock, durable provisioner, R7 crypto provider, SX1262 PHY, PCP
authority, radio HAL and active live radio profile. The USB-parent and peer
profiles start with their corresponding unbound adoption provisioner from
section 2; after the first valid binding durably publishes the selected local
Runtime ID, the owner initializes the one packet-link with the adopted ID. It
does not start RF before that point. A successful `BINDING_SET` callback creates
exactly two R7 directional
binds from the four returned N6 handles and the authenticated binding context IDs.
Only the direction transmitted by the local endpoint receives PCP/HAL/live
authority. The callback then installs the exact pair into the fixed packet
link. Capacity or any contradiction fences the owner; it cannot fall back to
another peer, key, path or radio configuration.

A Controller-to-board `FABRIC_PACKET` already passed the Controller Fabric's
TxGate and logical RF-path selection before entering the trusted-local USB
leg. The board therefore does not mint, reconstruct or pretend to possess a
second Foundation `ninlil_tx_permit_t`. It re-decodes the complete NFL1,
requires an exact active pair/Service/path match, maps it through NRA1 and then
uses the existing R7/R2/R5/R9 sole edge. `ACCEPTED_LOCAL` means only that this
bounded radio operation was retained; it is never transport completion or an
Application Receipt. A later RF failure is observed by the Controller as a
missing authenticated Receipt and remains owned by the existing Runtime retry
policy.

For RF-to-USB traffic the owner borrows exactly one decoded NFL1 from the
packet-link and submits one NVB1 `FABRIC_PACKET`. It retains that radio receive
loan until the host returns `ACCEPTED_LOCAL`. Only that result commits a
pending compact-Receipt correlation. Link loss, timeout, `BUSY`, rejection or
any mismatched result aborts that pending mapper token and drops the loan
without committing or erasing the correlation; the remote Runtime remains the
retry owner. No board-local retry loop or second packet copy is added.

One owner step performs, in order, at most one prior USB completion, one NVB1
bridge step, one radio progress unit and one new RF-to-USB handoff. It never
loops until idle. USB disconnect fences that USB generation but does not
fabricate RF success or erase an already active pair. Radio corruption,
binding contradiction or a fenced provisioner fences the whole owner and
prevents further RF admission. Physical USB/RF operation remains a separate
HIL gate.

The owner has exactly two compile-time selected data consumers. A USB-parent
uses the RF-to-USB behavior above. A generic peer uses `local Fabric`: USB is
retained only for `BOARD_INFO` and exact binding installation, USB
`FABRIC_PACKET` is rejected, and an installed RF receive loan is left for the
peer's registered Fabric packet-link instead of being drained by the board
owner. The selection is explicit at owner initialization and cannot change in
the same boot. Local-Fabric mode requires one bounded pair-ready callback; a
callback failure fences the owner after the already-durable binding rather
than falling back to USB forwarding.

### 7.1 Fixed peer Runtime composition

The generic-peer image owns one private `V1 LAB peer Runtime` object. It is a
fixed composition seam, not an installed API, role manager, plugin system or
application framework. Before provisioning it owns no Runtime. The board
owner's pair-ready callback copy-retains the first exact binding and the next
caller-driven step creates one endpoint `ninlil_composition_v1_t` using the
peer endpoint adopted by the provisioner. It registers:

- one RF packet-link for each distinct binding flow (at most two);
- the exact path policy and authority row already derived from the binding;
- every Service row in that binding (one to three) as an independent Runtime
  Service; and
- one caller-supplied, application-neutral delivery callback table for those
  Services. The application may obtain a Service handle by its exact binding
  slot to originate EventFact data, and may borrow the active Runtime handle
  for the existing public query/list APIs. The peer object retains ownership;
  neither borrow survives close.

Service descriptors copy the binding's namespace, Service, schema, revision,
digest, family and direction. Their remaining V1 contract is fixed: payload
upper bound 128 bytes, one target, application deduplication, required-evidence
custody, eight attempts per retry cycle and bounded 10-second admission. A
DesiredState Service admits Controller-origin downlink and an EventFact
Service admits peer-origin uplink; application-specific vocabulary is not part
of the descriptor builder. DesiredState's descriptor maximum evidence grace is
the fixed 60000 ms binding ceiling, while EventFact keeps zero.

The peer object supplies only the two missing fixed Runtime providers around
the caller's allocator, execution, clock, entropy and Storage: a fixed
760-byte logical-message TxGate (the Service descriptor enforces the 128-byte
upper bound; the binding-scoped origin grant also rejects zero-length
EventFact payloads) and a binding-scoped EventFact origin
grant. Both use the adopted endpoint and trusted boot clock; only the TxGate
draws from the configured entropy provider. The binding-derived origin grant
does not invent random policy state. Neither provider creates a general policy
engine. Progress remains one board-owner step followed by one bounded
Composition step on the same owner task. Close unregisters the fixed paths
before the normative Composition close/destroy sequence and never frees
borrowed platform, radio or workspace storage early.

### 8. ESP32-S3 diagnostic board profiles

The repository provides two default-off `radio_hil_app` build profiles for
physical USB/RF bring-up: `USB parent` and `generic peer`. They compile the same
source and differ by one fixed Kconfig role bit; V1 does not add a dynamic role
manager. Both enable the existing V1 LAB packet-link, open the native USB CDC
control stream and drive exactly one fixed board owner from the `app_main` task.
UART remains the diagnostic console. Neither image has a compiled Runtime ID,
and neither admits RF traffic until section 2's first valid binding adoption.
The peer profile additionally creates the fixed peer Runtime composition from
section 7.1 after that adoption; the USB-parent profile does not create a
second Runtime.

This profile deliberately uses session LAB Storage because the current ESP
flash adapter does not attest a successful `FULL` commit. The USB-parent
allocates one fixed provisioning ledger from PSRAM. The generic peer allocates
that same provisioning ledger plus one separately namespaced Runtime/Fabric
ledger; separating them prevents the fixed provisioning bounds from being
silently consumed by application state. Each ledger has the same exact bounds:
three namespaces, 32 entries per namespace, 48-byte keys and 1024-byte values.
The provisioning ledger is sufficient for PCP, N6 and two NLB1 pair records;
the peer ledger is sufficient for the one fixed Composition. Allocation or
initialization failure is fail-closed. Neither ledger has a growth policy or
fallback store.

The profile is marked `session_diag`, is never a release or restart-durability
claim and does not satisfy ADR-0034's flash-FULL acceptance requirement.
Power-cycle reprovisioning is required. Its purpose is to close target wiring
and enable physical USB/RF diagnosis while the independently gated flash-FULL
proof remains pending; software or hardware evidence from this profile must
retain that nonclaim.

## Acceptance before Accepted

1. NVB1 codec KATs cover all kinds/bounds, sequence consumption/fence and
   failure atomicity.
2. Binding KATs cover 1/3 rows, exact 557/966-byte limits, deterministic IDs,
   distinct endpoint clock epochs, local-clock-only rollback fencing,
   identity/Service negatives and four-slot capacity.
3. Storage tests cover namespace reset, exact N6 fresh install, coordinated
   receiver IDs/collision/floors, token single-consume and failure atomicity,
   FULL failure/COMMIT_UNKNOWN, cold-restart deny, one global strictly newer
   boot membership epoch shared by both pairs, pair generation floors,
   two-pair maximum-28-row bound, exact 32-row reset, Controller/peer identity
   adoption and fifth-record fence.
4. A PTY test uses the installed POSIX USB port and the same private bridge as
   ESP packaging. A Controller-adapter test additionally drives a registered
   Fabric packet link through binding, outbound completion and inbound NFL1.
5. Host vertical simulation covers two peers, the multi-Service node, both
   directions, APPLIED correlation, duplicate, timeout, tamper, wrong key,
   wrong binding/Service and restart/reprovision. The happy path must use the
   public Runtime surface rather than only hand-built NFL1: Controller
   ApplicationData reaches the selected peer Service callback and the
   callback-generated Receipt returns; an EventFact submitted through the
   peer Service reaches the Controller side. Focused failure tests remain the
   authority for the negative cases and are not duplicated in this vertical
   test.
6. The ESP32-S3 target compiles/links the same codec, owner and bridge in both
   USB-parent and generic-peer profiles, and the peer profile also links the
   fixed Runtime composition, with no test-only provenance or public ABI
   exposure.

Physical USB/RF evidence remains `NOT_RUN` until ADR-0034's three-board run.

## Consequences

- V1 implements one understandable Controller↔peer path and no relay disguise.
- Restart is safe but deliberately requires fresh LAB provisioning.
- M5 resume, unrestricted N6 ESP readiness, separate carriers, Join, relay,
  multi-parent, fragmentation and field reassignment remain V2.
