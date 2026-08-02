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

Unknown version/kind/flags, zero operation ID, wrong direction or wrong length
is rejected before binding/work-slot, Storage, RF or Runtime mutation. The
already accepted NCG1 sequence advancement in section 1 is the sole exception.

`STATUS` payload is `code:u32`, `reserved_zero:u32` and
`pair_generation:u64`. Closed codes are `INSTALLED=1`, `ACCEPTED_LOCAL=2`,
`REJECTED=3`, `BUSY=4`, `STORAGE_UNKNOWN=5`, `UNSUPPORTED=6` and
`REPROVISION_REQUIRED=7`. It copies the request operation ID and is emitted at
most once. `STATUS` proves only local USB handling; it is never an Application
Receipt or RF delivery result.

Each side owns IDs for operations it originates. A received STATUS resolves
only the exact outstanding local ID. Unknown, duplicate and wrong-direction
STATUS messages are rejected without releasing another operation.

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
rejected. The USB board and host Controller process use the same endpoint
identity. Service rows identify that endpoint consistently:

- DesiredState is DOWNLINK from Controller to peer; and
- EventFact is UPLINK from peer to Controller.

Contradictory rows are rejected. A board accepts the payload only when its
configured Runtime ID is A or B and its radio site-domain and membership epoch
match. In the operational bridge, the USB parent is the Controller endpoint. A
peer may be connected temporarily for provisioning, but it cannot act as the
Controller bridge for this pair. A third carrier ID is not inferred.

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
zero secrets. EventFact evidence grace is zero; DesiredState grace is retained.

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

Policy revision/path epoch and authority term equal pair generation; assignment
epoch is its exact u32 value. Authority ID is the Controller Runtime ID.

The policy and RF descriptor are closed rather than caller-selected:
direction `FORWARD`, traffic class `APPLICATION`, scope `TARGET_RUNTIME`,
capabilities `UNICAST | REGULATED_RF | EVIDENCE`, all four security flags,
latency/cost class `0`, minimum packet bytes `587`, authority mode
`BOUND_REQUIRED`, deadline guard `0`, and one candidate with rank `1`,
reservation units `1`, flags/reserved `0`. Any differing value or canonical
digest is rejected.

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
`ninlil.n6.v1` namespace before an N6 object is created. Empty is valid.
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

## Acceptance before Accepted

1. NVB1 codec KATs cover all kinds/bounds, sequence consumption/fence and
   failure atomicity.
2. Binding KATs cover 1/3 rows, exact 557/966-byte limits, deterministic IDs,
   identity/Service negatives and four-slot capacity.
3. Storage tests cover namespace reset, exact N6 fresh install, coordinated
   receiver IDs/collision/floors, token single-consume and failure atomicity,
   FULL failure/COMMIT_UNKNOWN, cold-restart deny, one global strictly newer
   boot membership epoch shared by both pairs, pair generation floors,
   two-pair 28-row bound and fifth-record fence.
4. A PTY test uses the installed POSIX USB port and the same private bridge as
   ESP packaging.
5. Host vertical simulation covers two peers, the multi-Service node, both
   directions, APPLIED correlation, duplicate, timeout, tamper, wrong key,
   wrong binding/Service and restart/reprovision.
6. The ESP32-S3 target compiles/links this same codec, owner and bridge with
   no test-only provenance or public ABI exposure.

Physical USB/RF evidence remains `NOT_RUN` until ADR-0034's three-board run.

## Consequences

- V1 implements one understandable Controller↔peer path and no relay disguise.
- Restart is safe but deliberately requires fresh LAB provisioning.
- M5 resume, unrestricted N6 ESP readiness, separate carriers, Join, relay,
  multi-parent, fragmentation and field reassignment remain V2.
