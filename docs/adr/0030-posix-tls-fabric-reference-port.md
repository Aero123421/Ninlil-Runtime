# ADR-0030: POSIX TLS Fabric reference port

- Status: Accepted
- Date: 2026-08-02
- Scope: Linux/macOS Host reference transport for ADR-0029 item 3
- Depends on: ADR-0017, ADR-0029
- Review: [2026-08-02 POSIX TLS reference-port specification review](../reviews/2026-08-02-posix-tls-reference-port-spec-review.md)

## Context

ADR-0029 accepts one portable public Fabric and then requires a real Host
TCP/TLS path. The existing ADR-0018 candidate contains useful TCP, TLS, bounded
framing, reconnect and packet-link code, but its private umbrella surface also
contains ESP ownership and internal attachment machinery. Publishing that
umbrella would make the V1 SDK larger and would couple Host users to internals.

On POSIX, the operating system owns Wi-Fi or Ethernet association. Ninlil only
needs a nonblocking authenticated TCP/TLS packet-link port. It is therefore
named `posix_tls_v1`, not a Wi-Fi application API.

## Decision

### 1. One Host-only package

The package is `Ninlil::posix_tls_v1` and installs one header:
`ninlil/posix_tls_v1.h`. It is supported only on Linux and macOS, links
`Ninlil::fabric_v1` and OpenSSL 3, and is experimental under the 0.x policy.
The experimental SDK accepts supported OpenSSL 3.x at configure/runtime; an
immutable pinned OpenSSL receipt remains a later `RELEASE_SUPPORTED` gate and
is not allowed to make ordinary installed consumers unusable.

The public target requires `OpenSSL >=3,<4`, links both `OpenSSL::SSL` and
`OpenSSL::Crypto`, and the installed package performs the matching
`find_dependency`. Its source list is an explicit POSIX allowlist and contains
no ESP STA/lwIP/mbedTLS/owner source. Normal SDK operation does not depend on
the private `NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL` LAB macro.

Portable Runtime and Fabric do not import POSIX sockets or OpenSSL. The package
does not expose `SSL *`, file descriptors, private session records, NWB1
frames, attachment evidence handles or test helpers.

### 2. Exact public purpose

One port instance owns exactly one client connection or one server listener
plus its current accepted connection. It:

- performs nonblocking TCP and TLS 1.3 mutual authentication;
- verifies the configured runtime/authority binding against both leaf
  certificates and TLS exporter context;
- frames only canonical NFL1 packets over the bounded NWB1 record format;
- exposes the link only by registering it with one public Fabric instance;
- reports disconnect as unavailable or lost-unknown, never as delivery
  success;
- reconnects with the fixed bounded profile already implemented by the Host
  candidate; and
- has no hidden thread, sleep, callback worker or unbounded queue.

Membership and deployment decisions remain outside this port. A caller gives
the port one immutable **trusted local static provisioning root** produced by
its management plane. The port does not authenticate that root and never
derives membership merely from a successful TLS handshake. Changing peer,
authority, certificate, endpoint or descriptor requires draining and creating
a new instance with a newer descriptor configuration revision.

### 3. Exact public types

The header defines only these opaque types:

```c
typedef struct ninlil_posix_tls_v1 ninlil_posix_tls_v1_t;
typedef struct ninlil_posix_tls_registration_v1
    ninlil_posix_tls_registration_v1_t;
```

The value types are:

```c
typedef uint32_t ninlil_posix_tls_status_t;
typedef uint32_t ninlil_posix_tls_role_t;
typedef uint32_t ninlil_posix_tls_operational_state_t;

typedef struct ninlil_posix_tls_endpoint_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t address_kind;
    uint16_t port;
    uint16_t reserved_zero_u16;
    uint32_t scope_id;
    uint8_t address[16];
} ninlil_posix_tls_endpoint_v1_t;

typedef struct ninlil_posix_tls_paths_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    const char *ca_pem_path;
    const char *cert_pem_path;
    const char *key_pem_path;
} ninlil_posix_tls_paths_v1_t;

typedef struct ninlil_posix_tls_leaf_expectation_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t role;
    ninlil_id128_t runtime_id;
    uint8_t leaf_spki_sha256[32];
    ninlil_id128_t authority_id;
    uint64_t authority_term;
    uint8_t authorized_attachment_binding_digest[32];
    uint32_t credential_generation;
    uint32_t revocation_generation;
} ninlil_posix_tls_leaf_expectation_v1_t;

typedef struct ninlil_posix_tls_authorization_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t assignment_epoch;
    uint32_t reserved_zero;
    ninlil_posix_tls_leaf_expectation_v1_t local_leaf;
    ninlil_posix_tls_leaf_expectation_v1_t peer_leaf;
    ninlil_id128_t registry_epoch_id;
    uint8_t credential_reference_digest[32];
    uint64_t credential_revision;
} ninlil_posix_tls_authorization_v1_t;

typedef struct ninlil_posix_tls_config_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t role;
    uint32_t flags;
    ninlil_id128_t instance_id;
    ninlil_posix_tls_endpoint_v1_t endpoint;
    ninlil_posix_tls_paths_v1_t tls_paths;
    ninlil_posix_tls_authorization_v1_t authorization;
    ninlil_fabric_link_descriptor_v1_t link_descriptor;
    ninlil_bytes_view_t storage_namespace;
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;
} ninlil_posix_tls_config_v1_t;

typedef struct ninlil_posix_tls_state_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t operational_state;
    uint32_t reason;
    uint64_t availability_epoch;
    uint16_t local_port;
    uint16_t reserved_zero_u16;
    uint32_t reconnect_count;
    uint64_t accepted_send_count;
    uint64_t accepted_receive_count;
} ninlil_posix_tls_state_v1_t;
```

`paths` and `storage_namespace` are borrowed only during `create`; the port
copies them into its caller-owned workspace. Each path is valid UTF-8 without
embedded NUL and at most 1023 bytes. The namespace is 1..127 bytes.

The leaf expectations are part of the trusted static root. Local and peer roles
must be opposite and match the configured port role. Runtime ID, SPKI digest,
authority ID/term, attachment binding, credential generation and revocation
generation are exact-match fields; none is learned and then trusted from the
connection. `credential_revision` must fit `uint32_t` and equal the local leaf
credential generation.

The public constants are exact:

```text
NINLIL_POSIX_TLS_API_VERSION = 0x0001

status:
  OK=0, INVALID_ARGUMENT=1, WRONG_THREAD=2, REENTRANT=3,
  UNSUPPORTED=4, WOULD_BLOCK=5, UNAVAILABLE=6, DENIED=7,
  CAPACITY=8, CORRUPT=9, CLOSED=10, IO=11, TLS=12,
  STORAGE=13, STORAGE_COMMIT_UNKNOWN=14

role: CLIENT=1, SERVER=2
address: IPV4=1, IPV6=2

operational state:
  CREATED=1, LISTENING=2, CONNECTING=3, HANDSHAKING=4,
  AUTHENTICATED=5, ATTACHED=6, BACKOFF=7, UNAVAILABLE=8,
  DRAINING=9, CLOSED=10, FENCED=11

reason:
  NONE=0, CONFIG=1, PEER_AUTHORIZATION=2, TLS=3, IO=4,
  STORAGE=5, LOST_UNKNOWN=6, LOCAL_CLOSE=7
```

Unknown status/state/reason and a status/output-shape contradiction are
`CORRUPT`. All constants and value layouts enter the existing ABI manifest.

### 4. Exact public functions

The complete function allowlist and signatures are:

```c
ninlil_posix_tls_status_t ninlil_posix_tls_v1_workspace_required(
    uint32_t *out_bytes, uint32_t *out_alignment);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_create(
    const ninlil_posix_tls_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_posix_tls_v1_t **out_port);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_descriptor_snapshot(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_register_fabric(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_v1_t *fabric,
    ninlil_posix_tls_registration_v1_t **out_registration);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_begin(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_poll(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration,
    uint32_t *out_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_step(
    ninlil_posix_tls_v1_t *port,
    uint32_t work_budget,
    uint32_t *out_work_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_state(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_state_v1_t *out_state);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_begin(
    ninlil_posix_tls_v1_t *port);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_poll(
    ninlil_posix_tls_v1_t *port, uint32_t *out_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_destroy(
    ninlil_posix_tls_v1_t *port);
```

The port never exports raw packet-link operations. `register_fabric` is the
only production registration path and binds the provider to exactly one
`ninlil_fabric_v1_t`. It is available after successful `create` while the
network link is still unavailable, returns one opaque registration only on
`OK`, and never describes `COMMIT_UNKNOWN` as atomic success. Unregister must
finish before close can finish.

### 5. Validation and attachment

`create` captures one non-zero execution owner and validates exact ABI/size,
zero reserved fields, non-zero IDs/revisions/digests, trusted clock, endpoint,
path limits and complete platform operations. Server port zero is allowed and
the bound port appears in `state`; client port zero is invalid.

The descriptor must be bidirectional Wi-Fi kind, must not advertise custody,
must advertise integrity, confidentiality, replay protection and session
freshness, and must fit the implemented NWB1/NFL1 bounds. Its authenticated
peer runtime, attachment authority/binding, attestation clock/expiry and
configuration tuple must match the TLS leaf binding, trusted clock and public
authorization/configuration.

Both local and peer leaf certificates must exactly match their provisioned
leaf expectation, including SPKI, role, runtime, authority term, attachment
binding and credential/revocation generations. The TLS exporter client/server
runtime order is derived from the two expected leaf roles, never from local /
peer ordering.

After mutual TLS, exact leaf matching and the first exporter succeed, the port
may mint the existing internal session-authority capability. It then writes
and re-reads the internal FULL membership, credential, attachment and Fabric
registry records under its private namespace. These records provide durable
consistency, linear consumption and restart fencing; **their write or re-read
does not create authorization**. Authorization comes only from the trusted
static root plus exact certificate/exporter checks. Only a fully re-read match
can enable the second exporter and `ATTACHED`. The private capability, evidence
type and record schema remain non-public. A failed, ambiguous or commit-unknown
result does not publish the link.

This limited `POSIX_STATIC_MTLS_PROFILE_1` is not the full ADR-0018 Wi-Fi
authority-clock profile. OpenSSL verifies chain/notBefore/notAfter against the
Host OS wall clock, while descriptor attestation, permits and stored lease
bounds use the configured trusted monotonic Clock. Both checks must pass. A
full authority-clock certificate chain and physical Wi-Fi profile remain
outside this tranche and cannot be claimed from this Host result.

This is static provisioning, not a public membership protocol. A future
composition owner may obtain the same immutable configuration from its
canonical management path; this port does not add join commands or deployment
vocabulary.

### 6. Progress, ownership and shutdown

Only `step` performs socket, TLS, reconnect, attachment or packet progress.
Each call accepts a 1..64 work budget and returns completed work. Provider and
storage callbacks are synchronous on the owner context and may not re-enter
the port, Fabric or Runtime. Wrong-thread and re-entry return with zero I/O,
mutation and callback effects.

The port copies the Storage, Clock and Execution vtables during `create`.
Their function code and non-NULL `user` pointees remain caller-owned through
successful `destroy`. Workspace and copied TLS paths remain valid for the same
lifetime. Port and Fabric must capture the same execution owner.

`register_fabric` is an intentional controlled composition call. During that
call only the exact Fabric instance may invoke the port's private `open` and
`state` entries under the prepared registration generation; this is not
general callback re-entry. Every public port call and all other callback
re-entry remain rejected. The returned registration is a port-owned borrow,
valid through `unregister_poll(done=1)` and consumed at that point.

Registration is allowed while the link is unavailable. It remains active
across disconnect/reconnect and is consumed only by explicit unregister. For
every unavailable/available transition, the port increments its availability
epoch exactly once and, while registered, calls
`ninlil_fabric_v1_link_availability_update` exactly once with the strict next
epoch. A `COMMIT_UNKNOWN` or contradictory update fences the port and publishes
no new I/O.

The port durably stores its last availability epoch and a clean-close marker.
Clean close first publishes and persists unavailable, so clean recreation can
re-register with the exact durable state and then advance on a new attachment.
A restart without a valid clean-close marker is `FENCED` in this tranche,
whether the last durable availability was available or unavailable. A
commit-unknown marker is not valid. Crash reconciliation is not silently
treated as clean restart.

Connection loss increments availability epoch. Every retained token records a
single `crossed_uncertain_boundary` bit, set only after the first positive TLS
write for that token's NWB1 record. Loss before the bit is set is definite
failure; loss after it is `LOST_UNKNOWN`. The same attempt is never
automatically resent. TLS/TCP completion is never Application success.
Reconnect uses the same immutable peer and descriptor and starts a fresh TLS
exporter, attached session and sequence zero.

`unregister_begin` first ensures the registered link has published unavailable,
then calls public Fabric unregister. A Fabric registration
`COMMIT_UNKNOWN` leaves the port fenced with a NULL public result; it is never
described as success. `close_begin` stops new connection and registration work.
The caller finishes unregister, then bounded `step` drains tokens/receive loans,
closes TLS/socket/listener, fully persists the clean-close marker, and only then
closes storage. Marker `COMMIT_UNKNOWN` fences the port and cannot complete a
clean close. `close_poll` reports done only after this order completes.
`destroy` only succeeds after done, zeroes the workspace and consumes the
object.

The ordinary drive order is `port.step -> runtime.step -> fabric.step ->
port.step`; each component keeps its own bounded budget. During shutdown the
Runtime stops first, then the caller drives `port.step -> fabric.step ->
unregister_poll` until consumed, followed by port close polling. No operation
implicitly steps another component except the explicit Fabric registration,
availability-update and unregister calls described above.

## Acceptance

The tranche is accepted only when:

1. A tests-OFF clean install on Linux/macOS exports only the stated header and
   `Ninlil::posix_tls_v1` target; no `src/**` or private symbol is required.
2. An external two-process consumer uses public Runtime, Fabric and POSIX TLS
   APIs over real loopback TCP/TLS: submit, peer callback, reverse verified
   Receipt and terminal satisfied outcome.
3. Focused fault injection proves separately: disconnect before any positive
   TLS write is definite failure; disconnect after a partial positive TLS
   write is lost-unknown; the old transaction never becomes satisfied and the
   same attempt is not resent. Reconnect then uses a new exporter/session,
   sequence zero and a new transaction that completes.
4. After clean unregister/close/destroy, both processes recreate Runtime,
   Fabric and the port with the same public Storage providers and complete a
   new transaction. Old token/session/exporter identifiers are rejected.
   A focused restart test stops after durable unavailable and before the
   clean-close marker, then proves recreation is fenced. Crash/power-cut
   completion is not claimed by this tranche.
5. Wrong certificate/runtime/authority/descriptor, expired attestation,
   malformed frame, duplicate/gap sequence, wrong thread, re-entry and bounded
   close negatives fail closed in focused module tests.
6. Strict normal and ASan/UBSan focused suites pass. macOS and Linux CI remain
   explicit platform evidence; physical access-point/HIL remains `NOT_RUN`.

The partial-write fault is a private deterministic test hook compiled only in
the focused test target. It is absent from installed headers and libraries.

## Rejected scope

- Publishing the private ADR-0018 umbrella header or ESP types.
- A transport plugin registry, background event loop or generic socket SDK.
- DNS discovery, mDNS, dynamic peer selection or in-place credential rotation
  in this tranche.
- Public attachment evidence, NWB1, MFDT, fragmentation, relay or route-state
  APIs.
- Treating Host TLS success as physical Wi-Fi, field or release completion.
