# ADR-0032: Runtime composition v1

- Status: Accepted
- Date: 2026-08-01
- Scope: ADR-0029 item 5 public Runtime composition owner
- Depends on: ADR-0017, ADR-0019, ADR-0020, ADR-0021, ADR-0029
- Review: [independent GO, P0=0 / P1=0 / P2=0](../reviews/2026-08-01-runtime-composition-v1-spec-review.md)

## Context

The public Runtime and Fabric can already be installed and composed manually.
The repository also contains internal multi-frame transfer, radio
fragmentation, relay and multi-parent engines. Publishing those engines as
separate SDKs would make an Application own transport state that ADR-0029
deliberately keeps internal. Leaving all composition to the Application is
also unsafe: sidecar recovery can happen after the Bearer opens, completed
Fabric attempts can retain bounded capacity, and a process-global relay owner
cannot isolate two Runtime/Fabric pairs.

V1 therefore needs one small owner that connects existing components. It does
not need a plugin system, a new wire/storage schema, or a second application
model.

## Decision

### 1. Package and public surface

The installed header is `ninlil/composition_v1.h`. Its implementation and
link dependencies are part of `Ninlil::runtime`; there is no separately
versioned CMake package or engine SDK.

The complete public type allowlist is:

```text
ninlil_composition_v1_t
ninlil_composition_step_budget_v1_t
ninlil_composition_step_result_v1_t
```

`ninlil_composition_v1_t` is opaque. The two value types have these exact
layouts:

```c
#define NINLIL_COMPOSITION_API_VERSION ((uint16_t)0x0001u)
#define NINLIL_COMPOSITION_PROFILE_1 ((uint32_t)1u)

typedef struct ninlil_composition_step_budget_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_step_budget_t runtime;
    uint32_t fabric_work;
    uint32_t reliability_work;
} ninlil_composition_step_budget_v1_t;

typedef struct ninlil_composition_step_result_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_step_result_t runtime;
    uint32_t fabric_work_done;
    uint32_t reliability_work_done;
    uint32_t more_work;
    uint32_t reserved_zero;
} ninlil_composition_step_result_v1_t;
```

The complete public function allowlist is:

```text
ninlil_composition_v1_workspace_required
ninlil_composition_v1_create
ninlil_composition_v1_runtime
ninlil_composition_v1_fabric
ninlil_composition_v1_step
ninlil_composition_v1_close_begin
ninlil_composition_v1_close_poll
ninlil_composition_v1_destroy
```

Their exact declarations are:

```c
ninlil_status_t ninlil_composition_v1_workspace_required(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment);

ninlil_status_t ninlil_composition_v1_create(
    uint32_t profile_id,
    const ninlil_runtime_config_t *runtime_config,
    const ninlil_platform_ops_t *platform_template,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_composition_v1_t **out_composition);

ninlil_status_t ninlil_composition_v1_runtime(
    ninlil_composition_v1_t *composition,
    ninlil_runtime_t **out_runtime);

ninlil_status_t ninlil_composition_v1_fabric(
    ninlil_composition_v1_t *composition,
    ninlil_fabric_v1_t **out_fabric);

ninlil_status_t ninlil_composition_v1_step(
    ninlil_composition_v1_t *composition,
    const ninlil_composition_step_budget_v1_t *budget,
    ninlil_composition_step_result_v1_t *out_result);

ninlil_status_t ninlil_composition_v1_close_begin(
    ninlil_composition_v1_t *composition);

ninlil_status_t ninlil_composition_v1_close_poll(
    ninlil_composition_v1_t *composition,
    uint32_t work_budget,
    uint32_t *out_done);

ninlil_status_t ninlil_composition_v1_destroy(
    ninlil_composition_v1_t *composition);
```

The accessors return borrowed handles. They do not transfer ownership and are
invalid after `close_begin`. Applications use the Runtime handle for Services,
submissions and queries. Reference ports use the Fabric handle for their
existing registration APIs. No raw chunk, frame, route, parent, session,
custody or retry-engine type becomes public.

### 2. Configuration and ownership

Profile 1 is the only V1 profile. `workspace_required` is the sole authority
for its bytes and alignment. The caller owns that fixed workspace from create
through successful destroy and must not move, reuse or free it earlier.

`runtime_config` is the ordinary public Runtime configuration. The platform
template supplies allocator, execution, clock, entropy, storage, Tx gate and
origin authorization. Its Bearer entry must be `NULL`; accepting and silently
discarding a caller Bearer would be ambiguous. Composition copies the required
vtable values, installs its Fabric Bearer in the private platform copy, and
does not retain the two outer input structures. Function code and non-null
`user` pointees remain caller-owned through successful destroy.

Profile 1 support for a reliability engine is automatic only after its
canonical durable management state exists. Absence of an attachment, route or
parent assignment keeps the corresponding engine inactive; it never causes a
fabricated session, route, parent, ACK, Receipt or success. There are no public
feature flags in V1.

Composition derives a separate binary Storage namespace for each internal
domain. The exact 32-byte namespace is SHA-256 of:

```text
"NCS1" || domain_u8 || 0x000000 || runtime_id16 ||
runtime_storage_namespace_length_u32be || runtime_storage_namespace_bytes
```

`domain_u8` is 1 for Fabric, 2 for multi-frame transfer, 3 for route/parent,
and 4 for radio fragmentation. Foundation Runtime continues to use the
caller's original namespace. The storage wrapper substitutes the derived
namespace only for the exact internal domain open and rejects every unexpected
open. This gives stable restart identity and isolates different Runtime IDs
even when two compositions share the same Storage vtable and `user` context.

#### Fabric-to-route/parent projection

Profile 1 uses existing public Fabric configuration as the sole Controller
input for relay and multi-parent state. It does not add a route API. A
projection becomes eligible only when one durable PathPolicy and one durable
AuthorityBinding match exactly on policy ID, policy revision, policy digest,
service identity digest, family, direction and traffic class; the binding is
`BOUND`, unexpired on the same trusted clock epoch, and every candidate names
one registered unicast link with a non-zero authenticated peer Runtime ID.
Missing, duplicate, expired or contradictory input leaves the scope inactive.

After a successful Fabric `policy_put`, `authority_put`, link registration or
removal, composition evaluates the affected binding after the Fabric mutation
has completed. It projects and FULL-persists one internal assignment before
the next relay admission. The exact source mapping is:

| Internal value | Public source |
| --- | --- |
| owner scope | `AuthorityBinding.owner_scope_id` |
| authority / term | `authority_id` / `authority_term` |
| assignment epoch / revision | `assignment_epoch` / `assignment_revision` |
| authority clock / lease | `authority_clock_epoch_id` / `lease_expires_at_ms` |
| path policy identity | `PathPolicy.policy_id` / `revision` / canonical digest |
| grant identity | `AuthorityBinding.binding_id` |
| ordered parent set | each candidate link's `authenticated_peer_runtime_id`, in candidate rank order, duplicate-free, maximum 8 |
| egress link | the candidate `instance_id` selected by Fabric for the new attempt |
| terminal hop | authenticated peer Runtime ID equals `target_runtime_id` |
| hop limit | 3 for profile 1, never increased by projection |
| queue bounds | per candidate, `floor((64 - 8) / candidate_count)` Application entries and `floor((16320 - 2048) / candidate_count)` Application bytes; the existing 8-entry/2048-byte control reserve is not divided |
| ACK policy | authenticated LINK_ACK required (`ack_policy=1`) |

Internal context IDs, route handles and generations are deterministic,
non-zero truncations of `D = SHA-256("NCR1" || owner_scope_id || policy_id ||
policy_revision_u64be || candidate_rank_u16be || peer_runtime_id)`:
`ingress_hop_context_id=u32be(D[0..3])`, `route_handle=u16be(D[4..5])`,
`route_generation=u16be(D[6..7])`,
`egress_hop_context_id=u32be(D[8..11])`,
`egress_route_handle=u16be(D[12..13])`, and
`egress_route_generation=u16be(D[14..15])`. A zero required value or any
truncation collision within the live scope is a conflict and publishes no new
assignment. Scope derivation at admission uses the actual Runtime message's
endpoint, direction, traffic class and canonical Service namespace/ID, and
must match the binding's service identity digest. Availability changes select
among the already assigned parents but do not rewrite assignment authority. A
different parent is used only by a new Runtime attempt; the same attempt
remains pinned. Policy/binding removal or replacement begins the existing
drain/handoff sequence and never fabricates an ACK or Receipt.

### 3. Construction and recovery order

Create performs this fail-closed order:

1. validate inputs, owner context, workspace and platform operations;
2. create/recover Fabric;
3. begin Runtime Foundation storage recovery;
4. create/recover enabled sidecars while the Runtime Bearer is still closed;
5. install and open the Fabric Bearer;
6. finish Runtime startup and publish both borrowed handles.

Failure unwinds only objects that were opened, exactly once, in reverse order.
No public handle is returned after a partial create. The existing late MFDT
configure seam remains test-only and is not used by composition.

### 4. Bounded progress and terminal release

`step` validates both nested extensible structures, calls each enabled
subsystem at most once, and performs no hidden loop. Each Runtime budget field,
`fabric_work`, and `reliability_work` may be zero to skip that work class and
must be within its owning component's configured limit. At least one work
class must be non-zero. `more_work` is the logical OR of Runtime, Fabric and
internal-engine pending work. Component counters are reported without treating
unlike work units as one total.

The exact owner order is Runtime, route/parent, radio fragmentation, then
Fabric. Multi-frame transfer is already owned by `ninlil_runtime_step` and
consumes only `budget.runtime`; composition never calls a second MFDT step.
`reliability_work` is one shared total for route/parent plus fragmentation. If
both are enabled, each receives half and an odd extra unit alternates between
them using an instance-local cursor; if one is inactive, the active engine
receives the whole total. Each engine is called at most once. Fabric receives
only `fabric_work`.

Composition validates and prepares the outer result, initializes the nested
Runtime result header, then starts work. On the first component error it stops
later components, preserves counters from work already completed, sets
`more_work` when any component may still have work, and returns the mapped
error. It never retries inside the same call.

Runtime terminalization is the only Application-success authority. Transport
acceptance, path availability, relay custody, reassembly or a Fabric provider
completion cannot synthesize success. When Runtime reaches a terminal result,
composition connects that exact transaction/attempt lifecycle to Fabric's
internal durable release. A successful terminal release must eventually free
the attempt slot; an uncertain release fences restart and cannot be retried as
a new effect. The installed API does not expose Fabric's private release
symbols.

The exact Profile 1 terminal release token is derived from the immutable,
non-zero transaction ID: interpret bytes 0..7 as one big-endian `uint64_t` and,
only when that value is zero, use bytes 8..15. A valid transaction ID makes the
result non-zero. Fabric always matches the full transaction ID before comparing
this token, so it is a restart-safe equality fence within one transaction, not
a global identity or ordering value. Mutable transaction `record_revision`,
EventFact `spool_revision`, and origin-only query sequence are not release
tokens.

Runtime exposes this lifecycle through one private, read-only bounded
projection. It emits one `{transaction ID, release token}` only for a durable
terminal owner, whether local-origin or inbound. It never calls a Port, changes
Runtime state or reconstructs attempt history. Composition owns the scan
cursor. Restart may replay an owner and therefore Fabric release is idempotent
for the same token.

For one projected terminal owner, Fabric first checks every matching in-memory
FBA1 and FBT1 row by full transaction ID. This intentionally covers current and
summarized EventFact retry cycles, inbound top-level attempts, and legitimate
forward/reverse row coexistence without a new Runtime storage field. A
different existing non-zero token anywhere in that set is a conflict with zero
mutation. Exact-token rows are skipped. Otherwise one call performs at most one
durable transition on a zero-token row and reports more work while any matching
row is not durably released. No matching row, or all matching rows already
carrying the exact token, is final success. A retained provider token is
cancelled/released through the existing bounded Fabric step before its FBA1
becomes GC-eligible, and an uncertain cancel remains fenced.

Terminal release and Fabric maintenance share `fabric_work`. Composition
projects at most one owner and requests at most one durable release transition
per outer step, charges every such transition as one Fabric work unit, then
calls the existing Fabric step only when the remaining budget is non-zero and
passes exactly that remainder. RAM-only scans are bounded and uncharged.
Pending terminal release contributes to `more_work`; there is no hidden retry
loop.

### 5. Instance isolation and shutdown

Each composition has one execution owner and all mutable Runtime, Fabric,
transfer, fragmentation, route and parent state is instance-local. Production
dispatch never selects an owner through process-global current/bind state.
Two compositions in one process may use different ports, policies and parents
without cross-instance mutation.

Applications must finish a reference port's documented unregister/close
sequence before composition close. If any external link registration remains,
`close_begin` returns `NINLIL_E_CONFLICT` with zero mutation, I/O or callback.
Otherwise it destroys the Runtime first, which closes its Fabric Bearer and
Runtime-owned sidecars, then begins internal-engine and Fabric drain.
`close_poll` advances bounded drain work. `destroy` returns
`NINLIL_E_WOULD_BLOCK` until close is complete; success zeroes the composition
workspace. No Application callback occurs after an accepted `close_begin`.

If Runtime destroy returns storage `COMMIT_UNKNOWN` after consuming the
Runtime, composition records that exact terminal close status and continues
reverse-order drain; it does not recreate or retry the Runtime. `close_begin`
still accepts the close and returns `NINLIL_OK`. While drain is incomplete,
`close_poll` returns OK
with `out_done=0`; at completion it returns the recorded status with
`out_done=1` (or OK when none was recorded). A failure that did not consume the
Runtime leaves close unaccepted and performs no later close mutation.

All functions except the pure `workspace_required` enforce owner-context and
non-re-entry rules. They return the existing `ninlil_status_t`; component
errors map without retry as follows. Runtime errors pass through unchanged.
Internal composition seams return `ninlil_status_t` directly. Fabric maps
`OK`, `INVALID_ARGUMENT`, `WRONG_THREAD`, `REENTRANT`, `CLOSED`, `CONFLICT`,
`UNSUPPORTED`, `CORRUPT`, `COMMIT_UNKNOWN`, `DENIED`, `UNAVAILABLE`,
`CAPACITY`, and `WOULD_BLOCK` respectively to `NINLIL_OK`,
`NINLIL_E_INVALID_ARGUMENT`, `NINLIL_E_WRONG_THREAD`,
`NINLIL_E_REENTRANT`, `NINLIL_E_INVALID_STATE`, `NINLIL_E_CONFLICT`,
`NINLIL_E_UNSUPPORTED`, `NINLIL_E_DEGRADED`,
`NINLIL_E_STORAGE_COMMIT_UNKNOWN`, `NINLIL_E_DEGRADED`,
`NINLIL_E_WOULD_BLOCK`, `NINLIL_E_CAPACITY_EXHAUSTED`, and
`NINLIL_E_WOULD_BLOCK`. No mapping reports Application success or masks a
durability-uncertain result.

## Software acceptance

V1 composition is complete only when a fresh tests-OFF install exports the
header through `Ninlil::runtime`, an external C11 consumer uses no private
header/symbol, and all of these paths pass under strict warnings and scoped
ASan/UBSan:

1. two isolated composition instances complete the existing public direct
   Runtime/Fabric transaction and Receipt path;
2. ApplicationData larger than one packet survives a cold restart, is applied
   once, Receipted and terminalized once;
3. a public RF packet-link with a smaller MTU exercises internal fragmentation
   and reassembly without exposing fragments to the Application;
4. relay forwarding plus a parent switch preserves transaction identity,
   creates a new attempt where required, and does not equate custody or path
   availability with success;
5. two concurrent Runtime/Fabric/relay pairs using the same Storage vtable and
   `user` context but different Runtime IDs do not mutate each other;
6. more than 64 sequential terminal attempts continue without retained Fabric
   capacity exhaustion;
7. partial create, wrong-thread, re-entry, backpressure, loss, uncertain
   release, close and cold-restart cases remain bounded and fail closed.

The external consumer proves the public happy/restart paths. Focused internal
tests own fault injection and the two P0 regression cases; they are not copied
into one oversized consumer executable.

Physical USB, Wi-Fi, SX1262, power-cut, regulatory and field evidence remain
separate HIL and stay `NOT_RUN` until actually executed.

## Non-goals

- A plugin framework, service locator, dependency-injection graph or dynamic
  loader.
- Public MFDT, FRAG, relay, parent, codec, storage-record or test APIs.
- A new wire format, storage schema, Join model or application vocabulary.
- Owning platform port event loops or background threads.
- Claiming physical or field completion from Host simulation.

## Consequences

- Applications retain one Runtime model while ports retain one Fabric
  registration boundary.
- Existing reliability engines can be repaired and integrated without freezing
  their internal state machines as public ABI.
- The remaining work is concrete integration and acceptance, not another
  architecture layer.
