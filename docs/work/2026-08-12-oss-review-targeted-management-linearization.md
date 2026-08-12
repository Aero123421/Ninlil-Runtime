# OSS review: targeted-management linearization and clock safety

Date: 2026-08-12

## Scope

The final OSS-review integration exposed a gap between the Accepted targeted
management ordering contract and the live Runtime.  This tranche closes the
unsafe current-epoch paths and the unsafe cross-epoch overtaking path without
adding a public ABI, wire field, storage schema, timer task, or new generic
state framework.

The affected public operations are `ninlil_cancel_request()`,
`ninlil_event_resume()`, `ninlil_event_discard()`,
`ninlil_delivery_complete()`, and `ninlil_runtime_step()`.  The changes remain
inside the existing caller-owned Runtime and NTS3 transaction owner.

## Closed behavior

- Successive accepted trusted clock samples share one Runtime-local current
  baseline.  A later call cannot accept a lower same-epoch value merely
  because it targets a different transaction or Port boundary.  The Clock
  Port contract additionally forbids reusing a prior epoch ID after publishing
  a different one (`A -> B -> A`); Runtime does not claim an unbounded history
  of every epoch ID ever observed.
- New cancel/resume/discard mutations sample the clock exactly once after
  replay/lookup precedence.  Temporary/uncertain/invalid/permanent/regressed
  samples add the `CLOCK_UNCERTAIN` health cause and leave the transaction,
  ordered-input counter, management ledger, and Storage commit count
  unchanged.
- Current-epoch correctness timers are reduced by logical time.  Semantic
  priority is used only at an exact same time.  Receipt timeout, Command effect
  deadline, evidence close, and management input therefore cannot overtake an
  older timer.
- A Command with possible prior effect remains non-terminal at its effect
  deadline and closes as `OUTCOME_UNKNOWN` only at evidence close.  A later
  TxGate/Bearer no-send result cannot erase the durable
  `EFFECT_POSSIBLE_EVIDENCE_PENDING` marker from an earlier accepted or
  `LOST_UNKNOWN` attempt.
- Command and Event receipt-timeout retry use checked
  `now + retry_backoff_ms`, not immediate redispatch.  Overflow degrades the
  Runtime without mutating the transaction.
- The Accepted Desired timeout keeps `EFFECT_POSSIBLE` as the durable truth;
  when the safe-apply guard holds, internal `RETRY_WAIT` / public
  `WAITING_WINDOW` means only that a fixed-backoff retry is scheduled. The
  timeout call itself creates no attempt and sends nothing. Normative
  `docs/13` now states this distinction explicitly.
- A trusted new-epoch `ninlil_delivery_complete()` cannot complete an old
  active token.  It returns `NINLIL_E_CLOCK_UNCERTAIN`, adds the clock health
  cause, and queues work.  The following step uses the existing FULL snapshot
  path to persist `EXPIRED / RECOVERY_REQUIRED / OUTCOME_UNKNOWN`; restart
  retains that tuple.  Business result reason and health reason remain
  separate: the transaction records `OUTCOME_UNKNOWN`, while health records
  `CLOCK_UNCERTAIN`.
- A terminal receiver may still resend its already-cached Receipt for a fresh
  duplicate Application attempt.  The terminal outcome is not reopened.  This
  fixes the temporary ACK-loss/restart Quickstart regression introduced while
  the chronological catch-up path was being connected.
- Ordered-input sequence allocation for a new cancel is checked and committed
  with the cancel snapshot.  `UINT64_MAX` fails before clock or transaction
  mutation.
- After a cold restart, same-epoch management samples are checked against
  every retained owner timestamp available in NTS3: admission, closed sends,
  active-token start, checked retry-decision time, Event recent/older retry
  summaries, and retained resume/discard audit samples.  A lower sample adds
  `CLOCK_UNCERTAIN` health and leaves state, ledger, order, and Storage
  mutation counts unchanged; an exact-boundary sample remains admissible.
- New resume ledgers persist the accepted management clock sample.  Legacy v1
  zero/zero resume audit tuples remain decodable and replayable, but an unseen
  management operation that encounters one samples the clock once and then
  fails closed because chronology is unknowable.  Mixed zero-epoch/nonzero-time
  tuples are corrupt.
- An exhausted Event receipt-timeout park retains the last accepted send tuple
  durably.  Its cycle end is the fixed logical deadline
  `V = send_observed_at_ms + attempt_receipt_timeout_ms`, not the later
  processing sample.  Explicit or availability resume transfers `V` into the
  completed-cycle summary before clearing the live send tuple, so a crash
  between park and resume cannot erase the owner chronology.
- Cold-restart automatic availability resume uses the step sample `T` only
  after checking both the persisted Bearer observation `A` and, for an
  exhausted accepted-send timeout cycle, `V`.  `T < A`, `T < V`, overflow,
  and cross-epoch tuples fail with `CLOCK_UNCERTAIN` health before any Event
  spool/retry/consume mutation; equality is accepted.  This also prevents a
  fresh availability epoch from consuming a parked owner whose durable
  chronology is still in the sample's future.
- A persisted outbound current-attempt closed-send tuple with a zero Receipt
  timeout or an overflowing `send_observed_at + timeout` is no longer silently
  omitted from due-work and next-wake projection.  Step and targeted
  management fail closed with `CLOCK_UNCERTAIN` health before Bearer,
  transaction, ordered-input, or Storage mutation; the exact `UINT64_MAX`
  non-overflow boundary remains valid.  Receiver-side reverse Receipt state is
  explicitly outside this forward-attempt validator.
- A terminal receiver's cached Receipt retry now remains a scheduler owner.
  A duplicate fresh attempt followed by `WOULD_BLOCK` projects the exact
  fixed-backoff wake, keeps it across a crash/recreate, and sends at the due
  point without reopening the terminal business outcome or invoking the
  application callback again.

## Cross-epoch safety boundary

For cancel/resume/discard, an old-epoch active correctness timer paired with a
trusted new management sample now returns `NINLIL_E_CLOCK_UNCERTAIN`, projects
degraded `CLOCK_UNCERTAIN` health, and performs no transaction, ordered-input,
ledger, or Storage mutation.  Epoch identifiers and their numeric times are
never ordered against one another.  This closes unsafe management overtaking.

This is deliberately not described as durable Recovery Fence convergence.
Except for the active callback-token case above, the current implementation
does not yet have a single canonical kind-21 reducer that converts every
old-epoch Command/Event timer into a durable post-state during create or step.
Restart alone does not heal those owners.  Disposition/CancelResult/Delivery/
reconcile targeted ingress and a Receipt's durable local ingress time also do
not have sufficient current NTS3 authority to synthesize ordering.  Those
states remain an explicit follow-up rather than being assigned invented times
or silently reset.

## Verification

Fresh normal and Clang ASan/UBSan trees both passed the same 13 tests:

```text
domain_store_codec
v1_transaction_codec
v1_event_ledger_codec
v1_event_mgmt_ledger
v1_runtime_spine
v1_runtime_delivery
runtime_terminal_owner_projection
v1_runtime_capability
v1_runtime_family
v1_posix_sqlite_restart_e2e
v1_posix_platform_restart_e2e
v1_integration_gate_e2e
v1_direct_1hop_e2e
```

Results were **13/13 PASS** in
`/private/tmp/ninlil-cancel-final-normal-20260812-v2` and **13/13 PASS** in
`/private/tmp/ninlil-cancel-final-asan-20260812-v2` with
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.  A fresh private
Domain-schema-1 Runtime build also passed.  Focused tests cover current-time
ordering, same-time priority, global clock regression, counter exhaustion,
all five clock-fault classifications for resume and discard, cross-epoch
no-mutation for all three management APIs, effect-possible preservation across
TxGate and Bearer denial, checked fixed backoff, callback-token recovery, FULL
commit, restart retention, canonical/legacy resume-ledger compatibility,
same-epoch cold-restart owner regression, production receipt-timeout park
chronology retention, and automatic availability resume at `V-1/V`,
`A-1/A`, cross epoch, and checked-overflow boundaries.  They also cover
missing/overflowing live Receipt deadlines for Event step/discard and Desired
cancel (root and target), exact-maximum addition, and terminal cached Receipt
retry wake/restart/due resend.  The parked-send
regression test was run against the pre-fix clear-before-park behavior and
failed at the retained-send guard; the automatic-resume test was run with its
chronology guard disabled and failed at the `V-1` negative assertion.
Scoped `git diff --check` passed.

## Nonclaims

This tranche does not complete the general kind-21 Recovery Fence reducer,
does not claim restart healing for every old-epoch timer, and does not add
missing durable ingress timestamps.  It does not change public ABI, wire,
storage layout/revision, maturity state, HIL status, or release status.  The
existing transaction and management-ledger codecs gained stricter shape and
legacy-compatibility validation.  No
commit, push, device flash, physical HIL, or RF soak was performed here.
