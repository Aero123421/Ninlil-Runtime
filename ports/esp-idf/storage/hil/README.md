# Power-cut HIL harness (V1 completion condition)

**Status: executable firmware and strict host runner implemented; hardware run
not executed in this slice.**

## Purpose

Prove the real ESP32-S3 wear-levelled dual-slot storage recovers one exact
multi-key OLD or NEW snapshot after power loss at each named media boundary.
This harness does not enable `FULL_ESP_HIL_ATTESTED` by itself.

## Atomic snapshot

Every run starts from an erased/reset HIL partition. `HIL_READY` protocol 3
includes a random boot nonce and reset reason; the runner requires the nonce to
change after the cut before accepting verification. This detects a no-op reset
fixture but is not by itself proof that flash power was physically removed.
Firmware establishes:

| Key | OLD | NEW |
| --- | --- | --- |
| `a` | `old-A` | `new-A-long` (replace) |
| `b` | `old-B` | ABSENT (erase) |
| `c` | ABSENT | `new-C` (add) |

Verification requires exact entry count, logical byte count, presence, value
length, and value bytes. Any partial/mixed/missing/extra shape emits `INVALID`
and the runner fails. A canonical SHA-256 fingerprint is independently
recomputed by the runner for the accepted OLD/NEW state.

## Exact named boundaries

A port-private observer is called from the same storage control flow as the
production media operations. It is unset in production. It neither changes the
public Storage ABI nor permits FULL success.

| ID | Exact observer event | Cut contract |
| --- | --- | --- |
| HIL-D0 | `DIR_BEFORE_ERASE` | pre-call event + delay sweep across erase |
| HIL-D1 | `DIR_BEFORE_WRITE` | pre-call event + delay sweep across full body write |
| HIL-D2 | `DIR_BEFORE_SEAL` | body sync complete; sweep across seal program |
| HIL-S0 | `DATA_BEFORE_ERASE` | pre-call event + delay sweep across inactive-slot erase |
| HIL-S1 | `DATA_BEFORE_WRITE` | pre-call event + delay sweep across full slot write |
| HIL-S2 | `DATA_AFTER_SYNC_BEFORE_RETURN` | post-sync, before public return; HIL-only wait window |

The host requires an exact `HIL_BOUNDARY <scenario> <event>` match. The
firmware pauses that production-path call until it receives the exact
`CONTINUE <scenario> <event>`. The runner first arms its power thread, then
starts the delay clock immediately before writing/flushing `CONTINUE`. Thus the
delay origin is a host-side approximation immediately before the target call,
not a claim of cycle-exact flash timing. A generic pre-operation window is not
accepted as named-boundary evidence.

One run or one selected delay does not prove a torn write occurred. Per event,
archive repeated sweeps that demonstrate the OLD side, NEW side, and attempts
around the observed transition. `delay=0` is allowed to cut before the media
call and legitimately recover OLD; positive delays are needed to cross it.
The runner also limits the power-off command to four seconds so the maximum
configured delay plus relay-command latency remains within the S2 firmware's
ten-second post-sync/pre-return observation window. A fixture that cannot meet
that bound fails the run and must not be used as S2 evidence.

## Directory scenarios

D0/D1/D2 create a second, scenario-specific empty namespace after the `HIL`
OLD snapshot exists. Recovery is accepted only as:

- OLD: exact `HIL` directory entry and exact OLD data; scenario namespace absent.
- NEW: those same truths plus exactly one empty scenario namespace with a valid
  durable seed.

Unexpected directory entries, missing HIL, invalid seed, non-empty scenario
namespace, or invalid HIL data fail.

## HIL-NS is separate

HIL-NS is not one atomic power-cut scenario and is not accepted by the runner.
Its evidence is a separate reboot/permutation campaign. It requires a dedicated
operator fixture that can report the port-private directory index; the atomic
runner in this directory cannot produce HIL-NS evidence.

Run two independently erased campaigns with namespaces `NS-A` and `NS-B`:

1. Campaign AB creates `NS-A`, cold reboots, creates `NS-B`, then cold reboots.
2. Campaign BA creates `NS-B`, cold reboots, creates `NS-A`, then cold reboots.
3. Immediately after each create, commit and verify distinct exact contents:
   `NS-A={a:A-old,b:A-stable,c:ABSENT}` and
   `NS-B={a:B-stable,b:ABSENT,c:B-new}`. Each has exactly two entries and 47
   logical bytes under this storage contract.
4. Record each name's directory index after creation. After every later cold
   boot, reopen in both AB and BA lookup orders and require the recorded index,
   exact entry count/logical bytes, and every key's presence/length/value to be
   unchanged. An unexpected namespace, duplicate name/index, mixed contents,
   corrupt open, or index drift fails the campaign.

Do not erase between steps within one campaign. Archive the same board/build
identity and raw serial evidence as the atomic matrix. Host-model conformance
or a successful D0-D2 run is not a substitute for this physical reboot proof.

## Files and prerequisites

- partition: [`../../partitions/ninlil_storage.csv`](../../partitions/ninlil_storage.csv),
  label `ninlil_st`
- firmware: `ports/esp-idf/hil_app/`
- runner: `host_powercut_runner.py` (`pyserial` and operator-supplied argv-array
  prepare/power-off/power-on commands)

Every D0/D1/D2/S0/S1/S2 invocation requires `--prepare-json`; this command must
erase/reset only the HIL test partition and leave the flashed firmware usable.
Until all hardware evidence is green and separately accepted, policy remains
`ESP_UNPROVEN`, `commit(FULL)` must not return `STORAGE_OK`, and field readiness
is not claimed.
