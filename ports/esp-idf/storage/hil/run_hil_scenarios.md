# HIL runner procedure (not executed in M3 storage slice)

1. Build and flash `ports/esp-idf/hil_app` with
   `partitions/ninlil_storage.csv`.
2. Connect a relay or reset fixture which actually interrupts flash power while
   preserving the operator's ability to restore and reboot the board.
3. Provide a `--prepare-json` argv command that erases/resets the HIL partition
   before every atomic scenario run.
4. For each D0/D1/D2/S0/S1/S2 event, run a documented delay sweep. The runner:
   - requires protocol-3 `HIL_READY` with boot nonce/reset reason;
   - creates and strictly verifies the OLD multi-key baseline;
   - arms exactly one scenario/event pair;
   - accepts only the matching `HIL_BOUNDARY` signal;
   - arms the power worker, starts its delay clock, then immediately sends the
     exact `CONTINUE <scenario> <event>` which releases the target call;
   - cuts/restores power;
   - requires the post-cut boot nonce to differ, then verifies exact OLD or NEW
     state plus canonical SHA-256. A changed nonce catches a no-op fixture but
     does not replace operator evidence of physical flash-power interruption.
5. Archive firmware revision, ESP-IDF pin, board/flash identity, relay setup,
   every delay, raw serial log, state, and digest. Only reviewed evidence may
   inform a later attestation decision.

Example (lab commands are installation-specific JSON argv arrays):

```sh
python3 ports/esp-idf/storage/hil/host_powercut_runner.py \
  --port /dev/ttyACM0 --scenario S1 --delay-ms 13.5 \
  --prepare-json '["lab-flash","erase-hil-and-reset"]' \
  --power-off-json '["lab-relay","off"]' \
  --power-on-json '["lab-relay","on"]'
```

The delay origin is the host timer release immediately before the host writes
and flushes `CONTINUE`; it approximates the instant just before the target call
and is not cycle-exact flash instrumentation. `delay=0` may cut before the call
and produce OLD. A single run or particular delay does not guarantee a torn
operation. For every event, repeat sweeps far enough to observe the OLD side,
the NEW side, and multiple attempts around the transition; retain every result,
including valid OLD/NEW runs that do not tear media.
The external power-off command is limited to four seconds. This keeps the
maximum five-second configured delay plus command latency inside S2's
ten-second post-sync/pre-return target window. A timeout fails the run; it is
not evidence.

`delay-ms` must be finite and within 0..5000. `boot-seconds` must be finite and
within 0..120. The runner also bounds serial baud and rejects shell strings,
wrong events, malformed lines, invalid states, and unexpected snapshot digests.

HIL-NS is a separate multi-namespace reboot/permutation campaign as described
in `README.md`. It needs a dedicated fixture that reports port-private directory
indices; that fixture is not supplied by this atomic runner. HIL-NS is not
represented as one power-cut transaction and does not use this runner's
scenario selector.

This repository has not executed the harness without attached hardware.
