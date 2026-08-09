# Three-node NJM1 RF HIL evidence

- Date: 2026-08-09 JST
- Scope: ADR-0037 private LAB only
- Result: `PASS`
- Firmware: `build-njm1-topology-review2/ninlil_radio_hil.bin`
- Firmware SHA-256: `4c315365b5fd5e49bc634a2ca717c14deee01b20df62e263863db53baceaf20e`
- Build: ESP-IDF v5.5.3, NJM1 LAB + diagnostic session ledger + USB Serial/JTAG

## Physical inventory

The same verified application image was written to all three boards at
offset `0x10000`; `esptool` verified the flash hash on every board.

| Label | USB device | factory MAC | NJM1 node ID |
| --- | --- | --- | --- |
| A | `/dev/cu.usbmodem1101` | `e0:72:a1:d8:3e:74` | `e072a1d83e744e31` |
| B | `/dev/cu.usbmodem1201` | `e0:72:a1:f7:ff:0c` | `e072a1f7ff0c4e31` |
| C | `/dev/cu.usbmodem1301` | `e0:72:a1:d7:77:28` | `e072a1d777284e31` |

All boards had antennas connected. The boards shared one desk; this was not
an RF-isolation or range fixture.

## RF and transmission authority

- 923.0 MHz
- bandwidth 125 kHz
- SF7
- CR 4/5
- 8-symbol preamble
- 10 dBm firmware cap
- existing R5 permit -> R1 HAL -> R9 edge -> SX1262 path
- existing CAD/LBT before transmission

This profile is conservative LAB configuration, not a finding of Japanese
legal compliance. Module certification, antenna approval, installation and
the applicable operating rules were not independently attested in this run.

## End-to-end observations

### Automatic Join and stable two-hop topology

1. A was promoted through USB with `MESH CONTROLLER`.
2. B automatically joined A with `parent=A`, `hops=1`, and
   `route_changes=1`.
3. The shared-desk direct A candidate was excluded on C with the explicit
   HIL-only `PENALTY A 200` control.
4. The RF trace showed `JOIN_REQUEST` C -> B -> A and `JOIN_ACCEPT`
   A -> B -> C.
5. C reported `joined=1`, `joining=0`, `parent=B`, `hops=2`, and
   `route_changes=1`.

The penalty changes logical candidate choice only. It does not prove that C
could not physically hear A.

### ApplicationData and correlated ACK

One operator command submitted the four bytes `01 02 03 04` from C to A.
The first RF attempt was not received. The bounded source retry used a fresh
sequence and the second attempt completed:

- C staged DATA after receiving B's parent beacon and sent to B;
- B forwarded the unchanged four-byte DATA to A;
- A emitted `event=3` and `payload_len=4`;
- A sent ACK to B and B forwarded it to C;
- C emitted the correlated `event=4`;
- C logged `data_ack attempts=2` after sequence correlation.

Relays do not perform the source ACK-wait retry. A source makes at most three
RF attempts, with a three-second bounded wait and deterministic jitter.

### Parent loss and reroute

The direct-A exclusion was reset to zero and B was held in the ESP ROM
bootloader. C detected parent loss, selected the already observed upstream A,
and completed a new Join:

- `parent=A`
- `hops=1`
- `joined=1`, `joining=0`
- `route_changes=2`

### Old-site expiry and relocation

A was then held in the ROM bootloader. B rebooted from the same firmware and
was promoted to a new controller/site:

- the new site ID and epoch differed from the old site

C did not adopt the live foreign site while its old lease remained valid.
After expiry and discovery it joined B with:

- `controller=B`, `parent=B`
- `hops=1`
- `joined=1`, `joining=0`
- `route_changes=3`

The final snapshot was `site=6a19a989d1b4340e`,
`epoch=1782859172`, `lease_ms=18581`. Site IDs and epochs are boot-local LAB
values and are not expected to repeat in another run.

The final run contained no session-ledger capacity failure.

## Controller-only USB topology and reroute follow-up

The follow-up run passed with the LAB Console opening only A's USB device.
B and C remained powered and transmitted over RF, but their serial devices
were disconnected from the host backend.

1. C excluded direct A with the HIL-only score `200`, then automatically
   joined through B. The initial RF tree was A <- B <- C.
2. After B/C USB detach, the backend retained exactly one connection
   (`/dev/cu.usbmodem1101`). A exported RF-only rows showing B at hop 1 and C
   at hop 2 through B, including each selected-parent RSSI/SNR.
3. A -> C Ping/Pong completed with a correlated ACK in 6,764 ms on attempt 2.
4. The topology stayed visible beyond the former 30-second route lifetime.
   Periodic reports refreshed the reverse routes; a second A -> C probe
   completed in 2,698 ms on attempt 1.
5. C's direct-A score was changed to `199` (eligible but unattractive), and B
   was held in the ESP ROM bootloader. C detected parent loss, automatically
   rejoined A at hop 1, and exported the changed edge to the one-USB UI. The
   post-reroute probe completed in 1,327 ms on attempt 1.
6. B was reset into the application, automatically rejoined A at hop 1, and
   resumed fresh RF topology reports. The final Console snapshot still had
   one USB connection and two RF-only remote rows.

Private NJM1 `TOPOLOGY=6` carries the chosen parent, original hop depth, and
selected-parent RSSI/SNR toward the Controller one second after Join/reparent
and then every 20,000..20,700 ms. Existing relay forwarding refreshes the
controller's reverse route. The Controller exports bounded rows as
`MESH TOPOLOGY` after `MESH STATUS`; the backend discards them immediately
when its Controller observer/site/epoch is lost.

Host coverage additionally proves invalid topology rejection before route or
dedupe mutation, old-route expiry followed by refresh, both DATA/ACK
directions, stale failure, reparent replacement, RSSI saturation, and one
Controller plus seven RF rows completing seven sequential ACK probes. The
eight-board physical HIL remains **NOT_RUN**.

For the 75-byte frame at this fixed SF7/125 kHz profile, the approximate
airtime is 133 ms. Seven remote nodes each traversing three legs would be at
most 21 legs per 20-second window, about 14% raw airtime before CAD/LBT and
other LAB traffic. It is not a capacity, duty-cycle, range, or production-MAC
claim.

## Reproduction gates completed on the final source

- fresh ESP-IDF v5.5.3 NJM1 build: pass
- final image flash and `verify_flash` on A, B and C: pass
- Host mesh state-machine test: pass
- Host mesh state-machine test with ASan/UBSan: pass
- focused radio/PCP/SX1262 normal tests: 6/6 pass
- focused radio/PCP/SX1262 sanitizer tests: 5/5 pass
- protocol magic registry: 77 entries, 166 exclusions, 243 candidates,
  zero mutations
- SX1262 control-plane source gate and mutation self-test: pass
- three-board RF scenario: direct Join, two-hop Join, four-byte DATA/ACK,
  parent-loss reroute, old-site expiry and new-site Join all pass

At handoff all three boards were running the verified LAB image. The Console
opened only A; B and C were RF-only from the application's point of view.

## Mac LAB Console

`tools/ninlil_lab_console.py` was started on loopback HTTP and its live state
showed three online nodes from one attached Controller USB. The topology,
selected-parent edges, RF report age, parent-link RSSI/SNR, correlated Ping
history and reroute were rendered in the macOS UI without console warnings.
Backend/console tests passed, and `tools/package_ninlil_lab_console_macos.sh`
produced a valid application bundle whose `Info.plist` passed `plutil -lint`.

## Non-claims and remaining work

- NJM1 is unauthenticated and is not Production Attachment.
- This does not accept or promote RRMP, NRA1/NRW1 V1 vertical-slice HIL,
  multi-parent, or durable custody.
- No RF isolation, obstruction, range, antenna, certification or legal
  attestation was performed.
- No 10 messages / 10 seconds, 20 messages / 10 seconds, soak, power-cut or
  reboot-durable membership test was run.
- The NJM1 diagnostic session ledger is explicitly not a release profile.
