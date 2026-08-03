# V1 functional LAB scope independent review

状態: **V1 scope review GO — P0=0 / P1=0 / P2=0**

- Date: 2026-08-03
- Subject: `docs/adr/0034-v1-functional-lab-scope.md`
- Reviewer role: independent specification review; no repository edits

## Verdict

GO. The V1 completion line is a bounded functional LAB path rather than a new
framework: Linux/macOS application, trusted-local USB parent, one SX1262 hop,
the intended Runtime Service, and an authenticated APPLIED Receipt.

The accepted scope keeps the public Runtime/Composition ABI unchanged and the
ESP radio adapter private. It defines fail-closed LAB binding and reboot
behavior, exact mapping and airtime gates, same-node multi-Service acceptance,
and a reproducible three-board single-channel workload of 10 submissions per
10 seconds. The 20-per-10-second capacity target, relay, multi-parent,
fragmentation and Production Attachment remain explicit V2 gates.

## Checks

- Initial P1 findings 1 through 7: closed
- USB trust boundary and uplink APPLIED authority: closed
- NRW1 190-byte budget, KAT and R3 airtime proof before promotion: closed
- README and compatibility state synchronization: closed
- Physical USB/RF HIL: honestly `NOT_RUN`

No implementation or hardware-completion claim is granted by this review.
