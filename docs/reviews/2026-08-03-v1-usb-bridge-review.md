# V1 USB bridge bounded independent review

状態: **GO — P0=0 / P1=0 / P2=0**

- Date: 2026-08-03
- Subject: ADR-0036 private fixed-capacity NCG1 USB bridge candidate
- Reviewer role: bounded independent code/specification review; no repository edits

## Verdict

GO for the reviewed USB bridge tranche. This is not ADR-0036 acceptance,
NRA1/NRW1/SX1262 path completion or a physical-HIL claim.

The bridge remains a private, caller-driven V1 component: one binding slot,
four packet slots and one transmit frame, with a measured LP64 object size
below the fixed 6144-byte ceiling. It adds no public API, registry, plugin
framework or background task.

## Findings closed during review

The independent review found and closed the following boundary defects:

- Provisioning outcomes and the provisioner's fenced state are mapped to the
  exact NVB1 status codes, including `STORAGE_UNKNOWN` and
  `REPROVISION_REQUIRED`.
- Every non-owner raw read and write result is followed by the same stream
  ticket check, including `WOULD_BLOCK` and zero-byte results. A generation
  observed during I/O is itself fenced, so it cannot be silently adopted on
  the next step.
- RX scratch, residual unused bytes, parser logical tail and completed or
  rejected frame payloads are zeroized without discarding a valid incomplete
  prefix.

The final review found no remaining P0, P1 or P2 and no unnecessary public
boundary or speculative abstraction.

## Evidence

- Strict C11 normal bridge and PTY tests pass.
- ASan/UBSan bridge and PTY tests pass.
- The installed public POSIX USB port is exercised through a real PTY for
  durable binding, bidirectional packet transfer and close/reopen generation
  recovery.
- Private-subproject, Production Attachment magic, ESP-IDF packaging and
  forbidden-vocabulary gates pass.
- `git diff --check` passes.
- The complete normal suite passes 468/468 with zero failures.
- Physical USB/SX1262 HIL remains `NOT_RUN`.
