# Public Fabric v1 first-tranche implementation re-review

Date: 2026-08-02  
Reviewer: independent Codex Sol high, review-only  
Decision: **GO — P0=0 / P1=0 / P2=0**

## Scope

This review covers only the portable Host `fabric_v1` first tranche accepted by
ADR-0029. It does not review or promote Wi-Fi, USB, ESP32-S3, physical radio,
HIL or release support.

## Closed findings

- The installed packet-link provider contract now states the exact Permit
  validation, one-shot consumption, poll completion and cancellation result
  rules needed by an external provider.
- All temporary Fabric promotion exceptions are limited to
  `fabric_v1` while its state is `PACKAGE_EXPERIMENTAL`. The manifest self-test
  proves that empty metadata, the ABI-negative exception and work-note-only
  evidence cannot be reused for `RELEASE_SUPPORTED`.
- All ten public value types remain covered by the existing ABI manifest with
  size, alignment and field offsets.
- README and the machine-readable manifest describe the package as
  experimental and retain the later transport, target and HIL nonclaims.

## Verification

- Root strict normal focused suite: **22/22 PASS** before the final contract
  repair; final repair-focused suite: **7/7 PASS**.
- Root ASan/UBSan installed consumer and public API/behavior: **3/3 PASS**.
- Manifest check and self-test: **PASS**.
- Python compile and scoped `git diff --check`: **PASS**.

## Engineering-scope check

The repair added no API, framework or future module. It changed only public
contract text and the three experimental-state guards requested by review.

