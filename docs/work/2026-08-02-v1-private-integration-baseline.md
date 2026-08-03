# V1 private-feature integration baseline

Date: 2026-08-02  
State: **Host software baseline PASS; public packaging and physical HIL remain**

## Purpose

Before changing the public SDK boundary, verify that the existing private
Fabric, Wi-Fi, radio fragmentation, relay/multi-parent and MFDT candidates can
be built and exercised together. This is a baseline, not a release claim.

## Results

- Domain-schema-1 ON, all private features ON: clean compile/link passed.
- Domain-schema-1 OFF, all private features ON: clean compile/link passed.
- Focused cross-feature Host suite: **21/21 passed**.
- The same focused suite under ASan/UBSan: **21/21 passed** with leak checking
  disabled; no ASan/UBSan finding was reported.
- The suite covered the public Runtime, installed-contract primitives, real
  POSIX TCP/TLS Wi-Fi, Fabric, relay/multi-parent, MFDT, Application callback,
  Receipt and terminal closure paths.

The full 480-test catalog was not rerun because this checkpoint changed no
production code. The focused suite was selected to detect coexistence and
connection failures without adding low-value execution time.

## Conclusion

The next software blocker is the OSS public/distribution boundary, not another
transport state machine. ADR-0029 therefore narrows V1 to one portable Fabric
composition module followed by Host and ESP32 reference ports.

Physical Wi-Fi, RF, USB and power-cut HIL remain `NOT_RUN`.
