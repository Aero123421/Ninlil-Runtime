# 2026-07-29 Fabric Bearer / NFL1 SPEC_ACCEPTED review

状態: **SPEC_ACCEPTED review GO — P0=0 / P1=0 / P2=0**

## Verdict

**P0=0 / P1=0 / P2=0 — SPEC_ACCEPTED GO**

This verdict accepts the design and the reserved private, default-OFF source
contract only. It does not accept an implementation, installed/public ABI,
Wi-Fi or radio support, target execution, HIL, legal compliance, production
readiness, or `RELEASE_SUPPORTED`.

## Reviewed authority

- `docs/34-v2-runtime-fabric-completion.md`
- `docs/adr/0017-bearer-registry-path-selection.md`
- `spec/vectors/fabric-bearer-spec-v1.json`
- `tools/fabric_bearer_spec_vector_gen.py`
- `tools/fabric_bearer_spec_gate.py`

The independent review covered NFL1 byte/length/CRC rules, the six-kind
semantic matrix, private API ownership and status precedence, registry joins,
deterministic path selection, FBR1/FBP1/FBC1/FBA1/FBT1/FBM1 canonical records,
COMMIT_UNKNOWN classification, generator drift, source/vector binding, and
default-OFF/public non-claims.

## Reproduced evidence

```text
python3 tools/fabric_bearer_spec_vector_gen.py --check
python3 tools/fabric_bearer_spec_vector_gen.py --self-test
python3 tools/fabric_bearer_spec_gate.py --check
python3 tools/fabric_bearer_spec_gate.py --self-test
git diff --check
```

All commands passed on 2026-07-29.

Pinned SHA-256 values at acceptance:

```text
ADR-0017  99cef4e4cb074e11790ecdcbe59191d7a39c9b533a4c6d8de78b4f67d61d53b1
docs/34   778e5621cfcb4424b2d4c9b8029a311759e64921b69ae5958c1813a19efebe7d
vector    a4248423d186769e6a58d610582940e6f8d2f493bd3847bedb8aa3d212d724a6
generator 8ee17a4c66620c5f9aeb27fbbbc5ac73908842ba0d8b6b0637b0be3a4999d54e
gate      4a8eadd94f2f6f3e268f680ddca4bdba3ddc386dd2ead4472ccbbf37bc542494
```

The ADR status edit and this non-normative review record necessarily change
the post-acceptance document hashes. The vector, generator, and gate remain
the machine authority.

## Open implementation gates

- No private Fabric implementation or C codec is accepted by this record.
- LP64/ILP32, GCC/Clang, Linux/macOS implementation conformance remains a C5/C6
  implementation gate.
- POSIX TCP/TLS Wi-Fi, ESP32-S3 Wi-Fi, NRW1 mapping, relay, multi-parent,
  target execution, physical HIL, soak, and release evidence remain open.
- `NINLIL_ENABLE_PRIVATE_FABRIC_V1` must remain default OFF, headers must remain
  non-installed, and the public Runtime ABI must remain unchanged until a
  separate public-ABI decision is accepted.
