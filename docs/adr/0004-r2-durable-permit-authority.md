# ADR-0004: R2 Durable Physical Compliance Permit Authority

状態: Accepted<br>
決定日: 2026-07-17<br>
改訂: 2026-07-17（final residual: fresh-epoch CLOCK_FENCE clear、ops→user、publish exact、ram_validate bind、GC、airtime ceiling、R clockless、pcp_r2_docs_gate）

## Context

P1 durable authority と R1 HAL の整合で、expired head が validate で止まり consume に到達しない、CLOCK_FENCE を壊れた same-epoch で解除してはならない、platform に create/close-status が無い、などの点が残る。正本は [24章](../24-r2-physical-compliance-permit-authority.md) **§14**。

## Decision

1. Durable one-shot 正本 = R2 storage; R1 watermark は boot-local。
2. FIFO + **`advance_expired_heads`**; owner S1→S3。
3. **CLOCK_FENCE**（regression/perm/ill-formed/unknown）解除は **fresh epoch**（fresh nonzero 128-bit `clock_epoch_id`）必須。same-epoch 前進のみでは解除禁止。
4. **`bind_storage`/`bind_clock`/`bind_entropy` は ops のみ**。呼び出しは常に **`ops->user`**（platform.h と一致; 別 user 引数禁止）。
5. **`publish_initial_meta`**: 唯一順 bind_live→publish; meta 全 field exact（L/ceiling/counters/generation/clock baseline/fence/instance/CRC）; zero-L 禁止。
6. **`ram_validate`**: seq+digest+epoch(+now) bind; matching consume のみ rollback 判定; fail/他 permit overwrite/recover/revoke/advance/shutdown で clear。
7. **GC**: terminal ∧ seq≤last_consumed のみ; last/next 不変; I1–I14 維持。
8. **Airtime**: meta **ceiling** と per-permit **max_airtime_us** 分離; 異 airtime outstanding≤8 可; 同一 airtime 強制 cohort 禁止。
9. **Algorithm R clockless**（clock 故障中も revoke 可; last_trusted 非更新）。
10. close/iter_close は **void**（failure mapping なし）。
11. create-on-open; open NOT_FOUND ≠ EMPTY。
12. **Complete private C API** 正本は `src/radio/pcp_authority.h`（complete type + consumer compile CTest）。
13. Algorithm E: RO snapshot of meta/fence **before** E body; single FULL revoke-all+baseline; COMMIT_UNKNOWN 収束は full-namespace scan。
14. docs gate **`pcp_r2_docs_gate`** semantic + QA mutations Required; clock ABI は **C offsetof**（LP64 CTest + arm-none ILP32 static_assert）。
15. MUST NOT: legal/R3–R10/HIL 完成、logical TxPermit 流用、**re-review GO**。

## Consequences

実装は 24章 §14 vectors と semantic `pcp_r2_docs_gate` に従う。public ABI 非露出。

## Related

[ADR-0003](0003-radio-usb-dependency-direction.md) · [24章 §14](../24-r2-physical-compliance-permit-authority.md) · [05](../05-security-and-compliance.md) · [23](../23-usb-radio-boundary.md) · `platform.h` · `radio_hal.h`
