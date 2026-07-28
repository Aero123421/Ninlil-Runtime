# 2026-07-29 Runtime Core callback / clock independent re-GO

状態: **candidate snapshot GO — P0=0 / P1=0 / P2=0**

この記録は、Runtime Core の application callback 境界、fresh clock、
durable callback fence、role-specific hook、および durable allowlist の独立再確認結果です。
非規範であり、commit、CI、target、HIL、またはRuntime全体の
`RELEASE_SUPPORTED`を単独では主張しません。

## Reviewed snapshot

Author が固定した次の9 fileのordered SHA-256 manifest:

```text
3d04aede5618df41a9e4690e21a97b9a25fbc5e12216ab1380dceaa1b37b1623
```

- `src/runtime/runtime_public.c`
- `src/runtime/runtime_v1_delivery_durable.c`
- `src/runtime/runtime_v1_delivery_durable.h`
- `src/runtime/runtime_v1_bearer_wire.c`
- `tests/runtime/v1_runtime_delivery_test.c`
- `docs/14-foundation-ports-and-simulator.md`
- `tools/vector_inventory_schema.h`
- `tools/vector_reference_test.c`
- `CMakeLists.txt`

Review時点ではworktree上の未commit candidateであり、commit SHAではない。

## Closed findings

1. Downlink、uplink、EventFactの3経路すべてで、callback直前・直後のfresh clockと
   role-specific `before_application_callback` / `after_application_callback` hookを接続した。
2. callback開始前のclock sampleはABI version、size、reserved、non-zero epoch、
   trust、regression、expiryをclosed validationする。
3. COMPLETE result/evidenceはapplication callbackからdeep-copyした後に
   `after_application_callback`を呼ぶ。post-callback clock failure、definite failure、
   `COMMIT_UNKNOWN`のいずれでも同じeffectを再発火しない。
4. `after_application_effect`はCore内部で推測せず、conformance application fixtureが
   actual effect直後に発火する。3経路で
   `before -> effect -> result copy -> after`の順序と各1回を固定した。
5. durable allowlistは19 operation × 34 kind = 646 pairを全列挙し、
   allowed 129 pairと全pair変更、operation/kind/doc omissionをgateで検査する。

## Independent verification

- 空build directoryからstrict configure/build: **PASS**
- full CTest: **279 / 279 PASS**
- focused callback / delivery / allowlist: **4 / 4 PASS**
- callback前後のtemporary、uncertain、permanent、ABI version/size/reserved、
  epoch change、rollback、expiry fault matrix: **PASS**
- definite failure / `COMMIT_UNKNOWN`のOLD・NEW truth、same-instance replay 0、
  restart recovery: **PASS**
- allowlist 646 pairの回帰試験: rejection miss **0**
- `git diff --check`: **PASS**

## Verdict

このcandidate snapshotに対する判定は **P0=0 / P1=0 / P2=0 GO**。
後続のDomain Store、Fabric、Identity / Attachment、Wi-Fi、radio、HIL、
release CIは別gateであり、本記録から完成を導出しない。
