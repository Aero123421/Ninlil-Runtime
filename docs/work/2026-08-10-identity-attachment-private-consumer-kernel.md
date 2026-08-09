# Identity / Attachment private consumer kernel

- Date: 2026-08-10
- Scope: ADR-0039 exact contractのprivate C11 consumer kernel
- State: Host candidate only; `identity-attachment-session-install` remains `PROPOSED`

## Change

`src/runtime/identity_attachment_v1/`に、manifest provider ABIの18 structと6 callbackを
private headerとして固定し、固定容量・no-heap・owner-context serializedのconsumerを置いた。
provider descriptorは初期化時にcopyする。prepareは`resolve -> validate -> subscribe`までで、
NIAF durable single writer未接続のため成功後も`PREPARED_FENCED`だけを保持し、availabilityを
公開しない。invalidationは入力が不正でもreturn前にfenceする。closeはfence、unsubscribeの
callback drain確認、releaseの`released=1`確認、zeroizationの順で進め、失敗時はfenced cleanup
stateを残してretryできる。

validateのauthoritative invalidation/expiry epochとsubscribe epochは、resolve snapshotと
**exact一致**だけを受理する。rollbackだけでなくforward gapもrelease/fresh-init、または
構造的に有効なsubscription handleを保持した`CLOSING`からunsubscribe→drain→releaseで閉じる。
cleanupのreleaseが失敗した場合は元のprovider結果ではなくcleanup errorを返し、callerはobjectを
保持してcloseをretryする。

`subscribe`が`OK`を返してもsubscription handle等の出力が不正なら、providerがcallback
contextを保持した可能性がある。その場合はunsubscribe/release/zeroizeを試みず、callback
contextとprovider copyを保持したuncertain-subscription quarantineへ入り、closeもfail-closedで
戻る。安全にsubscription handleを回収する後続contractがない限り、解放を推測しない。

manifest provider ABIの数値19は`AUTHENTICATION_FAILED`だが、現在のpublic `ninlil_status_t`の
数値19は予約済み`INTERNAL`である。このprivate kernelは数値19をpublic ABIへ偽装せず、
fail-closedの`NINLIL_E_DEGRADED`へ畳む。public status allocationはこのtrancheでは行わない。

## Evidence

- fake providerによる2 consumer / 2 provider isolation、正順、cross Runtime/module/provider、
  stale/expired/revoked/superseded、subscribe failure release順、invalidation fence、unsubscribe
  retry/drain、epoch rollback/forward gap、prepare cleanup retry、release boolean異常、availability
  0をHost testで確認する。
- ABIはprivate headerのLP64 static assertとESP32-S3 Xtensa layout static assertで固定する。
- private consumer側のfreshness testはKAT vectorとmanifest field orderから18 struct・両profileの
  全`sizeof`/`_Alignof`/`offsetof` assertionを再構成し、checked-in assertion includeとの差分と
  1 offset mutationを拒否する。ADR-0039 spec gate自体は実装非依存のまま保つ。
- `build-contract-check`のfocused Host test、ASan/UBSan focused test、ESP-IDF v5.5.3
  `radio_hil_app` fresh compile/linkが通った。ESP artifactは
  `ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.bin`、SHA-256
  `de2b4a24173084df8841f56ef9a05952b70ce07c85a4bb918dfc6a1275dcda31`。
  書込みはしていない。

## Deliberately open

NIAF durable writer、Composition activation/injection、admission/send revalidation、key operation、
Production Attachment provider、PA-S1〜S6、direct/cold Join、ESP target execution、physical HILは
この変更に含めない。public API、wire、storage schema、DTO、plugin/task/pumpは追加しない。
