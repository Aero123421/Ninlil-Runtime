# MFDT deadline sentinel and record safety erratum

Date: 2026-08-02  
Status: **narrow normative erratum implemented; Host + Sanitizer verification GREEN**

## Scope

ADR-0021の改訂OPENに残っていたdeadline sentinelの誤記を、既存Foundation
canonicalへ一致させる。MFDT admission profile revision 2、wire field、storage schema、
公開API、state machineは追加・変更しない。

## Normative correction

- uplink `EventFact`の`NO_DEADLINE`はdeadline epoch all-zero、
  `absolute_effect_deadline_ms = NINLIL_NO_DEADLINE (UINT64_MAX)`、grace 0。
- finite downlink `DesiredState`はdeadline epoch non-zero、deadline
  `1..UINT64_MAX-1`。
- original ApplicationとOPENのdeadline metadataはbit-exactであり、0やsentinelへの
  正規化は禁止する。
- deadline 0、downlink `UINT64_MAX`、familyに合わないepoch/deadline/grace/generationは
  pre-FULLでrejectする。
- JSON authorityで`UINT64_MAX`をraw numberにせず、16桁lowercase hex stringとして固定する。

## Implementation repair boundary

- `family_shape_ok`と、同じexact metadata検査に残るdeadline 0前提だけを訂正する。
- NM3S/NM3R record pack/unpackは既存上限とgeometryを、pointer形成・加算・copyより前に
  検証する。pack失敗時のoutput不変契約を維持する。
- original Application carrierの全field bit-exact照合、descriptor digest algorithmを含む
  pre-FULL handoff completionは後続3Cであり、このerratumでは実装しない。

## Nonclaims

本erratumは3B/3C、NTS3 1.2、公開MFDT API、release support、ESP実機/HILの完成を
主張しない。

## Implemented repair

- OPEN codecはuplink familyのzero epoch / `UINT64_MAX` / grace 0だけを
  `NO_DEADLINE`として受理し、finite downlinkはnon-zero epoch / `1..UINT64_MAX-1`
  だけを受理する。
- sender metadata preflightとlegacy convenience OPENも同じsentinelへ同期した。
- NM3S/NM3R pack/unpackはopen length、content geometry、entry bytes、required pointer、
  record capacityをcopyとpointer形成より前に検査する。失敗時はoutput bytesと
  caller-owned output lengthを変更しない。
- 生成authorityは64-bit sentinelをraw JSON numberにせず16桁hex stringで固定し、
  Python / Node / Cの独立ゲートとacceptance hardpinを再同期した。

## Verification

- fresh Debug: `ctest -R 'mfdt|multi_frame'` = **41/41 PASS**
- fresh ASan/UBSan: 同じ選択 = **41/41 PASS**
- focused runtime boundary: C gate/self-test、wire E2E、record KAT、Runtime-owner
  EventFact経路 = **6/6 PASS**
- Runtime-owner試験は4096-byte EventFactをzero epoch / `UINT64_MAX`でadmitし、
  durable NM3SからOPENとcontentをcold読戻ししてbit-exact一致を確認する。
- negative試験はuplink deadline 0、downlink `UINT64_MAX`、NULL manifest、
  invalid entry geometry、`UINT32_MAX` content lengthをfail-closedで確認し、pack failureの
  canary/output length不変を確認する。
- fresh tests-OFF / MFDT-OFF installは成功し、installed `libninlil_runtime.a`の
  MFDT symbolは0、installed header/CMake surfaceにもMFDT private名は無い。

## Residual boundary

3Cのoriginal Application全field照合、descriptor digest algorithm照合、pre-FULL
handoff completionは未実装のまま明示的に残す。本erratumのGREENを3C completion、
ESP実機/HIL、release supportへ拡張解釈しない。
