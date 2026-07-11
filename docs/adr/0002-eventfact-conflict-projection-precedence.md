# ADR-0002: EventFact Conflict Projection Precedence

状態: Accepted<br>
決定日: 2026-07-11

## Context

EventFactは同じscopeに、caller idempotency key mappingとevent ID mappingの2つをdurably保持します。正常なadmissionでは両mappingが同じtransactionへatomic commitされますが、corruption、旧実装、または外部から復元した不整合状態では別transactionを指し得ます。

M1aのpublic result matrixは`IDEMPOTENCY_CONFLICT`でexisting transaction IDとcanonical digestを1組返すことを要求します。一方、従来仕様は2つのmappingが別transactionを指す場合にどちらを返すか固定しておらず、実装や走査順によって結果が変わる余地がありました。

## Decision

1. Caller-key mappingが存在するconflictでは、そのmappingが指すpersist済みtransaction IDとcanonical digestを返す。
2. Caller-key mappingが存在せず、event ID mappingだけが存在する場合に限りevent mappingのpairを返す。
3. 両mappingが別transactionを指す場合もcaller-key mappingを優先し、片方のtransaction IDと他方のdigestを混合しない。
4. 選択したmappingが指すtransaction recordを検証または読取りできない場合、別mappingへfallbackしてconflictを合成せず、Storage corruption/errorとしてfail closedする。
5. Conflictではalias mappingの追加、既存mappingの上書き、counter、quota、capacity、entropy消費を行わない。

## Rationale

Public `ninlil_submit()`のidempotency boundaryはcallerが明示したraw idempotency keyです。これをprimary projectionにすると、同じcallを再提出したときの結果がevent indexの走査順に依存せず、DesiredStateのkey-based idempotencyとも一貫します。

Event mappingへのfallbackはcaller-key mappingが存在しない場合だけに限定します。これによりEvent IDの重複も既存transactionへ安定して結びつけながら、破損した2 recordを正常な1 recordのように合成しません。

## Consequences

- Submission preflightはkey mappingを先にlookup・検証し、次にevent mappingを検査する。
- Conflict outputは常に1つのauthoritative mappingからtransaction IDとdigestをvalue-copyする。
- 両mappingが異なること自体は新規admissionを禁止するsemantic conflictだが、mapping先recordの欠損・破損はStorage failureとして扱う。
- 将来mapping repairを導入する場合も、repair完了前のpublic projectionは本precedenceを維持する。

## Related requirements

- `M1A-ADM-021`〜`M1A-ADM-028`
- Foundation ABI §8 Submission idempotency rules
- Foundation State Machine TEST origin grant guard
