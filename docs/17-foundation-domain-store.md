# 17. Foundation Domain Store v1

状態: **Normative / pre-alpha storage format**
対象: Foundation M1a private Runtime Store family 5 / 6

本章は[12章](12-foundation-abi.md)のPrivate Runtime Store v1を拡張し、Runtime create Stage 5がdomain recovery、counter/capacity相互検査、durable health再構成を完了するための正本を定めます。Public C ABI、radio wire、Bearer message encodingではありません。

## 1. Scopeとpublish gate

本章が固定するのは、domain record catalog、key/value形式、atomic witness、retention、resource contribution、read-only recovery scanです。Reducer writer、SQLite、embedded KV、public `runtime_create()` bodyは後続実装です。

Runtimeは次の全条件を証明するまでpublic handleをpublishしてはなりません。

1. family 1〜4 bootstrap/profile検査完了
2. family 5 / 6全row scan完了
3. 15 WITNESS_HEAD_INDEX baseline/witnessed exact + CLOCK_BASELINE present、primary/index/backlink、witness、4 counter、11 capacity検査完了
4. unresolved old/new group 0
5. identity exactまたはforward rotation commit OK
6. CLOCK_BASELINE TRUSTEDかつcurrent Stage 7 sample commit OK
7. Storage priority 1/2 reference 0
8. transaction/iterator 0、exclusive Storage handle 1

Bootstrap直後のphysical empty domainはfamily 5/6 row 0で、metadata初期化前のrecovery transientとしてだけvalidです。Public publish可能なsemantic empty domainはexact 15 BASELINE WITNESS_HEAD_INDEX + 1 TRUSTED CLOCK_BASELINEとbusiness/health/witness row 0です。Stage 5直後のUNINITIALIZED clockはStage 7前だけvalidです。0-rowをpublish可能emptyと推測せず、full scan→16-record metadata初期化→fresh scanを必須とします。

## 2. Bounded format constants

| Name | Exact value |
| --- | ---: |
| `DOMAIN_FORMAT_VERSION` | 1 |
| `DOMAIN_RECORD_VERSION` | 1 |
| `PRIVATE_RECORD_MAX_BYTES` | 4096 |
| `PRIVATE_BODY_MAX_BYTES` | 3984 |
| `BLOB_CHUNK_DATA_MAX_BYTES` | 3072 |
| `WITNESS_MEMBER_MAX` | 256 |
| `WITNESS_ENTRIES_PER_CHUNK` | 8 |
| `WITNESS_CHUNK_MAX` | 32 |
| raw idempotency key max | 64 |
| audit metadata max | 128 |
| evidence bytes max | 128 |

`PRIVATE_RECORD_MAX_BYTES`はNinlil private namespaceのcurrent/future全root versionが生成・受理できるsingle value上限です。Storage ABIの65,536-byte上限とは別で、future formatもchunkingを使います。4097 bytes以上、または255-byte key/4096-byte value scratchへの`iter_next`がrequired key>255またはvalue>4096で`BUFFER_TOO_SMALL`を返すrowは、key/value bytesを推測せず`NINLIL_E_STORAGE_CORRUPT`です。ESP32 task stackへscratchを置かず、Runtime-owned workspaceを使います。

Logical payloadは1 recordへ詰めず、3072-byte以下のchunkに分割します。Chunk countは`ceil(total_length / 3072)`、zero-length blobだけcount 0です。非末尾chunkはexact 3072 bytes、末尾は1..3072 bytesです。

## 3. Integer、digest、reusable encoding

全integerはunsigned big-endianです。Booleanはu32 exact 0/1です。ABI header、reserved、pointer、padding、host endianを保存しません。

- `ID128`: exact 16 bytes
- `DIGEST256`: exact 32 bytes。SHA-256を指定したfieldだけで使用
- `TEXT_ID`: `length:u8 + bytes[length]`、length 1..63、unused bytesなし
- `RAW16`: `length:u16 + bytes[length]`
- `LOCAL_IDENTITY`: `flags:u32 + device[16] + installation[16] + site[16] + binding_epoch:u64 + membership_epoch:u64`
- `PARTY`: `runtime_id[16] + application_instance_id[16] + LOCAL_IDENTITY`
- `TARGET`: `flags:u32 + target_runtime[16] + target_application[16] + device[16] + installation[16] + site[16] + binding_epoch:u64 + membership_epoch:u64`
- `SERVICE_IDENTITY`: `TEXT_ID(namespace) + TEXT_ID(service) + TEXT_ID(schema) + descriptor_revision:u64 + descriptor_digest[32] + schema_major:u16 + schema_minor:u16 + family:u32`
- `RESOURCE_VECTOR`: kind 1..11の宣言順に`used:u64 + reserved:u64`を11回

Presence、zero ID、epoch、known enumの規則は12章public ABIと同じです。Hash keyを使うrecordはbodyへexact raw identityを重複保存し、hash一致だけで同一性を決めません。

## 4. Envelopeとdomain common header

Family 5/6 valueは12章6.2の`NLR1` envelopeを使います。`record_type=5`はhealth marker、`record_type=6`はdomain recordです。`record_version=1`、total `12 + payload_length + 4 <= 4096`です。

Family 5/6 payloadは次のexact common headerから始まります。

```text
domain_format       u16 = 1
subtype             u8, key subtypeとexact一致
flags               u8, subtypeごとのknown bitだけ
record_revision     u64, 1..UINT64_MAX
primary_id          16 bytes
head_witness_digest 32 bytes
primary_value_digest 32 bytes
body_length         u32
body                exact body_length bytes
```

Common headerは96 bytesです。`record_revision`は1始まり、replacement時にcurrent<UINT64_MAXならchecked +1します。TRANSACTION_STATE、EVIDENCE_CELL、EVENT_SPOOL、RESULT_CACHE、RETRY_SUMMARYは12/13章がMAX後も許すlate/duplicate/saturating updateだけcurrent=MAXを維持でき、他subtypeのMAX replacementはCOUNTER_EXHAUSTED/fail closedです。Value changeの一意性はrevisionだけでなくcomplete value digestとwitness headで判定します。TRANSACTION_STATEではpublic `record_revision`と同値です。Family 5/6 semantic business recordはmember 1件だけのmutationでもwitnessを使い、current revisionの`head_witness_digest`はnon-zeroです。Zero headを許すのはfamily 5 INTERNAL_INVARIANT、CLOCK_BASELINE、WITNESS_HEADER/CHUNK、BASELINE WITNESS_HEAD_INDEXだけです。WITNESSED HEAD_INDEXはnon-zeroです。BEARER_STATEを含む他family 6 recordのzero headはcorruptです。Family 3/4 memberはcommon headerを持たないためHEAD_INDEXとmanifest value digestで照合します。`primary_value_digest`はprimary recordではzero、secondary recordでは同じsnapshotにあるcomplete primary encoded valueのSHA-256です。Body trailing byteは禁止です。

Common `flags`はBLOBだけbit 0=manifest / bit 1=chunkのどちらかexact 1つを設定し、他subtypeは0です。Unknown bit、両bit、body variantとの不一致はcorruptです。

`primary_id`はprimary recordでは自分、secondaryでは参照primaryのidentityを16 bytesへ写したhintです。ID128はそのID、u64/singletonはleft zero-padしたbig-endian identity、digest keyはdigest先頭16 bytesです。これはlookup補助であり、最終同一性はbody内raw identityから再構成したcomplete primary keyと`primary_value_digest`で判定します。

## 5. Key grammar

Rootは12章と同じexact 8 bytes `4e494e4c494c0001`です。

```text
root[8] | family:u8 | subtype:u8 | key_format:u8=1 |
identity_kind:u8 | identity_length:u8 | identity[identity_length]
```

Key lengthは13..45 bytesです。Identity kindはclosedです。

| Kind | Value | Length |
| --- | ---: | ---: |
| singleton | 1 | 0 |
| ID128 | 2 | 16 |
| u64 | 3 | 8 |
| SHA-256 of exact raw identity | 4 | 32 |
| SHA-256 of typed composite identity | 5 | 32 |

Family 5は`family=05`、family 6は`family=06`です。Current keyspaceのunknown subtype/kind/lengthはcorruptです。Recognizable future rootは、key length 8..255、先頭7 bytesがexact `4e494e4c494c00`、8 byte目のunsigned versionが2..255、value length 16..4096、valueがcomplete `NLR1` envelope（magic、declared length、CRC32Cがvalid）であるrowだけです。Future rootの残りkey bytesとenvelope `record_type` / `record_version`は解釈しません。このpredicateを満たすrowが1件以上ありcurrent corruptionが0ならunsupported、prefixだけ一致するshort key、version 0、invalid/partial envelope、required key>255/value>4096はcorruptです。Current rootのenvelope `record_version>1`またはfamily 5/6 `domain_format>1`も、該当version fieldまで安全にdecodeできcurrent corruptionが0の場合だけunsupportedです。

### 5.1 Digestの正本

`VALUE_DIGEST(v)`はCRCを含むcomplete `NLR1` encoded value bytes全体の`SHA-256(v)`です。Fieldの一部、decoded body、host structのhashではありません。Key digestは次のexact preimageだけを使います。ASCII separatorは表記されたbyte列そのもので、NUL terminatorを含みません。`RAW16`はlength prefixを含むencoding、u16/u32/u64は本章のbig-endianです。

```text
COMPOSITE(subtype, components) =
  SHA-256(ASCII("NINLIL-DOMAIN-KEY-V1") || subtype:u8 || components)

KEY_DIGEST(complete_key) =
  SHA-256(ASCII("NINLIL-DOMAIN-ENCODED-KEY-V1") || complete_key_bytes)
```

Field名が`*_key_digest`、`primary_key_digest`、`manifest_key_digest`、`subject_primary_key_digest`で終わる場合は、identity kindに関係なくroot/family/subtype/key format/kind/length/identityを含むcomplete encoded keyの`KEY_DIGEST`です。Composite identityそのもの、key先頭16 bytes、value digestではありません。`witness_digest`だけはWITNESS_HEADER composite identityそのものです。

| Subtype / variant | Exact components |
| --- | --- |
| SERVICE `10` | `service_key_raw:RAW16` |
| SERVICE_QUOTA `11` | `service_key_raw:RAW16` |
| RESERVATION `23` | `owner_kind:u16 || owner_key_raw:RAW16` |
| IDEMPOTENCY_MAP `24` | `scope_raw:RAW16 || idempotency_key:RAW16` |
| EVENT_ID_MAP `25` | `scope_raw:RAW16 || event_id[16]` |
| BLOB manifest `30` | `u8=1 || blob_id_digest[32]` |
| BLOB chunk `30` | `u8=2 || blob_id_digest[32] || chunk_index:u32` |
| ATTEMPT `31` | `attempt_owner_kind:u16 || owner_key_raw:RAW16 || attempt_id[16]` |
| EVIDENCE_CELL `32` | `evidence_owner_kind:u16 || owner_key_raw:RAW16 || slot_index:u32` |
| CANCEL_STATE `33` | `cancel_owner_kind:u16 || owner_key_raw:RAW16` |
| DELIVERY `40` | `delivery_key_raw:RAW16` |
| RESULT_CACHE `41` | `delivery_key_raw:RAW16` |
| REVERSE_REPLY `42` | `reply_key_raw:RAW16` |
| RETRY_SUMMARY `51` | `transaction_id[16] || summary_kind:u16 || slot_index:u16` |
| MANAGEMENT_LEDGER `52` | `transaction_id[16] || operation_id[16]` |
| RETENTION_BASIS `61` | `subject_kind:u16 || subject_key_raw:RAW16` |
| CLEANUP_PLAN `63` | `subject_kind:u16 || subject_primary_key_digest[32]` |
| WITNESS_HEAD_INDEX `7d` | `member_key_digest[32]` |
| WITNESS_MANIFEST_CHUNK `7e` | `witness_digest[32] || chunk_index:u16` |
| WITNESS_HEADER `7f` | `operation_kind:u16 || operation_identity:RAW16` |

Reusable raw identityのcontentsもclosedです。

| Name | Exact contents（外側RAW16 lengthは含めない） |
| --- | --- |
| `service_key_raw` | `local_application_instance_id[16] || namespace:TEXT_ID || service:TEXT_ID || descriptor_revision:u64 || descriptor_digest[32]` |
| idempotency/event `scope_raw` | `source.application_instance_id[16] || service.namespace:TEXT_ID || service.service:TEXT_ID` |
| `delivery_key_raw` | `source.runtime_id[16] || source.application_instance_id[16] || transaction_id[16] || local_target.runtime_id[16] || local_target.application_instance_id[16]` |
| `reply_key_raw` | `delivery_key_raw:RAW16 || reply_kind:u32` |
| `subject_key_raw` | subject primaryのkey identity raw bytes。ID128=16 bytes、u64=8 bytes、composite=その元components encoding |

`target_digest = SHA-256(ASCII("NINLIL-DOMAIN-TARGET-V1") || TARGET)`です。`blob_id_digest = SHA-256(ASCII("NINLIL-DOMAIN-BLOB-ID-V1") || blob_owner_kind:u16 || owner_key_raw:RAW16 || blob_kind:u16 || content_digest[32] || total_length:u64)`です。これらのpreimageにABI header、pointer、padding、reserved byteを含めません。

同じdigestを別domainで再利用しません。`witness_digest`は上表のWITNESS_HEADER composite digestそのもので、header value digestではありません。Manifest digestは`SHA-256(ASCII("NINLIL-DOMAIN-MANIFEST-V1") || chunk_body_0 || ... || chunk_body_n)`です。Bodyが持つdigest-key identity componentは全てexact raw bytesを重複保存し、keyとの再計算一致を要求します。

Management canonical request digestは12章10節と同じ次のexact preimageです。ABI header、pointer、reserved、paddingを含めず、metadata lengthはu32です。

```text
resume_request_digest = SHA-256(
  ASCII("NINLIL-M1A-EVENT-RESUME") || transaction_id[16] ||
  operation_id[16] || actor_id[16] || expected_spool_revision:u64 ||
  resume_reason:u32 || metadata_length:u32 || metadata)

discard_request_digest = SHA-256(
  ASCII("NINLIL-M1A-EVENT-DISCARD") || transaction_id[16] ||
  operation_id[16] || actor_id[16] || expected_event_id[16] ||
  expected_content_digest_algorithm:u16 || expected_content_digest[32] ||
  expected_spool_revision:u64 || discard_reason:u32 ||
  acknowledge_required_receipt_absent:u32 || metadata_length:u32 || metadata)
```

`message_semantic_digest`はBearer C struct memoryでなく次のexact value digestです。

```text
SHA-256(ASCII("NINLIL-BEARER-MESSAGE-V1") ||
  kind:u32 || flags:u32 || transaction_id[16] || attempt_id[16] || event_id[16] ||
  source:PARTY || target:TARGET || service:SERVICE_IDENTITY || content_digest[32] ||
  generation:u64 || deadline_clock_epoch[16] || absolute_effect_deadline_ms:u64 ||
  evidence_grace_ms:u64 || required_evidence:u32 || receipt_stage:u32 ||
  disposition:u32 || effect_certainty:u32 || retry_guidance:u32 || cancel_kind:u32 ||
  retry_delay_ms:u64 || evidence_clock_epoch[16] || evidence_now_ms:u64 || evidence_trust:u32 ||
  payload_length:u32 || payload || evidence_length:u32 || evidence)
```

Kind-specific zero/empty ruleは12章5.4です。ORDERED_INGRESSはbodyが持つsemantic prefixと参照BLOBをstreamしてD1でこのdigestを再計算します。REVERSE_REPLYとATTEMPT bodyはPARTY/TARGET/SERVICE等のsemantic prefixを持たないため、D1ではstored digestのnon-zeroとkind/attempt/body closed shapeだけを証明し、D3がlive owner、RESULT/CANCEL、参照BLOBからmessageを再構成して再計算します。BLOB bytesだけで不足fieldを推測またはzero補完してはなりません。CANCEL_STATEの`message_semantic_digest`は`cancel_attempt_id`がnon-zeroのときだけnon-zeroで、both-zeroは§8.4 closed matrixのNONEとTX local pre-dispatch FENCEDだけです。D1はattempt/digestのboth-zeroまたはboth-non-zeroとmatrix整合だけを証明します。D3はnon-zero cancel caseだけをlive ownerとempty CANCEL_REQUEST viewからmessageを再構成して再計算し、そのrequest preimageの`cancel_kind`は0（bodyに保存するpublic result kindではない）です。

このpreimageの`PARTY` / `TARGET` / `SERVICE_IDENTITY`は本章3節のdomain encodingであり、public ABI header、pointer、reserved、paddingはhashしません。**ORDERED_INGRESS bodyのlocal durable-copy metadataである`controller_ingress_clock_epoch` / `controller_ingress_at_ms` / `controller_ingress_trust` / その直後`reserved:u32=0`、およびissuer evidence triple直後の`reserved:u32=0`はBearer message semantic preimageおよび`message_semantic_digest`に含めません**（§8.3）。実装はprefix、宣言済み`payload_length`、payloadのdata byte列、宣言済み`evidence_length`、evidenceのdata byte列の順を変えずincremental SHA-256へ投入し、BLOB chunk recordのframingはhashしません。各streamの実投入長が宣言長とexact一致しないfinalを拒否します。Zero-length viewはlength u32=0だけをhashし、data byteを投入しません。One-shot helperも同じstreaming state machineのwrapperとし、payload/evidenceを連結した一時bufferやVLAを要求しません。

## 6. Family 5: standalone health source

Current family 5 subtypeはexact 1個です。

| Subtype | Key identity | Body |
| ---: | --- | --- |
| `01 INTERNAL_INVARIANT` | marker ID128 | `reason:u32 + subject_kind:u16 + reserved:u16=0 + subject_digest[32] + first_clock_epoch[16] + first_at_ms:u64 + detail_digest[32]` |

Marker revisionは常に1、head witnessとprimary digestはzeroです。`subject_kind`はsubject complete keyのrecord roleで、family 3=`0x0300`、family 4=`0x0400`、family 6 current semantic subtype=`0x0600 | subtype`だけです。Family 1/2/5、witness subtype 7d..7f、unknown family/subtypeはcorruptです。`subject_digest`はそのcomplete keyの`KEY_DIGEST`で、namespace全体ならsubject kind/digestをともにzeroにします。Marker IDは`SHA-256(ASCII("NINLIL-DOMAIN-INVARIANT-V1") || reason:u32 || subject_kind:u16 || subject_digest[32])`の先頭16 bytesで、新しいEntropyを消費しません。既存別markerとID衝突してcomplete preimageが異なる場合はcorruptです。Aggregate health、counter/capacity exhausted、callback recovery、commit unknownはfamily 5へ重複保存しません。Raw Storage corruptionを発見した後にmarkerを書こうとしてはなりません。

## 7. Family 6 closed subtype catalog

Subtype `01`はfuture schema/migration marker用に予約し、v1 Coreは生成しません。Provider schema、key root version、Type 1 bindingの`storage_schema`がv1 schema truthです。

| Subtype | Name | Key identity | Max body |
| ---: | --- | --- | ---: |
| `10` | SERVICE | composite digest | 768 |
| `11` | SERVICE_QUOTA | composite digest | 512 |
| `20` | TRANSACTION_ANCHOR | transaction ID | 1536 |
| `21` | TRANSACTION_SEQUENCE_INDEX | u64 sequence | 64 |
| `22` | TRANSACTION_STATE | transaction ID | 512 |
| `23` | RESERVATION | composite digest | 512 |
| `24` | IDEMPOTENCY_MAP | composite digest | 512 |
| `25` | EVENT_ID_MAP | composite digest | 512 |
| `26` | SCHEDULER_OWNER | u64 owner sequence | 512 |
| `27` | ORDERED_INGRESS | u64 ordered sequence | 1536 |
| `30` | BLOB | composite digest | 3264 |
| `31` | ATTEMPT | composite digest | 512 |
| `32` | EVIDENCE_CELL | composite digest | 1024 |
| `33` | CANCEL_STATE | composite digest | 512 |
| `34` | ATTEMPT_ID_INDEX | attempt ID | 128 |
| `40` | DELIVERY | composite digest | 1024 |
| `41` | RESULT_CACHE | composite digest | 1024 |
| `42` | REVERSE_REPLY | composite digest | 3264 |
| `50` | EVENT_SPOOL | transaction ID | 1536 |
| `51` | RETRY_SUMMARY | composite digest | 768 |
| `52` | MANAGEMENT_LEDGER | composite digest | 1024 |
| `60` | BEARER_STATE | singleton | 64 |
| `61` | RETENTION_BASIS | composite digest | 512 |
| `62` | CLOCK_BASELINE | singleton | 64 |
| `63` | CLEANUP_PLAN | composite digest | 512 |
| `64` | ATTEMPT_REUSE_FENCE | singleton | 64 |
| `7d` | WITNESS_HEAD_INDEX | composite digest | 192 |
| `7e` | WITNESS_MANIFEST_CHUNK | composite digest | 3000 |
| `7f` | WITNESS_HEADER | composite digest | 384 |

### 7.1 Private integer registries

Public semantic field（transaction state/outcome/reason、Receipt stage、Disposition、effect certainty、retry guidance、cancel/result/resume/discard kind等）は12章のpublic integerをexact保存します。次だけがDomain Store private enumです。表にない値はcorruptです。

| Field | Closed values |
| --- | --- |
| reservation `owner_kind` | 1 SERVICE, 2 TRANSACTION, 3 INGRESS, 4 DELIVERY, 5 CALLBACK |
| scheduler `owner_kind` | 1 TRANSACTION, 2 DELIVERY, 3 INGRESS |
| `work_class` | 1 REDUCE, 2 DISPATCH, 3 TIMER, 4 CALLBACK, 5 CLEANUP, 6 RECOVERY |
| `ingress_state` | 1 PENDING |
| ingress `owner_binding_kind` | 1 EXISTING_TRANSACTION, 2 EXISTING_DELIVERY, 3 NEW_DELIVERY |
| `blob_kind` | 1 COMMAND_PAYLOAD, 2 EVENT_PAYLOAD, 3 INGRESS_PAYLOAD, 4 EVIDENCE, 5 REPLY |
| BLOB `blob_owner_kind` | 1 TRANSACTION, 2 INGRESS, 3 DELIVERY |
| `attempt_kind` | 1 COMMAND, 2 EVENT, 3 CANCEL |
| `attempt_state` | 1 PREPARED, 2 OBSERVED_SENT, 3 RESOLVED, 4 RECOVERY_REQUIRED |
| attempt `attempt_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| attempt `send_state` | 1 PREPARED, 2 RETRYABLE_NO_SEND, 3 SENT_POSSIBLE, 4 CLOSED_DENIED, 5 RECOVERY_REQUIRED |
| cancel `cancel_send_gate_state` | 1 NEVER_INVOKED, 2 WOULD_BLOCK_RETRYABLE, 3 INVOKED_CLOSED |
| evidence `cell_kind` | 1 SUMMARY, 2 RAW |
| evidence `cell_state` | 1 UNUSED, 2 MATERIALIZED |
| evidence `evidence_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| cancel `cancel_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| `cancel_state` | 1 NONE, 2 PENDING_REMOTE_FENCE, 3 FENCED_BEFORE_DISPATCH, 4 TOO_LATE_EFFECT_POSSIBLE |
| `delivery_state` | physical storage closed: 1 INBOX_COMMITTED, 2 DELIVERY_STARTED, 4 RESULT_COMMITTED, 5 DISPOSITION_COMMITTED, 6 RECOVERY_REQUIRED, 7 RECONCILE_WAIT, 8 CANCEL_TOMBSTONE_ONLY。numeric **3 は V1 reserved / illegal**（public/in-memory projection 名 `DEFERRED_WAIT` 用に予約するが Domain Store body へ書いてはならず、decode scalar が 3 でも same-record validator は corrupt） |
| delivery `creation_kind` | 1 APPLICATION_FIRST, 2 CANCEL_FIRST |
| `token_state` | 1 NONE, 2 ACTIVE, 3 CONSUMED, 4 EXPIRED, 5 RECOVERY_REQUIRED_TOMBSTONE |
| `reply_kind` | 1 RECEIPT, 2 DISPOSITION, 3 CUSTODY, 4 CANCEL_RESULT |
| reply `send_state` | 1 PENDING, 2 WAITING_RETRY, 3 CLOSED_SENT_OR_UNKNOWN, 4 CLOSED_DENIED, 5 CLOSED_COUNTER_EXHAUSTED |
| `spool_state` | 1 ACTIVE, 2 PARKED_RETRY, 3 RELEASED, 4 DISCARDED |
| retry `summary_kind` | 1 CUMULATIVE, 2 RECENT |
| retention `subject_kind` | 1 SERVICE, 2 TRANSACTION, 3 DELIVERY, 4 EVENT |
| `retention_state` | 1 ACTIVE, 2 ELIGIBLE, 3 CLEANUP_COMMITTED |
| cleanup `cleanup_phase` | 1 DELETE_NON_INDEX, 2 DELETE_ATTEMPT_INDEX, 3 FINALIZE |
| witness `retention_kind` | 0 NONE, 1 SERVICE, 2 TRANSACTION, 3 DELIVERY, 4 EVENT |
| witness `witness_state` | 1 ACTIVE, 2 SUPERSEDED, 3 RETIRED |
| head index `index_state` | 1 BASELINE, 2 WITNESSED |
| clock baseline `baseline_state` | 1 UNINITIALIZED, 2 TRUSTED |

Reservation owner identityはexact 1つです。SERVICEは`service_key_raw`のcontents、TRANSACTIONは`transaction_id[16]`、INGRESSは`ordered_sequence:u64`、DELIVERYは`delivery_key_raw`のcontents、CALLBACKは`delivery_key_raw:RAW16 || token_generation:u64`を`owner_key_raw`のcontentsにします。Primaryは順にSERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、DELIVERYです。同じsemantic ownerはcanonical formulaにより0または1 RESERVATIONだけを持ち、別keyや別rawでの重複はcorruptです。NAMESPACE reservationはv1でunknown owner kindとしてcorruptです。

Scheduler subject rawはTRANSACTION=`transaction_id[16]`、DELIVERY=`delivery_key_raw` contents、INGRESS=`ordered_sequence:u64`です。Primaryは順にTRANSACTION_ANCHOR、DELIVERY、ORDERED_INGRESSで、ownerがINGRESSからDELIVERYへ移るreductionはSCHEDULER_OWNER value/common primary digestのreplacementとINGRESS erase/DELIVERY createを同じwitness groupへ含めます。Namespace/Bearer/recovery barrierはownerを作らず、owner kind外です。

BLOB owner mappingはTRANSACTION=`transaction_id[16]`→TRANSACTION_ANCHOR、INGRESS=`ordered_sequence:u64`→ORDERED_INGRESS、DELIVERY=`delivery_key_raw` contents→DELIVERYです。Allowed pairはCOMMAND/EVENT_PAYLOAD×TRANSACTIONまたはDELIVERY、INGRESS_PAYLOAD/EVIDENCE×INGRESS、REPLY×DELIVERYだけです。各owner/blob kind/content digest tupleは0または1 manifestを持ち、別blob ID aliasはcorruptです。

## 8. Exact subtype bodies

下表のfieldを記載順にencodeします。Optional IDはpresence u8の直後に置き、absentなら16-byte ID自体を省略します。Bodyのraw identityとkey digestはexact一致必須です。

### 8.1 Serviceとquota

- `SERVICE`: `service_key_raw:RAW16(max 255) + descriptor_revision:u64 + descriptor_digest[32] + local_application_instance_id[16] + namespace:TEXT_ID + service:TEXT_ID + schema:TEXT_ID + schema_major:u16 + minor_min:u16 + minor_max:u16 + family:u32 + direction:u32 + admission_authority:u32 + apply_contract:u32 + custody_policy:u32 + supported_evidence_mask:u32 + logical_payload_limit:u32 + target_limit:u32 + inflight_limit:u32 + attempts_per_cycle:u32 + admission_window_ms:u32 + max_admissions_window:u32 + max_payload_window:u32 + minimum_deadline_ms:u64 + maximum_deadline_ms:u64 + maximum_evidence_grace_ms:u64 + attempt_receipt_timeout_ms:u64 + retry_backoff_ms:u64 + application_completion_timeout_ms:u64 + required_dedup_window_ms:u64 + quota_key_digest[32] + reservation_key_digest[32]`。
- `SERVICE_QUOTA`: `service_key_raw:RAW16(max 255) + service_key_digest[32] + window_clock_epoch[16] + window_start_ms:u64 + admissions_in_window:u32 + payload_bytes_in_window:u64 + active_transaction_count:u32 + active_spool_count:u32 + active_spool_bytes:u64`。Common primary digestはSERVICE value、`service_key_digest`はcomplete SERVICE keyの`KEY_DIGEST`です。Receiver DELIVERYはorigin descriptor quotaへ数えません。

Quotaのactive transaction/spool/count/bytesはlive TRANSACTION RESERVATION contributionからexact再計算します。`admissions_in_window`と`payload_bytes_in_window`はcleanup済みtransactionから再構成しないwitness-protected authoritative fixed-window accumulatorで、window epoch/start、descriptor limits、checked increment/rollover、`payload_bytes >= 0`を検査します。Window rollover前まで全transaction recordを保持する追加契約を作らず、historical counterをlive sumと比較しません。

### 8.2 Transaction、index、reservation、mapping

- `TRANSACTION_ANCHOR`: `transaction_id[16] + transaction_sequence:u64 + scheduler_owner_sequence:u64 + family:u32 + source:PARTY + service:SERVICE_IDENTITY + content_digest[32] + canonical_submission_digest[32] + event_id[16] + generation:u64 + admission_clock_epoch[16] + admitted_at_ms:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + target_count:u32=1 + target:TARGET + idempotency_scope_raw:RAW16(max 255) + idempotency_key:RAW16(max 64) + sequence_index_key_digest[32] + idempotency_map_key_digest[32] + event_map_key_digest[32] + reservation_key_digest[32] + scheduler_owner_key_sequence:u64 + payload_blob_key_digest[32]`。DesiredStateではevent ID/map keyはzero、EventFactではnon-zeroです。
- `TRANSACTION_SEQUENCE_INDEX`: `transaction_sequence:u64 + transaction_id[16] + anchor_value_digest[32]`。
- `TRANSACTION_STATE`: `transaction_id[16] + anchor_value_digest[32] + state:u32 + outcome:u32 + deadline_verdict:u32 + latest_evidence:u32 + reason:u32 + event_park_cause:u32 + retry_cycle_id:u64 + attempt_in_cycle:u32 + cumulative_attempts:u64 + event_spool_revision:u64 + has_late_evidence:u32 + explicitly_discarded:u32 + target:TARGET + target_state:u32 + target_outcome:u32 + target_reason:u32 + target_latest_evidence:u32`。
- `RESERVATION`: `owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 255) + primary_key_digest[32] + resources:RESOURCE_VECTOR + service_inflight:u32 + grant_active_count:u32 + grant_active_bytes:u64 + released_mask:u32`。全Core-owned allocationを7.1のowner別recordにし、11 kind全部を保存します。Keyとbody ownerは5.1で再計算し、common primary digestはそのowner primary valueです。`released_mask` bit 0..10はresource kind 1..11、known mask `0x000007ff`だけです。Bitは0→1単調で、そのkindのused/reservedが両方zeroになったfinal releaseと同じFULL groupで立て、同ownerによる再取得を禁止します。Ownerが一度も保持しないkindのbitは0です。
- `IDEMPOTENCY_MAP`: `scope_raw:RAW16(max 255) + idempotency_key:RAW16(max 64) + transaction_id[16] + canonical_submission_digest[32] + anchor_value_digest[32]`。
- `EVENT_ID_MAP`: `scope_raw:RAW16(max 255) + event_id[16] + transaction_id[16] + canonical_submission_digest[32] + idempotency_key:RAW16(max 64) + anchor_value_digest[32]`。

### 8.3 Schedulerとingress

- `SCHEDULER_OWNER`: `owner_sequence:u64 + owner_kind:u16 + work_class:u16 + subject_key_raw:RAW16(max 255) + primary_key_digest[32] + state_revision:u64 + logical_clock_epoch[16] + logical_at_ms:u64 + next_wake_clock_epoch[16] + next_wake_at_ms:u64 + ready:u32`。`subject_key_raw`からTRANSACTION_ANCHOR / DELIVERY / ORDERED_INGRESS primary keyをowner kindどおりexact導出します。`owner_sequence`と`state_revision`は1以上、`logical_clock_epoch`はnon-zero、`ready`はu32 exact 0/1です。Next wakeはepoch/timeともzero（future timerなし）またはepoch non-zeroかつtime non-zero（future timerあり）のexact 2形だけです。Immediate workと別のfuture timerは同じownerに併存できるため、`ready=1`でも後者を許します。`state_revision`はowner stateのrevisionでありcommon `record_revision`とは別counterなので、同値を要求しません。
- `ORDERED_INGRESS`: `ordered_sequence:u64 + owner_sequence:u64 + owner_binding_kind:u16 + reserved:u16=0 + message_kind:u32 + message_flags:u32=0 + transaction_id[16] + attempt_id[16] + event_id[16] + source:PARTY + target:TARGET + service:SERVICE_IDENTITY + content_digest[32] + generation:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + receipt_stage:u32 + disposition:u32 + effect_certainty:u32 + retry_guidance:u32 + cancel_kind:u32 + retry_delay_ms:u64 + evidence_clock_epoch[16] + evidence_now_ms:u64 + evidence_trust:u32 + reserved:u32=0 + controller_ingress_clock_epoch[16] + controller_ingress_at_ms:u64 + controller_ingress_trust:u32 + reserved:u32=0 + message_semantic_digest[32] + payload_blob_key_digest[32] + evidence_blob_key_digest[32] + ingress_state:u32=1 + reservation_key_digest[32]`。`message_kind`ごとの非該当fieldはzero、必須fieldとzero規則は12章Bearer message表とexact一致します。Issuer evidence time（`evidence_clock_epoch` / `evidence_now_ms` / `evidence_trust`）はBearer Receiptのself-contained copyで、非Receiptでは全zeroです。`controller_ingress_*`はlocal durable-copy metadataです（下記）。EXISTING variantsはowner sequenceの既存TRANSACTION/DELIVERY ownerへattachしnew ownerを作らず、NEW_DELIVERYだけINGRESS-primary ownerを同じcopy groupで作りreduction時にDELIVERYへtransferします。これだけと参照BLOBからBearer semantic valueをbyte-for-byte再構成できなければcorruptです。ReductionはORDERED_INGRESSをREDUCEDへreplaceせず、reducer outputと同じFULL groupでeraseします。

ORDERED_INGRESSのsame-record contractは次をexactとします。`ordered_sequence` / `owner_sequence`は1以上です。`owner_binding_kind`はAPPLICATION / CANCEL_REQUESTではEXISTING_DELIVERYまたはNEW_DELIVERY、RECEIPT / DISPOSITION / CUSTODY_ACCEPTED / CANCEL_RESULTではEXISTING_TRANSACTIONだけを許します。全kindでtransaction ID / attempt ID / content digestはnon-zero、source / target / serviceは本章3節のvalid shape、service familyはEventFactまたはDesiredState、required evidenceはknown non-zeroです。EventFactはevent ID non-zero、generation 0、deadline epoch zero、deadline `NINLIL_NO_DEADLINE`、evidence grace 0です。DesiredStateはevent ID zero、generation 1以上、deadline epoch non-zero、`absolute_effect_deadline_ms != NINLIL_NO_DEADLINE`です。CANCEL_REQUEST / CANCEL_RESULTはDesiredStateだけです。Receipt stageはsame-recordではknown non-zeroだけを要求し、SERVICEのsupported evidence maskとの照合はD3です。Disposition tuple、Cancel result kind、issuer evidence time、unused enum/viewのzero規則は12章5.4 / 7.2をそのまま適用し、Receiptの`evidence_now_ms==0`はvalid monotonic sampleとして許します。

Wire field orderは上表の列挙順で一意です。paddingやfield並びを推測しません。issuer evidence tripleの直後にある`reserved:u32=0`（`evidence_trust`と`controller_ingress_clock_epoch`の間）は常にexact 0で、他用途へ流用しません。その次にController durable ingress sampleをexact 32 bytesで置きます。

```text
controller_ingress_clock_epoch[16]
+ controller_ingress_at_ms:u64
+ controller_ingress_trust:u32
+ reserved:u32=0
```

この4 fieldの直後`reserved:u32=0`も常にexact 0で、`message_semantic_digest`の直前です。両`reserved:u32=0`を省略・統合・別offsetへ動かしてはなりません。

Controller durable ingress sampleは**local RuntimeがBearer messageをORDERED_INGRESSへdurable copyする時点**で固定した`ninlil_time_sample_t`のdomain encodingであり、Bearer wire / message semantic preimage / `message_semantic_digest`には**含めません**（§5.1）。SCHEDULER_OWNER logical time、CLOCK_BASELINE、EVIDENCE_CELL、TRANSACTION_STATE、witness、他subtypeは本sampleの代替durable sourceではありません。

| message_kind | controller_ingress_clock_epoch | controller_ingress_at_ms | controller_ingress_trust | trailing reserved |
| --- | --- | --- | --- | --- |
| RECEIPT | non-zero | 任意u64（**0もvalid** monotonic sample） | exact 1 TRUSTED または 2 UNCERTAIN | 0 |
| 非RECEIPT | all-zero | 0 | 0 | 0 |

表外（epoch non-zeroなのにtrust unknown、trust non-zeroなのにepoch zero、非RECEIPTでいずれかnon-zero、reserved≠0）はcorruptです。RECEIPTでもissuer evidence tripleとcontroller tripleは独立であり、一方がUNCERTAINでも他方の規則を緩めません。

ORDERED_INGRESSはreduction完了まで本sampleを保持します。RECEIPT reductionは同じFULL witness groupで (1) TRANSACTION_STATEのdeadline verdict固定、(2) EVIDENCE_CELL SUMMARY/RAW更新（issuer evidence_timeとmaterialのみ。controller sampleはEVIDENCE_CELLへ**コピーしない**）、(3) 必要なら他owner child更新、の後にORDERED_INGRESSをeraseします。erase前にcontroller sampleを別recordへ退避しません。crash/restart後のM1A-TIME-009/010再現は、未reduceのORDERED_INGRESS rowが保持する本fieldからだけ行います。

Payload BLOB key digestはAPPLICATIONだけzero/non-zeroを許し、Evidence BLOB key digestはRECEIPTだけzero/non-zeroを許します。他kind/反対側digestはzeroです。Zeroは元viewがexact length 0でmanifest 0件、non-zeroは元viewがlength 1以上でINGRESS ownerのmanifest exact 1件を意味し、zero-length manifestは作りません。APPLICATIONかつpayload digest zeroでは、D1が`content_digest=SHA-256(0-length byte string)`をsemantic digestとは独立に要求します。D1 same-record validationは両BLOB digestがzeroならempty payload/evidenceで`message_semantic_digest`を再計算し、どちらかがnon-zeroなら`message_semantic_digest`もnon-zeroであることとkind/presence規則までを検査します。controller ingress fieldは再計算preimageに入れません。D3 validationはzero/non-zero両経路でBLOB 0/1 cardinalityを照合し、non-zeroならmanifest/chunkのlength/content/key digestを検証し、参照data bytes（emptyなら0 bytes）をstreamしてsemantic digestを常に再計算します。B3bがBLOB keyをbody情報だけから推測してはなりません。

`reservation_key_digest`は`owner_kind:u16=INGRESS(3) || owner_key_raw:RAW16(contents=ordered_sequence:BE8)`をcomponentsとするRESERVATION (`23`) complete keyのKEY_DIGESTです。ORDERED_INGRESS keyはbody `ordered_sequence`と同じu64 identity、common primary IDはそのBE8をleft-zero-padした16 bytesです。これはimmutable primaryなのでcommon revisionは1、flags 0、primary value digest zero、head witness digest non-zeroです。

**D1-B3b retrofit境界**: 既存D1-B3b codec / golden vectorはcontroller ingress 32-byte block追加前のORDERED_INGRESS bodyを前提としており、本Normative追加後のwireとは非互換です。B3g（EVIDENCE_CELL）実装およびRECEIPT reduction / deadline proofのdurable再構成を行う前に、B3b body encode/decode / same-record validation / `message_semantic_digest`非包含 / golden vectorを本field layoutへ**retrofit完了**していることを前提とします。retrofit前のB3b artifactをB3g前提の正本とみなしてはなりません。B3b retrofit後もlive owner/SCHEDULER/RESERVATION/BLOB cardinality、owner transfer、reduction erase、namespace counter上限、deadline verdictの跨record証明はD3へ残します。

### 8.4 Blob、attempt、evidence、cancel

`BLOB.flags` low 2 bitsは1=manifest、2=chunkです。Manifest/chunk keyは5.1のcomposite formulaだけを使います。

- BLOB manifest: `blob_id_digest[32] + blob_owner_kind:u16 + blob_kind:u16 + owner_key_raw:RAW16(max 255) + owner_primary_key_digest[32] + total_length:u64 + chunk_count:u32 + content_digest[32]`。Common primary digestはowner primary valueです。
- BLOB chunk: `blob_id_digest[32] + manifest_key_digest[32] + chunk_index:u32 + chunk_count:u32 + total_length:u64 + content_digest[32] + chunk_length:u32 + chunk_bytes[chunk_length]`。Common primary digestはmanifest complete value、`chunk_length<=3072`です。

BLOBのsame-record wire contractは次をexactとします。Common flagsはmanifest=`1`、chunk=`2`のどちらか1つだけでbody variantと一致し、両variantともimmutable `record_revision=1`、head witness digest / primary value digestはnon-zeroです。`blob_owner_kind`はBLOB固有enumでTRANSACTION=1、INGRESS=2、DELIVERY=3とし、reservation/scheduler enumを流用しません。`owner_key_raw`はlengthだけでなくcanonical identityまで閉じます: TRANSACTIONはtransaction ID exact **nonzero** 16 bytes、INGRESSはordered sequence BE8 exact 8 bytesかつ **u64 big-endian >0**、DELIVERYは`delivery_key_raw` contents exact 80 bytesかつ **5個の16-byte IDがすべてnonzero**です（length-onlyでall-zero rawを許すのはcorrupt）。Allowed `(owner, blob_kind)`はTRANSACTION/DELIVERY×COMMAND_PAYLOAD/EVENT_PAYLOAD、INGRESS×INGRESS_PAYLOAD/EVIDENCE、DELIVERY×REPLYだけで、他はcorruptです。

Manifestはbodyのowner kind / raw、blob kind、content digest、total lengthから5.1節の`blob_id_digest`を再計算します。`owner_primary_key_digest`はTRANSACTION_ANCHOR ID128、ORDERED_INGRESS u64、DELIVERY compositeのcomplete keyをowner rawからexact導出したKEY_DIGESTです。Manifest key identityは`COMPOSITE(30, u8=1 || blob_id_digest)`、common primary IDは参照owner primary identity（transaction ID / ordered sequence left-zero-pad / DELIVERY composite identity先頭16）です。

Chunkは`chunk_count>=1`、`chunk_index<chunk_count`で、bodyの`blob_id_digest` / `chunk_index`から`COMPOSITE(30, u8=2 || blob_id_digest || chunk_index:u32)` key identityを再計算します。`manifest_key_digest`は`COMPOSITE(30, u8=1 || blob_id_digest)`をidentityとするcomplete manifest keyのKEY_DIGEST、common primary IDはそのmanifest composite identity先頭16です。Manifest/chunkともcommon primary value digestのlive value一致はD3で証明します。

Length/countはwrapしないchecked ceilを使います。`blob_id_digest` / `owner_primary_key_digest` / `manifest_key_digest` / `content_digest`は用途どおりnon-zeroです。`total_length=0`なら`chunk_count=0`かつ`content_digest=SHA-256(0-length byte string)`でchunk rowは0件です。`total_length>0`なら`chunk_count=ceil(total_length/3072)`がu32へexact収容できる場合だけvalidです。Chunk rowはzero-lengthを許さず、non-finalは`chunk_length=3072`、finalは`chunk_length=total_length-3072*(chunk_count-1)`の1..3072 bytesです。Single chunkではD1が`content_digest=SHA-256(chunk_bytes)`を再計算し、multi-chunk全体のstream digestと全indexのexact cardinalityはD3で検証します。

Zero-length manifestはwire上validですが、owner-side writer/cardinalityは別規則です。ORDERED_INGRESSのempty INGRESS_PAYLOAD/EVIDENCE viewは8.3節どおりmanifest 0件でzero-length manifestを作りません。Active TRANSACTION/DELIVERYのCOMMAND/EVENT payloadはownerがnon-zero manifest key digestを保持するためempty payloadでもcount 0のmanifest exact 1件を作ります。DELIVERY CANCEL_FIRSTはpayload manifest 0件です。REVERSE_REPLYのREPLY BLOBは全reply kindでmanifest exact 1件を作り、empty evidenceでもcount 0 / total length 0 / SHA-256(empty)のmanifestを作ります。REPLY BLOB contentはBearer evidence viewだけで、RECEIPTは0〜128 bytes、DISPOSITION/CUSTODY/CANCEL_RESULTは0 bytesです。Bearer payload viewは全reverse kindでemptyのためBLOBへ格納せず、semantic preimageへlength 0だけを入れます。`body_blob_key_digest`はREVERSE_REPLY lifetime中常にnon-zeroで、state 1〜4ではlive manifest key、state 5ではerase済みhistorical keyを指します。B3cはこのowner policyを推測せず、B3j/D3のcardinality規則を使います。

B3cはbody/key/blob ID、owner primary key digest、manifest key digest、local length規則、empty/single-chunk content digestまでを証明します。Live owner/manifest get、primary value digest一致、chunk 0..count-1 enumeration、multi-chunk stream、owner semantic content照合、同一owner/kind/contentのmanifest alias、lifecycle erase/capacity accountingはD3へ残します。

Scannerはmanifestからindex 0..chunk_count-1をexact `get`し、全chunkのblob ID/manifest key/count/total/content digestをmanifestへexact照合します。Chunk bytesをindex順にstreaming SHA-256へ入れ、checked length sumが`total_length`、final digestがmanifest `content_digest`と一致しなければcorruptです。Zero lengthはcount 0かつSHA-256(empty)、それ以外はsection 2の非末尾/末尾length規則を満たします。Ownerが保持するBLOB key digestをmanifest complete keyへ、COMMAND/EVENT payloadはowner `content_digest`へ、INGRESS/EVIDENCE/REPLYは対応message/reply semantic fieldへ照合します。Chunk CRCや反復field一致だけでsemantic content検証を省略しません。
- `ATTEMPT`: `attempt_id[16] + attempt_owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + transaction_id[16] + target_digest[32] + attempt_kind:u16 + attempt_state:u16 + retry_cycle_id:u64 + attempt_in_cycle:u32 + cumulative_attempts:u64 + send_operation_generation:u64 + send_invocation_count:u64 + send_counter_exhausted:u32 + reserved:u32=0 + message_semantic_digest[32] + prepared_clock_epoch[16] + prepared_at_ms:u64 + send_state:u32 + availability_epoch:u64 + receipt_timeout_clock_epoch[16] + receipt_timeout_at_ms:u64`。TRANSACTION ownerはanchor、DELIVERY ownerはEndpoint deliveryをprimaryにします。Application attemptのsend return certaintyは`send_state`、remote cancelの再invocation可否はCANCEL_STATE gateを正本にします。Cached reverse sendはREVERSE_REPLYだけで管理しATTEMPTを作りません。

ATTEMPTのsame-record identityは次をexactとします。`attempt_owner_kind`はATTEMPT固有enumの1 TRANSACTIONまたは2 DELIVERYで、reservation/scheduler/BLOB enumを流用しません。TRANSACTION rawはbody `transaction_id`と同じnon-zero 16 bytes、DELIVERY rawは`delivery_key_raw` contents exact 80 bytesで、そのtransaction ID component `[32,48)`はbody `transaction_id`と一致します。`primary_key_digest`は順にTRANSACTION_ANCHOR ID128 / DELIVERY composite complete keyのKEY_DIGESTです。ATTEMPT key identityは`COMPOSITE(31, attempt_owner_kind:u16 || owner_key_raw:RAW16 || attempt_id[16])`、common primary IDはtransaction IDまたはDELIVERY composite identity先頭16です。`attempt_id` / `transaction_id` / `target_digest` / `primary_key_digest` / `message_semantic_digest`はnon-zero、両reservedはzero、common flagsは0、record revisionは1以上、head witness digest / primary value digestはnon-zeroです。Target/semantic digestのlive owner/BLOB一致はD3です。

Prepared timeはclock epoch non-zeroで、`prepared_at_ms=0`をvalidとします。Receipt timeoutは`(epoch zero, at_ms 0)`または`(epoch non-zero, at_ms non-zero)`のexact 2形です。`send_invocation_count <= send_operation_generation`、`send_counter_exhausted`はu32 exact 0/1で、`send_counter_exhausted=1` iff generationまたはinvocation countが`UINT64_MAX`です。COMMAND/EVENTの各kind-6 final observationはgenerationを+1し、Bearer return observationだけinvocation countも+1します。MAX到達とexhausted設定は同じgroupで行い、exhausted後にnew send micro-operationを作りません。CANCELおよびDELIVERY-owned remote ingress ATTEMPTは3 counterを常に0とします。

TRANSACTION-owned local ATTEMPTのclosed snapshot matrixは次です。表外pairはcorruptです。COMMANDは`retry_cycle_id=0 / attempt_in_cycle=0 / cumulative_attempts>=1`、EVENTは`retry_cycle_id>=1 / attempt_in_cycle=1..8 / cumulative_attempts>=attempt_in_cycle`、CANCELは3 fieldとも0で、prepare後replacementでも不変です。

| attempt kind | attempt state | send state | counter / availability / timeout |
| --- | --- | --- | --- |
| COMMAND/EVENT | PREPARED | PREPARED | gen=inv=exhausted=0、availability=0、timeout=(0,0) |
| COMMAND/EVENT | RESOLVED | RETRYABLE_NO_SEND | exhausted規則、timeout=(0,0)、かつexactどちらか: TxGate TEMPORARY=`gen>=1 / inv=0 / availability=0`、Bearer WOULD_BLOCK/UNAVAILABLE=`gen>=1 / inv>=1 / inv<=gen / availability non-zero` |
| COMMAND/EVENT | RESOLVED | CLOSED_DENIED | exhausted規則、timeout=(0,0)、かつexactどちらか: TxGate DENIED/contract=`gen>=1 / inv=0 / availability=0`、Bearer DENIED=`gen>=1 / inv>=1 / inv<=gen / availability non-zero` |
| COMMAND/EVENT | OBSERVED_SENT | SENT_POSSIBLE | gen>=1、inv>=1、inv<=gen、exhausted規則、availability non-zero、timeoutはactive non-zero pairまたはcleared (0,0) |
| COMMAND/EVENT | RESOLVED | SENT_POSSIBLE | gen>=1、inv>=1、inv<=gen、exhausted規則、availability non-zero、timeout=(0,0) |
| COMMAND/EVENT | RECOVERY_REQUIRED | RECOVERY_REQUIRED | counter規則を保った凍結値、availability任意、timeoutは上記2形 |
| CANCEL | PREPARED | PREPARED | counter=0、availability=0、timeout=(0,0) |
| CANCEL | PREPARED | RETRYABLE_NO_SEND | counter=0、availability non-zero、timeout=(0,0)。Reinvoke可否はCANCEL_STATE gateだけで決める |
| CANCEL | RESOLVED | SENT_POSSIBLE | counter=0、availability non-zero、timeout=(0,0) |
| CANCEL | RESOLVED | CLOSED_DENIED | counter=0、availability 0（TxGate）またはnon-zero（Bearer）、timeout=(0,0) |
| CANCEL | RECOVERY_REQUIRED | RECOVERY_REQUIRED | counter=0、availability任意、timeoutは上記2形 |

DELIVERY-owned ATTEMPTはremote ingressのimmutable message historyです。COMMAND/EVENT/CANCELすべて`attempt_state=RESOLVED / send_state=SENT_POSSIBLE`、`retry_cycle_id=0 / attempt_in_cycle=0 / cumulative_attempts=0`、3 counter=0、availability=0、timeout=(0,0)、prepared epoch non-zero（time 0可）とします。TRANSACTION-owned localのCOMMAND/EVENT cycle規則はDELIVERY-ownedへ適用しません。FamilyとCOMMAND/EVENT kind、live owner、ATTEMPT_ID_INDEX 0、CANCEL_STATE gate、current/stale attempt、primary value digest、target/semantic digest、SEND_COUNTER health/cardinalityの相互証明はD3へ残します。
- `EVIDENCE_CELL`: `evidence_owner_kind:u16 + cell_kind:u16 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + target_digest[32] + slot_index:u32 + cell_state:u16 + reserved:u16=0 + highest_receipt_stage:u32 + latest_evidence_stage:u32 + material_receipt_stage:u32 + disposition:u32 + effect_certainty:u32 + late_material:u32 + issuer:PARTY + service_slot[240] + content_digest[32] + generation:u64 + durable_ingress_sequence:u64 + evidence_clock_epoch[16] + evidence_at_ms:u64 + evidence_trust:u32 + counter_saturated:u32 + evidence_digest[32] + evidence_length:u16 + reserved:u16=0 + evidence_bytes[128] + valid_material_count:u64 + exact_duplicate_count:u64 + raw_overflow_count:u64 + late_evidence_count:u64`。TRANSACTION owner rawはtransaction ID、primaryはTRANSACTION_ANCHOR、DELIVERY owner rawはdelivery key contents、primaryはDELIVERYです。`service_slot`は本章3節の通常`SERVICE_IDENTITY` encodingを**変更しない**固定240-byte領域です（下記same-record）。SUMMARYはslot 0/materialized、RAWはslot 1..Lでunused/materializedです。Admission/Delivery admission時にsummary 1件とraw上限件を最大encoded sizeのfixed cellとしてphysical materializeし、cell lifetime中value lengthを変えず、issuer/service/content/generation/time/ingress sequenceを含む13章のduplicate/latest/late判定を完全再構成します。

EVIDENCE_CELLのsame-record wire / identity contractは次をexactとします。

Body lengthはowner raw contentsだけで決まり、TRANSACTION raw exact 16なら**734**、DELIVERY raw exact 80なら**798**だけを許します（max 1024はsubtype上限で不変）。内訳は`718 + owner_key_raw contents`です（`service_slot` exact 240、PARTY exact 100、`evidence_bytes` exact 128、RAW16 length prefix u16、両reserved u16を含む固定部718 + TX16またはDLV80）。12章のfixed-size cell契約どおり、admission時にこのexact body lengthでphysical materializeし、UNUSED→MATERIALIZEDやSUMMARY updateを含むcell lifetime中にvalue length / entry countを増やしません。Body trailing byteは禁止です。

`evidence_owner_kind`はEVIDENCE固有enumの1 TRANSACTIONまたは2 DELIVERYで、reservation/scheduler/BLOB/ATTEMPT/CANCEL enumを流用しません。TRANSACTION rawはnon-zero transaction ID exact 16 bytes、DELIVERY rawは`delivery_key_raw` contents exact 80 bytesで、5つの16-byte component（source runtime/app、transaction ID at `[32,48)`、local_target runtime/app）はすべてnon-zeroです。`primary_key_digest`は順にTRANSACTION_ANCHOR ID128 / DELIVERY composite complete keyのKEY_DIGESTです（composite digest本体とのstore/compare禁止）。Key identityは`COMPOSITE(32, evidence_owner_kind:u16 || owner_key_raw:RAW16 || slot_index:u32)`、common primary IDはtransaction IDまたはDELIVERY composite identity先頭16です。`primary_key_digest` / `target_digest`は常にnon-zero、両reservedは0、common flagsは0、mutable `record_revision>=1`（late/duplicate/saturating updateはMAX維持可）、head witness digest / primary value digestはnon-zeroです。`target_digest`のlive TARGET一致はD3です。

`service_slot[240]`はEVIDENCE_CELL専用の固定slotであり、他subtypeの可変長`SERVICE_IDENTITY` wire規則を変えません。

- material active（SUMMARYかつ`valid_material_count>=1`、またはRAW MATERIALIZED）: 先頭へcanonical `SERVICE_IDENTITY` encoding（54..240 bytes、本章3節 / valid shape、`family`はEventFactまたはDesiredState）を置き、残り`[encoded_length, 240)`をzeroにします。encoded length超過やnon-zero padはcorruptです。
- inactive（SUMMARYかつ`valid_material_count==0`、またはRAW UNUSED）: 240 bytes all-zeroです。通常の`SERVICE_IDENTITY` valid shape検査は適用しません。

Private enumは§7.1どおり`cell_kind` 1 SUMMARY / 2 RAW、`cell_state` 1 UNUSED / 2 MATERIALIZEDだけです。Public stage / trust / disposition / effect certaintyは12章integerをexact保存します。Positive evidenceだけを保持するため`disposition`と`effect_certainty`は**全legal shapeで常に0**です。非0はcorruptです。

Same-record closed snapshot matrixは次の3 legal shapeだけです。表外のkind/state/slot組合せはcorruptです。`L=max_evidence_per_target`（1..8）はcell内に無く、D1はslot上限としてglobal 1..8だけを要求します。exact `slot<=L`、同primaryの`L+1` cardinality、slot連続性はD3です。

| # | cell_kind | cell_state | slot_index | 備考 |
| ---: | --- | --- | ---: | --- |
| 1 | SUMMARY (1) | MATERIALIZED (2) | 0 | admission時からphysical exact 1。SUMMARY+UNUSEDはillegal |
| 2 | RAW (2) | UNUSED (1) | 1..8 | admission時pre-materialize。RAW+slot0はillegal |
| 3 | RAW (2) | MATERIALIZED (2) | 1..8 | new materialが入ったraw detail |

**SUMMARY empty**（shape 1かつ`valid_material_count==0`）はidentity（`evidence_owner_kind` / `owner_key_raw` / `primary_key_digest` / `target_digest` / `slot_index=0` / `cell_kind=SUMMARY` / `cell_state=MATERIALIZED`）以外zeroです。issuer PARTY 100 bytes zero、`service_slot` 240 zero、全stage 0、`late_material` 0、content/generation/sequence/time/trust/digest/length/bytes/4 counters/`counter_saturated`はzeroです。

**SUMMARY material**（shape 1かつ`valid_material_count>=1`）は次をexactとします。

- `highest_receipt_stage == latest_evidence_stage == material_receipt_stage`かつ三者ともknown stage `1..4`（NONE=0不可）。13章どおりpublic latestはmonotonic highestと常に一致します。
- `late_material`はaggregate `late_evidence_present`として`late_material == (late_evidence_count > 0)`のexact 0/1です。
- issuerはvalid PARTY、`service_slot`は上記material encoding、`content_digest` non-zero、`durable_ingress_sequence` non-zeroです。
- `generation`は`service.family==EventFact`ならexact 0、`DesiredState`なら1以上です（service自己申告とのsame-record結合。live owner family一致はD3）。
- evidence time triple（`evidence_clock_epoch` / `evidence_at_ms` / `evidence_trust`）は**issuer `evidence_time`だけ**です。epoch non-zero、`evidence_trust`は1 TRUSTEDまたは2 UNCERTAIN、`evidence_at_ms==0`はvalid monotonic sampleとして許します。Controller durable ingress timeはEVIDENCE_CELLへ保存せず、§8.3 ORDERED_INGRESSの`controller_ingress_*`だけがreduction完了までのdurable sourceです。
- `evidence_length`は0..128、`[length,128)`はzero、`evidence_digest = SHA-256(evidence_bytes[0,length))`です。length 0でもempty hash（nonzero）であり、zero digestと同一視しません。
- 4 countersはSUMMARYだけが保持します。`raw_overflow_count <= valid_material_count`、`late_evidence_count <= valid_material_count`、`exact_duplicate_count > 0`なら`valid_material_count >= 1`です。`counter_saturated`はu32 exact 0/1で、0なら4 countersすべて`< UINT64_MAX`、1なら少なくとも1つが`UINT64_MAX`です。

**RAW UNUSED**（shape 2）はidentity以外zeroです（SUMMARY emptyと同じempty material encoding。4 countersと`counter_saturated`もzero）。

**RAW MATERIALIZED**（shape 3）はexact material tupleを保持し、SUMMARY aggregate fieldは持ちません。

- `highest_receipt_stage` / `latest_evidence_stage`は0、`material_receipt_stage`はknown `1..4`です。
- `late_material`は当該materialのlate bit exact 0/1です（aggregate countはSUMMARY側）。
- issuer/service/content/generation/sequence/time/trust/length/bytes/digest規則はSUMMARY materialと同型です。
- 4 countersと`counter_saturated`は常に0です。

D1 same-recordはtransition history、lower-stage非巻き戻しの時系列、duplicate判定の適用結果そのものは証明しません。snapshot閉包（matrix / zero関係 / digest再計算 / counter coherence / family-generation）だけを要求します。

Live primary PVD、live TARGET→`target_digest`、exact `L`と`L+1` cardinality / slot連続性、`valid_material_count = M + raw_overflow`（`M`=同primaryのRAW MATERIALIZED数）、owner family/content/required_evidence/supported mask、STATE.`latest_evidence` / `has_late_evidence`投影、RESULT_CACHE.`evidence_cell_key_digest`、EVIDENCE used=`1+M` / reserved=`L-M`、admission journal headroom、CANCEL_FIRSTでEVIDENCE_CELL 0、deadline proof、retention eraseはD3へ残します。

B3gはbody length 734/798、`service_slot` 240固定、owner/raw/primary_key_digest/primary_id、closed matrix 3行、SUMMARY stage三者一致、disp/effect常0、late_material coherence、evidence_digest再計算、counter coherence、family-generation、flags 0 / revision>=1 / head・PVD non-zeroまでを証明します。上列D3項目およびD2/D4はB3g非範囲です。B3g implementationは§8.3の**D1-B3b retrofit**（ORDERED_INGRESS `controller_ingress_*` 32-byte blockとsemantic digest非包含）完了を前提とし、retrofit前B3b wire/vectorと混在させません。

- `CANCEL_STATE`: `cancel_owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + transaction_id[16] + cancel_attempt_id[16] + cancel_state:u32 + cancel_kind:u32 + reason:u32 + effect_certainty:u32 + cancel_send_gate_state:u32 + message_semantic_digest[32] + timeout_clock_epoch[16] + timeout_at_ms:u64`。TRANSACTION ownerはController cancel、DELIVERY ownerはEndpoint cancel tombstoneです。Gate lifecycleはpre-sendのNEVER_INVOKED/WOULD_BLOCK_RETRYABLEからINVOKED_CLOSEDへ進み、definite WOULD_BLOCK観測時だけINVOKED_CLOSEDからWOULD_BLOCK_RETRYABLEへ戻せる。その他のINVOKED_CLOSEDはcrash/restart/timeoutでも再open不可でremote cancelを再送しません。

CANCEL_STATEのsame-record wire / identity contractは次をexactとします。Body lengthは`146 + owner_key_raw contents`で、TRANSACTION raw exact 16なら162、DELIVERY raw exact 80なら226だけを許します（max 512はsubtype上限で不変）。`cancel_owner_kind`はCANCEL固有enumの1 TRANSACTIONまたは2 DELIVERYで、reservation/scheduler/BLOB/ATTEMPT enumを流用しません。TRANSACTION rawはbody `transaction_id`と同じnon-zero 16 bytes、DELIVERY rawは`delivery_key_raw` contents exact 80 bytesで、そのtransaction ID component `[32,48)`はbody `transaction_id`と一致します。`primary_key_digest`は順にTRANSACTION_ANCHOR ID128 / DELIVERY composite complete keyのKEY_DIGESTです。Key identityは`COMPOSITE(33, cancel_owner_kind:u16 || owner_key_raw:RAW16)`、common primary IDはtransaction IDまたはDELIVERY composite identity先頭16です。`primary_key_digest` / `transaction_id`は常にnon-zero、`reserved=0`、common flagsは0、mutable `record_revision>=1`、head witness digest / primary value digestはnon-zeroです。

Public result tupleとprivate stateのbijectionはclosedです。`cancel_state`→`(cancel_kind, reason, effect_certainty)`は次のexact 4行だけで、表外pairおよび`cancel_kind=ALREADY_TERMINAL(4)`のstoreはcorruptです。

| cancel_state | cancel_kind | reason | effect_certainty |
| --- | ---: | ---: | ---: |
| 1 NONE | 0 | 0 | 0 |
| 2 PENDING_REMOTE_FENCE | 2 | 86 `CANCEL_PENDING_REMOTE_FENCE` | 0 `NONE` |
| 3 FENCED_BEFORE_DISPATCH | 1 | 82 `CANCEL_FENCED_BEFORE_DISPATCH` | 1 `NO_EFFECT_PROVEN` |
| 4 TOO_LATE_EFFECT_POSSIBLE | 3 | 83 `CANCEL_AFTER_EFFECT_POSSIBLE` | 2 `POSSIBLE` |

`cancel_attempt_id`と`message_semantic_digest`はboth-zeroまたはboth-non-zeroだけ（global attempt/digest pair）。Timeoutは`(epoch zero, at_ms 0)`または`(epoch non-zero, at_ms non-zero)`のexact 2形です。`cancel_send_gate_state`はexact 1 NEVER_INVOKED / 2 WOULD_BLOCK_RETRYABLE / 3 INVOKED_CLOSEDだけです。

Same-record closed snapshot matrixは次の7 legal shapeだけです。表外のowner/state/gate/attempt/digest/timeout組合せはcorruptです。D1はtransition historyを証明しません。したがってTX PENDING + gate CLOSED + timeout zeroはpre-send crash/denial/post-fireの合法snapshotです。

| # | owner | cancel_state | attempt/digest | gate | timeout |
| ---: | --- | --- | --- | --- | --- |
| 1 | TX or DLV | NONE | zero pair | NEVER_INVOKED | (0,0) |
| 2 | TX | PENDING_REMOTE_FENCE | non-zero pair | NEVER_INVOKED / WOULD_BLOCK_RETRYABLE / INVOKED_CLOSED | NEVER/RETRYABLE=(0,0); CLOSED=(0,0) or active exact pair |
| 3 | TX | FENCED_BEFORE_DISPATCH (local pre-dispatch) | zero pair | NEVER_INVOKED | (0,0) |
| 4 | TX | FENCED_BEFORE_DISPATCH (remote result) | non-zero pair | INVOKED_CLOSED | (0,0) |
| 5 | DLV | FENCED_BEFORE_DISPATCH | non-zero pair | NEVER_INVOKED | (0,0) |
| 6 | TX | TOO_LATE_EFFECT_POSSIBLE | non-zero pair | INVOKED_CLOSED | (0,0) |
| 7 | DLV | TOO_LATE_EFFECT_POSSIBLE | non-zero pair | NEVER_INVOKED | (0,0) |

DELIVERY-owned PENDINGはillegal、DELIVERY gateは常にNEVER_INVOKEDです。Live primary PVD、live CANCEL ATTEMPT/index/cardinality、message semantic recompute、RESULT/REVERSE_REPLY、prior transition/gate history、timeout scheduling、family/owner/cardinality/reply proofsはD3へ残します。

B3fはbody length 162/226、owner/raw/primary_key_digest、bijection、closed matrix 7行、key COMPOSITE(33,…) / primary_id、flags 0 / revision>=1 / head・PVD non-zeroまでを証明します。上列D3項目およびD2/D4はB3f非範囲です。

- `ATTEMPT_ID_INDEX`: `attempt_id[16] + transaction_id[16] + attempt_kind:u16 + reserved:u16=0 + attempt_record_key_digest[32] + attempt_creation_value_digest[32]`。Roleを問わずlocal RuntimeがEntropyから生成したApplication/cancel attemptだけexact 1件作り、common primary digestはそのlocal-origin TRANSACTION_ANCHORです。Controller DesiredState attemptとEndpoint EventFact attemptを含み、Endpointが受信したremote Application/cancel echo attempt、reverse replyは作りません。Creation digestはATTEMPT CREATE manifestのnew digestとexact一致するimmutable collision provenanceで、後のATTEMPT replacementではindexを更新しません。Recoveryはcurrent ATTEMPT key/bodyのattempt/transaction/owner bindingを別途検査します。Global retained collision lookupはこのdirect ID128 keyを使い、index/ATTEMPT/anchorを同じwitness groupでcreateし、eraseはsection 11のfenced cleanupだけで行います。

ATTEMPT_ID_INDEXのsame-record wire contractは次をexactとします。Body lengthはexact 100です。`attempt_id` / `transaction_id` / `attempt_creation_value_digest`はnon-zero、`attempt_kind`はexact 1 COMMAND / 2 EVENT / 3 CANCEL（§8.3 ATTEMPTと同じ closed constants）、`reserved=0`です。`attempt_record_key_digest`はTRANSACTION-owned ATTEMPT complete keyのKEY_DIGESTとexact一致します。そのATTEMPT identityは`COMPOSITE(31, attempt_owner_kind:u16=TRANSACTION(1) || owner_key_raw:RAW16(contents=transaction_id exact 16) || attempt_id[16])`であり、bare composite digestそのものとのstore/compareは禁止です。Keyはdirect ID128でbody `attempt_id`と一致、common primary IDはbody `transaction_id`、common flagsは0、immutable `record_revision=1`、head witness digest / primary value digestはnon-zeroです。Indexはcreate-once immutableで、ATTEMPT replacementはcreation digestを更新せず、後のfenced cleanupがindex/ATTEMPTをpair-eraseします。D1 same-recordではcreation digest non-zeroだけを要求します。

B3eはbody固定100 / kind / reserved、attempt_record_key_digestのcomplete-key KEY_DIGEST再計算、key ID128↔attempt_id、primary_id↔transaction_id、revision=1 / flags=0 / head・PVD non-zeroまでを証明します。Live TRANSACTION_ANCHOR primary value digest一致、live/current ATTEMPT binding、CREATE manifest new digest equality（replacement後のcurrent ATTEMPT valueではない）、local ATTEMPT/index cardinality、DELIVERY/remote no-index、reverse reply no-index、co-create witness、fenced pair cleanup/fence counts、family-kindおよびCANCEL_STATE cross proofsはD3へ残します。CANCEL_STATE (`0x33`) はB3e非範囲です。

### 8.5 Delivery、result、reply

- `DELIVERY`: `delivery_key_raw:RAW16(max 128) + creation_kind:u16 + reserved:u16=0 + scheduler_owner_sequence:u64 + transaction_id[16] + event_id[16] + source:PARTY + local_target:TARGET + service:SERVICE_IDENTITY + content_digest[32] + generation:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + payload_blob_key_digest[32] + result_cache_key_digest[32] + reservation_key_digest[32]`。Attemptに依存しないimmutable logical binding anchorで、common revisionは1です。Logical keyは`source.runtime_id + source.application_instance_id + transaction_id + local_target.runtime_id + local_target.application_instance_id`だけで、attempt IDを含みません。同じkeyの全messageはevent ID/generation、service identity、content digest、deadline/evidence snapshotを含むbody bindingがexact一致しなければ同一Deliveryへmergeせずconflict/invalid ingressです。APPLICATION_FIRSTと先行CANCEL_REQUESTのCANCEL_FIRSTのどちらも同じcanonical key formulaを使い、同一keyのDELIVERYを2件作ることは禁止します。

DELIVERYのsame-record wire / identity contractは次をexactとします。

Body lengthは`498 + canonical SERVICE_IDENTITY encoded length`です（固定部498は`delivery_key_raw` contents exact 80 + RAW16 length prefix u16、`creation_kind` / `reserved`、`scheduler_owner_sequence`、`transaction_id` / `event_id`、PARTY exact 100、TARGET exact 100、`content_digest`、`generation`、deadline/evidence/required、3つのkey digestを含む）。`SERVICE_IDENTITY`が本章3節どおり54..240のときbodyは**552..738**だけを許します（max 1024はsubtype上限で不変）。Body trailing byteは禁止です。

`delivery_key_raw` contentsはexact 80 bytesで、本章5.1節の`source.runtime_id[16] || source.application_instance_id[16] || transaction_id[16] || local_target.runtime_id[16] || local_target.application_instance_id[16]`と一致します。5つの16-byte componentはすべてnon-zeroです。bodyの`source.runtime_id` / `source.application_instance_id`、`transaction_id`、`local_target`のruntime/application（本章3節TARGETの`target_runtime` / `target_application`）と上記rawはbijectionであり、いずれかの不一致、またはRAW16 lengthが80以外はcorruptです。

`creation_kind`は1 APPLICATION_FIRSTまたは2 CANCEL_FIRSTだけです。`reserved`はexact 0、`scheduler_owner_sequence`は1以上、`transaction_id` / `content_digest`はnon-zeroです。`source` / `local_target` / `service`は本章3節のvalid shape、`service.family`はEventFactまたはDesiredState、`required_evidence`はknown non-zeroです。SERVICEのsupported evidence maskとの照合、live SERVICEの`maximum_evidence_grace_ms`上限、およびadmission時刻からのabsolute deadline derivationはD3です。

EventFactはevent ID non-zero、generation 0、deadline epoch zero、deadline `NINLIL_NO_DEADLINE`、evidence grace 0です。DesiredStateはevent ID zero、generation 1以上、deadline epoch non-zero、`absolute_effect_deadline_ms != NINLIL_NO_DEADLINE`です。DesiredStateの`evidence_grace_ms`はD1 same-recordではu64として保存形以外を制限せず、ORDERED_INGRESSと同じく`absolute_effect_deadline_ms > 0`等の追加強化はしません。

CANCEL_FIRSTは12章どおり`CANCEL_REQUEST`がDesiredState限定であること、およびBearer messageがkindを問わずoriginal admissionのservice/content/generation/deadline/evidence snapshotをself-contained echoする規則を根拠に、DesiredStateだけを許しbodyへ同じfull bindingを保存します。EventFactとの組合せはcorruptです。CANCEL_FIRSTの`payload_blob_key_digest`はall-zeroです（8.4節のpayload manifest 0件と一致）。APPLICATION_FIRSTはfamilyを問わず`payload_blob_key_digest` non-zeroです（empty payloadでもownerがcount 0のmanifest exact 1件を持つ8.4節規則どおり）。`payload_blob_key_digest`のBLOB manifest key再計算は`total_length`等がbodyにないためD1 same-recordでは行いません（8.3節ORDERED_INGRESS / 8.4節BLOBと同じ境界）。live BLOB 0/1 cardinalityとmanifest/chunk一致はD3です。

`result_cache_key_digest`は`KEY_DIGEST(complete RESULT_CACHE key)`とexact一致します。そのkey identityは`COMPOSITE(41, delivery_key_raw:RAW16)`で、bodyの`delivery_key_raw` encodingと同一です。`reservation_key_digest`は`KEY_DIGEST(complete RESERVATION key)`とexact一致します。そのcomponentsは`owner_kind:u16=DELIVERY(4) || owner_key_raw:RAW16(contents=delivery_key_raw contents exact 80)`です。いずれもcomposite digest本体とのstore/compareは禁止です（本章5.1節）。

Key identityは`COMPOSITE(40, delivery_key_raw:RAW16)`、common primary IDはcomposite identity先頭16 bytesです。DELIVERYはimmutable primaryなのでcommon revisionは1、flags 0、primary value digest zero、head witness digest non-zeroです。

**D1-B3h境界**: B3hはDELIVERY (`0x40`) pure body encode/decodeと本same-record閉包だけです。RESULT_CACHE (`0x41`) body/state matrixは次sliceでありB3h非範囲です。Live RESULT_CACHE exact 1とdelivery_state/token/reply、SCHEDULER_OWNER / DELIVERY RESERVATION live cardinality、APPLICATION/CANCEL ATTEMPT、EVIDENCE_CELL `L+1`またはCANCEL_FIRSTでの0、CANCEL_STATE、payload BLOB live、ORDERED_INGRESS eraseとadmission witness、後着APPLICATION attach / binding conflict、public ABSENT projection、supported evidence mask、evidence graceのlive SERVICE上限、deadline proof、retention/cleanupはD3および`DSD1_LOGICAL_DELIVERY`へ残します。

- `RESULT_CACHE`: `delivery_key_raw:RAW16(max 128) + delivery_key_digest[32] + transaction_id[16] + delivery_count:u64 + application_seen:u32 + application_attempt_count:u32 + delivery_state:u32 + reply_count:u32 + token_context_id[16] + token_generation:u64 + token_clock_epoch[16] + token_expires_at_ms:u64 + delivery_started_clock_epoch[16] + delivery_started_at_ms:u64 + completion_expires_at_ms:u64 + callback_invocations:u64 + reconcile_invocation_count:u64 + reconcile_retry_generation:u64 + reconcile_not_before_clock_epoch[16] + reconcile_not_before_ms:u64 + application_result_kind:u32 + evidence_stage:u32 + disposition:u32 + reason:u32 + effect_certainty:u32 + retry_guidance:u32 + retry_delay_ms:u64 + evidence_cell_key_digest[32] + token_state:u32 + cancel_result_kind:u32 + completed_clock_epoch[16] + completed_at_ms:u64`。

RESULT_CACHEのsame-record wire / identity / closed shape contractは次をexactとします。

Body lengthは`296 + delivery_key_raw contents`で、contents exact 80のときRAW16 length prefix u16を含む`delivery_key_raw` encodingはexact 82 bytes、**body exact 378**だけを許します（max 1024はsubtype上限で不変）。Body trailing byteは禁止です。

`delivery_key_raw` contentsはDELIVERYと同じexact 80 bytes（`source.runtime_id[16] || source.application_instance_id[16] || transaction_id[16] || local_target.runtime_id[16] || local_target.application_instance_id[16]`）で、5つの16-byte componentはすべてnon-zeroです。body `transaction_id`はraw component `[32,48)`とbijectionかつnon-zeroです。RAW16 lengthが80以外、またはcomponent/transaction不一致はcorruptです。

`delivery_key_digest`は`KEY_DIGEST(complete DELIVERY key)`とexact一致します。そのkey identityは`COMPOSITE(40, delivery_key_raw:RAW16)`で、bodyの`delivery_key_raw` encodingと同一です。composite digest本体とのstore/compareは禁止です（§5.1）。

Key identityは`COMPOSITE(41, delivery_key_raw:RAW16)`、common primary IDはDELIVERY composite identity先頭16 bytesです。RESULT_CACHEはmutable secondaryなのでcommon flagsは0、`record_revision>=1`（late/duplicate/saturating updateはMAX維持可）、head witness digestはnon-zero、primary value digestはnon-zeroです（live DELIVERY complete value一致はD3）。

#### Counter identity（delivery_count / callback_invocations / token_generation）

常に`delivery_count = callback_invocations = token_generation`（以下`N`）です。`N`は当該Deliveryにおける**actual `on_delivery` callback開始回数**のdurable counterです（metrics `application_callback_invocations` とは別）。public `delivery_view.delivery_count`およびactive tokenの`generation`は同一`N`を写します。

- **DELIVERY_START FULL commitだけ**が3値を同一post値へchecked +1し、そのpost値を発行tokenの`token_generation`へ保存します（1始まり。初回成功STARTのpostは`N=1`）。
- REDELIVER、KNOWN_RESULT、RETRY_LATER、OUTCOME_UNKNOWN、cancel tombstone、duplicate attempt観測は`N`を増やしません。
- `N=UINT64_MAX`のsnapshotはlegalです。**DELIVERY_STARTの`N+1`不能は必ず prior `N=MAX` かつ既存retained tombstone**（例: REDELIVER後INBOX）から callback 0のまま`delivery_state=RECOVERY_REQUIRED`・E_REC(`COUNTER_EXHAUSTED`)へFULL commitします。`N=0`からのSTART不能や`N>0`+NONE、`N=MAX`+NONEは到達不能/corruptです。
- `token_generation` field値は常にcounter `N`です。NONEは`N=0`のみ。ACTIVE/retained tombstoneではgeneration=`N≥1`です。REDELIVER後INBOXは`N≥1`かつretained tombstoneのgeneration=`N`を許します（次STARTが`N+1`のACTIVEへ上書き）。

#### Orthogonal closed shapes

**A origin**

| ID | application_seen | application_attempt_count | evidence_cell_key_digest | 備考 |
| --- | ---: | ---: | --- | --- |
| A_APP | 1 | ≥1 | non-zero。`KEY_DIGEST(complete EVIDENCE_CELL key)`、identity `COMPOSITE(32, evidence_owner_kind:u16=DELIVERY(2) \|\| owner_key_raw:RAW16(contents=delivery_key_raw contents exact 80) \|\| slot_index:u32=0)` とsame-record exact | APPLICATION_FIRST。live SUMMARY cell存在/cardinalityはD3 |
| A_CANCEL | 0 | 0 | all-zero | CANCEL_FIRST。`N=0`必須 |

APPLICATION_FIRSTへのexact-binding duplicateでnew remote attempt IDを初めて観測した場合はDELIVERY-owned ATTEMPTを追加し`application_attempt_count`だけをchecked incrementし、`N`/inbox/callback/effectを変更しません。CANCEL_FIRSTへ後着APPLICATIONが来ても13章の`ABSENT + cancel tombstone`を維持し、DELIVERY/RESULT/ATTEMPTを変更せず、`application_seen`/`N`を進めません。

**B counter**: 上節の`N`。B0は`N=0`、B_Nは`1..UINT64_MAX`。

**C token_state field matrix**（timer 5-tuple = `token_clock_epoch` / `token_expires_at_ms` / `delivery_started_clock_epoch` / `delivery_started_at_ms` / `completion_expires_at_ms`）

ACTIVE / CONSUMED / EXPIRED / RECOVERY_REQUIRED_TOMBSTONE の **legal timer 5-tuple**（same-record closed）:

1. `token_clock_epoch` **non-zero**
2. `delivery_started_clock_epoch` **non-zero** かつ **`token_clock_epoch` と exact 一致**
3. `delivery_started_at_ms` は **任意 u64（0 可）**。trusted clock `now_ms=0` は legal であり、これを started_at に写してよい
4. `completion_expires_at_ms` **non-zero** かつ **`completion_expires_at_ms > delivery_started_at_ms`**（same-record closed。`==` / `<` は corrupt）
5. `token_expires_at_ms` **non-zero** かつ **`completion_expires_at_ms` と exact 一致**

`completion_expires_at_ms = checked(delivery_started_at_ms + application_completion_timeout_ms)` かつ descriptor 上 `application_completion_timeout_ms ≥ 1` のため、`delivery_started_at_ms=0` でも expiry は non-zero かつ strictly greater than started。checked addition overflow / clock uncertain / non-zero epoch 不可では **token 発行前に fail**（callback 0、ACTIVE shape を作らない）。

| token_state | value | token_context_id | token_generation | timer 5-tuple |
| --- | ---: | --- | ---: | --- |
| NONE | 1 | all-zero | **exact 0 かつ `N=0`** | **all-zero**（5 field すべて zero） |
| ACTIVE | 2 | =`transaction_id` non-zero | =`N`≥1 | 上列 legal 5-tuple（ACTIVE 発行時の値） |
| CONSUMED | 3 | =`transaction_id` | =`N`≥1 | **retained** = ACTIVE 時の 5-tuple を保持（zero-out 禁止。`delivery_started_at_ms=0` の retain 可） |
| EXPIRED | 4 | =`transaction_id` | =`N`≥1 | **retained** = 上と同じ |
| RECOVERY_REQUIRED_TOMBSTONE | 5 | =`transaction_id` | =`N`≥1 | **retained** = 上と同じ |

「timer retained non-zero」は epoch / expires 対の non-zero と bijection を指し、**`delivery_started_at_ms` の non-zero を要求しない**。

`token_state=NONE`は`token_context_id` all-zero、`token_generation=0`、`N=0`、timer all-zero **だけ**です。**`N>0` + NONE は corrupt**。`N≥1`では token_state ∈ {ACTIVE, CONSUMED, EXPIRED, RECOVERY_REQUIRED_TOMBSTONE} 必須です。**`N=0` + tombstone も corrupt**です。

CONSUMED / EXPIRED / RECOVERY_REQUIRED_TOMBSTONE はresult-cache retention中のtoken tombstoneです。retention中のstale/late `delivery_complete`（known context・非ACTIVE）は`NINLIL_E_INVALID_STATE`、cleanup後record不在は`NINLIL_E_NOT_FOUND`です（12/13章と同一）。

**D reconcile**（`I=reconcile_invocation_count`、`G=reconcile_retry_generation`、not-before pair = epoch/ms）

`I`は**actual `on_reconcile` function entry回数**のdurable counterです（metrics `reconcile_invocations` と同趣旨の per-delivery durable 値）。`G`はreconcile retry generationです。witness kind 11 identityが`reconcile_retry_generation`と`post_reconcile_invocation_count`を含むことと一致します。

**Same-record 共通不変条件（recovery/reconcile履歴あり）**: 常に **`G≥1`、`I≥0`、`G ≤ I+1`**（`I>G` は合法）。**`G=I+1` は必須ではない**（同G crashで`I`が増えた後に`G+1`しても`G=I+1`に戻らない／超えない範囲に留まるだけ）。

same-record factor で G/I 算術だけから「未claim / claim済み」を区別してはなりません（actual claim済みは witness/scheduler history の **D3**）。

| ID | G | I | not-before | 意味 / physical state 割当 |
| --- | ---: | ---: | --- | --- |
| D_IDLE | 0 | 0 | (0,0) | 未recovery履歴 |
| D_OPEN | ≥1、`G≤I+1` | ≥0 | **(0,0)** | state **6** RECOVERY_REQUIRED。初回episode直後は`G=1,I=0`のみ。claim済みか否かはsame-record非区別 |
| D_WAIT | ≥1、`G≤I+1` | ≥0 | **both non-zero** | state **7** RECONCILE_WAIT |
| D_HELD | ≥1、**`I≥G`** | ≥1 | (0,0) | state **1/4/5** で reconcile episode 終了後の履歴（REDELIVER後INBOX、KNOWN/OUTCOME terminal）。成功actionを返したclaimあり |

Reconcile lifecycle（same-record + 13章）:

1. 当該Deliveryで**初めて**`delivery_state=RECOVERY_REQUIRED`へ入るFULL commit: `G=0→1`、`I=0`、not-before zero → **D_OPEN**（初回のみ `G=1,I=0`）。
2. 独立した新しいrecovery episode（直前がD_HELD）へ再入するFULL commit: `G=checked(G+1)`、`I`維持、not-before zero → **D_OPEN**。postは引き続き`G≤I+1`（過去crashで`I`が大きいと post で `I≥G` もあり得る）。G+1不能ならcallback/timer 0、`COUNTER_EXHAUSTED`でRECOVERYに留める。G/Iを0へresetしない。
3. **reconcile callback claim**（actual `on_reconcile` entry直前）のFULL commit: `G`維持、`I=checked(I+1)`（不能ならcallback 0、`COUNTER_EXHAUSTED`）、state/timer は D_OPEN のまま。kind 11 identityはpost-`I`。
4. **同じlogical claimのCOMMIT_UNKNOWN retry**だけ、同じpost-`I` identityを再利用する。**authoritative claim commit後**のactual再callbackは**別claim**として新しいpost-`I`へchecked +1（同Gで`I>G`になり得る）。
5. RETRY_LATER成功FULL commit: `G=checked(G+1)`、`I`維持、not-before atomic → **D_WAIT**。postは`G≤I+1`（`G=I+1`断定禁止）。G+1不能またはnot-before導出不能ならtimer/callback 0・state RECOVERY・`COUNTER_EXHAUSTED`またはclock fail-closed。
6. RECONCILE_DUE: not-beforeをzeroにし **D_OPEN**（G/I不変、`G≤I+1`維持）。
7. KNOWN_RESULT / OUTCOME_UNKNOWN / REDELIVER成功: active reconcile timerだけzeroにし**D_HELD**（成功actionを返したclaimがあるため post で `I≥G`、G/I保持）。

表外の`(G,I,not-before)`はcorruptです。とくに`G=0`かつ`I≠0`、`G > I+1`、D_WAITでnot-before zero、D_OPEN/D_HELDでnot-before non-zero、D_HELDで`I<G`はcorruptです。

**E result tuple**

| ID | application_result_kind | evidence_stage | disposition | reason | effect_certainty | retry_guidance / retry_delay_ms | completed_* |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| E_ZERO | 0 | 0 | 0 | 0 | 0 | NEVER / 0 | (0,0) |
| E_POS | 1 POSITIVE_EVIDENCE | 12章supported non-zero stage | NONE | NONE | NONE | NEVER / 0 | both non-zero |
| E_DISP | 2 DISPOSITION | NONE | known non-zero | 12章Disposition exact matrix | matrix | matrix | both non-zero |
| E_REC | 0 | 0 | 0 | exact 1 of `APPLICATION_FAILED` / `CALLBACK_CONTRACT` / `COUNTER_EXHAUSTED` / `APPLICATION_COMPLETION_TIMEOUT` / **`OUTCOME_UNKNOWN`** | **POSSIBLE** | 12章reason registryのdefault guidance / **delay 0** | **(0,0) 必須**（nonterminal） |

E_POS/E_DISP以外でcompleted non-zero、E_RECでcompleted non-zero、E_ZEROでnon-zero semantic field、E_REC reason表外はcorruptです。**`CLOCK_UNCERTAIN` / `STORAGE_COMMIT_UNKNOWN` を E_REC reason として RESULT へ保存してはなりません**（前者はCLOCK_FENCE health、後者はStorage fence；いずれも business reason 軸と分離）。

**E_REC reason × token_state 到達割当（same-record / transition 正本）**:

| 到達 | post token_state | E_REC reason | op kind/phase（§10） |
| --- | --- | --- | --- |
| actual completion / DEFER token timeout | EXPIRED | APPLICATION_COMPLETION_TIMEOUT | kind **10 phase 2** |
| controlled destroy active-token group | EXPIRED | OUTCOME_UNKNOWN | kind **19** |
| restart / create recovery が旧process ACTIVE を回収 | EXPIRED | OUTCOME_UNKNOWN | kind **21** |
| clock epoch mismatch が ACTIVE token を回収 | EXPIRED | OUTCOME_UNKNOWN | kind **21**（CLOCK_UNCERTAIN は RESULT に書かず old timer 由来 **CLOCK_FENCE** health） |
| CALLBACK_FATAL | RECOVERY_REQUIRED_TOMBSTONE | APPLICATION_FAILED | kind **11 phase 3** |
| callback unknown/invalid COMPLETE | RECOVERY_REQUIRED_TOMBSTONE | CALLBACK_CONTRACT | kind **11 phase 3** |
| effect後result不明（storage fence 解決後 authoritative が unknown-effect へ収束） | RECOVERY_REQUIRED_TOMBSTONE（既 tombstone 維持可）。ACTIVE 回収なら EXPIRED | OUTCOME_UNKNOWN | kind **11** または authoritative recovery |
| DELIVERY_START `N+1` 不能 | **existing retained tombstone 維持**（NONE 禁止） | COUNTER_EXHAUSTED | kind **9 phase 2** |
| raw Storage COMMIT_UNKNOWN 中 | **RESULT 推測 mutation 0** | 不変 | fence 解決後 all-or-none で該当 path のみ |
| unknown reconcile action / invalid KNOWN_RESULT | tombstone identity/timers/`N` **維持**（prior が EXPIRED / CONSUMED / RECOVERY_REQUIRED_TOMBSTONE のいずれでも保持） | **CALLBACK_CONTRACT へ置換**（health prio3 成立） | kind **11 phase 2/3**。valid terminal reconcile で source clear |

same-record では「direct invalid COMPLETE」と「unknown reconcile 後の CALLBACK_CONTRACT 置換」を履歴で区別できない。したがって physical state 6/7 で `reason=CALLBACK_CONTRACT` のとき token_state は retained tombstone ∈ {**CONSUMED, EXPIRED, RECOVERY_REQUIRED_TOMBSTONE**} を許す（`APPLICATION_FAILED` は RECOVERY_REQUIRED_TOMBSTONE のみ、`APPLICATION_COMPLETION_TIMEOUT` は EXPIRED のみ、`OUTCOME_UNKNOWN` は EXPIRED または RECOVERY_REQUIRED_TOMBSTONE、`COUNTER_EXHAUSTED` は `N=MAX` かつ retained のいずれか）。

**F cancel_result_kind**（delivery_stateと直交）

| ID | cancel_result_kind | 条件 |
| --- | ---: | --- |
| F_NONE | 0 | cancel未記録 |
| F_FENCED | 1 `FENCED_BEFORE_DISPATCH` | **never-startedのみ**: `N=0`かつ`token_state=NONE`かつ physical state∈{**1,8**}。**state 5 では禁止** |
| F_LATE | 3 `TOO_LATE_EFFECT_POSSIBLE` | 1回でもDELIVERY_START成功（`N≥1`）またはeffect possibility / result / recovery / active-or-tombstone tokenを記録済み。state5到着後のREMOTE_CANCELもF_LATE |

F_FENCEDと`N≥1`の同時、F_FENCEDとstate∉{1,8}、F_LATEとstate 8、表外kind（2/4等）はcorruptです。

**G completed time**: E_POS/E_DISPだけboth non-zero。state 4/5以外でnon-zeroはcorrupt。state 6/7は必ず(0,0)。

**reply_count**: exact 0..4。kindごと最大1のlive cardinalityとcanonical reply key規則はREVERSE_REPLY / D3。same-recordは範囲のみ。

#### Physical delivery_state × legal shape product

表外直積はcorruptです。DEFERRED_WAITはpublic/in-memory projection名であり、physical `delivery_state`値としては現れません（§7.1）。

| physical delivery_state | A | N / token | D | E | F | completed |
| --- | --- | --- | --- | --- | --- | --- |
| 1 INBOX_COMMITTED | A_APP | (a) virgin: `N=0` + NONE + D_IDLE + E_ZERO、(b) REDELIVER後: `N≥1` + tombstone∈{CONSUMED,EXPIRED,RECOVERY_REQUIRED_TOMBSTONE} + **D_HELD** + E_ZERO | 上列 | E_ZERO | (a) F_NONEまたはF_FENCED、(b) F_NONEまたはF_LATE | (0,0) |
| 2 DELIVERY_STARTED | A_APP | `N≥1` + ACTIVE | D_IDLE（未recovery）またはD_HELD（prior episode履歴） | E_ZERO | F_NONEまたはF_LATE | (0,0) |
| 4 RESULT_COMMITTED | A_APP | `N≥1` + CONSUMED | D_IDLEまたはD_HELD | E_POS | F_NONEまたはF_LATE | G1 |
| 5 DISPOSITION_COMMITTED | A_APP | (a) pre-callback: `N=0` + NONE + D_IDLE + E_DISP + **F_NONEのみ**、(b) post-callback/reconcile terminal: `N≥1` + CONSUMED + D_IDLEまたはD_HELD + E_DISP + F_NONEまたはF_LATE | 上列 | E_DISP | 上列 | G1 |
| 6 RECOVERY_REQUIRED | A_APP | (a) DELIVERY_START `N+1`不能: **`N=MAX` + retained tombstone** + E_REC(`COUNTER_EXHAUSTED`)、(b) その他: `N≥1` + E_REC reason ごとの token_state 割当（上表。特に **CALLBACK_CONTRACT は retained ∈{CONSUMED,EXPIRED,RECOVERY_REQUIRED_TOMBSTONE}**） | **D_OPEN** | E_REC | F_NONEまたはF_LATE | (0,0) |
| 7 RECONCILE_WAIT | A_APP | `N≥1` + tombstone∈{EXPIRED,RECOVERY_REQUIRED_TOMBSTONE,CONSUMED} | **D_WAIT** | E_REC | F_NONEまたはF_LATE | (0,0) |
| 8 CANCEL_TOMBSTONE_ONLY | A_CANCEL | `N=0` + NONE | D_IDLE | E_ZERO | F_FENCED | (0,0) |

禁止 cross product（corrupt）: `N>0`+NONE、`N=0`+tombstone、`N=MAX`+NONE、state5 pre-callback + F_FENCED、state6 + D_WAIT/D_HELD、state7 + D_OPEN。

#### Token invalidation → token_state / E_REC 割当

| 原因 | post token_state | E_REC reason |
| --- | --- | --- |
| CALLBACK_COMPLETE成功（POSITIVE/DISPOSITION）またはOUTCOME_UNKNOWN terminal（state5） | CONSUMED | n/a（E_POS/E_DISP） |
| actual completion / DEFER token timeout（kind10 phase2） | EXPIRED | APPLICATION_COMPLETION_TIMEOUT |
| controlled destroy kind19 ACTIVE group | EXPIRED | OUTCOME_UNKNOWN |
| restart/create が旧process ACTIVE を kind21 回収 | EXPIRED | OUTCOME_UNKNOWN |
| clock epoch mismatch が ACTIVE を kind21 回収 | EXPIRED | OUTCOME_UNKNOWN（CLOCK は health のみ） |
| CALLBACK_FATAL | RECOVERY_REQUIRED_TOMBSTONE | APPLICATION_FAILED |
| callback unknown/invalid COMPLETE | RECOVERY_REQUIRED_TOMBSTONE | CALLBACK_CONTRACT |
| effect後result不明（authoritative 収束後） | RECOVERY_REQUIRED_TOMBSTONE（または ACTIVE 回収なら EXPIRED） | OUTCOME_UNKNOWN |
| DELIVERY_START N+1 不能（kind9 phase2） | existing retained tombstone 維持 | COUNTER_EXHAUSTED |
| unknown reconcile / invalid KNOWN_RESULT | tombstone identity/timers/`N` 維持 | **CALLBACK_CONTRACT へ置換** |
| KNOWN_RESULT terminal | CONSUMED | n/a |
| REDELIVER | 既存tombstone保持、state→1、E→E_ZERO、`N`不変 | n/a |
| raw COMMIT_UNKNOWN 中 | mutation 0 | 不変 |

#### 初期形と主要transition（writer正本の要約；詳細reducerは13章）

| Transition | post physical RESULT要点 |
| --- | --- |
| APPLICATION_FIRST admit | state1、A_APP、`N=0`、NONE、D_IDLE、E_ZERO、F_NONE、completed0、attempt≥1、evidence digest formula |
| CANCEL_FIRST admit | state8、A_CANCEL、`N=0`、NONE、D_IDLE、E_ZERO、F_FENCED、completed0、evidence0 |
| pre-callback ABSENT/INBOX→DISPOSITION terminal | A_APP、state5、`N=0`、NONE、E_DISP、**F_NONE**、G1、attempt≥1（F_FENCED禁止） |
| DELIVERY_START success（kind9 phase1） | state2、`N=checked(N+1)`、ACTIVE、E_ZERO |
| DELIVERY_START N+1不能（kind9 phase2） | state6、`N=MAX`+tombstone維持、E_REC(`COUNTER_EXHAUSTED`)、callback/token claim 0 |
| CALLBACK_DEFER | **追加FULL writeなし**。physicalはstate2+ACTIVEのまま。DEFERRED_WAITは in-memory/public projection のみ |
| complete success（kind10 phase1） | state4または5、CONSUMED、E_POSまたはE_DISP、G1 |
| token timeout（kind10 phase2） | state6、EXPIRED、E_REC(`APPLICATION_COMPLETION_TIMEOUT`)、D_OPEN |
| destroy/restart/clock ACTIVE回収 | state6、EXPIRED、E_REC(`OUTCOME_UNKNOWN`)、D_OPEN |
| FATAL/contract | state6、RECOVERY_REQUIRED_TOMBSTONE、E_REC(APPLICATION_FAILED/CALLBACK_CONTRACT)、D_OPEN |
| unknown reconcile | state6維持、E_REC→CALLBACK_CONTRACT 置換、tombstone/`N`維持 |
| REDELIVER | state1、`N`/tombstone/D_HELD保持、**E_ZERO** |
| RETRY_LATER | state7、D_WAIT |
| never-started REMOTE_CANCEL | F_FENCED（state 1または8のみ） |
| ever-startedまたはstate5到着後 REMOTE_CANCEL | F_LATE |

**D1-B3i境界**: B3iはRESULT_CACHE (`0x41`) pure body encode/decodeと本same-record閉包だけです。REVERSE_REPLY body、live DELIVERY PVD/exact1、live reply_count一致、APPLICATION ATTEMPT cardinality、live EVIDENCE_CELL存在、CANCEL_STATE live kind一致、attach/binding conflict、public ABSENT projection、retention/cleanup、SCHEDULER/RESERVATIONはD3および`DSD1_LOGICAL_DELIVERY`へ残します。

- `REVERSE_REPLY`: `reply_key_raw:RAW16(max 192) + delivery_key_raw:RAW16(max 128) + transaction_id[16] + reply_kind:u32 + semantic_digest[32] + body_blob_key_digest[32] + send_state:u32 + send_operation_generation:u64 + send_invocation_count:u64 + send_counter_exhausted:u32 + reserved:u32=0 + attempt_id[16] + availability_epoch:u64 + retry_clock_epoch[16] + retry_not_before_ms:u64`。Legal bodyは**exact 330 bytes**です。`delivery_key_raw` contentsは5個のnon-zero IDから成るexact 80 bytes、body上のRAW16 encodingは82 bytesです。`reply_key_raw` contentsはその82 bytesとbyte-identicalな`delivery_key_raw:RAW16 || reply_kind:u32`のexact 86 bytes、body上のRAW16 encodingは88 bytesです。Body `transaction_id`はdelivery contents `[32,48)`、body `reply_kind`はreply raw末尾u32とexact一致します。Keyはbody rawから再計算した`COMPOSITE(42, reply_key_raw:RAW16)`、common primary IDは`COMPOSITE(40, delivery_key_raw:RAW16)`先頭16 bytes、common flagsは0、record revisionは1以上、head witness digest / primary value digestはnon-zeroです。Common primary value digestはDELIVERY complete valueとD3で照合します。

`reply_kind`は1 RECEIPT、2 DISPOSITION、3 CUSTODY、4 CANCEL_RESULTだけです。`attempt_id` / `semantic_digest` / `body_blob_key_digest`は全kind・全stateでnon-zero、reservedは0です。D1はsemantic digestをbodyだけから再計算せず、D3がDELIVERYのreverse source/target、service/content/deadline binding、RESULT/CANCEL field、REPLY evidence BLOBをstreamして12章5.4のexact Bearer messageを再構成し一致を証明します。Replyはinline opaque bytesを持ちません。

`send_invocation_count` (`I`) はactual call総数ではなくBearer return observationをdurably commitした回数、`send_operation_generation` (`G`) はTxGate TEMPORARY/DENIED/contract no-sendまたはBearer returnという各send micro-operation final observation commitごとのdurable ordinalです。各final observationはGをchecked +1し、Bearer return variantだけIもchecked +1します。常に`I <= G`です。`send_counter_exhausted`はu32 exact 0/1で、1 iff GまたはIが`UINT64_MAX`、かつ1 iff state 5です。MAX到達とflag/state5/timer clear/BLOB eraseは同じkind 6 witness groupで行い、state5はabsorbingです。

`availability_epoch`は本replyで最後にdurably観測したusable Bearer return epochの累積snapshotです。全stateで`I == 0` iff availability 0、`I > 0` iff availability non-zeroです。TxGate observationとduplicate reopenはI/availabilityを変更しません。Actual Bearer call前には12章5.4どおりnon-zero durable namespace Bearer stateを`fallback_epoch`へ固定します。Usable returnはclosed shapeを満たし、returned epochがfallbackおよびprior reply epoch以上（equal可）です。Usableならreturned epochを保存します。Zero/shape違反/unknown/regressed returnはpossible-delivery contract fenceとしてG/Iを進め、availabilityへ同じBearer domainの`max(fallback_epoch, prior reply epoch)`を保存してstate 3へ閉じます。Call済みinvalid observationを握りつぶしてPENDINGへ残さず、synthetic epochを作りません。

Retry timerは`(epoch all-zero, not-before 0)`または`(epoch non-zero, not-before non-zero)`のexact 2形です。次のclosed matrix以外はcorruptです。`not MAX`はG/Iとも`UINT64_MAX`未満を意味します。

| send state | G | I / availability | exhausted | retry timer |
| --- | --- | --- | ---: | --- |
| 1 PENDING virgin | 0 | I=0 / availability=0 | 0 | zero pair |
| 1 PENDING reopened | 1以上、not MAX | Iは0..G / availabilityはIとのexact coupling | 0 | zero pair |
| 2 WAITING_RETRY | 1以上、not MAX | Iは0..G / availabilityはIとのexact coupling | 0 | non-zero pair |
| 3 CLOSED_SENT_OR_UNKNOWN | 1以上、not MAX | Iは1..G / availability non-zero | 0 | zero pair |
| 4 CLOSED_DENIED | 1以上、not MAX | Iは0..G / availabilityはIとのexact coupling | 0 | zero pair |
| 5 CLOSED_COUNTER_EXHAUSTED | GまたはIがMAX、I<=G | availabilityはIとのexact coupling | 1 | zero pair |

State 3/4はexact duplicate inboundがsame semantic replyをPENDINGへ進めるnew opportunityを許します。ReopenはG/I/availability/attempt/semantic/key/BLOB digestを保持し、timerだけzero pair、stateだけPENDINGへ進めます。Callback/result/custody mutationを繰り返しません。State 5またはexhausted 1はduplicateでもreopen/send 0です。Send return後・observation commit前crashではG/I/state/availabilityを進めず、12章どおりsame immutable replyを再送できます。

**D1-B3j境界**: B3jはREVERSE_REPLY (`0x42`) pure body encode/decode、exact 330-byte wire、key/raw/header bijection、non-zero/reserved、counter/availability/timer/state closed matrixまでです。Live DELIVERY/PVD、REPLY BLOB manifest/chunks/content、semantic digest再計算、RESULT_CACHE.reply_count、kindごとexact1、attempt/RESULT/CANCEL binding、kind 6 witness member-set、duplicate reopen/retry writer E2E、retention/cleanupはD3以降です。

### 8.6 Event、management、namespace state

本節の5 body（`0x50` / `0x51` / `0x52` / `0x61` / `0x63`）はいずれも **family 6 secondary** です。same-record共通header閉包は次をexactとします（各slice境界でも再掲）: common `flags=0`、`head_witness_digest` non-zero、`primary_value_digest` non-zero、body trailing byte禁止。`primary_id`は参照primary identityの16-byte hintで、最終同一性はbody rawから再構成したcomplete primary keyと`primary_value_digest`で判定します（§4）。

| Subtype | `primary_id`（referenced primary identity） |
| --- | --- |
| `50` EVENT_SPOOL / `51` RETRY_SUMMARY / `52` MANAGEMENT_LEDGER | body `transaction_id`（TRANSACTION_ANCHOR ID128） |
| `61` RETENTION_BASIS / `63` CLEANUP_PLAN | subject kind 2 TRANSACTION: `subject_key_raw` contents exact 16 = transaction ID。subject kind 3 DELIVERY: `COMPOSITE(40, delivery_key_raw:RAW16(contents=subject_key_raw contents exact 80))` の composite identity先頭16 bytes |

M1a subject kindは2 TRANSACTION（raw exact 16）または3 DELIVERY（raw exact 80）だけです。1 SERVICE / 4 EVENTのsubject recordはcorruptです（cardinality 0; §9）。stored `subject_primary_key_digest` / `reservation_key_digest` 等のcomplete-key digest fieldは§5.1どおり `KEY_DIGEST(complete_key)` を再計算して一致を要求します。

- `EVENT_SPOOL`（**D1-B3k**）: `transaction_id[16] + event_id[16] + spool_revision:u64 + spool_state:u32 + park_cause:u32 + retry_cycle_id:u64 + payload_blob_key_digest[32] + provider_id[16] + provider_revision:u64 + decision_digest[32] + grant_id[16] + grant_revision:u64 + decision_clock_epoch[16] + evaluated_at_ms:u64 + valid_from_ms:u64 + expires_at_ms:u64 + provider_retry_delay_ms:u64 + grant_limit_payload:u32 + grant_limit_active_count:u32 + grant_limit_active_bytes:u64 + grant_window_ms:u32 + grant_max_admissions_per_window:u32 + grant_attempts_per_cycle:u32 + last_seen_availability_epoch:u64 + last_consumed_availability_epoch:u64 + successful_resume_count:u32 + discard_committed:u32 + reservation_key_digest[32]`。

EVENT_SPOOLのsame-record wire / identity / closed shape contractは次をexactとします。

Body lengthは**exact 300**です（max 1536はsubtype上限で不変）。Body trailing byteは禁止です。

Key identityはdirect ID128でbody `transaction_id`とexact一致、common `primary_id`もbody `transaction_id`、common flagsは0です。common `record_revision`はbody `spool_revision`とexact一致し、いずれも1以上です（late/duplicate/saturating updateは§4どおりMAX維持可）。head witness digest / primary value digestはnon-zeroです（live TRANSACTION_ANCHOR complete value一致はD3）。

`transaction_id` / `event_id`はnon-zeroです。`spool_state`は§7.1 closed 1 ACTIVE / 2 PARKED_RETRY / 3 RELEASED / 4 DISCARDEDだけです。`park_cause`はpublic `ninlil_event_park_cause_t`のclosed 0..5だけです。**state × cause matrix**: ACTIVE / RELEASED / DISCARDED は cause exact `NONE(0)`、PARKED_RETRY は cause exact 1..5（`CYCLE_EXHAUSTED_TRANSIENT` / `BEARER_UNAVAILABLE` / `CAPACITY_UNAVAILABLE` / `APPLICATION_REMEDIATION` / `COUNTER_EXHAUSTED`）。表外はcorruptです。

`retry_cycle_id`は1以上です。`payload_blob_key_digest`は全stateでnon-zero（historical key digest。payload manifest 0/1 live cardinalityとrelease eraseは§9 / D3）。`successful_resume_count`は0..8、`discard_committed`はu32 exact 0/1で、**`discard_committed=1` iff `spool_state=DISCARDED(4)`**（1かつ非DISCARDED、またはDISCARDEDかつ0はcorrupt）。

`reservation_key_digest`は`KEY_DIGEST(complete RESERVATION key)`とexact一致します。そのcomponentsは`owner_kind:u16=TRANSACTION(2) || owner_key_raw:RAW16(contents=transaction_id exact 16)`です。composite digest本体とのstore/compareは禁止です（§5.1）。

Admission時のsource/application/service/target authorization tupleは同TRANSACTION_ANCHORのexact snapshotを参照し、decision / grant / availability epoch fieldsと組み合わせた13章grant decisionの完全再検証、provider grantとdescriptor payload-byte quotaの混同禁止、live RESERVATION / STATE / RETRY / MANAGEMENT cardinality、payload BLOB live 0/1は **D3** です。Provider grantにbyte-window fieldはありません。B3kはsame-record body/key/header/state-cause/resume-discard bool/reservation digestまでだけを閉じ、grant/clock truthを追加凍結しません。

**D1-B3k境界**: B3kはEVENT_SPOOL (`0x50`) pure body encode/decodeと本same-record閉包だけの **implementation complete** です（vector format `ninlil-domain-store-v1-d1b3k`）。**D2-S3 scan path wiring implemented**（exact-profile → `validate_typed_record`）。Live TRANSACTION_ANCHOR PVD、grant re-verify、availability resume path、STATE/RETRY/MANAGEMENT cardinality、payload BLOB、retention/cleanupはD3以降です。

- `RETRY_SUMMARY`（**D1-B3l**）CUMULATIVE: `transaction_id[16] + summary_kind:u16=1 + slot_index:u16=0 + total_completed_cycle_count:u64 + folded_cycle_count:u64 + cumulative_attempt_count:u64 + last_outcome:u32 + last_reason:u32 + last_ended_clock_epoch[16] + last_ended_at_ms:u64 + delivery_possible_any:u32 + counter_saturated:u32`。
- `RETRY_SUMMARY` RECENT: `transaction_id[16] + summary_kind:u16=2 + slot_index:u16(0..3) + retry_cycle_id:u64 + attempt_count:u32 + last_outcome:u32 + last_reason:u32 + availability_epoch:u64 + ended_clock_epoch[16] + ended_at_ms:u64 + delivery_possible:u32 + reserved:u32=0`。

RETRY_SUMMARYのsame-record wire / identity contractは次をexactとします。

Body lengthはCUMULATIVE **exact 84**、RECENT **exact 80**だけです（max 768はsubtype上限で不変）。Body trailing byteは禁止です。variantを跨ぐlength、またはdeclared `summary_kind`とlayout不一致はcorruptです。

Key identityは`COMPOSITE(51, transaction_id[16] || summary_kind:u16 || slot_index:u16)`で、componentsはbody同名fieldとexact一致します。common `primary_id`はbody `transaction_id`、common flagsは0、`record_revision>=1`（§4 saturating MAX維持可）、head witness digest / primary value digestはnon-zeroです（live TRANSACTION_ANCHOR一致はD3）。

**CUMULATIVE（kind=1）**: `slot_index` exact 0。`folded_cycle_count = max(total_completed_cycle_count - 4, 0)`（checked u64算術; underflow禁止の定義どおり）。`delivery_possible_any` / `counter_saturated`はu32 exact 0/1です。`folded_cycle_count=0`（admission直後およびcompleted cycle 1..4）ではfold済みaggregateがまだ無いため、`cumulative_attempt_count` / `last_outcome` / `last_reason` / `last_ended_clock_epoch` / `last_ended_at_ms` / `delivery_possible_any` / `counter_saturated` はすべてexact 0です。

**RECENT（kind=2）**: `slot_index` exact 0..3。`retry_cycle_id`は1以上。`slot_index = (retry_cycle_id - 1) mod 4`（u64）。`attempt_count`は1..8（`NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`）。RECENTは少なくとも1 attemptを実行したpartial/full cycleをcloseしたときだけ作り、attempt 0のcycleには作りません。`reserved` exact 0。`delivery_possible`はu32 exact 0/1です。

Cross-row population（CUMULATIVE admission exact 1、RECENT 0..4、`recent_count=min(total,4)`、fold前replace、counter overflow→`counter_saturated=1`とEvent COUNTER_EXHAUSTED park、slot uniqueness）はwriter/D3です。B3lはsingle-row body/key/kind-slot arithmeticとbool/reservedだけを閉じます。

**D1-B3l境界**: B3lはRETRY_SUMMARY (`0x51`) pure body encode/decodeと本same-record閉包だけの **implementation complete** です（vector format `ninlil-domain-store-v1-d1b3l`）。**D2-S3 scan path wiring implemented**。Cross-row fold ordering、cardinality、live STATE/SPOOL整合はD3です。

- `MANAGEMENT_LEDGER`（**D1-B3m**）: `operation_id[16] + operation_kind:u16 + reserved:u16=0 + ordered_sequence:u64 + transaction_id[16] + event_id[16] + actor_id[16] + canonical_request_digest[32] + expected_spool_revision:u64 + expected_event_id[16] + expected_content_digest_algorithm:u16 + reserved:u16=0 + expected_content_digest[32] + request_reason:u32 + acknowledge_flag:u32 + audit_length:u16 + reserved:u16=0 + audit_bytes[128] + audit_clock_epoch[16] + audit_committed_at_ms:u64 + replay_result_kind:u32 + replay_result_reason:u32 + replay_retry_cycle_id:u64 + replay_spool_revision:u64 + replay_spool_released:u32 + reserved:u32=0`。

MANAGEMENT_LEDGERのsame-record wire / identity / digest contractは次をexactとします。

Body lengthは**exact 364**です（max 1024はsubtype上限で不変）。Body trailing byteは禁止です。全`reserved` fieldはexact 0です。

Key identityは`COMPOSITE(52, transaction_id[16] || operation_id[16])`で、body `transaction_id` / `operation_id`とexact一致します。common `primary_id`はbody `transaction_id`、common flagsは0、**immutable `record_revision=1`**（create-once; replacement禁止）、head witness digest / primary value digestはnon-zeroです（live TRANSACTION_ANCHOR一致はD3）。

`operation_kind`は15 EVENT_RESUMEまたは16 EVENT_DISCARDだけです（§10 operation kindと同値）。`ordered_sequence`は1以上です（public management inputへ割り当てたdurable sequence; family 3 counter upper boundはD3）。`transaction_id` / `operation_id` / `actor_id`は常にnon-zeroです。`event_id`はoperationが要求するときnon-zero: kind 16ではnon-zero、kind 15ではEventFactのdurable event IDとしてnon-zeroを要求します（zero event_idはcorrupt）。

Content digest algorithmは0 NONE / 1 SHA-256だけです。canonical request digestはbody fieldだけから12章10節のdomain-separated management request preimageを再計算しstored `canonical_request_digest`とexact一致させます。persist済み`audit_length:u16`はchecked u32へwidenしてpreimageの`metadata_length`へ入れます（u16→u32拡張overflowは起きない）。ABI header / pointer / reserved / paddingはhashしません（§5.1のCOMPOSITE / KEY_DIGEST preimageとは別）。

| 軸 | kind 15 EVENT_RESUME | kind 16 EVENT_DISCARD |
| --- | --- | --- |
| algorithm | exact 0 NONE | exact 1 SHA-256 |
| `expected_event_id` / `expected_content_digest` | both all-zero | both non-zero |
| `acknowledge_flag` | exact 0 | exact 1（`acknowledge_required_receipt_absent`） |
| `audit_clock_epoch` / `audit_committed_at_ms` | both zero | epoch **non-zero**（`audit_committed_at_ms`は **0可**; 12章presenceはepoch） |
| `replay_spool_released` | exact 0 | exact 1 |
| `request_reason` | resume reason 1..5（`CONNECTIVITY_REMEDIATED`..`TEST`） | discard reason 1..4（`DEVICE_DECOMMISSIONED`..`TEST_CLEANUP`） |
| stored replay kind / reason | `ALREADY_RESUMED(2)` + reason `NONE(0)` | `ALREADY_DISCARDED(2)` + reason `OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT` |
| `replay_retry_cycle_id` / `replay_spool_revision` | both non-zero | revision non-zero、**cycle exact 0** |

kind 16ではbody `event_id == expected_event_id`をexactに要求します。kind 15の`expected_event_id`はzeroですがbody `event_id`はnon-zero durable EventFact IDです。`audit_length`は1..128、`audit_bytes[audit_length,128)`はall-zeroです。`expected_spool_revision`は1以上かつ`UINT64_MAX`未満で、成功commitのpersist済み `replay_spool_revision = expected_spool_revision + 1`を両kindでexactに要求します（checked addition; overflow ledger生成は禁止）。

MANAGEMENT_LEDGERはEvent admission時に物理slotを作りません。成功したdistinct resume/discardのFULL mutationだけが`transaction_id || operation_id` composite keyのledgerを1件createし、Event spool/count、reservation vector、state/resultを同じwitness groupで更新します。Event spoolはresume最大8、discard最大1をguardし、RESERVATIONは未使用分をlogical `reserved`、作成済みledger分をlogical `used`としてexact 256/512 bytesずつ表します。Ledger hitはcanonical request digestとoperation kindを先に比較し、一致ならpersist済みreplay fieldをcurrent Event state/revisionを再評価せず返します。不一致はpublic conflict resultです。live counter/state/spool整合は **D3** です。

**D1-B3m境界**: B3mはMANAGEMENT_LEDGER (`0x52`) pure body encode/decodeと本same-record閉包だけの **implementation complete** です（vector format `ninlil-domain-store-v1-d1b3m`）。**D2-S3 scan path wiring implemented**。live SPOOL/STATE/RESERVATION counter、family 3 sequence upper bound、writer E2EはD3です。

- `BEARER_STATE`: `availability_epoch:u64 + available:u32 + observation_clock_epoch[16] + observed_at_ms:u64`。Absent before first observation、以後non-zero strictly increasing epochだけoperation kind 20 witnessでcreate/replaceします。Same/old epochはwrite 0、same epoch/different availableはcontract failureです。
- `RETENTION_BASIS`（**D1-B3n**）: `subject_kind:u16 + reserved:u16=0 + subject_key_raw:RAW16(max 255) + subject_primary_key_digest[32] + basis_clock_epoch[16] + basis_at_ms:u64 + exclusive_cleanup_at_ms:u64 + required_window_ms:u64 + retention_state:u32 + basis_pending:u32 + retention_overflow:u32`。

RETENTION_BASISのsame-record wire / identity / matrix contractは次をexactとします。

Body lengthは`90 + N`です。`N`は`subject_key_raw` contents長で、M1a legalは **TRANSACTION `N=16` → body exact 106**、**DELIVERY `N=80` → body exact 170**だけです（max 512はsubtype上限で不変）。他N、trailing byte、`reserved≠0`はcorruptです。

`subject_kind`は2 TRANSACTIONまたは3 DELIVERYだけ（1 SERVICE / 4 EVENTはcorrupt）。Key identityは`COMPOSITE(61, subject_kind:u16 || subject_key_raw:RAW16)`でbodyと同components exact一致です。common `primary_id`は本節冒頭表どおり、common flagsは0、`record_revision>=1`、head witness digest / primary value digestはnon-zeroです（live subject primary complete value一致はD3; common primary digestの意味はretained immutable subject complete value）。

`subject_primary_key_digest`はsubject primary complete keyの`KEY_DIGEST`を再計算してexact一致します。TRANSACTION: family 6 subtype `20` ID128 key、identity = raw exact 16。DELIVERY: family 6 subtype `40`、identity = `COMPOSITE(40, delivery_key_raw:RAW16(contents=raw exact 80))`。composite digest本体とのstore/compareは禁止です。

DesiredState/EventFactはともにTRANSACTION_ANCHORをrootとするTRANSACTION basis exact 1へ全attempt/index、Event spool/retry/managementを集約し、required windowは`terminal_retention_ms`です。Endpoint DeliveryはDELIVERY basis exact 1へresult/disposition/token/cancel/reply/evidenceを集約し、required windowは`result_cache_retention_ms`です。SERVICEはM1aにunregisterがないためbasis 0、EVENTはTRANSACTIONへ統合するためbasis 0です。BLOB/management/attemptはowner basisへ集約し独立basisを作りません。登録時guardにより各windowは該当service dedup要件以上で、stored `required_window_ms`がprofile値と異なればcorruptです（profile照合はD3）。

Retention field matrix（same-record）はclosedです。`retention_state`は§7.1の1 ACTIVE / 2 ELIGIBLE / 3 CLEANUP_COMMITTED、`basis_pending` / `retention_overflow`はu32 exact 0/1です。

| state | pending | overflow | epoch / basis_at / delete_at / window |
| --- | ---: | ---: | --- |
| ACTIVE pending | 1 | 0 | `required_window_ms>0`、epoch/time/delete-at **all-zero** |
| ACTIVE overflow | 0 | 1 | `required_window_ms>0`、epoch **non-zero**、`basis_at_ms`は0可、delete-at **zero** |
| ACTIVE trusted | 0 | 0 | epoch non-zero、`required_window_ms>0`、`delete_at=checked(basis_at+window)` |
| ELIGIBLE | 0 | 0 | ACTIVE trustedと同じtrusted arithmetic（basis/delete/window） |
| CLEANUP_COMMITTED | 0 | 0 | 同上trusted arithmetic |

ACTIVE overflowのpresenceは`basis_clock_epoch`で表し、他のtrusted-clock fieldと同じく時刻値0自体は合法です。したがって「trusted non-zero epoch/basis time」は **epochがnon-zeroでbasis timeがtrusted** の意味へ明確化し、`basis_at_ms` non-zeroを要求しません。current trusted now / profile window / plan generation整合は **D3** です。

ELIGIBLEはeligibility判定sampleがsame epochかつnow>=delete-atとなるFULL replacementです。CLEANUP_COMMITTEDはPLAN_CREATEと同じwitnessでELIGIBLEからだけ進み、両flag 0とbasis/delete-atを保持してCLEANUP_PLAN `cleanup_generation`へpost-replacement record revisionを保存します。Plan存在中はexact CLEANUP_COMMITTED、FINALIZEでbasisとplanを同時eraseします。Pending/overflowからELIGIBLE/CLEANUP_COMMITTEDへ直接進めず、Clock epoch changeだけがfull windowをnew trusted sampleから再基準化し、same-epoch regressionはcreate/operation failureでrebaseしません。

**D1-B3n境界**: B3nはRETENTION_BASIS (`0x61`) pure body encode/decodeと本same-record閉包だけの **implementation complete** です（vector format `ninlil-domain-store-v1-d1b3n`）。**D2-S3 scan path wiring implemented**。current-now/profile window/plan generation/live primary PVDはD3です。

- `CLOCK_BASELINE`: `baseline_state:u32 + reserved:u32=0 + trusted_clock_epoch[16] + last_trusted_now_ms:u64 + publish_generation:u64`。Metadata初期化はUNINITIALIZED/common revision 1、epoch/time/generation zeroを必ず作り、以後absentはcorruptです。最初のaccepted Stage 7 sampleはTRUSTED/common revision 2/generation 1へreplaceし、以後の各accepted sampleはsame/new epochともcommon revisionとgenerationをchecked +1してStage 8前にreplaceします。同epochでは`now >= last`、new epochでは任意のtrusted `now`を受理します。後続Bearer open等が失敗してpublic handleをpublishしなくてもbaselineを巻き戻さないため、`publish_generation`はpublish済みhandle数ではなくpublish-attempt用trusted sampleのdurable generationです。GenerationまたはrevisionがMAXならwrapせず`NINLIL_E_DEGRADED`、publish 0、Storage mutation 0です。COMMIT_UNKNOWNはold/new complete value digestで収束し、authoritative newを確認できるまでpublishしません。

Stage 7がstrictly new clock epochをcommitした場合、Stage 9前にfresh domain scanを行います。ATTEMPT receipt timeout、CANCEL timeout、TRANSACTION retry/deadline timer、RESULT token/reconcile timer、REVERSE_REPLY retry timer、RETENTION_BASISのnon-zero old epochをcomplete record keyごとのpriority 6 `CLOCK_UNCERTAIN` sourceとして導出します。Matching CLEANUP_PLANが存在しbasis state=CLEANUP_COMMITTEDのRETENTION_BASISだけはeligibilityが既にdurable確定しているためsource/rebase対象外で、plan phaseをepoch非依存に継続します。それ以外のmismatch subjectはtimer比較、callback completion、send、cleanupをfail closedし、old numeric timeをnew epochへ比較/換算しません。Active token/send effectを誤って再開しないためRESULT/CANCEL/ATTEMPTと必要なowner STATE/SPOOL/SCHEDULER companionはoperation kind 21のwitnessでRECOVERY_REQUIRED/parkへ進めます。RESULT が ACTIVE token を回収する post は **token_state=EXPIRED**、**E_REC reason=`OUTCOME_UNKNOWN`** です（**`CLOCK_UNCERTAIN` を RESULT business reason へ書かない**）。old-epoch RESULT token/reconcile timer 由来の health は complete key + timer_kind + stored epoch の **CLOCK_FENCE** source として別軸で add し、当該 recovery commit で clear します。RETENTION_BASISはnew trusted sampleからfull durationをrebaseします。Createはpriority 6を含むDEGRADED Runtimeをpublishでき、`runtime_step`はこれらrecovery itemを通常effectより先に1件ずつ処理します。各valid recovery commitでそのrecord-key sourceだけclearし、全件解消後にCLOCK_UNCERTAINをclearします。
- `CLEANUP_PLAN`（**D1-B3o**）: `subject_kind:u16 + cleanup_phase:u16 + subject_key_raw:RAW16(max 255) + subject_primary_key_digest[32] + subject_primary_value_digest[32] + cleanup_generation:u64 + batch_generation:u64 + initial_attempt_count:u64 + remaining_attempt_count:u64 + initial_attempt_index_count:u64 + remaining_attempt_index_count:u64 + attempt_reuse_fenced:u32 + reserved:u32=0`。

CLEANUP_PLANのsame-record wire / identity / phase contractは次をexactとします。

Body lengthは`126 + N`です。M1a legalは **TRANSACTION `N=16` → body exact 142**、**DELIVERY `N=80` → body exact 206**だけです（max 512はsubtype上限で不変）。他N、trailing byte、`reserved≠0`はcorruptです。

`subject_kind`は2 TRANSACTIONまたは3 DELIVERYだけ（1 SERVICE / 4 EVENTはcorrupt）。`cleanup_phase`は§7.1 closed 1 DELETE_NON_INDEX / 2 DELETE_ATTEMPT_INDEX / 3 FINALIZEだけです。Key identityは`COMPOSITE(63, subject_kind:u16 || subject_primary_key_digest[32])`で、body `subject_kind` / `subject_primary_key_digest`とexact一致します。common `primary_id`は本節冒頭表どおり、common flagsは0、**common `record_revision`はbody `batch_generation`とexact一致**し、いずれも1以上です。head witness digest / primary value digestはnon-zeroです。

`subject_primary_key_digest`はB3nと同じsubject primary complete keyの`KEY_DIGEST`再計算とexact一致です。`subject_key_raw` contentsはkindどおりexact 16または80で、digest再計算のraw sourceとbijectionです。`subject_primary_value_digest`はnon-zeroかつcommon header `primary_value_digest`とexact一致します（live primary row `VALUE_DIGEST`一致はD3）。

`cleanup_generation` / `batch_generation`は1以上です。`cleanup_generation`はplan create時のRETENTION_BASIS post-replacement common record revisionでimmutable、`batch_generation`はcreate=1、各phase/batch commitでchecked +1です（writer; D1はstored値の範囲とrevision一致だけ）。Initial countはPLAN_CREATE snapshotのsame-primary ATTEMPT / local ATTEMPT_ID_INDEX exact countでimmutable。same-record: **`initial_attempt_count >= initial_attempt_index_count`**、**`remaining_attempt_count <= initial_attempt_count`**、**`remaining_attempt_index_count <= initial_attempt_index_count`**。remainingの増加やinitial超過はcorruptです。

Phase closed matrix（same-record; §9と同値）:

| phase | remaining attempt / index | `attempt_reuse_fenced` | 追加 |
| ---: | --- | ---: | --- |
| 1 DELETE_NON_INDEX | `remaining_attempt >= remaining_index`、かつ `remaining_attempt_index_count == initial_attempt_index_count` | exact 0 | index phase前なのでindex count不変 |
| 2 DELETE_ATTEMPT_INDEX | equal かつ `>=1` | exact 1 | `initial_attempt_index_count >= 1` |
| 3 FINALIZE | both exact 0 | **1 iff `initial_attempt_index_count > 0`、else 0** | — |

Retention eligibility commit後にphase 1でcreateし、public query/listはplan存在subjectをlogically absentとして扱いますが、collision lookup/recoveryはphysical primaryをfinalizeまで保持します。Live ATTEMPT/index counts、basis CLEANUP_COMMITTED、ATTEMPT_REUSE_FENCE aggregate、phase batch eraseは **D3** です。

**D1-B3o境界**: B3oはCLEANUP_PLAN (`0x63`) pure body encode/decodeと本same-record閉包だけの **implementation complete** です（vector format `ninlil-domain-store-v1-d1b3o`）。size `126+N`、key kind+digest、KEY_DIGEST/PVD bijection、generation/revision、phase remaining/fence matrixまで。**D2-S3 scan path wiring implemented**（exact-profile → typed same-record）。live counts/basis/fence aggregateはD3です。

- `ATTEMPT_REUSE_FENCE`: `active_plan_count:u32 + reserved:u32=0 + fence_generation:u64`。Active count 1以上だけrecordが存在し、zeroでeraseします。Absent→first createのgenerationは1、present join/leave replacementはchecked +1、count 1→0ではrecordをeraseします。後に別cleanupでabsentから再createする場合もgeneration 1です。Fence単独mutation、MAX replacement、flagged planなしのpresent fence、flagged planがあるabsent fenceはcorruptです。Common primary digestはzeroです。Fence存在中はnew attempt Entropy allocationを`NINLIL_E_WOULD_BLOCK`で停止し、transaction ID allocationやreplay/recoveryは継続します。
- `WITNESS_HEAD_INDEX`: `index_state:u16 + reserved:u16=0 + member_key_digest[32] + member_key_length:u16 + reserved:u16=0 + member_key_bytes[member_key_length] + member_value_digest[32] + member_head_witness_digest[32]`。Memberはfamily 3 counter 4件またはfamily 4 capacity 11件、key lengthはexact 10です。BASELINEはhead zero/common head zero、WITNESSEDはnon-zero両head exact一致です。Common primary digestはzeroです。これはshared mutable recordにhead chainを与えるmetadataで、単独のsemantic truthではありません。

#### 8.6.1 D1-B3k..B3o status / ownership ledger

**Decision identifier: D1-B3k..B3o。** 本節は5 remaining Domain Store bodiesのsame-record Normative contract freezeを固定する。**D1-B3k / D1-B3l / D1-B3m / D1-B3n / D1-B3o implementation complete**（pure body + same-record + vector `d1b3k` / `d1b3l` / `d1b3m` / `d1b3n` / `d1b3o`）。**D1 complete / D2 complete / Stage 5 complete をclaimしない**（D2-S3 scan wiringは別ledger §15.9）。public C ABI / export symbol / public status を追加しない。

| Slice | Subtype | Body same-record（本freeze） | Status | Vector format | Implementation / D2-S3 |
| --- | ---: | --- | --- | --- | --- |
| **D1-B3k** | `0x50` EVENT_SPOOL | exact 300、ID128=tx、revision=spool_revision、state×cause、resume 0..8、discard iff DISCARDED、reservation KEY_DIGEST | **implementation complete** | `ninlil-domain-store-v1-d1b3k` | body + **D2-S3 scan path** |
| **D1-B3l** | `0x51` RETRY_SUMMARY | CUMULATIVE 84 / RECENT 80、composite key=body、kind/slot/fold arithmetic、bools | **implementation complete** | `ninlil-domain-store-v1-d1b3l` | body + **D2-S3 scan path** |
| **D1-B3m** | `0x52` MANAGEMENT_LEDGER | exact 364、tx+op key、immutable rev1、kind15/16 matrix、canonical digest recompute | **implementation complete** | `ninlil-domain-store-v1-d1b3m` | body + **D2-S3 scan path** |
| **D1-B3n** | `0x61` RETENTION_BASIS | 90+N→106/170、kind+raw key、KEY_DIGEST、pending/trusted/eligible matrix | **implementation complete** | `ninlil-domain-store-v1-d1b3n` | body + **D2-S3 scan path** |
| **D1-B3o** | `0x63` CLEANUP_PLAN | 126+N→142/206、kind+digest key、PVD bijection、phase/fence matrix | **implementation complete** | `ninlil-domain-store-v1-d1b3o` | body + **D2-S3 scan path** |

**Acceptance ownership（pure body + D2-S3 scan path wiring）:**

1. pure body encode/decode + same-record validator（Port call 0）が§8.6各slice閉包を満たす
2. independent generatorが上表format stringのoracleをappend-only生成し、production bridgeがbyte equality
3. **module alias / unchanged-output規則（B3a..oと同じ）**: 既存`domain_store_body_codec` module aliasへprivate helperを追加しpublic ABIを増やさない。`spec/vectors/domain-store-v1.json`は **prior format objectsをbyte-for-byte保持** したappend-onlyでformatを`d1b3k`→`d1b3l`→…→`d1b3o`へ順に進める。prior fingerprint / prefix guardを壊すin-place rewrite禁止
4. D2-S3 scan pathが当該subtype body local validationへ到達できること（§15.9 / §17.1.3）

**Explicit non-completion / non-claims:**

- B3k/B3l/B3m/B3n/B3o pure body + same-record are **implementation complete**; **D2-S3 scan path wiring is implementation complete**（exact-profile structural only）
- **D1 complete / D2 complete / Stage 5 complete / public Runtime complete をclaimしない**（D2-S3はbounded scannerの1ピースのみ）
- B3n overflowはepoch non-zeroでpresenceを表し、`basis_at_ms=0`を合法とする。current-now/profile/plan整合はD3
- cross-row / grant / profile now / fence aggregate / writer E2E / live CLEANUP countsはD3/D4

## 9. Primary/index/backlink rules

Secondary common headerは`primary_value_digest=VALUE_DIGEST(primary)`を持ち、bodyはprimary keyを再構成できるraw componentを持ちます。Primary common headerはzeroです。Witness header/chunkはoperation metadataであり、このprimary/secondary規則の例外として両方zeroです。

Zero primary digestはfamily 5 marker、SERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、BEARER_STATE、CLOCK_BASELINE、ATTEMPT_REUSE_FENCE、WITNESS_HEAD_INDEX、WITNESS_HEADER/CHUNKだけです。その他は下表のprimary digestがnon-zeroです。BLOB manifestはownerのsecondaryかつchunkのprimaryであり、manifest自身のcommon digestはowner value、chunkのcommon digestはmanifest valueです。

| Primary | Secondary | Cardinality / primaryからのproof | Secondaryからのexact primary key |
| --- | --- | --- | --- |
| SERVICE | SERVICE_QUOTA | exact 1、SERVICEのquota key digest | `service_key_raw` |
| SERVICE | SERVICE RESERVATION | exact 1、SERVICEのreservation key digest | owner kind SERVICE + owner raw |
| TRANSACTION_ANCHOR | SEQUENCE_INDEX | exact 1、anchorのsequence/key | `transaction_id` |
| TRANSACTION_ANCHOR | TRANSACTION_STATE | exact 1、same transaction ID | `transaction_id` |
| TRANSACTION_ANCHOR | IDEMPOTENCY_MAP | exact 1、anchorのraw scope/key | body transaction ID |
| TRANSACTION_ANCHOR | EVENT_ID_MAP | Event exact 1 / Command 0、anchorのscope/event | body transaction ID |
| TRANSACTION_ANCHOR | transaction RESERVATION | exact 1、anchor reservation key | owner raw transaction ID |
| TRANSACTION_ANCHOR | SCHEDULER_OWNER | exact 1、anchor owner sequence | subject raw transaction ID |
| TRANSACTION_ANCHOR | ATTEMPT/ATTEMPT_ID_INDEX/EVIDENCE/CANCEL/EVENT_SPOOL/BLOB | state/countでbounded、streaming subtype scan | owner kind TRANSACTION + transaction ID |
| ORDERED_INGRESS | optional new SCHEDULER_OWNER/RESERVATION/BLOB | owner bindingとviewでbounded | owner kind INGRESS + ordered sequence raw |
| DELIVERY | RESULT_CACHE/SCHEDULER_OWNER/RESERVATION/ATTEMPT/EVIDENCE/CANCEL/reply/BLOB | initial RESULT exact 1、他はstate/countでbounded scan | owner kind DELIVERY + `delivery_key_raw` |
| BLOB manifest | BLOB chunks | exact `chunk_count`、index 0..count-1 | manifest key digest + blob raw |
| TRANSACTION_ANCHOR | RETRY_SUMMARY/MANAGEMENT_LEDGER | cycle / successful countsでbounded、streaming subtype scan | body transaction ID |
| immutable subject | RETENTION_BASIS | stateに応じ0/1、streaming subtype scan | subject kind + subject raw |
| cleanup subject | CLEANUP_PLAN | retention前0、cleanup中exact 1 | subject primary key digest |

D3 missing-secondary proofは次のexact cardinalityを使います。`L`はaccepted profile `max_evidence_per_target`、countはsame primary digestを持つrowだけを数えます。

| Primary/state | Required secondary cardinality |
| --- | --- |
| SERVICE | QUOTA 1、SERVICE RESERVATION 1 |
| TRANSACTION_ANCHOR any retained | SEQUENCE_INDEX 1、STATE 1、IDEMPOTENCY_MAP 1、SCHEDULER_OWNER 1、TRANSACTION RESERVATION 1、EVIDENCE_CELL `L+1` |
| DesiredState transaction | EVENT_ID_MAP 0、EVENT_SPOOL 0、CANCEL_STATE physical exact 1。Application ATTEMPT count=`STATE.cumulative_attempts`、non-zero cancel attemptなら+1。ATTEMPT_ID_INDEX countはlocal ATTEMPT countと同じ |
| EventFact transaction | EVENT_ID_MAP 1、EVENT_SPOOL 1、CANCEL_STATE physical exact 0。ATTEMPT/ID_INDEX count=`STATE.cumulative_attempts`、MANAGEMENT_LEDGER count=`successful_resume_count + discard_committed`、RETRY_SUMMARYはCUMULATIVE 1 + RECENT `min(total_completed_cycle_count,4)` |
| ORDERED_INGRESS PENDING | INGRESS RESERVATION 1。NEW_DELIVERYならINGRESS-primary SCHEDULER_OWNER 1、EXISTING_TRANSACTION/DELIVERYならnew owner 0でowner sequenceの既存ownerをexact `get`。Payload/evidence viewごとにrequired BLOB 0/1 |
| DELIVERY APPLICATION_FIRST | RESULT_CACHE 1、SCHEDULER_OWNER 1、DELIVERY RESERVATION 1、EVIDENCE_CELL `L+1`。APPLICATION ATTEMPT count=`RESULT_CACHE.application_attempt_count`で1以上。DesiredStateはCANCEL_STATE physical exact 1、EventFactはphysical exact 0。Cancel attempt ID non-zeroならDELIVERY-owned CANCEL ATTEMPT +1。ATTEMPT_ID_INDEX 0、REVERSE_REPLY count=`RESULT_CACHE.reply_count` |
| DELIVERY CANCEL_FIRST | RESULT_CACHE 1、SCHEDULER_OWNER 1、DELIVERY RESERVATION 1、CANCEL_STATE physical exact 1、DELIVERY-owned CANCEL ATTEMPT 1、APPLICATION ATTEMPT 0、EVIDENCE_CELL 0、payload BLOB 0、ATTEMPT_ID_INDEX 0。RESULTはapplication_seen/count/attempt_count 0かつCANCEL_TOMBSTONE_ONLY、REVERSE_REPLY count=`RESULT_CACHE.reply_count` |
| DELIVERY physical `delivery_state=2` DELIVERY_STARTED かつ `token_state=ACTIVE` | CALLBACK RESERVATION 1。public/in-memory DEFERRED_WAIT projection も同一 physical row（state 2 + ACTIVE）を指す。それ以外の Delivery physical state は CALLBACK RESERVATION 0 |
| BLOB manifest | chunks exact `chunk_count` |
| SERVICE / active TRANSACTION / active DELIVERY | RETENTION_BASIS 0。SERVICE/EVENT subject-kind recordはM1aでは常に0 |
| terminal DesiredState/EventFact TRANSACTION | subject_kind TRANSACTION RETENTION_BASIS exact 1 |
| terminal/cancel-only DELIVERY | subject_kind DELIVERY RETENTION_BASIS exact 1 |
| cleanup-eligible TRANSACTION/DELIVERY | CLEANUP_PLANはcreate前0、create後finalizeまでexact 1 |

Public queryが「cancel record absent」とprojectする意味はphysical CANCEL_STATE rowがmissingであることではなく、DesiredState owner上のphysical CANCEL_STATEがexact 1件存在しその`cancel_state=NONE`であることです。DesiredState TXおよびDesiredState DELIVERY APPLICATION_FIRST/CANCEL_FIRSTはCANCEL_STATE physical exact 1、EventFact TX/DELIVERYはphysical exact 0です。

SCHEDULER_OWNERはprimaryに保存したowner sequenceのdirect u64 key、EVIDENCEはslot 0..L、RETRY recentはslot 0..3、known 1:1 digest fieldはdirect keyを導出します。Variable ATTEMPT/REPLY/MANAGEMENTはstreaming countに加え、各secondary bodyのraw owner、primary digest、ID uniqueness/indexを照合します。Countだけ一致する別key/別owner代入はvalidになりません。

ATTEMPT_REUSE_FENCEは`attempt_reuse_fenced=1`のphase 2/3 CLEANUP_PLAN数と`active_plan_count`がexact一致し、count 0ならrecord absent、1以上ならpresentです。Phase 1 planはremaining attempt>=remaining indexかつfenced 0、phase 2はremaining attempt=remaining index>=1かつfenced 1、phase 3は両remaining 0で、initial index 0ならfenced 0、1以上ならFINALIZEまでfenced 1です。Fence generationはplan join/finalize leaveごとchecked +1で、同じFULL witnessにplan/fence transitionを含めます。

Exact 1/known-key relationshipは同じREAD_ONLY snapshotでprimary→secondary `get`とsecondary→primary `get`を行います。One-to-many relationshipは全row streaming passでsecondary→primary exact `get`し、primaryのdeclared count/stateに対するchecked count/digest aggregateを、必要ならsubtypeごとにscanを再開して照合します。RAM節約のため整合性を弱めず、計算量増加を許します。Scannerはprimary key/value digest、relationship kind、checked countだけをworkspaceへ保持し、全ID集合を保持しません。

SERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、BLOB manifestはimmutable primaryでcommon revision 1です。Mutable lifecycleはQUOTA/STATE/RESULT/EVENT等のsecondaryへ分離します。これによりprimary digest更新のfan-outを禁止します。Missing backlink、別primary value digest、primary key raw不一致、declared cardinality不一致、revision conflict、hash collision raw identity mismatch、orphan index/chunkはcorruptです。CLEANUP_PLAN absent時は上表の通常cardinality、plan present時だけsection 11 phase-specific decreasing setを適用します。PrimaryはFINALIZEまで残し、planなしpartial deletionを許しません。

Payload/reply BLOBだけはlifecycle-dependent 1→0です。Active TRANSACTION/EVENT_SPOOL、INBOX/DELIVERY_STARTED（physical state 2。public DEFERRED_WAIT projectionを含む）/RECOVERY/RECONCILE DELIVERYのCOMMAND/EVENT payloadではreferenced manifest exact 1を要求します。REVERSE_REPLYはsend state 1 PENDING、2 WAITING_RETRY、3 CLOSED_SENT_OR_UNKNOWN、4 CLOSED_DENIEDの全てでREPLY manifest exact 1を保持し、state 3/4で早期eraseしてはなりません。State 5 CLOSED_COUNTER_EXHAUSTEDだけkind 6 witnessと同じgroupでmanifest/chunksをeraseしてexact 0、digestはhistorical non-zeroのままです。Duplicate reopenは既存live manifestを使い、再materialize pathを作りません。PENDING ORDERED_INGRESSは8.3節のmessage view規則どおりINGRESS_PAYLOAD / EVIDENCEごとに0/1で、empty viewはmanifest 0、non-empty viewはexact 1です。Required Receipt/discardでspool released、Delivery result/disposition terminalのCOMMAND/EVENT payloadはowner/anchorのhistorical key digestを保持したままmanifest 0を要求し、payload release stateとBLOB manifest/chunks eraseを同じwitness groupへ含めます。Retention FINALIZEはREVERSE_REPLYと各reply BLOBを同じgroupでeraseし、state 3/4 recordだけを残してmanifest 0へしません。それ以外のmissing manifest、release stateなのに残るmanifest、ownerより先でないorphanはcorruptです。

## 10. Atomic witness v1

Multi-record semantic mutationはwitness header 1件とmanifest chunk 1..32件を同じFULL transactionへ含めます。新しいEntropy IDを作らず、admissionはtransaction ID、attemptはattempt ID、ingressはordered sequence、managementは`transaction_id[16] || operation_id[16]`、timer/reducerはowner/ordered-input/timer generationのcanonical bytesをoperation identity contentsとします。これをRAW16で包むため、別transactionが同じcaller operation IDを使ってもkey collisionしません。

Operation kindはclosed u16です。

| Value | Operation |
| ---: | --- |
| 1 | SERVICE_REGISTER |
| 2 | COMMAND_ADMISSION |
| 3 | EVENT_ADMISSION |
| 4 | INGRESS_COPY |
| 5 | ATTEMPT_PREPARE |
| 6 | SEND_OBSERVATION_AND_CURSOR |
| 7 | RECEIPT_OR_DISPOSITION |
| 8 | DELIVERY_ADMISSION |
| 9 | DELIVERY_START |
| 10 | APPLICATION_RESULT |
| 11 | CALLBACK_RECOVERY |
| 12 | CANCEL_PREPARE_OR_GATE |
| 13 | CANCEL_RESULT |
| 14 | OWNER_AUTOMATIC_TRANSITION |
| 15 | EVENT_RESUME |
| 16 | EVENT_DISCARD |
| 17 | CAPACITY_BLOCK_OR_RELEASE |
| 18 | RETENTION_CLEANUP |
| 19 | DESTROY_TOKEN_RECOVERY |
| 20 | BEARER_STATE_OBSERVATION |
| 21 | RECOVERY_ITEM_MUTATION |

`operation_identity:RAW16`のcontentsはkindごとにclosedです。`post_*_revision` / countはchecked mutation後の値です。

| Kind | Exact identity contents |
| ---: | --- |
| 1 | `service_complete_key_digest[32]` |
| 2 | `transaction_id[16]` |
| 3 | `transaction_id[16]` |
| 4 | `ordered_sequence:u64` |
| 5 | `attempt_complete_key_digest[32]` |
| 6 | `send_record_complete_key_digest[32] || post_send_operation_generation:u64` |
| 7 | `ordered_sequence:u64` |
| 8 | `ordered_sequence:u64` |
| 9 | `delivery_complete_key_digest[32] || token_generation:u64 || phase:u16` |
| 10 | `delivery_complete_key_digest[32] || token_generation:u64 || phase:u16` |
| 11 | `delivery_complete_key_digest[32] || reconcile_retry_generation:u64 || post_reconcile_invocation_count:u64 || phase:u16` |
| 12 | `cancel_complete_key_digest[32] || post_record_revision:u64 || phase:u16` |
| 13 | `ordered_sequence:u64` |
| 14 | `subject_primary_key_digest[32] || phase:u16 || post_state_revision:u64` |
| 15 | `transaction_id[16] || operation_id[16]` |
| 16 | `transaction_id[16] || operation_id[16]` |
| 17 | `resource_kind:u16 || post_capacity_epoch:u64 || post_blocked_state:u32` |
| 18 | `cleanup_plan_complete_key_digest[32] || cleanup_phase:u16 || post_batch_generation:u64` |
| 19 | `runtime_id[16] || clock_publish_generation:u64` |
| 20 | `availability_epoch:u64` |
| 21 | `target_complete_key_digest[32] || expected_old_value_digest[32] || recovery_action:u16` |

同じkind/identityは同じlogical mutationのretryだけに使用し、別write-setならcontract failureです。Kind 6/9/10/11/12/14/17/18のpost値、kind 19のgeneration、kind 20のepochはdurable sourceから再構成でき、COMMIT_UNKNOWN後にnew Entropyやclock sampleで作り直しません。Kind 6はApplication ATTEMPTまたはREVERSE_REPLYの各send micro-operation final observationだけです。TxGate TEMPORARY/DENIED/contract no-sendとBearer returnの全variantがsend operation generationをchecked +1し、そのpost generationをidentityへ使います。Bearer return variantだけsend invocation countもchecked +1します。Generation/count MAXで次operationを作らずCOUNTER_EXHAUSTEDへfail closedします。Kind 6にpre-send semantic commitはなく、TxPermit acquisition/actual call後・observation前crashは12章のmessage-kind別再送/fence規則へ従います。Cancel REQUESTのconservative pre-send gate/WOULD_BLOCK observationだけはkind 12です。

**Kind 9 phase**（closed u16、D1 same-record/vector検証可）: **1 DELIVERY_START_SUCCESS**、**2 DELIVERY_START_COUNTER_EXHAUSTED**。identity の `token_generation` は phase1 では post `N`、phase2 では prior/current `N=MAX`（tombstone generation）。phase1 post: physical state2、ACTIVE、E_ZERO、callback 可能。phase2 post: state6、existing retained tombstone 維持、E_REC(`COUNTER_EXHAUSTED`)、callback/token claim **0**。同一 delivery で phase が異なり collision しない。

**Kind 10 phase**（closed u16）: **1 APPLICATION_RESULT_OR_DELIVERY_COMPLETE**、**2 TOKEN_TIMEOUT**。identity の `token_generation` は当該 ACTIVE/`N`。phase1: accepted sync/deferred completion → CONSUMED + E_POS/E_DISP + terminal state4/5。phase2: exact active token timeout → EXPIRED + E_REC(`APPLICATION_COMPLETION_TIMEOUT`) + state6。同一 `token_generation` で phase が分かれ、race は authoritative current state で片方だけ commit（ACTIVE 残存時のみ phase2、既 CONSUMED/EXPIRED なら phase2 は no-op/INVALID path）。

**Kind 11 phase**は1 RECONCILE_CLAIM、2 RECONCILE_RESULT、3 CALLBACK_FAILURE_FENCE、kind 12 phaseは1 CANCEL_PREPARE、2 SEND_GATE_CLOSE、3 WOULD_BLOCK_REOPEN、4 CANCEL_TERMINALです。Kind 14 phaseは1 COMMAND_ATTEMPT_TIMEOUT、2 COMMAND_EVIDENCE_CLOSE、3 COMMAND_DEADLINE_TERMINAL、4 EVENT_TIMEOUT_OR_PARK、5 EVENT_AVAILABILITY_RESUMEです。Post state revisionはTRANSACTION_STATEのpost common revisionで、phase 4/5ではEVENT_SPOOL post revisionとのexact同時更新も要求します。Reconcile CLAIM（phase 1）はactual `on_reconcile` entry直前に`reconcile_invocation_count`をchecked +1し、identityへpost-`I`を使う。同じlogical claimのCOMMIT_UNKNOWN retryだけ同一post-`I`を再利用し、authoritative claim後の再entryは新post-`I`（同Gで`I>G`可）。RESULT（phase 2）は同じ`G`と当該claimのpost-`I`を参照します。Kind 17はadmission rejection等でRESERVATIONがまだ無いBLOCK_SETも表現し、blocked stateは0/1です。Kind 21 recovery actionは1 REPLACE_OLD_TO_NEW、2 ERASE_RETIRED、3 RECREATE_REQUIRED_INDEXだけです。

Kind 6 counter headroomはproactiveに閉じます。どちらかのpost counterがUINT64_MAXへ到達する最後のvalid observation commitは同じgroupで`send_counter_exhausted=1`を固定し、以後new send micro-operationを作りません。ATTEMPTで通常post-stateがfuture retryを必要とする場合はownerをCOUNTER_EXHAUSTED park/fail-closedへ進め、accepted/unknown/terminal observationならbusiness certainty/outcomeを上書きせずSEND_COUNTER health sourceだけを残します。REVERSE_REPLYはBearer resultに関係なくstate 5 CLOSED_COUNTER_EXHAUSTED、timer zeroへ進め、reply BLOBを同じwitnessでeraseします。Delivery RESULTのapplication result/reason/effect certaintyは上書きしません。Flagは0→1だけで、counter MAXかつflag 0、MAX未満でflag 1、flag reset、state 5でflag 0はcorruptです。「MAXで次operationを作らない」は別のoverflow commitを行う意味ではありません。

### 10.0 Canonical member-set builders

各operation kindは12/13章のlegal triggerとpost-stateを入力し、下表のnamed builderだけでmember setを作ります。Builderはfresh snapshotからcanonical post-stateを1つ導出し、許可roleのうちpresenceまたはcomplete encoded valueが変わるkeyだけをCREATE/REPLACE/ERASEへ入れます。変更するfamily 3/4 keyには対応HEAD_INDEXを必ず加え、変更memberが指すdistinct ACTIVE predecessor headerをSUPERSEDE_WITNESSとして加えます。許可role外の変更、必要keyの省略、no-op member、同じkind/identityから異なるkey set/value digestを作ることはcontract failureです。表のceilingはHEAD_INDEXと最大distinct predecessorを含み、header/chunk自身は含みません。

| Kind | Builder | Permitted semantic mutation roles | Member ceiling |
| ---: | --- | --- | ---: |
| 1 | `build_service_register` | SERVICE, SERVICE_QUOTA, SERVICE RESERVATION, SERVICE capacity | 16 |
| 2 | `build_command_admission` | counters, ANCHOR/SEQUENCE/STATE/IDEMPOTENCY, transaction RESERVATION/SCHEDULER, EVIDENCE, CANCEL, payload BLOB, SERVICE_QUOTA, capacities | 48 |
| 3 | `build_event_admission` | kind 2 roles + EVENT_ID_MAP, EVENT_SPOOL, RETRY_SUMMARY | 56 |
| 4 | `build_ingress_copy` | ordered/owner counters, ORDERED_INGRESS, optional ingress SCHEDULER/RESERVATION/BLOB, capacities | 32 |
| 5 | `build_attempt_prepare` | ATTEMPT, local ATTEMPT_ID_INDEX, TRANSACTION_STATE/EVENT_SPOOL/RESULT_CACHE/CANCEL_STATE, SCHEDULER/cursor, capacities | 24 |
| 6 | `build_send_observation` | ATTEMPT or REVERSE_REPLY。REVERSE_REPLY post state 5だけreply BLOB erase必須、post state 1〜4はerase禁止。owner STATE/SPOOL/RESULT/CANCEL、SCHEDULER/cursor | 24 |
| 7 | `build_receipt_or_disposition` | ORDERED_INGRESS erase, STATE/RESULT/EVIDENCE/SPOOL/ATTEMPT/REPLY/BLOB, owner/cursor, reservations/capacities | 48 |
| 8 | `build_delivery_admission` | ORDERED_INGRESS erase, DELIVERY/RESULT/CANCEL/remote ATTEMPT/EVIDENCE/payload BLOB, cached REVERSE_REPLY/reply BLOB, RETENTION_BASIS, DELIVERY RESERVATION/SCHEDULER, counters/capacities | 64 |
| 9 | `build_delivery_start` | phase1 SUCCESS: RESULT_CACHE→STARTED/ACTIVE、CALLBACK RESERVATION claim、capacities。phase2 COUNTER_EXHAUSTED: RESULT→RECOVERY/E_REC counter、callback/token claim 0、tombstone維持 | 24 |
| 10 | `build_application_result` | phase1 COMPLETE: RESULT terminal + CONSUMED + reverse reply/BLOB/RETENTION/capacities。phase2 TOKEN_TIMEOUT: EXPIRED + E_REC application timeout + slot release（result tuple は E_REC、positive Receipt 0） | 32 |
| 11 | `build_callback_recovery` | RESULT_CACHE recovery/reconcile（FATAL/contract/unknown-effect/OUTCOME_UNKNOWN entry、reconcile claim/result、CALLBACK_FAILURE_FENCE）、token RESERVATION、RETENTION、REPLY/BLOB、capacities | 24 |
| 12 | `build_cancel_prepare_or_gate` | CANCEL_STATE, ATTEMPT, local ATTEMPT_ID_INDEX, owner STATE/RESULT, REVERSE_REPLY/BLOB, SCHEDULER/cursor | 24 |
| 13 | `build_cancel_result` | ORDERED_INGRESS erase, CANCEL_STATE, owner STATE/RESULT, REVERSE_REPLY/BLOB, RETENTION_BASIS, cursor/capacities | 32 |
| 14 | `build_owner_automatic_transition` | TRANSACTION_STATE, optional EVENT_SPOOL/ATTEMPT/EVIDENCE/RETRY_SUMMARY/BLOB/RETENTION_BASIS, RESERVATION, SCHEDULER/cursor, capacities | 48 |
| 15 | `build_event_resume` | ordered counter, MANAGEMENT_LEDGER, STATE/SPOOL/RETRY/RESERVATION, SCHEDULER/cursor, capacities | 32 |
| 16 | `build_event_discard` | kind 15 roles + payload BLOB erase, RETENTION_BASIS, terminal resource release | 48 |
| 17 | `build_capacity_block_or_release` | one family 4 capacity key and its HEAD_INDEX only | 8 |
| 18 | `build_retention_cleanup` | CLEANUP_PLAN phase rules、eligible subject rows、optional ATTEMPT_REUSE_FENCE、quota/counter/capacity companions | 256 |
| 19 | `build_destroy_token_recovery` | bounded active-token RESULT_CACHE/CALLBACK RESERVATION set、shared capacities/owners | 160 |
| 20 | `build_bearer_state_observation` | BEARER_STATE only | 8 |
| 21 | `build_recovery_item_mutation` | identityが指すsingle target、owner TRANSACTION_STATE/EVENT_SPOOL/RESULT_CACHE/CANCEL_STATE/ATTEMPT/REVERSE_REPLY/SCHEDULERのrequired park/recovery transition、index/reservation/capacity/RETENTION_BASIS companion | 16 |

Optional roleは12/13章のpost-state predicateがtrueの場合だけ存在し、builder裁量ではありません。D1 vector generatorはkind/phaseごとにbase semantic member、family 3/4 HEAD companion、distinct ACTIVE predecessorを別々に数え、上表超過を仕様失敗としてCIで検出します。

Witness header metadataもbuilder裁量ではありません。

| Kind | `subject_id` source | `retention_kind` / subject key digest |
| ---: | --- | --- |
| 1 | SERVICE complete key digest先頭16 | 0 / zero |
| 2, 3, 15, 16 | transaction ID | 2 / TRANSACTION_ANCHOR complete key digest |
| 4 | ORDERED_INGRESS complete key digest先頭16 | EXISTING_TRANSACTION=2/anchor、EXISTING_DELIVERY=3/delivery、NEW_DELIVERY=0/zero |
| 5 | ATTEMPT complete key digest先頭16 | owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 6 | ATTEMPTまたはREVERSE_REPLY complete key digest先頭16 | semantic owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 7 | ORDERED_INGRESS complete key digest先頭16 | bound owner TRANSACTION=2/anchor、DELIVERY=3/delivery、invalid no-owner drop=0/zero |
| 8, 9, 10, 11 | DELIVERY complete key digest先頭16 | 3 / DELIVERY complete key digest |
| 12 | CANCEL_STATE complete key digest先頭16 | owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 13 | ORDERED_INGRESS complete key digest先頭16 | 2 / Controller TRANSACTION_ANCHOR complete key digest |
| 14 | TRANSACTION_ANCHOR complete key digest先頭16 | 2 / TRANSACTION_ANCHOR complete key digest |
| 17 | family 4 capacity complete key digest先頭16 | 0 / zero |
| 18 | cleanup subjectがID128ならそのID、それ以外はprimary key digest先頭16 | plan subject TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 19 | runtime ID | 0 / zero |
| 20 | BEARER_STATE complete key digest先頭16 | 0 / zero |
| 21 | target complete key digest先頭16 | target owner TRANSACTION=2/anchor、DELIVERY=3/delivery、namespace/witness metadata=0/zero |

Kind 19だけはruntime単位のbounded multi-delivery recoveryでsingle semantic subjectを持たないためretention 0です。他kindで表にないvariant、non-zero retentionとzero subject digest、または表と異なるsubject IDはcontract failureです。12章17節のnamed FULL hook pairはhook名でbuilderを選ばず、そのhookが囲むsemantic boundaryに従い上表kindへexact 1つ対応します: service register=1、Command/Event admission=2/3、ingress copy=4、attempt prepare=5、post-send observation/cursor=6、Receipt/Disposition reduction=7、Endpoint delivery/cancel-first admission=8、**DELIVERY_START success (kind9 phase1)=** role `*_delivery_started_commit`、**DELIVERY_START counter exhausted (kind9 phase2)=** role `*_delivery_start_counter_exhausted_commit`（**started hook への alias 禁止**）、**application result / delivery_complete (kind10 phase1)=** role result-cache commit pair、**token timeout (kind10 phase2)=** role `*_token_timeout_commit`、callback/reconcile recovery=11、cancel prepare/send gate=12、cancel result reduction=13、Command attempt timeout/evidence close/pre-dispatch deadline terminalとEvent timeout/park/automatic availability resume=14、explicit management resume=15、discard=16、capacity block/release=17、retention cleanup=18、destroy token recovery=19（EXPIRED+OUTCOME_UNKNOWN）、Bearer state=20、Stage-5/clock recovery item=21（ACTIVE 回収時 EXPIRED+OUTCOME_UNKNOWN；CLOCK は health のみ）。Automatic availability resumeはcaller operation IDを生成せずkind 14 phase 5を使い、kind 15はnon-zero persisted management operation IDを持つexplicit resume専用です。Hook pairとsemantic boundaryがこのmappingへ一意に落ちない場合は新hookを推測せず仕様不備です。

Namespace bootstrapはfamily 1〜4 exact 17-record all-present/all-absent規則、identity/clock baselineはsingle-record old/new規則を使うため、このoperation kindを使いません。Witness memberにできるfamily 3/4は`record_role=(family << 8)`、family 5/6は`(family << 8) | subtype`としてencodeします。Family 1/2をmanifest memberにしません。

Witness key identity / `witness_digest`は5.1のWITNESS_HEADER composite digestです。Header encoded valueのdigestをkeyやmember headに使いません。

`WITNESS_HEADER` body:

```text
operation_kind       u16
witness_state        u16  # 1 ACTIVE, 2 SUPERSEDED, 3 RETIRED
operation_identity   RAW16, max 128
subject_id           16 bytes
canonical_digest     32 bytes
member_count         u16, 1..256
chunk_count          u16, ceil(member_count/8), 1..32
manifest_digest      32 bytes
retention_kind       u16
reserved             u16 = 0
retention_subject_key_digest 32 bytes
successor_witness_digest 32 bytes
```

ACTIVEでは`successor_witness_digest` zero、SUPERSEDED/RETIREDでは最初にsupersedeしたnon-zero successor witnessです。`WITNESS_MANIFEST_CHUNK` key identityは5.1のcomposite formula、body prefixは`witness_digest[32] + chunk_index:u16 + chunk_count:u16 + entry_count:u16 + reserved:u16=0`です。非末尾entry countは8、末尾は1..8です。

`subject_id`はoperationのsingle semantic subjectがID128ならそのID、u64/composite/singletonならそのcomplete keyの`KEY_DIGEST`先頭16 bytesです。全zeroは禁止します。

Header `canonical_digest`はstate/successor進行で変えないoperation write-set identityです。

```text
SHA-256(ASCII("NINLIL-DOMAIN-OPERATION-V1") ||
  operation_kind:u16 || operation_identity:RAW16 || subject_id[16] ||
  manifest_digest[32] ||
  retention_kind:u16 || retention_subject_key_digest[32])
```

Retention kind 0ではsubject key digest zero、1..4ではnon-zero `KEY_DIGEST`です。M1aが新規生成するretention kindはTRANSACTION=2とDELIVERY=3だけです。

各member entryは次のexact variable encodingです。

```text
record_role       u16
action            u8   # 1 CREATE, 2 REPLACE, 3 ERASE, 4 SUPERSEDE_WITNESS
reserved          u8 = 0
key_length        u16, 1..255
reserved          u16 = 0
key_bytes         key_length bytes
old_present       u8, 0/1
new_present       u8, 0/1
reserved          u16 = 0
prior_head_witness_digest 32 bytes
old_value_digest  32 bytes, absentならzero
new_value_digest  32 bytes, absentならzero
```

Entryはkey unsigned-byte lexicographic順です。Manifest digestは5.1のdomain-separated formulaです。Family 5/6 semantic REPLACE/ERASEでは`prior_head_witness_digest`がold complete valueのcommon headとexact一致します。Family 3/4では対応するold WITNESS_HEAD_INDEXのhead、BASELINEだけzeroです。CREATEとwitness metadata memberではzeroです。Member count/chunk count、actionとpresenceの組合せ、digest zero/non-zeroが矛盾すればcorruptです。

Manifest member keyはcurrent private keyspaceのfamily 3/4/5/6だけです。Family 3/4はlength 10、family 5/6は13..45で5節grammarにexact一致します。`record_role` high byteはkey family、family 5/6 low byteはkey subtypeと一致し、family 3/4 low byteはzeroです。Key length 1..255はwire field capacityであり、上記legal length外、family 1/2、別root/future root、role/key mismatchを受理する許可ではありません。

CREATEはold=0/new=1、REPLACEはold=1/new=1かつdigest不一致、ERASEはold=1/new=0だけです。SUPERSEDE_WITNESSはfamily 6 subtype 7f headerだけに使い、old/new=1、old ACTIVE、new SUPERSEDED、new successor=this witnessをexact encodeします。No-op member、同じkeyの重複、256件超過はCore contract failureです。

Unbounded lifetime Event attempt/indexはterminal cleanup 1 groupへ詰めません。Section 11のCLEANUP_PLANがbounded batchへ分けます。各batch builderはsemantic candidate、plan/fence/capacity/cursor mutation、distinct ACTIVE predecessor headerを追加する前にtotalをcheckedし、256を超えるcandidateを次batchへ残します。Candidate 1件でも固定overhead込み256以下なので必ずforward progressし、header/manifest chunks自身はmember count外です。Non-cleanup named operationはprofile上64 members以下、destroy active token groupは32 tokenに各state/reservationとshared metadataを加えて160以下です。D1 catalog testがoperation別exact上限を再導出します。

Recovery判定:

| Snapshot | Result |
| --- | --- |
| 全memberがold presence/digest、witness header/chunk全てabsent | not applied |
| ACTIVE header/chunk完全、全semantic memberがnew presence/digest一致。Family 5/6 semantic memberのhead、family 3/4対応HEAD_INDEXのhead/value digestはwitness/member new digest。SUPERSEDE_WITNESS memberは下記progression | applied / current head |
| SUPERSEDED header/chunk完全、successor witness完全、そのmanifestにこのheaderのACTIVE→SUPERSEDED exact replacementが存在。Current headがまだこのwitnessのmemberはmanifest new digestと一致 | applied / partially current historical |
| RETIRED header、current semantic head参照0。Incoming predecessor successor参照ありなら全chunk complete、参照0なら任意のcleanup-in-progress subset | applied / cleanup eligible |
| all-oldだがACTIVE witness完全に存在 | corrupt |
| old/new混在、ACTIVE/SUPERSEDED chain partial、ACTIVE header/chunk partial、digest/revision conflict | corrupt |
| recognizable future witness versionだけ | unsupported |

Provider FULL atomicityによりoperation commit境界はall-old/absentまたはall-new/completeだけで、SUPERSEDED/RETIREDは後続のcomplete transitionでのみ到達します。判定不能をretry可能な失敗へ弱めません。

### 10.1 Successor chain

Bootstrap 17-record create後、Stage 5はbusiness/domain recordが0件であることを証明してからfamily 3 counter 4件+family 4 capacity 11件に対するBASELINE WITNESS_HEAD_INDEX 15件とUNINITIALIZED CLOCK_BASELINE 1件を1 FULL transactionで作ります。0/16は未初期化、16/16 exactは初期化済み、1..15/16、business/domain rowありで0/16、index member digest不一致はcorruptです。COMMIT_UNKNOWNは0/16または16/16だけへ収束します。このgroupはsemantic mutation前のone-time metadata initializationなのでwitnessを使いません。Family 1 immutable profileとfamily 2 single identity replacementにはindexを作りません。

以後family 3/4 recordをmulti-record witness memberとしてREPLACEする場合、同じFULL groupに対応WITNESS_HEAD_INDEX replacementを必ず含めます。初回business mutationはBASELINE→WITNESSED、以後はindex value/headをnew member digest/current witnessへ進めます。Persistent counter/capacity indexのeraseは禁止です。Recoveryはindex→member exact `get`、member→index exact `get`を行い、indexだけ/memberだけ、value digest不一致、head不一致をcorruptとします。これによりshared counter/capacityをW2が更新するときもold indexからW1を発見し、W1を同じgroupでSUPERSEDEDへ進められます。

新しいwitness `W2`が、current head `W1`を持つsemantic memberをREPLACE/ERASEする場合、`W2`のFULL groupはmemberのnew headを`W2`へ進めます。`W1`がACTIVEなら、そのheaderをACTIVE→SUPERSEDEDへreplaceし、`successor_witness_digest=W2`を保存し、そのheader replacement自体をW2 manifestへ`SUPERSEDE_WITNESS` actionで含めます。複数memberが別のACTIVE predecessorを持つ場合はdistinct predecessor全てを同じgroupでsupersedeします。すでにSUPERSEDEDのpredecessor headerは再更新しません。

したがってcrash後は、W2全体が不在でW1 ACTIVEのold truthか、W2全体とW1 SUPERSEDEDのnew truthだけです。W2 member上限256はsemantic member、supersedeするpredecessor header、family 3/4 memberとHEAD_INDEXを全て含めてchecked導出します。Witness自身のheader/chunkは自分のmanifestへ含めません。

Successorはself不可、digest collision不可、chain cycle不可です。SUPERSEDED headerごとにsuccessor manifest内のold/new header digestとstate transitionをexact検査し、successor missing、別successor、ACTIVEへの逆行、SUPERSEDEDの再supersedeはcorruptです。Chain検査も全header集合をRAMへ置かず、起点ごとのbounded walkとfresh exact `get`で行い、visited stepがwitness row countを超えたらcycleとしてcorruptです。

Every current family 5/6 semantic headとfamily 3/4 HEAD_INDEX headは、complete ACTIVEまたはSUPERSEDED headerを指さなければなりません。SUPERSEDEDを指すcurrent memberはそのwitness manifestに同keyのnew entryがあり、current value digestがentry new digestと一致することを要求します。RETIRED/absent witnessをcurrent headが指す、manifestにないkeyがheadを指す、同keyだがdigest不一致はcorruptです。SUPERSEDED witnessは「全memberがhistorical」を意味せず、successorで進んだmemberと旧headを保つmemberの混在を明示的に許します。

`SUPERSEDE_WITNESS` entryは普通のsemantic memberと違い、後続cleanupを許すhistorical transitionです。Current predecessor headerがmanifestのexact SUPERSEDED valueなら直接一致、同じsuccessorを保持するvalid RETIRED valueならprogressed、header/chunkが全てabsentならcleanup済みとして一致します。別successor、ACTIVE、header absent + orphan chunk、partial ACTIVE/SUPERSEDED、incoming参照ありRETIRED partialはcorruptです。このprogression規則によりW1をretire/cleanupしてもW2 manifestを破損扱いしません。

### 10.2 Witness retentionと有限回収

Memberのcurrent revisionがhead witnessを参照する間、witnessを削除しません。Fresh full scanでcurrent semantic headからの参照が0と証明できたSUPERSEDED headerだけを、single-record FULL replacementでRETIREDへ進めます。ACTIVE→RETIREDを禁止します。Replacement COMMIT_UNKNOWNはold SUPERSEDED/new RETIRED headerのexact digestで収束できます。

RETIRED headerはsemantic truthではありません。ただし別のSUPERSEDED/RETIRED predecessor headerが`successor_witness_digest`でこのwitnessを参照する間はsuccessor proofなので、headerと全chunkをcompleteで保持します。Incoming predecessor successor参照が0とfresh scanで証明できた後だけ、headerを保持したままmanifest chunkを1 keyずつ消し、全chunk absentをfresh snapshotで確認してheaderをsingle-key eraseします。したがってcleanupはchainの古いpredecessor側から進みます。各single-key COMMIT_UNKNOWNはold/new presenceで収束します。Incoming参照0で途中crashしたRETIRED header + chunk subsetはvalid cleanup-in-progressです。Header不在のorphan chunkはretiredと証明できないためcorruptであり、cleanup debrisとして消してはなりません。ACTIVE/SUPERSEDED、またはincoming参照ありRETIRED headerのpartial chunkはcorruptです。

## 11. Retention rules

- Transaction anchor/state/target/reservation/mapping/index/evidence/attempt/indexはterminal retention exclusive endまでlogical retention対象
- Result cache、Delivery token/disposition/cancel/replyはresult-cache retention exclusive endまでlogical retention対象
- Event spool/payload/mappingはrequired receiptまたはexplicit discardのdurable commitまで期限削除禁止
- Service recordはunregister commit後もrequired dedup windowと参照transactionの長い方まで保持
- Retention basisはterminal subjectごとexact 1件で、Clock epoch change時だけfull durationを再基準化する。Pending/overflowは削除不可
- Blob manifest/chunkはowner release stateと同じwitness、またはcleanup plan FINALIZEだけで削除
- 成功したManagement ledgerは最大8 resume / 1 discardをEventのsingle retention basis終了まで保持。未使用logical slotにphysical recordは存在しない

Exclusive end到達後のcleanupは次のrestart-safe state machineです。Planなしsubjectへpartial deleteを行いません。

1. `PLAN_CREATE`: immutable primary、ELIGIBLE RETENTION_BASIS、全backlinkがcompleteなfresh snapshotだけから、basisをCLEANUP_COMMITTEDへreplaceしCLEANUP_PLAN phase 1 / batch generation 1を同じwitnessでcreateします。Plan `cleanup_generation`はbasisのpost-replacement revisionです。SnapshotでATTEMPTとlocal ATTEMPT_ID_INDEXをcountし、initial/remainingへ同値保存します。このcommitでは他child/resourceを削除せずfenced=0です。以後public query/listはsubjectをlogically absentとして扱います。Matching retained idempotency key、transaction ID、logical delivery keyへのnew admission/ingressはFINALIZEまで`NINLIL_E_WOULD_BLOCK` / retryへ収束し、old result replay、new owner create、callback、effectは0です。Binding不一致は既存conflict規則を維持します。Transaction/attempt collision lookupはphysical key/indexを使い続けます。
2. `DELETE_NON_INDEX`（phase 1）: 0-byte global scanからsame primaryのうちdirect attempt-ID lookupでATTEMPT_ID_INDEXが存在しないremote-origin ATTEMPTだけをunsigned-key順に選び、最大bounded prefixをeraseします。各batchは消した件数だけremaining attemptをchecked減算しbatch generationを+1し、remaining indexは不変です。したがって全index→ATTEMPT backlinkは通常どおり常に存在し、`remaining_attempt_count >= remaining_attempt_index_count`です。EVIDENCE/BLOB/management/retry/reply/state/maps/reservation等はFINALIZEまでexact通常cardinalityを保持します。Remote ATTEMPTが0、すなわち両remaining countが一致したcommitで、remaining indexが1以上ならphase 2へ進めてATTEMPT_REUSE_FENCEをcreate/replace、active plan countを+1、fenced=1とします。両countが0ならphase 3/fenced 0へ進みます。Fence transitionのCOMMIT_UNKNOWN解決前はnew attempt allocation 0です。
3. `DELETE_ATTEMPT_INDEX`（phase 2）: remaining attempt=remaining index>=1、fenced=1だけがlegalです。ATTEMPT_ID_INDEXをkey順に選び、そのindexが指すlocal ATTEMPTとexact pair closureで同じbounded witnessからeraseし、消したpair数だけ両remaining countをchecked減算、batch generationを+1します。Pairを別batchへ分割せず、indexだけ/ATTEMPTだけのnew truthを作りません。両countが0になった同じcommitでphase 3へ進み、fenced=1をFINALIZEまで維持します。
4. `FINALIZE`（phase 3）: fresh snapshotでATTEMPT/ATTEMPT_ID_INDEXがともに0、plan remainingがともに0であることを証明します。残るbounded child（EVIDENCE最大9、MANAGEMENT最大9、RETRY_SUMMARY最大5、owner payload BLOB最大2、REVERSE_REPLY最大4と各reply BLOB最大2でreply系最大12、CANCEL_STATE最大1）、primary、STATE/RESULT spine、sequence/idempotency/event map、RESERVATION、RETENTION_BASIS、SCHEDULER_OWNER、CLEANUP_PLANを全て同じgroupでeraseし、service quota/resource capacity/cursorをreleaseします。Initial index countが1以上のplanはATTEMPT_REUSE_FENCE countを-1し、0ならeraseします。Fixed child + spine/shared metadata + distinct ACTIVE predecessorはchecked 64以下です。Commit OK/authoritative committed後だけtransaction/attempt/idempotency/logical-delivery identityを再利用可能にします。

各batch COMMIT_UNKNOWNはplanのold/new batch generation、remaining count、manifest、member presenceでall-old/all-newへ収束し、same batchをblind retryしません。Recovery scanは全phaseで`observed ATTEMPT = remaining_attempt_count`かつ`observed index = remaining_attempt_index_count`を要求します。Phase 1はattempt>=indexで全index backlink present、phase 2はattempt=index>=1かつ全ATTEMPT/INDEXがexact pair、phase 3は両方0です。Initial count変更、remaining増加/不一致、orphan pair、Evidence/BLOB/management/retry/reply/spine/resource proofのearly欠損、fence countとphase-2/3 fenced plan数不一致、cleanup generation変更、batch generation gap/overflow、planなしpartial graphはcorruptです。Capacity `used/reserved`はFINALIZEまで保持するため途中crashで過少申告しません。Cleanupはdurable scan cursorを保存せず、各batchが先頭から再scanして次のlexicographic eligible rowを選びます。RETIRED witness physical cleanupは10.2の別非semantic incremental cleanupです。

## 12. Four-counter validation

1. Retained transaction sequence、ordered-input sequence、owner sequenceはnon-zeroで対応counter以下
2. Sequence/index keyはunique、primary/backlink exact
3. Retention gapを許すためobserved maximumとcounterの一致は要求しない
4. Observed value > counter、zero sequence、duplicate/reuse、wrapはcorrupt
5. `last_visited_owner <= last_assigned_owner`。Visitedがcleanup済みownerを指すことはvalid
6. Counter exhausted marker 1は12章Type 3 invariantに従い、healthはcounter recordから直接再構成

## 13. Resource contribution table

Scanは全live `RESERVATION`の`RESOURCE_VECTOR`をchecked加算し、11 kindのused/reservedを再構成します。これがportable ledgerの唯一の加算元です。Storage logical bytesではありません。下表のdomain truthは各owner reservationが持つべき値のcross-checkであり、同じunitを二重加算しません。

Precommitのadmission/registration/receive-copy checkはunpublished write-transaction stagingで、recovery可能なdurable `reserved`ではありません。PrimaryとRESERVATIONが同じFULL commitで現れた後のexact owner vectorだけを保存します。Committed owner formulasは次です（`L=max_evidence_per_target`、`M=materialized raw count`、`P=payload bytes`、`r=successful resume count`、`d=discard committed 0/1`）。記載外kindはused/reservedともzeroです。

| Owner | Exact live vector |
| --- | --- |
| SERVICE | SERVICE used 1 |
| TRANSACTION Command | TRANSACTION used 1、TARGET used 1、OUTBOX_BYTES used `P` until payload release、EVIDENCE used `1+M` / reserved `L-M` |
| TRANSACTION Event | TRANSACTION used 1、TARGET used 1、EVENT_SPOOL_COUNT used 1 until release、EVENT_SPOOL_BYTES used `P+r*256+d*512` / reserved `(8-r)*256+(1-d)*512` while live、terminal後used `r*256+d*512` / reserved 0、EVIDENCE used `1+M` / reserved `L-M` |
| INGRESS | INGRESS used 1 |
| DELIVERY | DELIVERY used 1 until result/disposition/reconcile terminal、RESULT_CACHE reserved 1 before token/result then used 1 through retention、EVIDENCE used `1+M` / reserved `L-M`、DEFERRED_TOKEN reserved 1 before callback claim |
| CALLBACK | Active tokenのDEFERRED_TOKEN used 1。作成時にDELIVERYの同kind reservedを0へ移し、complete/timeout/recoveryでusedをrelease |

Owner state transitionは該当primary/state、RESERVATION、family 4 capacity metadataを同じwitness groupへ含めます。Aggregateが偶然一致しても、上表と違うownerへのunit移動はcorruptです。

Reservation quota/grant contributionはTRANSACTION ownerだけnon-zeroです。Command/Eventともtransaction non-terminal中`service_inflight=1`、terminal/retainedは0です。Eventはspool未release中だけ`grant_active_count=1`、`grant_active_bytes=P+2560`、required Receipt/discard後は両方0です。Commandのgrant fieldsと他ownerの3 fieldはzeroです。Scannerはanchorのservice keyへgroupし、SERVICE_QUOTA `active_transaction_count/active_spool_count/active_spool_bytes`とgrant snapshot limitをexact cross-checkします。Historical window admissions/payload bytesはSERVICE_QUOTA自身のwindow truthで、RESERVATIONへ複製しません。

| Resource kind | Reservation `used`のsemantic cross-check | Reservation `reserved`のsemantic cross-check |
| --- | --- | --- |
| SERVICE | committed SERVICE 1 | 0 |
| TRANSACTION | nonterminal/retained anchor 1 | 0 |
| TARGET | committed target 1 | 0 |
| OUTBOX_BYTES | required evidence未達Command manifest `total_length` | 0 |
| DELIVERY | nonterminal DELIVERY 1 | 0 |
| EVENT_SPOOL_COUNT | retained unreleased EVENT_SPOOL 1 | 0 |
| EVENT_SPOOL_BYTES | Event payload + consumed management logical bytes、terminal後used ledger bytes | unused management logical bytesだけ |
| RESULT_CACHE | result/disposition/token tombstone 1 | Delivery admission後callback/result前slot 1 |
| EVIDENCE | summary/materialized raw cell各1 | unused raw fixed cell各1 |
| INGRESS | unreduced ORDERED_INGRESS 1 | 0 |
| DEFERRED_TOKEN | CALLBACK ownerのactive token 1 | DELIVERY ownerのcallback前slot 1 |

同じsemantic unitをprimary/index/chunkから直接加算しません。各reservation vectorを上表のprimary/state/fixed-cell truthへ照合します。BLOB chunk数やStorage byte数はOUTBOX/EVENT bytesへ使わずmanifest `total_length`だけをcross-checkします。Derived used/reservedはfamily 4 metadataとexact一致必須です。`high_water`は履歴なので再計算せず、`used+reserved <= high_water <= limit`を検査します。Limitはprofile derivationとexact一致します。

## 14. Durable health reconstruction

Aggregate health recordは保存しません。Healthはreference countでなくcanonical source IDのsetです。

```text
HEALTH_SOURCE_ID = SHA-256(
  ASCII("NINLIL-DOMAIN-HEALTH-SOURCE-V1") ||
  priority:u8 || source_kind:u16 || source_identity:RAW16)
```

同じsource IDの反復観測は1件、別sourceは同じreasonでも別件です。Current health reasonは存在する最小priorityだけで決まり、scan順やhash iteration順を使いません。Durable sourceだけをStage 5で再構成し、instance-only entropy/Bearer/provider/method causeはrestartへcopyしません。

Private registryはclosedです。`source_kind`: 1 CREATE_STORAGE_FAILURE、2 COMMIT_UNKNOWN、3 DELIVERY_CALLBACK_CONTRACT、4 DELIVERY_APPLICATION_FATAL、5 CLOCK_FENCE、6 FAMILY3_COUNTER、7 FAMILY4_CAPACITY、8 EVENT_COUNTER、9 RETENTION_OVERFLOW、10 DELIVERY_COUNTER、11 INTERNAL_INVARIANT、12 SEND_COUNTER。`timer_kind`: 1 ATTEMPT_RECEIPT、2 CANCEL_TIMEOUT、3 TRANSACTION_DEADLINE、4 TRANSACTION_RETRY、5 RESULT_TOKEN、6 RESULT_RECONCILE、7 REVERSE_REPLY_RETRY、8 RETENTION_BASIS。`event_counter_kind`: 1 RETRY_CYCLE、2 CUMULATIVE_ATTEMPTS、3 SPOOL_REVISION、4 COMPLETED_CYCLES、5 MANAGEMENT_OPERATIONS。Create `stage`: 1 OPEN、2 BOOTSTRAP、3 DOMAIN_SCAN、4 RECOVERY_MUTATION、5 IDENTITY、6 CLOCK_BASELINE、7 BEARER_OPEN、8 PUBLISH_CLEANUP。Storage `method`: 1 OPEN、2 BEGIN、3 GET、4 ITER_OPEN、5 ITER_NEXT、6 PUT、7 ERASE、8 COMMIT、9 ROLLBACK、10 ITER_CLOSE、11 CLOSE。Unknown numeric valueはcorruptです。

COMMIT_UNKNOWN single/group identityは次で32 bytesへ閉じます。

```text
COMMIT_FENCE_DIGEST = SHA-256(
  ASCII("NINLIL-DOMAIN-COMMIT-FENCE-V1") ||
  fence_kind:u16 || fence_identity:RAW16)
```

`fence_kind`: 1 WITNESS（identity=witness digest 32 bytes）、2 BOOTSTRAP（identity=current root 8 bytes）、3 CLOCK_BASELINE（identity=complete key digest 32 bytes）、4 IDENTITY_ROTATION（identity=family 2 complete key digest 32 bytes）。EVENT_COUNTER source identityは`transaction_complete_key_digest[32] || event_counter_kind:u16`、CLOCK_FENCEは`owner_complete_key_digest[32] || timer_kind:u16 || stored_clock_epoch[16]`をexact RAW16 contentsにします。

| Priority | source_kind | Exact source identity / durable predicate |
| ---: | --- | --- |
| 1 STORAGE_IO | CREATE_STORAGE_FAILURE | create中だけ`stage:u16 || method:u16 || call_ordinal:u32`。Non-zeroならpublish禁止、successful fresh scan後へ持ち越さない |
| 2 STORAGE_COMMIT_UNKNOWN | COMMIT_UNKNOWN | `source_identity`は全variantでexact `COMMIT_FENCE_DIGEST[32]`だけ。Raw witness/key/group digestを直接HEALTH_SOURCE_IDへ入れない。Authoritative all-old/all-newまでpublish禁止 |
| 3 CALLBACK_CONTRACT | DELIVERY_CALLBACK_CONTRACT | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact CALLBACK_CONTRACTだけ |
| 4 APPLICATION_FAILED | DELIVERY_APPLICATION_FATAL | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact APPLICATION_FAILEDだけ |
| 5 GRANT_PROVIDER_UNAVAILABLE | none | durable sourceなし |
| 6 CLOCK_UNCERTAIN | CLOCK_FENCE | `owner_complete_key_digest[32] || timer_kind:u16 || stored_clock_epoch[16]`。ATTEMPT/CANCEL/STATE/RESULT/REVERSE_REPLY/RETENTION_BASISのnon-zero old-epoch timerごと |
| 7 COUNTER_EXHAUSTED | FAMILY3_COUNTER | family 3 complete key digest |
| 7 COUNTER_EXHAUSTED | FAMILY4_CAPACITY | family 4 complete key digest |
| 7 COUNTER_EXHAUSTED | EVENT_COUNTER | transaction complete key digest + counter kind u16 |
| 7 COUNTER_EXHAUSTED | RETENTION_OVERFLOW | RETENTION_BASIS complete key digest |
| 7 COUNTER_EXHAUSTED | DELIVERY_COUNTER | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact COUNTER_EXHAUSTED |
| 7 COUNTER_EXHAUSTED | SEND_COUNTER | ATTEMPTまたはREVERSE_REPLY complete key digest。`send_counter_exhausted=1`のrecordごとexact 1 source |
| 8 OUTCOME_UNKNOWN | INTERNAL_INVARIANT | family 5 marker complete key digest |

同じDeliveryをRESULT_CACHEとbacklinkから発見してもcomplete RESULT_CACHE key由来の1 sourceだけです。Delivery reasonはpriority 3/4のexact片方で、family 5へ複製しません。CLOCK_FENCEはrecord keyとtimer kindが同じ場合だけdedupし、別timerをまとめません。Source clearはそのcanonical predicateを解消したcommitだけが行い、類似ownerの成功で一括clearしません。Capacity blocked、ordinary capacity exhaustion rejection、Event PARKED_RETRY、business OUTCOME_UNKNOWN、Bearer WOULD_BLOCKはhealth sourceではありません。Priority 3〜8はDEGRADED publish可能、1/2は不可です。

## 15. Stage 5 recovery scan

Scanは1 READ_ONLY snapshot上で行う。Current rootだけのprefix scanは禁止です。**D2-S2 production path**では、zero-prefix iteratorを開く**前**にsame-txnでfamily 1〜4の17 exact `get` + completeness/CRC/version/profile exact compareを行い、その後namespace全体をunsigned-byte lexicographic順の**single** zero-prefix iteratorで走査します（§15.10）。TEST-build S1 transport adapterはgetなしでiteratorのみ（S1 regression専用）。

次の1〜11は**最終Stage 5 recoveryのclosed order**です。D2 bounded scannerはこれに沿って走査・seam・status集約を**供給/接続**しますが、**各stepの事実をすべてD2単独で証明するわけではない**。本節の最終Runtime objectiveは縮小しません。D2-S0/S2 Normative freezeはscanner contractを固定するだけで、D2実装完了・Stage 5完了・public Runtime publishを主張しません。

1. provider schema/open fencing完了
2. family 1〜4 completeness/CRC/current version（**same READ_ONLY txn、`iter_open`前の17 exact get**; D2-S2 §15.10）
3. profile exact compare（same txn / model; mismatch/futureはnon-terminal candidate）。Mismatchならdomain decode/mutation 0のままiteratorでf1-4 corruptionをなお検出（§15.10）
4. exact profileだけfamily 5/6全key、envelope、4096-byte上限、duplicate/order検査
5. witness header/chunk/member old/new検査（所有は下表。D1 pure codec / D2-S3 same-record local / D3 cross-row に分割し、step 5をownerlessにしない）
6. primary/index/backlink/blob参照検査
7. 4 counter upper bound/unique/orphan検査
8. service quota、ingress/owner、attempt/delivery/result/event ledger検査
9. 11 capacity checked再計算とfamily 4比較
10. durable health source再構成
11. iterator close→READ_ONLY rollback OK後だけresult採用

**所有分割（D2-S0）:**

| Owner | 担当 |
| --- | --- |
| **D1** | Port call 0のpure key/record/**witness** codecとgolden。witness header/chunk/memberのbyte layout・local encode/decode正本 |
| **D2** | mutation 0 bounded traversal、Port/shape/transport、lex order、framing/coarse classification、scanner-detectable status集約、same-snapshot exact `get` seam、adopt/finalize/fence。steps 2〜4のscanner到達可能な部分、**step 5のうち same-record/local witness header+chunk framing/matrix のscan到達（D2-S3）**、step 11のtxn/iterator lifetime |
| **D3** | cross-row semantic / partial group / orphan / cardinality / counter / capacity / health の相互validation。**step 5のうち witness member old/new・partial witness group・successor/supersede chain および他cross-row witness validation**。そのfindingを§16 precedenceへ投入。**Normative architecture / slice ledger 正本は §18（D3-S0 architecture + D3-S1a mode/context freeze docs only + D3-S2a declared multi-count freeze docs only + D3-S3a BLOB lifecycle freeze docs only + D3-S4a DSW1 freeze docs only §18.15 + D3-S5a DSW2 freeze docs only §18.16; **D3-S1 exact-1 implementation complete**; **D3-S2 declared multi-count implementation complete**; D3-S3/S4/S5 implementation / D3-S6..S12 / D3 overall / Stage 5 D3 bind pending）** |
| **D4** | recovery mutation / convergence / FULL writer。snapshot終了後の1 item mutationとfresh re-scan接続 |

必要なrecovery mutationはsnapshot終了後、1 item / 1 specific FULL transactionで行い、fresh READ_ONLY scanを先頭から再実行します（D4）。Durable scan cursorは作りません。Crash/reopenは常に先頭からです。Identity比較/rotationは最終scan成功後だけです。

Cross-referenceは同じsnapshotのexact `get`を使います（D2-S4 seam; S2のfamily1-4 get+iterator reconciliationとは別）。全ID集合をRAMへ保持しません。Private scannerはcaller-owned fixed workspace（§15.5: S1 255+4096+255 scratch + S2 packed 1143/views/validated/candidate、ceiling 8192）とproduction profiled `begin` / TEST transport adapter / `advance(row_budget)` / `finalize`/`abort`状態機械にし、関数stackにrecord bufferを置きません。Recognizable futureの唯一のpredicateはsection 5のkey length/prefix/versionとcomplete NLR1 length/CRC条件で、本節およびD2各sliceはそれを再定義・緩和しません。Predicate外のcurrent root外rowはcorruptです。Futureを読むための65,536-byte allocationは行いません。

**D2 completion ≠ Stage 5 completion。** S1〜S5完了はmutation 0 bounded scannerの完成だけを意味し、public Runtime publish gate・§1条件・step 5 cross-row witnessおよびsteps 6〜10のcross-row/health証明はD3/D4および残gateが揃うまでfalseのままです（step 5 local framingはD2-S3到達分まで）。

### 15.1 D2-S0 placementと所有境界

**D2-S0**（本freezeのdecision identifier）: private Domain Store bounded scannerのNormative contract。実装・vector・generated oracleの追加は後続sliceです。

Private scannerは概念上`src/runtime`に置きます。Port-owning state machineであり、pure model codecでもpublic C ABIでもありません。Public header / export symbol / new public status / public workspace typeを追加しません。

Callerは次を所有し、scannerへ渡します。

1. すでに`open`成功済みのcaller-owned Storage handle slot: 12章の`ninlil_storage_handle_t`を保持するcaller変数へのpointer、すなわち`ninlil_storage_handle_t *inout_handle`。`*inout_handle`はnon-NULLのlive handle。新typeや`ninlil_storage_t`は導入しない
2. prevalidated Storage Port ops tableへのexact pointer `const ninlil_storage_ops_t *storage`（required entryは少なくとも`begin` / `get` / `iter_open` / `iter_next` / `iter_close` / `rollback`、およびfence時の`close`。D2本体は`READ_WRITE` / `put` / `erase` / `commit`を呼び出さない。ops表の`get` non-NULLはS1 transport adapterでも要求してよく、**production profiled begin（S2）**のsame-txn exact getのため必須）
3. Runtime arena上のcaller-owned scanner workspace（§15.5 / §15.10）
4. private scanner session/control object（状態機械本体。public type名は持たない）
5. **production profiled beginのみ:** caller-owned `const ninlil_model_runtime_store_binding_t *candidate`（typed binding。non-NULL必須。scannerはconfig projectionを行わない。§15.10）

Scannerは成功したproduction profiled `begin`（またはTEST-build transport adapter）から`finalize`または`abort`完了まで、そのsnapshotのREAD_ONLY transactionを所有します。zero-prefix iteratorは`iter_open`成功からcloseまで所有します（**S2 production pathは`iter_open`前にsame-txn 17 exact `get` + profile gateを必須とする。§15.10**）。Fenceが必要になった時点でStorage handleを`close`し、`*inout_handle = NULL`にします。Callerはfenced handleを再利用せず、reopen後に新しいhandleを渡します。

### 15.2 状態機械（D2-S0）

状態はexactに次のclosed setです。

| State | 意味 |
| --- | --- |
| `IDLE` | 資源0。唯一の`begin`合法起点。**明示初期化済みのfresh sessionだけ**がこの状態を持つ |
| `OPEN` | READ_ONLY txn live、かつzero-prefix iterator live。`advance`可能。**S4 exact-get 合法**（§15.11）。**non-terminal candidate flag（`profile_mismatch` / `future_profile_candidate` / `recognizable_future_seen`）があっても`OPEN`のまま** |
| `EXHAUSTED` | 終端`NOT_FOUND`（両length 0）到達**かつ**production profiled pathではiterator reconciliation mask条件を満たす（§15.10）。iterator/txnはまだlive。**S4 exact-get 合法**（§15.11）。candidate flagは保持してよい。mask不一致は`EXHAUSTED`ではなくterminal `STORAGE_CORRUPT` |
| `FAILED` | **terminal primary failure**後、**live資源が残る間だけ**のpoison状態。`advance`不可。**exact-get も `INVALID_STATE`（Port 0）** |
| `DONE` | 当該sessionの終端。cleanup完了（live Port資源0）。result採用の有無は§15.6。**`begin`再入不可** |

#### 観察の二分類（D2-S0 closed）

Scan observationは次の2集合だけに属する。混同禁止。

| Class | 含むもの | 状態への影響 | scan停止 |
| --- | --- | --- | --- |
| **Terminal primary failure** | Port/status-shape unsafe error、lex duplicate/out-of-order、`BUFFER_TOO_SMALL`/domain-bound（255/4096）corruption、および **exact-profile pathがactiveなときの** D2-detectable current corruption（S3 structuralを含むscanner到達分） | live資源が残る間`FAILED`へ遷移しsticky primaryを記録。cleanup failureで上書きしない | **停止**: 以降`advance`禁止。後続rowを読んでstatusを書き換えない |
| **Non-terminal candidate** | `recognizable_future_seen`、`profile_mismatch` / `future_profile_candidate` | **`FAILED`へは遷移しない**。状態は`OPEN`/`EXHAUSTED`のまま。aggregate flagとしてsessionに保持 | **停止しない**。走査・lex・transport検査は継続 |

規則:

1. Non-terminal candidateは**primary failureではない**。したがって「sticky primaryを後続rowで上書きしない」規則の対象外である。
2. **後続のterminal corruptionはnon-terminal candidateをreplace/overrideしてよい**（corrupt > future、family1-4 corruption > profile unsupported）。これはsticky-primary禁止の例外ではなく、candidateがprimaryではないことの帰結である。
3. Terminal primaryが一度立った後は、candidate flagの有無にかかわらずscan停止・`FAILED`（またはcleanup後`DONE`）であり、後続rowでprimaryを書き換えない。
4. Cleanup failureはterminal sticky primaryを上書きしない（§15.6）。

#### `finalize`集約順序（closed）

`finalize`が返すoutcome（cleanup後）はexactに次順:

1. terminal sticky primaryがある → そのprimary（通常`NINLIL_E_STORAGE_CORRUPT`または14章closed mappingのPort failure）
2. なければ `profile_mismatch` / `future_profile_candidate` → `NINLIL_E_UNSUPPORTED`（domain decode/mutation 0）
3. なければ `recognizable_future_seen`のみ → `NINLIL_E_UNSUPPORTED`候補（Stage 5最終はS2+composition。S1単独は最終証明をclaimしない）
4. どれもなければ success/adopt path（`EXHAUSTED`かつrollback OK shape等。§15.6）

#### 遷移規則

1. production / TEST adapterの`begin`はいずれも`IDLE`だけ合法。成功で`OPEN`（**TEST-build S1 transport adapter:** txn+iterator確立後。**production profiled begin（S2）:** §15.10のbind→`begin(READ_ONLY)`→17 exact `get`→completeness/validate/compare→zero-prefix `iter_open`の後にだけ`OPEN`）
2. `advance`は`OPEN`だけ合法。
3. 終端条件を満たす`advance`は`EXHAUSTED`へ進む（§15.3 / §15.10）。candidate flagは保持する。production profiled pathでiterator seen maskがall-present maskと不一致ならterminal CORRUPTであり`EXHAUSTED` successへは進まない。
4. **S4 exact-get**は`OPEN` / `EXHAUSTED`だけ合法（§15.11）。成功でも state / counters / iterator position を変えない。terminal Port-path failure は sticky primary + `FAILED`（`advance` と同型）。
5. **Terminal primary failure**だけが、live資源が残る間`FAILED`へsticky遷移する。Non-terminal candidateでは`FAILED`へ遷移しない。
6. `finalize`は`EXHAUSTED`または`FAILED`で合法。
7. `abort`は`OPEN` / `EXHAUSTED` / `FAILED`で合法。
8. 第二回cleanup（既に`DONE`）および上記以外のillegal callは`NINLIL_E_INVALID_STATE`、**Port call 0**、状態/workspace/outputs不変。`IDLE`への`finalize`/`abort`もillegal（資源0でcleanup不要）。
9. **`DONE`は当該scanner session/control objectの終端である。`DONE → IDLE`の暗黙遷移も、同一session objectへの`begin`再呼出も禁止。** 再scanするcallerは、prior sessionが`DONE`（または未使用）でlive Port資源0であることを確認したうえで、**新しいsession/control objectを明示初期化して`IDLE`にする**。将来private init APIがworkspace byte領域の再利用を許す場合でも、それは明示初期化であり、`DONE` sessionのreuseではない。途中状態（`OPEN` / `EXHAUSTED` / `FAILED`）からのsession再利用は禁止。
10. **`FAILED`はlive資源が残る間だけ存在する。** cleanup tree（§15.6）でchildrenをconsumeし終わったfailureは`DONE`（unadopted）へ進む。fully cleaned failureを`FAILED`に残してはならない。

### 15.3 `begin` / `advance` / `row_budget` / `iter_next`（D2-S0）

#### begin（API分割: production profiled vs TEST transport）

**Production private release（tests OFF）はprofiled beginだけを露出する。** 最終private symbol名は実装で`ninlil_domain_scan_begin_profiled`としてよいが、**required non-NULL candidate binding**と§15.10のPort/model順序を満たすこと。`candidate == NULL`、optional gate、またはprofile workを飛ばすproduction pathは**禁止**（Stage 5 / S6 bypass）。

| API | 露出 | 役割 |
| --- | --- | --- |
| **production profiled begin** | tests-OFF release artifactに含まれる唯一のbegin | candidate必須。bind→`begin(READ_ONLY)`→17 `get`→completeness/validate/compare→zero-prefix `iter_open`→`OPEN`（§15.10）。内部でS1 transport力学（txn/iter ownership、cleanup tree、lex advance）をprofile workの**後**に再利用する |
| **S1 transport-only begin** | **TEST-build adapterのみ**。explicit test macroの下だけでcompile/declareされ、tests-OFF release artifactから**absent** | S1 oracle frozen regression用。追加`get`なしでtxn+`iter_open`。**S6 / Stage 5 / production orchestrationから呼ぶことは禁止** |

両begin共通のpre-validation（**当該begin callの実引数のみ**に対する。beginは`out_result`引数を持たないため、将来の`finalize`/`abort` result objectをprevalidateしてはならない。§15.7 temporal boundary）。違反は`NINLIL_E_INVALID_ARGUMENT`（またはpointer shapeが12章のPort contractに該当するなら同章のclosed mapping）、**Port call 0**、状態`IDLE`維持、session/workspace/（profiledなら）caller candidate不変です。

1. scanner session/control object / workspace / required ops table / `inout_handle`がnon-NULL
2. `*inout_handle`がnon-NULL（already-open `ninlil_storage_handle_t`）
3. required ops function pointerがすべてnon-NULL（production profiled beginは`get`必須）
4. workspace rangesがcapacity exact、かつ**session / full workspace / ops table object / handle slot**とpairwise non-overlap（§15.5 / §15.7 / §15.10）。**result objectはbegin引数に無いため検査対象外**
5. 状態が`IDLE`（`DONE`を含む非`IDLE`は`NINLIL_E_INVALID_STATE`）
6. **production profiled beginのみ追加:** `candidate` non-NULL。begin時点のalias検査は**candidate vs session / full workspace / ops table object / handle slot**（および当該beginの他実引数）のpairwise non-overlapだけ。**`out_result`はbeginに存在しないため検査しない。** prevalidation成功後・**最初のPort call前**にworkspaceのcandidate copy領域へ**exact copy**する。copy後はcaller candidateのlifetimeを要求せず、scannerは以後caller pointerを読まない。scannerはconfig→binding projectionを行わない

検証成功後のPort順序:

- **TEST transport adapter（S1）:** Storage `begin(READ_ONLY)` exact 1回 → 成功shape txn保持 → 追加`get`なしでzero-prefix `iter_open` exact 1回 → `OPEN`
- **production profiled begin（S2）:** §15.10 closed順序（bind/copy → `begin(READ_ONLY)` exact 1 → `get` key IDs 1..17 catalog順 exact 17 → completeness/validate/compare → zero-prefix `iter_open` exact 1 → `OPEN`）。**当該READ_ONLY transaction上のzero-prefix iteratorはlifetime中exact 1つ**

Handle/status shapeは12章Storage Port規則に従います。

- call前にout handle（txn / iterator）をNULLにする
- `OK`は対応handle non-NULL、non-OKはNULLが唯一のvalid shape
- `OK + NULL`は`NINLIL_E_STORAGE_CORRUPT`
- non-OK + non-NULLは§15.6 cleanup treeでlive childをexactly once consumeしたうえで`NINLIL_E_STORAGE_CORRUPT`（cleanup statusでprimaryを上書きしない）
- unknown status / invalid output shapeでreuseが安全でない場合はchild consume後にStorageをfence（`close` + `*inout_handle = NULL`、`reopen_required`）。**fence/`close`はlive childrenをconsume済み（またはrollbackによる暗黙consume済み）と分かってからのみ**

`begin`途中failureは§15.6 cleanup treeを使い、採用可能resultを公開しません。live資源が残る間だけ`FAILED`、**fully cleaned failureは`DONE`（unadopted）**です。production profiled pathでget/model terminal failureのときは**`iter_open`を呼ばない**（§15.10）。`DONE`になったsessionへは`begin`し直せません。

#### advanceとrow_budget

- `row_budget = 0`は`NINLIL_E_INVALID_ARGUMENT`。状態は`OPEN`のまま、workspace/outputs不変、**Port call 0**。
- 正の`row_budget`は**successful `OK` rowだけ**を数える。classification markや内部bookkeepingはbudgetを消費しない。
- budget exhaustionは`NINLIL_OK`を返し状態は`OPEN`のまま。callerは同じsnapshotで再度`advance`できる。
- `iter_next`が`NOT_FOUND`かつkey/value lengthが両方exact 0なら:
  - **TEST transport / S1:** 終端として`EXHAUSTED`へ遷移し、その`advance`は`NINLIL_OK`（0 OK rows可）
  - **production profiled path:** §15.10 iterator reconciliation（seen mask == get present/all mask）を満たすときだけ`EXHAUSTED`。不一致はterminal `NINLIL_E_STORAGE_CORRUPT`（`EXHAUSTED` successではない）
- `EXHAUSTED`後の`advance`は`NINLIL_E_INVALID_STATE`、Port call 0、状態/workspace/outputs不変。
- 終端以外の`NOT_FOUND`（length shape不正）はcorruption。

#### 各`iter_next`前のbuffer契約

毎回`iter_next`を呼ぶ直前に、scannerはcaller-owned bufferを次へresetします。

| Field | Exact value |
| --- | ---: |
| key.length | 0 |
| value.length | 0 |
| key.capacity | 255 |
| value.capacity | 4096 |
| key.data / value.data | workspace固定scratch（heap/VLAなし） |

**Observable shape checks（scannerが必ず行い、違反をterminal corruptionとする）:**

1. `NINLIL_STORAGE_BUFFER_TOO_SMALL`（BTS）: private D2の255/4096 workspaceでは常にterminal `NINLIL_E_STORAGE_CORRUPT`。required lengthを信頼してのreread、65,536-byte（または任意size）一時allocation、iterator advance仮定は行わない。**BTSは12章のvalid non-OK shapeであり、atomic pairは両方の`length`へrequired countを書く（oversized時は非0になり得る）。そのch12-validな非0 lengthを「第二のshape violation」として数えてはならない。** domain outcomeはstatus→`STORAGE_CORRUPT`のみ。
2. **BTSを除く** non-OK statusでkey.lengthまたはvalue.lengthが非0はobservable corruption。終端`NOT_FOUND`およびother errorは12章どおり両length 0がvalid shape。generic「non-OKならlength==0」規則は**明示的にBTSを除外**する。
3. `NOT_FOUND`で両lengthが0以外はcorruption（終端条件は両exact 0のみ）。
4. `OK`でkey lengthが1..255外、value lengthが0..4096外、length>capacity、またはdata NULL（non-zero length時）はcorruption。
5. unknown Storage statusは14章closed mappingを維持し、reuse unsafeなら§15.6 treeでchild consume後にfence。
6. **`iter_next` descriptor identity（get pathと同型）:** `inout_key.data` / `inout_value.data` と `capacity` はcaller-owned workspace固定scratch記述子であり、providerが書き換えてはならない（`length`とbuffer contentsだけがiter_nextの出力）。return後に `key.data` がworkspace key slotでない、`value.data` がworkspace value slotでない、または `capacity` が255/4096 exactでない場合はunsafe provider shape → terminal `STORAGE_CORRUPT`（children consume後fence）。getの`inout_value` descriptor規則（§15.10.3）と同趣旨。

**Data-byte policyとprovider conformance（完璧検出を主張しない）:**

1. non-OK（`BUFFER_TOO_SMALL`含む）ではkey/value **data bytesを採用しない**。classification、lex previous、result、coarse counterのいずれへも取り込まない。
2. non-OK後のscratch data内容はunspecifiedとして無視する。scannerはfull shadow copyを持たないため、providerがcapacity内dataを部分書き換えしても**bytes mutationそのものを完全検出する義務も能力も持たない**。
3. capacity内dataをnon-OKで書き換えるproviderは12/14章Port conformance違反である。D2のNormative義務は (a) observable length/status shapeの検査、(b) non-OK dataの非採用、(c) OK rowだけをlex/classificationへ投入、までに閉じる。
4. `OK`のときだけlength範囲内dataを当該rowの内容として読んでよい。

### 15.4 順序・terminal primary / candidate・S1分類分岐（D2-S0 freeze）

#### 順序

Iteratorが返す各OK keyはstrict unsigned-byte lexicographic増加で、duplicate 0です。比較状態はworkspaceの **explicit `has_previous` flag** とprevious-key scratch（最大255 bytes）だけです。全key集合を保持しません。**previous length 0をfirst-row sentinelに使ってはならない。**

- session/`begin`成功時: `has_previous = 0`。previous lengthの値は比較に使わない
- `has_previous == 0`の最初のOK row: 順序比較なしで受理し、keyをprevious scratchへcopy、previous lengthをkey lengthへ設定、`has_previous = 1`
- `has_previous == 1`の以降のOK row: previous lengthとprevious bytesに対し`memcmp`共通prefix + length規則でstrict increaseを要求
- equal（duplicate）またはdecrease（out-of-order）は即**terminal** `NINLIL_E_STORAGE_CORRUPT`（scan停止、`FAILED`）
- non-OK / 終端rowはpreviousを更新しない
- **Terminal primary**が立った時点でscan classificationを停止する。後続rowを読んでterminal primaryを上書きしない
- **Non-terminal candidate**（`recognizable_future_seen` / profile candidate）では停止しない。後続のterminal corruptionはcandidateをoverrideしてよい（§15.2）
- sticky **terminal** primaryはcleanup failureで上書きしない

#### D2-S1 row classification分岐（実装はS1、分岐表はS0で固定）

各OK rowのcoarse分類はexactに次のclosed branchだけです。S1はtransport / lexicographic order / 本coarse分類までを確立し、§16の**Stage 5 four-level precedence全体**を完成したとは主張しません。

**D1 `ninlil_model_domain_classify_row`の実enum/semantics（唯一のrow-class helper。dual future predicate禁止）:**

| Class | 意味（実装どおり） |
| --- | --- |
| `NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT` | current-root key grammarが受理された。**valueはclassify_rowが検証しない**。envelope/CRC/body structuralは**S3**が担当 |
| `NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE` | **非current-root**について、complete key length/prefix/version **かつ** complete NLR1 framing/CRC を満たすrowだけ |
| `NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED` | 上記どちらでもない |

「current valid / current malformed value」をclassify_rowの出力として述べてはならない。`CURRENT`はkey側受理のみである。

各OK rowの分岐:

1. **exact valid family 1〜4 Runtime Store key**（L2a/Runtime Store key grammar: current root `4e494e4c494c0001` + family `0x01`/`0x02` length 9、または family `0x03` suffix 1..4 / `0x04` suffix 1..11 length 10のcatalog一致）:
   - **S1 transport adapter:** family1-4 seenとしてcount/markするのみ（value integrityなし）
   - **S2 production profiled path:** §15.10 iterator reconciliation（key IDへroute、seen bit、targeted-get retained bytesとのlength/bytes一致、checked count）。value integrityの正本はsame-txn get path + 本reconciliation
2. **family 1〜4 prefix-shapedだがcatalog外（malformed / noncatalog）:** **terminal** family1-4 corruption（S1 coarseでもkey grammar failureとしてcorrupt側。S2は§15.10 prefix routingで明示）
3. **それ以外のOK row（non-family1-4）**:
   - **profile-mismatch modeまたは`future_profile_candidate` mode**（§15.10; exact-profile inactive）: domain body decodeも`classify_row`も行わない。当該rowは**successfully visited**として`ok_row_count`へ数え、lex previousを進め、profile candidateをoverrideしない
   - **それ以外（S1 transport既定、およびS2で`profile_exact_active`）**: D1 `ninlil_model_domain_classify_row`（Port call 0）を**exact 1回**呼ぶ（future predicateの再実装・緩和禁止）。
     - `CURRENT` → current-key accepted。value未証明。`profile_exact_active`なら後続**S3** structuralの対象（S2はbody structuralを完成しない）
     - `RECOGNIZABLE_FUTURE` → non-terminal `recognizable_future_seen` flagを立て、**scan継続**（`FAILED`にしない）
     - `MALFORMED` → **terminal** D2-detectable corruption（key/class failure。value valid/invalidの主張ではない）

追加closed規則:

- current root上のunknown subtype / key grammar failureは**futureではない**（`MALFORMED`側。silent ignore禁止）。
- `recognizable_future_seen`の後でも、後続の**terminal** D2-detectable corruptionがあればoutcomeはcorrupt（candidateはprimaryではないのでoverride可）。partial group / orphan / counter / capacity / health はD3 findingでありS1が証明しない。
- future-only候補およびprofile gateの最終`UNSUPPORTED`合成は**S2**（§15.10 / §15.2 finalize順）。S1 transport adapter単独の「futureを見た」はStage 5最終`UNSUPPORTED`証明ではない。

### 15.5 Mutation 0とworkspace天井（D2-S0 / D2-S2 layout freeze）

D2全slice（S1〜S6）は次を必須とします。

- Storage mutation 0: `READ_WRITE` / `put` / `erase` / `commit` call 0
- heap allocation 0、VLA 0、recursion 0
- 関数stack上のrecord buffer 0
- 65,536-byte temporary value allocation 0
- public ABI追加 0
- **第二の4096-byte value bufferを追加しない**（S2 get pathはtyped fixed capacity。§15.10）

Caller-owned固定scratch（Runtime arena）。**D2-S3以降のNormative packed workspace**（natural alignment padding可。`sizeof(workspace) <= 8192`を**every target**で`_Static_assert`）:

| Region | Exact capacity / meaning |
| --- | --- |
| key | 255 bytes（`iter_next`） |
| value | 4096 bytes（`iter_next` only。get pathでは使わない） |
| previous key | 255 bytes |
| `has_previous` / previous key length | session側flag。first-row sentinelにlength 0を使わない |
| encoded values (packed) | **1143** bytes total = binding **183** + identity **84** + counter **32** ×4 + capacity **68** ×11。catalog index順に固定pack。targeted-get成功値のretained bytes |
| encoded snapshot views | 17 × `ninlil_bytes_view_t`（上記encoded valuesへborrow。call-localではない固定領域） |
| validated snapshot | `ninlil_model_runtime_store_validated_snapshot_t`（get-path `validate_snapshot`出力） |
| candidate binding copy | `ninlil_model_runtime_store_binding_t`（begin prevalidation後・Port前にcopy。以後read-only） |
| **row_validate_scratch（S3）** | **union** of `ninlil_model_domain_typed_record_t` / `ninlil_model_domain_witness_header_t` / `ninlil_model_domain_witness_chunk_t`（exact-profile family 5/6 CURRENT structural path only）。**scanner stackへlarge typed/witness bodyを置かない**。第二4096 value bufferではない |

S1 transport adapterは上記S2/S3領域を触らなくてよいが、**同一workspace type**のsizeof上限8192は共有する（S2/S3 fieldsがゼロ初期化で存在する）。

Scanner session/control objectの固定フィールド（state、txn/iterator opaque、sticky **terminal** primary status、non-terminal candidate flags、`profile_exact_active`、`profile_get_present_mask` / `family14_iter_seen_mask`（各 legal 17-bit `0x1ffff`）、coarse counters/flags、`has_previous`、reopen flag等）もRuntime-owned固定領域に置き、heapへ逃がしません。

**保守的static workspace天井**（private Normative bound名。public ABI / public header constantではない）:

| Name | Exact value | 意味 |
| --- | ---: | --- |
| `DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES` | 8192 | scanner workspace静的上限（doc bound。実装は`sizeof <= 8192`を全targetでstatic assert） |

8192はS1 scratch（4606）+ S2 encoded/views/validated/candidateとalignment headroomを含む。後続D2 sliceが本天井を超える必要がある場合、**そのsliceの実装/vectorより先に本章のNormative docでexact新ceilingを更新**しなければならない。silent raise・実装側だけの拡大は禁止。次を破ってはなりません。

1. heap / VLA / stack record buffer / 65,536 temp pathを使わない
2. 全ID集合や可変長row listをRAMへ保持しない
3. public symbol / public type / public constantとして露出しない
4. ESP32 task stackへaggregateを置かない
5. non-OK data検出のためのfull shadow copy bufferを追加しない
6. get path用に第二4096 value scratchを持たない

`DSR2_ESP_BOUND`は**当時のNormative exact ceiling**（現行8192）と4096 iter scratch / allocation 0を証明します（所有は§17.1）。forever-8192固定をclaimしてはならない。

### 15.6 `finalize` / `abort` / fence / result採用（D2-S0）

#### 単一cleanup tree（begin / advance failure / finalize / abort 共通）

全failureおよび正常終了cleanupは**exactに次の1 tree**だけを使う（12章: ACTIVE中の明示`iter_close`、`rollback`は未close childを暗黙consume、rollback後の`iter_close`禁止、`close`時live txn/iterator 0）。

1. iteratorがliveかつparent txnがまだACTIVEなら → `iter_close` exactly once。その後iteratorをliveとみなさない
2. transactionがliveなら → `rollback` exactly once。txnは戻り値にかかわらずconsumed。**rollback後にそのtxnのchildへ`iter_close` / `iter_next`を呼んではならない**（未closeだったchildはrollbackが暗黙consume済み）
3. fenceが必要なときだけ（rollback non-OK、unknown/unsafe shape、reuse unsafe）: live childrenがconsume済み（またはrollback暗黙consume済み）と分かってから `close` exactly once + `*inout_handle = NULL` + `reopen_required`
4. どちらのchild handleもreuseしない
5. **fully cleaned failure / 正常cleanup完了後の状態は`DONE`（unadoptedまたはadopt後）。`FAILED`はlive資源が残って`finalize`/`abort`待ちの間だけ**

#### finalize

`finalize`は上記cleanup treeを実行する。outcome集約は§15.2（terminal primary → profile candidate → future candidate → adopt/success）。

採用規則:

- **adopt**は次をすべて満たすときだけ: 状態が`EXHAUSTED`、**terminal sticky primaryなし**、`profile_mismatch` / `future_profile_candidate` / `recognizable_future_seen` **いずれもなし**、`rollback`がOK shape、provider contract shapeがvalid
- terminal primaryまたはcandidate-onlyの`finalize`はcleanupを行うが**never adopt**（`adopted`は0のまま。candidateは§15.2順で`UNSUPPORTED`等を返す）
- `FAILED`上の`finalize`はcleanupを行うが**never adopt**
- adopt失敗（rollback non-OK、shape fault、unknown unsafe status）ではresultはunadoptedのまま

**private result diagnostics（oracle-visible; public ABIではない）:** finalize/abortがpublishするprivate resultは、既存のstatus/adopted/reopen/cleanup/coarse countsに加え、少なくとも次をsessionから写す: `profile_exact_active`、`profile_mismatch`、`future_profile_candidate`、`profile_get_present_mask`、`family14_iter_seen_mask`。candidate-only / failure pathでもこれらの診断は写してよいが **`adopted`は0**。

`rollback` non-OK:

1. transactionはconsumedとみなす（再rollbackしない。残childは暗黙consume済みなので`iter_close`しない）
2. Storageをfence: `close` exactly once + `*inout_handle = NULL`（children consume後のみ）
3. `reopen_required`を立てる
4. sticky **terminal** primaryがあればそれを維持し、なければclosed mappingのrollback failureを返す
5. resultはunadopted。状態は`DONE`

Provider contract shape violation / unknown statusでreuse unsafeな場合も、同じtreeでlive childrenをconsumeしたあとfenceする。Cleanup failureはsticky **terminal** primaryを上書きしない。

#### abort

`abort`は常にresultをdiscard（unadopted）し、`OPEN` / `EXHAUSTED` / `FAILED`のlive資源を**同一cleanup tree**で破棄する。rollback non-OK / unsafe shape時のfence規則も同じ。成功abort後の状態は`DONE`（unadopted）です。

#### 第二cleanupとsession終端

`DONE`に対する`finalize`/`abort`/`begin`/`advance`再呼出は`NINLIL_E_INVALID_STATE`、Port call 0です。cleanup後sessionは死んでおり、再利用には明示的なfresh session初期化が必要です（§15.2規則8）。

### 15.7 Result publicationとalias政策（C11実装可能）

C11実装が満たすべきpublication / unchanged / alias規則:

1. **Pre-validation failure**（`INVALID_ARGUMENT` / `INVALID_STATE`でPort call 0）: scanner session state、workspace scratch contentsのうちcallが触る必要のない領域、caller result objectを変更しない。out statusだけ返す。
2. **Port-path failure with sticky terminal primary**: sticky terminal statusをscanner stateへ記録してよい。adopt済みresult flagはfalseのまま。caller result summaryを部分更新する場合は「unadopted / not authoritative」がobservableで、adopt境界（成功`finalize`のみ）前にauthoritative successと解釈させない。
3. **Successful `advance`（budget内OK rowsまたは終端）**: coarse counters/flags、non-terminal candidate flags、`family14_iter_seen_mask`、`has_previous`、previous-key scratchだけを更新してよい。final adopt resultは`finalize`成功までcallerへauthoritative公開しない。non-OK / terminal pathではprevious/`has_previous`/seen maskを不正に進めない。
4. **Successful adopt `finalize`**: rollback OK後にだけresult summaryをauthoritative trueへpublishする。publish前にfailureが確定した場合はresultをnone/unadoptedへ戻すか、当初からunadoptedのままにする。
5. **Alias（temporal API boundary; callごとの実引数だけ）:**
   - **`begin` / production profiled begin:** 当該callの実引数だけを検査する。session、full workspace、ops table object、handle slot、およびproduction profiled beginの`candidate` inputはpairwise non-overlap。違反はPort 0・`INVALID_ARGUMENT`・状態/workspace/candidate不変。**beginは`out_result`引数を持たない**ため、未渡し・未存在のfinalize/abort result objectをprevalidateしてはならない（不可能な「未来のresult」pairwise要求は禁止）。
   - **candidate copy後:** caller `candidate` pointerのlifetimeを要求しない。sessionが保持するのはworkspace内candidate copyのみ。後続`advance`/`finalize`/`abort`はcaller candidate pointerを再検査しない。
   - **`finalize` / `abort`:** 当該callの`out_result`を、session、**bound** workspace（candidate copyを含む全域）、**bound** ops table object、**bound** handle slotとpairwise non-overlapで検査する。違反はPort 0・`INVALID_ARGUMENT`・live state/workspace不変。expired caller candidate pointerは**検査対象外**（begin時点でlifetime終了済みであり、finalize/abortがそれをinspectできない・する必要もない）。
   - readonly input viewがworkspaceとaliasすることも禁止（当該callが受け取るreadonly引数がある場合のみ）。
   - **S4 exact-get 例外（§15.11.3）:** exact-get の key readonly input は `workspace->value` と disjoint 必須だが、`key[]` / `previous_key[]` への borrow は合法（Storage Port が call 中に key を copyするため）。workspace 他領域との key alias は禁止のまま。
6. **NULL/length shape**: zero lengthはdata NULLを許すview規則に12章/ D1 helperと同じく従う。non-zero length + NULL dataは`INVALID_ARGUMENT`またはcorruptionのclosed側へ倒し、silent skipしない。
7. **単一thread / owner**: scanner sessionは同時に1 owner contextだけが操作する。re-entrancyはpublic Runtime規則に従いD2 scanner APIをcallbackから再入させない。
8. **non-OK data**: §15.3のとおりdata bytesは無視・非採用。shadow比較による「部分書込検出」を実装要件にしない。

### 15.8 L2b1 oversized iterator path（removed / D2-aligned; D2-S6a）

**Status: removed / aligned.** L2b1 bootstrap orchestrator（`src/runtime/runtime_store_orchestrator.c`）の empty-namespace scan は caller-owned key 255 / value 4096 workspace を使い、`BUFFER_TOO_SMALL`（required key>255 または value>4096）を **即時 `NINLIL_E_STORAGE_CORRUPT`** とする。**reread 0 / temporary allocation 0 / 65,536-class heap path 0。** Allocator 引数は private L2b1 API から除去済み（public ABI 影響なし）。

1. 本章§2 / §15および12/14章の private namespace single value 上限4096 と BTS→CORRUPT（reread/allocationなし）へ収束
2. D2 scanner と同 contract（§15.3）
3. L2b1 success は Stage 5 完了でも D2 完了でもない（14章 L2b1 boundary と同じ）

### 15.9 Ordered D2 slice ledger（D2-S0..S6）

| Slice | 内容 | D2完了証明 |
| --- | --- | --- |
| **D2-S0** | 本節のNormative contract freeze。実装/vector変更なし。**Historical S0 freeze status:** S0 alone did not complete D2 / DSR1 / DSR2 at freeze time（spec only）。**Current status after S5:** D2 bounded scanner / DSR1_SCAN / DSR2_ESP_BOUND are complete via S1–S5 composition; this S0 row remains the historical freeze record and is not retroactively rewritten as implementation-complete | 否（S0単独） |
| **D2-S1** | scanner core: state machine、begin binds Port/handle/workspace、advance(row_budget)/finalize|abort(result) only、iter buffer、`has_previous` lex、§15.4 coarse class、mutation 0、uint64 checked counters。独立oracle + production bridge。**実装済み（D2 incomplete）** | 否 |
| **D2-S2** | **実装済み（D2 incomplete）:** production profiled begin only（required candidate; TEST transport beginはtest macro専用）、same-txn 17 exact get + completeness/validate/compare、typed get capacities、iterator reconciliation masks、mismatch/future mode skip、private result diagnostics、sibling profile oracle `domain-scan-profile-v1.json` / `ninlil-domain-scan-profile-v1-d2s2` + independent generator + production bridge。D2 complete / DSR1/DSR2 complete / Stage 5 / public Runtime / ESP hardwareをclaimしない | 否 |
| **D2-S3** | **実装済み（D2 incomplete）:** exact-profile時 family 5/6 CURRENT structural same-recordをscan pathから到達。closed catalog family5 `01`+family6 §7 全29 current subtypes（`10,11,20-27,30-34,40-42,50-52,60-64,7d-7f`）REQUIRED。business+`7d` → `ninlil_model_domain_validate_typed_record`（workspace typed scratch; public APIに large local 無し）。`7e`/`7f` → parse key + envelope + pure witness decode + key/body/header bijection + independent header mutates（flags/PVD/primary/identity/subtype/rev0/rtype）scan到達。status: `UNSUPPORTED` future non-terminal、後続current corrupt precedence（record_version/domain_format）; profile mismatch/future_profile skip S3 decode; BTS 4097/unknown subtype/lex OOO。sibling oracle `domain-scan-structural-v1.json` / `ninlil-domain-scan-structural-v1-d2s3` + D1 d1b3o SHA/count pin composition + S1 transport body-nonvalidation hash/ID pin + independent generator + production bridge。**member old/new・partial group・successor chain・cross-row PVD/cardinalityはD3。S4 exact-get追加なし。** D2 complete / DSR1/DSR2 / Stage 5 / public Runtime / ESP hardwareをclaimしない | 否 |
| **D2-S4** | **実装済み（D2 incomplete）:** same-snapshot production-private exact `get`（`OPEN`/`EXHAUSTED`、sole iterator live、row_budget/counters 不変）+ presence enum / borrowed value view + fixed-memory proof（single 4096 value buffer reuse; session に unused xref digest/kind/count なし; 全ID集合非保持）。sibling oracle `domain-scan-exact-get-v1.json` / `ninlil-domain-scan-exact-get-v1-d2s4` + independent generator + production bridge。D3 relationship/cardinality/orphan/backlink semantics は所有しない。D2 complete / DSR1/DSR2 / Stage 5 / public Runtime / ESP hardware を claim しない | 否 |
| **D2-S5** | **実装済み（D2 bounded scanner complete; Stage 5 incomplete）:** S1〜S4 + deps composition。`DSR1_SCAN` complete + `DSR2_ESP_BOUND` complete。production-private `ninlil_domain_scan_note_terminal_corrupt`（D3 corruption injection/aggregation seam only; D3 finding correctness is D3）。profiled budget 1/64、same-snapshot exact_get lifecycle（per-call status + counter/previous/get snapshots）、fresh-session restart from front with first post-restart `advance` budget=1 + front-key assert（not same-session budget resume）、changed-snapshot restart asserts new front key、FAILED cleanup restart、rollback failure sticky + unknown rollback fence-once、handle drift closes original only、future/mismatch/structural candidates then note → sticky CORRUPT outranks、state gates、`note_then_reject` / `note_exhausted`、note then advance/exact_get reject Port0、close/fence once、mutation0、full Port-trace equality。sibling oracle `domain-scan-composition-v1.json` / `ninlil-domain-scan-composition-v1-d2s5`（22 vectors / 21 kinds）+ independent generator（per-call `expected_status` / anti-false-pass / exact kind set）+ production bridge + `tools/domain_scan_dsr2_gate.py` complete + compiler `-Wvla`。S1–S4 and D1 JSON byte-for-byte frozen。**Does not claim Stage 5 / D3 semantics / D4 mutation / S6 orchestration / public Runtime / ESP-IDF compile / hardware** | **S1〜S5+deps で D2（bounded scanner）のみ証明。Stage 5全体は証明しない** |
| **D2-S6** | **部分実装済み（Stage 5 incomplete）:** S6a L2b1 BTS no-reread hardening + S6b production-private fail-closed seam `runtime_store_stage5_seam.{c,h}`（`ninlil_runtime_private` only; not `include/ninlil`）。L2b1 first → NEW_BOOTSTRAP_STAGE5_PENDING（scanner not invoked）/ EXISTING → begin_profiled + advance(64) + finalize → EXISTING_SCAN_ADOPTED_D3_PENDING（storage_recovery_complete=0）。TEST transport begin 禁止。mutation 0。新規D2 oracle不要。**Does not claim Stage 5 / D3 finding correctness / D4 / identity / health / public runtime_create / Bearer/clock/entropy / Stage9 / ESP-IDF/hardware** | D2を統合するだけで、S5未完了をD2完了に置換せず、D3/D4未完了をStage 5完了に置換しない |

**「S5 proves D2」の意味（D2-S0）:** S5 completionは、S1〜S5本体と、それらが要求する依存・vector/oracleが**すべて**完了していることの**bounded scanner composition**証明です。S4が未完了のまま（S1/S2/S3はimplementation completeでも **D2 incomplete**）、S5だけをcomplete宣言してはなりません。**D2 completionはS1〜S5 bounded scanner completeを意味し、Stage 5 / public Runtime completionはD3・D4および§1残gateが揃うまでfalseのままです。** S6は統合でありD2証明の代替でもStage 5証明でもありません。S0単独、L2a/L2b1、D1 codec完了、部分vector、body-only completeもD2完了宣言に使ってはなりません。

D3（cross-row semantic / cardinality / capacity / health / **witness member old/new・partial group・successor chain**）とD4（operation別mutation / convergence / FULL writer）は本ledgerの外です。**D3 の architecture / ordered slice ledger（D3-S0..S12）/ hybrid / corruption / outcome ladder 正本は §18。closed exact-1 modes / fixed context / `begin_profiled_d3s1` contract は §18.12（D3-S1a docs freeze; D3-S1 implementation complete は別 slice）。declared multi-count / same-txn multipass contract は §18.13（D3-S2a docs freeze; D3-S2 implementation complete は §18.2 / §18.13.19）。BLOB lifecycle / chunk stream contract は §18.14（D3-S3a docs freeze; D3-S3 implementation は別 slice）。`DSW1_ALL_OLD_NEW` contract は §18.15（D3-S4a docs freeze; D3-S4 implementation は別 slice）。`DSW2_SUPERSEDE_CHAIN` contract は §18.16（D3-S5a docs freeze; D3-S5 implementation は別 slice）。** D3-S0 / D3-S1a / D3-S2a / D3-S3a / D3-S4a / D3-S5a は docs freeze only のまま。**D3-S1 exact-1 / D3-S2 declared multi-count implementation は complete** だが **D3-S3 implementation / D3-S4 implementation / D3-S5 implementation / D3-S6..S12 / D3 overall / Stage 5 complete / Stage 5 D3 bind は claim しない**。§15 steps 1〜11の最終Stage 5 closed orderと§1 publish gateはD1+D2+D3+D4 compositionのRuntime objectiveのままです。

### 15.10 D2-S2 profile gateとone-iterator互換（D2-S2 Normative freeze）

**Decision identifier: D2-S2。** 本節はfamily 1〜4 integrity + exact profile gate + one-iterator reconciliationの**Normative freeze**であり、実装は production profiled begin / oracle / bridge / tests まで到達してよい。**S2 implementation complete ≠ D2 completion ≠ Stage 5 / public Runtime / ESP hardware completion。** S3–S5 は D2 bounded scanner complete; S6 seam は partial integration（Stage 5 incomplete）。L2b1 oversized allocator re-read（§15.8）は **removed / D2-aligned（S6a）**。

family1-4 corruption > profile unsupported を、**READ_ONLY transaction 1つ + zero-prefix iterator 1つ**と両立させる。`profile_mismatch` / `future_profile_candidate`は**non-terminal candidate**であり、`FAILED`へ遷移させずscanを止めない（§15.2）。

#### 15.10.1 Production API / no bypass

1. **Production private release（tests OFF）はprofiled beginだけを露出する。** private symbol名は`ninlil_domain_scan_begin_profiled`としてよい。`const ninlil_model_runtime_store_binding_t *candidate` **non-NULL必須**。`NULL` / optional / skip-gate production pathは**禁止**。
2. **S1 transport-only begin**は**TEST-build adapterのみ**: explicit test macroの下だけでcompile/declareし、tests-OFF release artifactから**absent**。S1 oracle（`domain-scan-v1.json` / `ninlil-domain-scan-v1-d2s1`）は**byte-for-byte frozen regression**として維持する。
3. **S6 / Stage 5 / production orchestrationはTEST transport beginを呼んではならない。** 必ずproduction profiled beginを使う。
4. Production profiled beginはprofile work完了後にS1 transport力学（txn/iterator ownership、cleanup tree、lex `advance`、fence）を**内部再利用**する。S1 frozen vectorsを破壊するin-place semantic置換でproduction bypassを作らない。
5. public C ABI / public status / public workspace type / new ADRは本freezeで**追加しない**。

#### 15.10.2 Candidate binding

1. Inputは`const ninlil_model_runtime_store_binding_t *candidate`（typed binding only）。**production profiled beginの実引数**であり、`out_result`ではない。
2. **begin-time prevalidation（当該callの実引数のみ）:** `candidate` non-NULL、かつ session / full workspace / ops table object / handle slot / candidate がpairwise non-overlap。**beginは`out_result`を持たないため、result objectをalias検査に含めてはならない**（§15.3 / §15.7）。違反は`INVALID_ARGUMENT`、Port 0、状態/workspace/caller candidate不変。
3. prevalidation成功後・**最初のPort call前**にworkspaceのcandidate copy領域へ**exact copy**する。copy後は**caller candidateのlifetimeを要求しない**。scannerは以後caller pointerを読まない・再検査しない。
4. **`finalize` / `abort`:** その時点の`out_result`を session / bound workspace（**candidate copyを含む**）/ bound ops / bound handle slot とpairwise non-overlapで検査する。expired caller candidate pointerは検査対象外（§15.7）。
5. scannerはruntime config validation resultからの**projectionを行わない**（L2a/bootstrap model側の責務）。compareは`ninlil_model_runtime_store_compare_binding`のみ。

#### 15.10.3 Same-transaction Port / model order（existing bound namespace）

本pathは**L2b1後のexisting bound namespace**向けである。new bootstrap（0/17 empty → write plan）はL2b1 orchestratorの責務であり、domain scanner profiled beginの成功pathではない。

**Closed order（production profiled begin）:**

1. bind Port/handle/workspace + candidate copy（Port 0）
2. Storage `begin(READ_ONLY)` **exact 1**
3. `get` **exact 17**、key ID **1..17 catalog順**（binding→identity→counter×4→capacity×11）
4. completeness → `validate_snapshot` → `compare_binding`（Port 0 model）
5. zero-prefix `iter_open` **exact 1**（prefix `{NULL,0}`）→ state `OPEN`

**Completeness:** 17 keys **all present**必須（present mask == `0x1ffff`）。**missing / partial / empty（0/17含む）はterminal `NINLIL_E_STORAGE_CORRUPT`。当該beginは`iter_open`を呼ばない。** cleanup treeでtxnをconsumeし、fully cleaned failureは`DONE`（unadopted）。

**Get value capacities（exact by key type; second 4096 buffer禁止）:**

| key IDs | typed capacity |
| --- | ---: |
| 1 binding | 183 |
| 2 identity | 84 |
| 3..6 counters | 32 each |
| 7..17 capacities | 68 each |

**Storage `get` call shape（ABI; atomic key/value pairではない）:**
`get`のmutable outputは**`inout_value` exactly 1つ**だけである（`iter_next`のkey+value atomic pairとは別規則）。各`get` call前にscannerは次を満たす:

1. `inout_value.length = 0`
2. `inout_value.capacity` = 当該key typeのtyped capacity（上表 exact）
3. `inout_value.data` = workspace packed encoded slot for that key（non-NULL; capacity>0）

`inout_value.data` と `inout_value.capacity` はcaller-owned descriptorであり、providerが書き換えてはならない（`length`とbuffer contentsだけがgetの出力）。return後に `data` がexact slot pointerでない、または `capacity` がtyped capacityでない場合はunsafe provider shape → terminal `STORAGE_CORRUPT`（children consume後fence）。成功`OK` valueは同じ`inout_value` bufferへ書かれ、workspace packed encoded valuesとしてretainedする（viewsがborrow）。

**Get status / `inout_value` length / poison / fence（closed）:**
下記の`length`は**常に`inout_value.length`のみ**を指す。key lengthや「both lengths」表現は`get`に適用しない（key/value両length 0は`iter_next`終端規則のみ。§15.3）。

| Status + observable `inout_value` shape | Outcome |
| --- | --- |
| `OK` + `length` ≤ typed capacity + (`length`>0 ⇒ data non-NULL) | accept; set present bit; retain `length`/bytes |
| `OK` + `length` > capacity / NULL data with `length`>0 | terminal `STORAGE_CORRUPT` |
| `NOT_FOUND` + `inout_value.length == 0` | absent（present bit 0） |
| `NOT_FOUND` + `inout_value.length != 0` | terminal `STORAGE_CORRUPT` |
| `BUFFER_TOO_SMALL` | terminal `STORAGE_CORRUPT`。**reread 0 / allocation 0**。ch12-validなrequired `inout_value.length`非0を第二shape violationに数えない。data非採用 |
| other known non-OK + `inout_value.length == 0` | 14章closed mapping（BUSY→`WOULD_BLOCK`、NO_SPACE→`CAPACITY_EXHAUSTED`、IO→`STORAGE`、`UNSUPPORTED_SCHEMA`→`UNSUPPORTED`、`COMMIT_UNKNOWN`→`STORAGE_COMMIT_UNKNOWN`、等）。**Port `UNSUPPORTED_SCHEMA`はPort failureであり`future_profile_candidate`ではない** |
| other non-OK + `inout_value.length != 0`（BTS除外） | terminal `STORAGE_CORRUPT` |
| unknown status / unsafe shape | terminal corrupt + children consume後fence（§15.6） |

terminal get/model failure時: sticky primary記録、**`iter_open` 0**、§15.6 cleanup、adopt 0。

#### 15.10.4 Model mapping（validate / compare）

| Model result | Session effect | Iterator |
| --- | --- | --- |
| `validate_snapshot` → `NINLIL_E_STORAGE_CORRUPT` | sticky terminal CORRUPT | **no** `iter_open` |
| `validate_snapshot` → `NINLIL_E_UNSUPPORTED` | non-terminal `future_profile_candidate=1`（`profile_exact_active=0`） | open iterator |
| `validate_snapshot` → `NINLIL_OK` かつ `compare_binding` → `BINDING_EXACT` | `profile_exact_active=1`；mismatch/future flags 0 | open iterator |
| `validate_snapshot` → `NINLIL_OK` かつ `compare_binding` → `BINDING_UNSUPPORTED` | non-terminal `profile_mismatch=1`（`profile_exact_active=0`） | open iterator |
| `validate_snapshot` / `compare_binding`が上記以外のstatus、またはcomparison enumがclosed集合外 | sticky terminal CORRUPT | **no** `iter_open` |

`validate_snapshot`内のcorrupt>unsupported集約（CRC/shape vs record version）はL2a pure model正本を再実装せず呼ぶ。CRC/malformed shapeはcorrupt、unsupported record version等はUNSUPPORTED。

#### 15.10.5 Iterator reconciliation（provider same-snapshot consistency; not S4）

sessionは少なくとも次を保持する（private; oracle-visible diagnosticsへpublish可）:

| Field | Meaning |
| --- | --- |
| `profile_get_present_mask` | get path present bits。legal 17-bit `0x1ffff`。production success pathではbegin後 `0x1ffff` |
| `family14_iter_seen_mask` | iteratorでreconcile済みcatalog bits。legal 17-bit `0x1ffff` |
| `profile_exact_active` / `profile_mismatch` / `future_profile_candidate` | gate結果 |

**exact catalog key → key ID route**（L2a key grammar; valueは見ない）:

| Match | Key bytes（current root `4e494e4c494c0001`） | key ID |
| --- | --- | ---: |
| binding | length 9、`family=0x01` | 1 |
| identity | length 9、`family=0x02` | 2 |
| counter | length 10、`family=0x03`、suffix `1..4` | 3..6 |
| capacity | length 10、`family=0x04`、suffix `1..11` | 7..17 |

各OK iterator row:

1. **exact catalog key:** bitが既に立っていればterminal CORRUPT（dup; lexでも検出）。そうでなければ iterator value **lengthとbytes**がtargeted-get retained bytesと**完全一致**すること。不一致はterminal CORRUPT（provider same-snapshot inconsistency）。一致後にbit set + checked `family14_row_count`。本義務は**S2 integrity**であり、S4 domain cross-reference seamではない。
2. **f1–4 prefix-shapedだがnoncatalog / malformed**（例: `0x03` suffix 0/5+、length 10の`0x01`、catalog外suffix）: **terminal** family1-4 corruption（profile candidateをoverride可）。
3. **non-family1-4:** §15.10.6。

**clean terminal `NOT_FOUND`（両length 0）:** `family14_iter_seen_mask == profile_get_present_mask`（production success pathでは both `0x1ffff`）を要求。不一致はterminal `STORAGE_CORRUPT`であり、`EXHAUSTED` successへ進まない。一致時のみ`EXHAUSTED`（candidate flagsは保持可）。

iteratorはlifetime中**exact 1**。prefix分割やsecond iterator禁止。restartはtxn/iterator close後の先頭から。

#### 15.10.6 Mismatch / future-profile mode vs exact-profile mode

**`profile_mismatch`または`future_profile_candidate`（exact-profile inactive）:**

1. lex / transport / status-shape / BTS / family1-4 routing / reconciliationを**継続**する（scan停止しない）。
2. **non-family1-4 rowはすべてskip:** `classify_row` 0、domain body decode 0、family 5/6 structural 0。ただしOK rowとして**successfully visited**し、`ok_row_count` checked incrementとprevious-key更新は行う。profile candidateをoverrideしない。
3. family1-4 corruption、transport/shape unsafe、lex dup/ooo、BTS、reconciliation failureは**terminal**でありprofile candidateを**override**する。
4. family1-4 terminal corruption 0のままcandidateだけなら`finalize`で`NINLIL_E_UNSUPPORTED`（domain decode/mutation 0、`adopted=0`）。

**`profile_exact_active`:**

1. non-family1-4は既存§15.4 `classify_row`分岐を許可する。
2. **S2はcurrent domain body structuralを完成しない。** envelope/body local structuralは**S3**。S2はexact-profile pathをactiveにするだけ。

#### 15.10.7 Finalize precedence / diagnostics

`finalize` outcome（cleanup後）は§15.2と同順でclosed:

1. sticky terminal primary
2. `profile_mismatch` / `future_profile_candidate` → `NINLIL_E_UNSUPPORTED`
3. `recognizable_future_seen` → `NINLIL_E_UNSUPPORTED`（S1 seam; Stage 5最終証明は後続composition）
4. else adopt/success path

private result diagnostics（§15.6）: `profile_exact_active`、`profile_mismatch`、`future_profile_candidate`、`profile_get_present_mask`、`family14_iter_seen_mask`をoracle-visibleにpublish。candidate/failureでは`adopted=0`。

#### 15.10.8 S2 acceptance ownership（vectors後続; schemaは§17.1.2）

実装PRが最低限所有するacceptance（因果・false-pass防止を含む）:

- exact profile success path
- semantic field mismatch → `profile_mismatch` / `UNSUPPORTED`
- future record version → `future_profile_candidate` / `UNSUPPORTED`
- corrupt + future 混在 → CORRUPT precedence
- every missing key（partial/empty）→ CORRUPT、**`iter_open` 0**
- get BTS → CORRUPT、reread/alloc 0
- get status poison / fence
- port_trace: 17 `get` catalog順、その後ちょうど1 `iter_open`
- terminal get/model failureでiteratorなし
- mismatch継続 + domain malformed skip（non-family）
- 後続f1-4 malformedがprofile candidateをoverride
- iterator value ≠ get retained → CORRUPT
- iterator missing one catalog key → CORRUPT（not EXHAUSTED success）
- `iter_open` count == 1 only
- mutation 0
- workspace `sizeof <= 8192` every target
- **S1 `domain-scan-v1.json` regression unchanged（byte-for-byte）**

**因果assertion例（must）:** production bootstrap生成bytesではなくoracle literal hexでprofile bytesを供給すること; optional-NULL gateでadoptしないこと; second iteratorを持たないこと。

#### 15.10.9 Completion boundary

| Claim | S2 freeze / future completion |
| --- | --- |
| D2-S2 Normative freeze（本節） | **本doc更新で成立** |
| D2-S2 implementation complete | profiled begin + gate + reconciliation + oracle/bridge/testsが本節を満たしたとき（実装PRで到達可）。なお**D2 completeではない** |
| D2 complete | S1–S5 + deps（§15.9） |
| Stage 5 / public Runtime / ESP hardware | D3/D4/§1残gate後。S2 successで置換禁止 |

### 15.11 D2-S4 same-snapshot exact `get` seam（Normative freeze）

**Decision identifier: D2-S4。** 本節はsame READ_ONLY snapshot上の**production-private exact-get API**とfixed-memory cross-reference **mechanism**のNormative freezeである。全ID集合のRAM保持は禁止。D3 relationship / cardinality / orphan / backlink semantics、public Runtime ABI/status、S5/S6、ESP hardwareは**out of scope**。**S4 implementation complete ≠ D2 completion ≠ Stage 5 / public Runtime / ESP hardware completion。** D2はS1〜S5が揃うまでincompleteのまま。

#### 15.11.1 Production-private API / no public ABI

1. **tests-OFF release private artifact**に露出する exact-get は production-private だけである。public `include/ninlil/*` header / export symbol / new public status / public workspace type / new ADRを**追加しない**。
2. 推奨private symbol名: `ninlil_domain_scan_exact_get`。既存 scanner session 上の API であり、second session / second txn / second iterator を開かない。
3. 合法状態は **`OPEN` と `EXHAUSTED` のみ**（いずれも bound READ_ONLY txn live かつ sole zero-prefix iterator live）。`IDLE` / `DONE` / `FAILED` は `NINLIL_E_INVALID_STATE`、**Port call 0**、session/caller output 不変。
4. sticky terminal primary 後（`FAILED`）の exact-get は **reject**（`INVALID_STATE`、Port 0）。cleanup / fence は finalize/abort の所有。
5. 本APIは **row_budget を消費しない**。`ok_row_count` / `family14_row_count` / `current_domain_key_count` / previous-key / iterator position / `has_previous` を成功 path で変更しない。iterator は live のまま。`iter_open` は session lifetime 中 exact 1 のまま。

#### 15.11.2 Presence enum / observation result（not full-ID set）

private presence と observation/result を次のとおり固定する（session に unused xref digest/kind/count を**持たない**; D3 が semantic aggregation を所有）:

| Field | Meaning |
| --- | --- |
| presence enum | exact closed: `ABSENT` / `PRESENT` |
| value view | `PRESENT` 時のみ `workspace->value` を borrow する read-only view。`ABSENT` は empty view（length 0、data NULL） |
| present zero-length | `PRESENT` + length 0。presence enum で `ABSENT` と区別する（value length だけに依存しない） |

**成功 shape（Port path 成功後だけ caller output を書く）:**

1. clean `NOT_FOUND` + `inout_value.length == 0` → return `NINLIL_OK` + `ABSENT` + empty view
2. `OK` + length ≤ 4096 +（length>0 ⇒ data non-NULL）→ return `NINLIL_OK` + `PRESENT` + view（length>0 は `data=workspace->value`、length 0 は empty view でも presence=`PRESENT`）
3. **Port-path failure**（terminal）: caller `out_result` は **不変**。scanner は sticky primary を記録し state=`FAILED`（`advance` と同じ）。cleanup tree は呼ばない

**Borrowed lifetime:** 成功 view は **次の** `advance` / `exact_get` / `finalize` / `abort` まで有効。それ以降の参照は caller contract 違反。反復 exact-get は value buffer を上書きし、過去 ID/value を session に保持しない（full-ID set 禁止の固定メモリ証明）。

#### 15.11.3 Key input shape / S4 alias exception

1. key: `data` non-NULL、`length` exact `1..255`。NULL / length 0 / length>255 は `INVALID_ARGUMENT`、Port 0、session/output 不変。
2. Storage Port は call 中に key を copy する前提で、key は **external storage**、または scanner workspace の **`key[]` / `previous_key[]` 領域**を borrow してよい。
3. key range は **address-safe**（overflow なし）かつ **`workspace->value`（exact-get 出力領域）と disjoint** 必須。value 領域との alias は `INVALID_ARGUMENT`。
4. **S4 狭い例外 / 明確化（§15.7 generic readonly-input alias 規則）:** exact-get の key readonly input が workspace 全体と一律禁止ではなく、**`key[]` / `previous_key[]` への borrow だけを合法**とする。workspace の他領域（`value[]` / `encoded_values[]` / views / validated / candidate / row_validate_scratch 等）への key alias は `INVALID_ARGUMENT`。second max-key buffer への copy は **evidence が必要と証明するまで禁止**（S4 既定は copy しない）。
5. `out_result` は session / bound workspace / bound ops table object / bound handle slot と pairwise non-overlap。違反は `INVALID_ARGUMENT`、Port 0、session/output 不変。key と `out_result` も non-overlap。

#### 15.11.4 Prevalidation / live binding gates

Port 呼び出し前（失敗時 Port 0）:

1. session / out_result non-NULL
2. state ∈ {`OPEN`,`EXHAUSTED`}（上記以外は `INVALID_STATE`。bound field を読まない）
3. key basic shape（data non-NULL、length 1..255。違反は `INVALID_ARGUMENT`）
4. legal live state における bound storage ops / handle slot / workspace non-NULL、required ops（`get` 含む）non-NULL、`txn_live` かつ `iter_live`。違反は caller argument error へ丸めず sticky `STORAGE_CORRUPT` + `FAILED`
5. handle slot **exact match**（begin-time original; authority live 中）。不一致は sticky `STORAGE_CORRUPT` + `FAILED` + `fence_pending`
6. key range / alias（§15.11.3。違反は `INVALID_ARGUMENT`、session/output 不変）

#### 15.11.5 Single storage `get` / descriptor / status matrix

**Port 順序:** 各成功 prevalidation 後、**exact 1** 回の Storage `get` を bound READ_ONLY txn に対して行う。iterator は閉じない・進めない。allocation / reread / cleanup tree は exact-get call 内で **0**。

**call 前 mutable output descriptor（唯一の 4096 value buffer）:**

1. `inout_value.data = workspace->value`
2. `inout_value.capacity = 4096`
3. `inout_value.length = 0`

`data`/`capacity` は caller-owned descriptor。provider rewrite は unsafe shape。

| Status + observable shape | Outcome |
| --- | --- |
| `OK` + length ≤ 4096 + (length>0 ⇒ data non-NULL) + descriptor intact | success PRESENT |
| `OK` + length > capacity / length>0 with NULL data | terminal `STORAGE_CORRUPT` |
| `NOT_FOUND` + length == 0 | success ABSENT |
| `NOT_FOUND` + length != 0 | terminal `STORAGE_CORRUPT`（poison） |
| `BUFFER_TOO_SMALL` | terminal `STORAGE_CORRUPT`。**reread 0 / allocation 0**。ch12-valid required length 非0を第二 shape に数えない |
| other known non-OK + length == 0 | 14章 closed mapping（BUSY→`WOULD_BLOCK`、NO_SPACE→`CAPACITY_EXHAUSTED`、IO→`STORAGE`、`UNSUPPORTED_SCHEMA`→`UNSUPPORTED`、`COMMIT_UNKNOWN`→`STORAGE_COMMIT_UNKNOWN`、CORRUPT→`STORAGE_CORRUPT`） |
| other non-OK + length != 0（BTS 除外） | terminal `STORAGE_CORRUPT` |
| unknown raw status / descriptor rewrite（data/capacity） | terminal `STORAGE_CORRUPT` + **fence_pending**（cleanup は finalize/abort） |
| `COMMIT_UNKNOWN`（known fence status） | map + **fence_pending** |

terminal path: sticky primary、state=`FAILED`、`out_result` 不変。Finalize/abort が cleanup tree を所有し sticky primary を保持する（§15.6）。

#### 15.11.6 No automatic D3 / future internal ordering contract

1. S4 は D3 relationship / cardinality / orphan / backlink を **自動実行しない**。peer key 導出・aggregate も行わない。
2. profile mismatch / `future_profile_candidate` / recognizable future でも scanner が **自動 exact-get を起動しない**（seam は caller が明示呼出するときだけ）。
3. **Future internal ordering contract（D3 以降が従う; S4 が mechanism だけを固定）:**
   1. S3 structural success on current row（or transport coarse accept）
   2. copy required descriptor / commit lex state（previous-key 等; advance 側）
   3. optional exact-get overwrites `workspace->value`（borrowed）
   4. consume borrowed result **before** next exact-get / advance
4. Fixed-memory proof in S4 = exact lookup mechanism + borrowed result + **既存 single 4096-byte value buffer の reuse**。xref digest/kind/count session fields は D3 まで追加しない。

#### 15.11.7 Non-claims / workspace

1. heap / VLA / recursion / second 4096 value buffer / full-ID set 禁止
2. workspace `sizeof <= 8192` 維持
3. mutation Port calls 0（`put`/`erase`/`commit`/`open` 0）
4. D2 / DSR1 / DSR2 / Stage 5 / public Runtime / ESP hardware を claim しない

#### 15.11.8 Acceptance ownership（implementation + oracle）

最低限の conformance（unit + sibling oracle/bridge）:

- present while iterator live; missing; present zero-length; get in `EXHAUSTED`
- 4096 boundary; `BUFFER_TOO_SMALL`/4097 without reread
- pointer/capacity rewrite; `NOT_FOUND` poison
- known IO / BUSY / CORRUPT / UNSUPPORTED / COMMIT_UNKNOWN と unknown raw status
- state gates; key length/null/alias; handle drift
- repeated gets overwrite borrowed value without retaining IDs
- row_budget/counters unchanged; iterator resumes; `iter_open` remains 1
- profile mismatch/future no automatic get; sticky failure then exact_get rejected
- rollback/close/fence precedence; mutation0; workspace/source gates

## 16. Status precedence

Port call/shapeのearlier primary failureは14章closed mappingを維持します。Precedenceはphase境界ごとにclosedです。次の四段は**最終Stage 5 composition**（D2 scanner + D3 cross-row/health + 残gate）が守る順序です。D2単独・D2-S5単独が全段を証明するわけではありません。

1. family 1〜4 current key/value CRC/shape/length/completeness failure → `NINLIL_E_STORAGE_CORRUPT`
2. family 1〜4 integrity後のprofile mismatch/future profile → `NINLIL_E_UNSUPPORTED`。ここでdomain decode/mutationを行わない
3. Exact profileでのcurrent domain CRC/shape/length、partial group、orphan、duplicate/order、digest/revision、counter/capacity不一致 → `NINLIL_E_STORAGE_CORRUPT`
4. Exact profileかつcurrent domain corruption 0でrecognizable future root/record versionだけ → `NINLIL_E_UNSUPPORTED`

言い換え（Stage 5必須の保存順序）: **family1-4 corruption > profile unsupported > exact-profile current corruption > recognizable future unsupported**。

**D2 / D2-S5が証明すること:**

- scanner-detectable / transport / framing / lex / coarse classification / family1-4 integrity+profile gate（S2）/ same-record structural（S3）に由来する corruption と future の相対順序
- D2-detectable corruption が recognizable future より常に勝つこと（`DSR1_SCAN`のD2-detectable corrupt>future）
- 後続D3が同じsnapshot/session結果へcross-row corruption findingを投入したとき、そのcorruptionがfutureより上位に出る**exact mechanism / aggregation seam**（D3がfindingを供給する前提。D2はpartial group / orphan / counter / capacity / health の正しさ自体を証明しない）

**D2 / D2-S5が証明しないこと:** partial group、orphan、counter upper-bound/unique、capacity recompute一致、durable health reconstruction、およびそれらを含む§16 level 3の全集合。それらはD3。recovery mutation/convergenceはD4。

Exact profile domain scan内でfutureと**D2-detectable** current malformedが混在すればcorruptです。Current rootのunknown subtypeをfutureとしてsilent ignoreしません。Global scanのatomic iterator pairが4096 bytesを超えるrowを返した場合はkeyだけを信用せずcorruptです（D2-detectable）。

S2 one-iterator互換・production profiled begin・get completeness・iterator mask reconciliationの正本は§15.10。profile mismatch / future profileはnon-terminal candidateのままiteratorを継続し、family1-4 terminal corruption / transport / lex / BTS / reconciliation failureが見つかればcorruptがcandidateをoverrideする。

**D2-S1限定**: S1 transport adapterはtransport / shape / lex order / §15.4 coarse classification（terminal vs candidate分離含む）だけを確立します。S1は上記Stage 5 four-level precedenceの最終証明をclaimしてはなりません。**D2-S2**はfamily1-4 integrity + profile gate + one-iterator reconciliation（§15.10）まで。D2-detectable current domain structuralはS3（`profile_exact_active`時）、cross-rowおよびwitness member old/newはD3、D2-detectable corrupt>future compositionとD3投入seamはS5、Stage 5最終precedenceはD2+D3 compositionです。

## 17. Mandatory D0/D1/D2 vectors

D3 invariant / vector の slice ownership 表は **§18.6**（D3-S0）。closed exact-1 mode / fixed context は **§18.12**（D3-S1a）。declared multi-count / same-txn multipass は **§18.13**（D3-S2a）。BLOB lifecycle / chunk stream は **§18.14**（D3-S3a）。`DSW1_ALL_OLD_NEW` closed contract は **§18.15**（D3-S4a）。`DSW2_SUPERSEDE_CHAIN` closed contract は **§18.16**（D3-S5a）。本節の DSI1 / DSW* / DSC* / DSH1 行は mandatory case 名の正本であり、D3-S0 / D3-S1a / D3-S2a / D3-S3a / D3-S4a / D3-S5a 単独で green にはならない。

- `DSK1_KEY_CATALOG`: 全subtype exact key golden、unknown kind/subtype/root version
- `DSV1_RECORD_BOUNDARY`: 各body min/max、4096/4097、chunk 3072/3073、trailing/short/CRC
- `DSI1_BACKLINK`: primary/index exact、missing、orphan、collision raw mismatch、revision conflict
- `DSW1_ALL_OLD_NEW`: create/replace/erase、1/8/9/199/256 members、1/2/25/32 chunks、all-old/all-new/mixed/partial（D1 pure witness codec golden + D2-S3 same-record header/chunk scan到達 + D3 member old/new cross-row。所有を混ぜてstep 5をownerlessにしない）
- `DSW2_SUPERSEDE_CHAIN`: W1 ACTIVE / W2 absent、W1 SUPERSEDED / W2 ACTIVE、複数predecessor、successor欠損、head advance crash境界（successor/supersede chainはD3 cross-row。header localはD1/D2-S3）
- `DSW3_RETIRE_CLEANUP`: SUPERSEDED→RETIRED unknown両truth、semantic head/incoming successor参照、oldest-first chunk partial cleanup、ACTIVE partial拒否（D3 cross-row主体。local framing依存はD1/D2-S3）
- `DSC1_COUNTERS`: gap、retained max以下/超過、zero/duplicate/wrap、visited cleanup gap
- `DSC2_CAPACITY`: 11 kind used/reserved exact、overflow、double count、manifest/chunk accounting、high-water
- `DSH1_HEALTH`: priority 1..8 source、重複count 0、publish gate
- `DSR1_SCAN`: row budget 1/64、restart先頭、same snapshot get、rollback failure、**D2-detectable** corrupt>future precedence（cross-row orphan/partial/counter/capacity/healthのfull corrupt>futureはD3統合。D2自身のDSR1 caseは弱めない）
- `DSR2_ESP_BOUND`: **当時のNormative exact** workspace ceiling、VLA/recursion/stack record 0、4096 scratch、65,536 allocation 0
- `DSD1_LOGICAL_DELIVERY`: APPLICATION_FIRST、CANCEL_FIRST、later matching APPLICATION、binding conflict、same logical delivery/different attempt、reply-kind single key replacement
- `DSC3_CLEANUP_PHASES`: remote ATTEMPT phase 1、local ATTEMPT+INDEX pair phase 2、fence join/leave/recreate、phase COMMIT_UNKNOWN all-old/all-new、cleanup中submission/ingress WOULD_BLOCK
- `DSH2_HEALTH_GOLDEN`: source/stage/method/timer/counter/fence numeric registry、exact HEALTH_SOURCE_ID/COMMIT_FENCE_DIGEST、Delivery counter exhaustion dedup
- `DSO1_OPERATION_BUILDERS`: kind 1..21全variantのsubject ID、retention kind/key、allowed role、HEAD companion、predecessor、member ceiling、named-hook mapping
- `DSO2_AUTOMATIC_TRANSITIONS`: ATTEMPT/REVERSE_REPLY kind 6 send operation generation、TxGate no-send反復、Bearer-return count、reply BLOB close、SEND_COUNTER MAX、Command timeout/evidence-close/deadline-terminal、Event timeout/park/availability resume kind 14 phase/identity、explicit resume kind 15分離

### 17.1 D2 slice別vector ownership（D2-S0）

| Slice | Mandatory ownership | 完了条件の注意 |
| --- | --- | --- |
| D2-S0 | vector/oracle追加なし。本ledgerと§15 contractだけ | spec freeze ≠ implementation |
| D2-S1 | `DSR1_SCAN` transport subset + `DSR2_ESP_BOUND` skeleton の**ownership**。独立machine-readable oracle artifactを **`spec/vectors/domain-scan-v1.json`**、format **`ninlil-domain-scan-v1-d2s1`** として固定（schemaは§17.1.1）。**S2以降も本artifactはbyte-for-byte frozen regression**。D1 JSONへscanner fieldを追加しない | S1 ownershipのみ。**DSR1/DSR2 completeおよびD2 completeをclaimしない** |
| D2-S2 | family 1〜4 integrity + exact profile gate + §15.10 one-iterator reconciliation。sibling oracle **`spec/vectors/domain-scan-profile-v1.json`**、format **`ninlil-domain-scan-profile-v1-d2s2`**（§17.1.2）+ independent generator + production profiled-begin bridge + unit acceptance。**実装済み（D2 incomplete）** | domain structural全体はS3。**DSR1/DSR2/D2 completeをclaimしない** |
| D2-S3 | current domain structural/same-recordをscan pathから到達させるvectors。**witness header+chunk same-record framing/matrixのscan到達**（D1 witness pure codec依存。member old/new・chainはD3）。sibling oracle **`spec/vectors/domain-scan-structural-v1.json`**、format **`ninlil-domain-scan-structural-v1-d2s3`**（§17.1.3）。依存D1 body hexは `ninlil-domain-store-v1-d1b3o` authority（byte-for-byte frozen; S3は同fileへscanner fieldを追加しない） | **D2-S3 implementation complete**（S1–S5の1ピース。**D2/DSR1/DSR2/Stage5 completeをclaimしない**） |
| D2-S4 | same-snapshot exact `get` seam、fixed-memory cross-reference mechanism（§15.11; full-ID set 禁止）。sibling oracle **`spec/vectors/domain-scan-exact-get-v1.json`** / format **`ninlil-domain-scan-exact-get-v1-d2s4`**（§17.1.4）+ independent generator + production bridge + unit acceptance。**実装済み（D2 incomplete）** | 全ID集合RAM保持テストを合法化しない。D3 semantics は所有しない |
| D2-S5 | **実装済み:** `DSR1_SCAN` complete（**D2-detectable** corrupt>future + D3 corruption投入seam）+ `DSR2_ESP_BOUND` complete。sibling oracle **`spec/vectors/domain-scan-composition-v1.json`** / format **`ninlil-domain-scan-composition-v1-d2s5`**（§17.1.5）+ independent generator + production bridge + unit acceptance。S1〜S4 ownership vectorと依存D1 body pin | **S1〜S5+deps で D2（bounded scanner）証明。Stage 5 / D3 / D4 / public Runtime / ESP-IDF / hardware は証明しない**（S6 seam は §15.13 の partial integration） |
| D2-S6 | **S6a/S6b 実装済み（Stage 5 incomplete）:** 新規D2 oracleを必須化しない。private seam integration matrix + source gates。Stage 5 orchestration integration testはD2完了の代替にもStage 5完了の代替にもならない | S6 successでStage 5 / public Runtime claim禁止 |

D0 completionは本章と12/13/14/16のmirror矛盾0です。D1 completionはPort call 0のkey/record/witness pure codecと全golden、**D2 completionはS1〜S5および依存が揃ったmutation 0 bounded scanner composition証明**です（partial group / orphan / counter / capacity / health の正しさは含まない）。D2-S0はNormative固定のみでimplementation pendingです（historical; 現在 D2 は S1–S5 で complete）。**D3-S0（§18 冒頭–§18.11）は architecture docs freeze only。D3-S1a（§18.12）は closed modes / fixed context / private API contract の docs freeze only（historical; 実装完了へ書き換えない）。D3-S1 exact-1 implementation は complete（§18.2 / §18.7 / §18.12.9 current status）。D3-S2a（§18.13）は declared multi-count / same-txn multipass の docs freeze only（historical; 実装完了へ書き換えない）。D3-S2 implementation は complete（§18.2 / §18.13.19 current status; D3 incomplete / Stage 5 未接続）。D3-S3a（§18.14）は BLOB lifecycle / chunk stream の docs freeze only（historical; 実装完了へ書き換えない）。D3-S4a（§18.15）は DSW1_ALL_OLD_NEW の docs freeze only（historical; 実装完了へ書き換えない）。D3-S5a（§18.16）は DSW2_SUPERSEDE_CHAIN の docs freeze only（historical; 実装完了へ書き換えない）。D3-S3 implementation / D3-S4 implementation / D3-S5 implementation / D3-S6..S12 と D3 overall は incomplete。** **Stage 5全体・public Runtime・SQLite recoveryの完成はD2完了後も、D3/D4および§1残gateが揃うまで主張しません。**

D1は上記case名だけで完了扱いせず、`spec/vectors/domain-store-v1.json`をmachine-readable正本として追加します。各caseはinput semantic fields、expected complete key/value hex、全SHA-256/CRC、expected status、required workspace bytesを持ち、production codecとは独立したvector generatorとのbyte equalityをCI gateにします。D0はformat contract、実hex oracleの追加はD1 deliverableです。**既存`domain-store-v1.json`はD1 authorityのまま残し、D2 scanner/fault/call-trace vectorを同schemaへ押し込めない。**

### 17.1.1 D2-S1 oracle artifact（Normative freeze）

| Field | Exact value |
| --- | --- |
| path | `spec/vectors/domain-scan-v1.json` |
| format | `ninlil-domain-scan-v1-d2s1` |
| version | `1` |
| independent generator | `tools/domain_scan_vector_gen.py`（production Cをinvoke/translateしない） |

Top-level object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | number | artifact schema version; exact `1` |
| `format` | string | exact `ninlil-domain-scan-v1-d2s1` |
| `scope` | string | S1 ownership prose; must not claim DSR1/DSR2/D2 complete |
| `workspace` | object | `key_capacity=255`, `value_capacity=4096`, `previous_key_capacity=255`, `ceiling_bytes=8192` |
| `vectors` | array | S1 lifecycle / row-budget / call-trace / outcome cases |

Each vector object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | stable case id |
| `kind` | string | closed: `lifecycle`, `row_budget`, `call_trace`, `outcome`, `classification`, `dsr2_skeleton` |
| `rows` | array | zero or more `{key_hex,value_hex}` snapshot rows in storage order |
| `faults` | **array** of objects | optional scripted Port faults; each element has `op`, `on_call` (1-based), `status`, `shape`, optional `key_length`/`value_length`. **Not** a map/object keyed by op |
| `calls` | array | scanner API sequence (`begin` / `advance`+`row_budget` / `finalize` / `abort`) |
| `expected` | object | `final_status`, `adopted`, `state_after`, coarse flags/counters (`uint64` counts), `port_trace`, `mutation_calls=0` (schema symmetry; production mutation-zero is gated by the scripted spy, not by the oracle field alone), `reopen_required`, `close_count` |

**Fault object fields (exact):** `op` ∈ {`begin`,`iter_open`,`iter_next`,`rollback`}, `on_call` positive integer, `status` storage status name, `shape` ∈ {`natural`,`ok_null`,`error_with_handle`,`bts`,`not_found_poison`,`io_error`,`unknown`}, optional length fields for BTS/poison shapes.

**CI gate:** independent generator `check` plus a production bridge that executes the production private scanner against oracle expected status/adopted/`state_after`/counts/trace/fence for every vector, including begin-only failures, and asserts `result.status ==` returned status on finalize/abort (generated C fixture; oracle remains independent of production C). A mere ID list is insufficient.

**Counter overflow:** `ok_row_count` / `family14_row_count` / `current_domain_key_count` are `uint64` with checked increment; overflow is **D2-detectable corruption** (sticky `STORAGE_CORRUPT`, no wrap).

S1 vectors own transport/lifecycle/shape/lex/coarse-class subsets only. They do **not** complete `DSR1_SCAN` or `DSR2_ESP_BOUND`.

**S2 relationship:** production profiled beginは本S1 artifactを書き換えない。S1 transport-only beginはTEST-build adapterとして本oracle regressionにのみ使われ、tests-OFF release / S6 / Stage 5からabsent（§15.10.1）。

### 17.1.2 D2-S2 profile oracle artifact schema ownership（Normative freeze）

**本節はschema ownershipのfreezeである。** 実vector JSON・Python generator・production bridgeはD2-S2 **implementation** deliverableとして追加される（`tools/domain_scan_profile_vector_gen.py` / `spec/vectors/domain-scan-profile-v1.json`）。**DSR1_SCAN complete / DSR2_ESP_BOUND complete / D2 completeをclaimしない。**

| Field | Exact value |
| --- | --- |
| path | `spec/vectors/domain-scan-profile-v1.json`（S1 `domain-scan-v1.json`の**sibling**; 同fileへmergeしない） |
| format | `ninlil-domain-scan-profile-v1-d2s2` |
| version | `1`（artifact schema version; vectors未追加の間もschema contractとして固定） |
| independent generator（implementation PR） | oracle-side Python only: NLR1 framing / CRC32C / typed field encoding。**production C bootstrap plan / encode / scannerをinvoke・translateしない** |
| production bridge（implementation PR） | production **profiled** beginをoracle **literal** key/value hexとcandidate fieldsに対して実行し、status / adopted / state_after / coarse counts / **profile diagnostics**（`profile_exact_active`、`profile_mismatch`、`future_profile_candidate`、`profile_get_present_mask`、`family14_iter_seen_mask`）/ port_trace / mutation0 / reopen/close を比較 |

Top-level object（required keys; schema ownership）:

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | number | exact `1` |
| `format` | string | exact `ninlil-domain-scan-profile-v1-d2s2` |
| `scope` | string | S2 ownership prose; must not claim DSR1/DSR2/D2 complete |
| `workspace` | object | S1 capacities + `ceiling_bytes=8192` + encoded_value packing note（1143; 183/84/32/68） |
| `vectors` | array | S2 profile/get/reconciliation/precedence cases（implementation PRで充填） |

Each vector object（required keys; schema ownership）:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | stable case id |
| `kind` | string | closed set includes at least: `profile_exact`, `profile_mismatch`, `future_profile`, `completeness`, `get_fault`, `iterator_reconcile`, `precedence`, `dsr2_ceiling` |
| `candidate_binding` | object | typed binding semantic fields for compare（oracle-owned; not production projection output） |
| `rows` | array | `{key_hex,value_hex}` snapshot rows; profile values are **literal oracle hex** |
| `faults` | array | scripted Port faults; `op` includes `get`（1-based `on_call` over get occurrences 1..17）in addition to S1 ops |
| `calls` | array | scanner API sequence using **profiled begin** + `advance`/`finalize`/`abort` |
| `expected` | object | `final_status`, `adopted`, `state_after`, coarse counts, **profile diagnostics/masks**, `port_trace`（must show 17 gets before single `iter_open` on success-gate paths）, `mutation_calls=0`, `reopen_required`, `close_count` |

**CI gate（implementation PR）:** independent generator `check` + production bridge over every vector; S1 `domain-scan-v1.json` remains a separate frozen regression job. A mere ID list is insufficient.

**Explicit non-claims:** filling this schema does not complete DSR1/DSR2/D2 or Stage 5. S3 domain structural vectors remain separate.

### 17.1.3 D2-S3 structural oracle artifact schema ownership（Normative freeze）

**Decision identifier: D2-S3（oracle schema + implementation ownership）。** S1/S2 artifactは**sibling**のままbyte-for-byte frozen。D1 `domain-store-v1.json`へscanner call-traceを押し込まない。

| Field | Exact value |
| --- | --- |
| path | `spec/vectors/domain-scan-structural-v1.json` |
| format | `ninlil-domain-scan-structural-v1-d2s3` |
| version | `1` |
| independent generator | `tools/domain_scan_structural_vector_gen.py`（production Cをinvoke/translateしない。profile/NLR1/CRC/SHA-256/typed hexはoracle側。D1 authority hexのliteral再利用可） |
| production bridge | production **profiled** begin + exact candidate + 17 profile rows + domain row(s) をoracle literalに対して実行（全negativeを含む every vector で port trace / counters / budget / status をassert） |

Top-level object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | number | exact `1` |
| `format` | string | exact `ninlil-domain-scan-structural-v1-d2s3` |
| `scope` | string | S3 ownership prose; must not claim DSR1/DSR2/D2/Stage5 complete |
| `workspace` | object | S1 capacities + `ceiling_bytes=8192` + `row_validate_scratch` note（typed/witness union） |
| `d1_authority` | object | D1 d1b3o pin: `path` / `format=ninlil-domain-store-v1-d1b3o` / full `sha256` / `vector_count` / composition note |
| `s1_authority` | object | S1 d2s1 pin: full `sha256` + transport body-nonvalidation vector ids（sibling frozen regression） |
| `catalog_coverage` | object | **closed** subtype list（docs §7 table literal）+ required + covered（scan到達 assertion; `required==covered` self-definition alone is insufficient — closed list must match §7） |
| `vectors` | array | structural / witness-local / precedence / profile-skip / bts / lex / s1_evidence cases |

**Closed catalog（REQUIRED; family5 `01` + family6 §7 current）:**
`01,10,11,20-27,30-34,40-42,50-52,60-64,7d-7f`（exact 30）。business+`7d` は各 positive scan到達。可能な限り各subtypeの D1 CORRUPT typed negative も scan replay。`7e`/`7f` は local witness path。

Each vector object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | stable case id |
| `kind` | string | closed set includes at least: `structural_positive`, `structural_corrupt`, `structural_unsupported`, `witness_header_local`, `witness_chunk_local`, `precedence`, `profile_skip`, `lex_regression`, `dsr2_ceiling`, `bts_corrupt`, `s1_evidence` |
| `candidate_binding` | object | typed binding for profiled begin（oracle-owned） |
| `rows` | array | `{key_hex,value_hex}` snapshot; **17 profile rows + domain row(s)** in storage order |
| `faults` | array | scripted Port faults（BTS value_length=4097 等） |
| `calls` | array | **profiled begin** + `advance`/`finalize`/`abort` |
| `expected` | object | `final_status`, `adopted`, `state_after`, coarse counts, profile diagnostics, `port_trace`, `mutation_calls=0`, reopen/close |

**Composition design（D1 authority + oracle framing; not D1 reimplementation）:**

1. Generator pins D1 artifact as **independent authority**: format `ninlil-domain-store-v1-d1b3o`、full SHA-256、vector count。Selected typed vectors assert `id` / `expected_status` / `op` / `subtype` / key+value presence。
2. Business+`7d` same-record outcome is **composed** from D1 `expected_status`（OK→scan continue、non-OK→terminal CORRUPT）。S3 does **not** reimplement D1 body matrices。
3. Synthetic envelope / common-header / future / witness mutations derive framing/status **independently on the oracle**（CRC、record_version、domain_format、flags/PVD/revision/primary_id/identity/subtype/record_type）。Mere good/bad whitelist of full row hex is not the sole derivation path。
4. `7e`/`7f` body matrix negatives may embed D1 pure-body authority bytes; header-local mutates are oracle-derived。Head zero and nonzero are both legal positives for witness subtypes。
5. Generator production C invoke/translate remains **forbidden**。

**Status semantics（exact-profile path only）:**

1. `ninlil_model_domain_validate_typed_record` / witness local helper → `OK` → count + continue
2. → `NINLIL_E_UNSUPPORTED`（safe record_version/domain_format future）→ non-terminal `recognizable_future_seen`、scan継続
3. → `NINLIL_E_STORAGE_CORRUPT` / `NINLIL_E_INVALID_ARGUMENT` / other structural failure → terminal sticky `STORAGE_CORRUPT`
4. profile mismatch / `future_profile_candidate` → **S3 decode 0**（malformed domain row skipped; S2 skip維持）
5. S1 transport begin（`profile_exact_active=0`）→ body validate 0

**Precedence:** `record_version` future on an earlier current key then later current CORRUPT wins terminal; `domain_format` future→corrupt 同型。Future-root key is lexically after current root, so current-corrupt-then-future-root is the storage-order reality（not a misnamed future-then-corrupt root pair）。

**Gap coverage（scan evidence）:** value length 4097 iter `BUFFER_TOO_SMALL`→CORRUPT; current-root unknown subtype→CORRUPT; lex out-of-order/duplicate; profile mismatch skip; future_profile skip of malformed domain。

**S1 transport body nonvalidation evidence:** sibling `spec/vectors/domain-scan-v1.json` format `ninlil-domain-scan-v1-d2s1` full SHA pin + vector ids `s1-65-rows`（empty-value domain CURRENT counted without body validate）and `s1-family14-current`。S3 profiled path does not execute transport begin; S1 remains frozen regression。

**Typed stack:** public `ninlil_model_domain_validate_typed_record` has **no large typed_record local** in its function body; `out_record==NULL` uses separate no-output helper. Scanner non-NULL path uses workspace scratch only. Alias/failure zero/NULL tests maintained. Source gate may assert helper separation without nonportable stack attributes。

**CI gate:** independent generator `check` + production bridge over every vector; S1/S2 JSON and D1 d1b3o JSON remain frozen regressions. Representative matrix is sufficient（全1549 typed vectorsの複製は不要）; closed catalog coverage assertion required。

**Explicit non-claims:** D2 complete / DSR1_SCAN complete / DSR2_ESP_BOUND complete / Stage 5 / public Runtime / S4 exact-get / D3 cross-row / ESP hardware。

### 17.1.4 D2-S4 exact-get oracle artifact schema ownership（Normative freeze）

**Decision identifier: D2-S4（oracle schema + implementation ownership）。** S1/S2/S3 JSON および D1 `domain-store-v1.json` は **sibling frozen**（byte-for-byte; 本sliceはそれらを書き換えない）。全ID集合RAM保持テストを合法化しない。

| Field | Exact value |
| --- | --- |
| path | `spec/vectors/domain-scan-exact-get-v1.json`（S1/S2/S3 の **sibling**; merge 禁止） |
| format | `ninlil-domain-scan-exact-get-v1-d2s4` |
| version | `1` |
| independent generator | `tools/domain_scan_exact_get_vector_gen.py`（production C を invoke/translate しない。profile/NLR1 は oracle 側） |
| production bridge | production **profiled** begin + real private `ninlil_domain_scan_exact_get` を oracle literal に対して実行（every vector） |

Top-level object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | number | exact `1` |
| `format` | string | exact `ninlil-domain-scan-exact-get-v1-d2s4` |
| `scope` | string | S4 ownership prose; must not claim DSR1/DSR2/D2/Stage5 complete |
| `workspace` | object | S1 capacities + `ceiling_bytes=8192` + note: single 4096 value buffer reuse（second buffer 禁止） |
| `s1_authority` | object | S1 d2s1 pin: full `sha256`（sibling frozen regression） |
| `s2_authority` | object | S2 d2s2 pin: full `sha256` |
| `s3_authority` | object | S3 d2s3 pin: full `sha256` |
| `vectors` | array | exact-get seam / shape / fence / state / counter-stability cases |

Each vector object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | stable case id |
| `kind` | string | closed set includes at least: `present_live`, `absent`, `present_zero`, `exhausted_get`, `value_boundary`, `bts_corrupt`, `descriptor_rewrite`, `not_found_poison`, `known_port_fault`, `unknown_status`, `state_gate`, `key_shape`, `counter_stable`, `repeat_overwrite`, `profile_no_auto`, `dsr2_ceiling`, `mutation_zero` |
| `candidate_binding` | object | typed binding for profiled begin（oracle-owned） |
| `rows` | array | `{key_hex,value_hex}` snapshot; typically 17 profile rows + optional target row(s) |
| `faults` | array | scripted Port faults; `op` may be `get` with 1-based `on_call` over **all** get occurrences（profile 17 + exact-get） |
| `calls` | array | scanner API sequence: `begin_profiled` / `advance`+`row_budget` / `exact_get`+`key_hex` / `finalize` / `abort` |
| `expected` | object | `final_status`, `adopted`, `state_after`, coarse counts, profile diagnostics, `exact_observations`（ordered list of `{status,presence,value_hex}` for each exact_get success or prevalidation reject shape as needed）, `port_trace`, `mutation_calls=0`, reopen/close, `iter_open_count` |

**exact_get call object fields:** `op` exact `"exact_get"`、`key_hex`（non-empty for legal keys; may be empty/absent only for invalid-shape vectors that assert `INVALID_ARGUMENT` without Port）。

**CI gate:** independent generator `check` + production bridge over every vector; S1/S2/S3 JSON and D1 d1b3o remain frozen. known-answer/hash/count pins on this artifact after generate.

**Explicit non-claims:** D2 complete / DSR1_SCAN complete / DSR2_ESP_BOUND complete / Stage 5 / public Runtime / D3 relationship semantics / full-ID set / ESP hardware。

### 15.12 D2-S5 composition freeze（`DSR1_SCAN` + `DSR2_ESP_BOUND` complete）

**Decision identifier: D2-S5。** 本節は S1〜S4 および依存 D1 body authority が揃ったうえでの **mutation 0 bounded scanner composition** の Normative freeze である。**D2-S5 completes `DSR1_SCAN` and `DSR2_ESP_BOUND` and therefore D2 (bounded scanner) only.**

#### 15.12.1 Explicit non-claims（必須）

本 freeze / implementation は次を **claim しない**:

1. **Stage 5** completion / public Runtime publish gate / §1 full gate
2. **D3** cross-row relationship / cardinality / orphan / backlink / partial group / counter upper-bound / capacity recompute / health reconstruction の **finding correctness**（S5 は injection/aggregation **mechanism** のみ）
3. **D4** recovery mutation / convergence / FULL writer
4. **S6** Stage 5 orchestration as **complete Stage 5**（S6 seam partial integration は §15.13; Stage 5 は incomplete のまま）
5. **public Runtime** ABI / public status / installed public scanner API
6. **ESP-IDF** toolchain compile / component / **hardware** end-to-end

No new ADR. public C ABI / public include / public status を追加しない。

#### 15.12.2 D3 corruption injection seam（production-private）

Exactly one minimal production-private API:

```text
ninlil_status_t ninlil_domain_scan_note_terminal_corrupt(
    ninlil_domain_scan_session_t *session);
```

| Rule | Exact contract |
| --- | --- |
| `session == NULL` | `NINLIL_E_INVALID_ARGUMENT`。Port 0。mutation 0 |
| Legal states | `OPEN` または `EXHAUSTED` のみ |
| Legal call effect | Port call **0**。first sticky primary を `NINLIL_E_STORAGE_CORRUPT` に set（既に sticky があれば first を保持）。`state = FAILED`。return `NINLIL_E_STORAGE_CORRUPT` |
| Preserved on legal call | 全 candidate/future flags（`recognizable_future_seen` / `profile_mismatch` / `future_profile_candidate` / `profile_exact_active` 等）、全 counters、`has_previous` / previous key、workspace contents、iter/txn live ownership、bound Port/handle/workspace、`original_handle_authority`、`fence_pending` |
| Forbidden on legal call | cleanup tree、iter_close、rollback、fence/close、row_budget consume、iterator advance、exact get |
| `IDLE` / `DONE` / `FAILED` | `NINLIL_E_INVALID_STATE`。**no mutation / Port 0**（`FAILED` 再 note も状態・sticky を変えない） |
| Status argument | **none**（status を引数に取らない） |
| Public include | **no change** |

**D3 finding correctness remains D3.** S5 only supplies the injection/aggregation mechanism: after note, `advance` / `exact_get` reject with sticky/`FAILED` authority rules; `finalize` / `abort` use the existing cleanup tree; sticky `STORAGE_CORRUPT` **outranks** future/profile candidates in finalize aggregation（§15.2 / §15.10.7）。

#### 15.12.3 `DSR1_SCAN` composition requirements

Production bridge + focused units **must** close:

1. profiled budget **1** and **64**（same-session multi-advance resume is **not** labeled restart）
2. same-snapshot `exact_get` inside lifecycle（S4 seam; counters/iterator position unchanged）
3. **fresh-session restart from front** after partial `abort` / after partial path then `finalize`（new `session_init` + profiled begin; counters restart; first row is snapshot front）
4. restart against **changed** snapshot（different rows after prior cleanup）
5. restart after **FAILED** cleanup（sticky terminal path cleaned to `DONE` then new session）
6. rollback failure preserving sticky primary
7. unknown rollback cleanup status → fence **exactly once**
8. handle drift closes **original** handle, never foreign slot contents
9. future then note → sticky CORRUPT outranks future on finalize
10. exhausted + future then note → same corrupt outrank
11. profile mismatch candidate then note → corrupt mechanism（mismatch flags preserved; outcome CORRUPT）
12. structural/future candidate composition as applicable under exact profile
13. state gates for note / post-note advance/exact_get
14. note then `advance` / `exact_get` rejected（Port 0 on those rejects when state is `FAILED`）
15. close/fence exactly once when required; mutation calls **0**

Production path uses **profiled begin** only. TEST transport-only begin remains frozen S1 regression only and is absent from tests-OFF release symbols.

#### 15.12.4 `DSR2_ESP_BOUND` complete gates

1. **Current Normative ceiling** is **8192** bytes（**not** forever-8192 claim; ceiling may change only by later Normative amendment）
2. **Live `sizeof(ninlil_domain_scan_workspace_t) <= 8192`** asserted in tests / oracle kinds
3. **Single** 4096 value buffer; **no** second 4096 / full-ID set / unused session xref digest/kind/count fields
4. **No** heap `malloc`/`calloc`/`realloc`/`free`、`alloca`、VLA、recursion among **all** defined scanner functions（direct or mutual; call graph）、large automatic workspace/row_scratch/typed-record buffers、`65536` temporary allocation or reread path in scanner `.c`/`.h`
5. **Complete source gate** is `tools/domain_scan_dsr2_gate.py`（CTest `domain_scan_dsr2_complete_gate`）: strip comments/strings before analysis; fail-closed if function bodies cannot be parsed; negative self-tests（VLA / mutual recursion / allocator / automatic workspace / second 4096）via `domain_scan_dsr2_gate_self_test`
6. **Compiler VLA gate** on `domain_store_scanner.c`（`-Wvla` under existing `-Werror` for GNU/Clang/AppleClang; C11 extensions OFF）. **No** permanent stack-byte ceiling is claimed; forbidden large automatic record objects are proved by the source gate. Residual honesty: source analysis is pattern/structural, not a full C abstract interpreter
7. **ESP-IDF toolchain build is not required in S5**
8. tests-OFF private symbol gate: `note_terminal_corrupt` **present**; transport-only `ninlil_domain_scan_begin` **absent**; profiled begin + exact_get remain present
9. Oracle kind `dsr2_source` is **composition** of static assert/live sizeof + bridge + complete source/VLA gate + mutation0 — **not** proved by a success-path clone alone

#### 15.12.5 Frozen sibling authority

S5 must pin full SHA-256 / format / vector_count of:

| Authority | Path | Format |
| --- | --- | --- |
| S1 | `spec/vectors/domain-scan-v1.json` | `ninlil-domain-scan-v1-d2s1` |
| S2 | `spec/vectors/domain-scan-profile-v1.json` | `ninlil-domain-scan-profile-v1-d2s2` |
| S3 | `spec/vectors/domain-scan-structural-v1.json` | `ninlil-domain-scan-structural-v1-d2s3` |
| S4 | `spec/vectors/domain-scan-exact-get-v1.json` | `ninlil-domain-scan-exact-get-v1-d2s4` |
| D1 | `spec/vectors/domain-store-v1.json` | `ninlil-domain-store-v1-d1b3o` |

S1–S4 and D1 artifacts remain **byte-for-byte frozen**. S5 adds only the composition sibling.

#### 15.12.6 Completion boundary

| Claim | Status after S5 implementation |
| --- | --- |
| D2-S5 Normative freeze（本節） | this doc |
| D2-S5 implementation / `DSR1_SCAN` complete / `DSR2_ESP_BOUND` complete | implementation PR |
| **D2 (bounded scanner) complete** | **yes** when S1–S5 + deps + vectors/oracles all present |
| Stage 5 / D3 / D4 / public Runtime / ESP-IDF / hardware | **still pending**（D2-S6 private seam is separate partial integration; §15.13） |

### 17.1.5 D2-S5 composition oracle artifact schema ownership（Normative freeze）

**Decision identifier: D2-S5（oracle schema + implementation ownership）。** S1/S2/S3/S4 JSON および D1 `domain-store-v1.json` は **sibling frozen**（byte-for-byte; 本sliceはそれらを書き換えない）。

| Field | Exact value |
| --- | --- |
| path | `spec/vectors/domain-scan-composition-v1.json`（S1–S4 の **sibling**; merge 禁止） |
| format | `ninlil-domain-scan-composition-v1-d2s5` |
| version | `1` |
| independent generator | `tools/domain_scan_composition_vector_gen.py`（production C を invoke/translate しない。profile/NLR1/CRC は oracle 側。authority pin は full SHA/format/count） |
| production bridge | production **profiled** begin + real private `note_terminal_corrupt` / `exact_get` / `advance` / `finalize` / `abort` を oracle literal に対して実行（**every vector**） |

Top-level object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | number | exact `1` |
| `format` | string | exact `ninlil-domain-scan-composition-v1-d2s5` |
| `scope` | string | S5 composition ownership; claims D2/`DSR1_SCAN`/`DSR2_ESP_BOUND` complete only; must not claim Stage 5 / D3 finding correctness / D4 / S6 / public Runtime / ESP-IDF / hardware |
| `workspace` | object | S1 capacities + `ceiling_bytes=8192` + single 4096 value buffer note |
| `s1_authority` | object | path / format / full `sha256` / `vector_count` |
| `s2_authority` | object | path / format / full `sha256` / `vector_count` |
| `s3_authority` | object | path / format / full `sha256` / `vector_count` |
| `s4_authority` | object | path / format / full `sha256` / `vector_count` |
| `d1_authority` | object | path / format=`ninlil-domain-store-v1-d1b3o` / full `sha256` / `vector_count` |
| `vectors` | array | DSR1 composition + DSR2 bound cases |

Each vector object（required keys）:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | stable case id |
| `kind` | string | **closed set**（required coverage; exact equality not subset）: `budget_1`, `budget_64`, `same_snapshot_exact_get`, `restart_after_abort`, `restart_after_finalize`, `restart_changed_snapshot`, `restart_after_failed`, `rollback_failure_sticky`, `unknown_rollback_fence`, `handle_drift_original`, `future_then_note`, `exhausted_future_then_note`, `mismatch_then_note`, `structural_future_composition`, `state_gate`, `note_then_reject`, `note_exhausted`, `close_fence_once`, `mutation_zero`, `dsr2_ceiling`, `dsr2_source` |
| `candidate_binding` | object | typed binding for profiled begin（oracle-owned） |
| `rows` | array | primary snapshot `{key_hex,value_hex}` |
| `alt_rows` | object | optional named alternate snapshots for restart-changed cases（map name → row array） |
| `faults` | array | scripted Port faults（`get`/`iter_next`/`rollback`/…） |
| `calls` | array | scanner/harness sequence; **every call** carries `expected_status`（scanner ninlil status name, or `VOID` for harness ops） |
| `expected` | object | `final_status`, `adopted`, `state_after`, coarse counts, profile/future diagnostics, `port_trace`（full Port equality; no dropped enum category）, `mutation_calls=0`, reopen/close, `iter_open_count`, sticky fields |

**Call ops（closed）:** scanner: `begin_profiled`, `advance`, `exact_get`, `note_terminal_corrupt`, `finalize`, `abort`. Harness（Port 0; `expected_status=VOID`）: `session_init`（fresh session object only after cleanup `DONE`; not budget resume）, `use_rows`（switch to `alt_rows[name]` only in `IDLE`）, `handle_drift`（oracle/bridge handle-slot drift; not a scanner API）. TEST transport `begin` is **forbidden** in this artifact.

**Call outcomes:** every call has an immediate expected result. Bridge compares scanner status after **each** call (not final only). Harness ops validate legal ordering. `note_then_reject` proves note then `advance`/`exact_get` are `INVALID_STATE` with Port 0. Restart vectors: cleanup `DONE` before `session_init`; first post-restart `advance` has `row_budget=1`; bridge asserts `previous_key` equals lexicographically first active-snapshot row and counters reset to 1, then a later advance completes. Same-snapshot `exact_get`: bridge snapshots ok/family/current counters, iter_next/iter_open counts, previous-key/has_previous before get and asserts unchanged after success with get count exactly +1. `dsr2_source` is composition of live sizeof/bridge + `tools/domain_scan_dsr2_gate.py` complete gate + compiler `-Wvla` + mutation0 — not a success-path clone alone.

**CI gate:** independent generator `check` requires **full deterministic document equality** with regenerated output（not ID-list only）+ known-answer hash/count pins + **real anti-false-pass**（closed call-op set including `handle_drift`; expected_status presence; restart ordering; budget resume has no `session_init`; no TEST transport begin; `note_then_reject` structure; exact required kind set）; production bridge executes **every** vector and proves **all** required kinds（bitmask/exact set）; S1–S4 and D1 remain frozen regressions.

**Explicit claims after green gates:** D2 bounded scanner complete; `DSR1_SCAN` complete; `DSR2_ESP_BOUND` complete.

**Explicit non-claims:** Stage 5 / D3 finding correctness / D4 mutation / public Runtime / ESP-IDF compile / hardware。S6 seam is a separate partial integration（§15.13）and does not complete Stage 5.

### 15.13 D2-S6 private fail-closed Stage 5 seam（partial integration）

**Decision identifier: D2-S6。** 本節は **S6 seam implemented / Stage 5 incomplete** の Normative partial integration である。public C ABI / public status / installed public include を追加しない。

#### 15.13.1 Production-private surface

| Item | Contract |
| --- | --- |
| TU | `src/runtime/runtime_store_stage5_seam.{c,h}` only in `ninlil_runtime_private` |
| Public include | **forbidden**（`include/ninlil` に置かない） |
| Entry | `ninlil_runtime_store_stage5_private_hookup(storage, inout_handle, validation, hooks, workspace, out_result)` |
| Begin | **production `ninlil_domain_scan_begin_profiled` only**。TEST `ninlil_domain_scan_begin` **禁止** |
| Budget | fixed positive `advance` budget **64** until EXHAUSTED/FAILED |
| D3 | **never** call `note_terminal_corrupt` without real D3 |
| Mutation | scanner phase put/erase/commit **0**（new bootstrap の既存 FULL 17 write は L2b1 の責務で区別） |
| Ports | Bearer / clock / entropy 引数 **なし**（open 不能） |
| Workspace | caller-owned Runtime arena; L2b1 ∪ scanner phase union; session+candidate outside union as needed; documented ceiling; **no heap** in seam |

#### 15.13.2 Private outcomes（not public status）

| Outcome | When | Status | Notes |
| --- | --- | --- | --- |
| `NONE` | failure / non-adopt | mapped scanner/L2b1 status | adopted false |
| `NEW_BOOTSTRAP_STAGE5_PENDING` | L2b1 `NEW_BOOTSTRAP_COMMITTED` | `NINLIL_OK` | scanner **not** invoked; no Runtime/Bearer publish |
| `EXISTING_SCAN_ADOPTED_D3_PENDING` | L2b1 exact + scanner finalize adopted OK | `NINLIL_OK` | **integration result only**; `storage_recovery_complete` **remains false**; Stage 5 incomplete |

Scanner UNSUPPORTED / CORRUPT / Port / fence status は **exactly propagate**。`reopen_required` / `cleanup_status` / original-handle fencing を保持。**第二 precedence layer を作らない。**

**OK + `OUTCOME_NONE` is closed:** if scanner finalize returns `NINLIL_OK` but `adopted==0`, the seam returns `NINLIL_E_STORAGE_CORRUPT` with `OUTCOME_NONE`（never OK+NONE）.

**`scan_ran` semantics:** set to 1 only when the scanner lifecycle was actually entered（`begin_profiled` was called, including failed begin）. Prevalidation rejects and L2b1-only paths leave `scan_ran=0`.

**Prevalidation publication contract:** validate all required pointers, storage ops, non-NULL handle, and pairwise alias/disjointness **before** any `out_result`/`workspace` mutation. Every `INVALID_ARGUMENT` prevalidation failure leaves poisoned `out_result`/`workspace` bytes unchanged. Outputs are zero-initialized only after full prevalidation succeeds.

**Workspace production contract:** Runtime arena（never task stack）. Host unit tests may stack-allocate for convenience. Seam functions do not declare workspace automatic locals（source gate + `-Wvla`）.

#### 15.13.3 S6a L2b1 hardening（companion）

§15.8: empty-ns `BUFFER_TOO_SMALL`（value>4096 **or** key required length>255）→ immediate `STORAGE_CORRUPT`; reread 0; allocate 0; private value workspace 4096; allocator parameter removed from private L2b1 API.

#### 15.13.4 Explicit non-claims（必須）

1. **D3** finding correctness（cardinality / orphan / backlink / PVD / health reconstruction）。architecture freeze は §18（D3-S0）+ closed mode/context freeze は §18.12（D3-S1a docs only）+ declared multi-count freeze は §18.13（D3-S2a docs only）+ BLOB lifecycle freeze は §18.14（D3-S3a docs only）+ DSW1 freeze は §18.15（D3-S4a docs only）+ DSW2 freeze は §18.16（D3-S5a docs only）。**D3-S1 exact-1 / `DSI1_BACKLINK` core implementation complete**; **D3-S2 declared multi-count implementation complete**; D3-S3 implementation / D3-S4 implementation / D3-S5 implementation / D3-S6..S12 / D3 overall / Stage 5 D3 bind still pending
2. **D4** recovery / metadata mutation / FULL writer beyond L2b1 bootstrap
3. **identity** comparison / rotation
4. **health** reconstruction / Stage 9 publish
5. **public `runtime_create`** / Runtime publish / Bearer open
6. **clock / entropy** interfaces
7. **Stage 5 complete** / `storage_recovery_complete == 1`
8. **ESP-IDF** compile / **hardware**

#### 15.13.5 Integration matrix（minimum）

exact existing 17 clean → `EXISTING_SCAN_ADOPTED_D3_PENDING`; new empty → `NEW_BOOTSTRAP_STAGE5_PENDING` + scanner not invoked; exact profile + structurally valid family5/6 domain row → adopt + exact `current_domain`/`ok` counters + scanner-phase mutation0; recognizable future → UNSUPPORTED; corrupt structural/BTS/lex / partial 1..16 → CORRUPT; profile mismatch → UNSUPPORTED; L2b1→scanner second-snapshot race revalidates; scanner-phase Port faults（IO no-fence / unknown fence）; candidate handoff outside phase union; poison-retention prevalidation; fixed workspace/source gates（`tools/runtime_store_stage5_gate.py` + self-tests）; frozen S1–S5/D1 vector hashes unchanged。

## 18. Normative D3-S0 architecture freeze

**Decision identifier: D3-S0。** 本節は Domain Store **D3 cross-row finding correctness** の Normative architecture freeze である。**docs only**: implementation / test / CMake / vector JSON の追加・変更は本sliceで行わない。

**Historical S0 freeze status:** S0 alone does **not** complete D3 / Stage 5 / public Runtime / D4。Current main behavior（D2 complete + D2-S6 private seam → `EXISTING_SCAN_ADOPTED_D3_PENDING` / `storage_recovery_complete=0`）を変更しない。

**前提 evidence（現行 code/docs）:**

- D1 pure/same-record: `src/model/domain_store_{codec,body_codec}.*` + `spec/vectors/domain-store-v1.json`（format `ninlil-domain-store-v1-d1b3o`）
- D2 traversal / structural / exact_get / note mechanism: `src/runtime/domain_store_scanner.*` + S1–S5 sibling oracles + §15.1–§15.12
- D2-S6 Stage 5 private seam: `src/runtime/runtime_store_stage5_seam.*` — `note_terminal_corrupt` を real D3 なしで呼ばない（§15.13）
- Cross-row cardinality / backlink / counter / capacity / health の正本は本章 §9 / §10 / §12 / §13 / §14。本節はその **finding 実行方式** と **slice 分割** を閉じる

### 18.1 Ownership close（D1 / D2 / D3 / D4）

| Owner | Closed scope | Non-claims |
| --- | --- | --- |
| **D1** | Port call 0 の pure key/record/**witness** codec と same-record validation / golden。authority は **grammar（key/body/witness layout と same-record 閉包）** と既存 pure helpers（`ninlil_model_domain_build_key` / `key_digest` および関連 pure digest helpers）。body が保持する raw identity は peer key の **forward 材料** として存在するが、typed peer rebuild helpers の production 接続は **D3 work items**（§18.10）であり D1 complete の言い換えではない | live exact_get、cross-row cardinality、mutation、typed peer rebuild production helpers の complete 主張 |
| **D2** | mutation 0 bounded traversal、Port/shape/transport、lex、framing、family1-4 + profile gate、same-record structural（S3）、same-snapshot exact `get` **mechanism**（S4）、`note_terminal_corrupt` **injection/aggregation seam only**（S5）、S6 private fail-closed integration | D3 finding correctness、D4 writes、Stage 5 complete、public Runtime |
| **D3** | Stage 5 closed order **steps 5–10** の **cross-row finding correctness**: step 5 の witness member old/new・partial group・successor/supersede chain；step 6 primary/index/backlink/BLOB 参照；step 7 4-counter；**step 8 の ownership は §18.2 に map**（ingress-owner と attempt/delivery/result/event ledger → **S1/S2**；**SERVICE_QUOTA → S9**）；step 9 11-capacity recompute；step 10 durable health reconstruction。finding を §16 precedence へ sticky CORRUPT として投入 | D4 recovery mutation / FULL writer / convergence；identity rotation；Stage 7 clock；public Runtime publish；ESP-IDF/hardware |
| **D4** | snapshot 終了後の recovery mutation / operation 別 convergence / FULL writer と fresh re-scan 接続 | D3 finding の正しさ自体 |

**Stage 5 steps 1–4 / 11** は D2（+ L2b1）が scanner 到達可能な部分を供給する。**steps 5–10 の cross-row 事実**は D3 が証明するまで Stage 5 は incomplete のまま（§15 / §1）。

### 18.2 Ordered D3 slice ledger（D3-S0..S12）

**Slice order の意味:** 本表の S0..S12 順序は **implementation dependency / deliverable 分割** の ledger である。Stage 5 closed scan order（§15 steps 1–11）そのものでも、Runtime が単一 iterator でこの順に固定走査する義務でもない。各 slice の finding は hybrid（§18.3）の下で、local per-row と fresh multi-pass を組み合わせてよい。

**Stage 5 step 8 ownership map（explicit）:**

| Step 8 concern | Primary D3 slice(s) |
| --- | --- |
| ingress-owner ledger / exact-1 backlink・PVD | **S1**（core）、関連 multi は **S2** |
| attempt / delivery / result / event ledger（declared-count graph・cardinality・state 照合） | **S2**（exact-1 部分は **S1** と共有可） |
| **SERVICE_QUOTA**（service-key focus multi-pass / contribution cross-check） | **S9** |

| Slice | Exact scope | Non-claims |
| --- | --- | --- |
| **D3-S0** | 本節の Normative architecture freeze。docs のみ。vector/code 変更 0 | D3 implementation / Stage 5 complete |
| **D3-S1a** | **docs only** closed exact-1 relationship freeze（§18.12）: fixed `k=20` modes、fixed D3 context layout/ceilings、`begin_profiled_d3s1` private API contract、evaluator order、multi-peer packing rejection、oracle architecture only。**JSON / code / tests 変更 0**（historical; 実装完了を claim しない） | D3-S1 implementation、Stage 5 D3 bind、public Runtime |
| **D3-S1** | **実装済み（D3 incomplete）:** §18.12 exact-1 known-key backlinks + live primary value digest（PVD）。**`DSI1_BACKLINK` core**。raw body → peer complete key rebuild → same-snapshot `exact_get` → presence + PVD / raw bijection。typed peer rebuild helpers の D3 側接続、fixed context（421 / ceiling 448）、`begin_profiled_d3s1`、per-row evaluator modes 1..20。sibling oracle `spec/vectors/domain-scan-crossrow-v1.json` / format `ninlil-domain-scan-crossrow-v1-d3s1`（`vector_count` **94** / full JSON sha256 `f47dff4f5753a92ebf3627408c576f69cc1862d20e1f74021e22ef5603c87176` / canonical `content_sha256` `76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468`）+ independent generator + production bridge + exact 94 kinds + mutation 0 + frozen D1/S1–S5 pins（§18.7） | declared-count multi-row、BLOB stream、witness chain、capacity/health、D4、D1 grammar の再定義、S1a で禁止した multi-peer packing、**D3-S2..S12**、D3 complete、Stage 5 D3 bind、public Runtime、ESP-IDF/hardware |
| **D3-S2a** | **docs only** declared multi-count graph Normative freeze（§18.13）: snapshot-only scope、modes **21..26** / **k₂=6**、**1 session = 1 mode / 1 txn**（S2 complete = **6** self-contained sessions）、SHA256_COMPOSITE non-owner-contiguous、same-txn phase machine（baseline D2 once + sequential zero-prefix reopen + `PASS_INTERNAL` future/profile freeze）、mode-scoped FOCUS/BIND sets（Mode21 ATTEMPT+INDEX; Mode22 ATTEMPT+BIND_ATTEMPT only）、global BIND requires **declared-count carrier** presence/body + true primary PVD/raw + optional pair peer（get budget ≤1+1+1 max 3）、generic A/B/C declared/observed u64 lanes + exact mode map、controls `binding_complete_mask`/`focus_mode`/`cleanup_skip`、BIND scratch reuse、B0–B11 budget、context **306/320** exact offsets、aggregate ceiling path **9152**、oracle architecture only。**JSON / code / tests 変更 0** | D3-S2 implementation、Stage 5 D3 bind、public Runtime、D3 complete |
| **D3-S2** | **実装済み（D3 incomplete）:** §18.13 declared multi-count / same-txn multipass。modes **21..26** の **6 self-contained sessions**（1 session = 1 mode = 1 same `READ_ONLY` txn）、context **306/320**、sibling oracle `spec/vectors/domain-scan-crossrow-v1.json` / format `ninlil-domain-scan-crossrow-v1-d3s2`（`vector_count` **144** = d3s1 prefix **94** + d3s2 suffix **50** / full JSON sha256 `e270743e99189a830b1b39d6c4b464fc3d2eb63ff8fe2b20dcfa7ae0f91d01ec` / canonical `content_sha256` `a9fccb12d932f0082111c94da3a23cd6680dc4bedecb2108e739bdca55d80fed`）+ independent generator + production bridge + mutation **0** + DSD1 multi-session composition（**7** sessions; format `ninlil-domain-scan-dsd1-composition-v1-d3s2`）。§18.13.15 case classes 1..21 closed on fixed candidate `39e4752` / merge `ca02e24` / PR #105（§18.13.19; non-normative review `docs/reviews/2026-07-20-d3s2-implementation-accepted.md`） | BLOB chunk lifecycle、witness old/new、global capacity、health、SERVICE_QUOTA multi-pass（S9）、CLEANUP phase remaining（S11）、**D3-S3..S12**、D3 complete、Stage 5 D3 bind、public Runtime、ESP-IDF/hardware |
| **D3-S3a** | **docs only** BLOB lifecycle Normative freeze（§18.14）: KEY_DIGEST SCAN（single arm）、modes **27..30**、Mode28 view pin+re-SCAN、**expected_semantic_digest / expected_owner_pvd pins**、Mode30 #14 binding + #15 length + #16 RECEIPT tri-match、Mode29 always RESULT setup、untyped orphan、context **754/768**、outer **9920**。**JSON/code/tests 0** | D3-S3 implementation、Stage 5 D3 bind、public Runtime、D3 complete |
| **D3-S3** | BLOB lifecycle / chunks / multi-chunk stream digest / owner 0·1 cardinality。**implementation** of §18.14: four mode sessions + digest-match SCAN + known-index stream + Mode30 referrer/companion matrix + untyped orphan | witness member old/new、DSW*、capacity double-count 回避以外の global ledger、D4 erase history |
| **D3-S4a** | **docs only** `DSW1_ALL_OLD_NEW` Normative freeze（**§18.15**; §18.14=S3a）: modes **31..34** / **k₄=4**、**FOCUS_MEMBERS_2M+P**、**MEMBERSHIP_DUAL full-M + Mode34 same-txn manifest SHA**、Mode34 A/B/C + **carrier pin**、same-txn primary PVD + S4 closed byte-exact raw/raw2/aux normalization（BLOB manifest/chunk含む）、Mode31/32 SUPERSEDE deferred progression、Mode33 RETIRED-header inventory、finalize/quota gates、context **949/960**、full outer **10880**、oracle architecture only。**JSON / code / tests 変更 0** | D3-S4 implementation、Stage 5 D3 bind、public Runtime、D3 complete |
| **D3-S4** | **`DSW1_ALL_OLD_NEW`**: witness member all-old / all-new / mixed / partial group detection（§10 Recovery 表）。**implementation** of §18.15: four mode sessions + 2M+P stream + dual membership + chunk orphan + head/index backlink | successor chain walk（S5）、retire/cleanup（S6）、D4 mutation |
| **D3-S5** | **`DSW2_SUPERSEDE_CHAIN`**: ACTIVE/SUPERSEDED successor chain、bounded walk、cycle/missing successor。**D3-S5a docs freeze complete（§18.16）:** Mode35 / k₅=1、bounded chain walk + manifest SUPERSEDE_WITNESS entry full-M proof + canonical NLR1 old digest + hop_witness_digest 別 pin + RETIRED handoff、context **651/656**、full outer **11536**。implementation pending | retire/cleanup physical erase truth（S6）、D4 |
| **D3-S6** | **`DSW3_RETIRE_CLEANUP`**: SUPERSEDED→RETIRED、incoming successor 参照 0、oldest-first chunk partial cleanup eligibility、ACTIVE partial 拒否。**S5a（§18.16）から移管:** RETIRED node 自身の outgoing successor suffix walk / chain authority（S5 が RETIRED successor 到達時に manifest proof 後 S6_REQUIRED を set し停止した後の、RETIRED node の successor suffix・retirement eligibility・incoming reference・partial chunk truth） | D4 actual erase/replace commits |
| **D3-S7** | **`DSC1_COUNTERS`**: 4 family-3 counter upper-bound / unique / orphan / visited gap 規則（§12） | capacity 11-kind（S8）、health source set（S10） |
| **D3-S8** | **`DSC2_CAPACITY`**: 11-kind used/reserved recompute vs family-4 + owner formula cross-check（§13）。reservation vector が唯一加算元 | SERVICE_QUOTA multi-pass focus（S9）、health |
| **D3-S9** | **SERVICE_QUOTA focus multi-pass**: service-key で group した inflight/spool/grant contribution を QUOTA record と exact cross-check（§13）。fresh scanner sessions / multi-pass。cost は **O(S·N)**（S は selected profile の SERVICE / service-quota capacity で bound；§18.5） | undocumented/unbounded all-pairs default、full-ID set、false O(N) one-pass claim |
| **D3-S10** | **`DSH1_HEALTH`**: durable health source set reconstruction（§14）。priority 1..8 source IDs、dedup、publish-gate inputs の再構成だけ | Stage 9 publish、instance-local cause copy、public health API |
| **D3-S11** | CLEANUP_PLAN overlay: plan present 時の phase-specific decreasing cardinality / fence aggregate / remaining counts vs live ATTEMPT·INDEX（§9 / §11） | D4 phase batch erase writer |
| **D3-S12** | Stage 5 integration: D3 slices S1–S11 green を private seam へ接続し、private outcome を **`EXISTING_SCAN_ADOPTED_D3_PENDING` から private `D4_PENDING` へ transition** する（**implementation name は S12 で freeze**）。**`storage_recovery_complete` は 0 のまま** | public Runtime、identity rotation、Bearer/clock/entropy open、Stage 9、ESP-IDF/hardware、D4 mutation complete、Stage 5 complete |

**「S12 proves D3」:** S1–S11 本体と依存 oracle/helpers がすべて green のときだけ D3 finding correctness complete。S0 単独・部分 slice・D2-S6 adopt 成功を D3 complete や Stage 5 complete に置換してはならない。S12 は private `EXISTING_SCAN_ADOPTED_D3_PENDING` → private `D4_PENDING` の outcome transition だけを閉じ、`storage_recovery_complete` を 1 にしない。

### 18.3 Hybrid architecture freeze

D3 は次の **hybrid** だけを合法とする（§9 最終段落 / §15.11 と整合）:

1. **Per-row private evaluator（local exact-get checks）**
   production scanner が exact-profile で **S3 structural success** した **current row** の直後に限り、同一 session / 同一 READ_ONLY snapshot 上で private evaluator が local exact-1 / known-key backlink / local PVD を実行してよい。
   順序は §15.11.6 Future internal ordering に従う: structural success → copy needed descriptor → optional `exact_get`（value overwrite）→ consume borrowed result **before** next exact_get / advance。

2. **Fresh scanner sessions / multi-pass（nonlocal aggregates）**
   declared-count graph、SERVICE_QUOTA、BLOB stream digest matching（nonlocal）、retire refcount、capacity/health の nonlocal aggregate は、**sole iterator を第二 iterator と並行させず**、必要なら session を cleanup→`DONE` 後に **fresh session で先頭から** multi-pass する（D2 restart 規則と同じ。same-session budget resume を restart と呼ばない）。
   **S2a specialization（§18.13; historical S0 文を削除しない）:** declared multi-count cardinality の **list-then-count across two `READ_ONLY` snapshots** は **禁止**。S2 は **単一 txn** 上で baseline once + sequential zero-prefix iterator reopen + `PASS_INTERNAL` で multipass する。§18.3 の fresh-session multipass は S9 等の **independent one-pass-per-session proofs** には残り得るが、S2 carrier 列挙と count を別 snapshot に分割する vehicle ではない。
   **S3a specialization（§18.14; historical S0/S2a 文を削除しない）:** BLOB owner→manifest→chunk / stream digest の **list-then-prove across two `READ_ONLY` snapshots** は **禁止**。S3 は **単一 txn** 上で baseline once + sequential zero-prefix reopen + `PASS_INTERNAL` + **KEY_DIGEST digest-match SCAN**（owner からの complete-key rebuild exact_get は **禁止**）+ install 後 known-index chunk `exact_get` で multipass する。BLOB keys は SHA256_COMPOSITE のため same-blob contiguous-run count は **禁止**（§18.14.3）。

   **S4a specialization（§18.15; historical S0/S2a 文を削除しない）:** witness group member all-old/all-new の **list-then-prove across two `READ_ONLY` snapshots** は **禁止**。S4 は **単一 txn** 上で baseline once + sequential zero-prefix reopen + `PASS_INTERNAL` + **per-member chunk re-get + member get + same-txn primary PVD（2M+P）** + **MEMBERSHIP_DUAL full-M** で multipass する（single 4096; pin-before-overwrite; chunk borrow **禁止**）。Mode34は同じtxnでM/C/chunk framing/final manifest SHAを独立証明し、Modes31/32の別session結果を代用しない。full member-ID set / successor chain walk（S5）/ retire cleanup（S6）を S4 に混入しない。

   **S5a specialization（§18.16; historical S0/S2a/S4a 文を削除しない）:** successor chain bounded walk の **list-then-prove across two `READ_ONLY` snapshots** は **禁止**。S5 は **単一 txn** 上で baseline once（witness header checked-u64 count → walk_bound）+ sequential zero-prefix reopen + `PASS_INTERNAL` + **per-origin bounded chain walk（successor exact_get + manifest SUPERSEDE_WITNESS entry full-M stream）** で multipass する（single 4096; pin-before-overwrite; `hop_witness_digest` / `successor_witness_digest` 別 pin; full-ID set / visited hash table **禁止**）。RETIRED successor 到達時は manifest proof 完了後に S6_REQUIRED set + 停止（S6 移管）。retire cleanup（S6）/ D4 mutation を S5 に混入しない。

3. **絶対禁止**
   - **second concurrent iterator**（zero-prefix を含む second live iterator）
   - **full-ID set** を RAM に保持（全 transaction/delivery/blob ID の可変集合）
   - **D4 writes**（`put` / `erase` / `commit` / `READ_WRITE`）を D3 が行うこと
   - heap / VLA / 関数 stack 上の record buffer / 65,536 temporary value path

4. Scanner session に unused xref digest/kind/count の「D3 専用 shadow 全集合」を追加してはならない。D3 が保持してよいのは **fixed-size D3 context**（§18.4）と checked counters / O(1) aggregates のみ。

### 18.4 Descriptor lifetime / order freeze

| Rule | Exact contract |
| --- | --- |
| Value overwrite | `exact_get` success は `workspace->value` を上書きし、typed/borrowed views を invalid にする（§15.11.2） |
| Copy-before-get | peer key rebuild に必要な **raw IDs / digests / declared counts / presence bits** は、exact_get の **前** に fixed D3 descriptor / context へ **copy** する |
| D3 context | scanner workspace とは **separate fixed-size object**（Runtime arena）。session に可変長 ID list をぶら下げない |
| Borrowed consume | borrowed present value / PVD bytes は **次の** advance / exact_get / finalize / abort 前に消費し終える |
| Ceiling（既存） | `DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES`（現行 8192）および Stage5 seam workspace ceiling（現行 **8704**）の変更は **doc-first**（本章 Normative 更新が実装/vector より先）。silent raise 禁止 |
| **D3 fixed context size** | **Historical S0 text:** size は TBD at D3-S1；S0 は具体 byte 数を **guess しない**。**S1a supersession（§18.12）:** fixed layout `sizeof=421` / object ceiling **448**；NEW D3 aggregate arena ceiling **8832**（= 8384+448；doc-first **+128** over Stage5-alone 8704）。**S2a addition（§18.13）:** S2 context `sizeof=306` / object ceiling **320**；outer future aggregate when S1+S2 co-resident **9152**（= 8384+448+320）。**S3a addition（§18.14）:** S3 context `sizeof=754` / object ceiling **768**；outer future aggregate when S1+S2+S3 co-resident **9920**（= 8384+448+320+768）。**S4a addition（§18.15）:** S4 context `sizeof=949` / object ceiling **960**；outer S1+S2+S4 **10112**；**full S1+S2+S3+S4 outer 10880**（= 8384+448+320+768+960）。**S5a addition（§18.16）:** S5 context `sizeof=651` / object ceiling **656**；S1+S2+S5 **9808**；**full S1+S2+S3+S4+S5 outer 11536**（= 8384+448+320+768+960+656）。scanner ceiling **8192** と Stage5-seam-alone ceiling **8704** は **unchanged**。Stage5 は S12 まで D3 context を allocate/bind/run しない。DSR2（scanner workspace 8192 / single 4096 value / no second 4096 / no full-ID / no VLA/heap record buffer）は維持 |
| Mutation | D3 path の Storage mutation 0（D2 と同） |

### 18.5 Algorithm categories（closed）+ rejected claims

| Category | Used for | Cost model / mitigation |
| --- | --- | --- |
| **A. exact-1 key rebuild / reverse / PVD** | §9 exact-1 secondaries（QUOTA、STATE、RESULT_CACHE、1:1 digest fields 等）。body raw → complete peer key → `exact_get` → PVD/raw bijection | O(1) Port get / relationship。**undocumented all-pairs 禁止** |
| **B. contiguous run streaming counts** | same-primary / same-subtype の lex 連続 run を advance で数え、declared count と checked 照合 | O(N_subtype) single pass per focused family。必要なら multi-pass |
| **C. O(1) global aggregates** | family-3 observed max、fence active plan count、checked add of reservation vectors の running totals | O(N) one pass + O(1) state。full-ID set 不要 |
| **D. focused multi-pass（profile/data-bounded）** | SERVICE_QUOTA service-key grouping、BLOB digest matching、retire incoming-successor refcount 等。**S2a 以降:** declared multi-count families の focus multipass（§18.13）も本 category。**S3a 以降:** BLOB known-index + stream digest multipass（§18.14）も本 category。**S4a 以降:** witness group **2M+P** member stream / dual membership / head-backlink（§18.15）も本 category | 複数 pass / focus。focus key/digest は fixed context に 1 件ずつ。**固定関係種別 k** と **データ依存 focus 数 F/S** を混同しない（下記） |
| **E. bounded successor walk** | witness SUPERSEDED chain（§10.1）。起点 header から successor exact_get、visited step ≤ witness row count。**S5a 以降:** DSW2 successor chain bounded walk（§18.16）も本 category | O(chain length) ≤ O(witness headers)。cycle → corrupt |

**Category B applicability correction（S2a; historical row を偽書き換えしない）:**

1. **S0 historical row は残す。** 上表 B 行は architecture freeze 時点の generic category 名のまま残す。B が「常に無意味だった」と後から書く rewrite は禁止。
2. **適用条件:** category B が合法なのは、同一 focus の secondary が **complete key lex で owner/subject 連続 run** を形成する場合だけである（例: 将来の non-hash identity や、subtype band 全体を 1 つの N_subtype pass と数える場合）。
3. **S2 declared multi-count families への非適用:** ATTEMPT / EVIDENCE_CELL / REVERSE_REPLY / RETRY_SUMMARY / MANAGEMENT_LEDGER の key identity は **`SHA256_COMPOSITE`**（§5.1）であり、**same-owner / same-subject は owner-contiguous ではない**（hash で interleave）。したがって S2 が「owner contiguous-run + O(k₂·N) one-pass」と claim するのは **spec fiction** であり **禁止**。
4. **S2 の合法 category:** focus multipass + body-filter stream counts + known-slot `exact_get` は **category D**（honest **per-session O(Fₘ·N + mode BIND walks)**; complete product = sum over six sessions; §18.13）。category B を S2 の core algorithm として再主張してはならない。
5. **subtype band 全体**（全 ATTEMPT が subtype で隣接する等）は contiguous だが、それは **owner run ではない**。band 走査は multipass の 1 walk 材料であり、B の same-primary run と同義にしない。

**Fixed relationship-type `k` と data-dependent focus `F` / `S` の区別（必須）:**

| Symbol | Meaning | Bound |
| --- | --- | --- |
| **`k`** | **固定** relationship-type / category 数（本節 A–E と Normative が列挙する closed 関係種別）。実装が「関係種別を増やした」ときの doc 上の focus 回数 | Normative が閉じた固定数。data size `N` に連動して勝手に増えない。**exact-1 local set は D3-S1a で `k=20` 固定**（§18.12; honest O(20·N)）。**declared multi-count mode set は D3-S2a で `k₂=6`（modes 21..26）固定**（§18.13; **1 session = 1 mode**; S2 complete = 6 sessions; per-session cost **O(Fₘ·N + mode BIND walks)** であり固定 k₂·N one-pass や one-session-all-six は禁止）。**BLOB lifecycle mode set は D3-S3a で `k₃=4`（modes 27..30）固定**（§18.14; **1 session = 1 mode**; S3 complete = 4 sessions）。**DSW1 mode set は D3-S4a で `k₄=4`（modes 31..34）固定**（§18.15; **1 session = 1 mode**; S4 complete = 4 sessions each with **Θ(N) baseline**; per-header **Θ(2M+P)**; dual membership **Θ(M)** full scan; product **Θ(4N+W)** where `W` includes every internal full-domain scan, including Mode33's two scans；false one-baseline-all-four / C+M-without-reget / full-ID set は禁止）。**DSW2 mode set は D3-S5a で `k₅=1`（mode 35）固定**（§18.16; **1 session = 1 mode**; S5 complete = 1 session with **Θ(N) baseline**; per-origin bounded walk **Θ(Σ_hops (1+M_hop))**; worst-case **Θ(L²·(1+M_avg))**; full-ID set / visited hash table / unbounded walk は禁止） |
| **`F`** | ある multi-pass 検査における **data-dependent** focus 件数（例: distinct BLOB digest、retire 対象 successor 起点） | その検査の domain data と profile 規則で bound。実装が unbounded set を RAM に積んではならない |
| **`S`** | **SERVICE_QUOTA（S9）** の service-key focus 件数 | **selected profile の SERVICE / service-quota capacity** で upper-bound。S0 は具体 profile 定数を再掲しないが、**profile capacity 外の unbounded S** は禁止 |

**Honest cost（偽 O(N) 禁止）:**

1. **SERVICE_QUOTA（S9）** は focused multi-pass で **O(S·N)**。`S` は上記 profile capacity で bound。`S` が data と共に `N` へ scale する profile では wall time は **quadratic-class（O(N²) 級）** になり得る。
2. 他の per-focus multi-pass は **O(F·N)** になり得る。同様に `F` が `N` と共に scale すれば wall time は quadratic-class。
3. それでも **memory は fixed**（fixed D3 context + O(1) aggregates；**full-ID set なし**；second concurrent iterator なし）。quadratic-class **wall time** を認めても、可変 ID 集合の RAM 保持や undocumented all-pairs を合法化しない。
4. **固定 `k` だけ**の関係を「O(k·N) かつ k≪N だから実質 O(N)」と書いて、**data-dependent F/S** のコストを隠してはならない。

**Explicit rejections（実装禁止 / 偽 claim 禁止）:**

1. **`KEY_DIGEST` の不可能な reverse**: `KEY_DIGEST(complete_key)` は SHA-256 one-way。digest 32 bytes **だけ**から complete key / raw identity を復元してはならない。peer lookup は body が保存する **raw components** から key を **forward rebuild** し、digest は再計算一致にだけ使う（§5.1 / §9）。
2. **False one-pass / false O(N) claim**: steps 5–10 全体を「iterator 1 回で全 cross-row 完了」または「全体が O(N)」と claim しない。local exact-1 は per-row、nonlocal は multi-pass を許す。**O(S·N) / O(F·N) を O(N) と偽らない**。
3. **False full-ID claim**: 整合性のために全 ID 集合の RAM 保持を合法化しない（§9 / §15.5 / DSR2）。
4. **Undocumented / unbounded all-pairs**: primary×secondary の **無制限・未文書** 二重全走査を default にしない。worst-case を隠したまま「O(N)」と称する実装も禁止。
5. **本節が文書化した profile-bounded multipass は禁止しない**: S9 の **O(S·N)**（S = profile SERVICE/service-quota capacity bound）および他の **O(F·N)** focused multi-pass は、上記 honest cost・fixed memory・no full-ID set を守る限り **合法**。doc-first なしに F/S bound を外す変更、または未文書の unbounded all-pairs 追加だけを禁ずる。

### 18.6 Complete D3 invariant / vector ownership table

| Vector / invariant | D3 ownership | Primary slices | Shared / non-D3-alone |
| --- | --- | --- | --- |
| **`DSI1_BACKLINK`** | primary↔secondary exact-1 / orphan / missing / collision raw / revision / PVD | **S1**（core）、S2 で multi | D1 same-record raw/digest local only |
| **`DSI2_BLOB_STREAM`**（name freeze; S3a） | SCAN+stream+pins / Mode28 re-SCAN / Mode30 #14/#15/#16 / Mode29 RESULT setup / untyped orphan | **S3**（core; §18.14） | D1 same-record BLOB; KEY_DIGEST reverse **forbidden**; capacity **S8**; erase **D4** |
| **`DSW1_ALL_OLD_NEW`** | member old/new/mixed/partial/dup/missing/extra group; chunk orphan; head backlink; f3/4↔HEAD_INDEX | **S4**（§18.15 freeze; implementation pending） | D1 witness pure codec + D2-S3 header/chunk local framing; successor **S5**; retire **S6** |
| **`DSW2_SUPERSEDE_CHAIN`** | successor/supersede chain; bounded walk; cycle/missing successor; manifest SUPERSEDE_WITNESS entry full-M proof | **S5**（§18.16 freeze; implementation pending） | header local: D1/D2-S3; RETIRED suffix: **S6** |
| **`DSW3_RETIRE_CLEANUP`** | retire eligibility / partial chunk rules | **S6** | physical erase commits: **D4** |
| **`DSC1_COUNTERS`** | 4-counter validation（§12） | **S7** | family-3 codec: D1；scan reach: D2 |
| **`DSC2_CAPACITY`** | 11-kind recompute + owner formula（§13） | **S8** | family-4 codec: D1 |
| **`DSH1_HEALTH`** | durable source set reconstruction（§14） | **S10** | Stage 9 project/publish: **not D3 complete** |
| **`DSC3_CLEANUP_PHASES`** | phase remaining/fence/live count の **finding** 部分 | **S11**（overlay） | phase batch erase / COMMIT_UNKNOWN convergence: **D4** 共有 |
| **`DSD1_LOGICAL_DELIVERY`** | APPLICATION_FIRST / CANCEL_FIRST / later APPLICATION / binding conflict の **cross-row finding** | S2 + delivery graph | public ABSENT projection / writer E2E: **D4** 共有 |
| **`DSH2_HEALTH_GOLDEN`** | numeric registry / exact source ID golden の **finding 側** | S10 companion | full registry mirror / Stage9: 後続 |
| **`DSO1_OPERATION_BUILDERS`** | subject/retention/member ceiling の **recovery-time consistency finding** に必要な範囲のみ | 参照のみ（S4–S6） | builder 実装本体: **D4 / writers** 共有 |
| **`DSO2_AUTOMATIC_TRANSITIONS`** | send/timeout/park 等 automatic transition の **durable shape finding** に必要な範囲のみ | 参照のみ | transition writer: **D4** 共有 |
| **`DSR1_SCAN` / `DSR2_ESP_BOUND`** | D3 は D2 complete を前提利用 | — | **D2-S5 ownership**（D3 が再 claim しない） |

### 18.7 D3 sibling oracle schema ownership（architecture level; JSON は S0 で追加しない）

**S0 は oracle JSON / generator / bridge を追加しない。** 後続実装 slice が従う schema ownership だけを固定する。**S0 時点で crossrow sibling file が存在するとは claim しない**（proposed path は後続 slice が従う契約名）。**S1a も JSON を作成しない（§18.12.8）。** 現在の sibling 正本は下記 **Current D3-S1 crossrow authority** であり、S0/S1a の「未作成」historical 文を後から書き換えない。

| Field | Exact architecture contract |
| --- | --- |
| Proposed path | `spec/vectors/domain-scan-crossrow-v1.json`（S1–S5 / D1 の **sibling**; merge 禁止）。**S0 では未作成** |
| Proposed format | `ninlil-domain-scan-crossrow-v1-d3sN`（slice 進行で suffix を更新してよいが、**単一 sibling file** を破壊的 fork しない） |
| Independent generator | `tools/domain_scan_crossrow_vector_gen.py`（名称は実装で確定可）。**production C を invoke/translate しない** |
| Production bridge | real private D3 evaluator + existing production scanner（profiled begin / exact_get / note_terminal_corrupt / advance / finalize）を oracle literal に対して実行 |
| Frozen authority pins | 各 D3 oracle は少なくとも D1 + S1–S5 の **path / format / full sha256 / vector_count** を pin する（byte-for-byte frozen regression） |
| Per-call statuses | 各 call に `expected_status`（scanner status または harness `VOID`） |
| Mutation | `mutation_calls=0` |
| Restart rules | cleanup `DONE` 後の `session_init` + fresh profiled begin；first post-restart `advance` budget=1 可；same-session budget resume を restart と偽らない |

**Current D3-S1 crossrow authority（implementation; not a rewrite of S0/S1a）:**

| Field | Exact value |
| --- | --- |
| Path | `spec/vectors/domain-scan-crossrow-v1.json`（D1 / S1–S5 sibling; merge 禁止） |
| Format | `ninlil-domain-scan-crossrow-v1-d3s1` |
| `vector_count` | **94** |
| Full JSON sha256 | `f47dff4f5753a92ebf3627408c576f69cc1862d20e1f74021e22ef5603c87176` |
| Canonical `content_sha256` | `76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468`（artifact embedded pin） |
| Independent generator | `tools/domain_scan_crossrow_vector_gen.py`（**production C を invoke/translate しない**） |
| Production bridge | real private D3-S1 evaluator + production scanner（`begin_profiled_d3s1` / exact_get / note_terminal_corrupt / advance / finalize） |
| Exact kinds | **94**（`required_kinds` exact closed set; generator/bridge anti-false-pass） |
| Mutation | **0**（Storage mutation calls 0; D2 と同） |
| Frozen upstream pins | D1 + S1–S5 の path / format / full sha256 / `vector_count`（下表 read-only; D3-S1 は rewrite しない） |

**D1 および S1–S5 JSON は read-only pins（S0 freeze）:**

下記 path / format / `vector_count` / full sha256 は **read-only authority pins** である。D3-S0 および通常の D3 実装 slice はこれらを **rewrite しない**。byte-for-byte regression の基準としてのみ参照する。

| Authority | Path | Format | vector_count | sha256 |
| --- | --- | --- | ---: | --- |
| S1 | `spec/vectors/domain-scan-v1.json` | `ninlil-domain-scan-v1-d2s1` | 18 | `5705363e8f8890849e41476013eab3cd4ac1a20b6c33efb54ab65f300d40a165` |
| S2 | `spec/vectors/domain-scan-profile-v1.json` | `ninlil-domain-scan-profile-v1-d2s2` | 32 | `b0ecac1d4d56e0abb63c53277ed5b1ab86a3e3c1377ad2393de6f4d74edcd0a5` |
| S3 | `spec/vectors/domain-scan-structural-v1.json` | `ninlil-domain-scan-structural-v1-d2s3` | 89 | `f8e75437202c90476aa93fb0a336c86ad03e7e4820510e15074a69cbc6041684` |
| S4 | `spec/vectors/domain-scan-exact-get-v1.json` | `ninlil-domain-scan-exact-get-v1-d2s4` | 30 | `5f458424a2f2adc1fd421285853b7567a9cc6fbf9ba43808b4d8dec69e4b9a8a` |
| S5 | `spec/vectors/domain-scan-composition-v1.json` | `ninlil-domain-scan-composition-v1-d2s5` | 22 | `9492b40771d4e30a3a24e0e23110da2ecb91ceaa286d169cc90186545085d549` |
| D1 | `spec/vectors/domain-store-v1.json` | `ninlil-domain-store-v1-d1b3o` | 1549 | `b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4` |

**Crossrow authority の append-only 進化（d3sN）:**

1. 後続 D3 slice が sibling oracle を導入・拡張するとき、authority は **append-only** で進む: prior vectors を削除・改竄せず、**prior fingerprint prefix**（既存 vector の identity / 期待値の安定接頭）を retain する。
2. format suffix は `…-d3sN` へ進められるが、**単一 sibling path** を破壊的 fork しない（別 schema へ silent 分岐しない）。
3. **意図的 revision**（prior vector の意味変更・削除・pin の付け替え）は、その authority の **Normative owner 変更と同時** にだけ許す（本章または当該 owner 節の Normative 更新と同一 change set）。単独の JSON rewrite は禁止。

**Pin update procedure（format / vector_count / full sha256; ファイル存在 claim なし）:**

後続 slice が crossrow sibling を **初めて作成** するか、append-only で拡張するとき、次を **同一 change set** で行う（S0 は手順だけを固定し、file を作らない）:

1. **Normative**: 本章（または slice 固有 owner 節）で schema / case 追加の意味を更新する。
2. **Generator**: independent generator が expected hex/status を決定論生成する（production C 非 invoke）。
3. **Artifact**: proposed path に JSON を作成または append（prior vectors retain）。
4. **Pins を同時更新**: 少なくとも次を document / CI / generator self-check の正本として更新する:
   - `format`（`ninlil-domain-scan-crossrow-v1-d3sN`）
   - `vector_count`（全 vector の exact 件数）
   - **full sha256**（file 全体の SHA-256）
5. **Upstream D1/S1–S5 pins**: 通常は **read-only のまま**。D1 または S1–S5 authority 自体を意図改訂する場合のみ、その owner の Normative 変更と同時に上表 pin を改訂する（D3 単独では触らない）。
6. **禁止**: pin だけ先に書く、Normative なしの JSON 改変、prior vectors の silent rewrite、full sha256 未更新の format/count 変更。

### 18.8 Corruption reporting freeze

| Rule | Exact contract |
| --- | --- |
| Who may note | **real D3 finding** だけが `ninlil_domain_scan_note_terminal_corrupt` を呼ぶ。D2-S6 seam / 偽 positive / profile mismatch だけでは呼ばない（§15.12.2 / §15.13） |
| First sticky | 既に sticky terminal がある場合は **first sticky を保持**（S5 note 契約） |
| Future precedence | sticky `STORAGE_CORRUPT` は recognizable future / profile candidate より **常に上位**（§15.2 / §16） |
| Skip D3 | `profile_mismatch` / `future_profile_candidate`（exact-profile inactive）では **D3 cross-row evaluator を起動しない**（S2 skip と同型: domain structural 0 のまま transport/f1-4 のみ） |
| Future then current D3 corrupt | recognizable future 観測後でも、後続で **current** D3 finding が立てば outcome は **corrupt** |
| Non-finding | Port/shape/lex/S3 structural の terminal は D2 既存経路。D3 はそれを再実装せず、cross-row finding だけを note する |

### 18.9 Stage 5 outcome ladder freeze

| Stage | Private outcome / flag | Meaning |
| --- | --- | --- |
| D2-S6 existing adopt（現行 main） | `EXISTING_SCAN_ADOPTED_D3_PENDING` + `storage_recovery_complete=0` | D2 scan adopted only。private **`EXISTING_SCAN_ADOPTED_D3_PENDING` を S12 完了まで retained** |
| D3 incomplete | 同上 outcome を維持してよい | 部分 D3 slice green を Stage 5 complete にしない |
| D3 complete（**S12**） | private **`EXISTING_SCAN_ADOPTED_D3_PENDING` → private `D4_PENDING`** へ transition（**implementation name は S12 で freeze**） | D3 finding green。**`storage_recovery_complete` は 0 のまま** |
| D4 / remaining gates | （D4 ledger 外） | identity / clock / health publish / public Runtime は別 gate |

**Closed non-claims for D3-S0 and all D3 implementation slices until §1 full gate:**

1. Stage 5 complete / `storage_recovery_complete == 1`
2. public Runtime / `runtime_create` publish
3. D4 mutation / convergence complete
4. Bearer / clock / entropy open
5. Stage 9 health publish
6. ESP-IDF compile / hardware
7. public C ABI / public status / new ADR（本 freeze は ADR を新設しない）

### 18.10 Missing D3 helper needs（code を装わない）

S0 時点で **存在する** D1 evidence（欠落 claim 禁止）:

- grammar 正本（本章 key/body/witness layout と same-record 閉包）
- pure helpers: `ninlil_model_domain_build_key` / `parse_key` / `key_digest` / `composite_digest` / `value_digest`
- typed body codecs と same-record validators（D1-A..B3o）
- body 内 raw identity fields（peer key rebuild の入力になる **forward** 材料）

**D1 authority の境界:** D1 は grammar + 上記 pure `build_key` / `key_digest` まで。typed peer rebuild helpers は **D3 work items** であり、D1 complete や「D1 に helper が無い＝D1 incomplete」の言い換えに使わない（§18.1）。

S0 時点で **D3 が必要とし、production helper として未接続 / 未固定のもの**（実装を claim しない; 後続 slice の work item）:

| Needed helper | Purpose | Notes |
| --- | --- | --- |
| **Peer-key rebuild helpers**（**D3 work items**） | typed body raw → complete secondary/primary key bytes（exact-1 / backlink） | `KEY_DIGEST` reverse ではない。D1 raw fields と `build_key`/`key_digest` は evidence 上存在する。typed 接続は D3-S1。closed mode 表は §18.12 |
| **Fixed D3 descriptor / context object** | exact_get 前に raw IDs/digests/counts を copy する fixed-size context | **Historical S0:** size TBD at S1。**S1a freeze（§18.12）:** exact layout 421 / ceiling 448; NEW aggregate arena ceiling 8832（8384+448; +128 over Stage5-alone 8704）。**S2a freeze（§18.13）:** S2 multipass context exact layout 306 / ceiling 320; outer future aggregate 9152 when S1+S2 co-resident。**S3a freeze（§18.14）:** S3 BLOB context exact layout 754 / ceiling 768; outer future aggregate 9920 when S1+S2+S3 co-resident。**S4a freeze（§18.15）:** S4 multipass context exact layout **949** / ceiling **960**; S1+S2+S4 **10112**; **full S1+S2+S3+S4 10880**。**S5a freeze（§18.16）:** S5 bounded-walk context exact layout **651** / ceiling **656**; S1+S2+S5 **9808**; **full S1+S2+S3+S4+S5 11536**。Stage5-alone 8704 / scanner 8192 unchanged。S1 implementation complete; S2/S3/S4/S5 implementation pending |
| **Witness member streaming consumer** | per-member chunk re-get + pins + dual membership full-M + same-txn primary PVD（2M+P） | D1 pure witness decode は存在; cross-row consumer は **D3-S4**（§18.15; implementation pending） |
| **Reservation contribution pure helper** | owner state → §13 exact live vector / quota contribution を pure 計算 | D1 RESERVATION body は存在; §13 formula pure helper は D3 所有で追加可 |

**Do not state** that D1 fields are missing unless a later audit proves a concrete body field gap。cross-row absence は D3 finding であり D1 incomplete の言い換えではない。

### 18.11 Completion boundary / historical truth

| Claim | After D3-S0 docs freeze |
| --- | --- |
| D3-S0 Normative freeze | **yes**（本節） |
| D3-S1a / S2a / S3a / S4a / S5a docs freeze | **yes**（§18.12 / §18.13 / §18.14 / §18.15 / §18.16; historical docs only） |
| D3 implementation complete | **no**（S1–S12 pending） |
| Stage 5 complete | **no** |
| D2 complete / D2-S6 seam | **unchanged**（既存） |
| public Runtime / ESP-IDF / hardware | **no** |

S0 historical row は後から「implementation complete」へ書き換えてはならない。S12 完了時も S0 行は **docs freeze only** のまま残す。

### 18.12 Normative D3-S1a freeze（closed modes / fixed context / private API）

**Decision identifier: D3-S1a。** 本節は D3-S0（§18 冒頭–§18.11）を **上書きせず**、exact-1 relationship-focused D3-S1 の **docs-only Normative freeze** を追加する。**docs only**: implementation / test / CMake / tools / vector JSON / ADR / code の追加・変更は本 slice で行わない。**D3-S1 implementation / D3 complete / Stage 5 / D4 / public Runtime / ESP-IDF / hardware は pending。** 本節は private API / type / constant が **既に存在する** とは claim しない（契約名と layout だけを固定する）。

**Design choice（relationship-focused; packed multi-peer を拒否）:** 1 fresh profiled scanner session につき **closed mode を exact 1 つ** だけ。applicable な current row では **at most one peer-key rebuild** と **at most one** same-snapshot `exact_get`。fixed relationship-type **`k=20`**。honest cost **O(20·N)**（固定 `k`；data-dependent `F`/`S` と混同しない。§18.5）。mode と row の subtype/family が mismatch なら **その row の get は skip** するが、**mode 自体は mandatory** であり silently disable / optional skip / nullable mode は禁止。

#### 18.12.1 Closed modes 1..20（exact relationship set）

**Forward exact-1（modes 1–16）:** source primary/owner row から body raw で peer complete key を rebuild → `exact_get` → `expect_presence` と（PRESENT 時）header `primary_value_digest` / peer body raw bijection を照合する。family-gated は EventFact / DesiredState（または DELIVERY family）に応じて PRESENT または ABSENT を要求する。

| Mode | Source | Peer | Expectation / gate | Rebuild material（D1 body/key evidence） |
| ---: | --- | --- | --- | --- |
| **1** | SERVICE | SERVICE_QUOTA | PRESENT exact-1 | `service_key_raw` → QUOTA composite key |
| **2** | SERVICE | SERVICE RESERVATION | PRESENT exact-1 | `owner_kind=SERVICE(1)` + service owner raw |
| **3** | TRANSACTION_ANCHOR | TRANSACTION_SEQUENCE_INDEX | PRESENT exact-1 | `transaction_sequence` / `transaction_id` |
| **4** | TRANSACTION_ANCHOR | TRANSACTION_STATE | PRESENT exact-1 | `transaction_id`（ID128） |
| **5** | TRANSACTION_ANCHOR | IDEMPOTENCY_MAP | PRESENT exact-1 | **dual RAW16:** `idempotency_scope_raw`（≤255）+ `idempotency_key`（≤64）byte-exact；hash substitute 禁止 |
| **6** | TRANSACTION_ANCHOR | TRANSACTION RESERVATION | PRESENT exact-1 | `owner_kind=TRANSACTION(2)` + `transaction_id` |
| **7** | TRANSACTION_ANCHOR | SCHEDULER_OWNER | PRESENT exact-1 | `scheduler_owner_sequence` / subject raw transaction ID |
| **8** | TRANSACTION_ANCHOR | EVENT_ID_MAP | **family-gated**: EventFact PRESENT / DesiredState ABSENT | Event: `scope_raw` + `event_id`；Command: get で ABSENT |
| **9** | TRANSACTION_ANCHOR | EVENT_SPOOL | **family-gated**: EventFact PRESENT / DesiredState ABSENT | Event: `transaction_id` ID128；Command: ABSENT |
| **10** | TRANSACTION_ANCHOR | CANCEL_STATE | **family-gated**: DesiredState PRESENT / EventFact ABSENT | DesiredState: `cancel_owner_kind=TRANSACTION` + `transaction_id`；Event: ABSENT |
| **11** | DELIVERY | RESULT_CACHE | PRESENT exact-1 | `delivery_key_raw` → RESULT_CACHE composite |
| **12** | DELIVERY | DELIVERY RESERVATION | PRESENT exact-1 | `owner_kind=DELIVERY(4)` + `delivery_key_raw` contents |
| **13** | DELIVERY | SCHEDULER_OWNER | PRESENT exact-1 | `scheduler_owner_sequence` / subject raw delivery |
| **14** | DELIVERY | CANCEL_STATE | **family-gated**: DesiredState DELIVERY PRESENT / EventFact DELIVERY ABSENT | DesiredState: `cancel_owner_kind=DELIVERY` + delivery raw；Event: ABSENT |
| **15** | ORDERED_INGRESS | INGRESS RESERVATION | PRESENT exact-1（PENDING） | `owner_kind=INGRESS(3)` + `ordered_sequence` BE8 |
| **16** | ORDERED_INGRESS | SCHEDULER_OWNER | **PRESENT（ABSENT 禁止）** — 下記 Mode 16 補正 | `owner_sequence` direct u64 key + owner raw/kind match |

**Mode 16 補正（Normative; ABSENT と言わない）:**

1. **`owner_binding_kind=NEW_DELIVERY`:** SCHEDULER_OWNER は **PRESENT** かつ **ingress-owned**（INGRESS-primary subject）。`owner_sequence` で exact_get し、peer body の `owner_kind` / `subject_key_raw` が本 ORDERED_INGRESS と bijection。
2. **`EXISTING_TRANSACTION` / `EXISTING_DELIVERY`:** 新 INGRESS-primary owner を作らない。**参照 `owner_sequence` 上の既存 owner SCHEDULER_OWNER も PRESENT** であり、peer の raw/kind は **referenced existing owner**（TRANSACTION_ANCHOR または DELIVERY）と exact match しなければならない。**ABSENT を期待してはならない。** この peer の common PVD は ORDERED_INGRESS ではなく referenced existing owner を指すため、Mode 16 で ingress value digest と比較してはならない。live PVD は Mode 17 が当該 SCHEDULER_OWNER row から referenced primary を `exact_get` して検証する。
3. owner **transfer / full cardinality / erase-after-reduce** の multi-row graph は **D3-S2** に残す。S1a/S1 の Mode 16 は known-key presence + raw/kind を閉じ、NEW_DELIVERY だけ ingress PVD を同じ get で照合する。EXISTING_* の live PVD は Mode 17 所有とする。

**Mode 17 REV_PRIMARY（closed enumerated true-primary reverse table）:**

Source secondary row から true primary を rebuild → `exact_get`。Every reverse edge expects **PRESENT** true primary、compares live primary **VALUE_DIGEST** to source header **PVD**、and proves **byte-exact raw identity** with the source body raw components used to rebuild the primary key. **IDEMPOTENCY_MAP reverse** uses **both** dual-raw buffers（`source_raw` scope + `source_raw2` idempotency key）against the peer ANCHOR dual RAW16 fields.

| Source secondary | True primary |
| --- | --- |
| SERVICE_QUOTA | SERVICE |
| RESERVATION `owner_kind=SERVICE(1)` | SERVICE |
| RESERVATION `owner_kind=TRANSACTION(2)` | TRANSACTION_ANCHOR |
| RESERVATION `owner_kind=INGRESS(3)` | ORDERED_INGRESS |
| RESERVATION `owner_kind=DELIVERY(4)` | DELIVERY |
| RESERVATION `owner_kind=CALLBACK(5)` | **DELIVERY**（CALLBACK `owner_key_raw` contents = **`delivery_key_raw:RAW16 || token_generation:u64`**。先頭の nested RAW16 length を検証して exact 80-byte delivery contents を抽出し DELIVERY key を forward rebuild する；header PVD は **DELIVERY** complete value。**RESULT_CACHE ではない**） |
| TRANSACTION_SEQUENCE_INDEX | TRANSACTION_ANCHOR |
| TRANSACTION_STATE | TRANSACTION_ANCHOR |
| IDEMPOTENCY_MAP | TRANSACTION_ANCHOR（dual-raw scope+key bijection） |
| EVENT_ID_MAP | TRANSACTION_ANCHOR |
| EVENT_SPOOL | TRANSACTION_ANCHOR |
| RETRY_SUMMARY | TRANSACTION_ANCHOR |
| MANAGEMENT_LEDGER | TRANSACTION_ANCHOR |
| SCHEDULER_OWNER | subject primary: TRANSACTION_ANCHOR / DELIVERY / ORDERED_INGRESS（`owner_kind` 1/2/3） |
| ATTEMPT | owner primary: TRANSACTION_ANCHOR / DELIVERY |
| ATTEMPT_ID_INDEX | TRANSACTION_ANCHOR（live primary PVD only；index↔attempt pair は Mode 18） |
| CANCEL_STATE | owner primary: TRANSACTION_ANCHOR / DELIVERY |
| EVIDENCE_CELL | owner primary: TRANSACTION_ANCHOR / DELIVERY |
| RESULT_CACHE | DELIVERY |
| REVERSE_REPLY | DELIVERY |
| RETENTION_BASIS | subject primary: TRANSACTION_ANCHOR / DELIVERY（reverse PVD/raw only） |
| CLEANUP_PLAN | subject primary: TRANSACTION_ANCHOR / DELIVERY（reverse PVD/raw only；phase/cardinality は **S11**） |

**Mode 17 明示除外（本 mode に載せない）:**

| Excluded | Evidence / owner |
| --- | --- |
| BLOB manifest / chunk | **S3** lifecycle；manifest は owner secondary かつ chunk primary の dual role（§9） |
| witness header / chunk / HEAD_INDEX exceptions | **S4–S6**；common primary digest **zero**（§9） |
| family 5 INTERNAL_INVARIANT markers | primary digest **zero**（§6 / §9） |
| ATTEMPT_REUSE_FENCE / BEARER_STATE / CLOCK_BASELINE / primaries themselves | primary digest **zero** または primary row（§9 zero-PVD closed set） |

**Mode 18 / 19 / 20（local gates）:**

| Mode | Relationship | Contract |
| ---: | --- | --- |
| **18** | **ATTEMPT ↔ ATTEMPT_ID_INDEX** | local gate only。TRANSACTION-owned local attempt は index **PRESENT**（pair / missing / collision）、DELIVERY-owned attempt は同じ `attempt_id` index key を **ABSENT probe**（unexpected PRESENT は corrupt）。**declared counts / multi-row streaming は禁止**（counts は **S2**）。Mode 17 が存在する index の live ANCHOR PVD を独立証明する |
| **19** | **RESULT_CACHE → CALLBACK RESERVATION** | **ACTIVE gate:** physical `delivery_state=2`（DELIVERY_STARTED）かつ `token_state=ACTIVE` のとき CALLBACK RESERVATION **PRESENT exact-1**（`owner_kind=CALLBACK(5)` + **`delivery_key_raw:RAW16 || token_generation:u64`**）。それ以外の Delivery physical state は CALLBACK RESERVATION **ABSENT**（§9）。gate は **nested RAW16 length + exact 80-byte delivery raw + token_generation** の presence/bijection だけを閉じる。**reservation header PVD を RESULT_CACHE value と比較してはならない**（reservation PVD は DELIVERY を指す；Mode 17 が CALLBACK RES→DELIVERY を独立証明） |
| **20** | **GATE_RETENTION_BASIS** | current **TRANSACTION_STATE** または **RESULT_CACHE** lifecycle row から subject retention key を導出する。**terminal retained** states は RETENTION_BASIS **PRESENT**、**active** states は **ABSENT**。terminal/active の判定は **既存 §9 terminal/nonterminal matrix** を exact に使う（S1a が新 enum case を発明しない）。実装 vector は legal state product を網羅する。本 mode は **presence + subject raw** を閉じる。peer retention header PVD は immutable ANCHOR/DELIVERY を指し **Mode 17** が独立証明する。CLEANUP phase / decreasing cardinality は **S11** |

**Dual-raw field audit（truthful closure; false freeze 禁止）:**

1. Mode 5 forward と IDEMPOTENCY reverse は **dual RAW16** identity を持つ: scope contents ≤255 と idempotency key contents ≤64 の **byte-exact** pair（§8.2 ANCHOR / IDEMPOTENCY_MAP）。single `source_raw[255]` だけでは dual identity を閉じられない。
2. 本 freeze の context は `source_raw[255]` + `source_raw2[64]` で dual-raw を **閉じる**。hash / truncated digest / single-buffer packing による substitute は **禁止**。
3. modes 1–20 の rebuild material は本章 §5 / §8 / §9 の body raw・key grammar から **forward** 導出できる（complete current key length 13..45；`KEY_DIGEST` reverse ではない）。
4. **「pending modes 0」を single-raw だけで主張してはならない。** dual-raw 欠落は Mode 5 / IDEM reverse の concrete field gap であった。本 layout がその gap を閉じた後も、後続 audit で別の concrete body field gap が証明された mode だけを reopen し、invented field で埋めない。

#### 18.12.2 Explicit exclusions（S1a/S1 非範囲）

| Exclusion | Owner slice |
| --- | --- |
| declared multi-count graph（ATTEMPT / EVIDENCE `L+1` / REVERSE_REPLY / RETRY / MANAGEMENT 等） | **D3-S2** |
| BLOB lifecycle / chunks / multi-chunk stream digest | **D3-S3** |
| SERVICE_QUOTA aggregate / service-key focus multi-pass | **D3-S9** |
| CLEANUP_PLAN overlay / phase decreasing cardinality | **D3-S11**（Mode 17 reverse PVD/raw は上表どおり S1a 範囲） |
| `KEY_DIGEST` reverse（digest-only → complete key / raw） | **forbidden**（§18.5） |
| witness member old/new / supersede / retire | **D3-S4..S6** |
| capacity 11-kind / health source set | **D3-S8 / S10** |

#### 18.12.3 Why multi-peer packing is rejected

1 つの current row に対し複数 peer exact_get を **同一 mode / 同一 context slot へ pack** する設計は **禁止**。理由:

1. **`exact_get` は source value / typed を破壊する。** success は `workspace->value` を上書きし、typed / borrowed source view を invalid にする（§15.11 / §18.4）。第 2 peer の rebuild 前に source body を再読できず、pack は silent corruption または第 2 の 4096 buffer を誘発する。
2. **DesiredState は 2 つの family-gated ABSENT edge を持つ**（TX→EVENT_ID_MAP / TX→EVENT_SPOOL；Command 側）。1 packed multi-peer pass は present peer と absent peer の expect を 1 回の get 結果へ押し込み、ABSENT と Port/terminal を混線させる。closed mode は edge ごとに `expect_presence` を独立に持つ。
3. **raw collision defense** は peer key の digest 一致だけでは不十分。source 側の **byte-exact raw**（service / scope / owner / dual-IDEM grammar）を保持し peer body raw と bijection する必要がある。packed context は raw slot を共有・上書きし collision を隠す。**dual RAW16**（scope + idempotency key）を 1 つの digest slot に潰すことも禁止。

したがって S1a は **1 session = 1 mode = per applicable row ≤1 rebuild + ≤1 exact_get** だけを合法とする。

#### 18.12.4 Fixed D3 context layout（all `uint8` fields）

**Object name（contract only; code 未 claim）:** private fixed D3 relationship context。scanner workspace とは **separate**。natural packing は **align 1**（全 field `uint8_t` / byte array）。

```text
expected_pvd[32]
peer_key[45]
source_raw[255]
source_raw2[64]
source_aux[16]
peer_key_len        : u8
source_raw_len      : u8
source_raw2_len     : u8
source_aux_len      : u8
mode                : u8   /* 1..20 */
flags               : u8
source_subtype      : u8
expect_presence     : u8   /* ABSENT / PRESENT closed */
owner_kind          : u8
```

| Property | Exact contract |
| --- | --- |
| **sizeof** | **421** = 32+45+255+64+16+9 |
| **alignment** | **1**（byte layout; padding 0） |
| **object ceiling** | **448**（fixed headroom; silent grow 禁止） |
| `peer_key[45]` | complete current Domain key max（§5: key length 13..45） |
| `source_raw[255]` | RAW16 service / scope / owner grammar の byte-exact collision defense（max 255 contents） |
| `source_raw2[64]` | **dual RAW16 second buffer**（Mode 5 / IDEMPOTENCY reverse の `idempotency_key` ≤64 contents）。hash / truncated digest **substitute 禁止** |
| `source_aux[16]` | mode 固有の固定補助 identity（例: `token_generation` / attempt_id 片側 / sequence BE8 left-pad 等）。可変 list 禁止 |
| control bytes | **nine** `u8`: `peer_key_len`, `source_raw_len`, `source_raw2_len`, `source_aux_len`, `mode`, `flags`, `source_subtype`, `expect_presence`, `owner_kind` |
| `mode` | **1..20 only**。0 / >20 / unknown は prevalidation `INVALID_ARGUMENT` |
| `expect_presence` | D2-S4 presence と同型 closed ABSENT/PRESENT。family-gated mode が row family に応じてセット |
| Mutation | context は copy-before-get 用；Storage mutation 0 |

#### 18.12.5 Memory ceilings（doc-first; explicit aggregate +128）

| Object | Current measured / documented layout | Future with D3 session pointer | Ceiling freeze |
| --- | ---: | ---: | ---: |
| scanner workspace | **8096 ≤ 8192** | unchanged | **8192**（**unchanged**） |
| scan session | **136** | **144**（+ pointer to D3 context; non-owning） | session は aggregate 内 |
| Stage5 seam workspace alone | **8376 ≤ 8704** | **8384**（session 144） | **Stage5-seam-alone 8704 unchanged** |
| D3 context object | — | sizeof **421** / ceiling **448** | **448** |
| **aggregate arena**（Stage5 future + D3 context） | — | packed sum **8384+421 = 8805**；outer **align8 actual = 8808** | **NEW D3 aggregate arena ceiling 8832**（= 8384+448） |

**Explicit doc-first increase:** aggregate ceiling **8832** は既存 Stage5-alone **8704** から **+128** の intentional raise である（= 8384+448）。silent ではない。**scanner ceiling 8192** と **Stage5-seam-alone ceiling 8704** は **変更しない**。future session **144** と Stage5 future packed **8384** も **unchanged**。

**Stage5 非 bind 規則:** Stage5 private seam は **S12 まで** D3 context を **allocate / bind / run しない**。S12 未満の seam は既存 `begin_profiled`（D2-only）のまま `EXISTING_SCAN_ADOPTED_D3_PENDING` を retain する（§18.9）。

#### 18.12.6 Strict future private API contract

| API（contract name only） | Normative rule |
| --- | --- |
| **`ninlil_domain_scan_begin_profiled`** | **D2-only のまま**。D3 mode/context を受け付けない。既存 S2–S6 / Stage5 経路を破壊しない |
| **`ninlil_domain_scan_begin_profiled_d3s1`** | D3-S1 実装が追加する production private begin。**prevalidation（mutation / Port 前）** で: `mode ∈ 1..20`、D3 context **non-NULL**、session / workspace / ops / handle / candidate / context が **pairwise disjoint**、context が object ceiling 内。違反は Port 0・`INVALID_ARGUMENT`・状態不変 |
| **nullable / optional skip** | **禁止**。`context==NULL` で D3 を skip する production path、mode 0「disabled」、optional gate は fail-closed |
| **Stage5 until S12** | seam は **旧 `begin_profiled` のみ**。`begin_profiled_d3s1` を呼ばない |
| **TEST transport begin** | 引き続き tests-OFF / Stage5 から absent（§15.10） |

本 freeze はこれらの symbol が **現 branch に存在する** とは述べない。D3-S1 が doc-first 契約に従って追加する。

#### 18.12.7 Evaluator order and finding vs Port terminal

Production exact-profile path での per-row private evaluator（hybrid local leg; §18.3）:

1. D2 **S3 structural success** の後。
2. **`previous_key` 更新および `ok_row_count` 加算の前**（corrupt finding を ok-row と偽らない）。
3. source に必要な raw / raw2 / PVD / aux / expect_presence を D3 context へ **copy-before-get**。
4. **`workspace->key` は preserve**（iterator current key を peer rebuild で壊さない）。peer key は context `peer_key[]` または alias 規則を満たす scratch を使う。
5. mode が row に非 applicable なら get 0 で次 row；mode 自体は session で固定。
6. applicable なら peer rebuild → exact 1 `exact_get`。
7. **Port-path terminal**（IO / unknown / shape / sticky FAILED）は **D2 sticky 契約のみ**。**`note_terminal_corrupt` を呼ばない**（D2 Port terminal = no D3 note）。
8. **real D3 findings** だけ note する: missing when PRESENT expected、present when ABSENT expected、PRESENT だが **PVD mismatch**、**raw / dual-raw bijection mismatch** / collision raw、Mode 16 owner kind/raw mismatch、Mode 19 ACTIVE gate 違反（presence/raw/token only；PVD-to-RESULT 比較禁止）、Mode 20 retention gate 違反（§9 terminal matrix に対する PRESENT/ABSENT）。
9. borrowed peer value / PVD は次の advance / exact_get / finalize / abort 前に消費（§18.4）。

`profile_mismatch` / `future_profile_candidate`（exact-profile inactive）では evaluator を起動しない（§18.8）。

#### 18.12.8 Sibling oracle architecture only（JSON は作らない）

S1a は `spec/vectors/domain-scan-crossrow-v1.json` を **作成しない**（§18.7 継続）。後続 D3-S1 oracle が満たすべき **architecture checklist** だけを固定する:

| Case class | Must cover |
| --- | --- |
| Mode coverage | **all 20 modes**（positive PRESENT と family-gated ABSENT の両方；Mode 17 closed reverse sources；Mode 20 は §9 legal state product を網羅） |
| DS EVENT_MAP / EVENT_SPOOL absent | DesiredState で Mode 8/9 ABSENT を **two fresh sessions**（1 mode / session）で独立証明 |
| Restart / front-key | cleanup `DONE` 後 fresh `session_init` + begin；first post-restart `advance` budget=1 可；front key assert |
| Prevalidation | null context、bad mode（0/>20）、alias/overlap → Port 0・不変 |
| Port-no-note | exact_get Port terminal で sticky のみ、`note_terminal_corrupt` 呼び出し 0 |
| Raw collision | same digest path でも source/peer raw mismatch → D3 note；dual-raw IDEM mismatch も note |
| CALLBACK split | Mode 19 presence gate と Mode 17 CALLBACK→DELIVERY PVD を独立；Mode 19 が RESULT value と reservation PVD を比較しないこと |
| Profile skip | mismatch / future candidate で D3 evaluator 0 |
| D2 begin no-D3 | `begin_profiled` 経路は D3 mode/context を持たず cross-row note 0 |

Independent generator / production bridge / format `ninlil-domain-scan-crossrow-v1-d3sN` / D1+S1–S5 pin 規則は §18.7。**S1a で JSON / generator / bridge を追加しない。**

#### 18.12.9 Completion boundary / non-claims（S1a）

| Claim | After D3-S1a docs freeze |
| --- | --- |
| D3-S0 architecture freeze | **yes**（historical; §18 冒頭–§18.11 unchanged in meaning） |
| D3-S1a Normative freeze（modes/context/API contract） | **yes**（本節） |
| D3-S1 implementation complete | **no** |
| D3 complete / S12 | **no** |
| Stage 5 complete / `storage_recovery_complete=1` | **no** |
| Stage5 allocates/binds/runs D3 context | **no until S12** |
| public Runtime / D4 / ESP-IDF / hardware | **no** |
| Implemented private APIs/types/constants exist | **no claim** |

S1a historical row を後から「implementation complete」へ書き換えてはならない。D3-S1 実装 PR は別 change set で S1 行だけを進める。

**Current status after D3-S1 implementation（separate row; does not rewrite the S1a table above）:**

| Claim | After D3-S1 implementation |
| --- | --- |
| D3-S0 architecture freeze | **yes**（historical docs only; unchanged） |
| D3-S1a Normative freeze | **yes**（historical docs only; unchanged — **not** re-labeled as implementation） |
| D3-S1 implementation complete | **yes**（exact-1 modes 1..20 + context + `begin_profiled_d3s1` + evaluator + crossrow oracle/bridge; §18.2 / §18.7） |
| Crossrow authority | format `ninlil-domain-scan-crossrow-v1-d3s1` / `vector_count` **94** / full JSON sha256 `f47dff4f5753a92ebf3627408c576f69cc1862d20e1f74021e22ef5603c87176` / canonical `content_sha256` `76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468` / independent generator + production bridge / exact 94 kinds / mutation 0 / frozen D1+S1–S5 pins |
| D3-S2a Normative freeze | see §18.13.18（docs only; not claimed in this S1 row） |
| D3-S3a Normative freeze | see §18.14.18（docs only; not claimed in this S1 row） |
| D3-S2 / D3-S3 / D3-S4 implementation / D3-S5..S12 | **pending**（S4a docs freeze は §18.15; S5a docs freeze は §18.16; implementation は pending） |
| D3 complete / S12 outcome transition | **no** |
| Stage 5 D3 bind / Stage 5 complete / `storage_recovery_complete=1` | **no** |
| D4 / public Runtime / ESP-IDF / hardware | **no** |
| SDK / field / V1 readiness | **no** |

### 18.13 Normative D3-S2a freeze（declared multi-count / same-txn multipass）

**Decision identifier: D3-S2a。** 本節は D3-S0（§18 冒頭–§18.11）および D3-S1a（§18.12）を **上書きせず**、declared multi-count graph を所有する **D3-S2** の **docs-only Normative freeze** を追加する。根拠は 3 件の design adjudication（contiguous-run reject + same-txn multipass + same-txn BIND）。**docs only**: implementation / test / CMake / tools / vector JSON / ADR / code の追加・変更は本 slice で行わない。**D3-S2 implementation / D3 complete / Stage 5 / D4 / public Runtime / ESP-IDF / hardware は pending。** 本節は private API / type / constant が **既に存在する** とは claim しない（契約名と layout だけを固定する）。

**Design choice（snapshot-only declared multi-count; owner-contiguous fiction を拒否; 1 session = 1 mode）:** S2 は §9 の **snapshot** declared-count / multi-row cardinality + live owner/PVD/raw binding だけを閉じる。erase-after-reduce / transfer **history** は snapshot に無く **D4**。**1 profiled S2 session = 1 mode `m` ∈ {21..26} = 1 bound `READ_ONLY` txn**: baseline once → **only** that mode の carrier FOCUS loop + corresponding same-txn BIND set → COMPLETE | FAILED。**`k₂=6`** は D3-S2 **complete** の closed mode 集合（**6 self-contained sessions**）であり、「1 begin の中で 6 modes」ではない。honest **per-session** cost **O(Fₘ·N + mode BIND subtype walks)**（data-dependent `Fₘ`; §18.5 category **D**）；full S2 product cost は 6 sessions の **sum**（各 session が独立 baseline）。S1 exact-1 modes 1..20 と packed multi-peer 禁止は維持。S1/S2 contexts は **scanner session ごとに mutually exclusive**（dual-bound 禁止）。

#### 18.13.1 Snapshot-only declared multi-count scope

| In scope（S2） | Out of scope |
| --- | --- |
| Ordinary §9 declared multi-cardinality when **CLEANUP_PLAN ABSENT** | Plan phase decreasing / `remaining_*` / fence aggregate（**S11**） |
| Focus stream counts: ATTEMPT / ATTEMPT_ID_INDEX / MANAGEMENT | BLOB lifecycle / multi-chunk digest（**S3**） |
| Known-slot presence: EVIDENCE / REPLY / RETRY | Witness old/new / supersede / retire（**S4–S6**） |
| Same-txn BIND: secondary→**declared-count carrier** presence/body + true primary PVD/raw + Mode21 ATTEMPT↔INDEX pairs | Capacity 11-kind / health / SERVICE_QUOTA multipass（**S8 / S10 / S9**） |
| `DSD1_LOGICAL_DELIVERY` **composition** of S1+S2 snapshot pieces（multi-session） | Writer E2E / public ABSENT projection（**D4**） |
| Snapshot shapes only（APPLICATION_FIRST / CANCEL_FIRST cardinalities） | Mode 16 owner-transfer **timeline** / erase-after-reduce history（**D4**） |

**Non-ownership of S1 success:** S2 は Mode 1–20 exact-1 presence/PVD/raw を「再成功」として claim しない。S2 は multi-count + same-txn binding だけを所有する。

#### 18.13.2 Closed modes 21..26（k₂=6; 1 session = 1 mode）

| Mode | Name | Carrier set（SELECT） | Ordinary declared（plan ABSENT） | FOCUS set | BIND set | Count mechanism |
| ---: | --- | --- | --- | --- | --- | --- |
| **21** | `TX_ATTEMPT` | live `TRANSACTION_STATE`（ID128 tx; companion ANCHOR/SPOOL install as needed） | App ATTEMPT = `cumulative_attempts`; CANCEL ATTEMPT 0\|1 per §9; INDEX total = app+cancel | `FOCUS_ATTEMPT` + `FOCUS_INDEX` | `BIND_ATTEMPT` + `BIND_INDEX`（pair both ways） | **stream** TX-owned ATTEMPTs + TX-local INDEX |
| **22** | `DELIVERY_ATTEMPT` | live `RESULT_CACHE` | APPLICATION_FIRST: app = `application_attempt_count` ≥1; CANCEL_FIRST: app=0 + cancel ATTEMPT=1; **INDEX expect 0**（not a focus/bind walk） | `FOCUS_ATTEMPT` **only** | `BIND_ATTEMPT` **only**（per row: INDEX **ABSENT** peer; **no** `FOCUS_INDEX` / **no** `BIND_INDEX`） | **stream** DELIVERY-owned ATTEMPTs |
| **23** | `EVIDENCE` | TX retained `TRANSACTION_STATE` / DELIVERY APPLICATION_FIRST `RESULT_CACHE`（CANCEL_FIRST → 0 cells） | `L = accepted profile max_evidence_per_target`（1..8; **not** a cell body field）; slots 0..L; SUMMARY@0 counters | `FOCUS_EVIDENCE` | `BIND_EVIDENCE` | **known-slot** `exact_get` |
| **24** | `REVERSE_REPLY` | live `RESULT_CACHE` | count = `reply_count`（0..4）; ≤1 per closed `reply_kind` | `FOCUS_REPLY` | `BIND_REPLY` | **known-kind** `exact_get` |
| **25** | `RETRY` | each CUMULATIVE RETRY（kind=1, slot=0） as carrier | CUM exact 1 when retained; RECENT = `min(total_completed_cycle_count, 4)`; D1 slot matrix | `FOCUS_RETRY` | `BIND_RETRY` | **known-slot** `exact_get` |
| **26** | `MANAGEMENT` | live `EVENT_SPOOL` | count = `successful_resume_count + discard_committed`（0..9） | `FOCUS_MANAGEMENT` | `BIND_MANAGEMENT` | **stream** same-tx MANAGEMENT rows |

**Session product（Normative）:**

1. `begin_profiled_d3s2(..., mode=m, ctx)` は **exact 1** mode を bind し `focus_mode := m` を context に固定する。
2. その session は **FOCUS set(m) と BIND set(m) だけ** を走らせる。他 mode の FOCUS/BIND family を同じ session で実行することは **illegal**。
3. **Mode 21 pairing is mandatory:** INDEX は Mode 27 ではなく Mode 21 の inseparable half。Mode 21 COMPLETE は ATTEMPT+INDEX の focus close **and** both BIND passes を要求する。
4. **Mode 22 INDEX discipline:** INDEX は Mode 22 の focus stream / BIND_INDEX walk ではない。DELIVERY-owned ATTEMPT 行ごとの **INDEX ABSENT peer probe は `BIND_ATTEMPT` 内だけ**（Mode 18 multi-row の S2 側）。
5. **D3-S2 implementation complete** = modes **21..26** の **6 self-contained sessions** がすべて close（各 session は snapshot-self-contained; harness が同一/別 snapshot を選ぶ; 1 baseline が 6 modes をカバーすると偽らない）。
6. S2a は multi-mode orchestration API を claim しない。

**Dropped / rejected mode inventions:** Mode 27 orphan-aggregate-as-mode、Mode 28 standalone DSD1 product mode — **禁止**。orphan/binding は §18.13.9 の mode-scoped **BIND_*** INTERNAL passes。DSD1 は §18.13.16 multi-session composition。

**INDEX wording（tight）:** 独立 mode を増やさない。TX-local（Mode **21**）: `declared_index_total := declared_app_attempt_count + declared_cancel_attempt_count`（§9: INDEX count = local ATTEMPT count; independent STATE field ではない）。DELIVERY focus（Mode **22**）: `declared_index_count = 0` かつ **no FOCUS_INDEX / no BIND_INDEX**; unexpected INDEX は `BIND_ATTEMPT` の ABSENT-peer fail としてだけ note する。

#### 18.13.3 SHA256_COMPOSITE keys are not owner-contiguous

Complete Domain key order:

```text
root[8] | family | subtype | key_format=1 | identity_kind | identity_length | identity[]
```

S2 multi-count secondaries use **`SHA256_COMPOSITE` identity**（§5.1）:

| Family | Identity | Same-owner contiguous? |
| --- | --- | --- |
| ATTEMPT `0x31` | `COMPOSITE(31, owner_kind\|\|owner_raw\|\|attempt_id)` → hash | **No** |
| EVIDENCE `0x32` | `COMPOSITE(32, owner_kind\|\|owner_raw\|\|slot_u32)` → hash | **No**（slots of one owner scatter） |
| REVERSE_REPLY `0x42` | `COMPOSITE(42, reply_key_raw)` → hash | **No** |
| RETRY `0x51` | `COMPOSITE(51, tx16\|\|kind\|\|slot)` → hash | **No** |
| MANAGEMENT `0x52` | `COMPOSITE(52, tx16\|\|op_id)` → hash | **No** |

What **is** contiguous: entire **subtype band**; non-hash carriers such as `TRANSACTION_STATE` / `EVENT_SPOOL` ID128(tx); `ATTEMPT_ID_INDEX` ID128(attempt_id)（by attempt id, **not** by tx — INDEX contiguous-per-tx count は **禁止**）。

**Implication（adjudication #1）:** owner contiguous-run as S2 core algorithm is **false** under real key grammar。§18.5 category B をこれらの families に same-primary run として適用してはならない（§18.5 applicability correction）。

#### 18.13.4 Same-txn phase machine（baseline once + sequential reopen; mode-scoped）

S2 は **higher-level phase machine** であり、S1 の「+6 modes」ではない。1 session は **1 mode** の FOCUS/BIND set だけを完走する。

**Illegal（P0）:**

- focus 列挙を txn A で行い、count を txn B（fresh `begin` / new snapshot）で行うこと
- second **concurrent** live iterator
- full-ID / focus set を RAM に保持
- same-session で D2 baseline を再実行して `ok_row_count` / family14 reconciliation を二重加算すること
- 1 session で `focus_mode` 外の FOCUS/BIND family を走らせること
- 1 session で modes 21..26 を「全部証明した」と claim すること

**Required:**

| Rule | Exact contract |
| --- | --- |
| Snapshot | 全 proof in this session は **単一** bound `READ_ONLY` txn |
| Mode | `focus_mode` fixed at begin; FOCUS set / BIND set / carrier set は mode table（§18.13.2） |
| Baseline | D2 profiled begin path を **once**: `begin(RO)` → 17 family1–4 `get` → one zero-prefix `iter_open` → advance to EXHAUSTED |
| Internal multipass | baseline 後、sole zero-prefix iterator を **close → reopen**（txn は rollback しない） |
| Live iterators | always **≤1**; sequential reopen は multi `iter_open` count を許すが concurrent live は 0 |
| Prefix iters | production S2 では **zero-prefix only**（non-zero family/subtype/owner prefix は禁止） |
| Fresh session | §18.3 の「fresh session multi-pass」は S2 **cardinality の vehicle ではない**（honest independent one-pass proofs には残り得るが、list-then-count は禁止）。D3-S2 complete の 6 modes は **6 sessions** |

**Phase enum（contract; control order ≠ Stage 5 scan order）:**

```text
IDLE → BASELINE
    → (SELECT_CARRIER → CLEANUP gate → FOCUS set(focus_mode))*
    → BIND set(focus_mode)
    → COMPLETE | FAILED

FOCUS set / BIND set = §18.13.2 closed pairs
  Mode21 = ATTEMPT+INDEX focus and bind
  Mode22 = ATTEMPT focus + BIND_ATTEMPT only
  Modes23–26 = single FOCUS_* + matching BIND_*
```

| Phase class | Duty |
| --- | --- |
| `BASELINE` | D2 structural + counter/reconciliation once; freeze D2 globals + future/profile diagnostics |
| `SELECT_CARRIER` | next **mode-eligible** cardinality carrier with complete key **strictly greater** than `last_carrier_key` |
| `FOCUS set(focus_mode)` | per-focus declared vs observed（or cleanup skip） for **only** that mode’s focus bits |
| `BIND set(focus_mode)` | begins only when `focus_live==0` and carrier loop done; global same-txn **declared-count carrier** presence/body subject + true primary PVD/raw（+ Mode21 pairs / Mode22 INDEX ABSENT） for **only** that mode’s bind bits |
| `COMPLETE` | baseline done; no sticky; `focus_live==0`; all eligible carriers for `focus_mode` selected exactly once（**including empty-carrier**: zero carriers is legal）; `count_complete_mask` satisfied for every closed carrier（observed may clear on carrier advance; **must not** clear `binding_complete_mask`）; `binding_complete_mask` has all bits required by `focus_mode`; every required BIND finished without sticky |
| `FAILED` | sticky already on session |

**Empty-carrier behavior（Normative）:** zero eligible carriers for `focus_mode` still requires BIND set(`focus_mode`) walks。Empty secondary band（0 rows ⇒ no binding notes）then COMPLETE when masks are satisfied。**Non-empty secondary band under empty-carrier fails through BIND**（each secondary’s declared-count carrier ABSENT/subject fail is a real S2 orphan finding; must not COMPLETE green）。Example: Mode 21 with zero TX carriers and zero ATTEMPT/INDEX rows still runs empty `BIND_ATTEMPT` + `BIND_INDEX` then COMPLETE; Mode 21 with zero TX carriers but live ATTEMPT rows notes orphan via BIND carrier ABSENT。

#### 18.13.5 PASS_INTERNAL fence（D2 counters / future / profile frozen; pass-local lex only）

```text
PASS_BASELINE = 0
PASS_INTERNAL = 1
```

| Effect | `PASS_BASELINE` | `PASS_INTERNAL` |
| --- | --- | --- |
| `ok_row_count` / `family14_*` / `current_domain_key_count` / recon masks | D2 truth increments / once reconciliation | **frozen; must not re-run / re-increment / re-reconcile** |
| `profile_exact_active` / `profile_mismatch` / `future_profile_candidate` / `recognizable_future_seen` | D2 may set | **must not mutate**（no set/clear/recompute） |
| S3 structural | yes（exact-profile） | re-decode **for S2 filter only** when `profile_exact_active`; may note real S2 findings; **not** a second D2 baseline。if baseline left profile inactive, S2 evaluator remains **off** for whole machine |
| Recognizable future row（D2 class） | D2 candidate flag + continue | **S2 skip**: not a focus match; not a BIND subject; no S2 note; still a successful OK visit for **row_budget** only |
| MALFORMED / non-future terminal | D2 sticky | same; S2 does not reinterpret |
| D3-S1 evaluator | if bound（S2 default: not bound） | **off** |
| D3-S2 focus/BIND evaluator | off | on（when profile exact active） |
| `previous_key` / `has_previous` | baseline lex | **reset on each reopen**; pass-local lex only |
| `exact_get` | legal OPEN/EXHAUSTED | legal OPEN/EXHAUSTED; does not consume `row_budget` |

Baseline counters are the **only** values published on `ninlil_domain_scan_result` for D2 diagnostics。Internal observed counters live **only** in S2 context。INTERNAL must not use future rows as “extra” secondaries and must not clear baseline future/profile diagnostics on finalize path。

##### 18.13.5.1 Drive / `row_budget` progress（B0–B11）

```text
B0. row_budget == 0 → NINLIL_E_INVALID_ARGUMENT; Port 0; session/context unchanged (D2).

B1. Positive row_budget counts successful OK rows visited by advance’s iter_next
    path only (D2 definition). Classification / bookkeeping / exact_get do NOT
    consume budget.

B2. PASS_BASELINE: OK rows consume budget AND update D2 counters (D2).

B3. PASS_INTERNAL: OK rows consume budget BUT do not update frozen D2 counters
    (table above). S2 observed_*/masks/phase/flags may update.
    H1 still runs for S2 filters but must not touch frozen D2 counters.

B4. exact_get (CLEANUP_PLAN, known-slot, BIND primary/carrier companion/pair peer) never consumes budget.

B5. Budget exhaustion (consumed == row_budget) with more work remaining:
    - return NINLIL_OK
    - state remains OPEN if iterator not at NOT_FOUND; EXHAUSTED only on true end
    - do NOT run H2 focus-close compare
    - do NOT clear focus_live
    - do NOT advance phase to next FOCUS/BIND/COMPLETE
    - preserve observed_*, masks, last_carrier_key, phase, pass_kind, cleanup_skip
    - next advance resumes the same phase mid-pass (same-session resume ≠ restart)

B6. True iterator EXHAUSTED (NOT_FOUND validated) on a FOCUS **stream** pass only
    (Mode21 ATTEMPT/INDEX; Mode22 ATTEMPT; Mode26 MANAGEMENT):
    - H2 runs (after state=EXHAUSTED, before return OK): compare or cleanup_skip
    - set the appropriate count_complete_mask bit; clear focus_live for that
      focus sub-phase; may reopen for next FOCUS sub-phase / SELECT / BIND
    - **Not applicable to FOCUS known-slot** (Modes 23–25): those close after the
      exact_get presence matrix completes (B6k), without requiring iterator EXHAUSTED.

B6k. FOCUS known-slot close (Modes 23–25; exact_get only — no secondary stream walk):
    - after setup (CLEANUP_PLAN / companions as applicable) and all required
      known-slot / known-kind presence exact_gets for the current carrier,
      run focus-close compare (same duty as H2: compare or cleanup_skip path)
    - set the appropriate count_complete_mask bit; clear focus_live for that
      focus sub-phase; may proceed to next FOCUS sub-phase / SELECT / BIND
    - does not consume row_budget (B4); does not wait for iterator EXHAUSTED
    - budget stop mid-matrix (if drive yields before matrix done): preserve state
      and resume (same spirit as B5; do not close focus early)

B7. True EXHAUSTED on SELECT_CARRIER with no next carrier:
    - if focus_live!=0 → invariant fail (must not happen)
    - else enter BIND set(focus_mode) on subsequent drive steps (reopen as needed)
    - empty-carrier path: still enter BIND set(focus_mode)

B8. True EXHAUSTED on a BIND subtype walk:
    - set corresponding binding_complete_mask bit
    - if mask complete for focus_mode → COMPLETE; else reopen next BIND subtype in set

B9. Port failure mid-FOCUS/BIND (H3): sticky FAILED; no undercount note;
    incomplete observed is not corrupt-by-undercount.

B10. ninlil_domain_scan_d3s2_drive (contract): may call advance with caller budget
     repeatedly; must obey B5–B9 and B6k; must not finalize as the first place
     count is compared when compare needs live txn (stream H2 / known-slot B6k /
     BIND mandatory while txn live).

B11. Fresh session restart after DONE is a new baseline (new begin); it is not
     mid-focus resume. Oracle must distinguish the two. Each of the six complete
     product sessions baselines independently.
```

#### 18.13.6 Carrier cursor selection by complete key（mode-dependent）

Context holds **complete key** of last installed carrier: `last_carrier_key[45]` + `last_carrier_key_len`（`len==0` ⇒ −∞）。

**SELECT_CARRIER**（INTERNAL, zero-prefix from front）:

1. Walk OK current-domain rows in D2 lex order。
2. Skip non-carriers for **`focus_mode`**（§18.13.2 carrier set）; skip keys `<= last_carrier_key`（length-aware memcmp と同型の D2 lex）; skip recognizable future（§18.13.5）。
3. First remaining mode-eligible cardinality carrier becomes `next`; copy complete key → `last_carrier_key`; install focus raw / tx id / primary_key_digest / declared A/B/C + small fields per §18.13.12.1。
4. If no next → enter BIND set(`focus_mode`) only if `focus_live==0` and count requirements for the last carrier are satisfied（or no carriers / empty-carrier）; else if `binding_complete_mask` already has all required bits → COMPLETE; else FAILED sticky path if invariants broken。

**No skip / no dup:** every eligible carrier for `focus_mode` is selected exactly once as the unique min among remaining keys `> last`。Ordering is **complete encoded key** order（including identity digest）、not owner-raw order。

**Closed carriers by mode（restate）:**

| Mode | Eligible carrier rows |
| ---: | --- |
| **21** | live `TRANSACTION_STATE`（TX multi-count install; ANCHOR/SPOOL companions as copy sources only） |
| **22** | live `RESULT_CACHE` |
| **23** | live `TRANSACTION_STATE` retained TX **or** live `RESULT_CACHE` APPLICATION_FIRST; CANCEL_FIRST RESULT installs declared evidence set empty |
| **24** | live `RESULT_CACHE` |
| **25** | CUMULATIVE `RETRY_SUMMARY`（kind=1, slot=0） |
| **26** | live `EVENT_SPOOL` |

Exact-1 companions remain **S1**。S2 copies multi declared fields **before** leaving the carrier row（copy-before-get）。

#### 18.13.7 Focus count mechanisms

| Pass class | `exact_get` | Proves |
| --- | --- | --- |
| **FOCUS stream**（Mode21 ATTEMPT/INDEX; Mode22 ATTEMPT; Mode26 MANAGEMENT） | **0 per secondary row** | body owner/raw + `primary_key_digest` match → observed++; focus close on true iterator **EXHAUSTED** only（B6/H2） vs declared A/B/C |
| **FOCUS known-slot**（Mode23 EVIDENCE / Mode24 REPLY / Mode25 RETRY） | **presence gets only**（rebuild slot/kind key → PRESENT/ABSENT matrix; **no** secondary stream / **no** iterator EXHAUSTED required） | count/slot/kind closure after matrix complete（**B6k**）; **not** live primary PVD（value overwrite; BIND later） |
| **FOCUS setup** | CLEANUP_PLAN get（≤1）+ optional non-current carrier companion（≤1） | plan skip gate; install declared |
| **BIND_*** | ≤1 true-primary get + ≤1 **declared-count carrier companion** get + ≤1 pair peer get per secondary row（**max 3** for Mode21/22 ATTEMPT; not every row uses all three） | same-txn carrier presence/body subject + live true primary PVD/raw（+ Mode21 pairs / Mode22 INDEX ABSENT） |

**Focus-close split（Normative）:** B6 / H2 / H5 iterator-EXHAUSTED focus-close rules apply **only to FOCUS stream** modes。FOCUS known-slot is **exact_get only** and closes via **B6k** after the presence matrix for the current carrier — not via iterator EXHAUSTED。

**Matching predicate（stream）:** `body.owner_kind` / owner raw / `transaction_id` / delivery raw matches focus **and** `body.primary_key_digest == focus_primary_key_digest`（FOCUS-phase meaning: carrier primary **KEY_DIGEST**）。Mode21 may split observed app vs cancel via in-band `attempt_kind`。

#### 18.13.8 CLEANUP_PLAN presence gate

On every focus open:

1. Rebuild `CLEANUP_PLAN` key = `COMPOSITE(63, subject_kind || KEY_DIGEST(complete primary key))` → `exact_get`（≤1 of setup budget）。
2. **PRESENT** → for **ordinary ATTEMPT / Mode21 INDEX count only**: set `cleanup_skip=1`；**do not** compare vs ordinary declared app/cancel/index fields；**do not note** ordinary under/over。Defer phase/remaining/fence to **S11**。
3. **ABSENT** → ordinary §9 declared counts apply；`cleanup_skip=0`。
4. `cleanup_skip` is cleared on carrier advance。Modes **23–26** force `cleanup_skip=0` and still apply ordinary counts。

| Mode / family | Plan PRESENT |
| --- | --- |
| **21** ordinary app/cancel ATTEMPT counts + INDEX total equality | **Mandatory skip** ordinary declared compare; S11 owns remaining |
| **22** ordinary app/cancel ATTEMPT counts only | **Mandatory skip** ordinary attempt compare; **no INDEX ordinary equality path**（INDEX not focused） |
| 23–26 EVIDENCE / REPLY / RETRY / MANAGEMENT | **Ordinary counts still apply** through phase 1/2（§11 keeps them until FINALIZE）。Early missing is S2 corrupt **now** |
| BIND carrier/primary/pair on live rows under plan | **Still runs** on remaining physical rows without comparing to STATE/RESULT ordinary declared（count side skipped only for 21/22 as above） |

S2 **must not** note legal cleanup under-count vs ordinary declared attempt/index fields。

#### 18.13.9 Mandatory INTERNAL BIND passes（same txn; mode-scoped）

**P0 close（adjudication #3）:** §9 は count match without live owner/PVD/raw binding を corrupt とする。S1 Mode17 in **another** session/snapshot is **not** same-txn evidence。S1/S2 contexts are mutually exclusive — co-binding Mode17 mid-S2 is **forbidden**。

**P0 correction（global mode-scoped BIND）:** true-primary PRESENT alone is **not** sufficient。Every BIND secondary row must also prove same-txn **declared-count carrier** presence + body subject match for the mode’s carrier set。A secondary whose carrier is **ABSENT** or whose body subject does not match that carrier is a **real S2 orphan finding**（not Port silence）。Port failure on any BIND get remains **no-note** sticky FAILED。

**BIND entry（Normative）:** BIND set(`focus_mode`) begins only when:

```text
pass_kind == PASS_INTERNAL
flags.focus_live == 0
SELECT_CARRIER has returned no next carrier for focus_mode
count requirements for the mode’s carrier loop are satisfied
  (including empty-carrier: zero carriers ⇒ still run BIND walks)
```

Illegal: BIND while `focus_live!=0`; illegal: concurrent FOCUS+BIND; illegal: BIND family outside set(`focus_mode`)。

After all FOCUS closes for all carriers of **`focus_mode`**, this session runs **exactly BIND set(`focus_mode`)** on the **same** txn — not the other modes’ BIND passes:

| Pass | Subtype | Declared-count carrier companion | True primary | Pair / extra | Modes |
| --- | --- | --- | --- | --- | --- |
| `BIND_ATTEMPT` | ATTEMPT `0x31` | Mode21: live `TRANSACTION_STATE`; Mode22: live `RESULT_CACHE` | TX→ANCHOR / DLV→DELIVERY | Mode21: INDEX **PRESENT** peer; Mode22: INDEX **ABSENT** peer | **21, 22** |
| `BIND_INDEX` | ATTEMPT_ID_INDEX `0x34` | **no separate STATE get**（STATE is covered when the paired ATTEMPT is walked in `BIND_ATTEMPT`） | ANCHOR | ATTEMPT **PRESENT** pair（`attempt_record_key_digest` complete-key bijection） | **21 only** |
| `BIND_EVIDENCE` | EVIDENCE_CELL `0x32` | matching owner carrier: TX retained → `TRANSACTION_STATE`; DLV APPLICATION_FIRST → `RESULT_CACHE` | TX/DLV primary（ANCHOR / DELIVERY） | slot legality vs owner shape / profile `L` | **23** |
| `BIND_REPLY` | REVERSE_REPLY `0x42` | live `RESULT_CACHE` | DELIVERY | closed `reply_kind` domain | **24** |
| `BIND_RETRY` | RETRY_SUMMARY `0x51` | **RECENT** rows: same-tx CUMULATIVE（kind=1, slot=0）carrier; **CUM** row itself is the selected carrier（self; no extra companion get）— **RECENT-without-CUM is corrupt** | ANCHOR | kind/slot matrix legality | **25** |
| `BIND_MANAGEMENT` | MANAGEMENT_LEDGER `0x52` | live `EVENT_SPOOL` | ANCHOR | — | **26** |

**Get budget per secondary row（Normative freeze）:**

```text
≤1 true-primary get
+ ≤1 declared-count carrier companion get
+ ≤1 pair peer get
= max 3 exact_get for Mode21/22 ATTEMPT rows
  (Mode21 INDEX: ≤1 primary + ≤1 ATTEMPT pair = 2; no STATE companion)
  (Modes 23–26: typically ≤1 carrier + ≤1 primary = 2; CUM self-carrier = ≤1 primary)
Not every row consumes all three slots.
exact_get never consumes row_budget (B4).
```

**BIND per-row algorithm（Normative; streaming; copy-before-get）:**

For each OK secondary row in the current BIND subtype walk（empty band ⇒ 0 iterations, no notes）:

```text
1. Copy-before-get into BIND scratch (no second 4096):
     focus_raw80 / focus_raw_len     := secondary body owner raw (TX16 | DLV80)
     focus_tx_id                     := tx component when rebuild needs it
     focus_primary_key_digest        := secondary header primary_value_digest
                                         (EXPECTED live true-primary PVD; not KEY_DIGEST)
     source_aux / source_aux_len     := attempt_id | slot BE | reply_kind BE | op_id …
     focus_owner_kind / family_gate  := secondary body for rebuild/gate

2. Carrier companion (when required by the BIND table for this row/mode):
     rebuild complete declared-count carrier key into peer_key
     exact_get(peer_key)             # ≤1 carrier companion
       Port fail                     → sticky FAILED; note 0; stop row
       ABSENT                        → real S2 orphan finding → note_terminal_corrupt
       PRESENT but body subject/raw
         mismatch vs secondary       → real S2 orphan finding → note_terminal_corrupt
       (Mode25 CUM self-carrier: skip this get; the secondary IS the carrier)
       (Mode21 BIND_INDEX: skip STATE companion; covered via paired ATTEMPT walk)

3. True primary:
     rebuild complete true-primary key into peer_key (may overwrite carrier key)
     exact_get(peer_key)             # ≤1 primary
       Port fail                     → sticky FAILED; note 0; stop row
       ABSENT | live VALUE_DIGEST != focus_primary_key_digest |
       raw bijection fail            → real S2 finding → note_terminal_corrupt

4. Pair peer (Mode21 ATTEMPT INDEX PRESENT; Mode21 INDEX ATTEMPT PRESENT;
              Mode22 ATTEMPT INDEX ABSENT only):
     rebuild peer key into peer_key (overwrite after primary proof finished)
     exact_get(peer_key)             # ≤1 pair peer
       Port fail                     → sticky FAILED; note 0; stop row
       Mode21 expected PRESENT:
         ABSENT | pair digest/raw fail → real S2 finding → note_terminal_corrupt
       Mode22 expected ABSENT:
         PRESENT                     → real S2 finding → note_terminal_corrupt
         ABSENT                      → OK for this probe
```

**Scratch reuse / order（no sizeof change; no retained pair state）:**

```text
While flags.bind_phase_active:
  focus_raw80 / focus_raw_len / focus_tx_id / focus_primary_key_digest /
  source_aux / source_aux_len / focus_owner_kind / family_gate
    := secondary fields (step 1; durable for the row)
  peer_key / peer_key_len
    := carrier key → then true-primary key → then pair peer key
       (strict order; each get may overwrite peer_key after prior proof done)
```

FOCUS-phase meaning of `focus_primary_key_digest` remains carrier primary **KEY_DIGEST** for stream match; BIND phase **repurposes the same 32 bytes** as expected true-primary PVD。Carrier focus identity is not required after `focus_live` clears; `last_carrier_key` frontier is retained separately。**No retained multi-carrier set:** BIND proves carrier per secondary row via `exact_get`, not via RAM focus history。

**Empty-carrier + secondary（Normative）:** zero eligible carriers for `focus_mode` still enters BIND set(`focus_mode`)。If the secondary band is non-empty while no carrier was selected, every secondary fails step 2 carrier ABSENT/subject → **real S2 orphan findings**（must not COMPLETE green）。Empty secondary band under empty-carrier: BIND still runs（0 rows ⇒ no binding notes）then COMPLETE when masks are satisfied。

S2 **may** reuse S1 **pure** reverse-key rebuild / VALUE_DIGEST helpers。S2 **must not** bind/run `begin_profiled_d3s1` / Mode17 evaluator in the S2 session, nor treat prior S1 session notes as same-txn proof。

**Ordering invariant:** all FOCUS missing|extra for `focus_mode` **and** all BIND carrier|primary|pair findings for BIND set(`focus_mode`) complete **before** `COMPLETE`。Count match without BIND success is **corrupt**。True-primary-only success without carrier companion success is **corrupt**。

**Count-green incomplete BIND finalize gate（Normative; §18.13.15 case 10）:** when `count_complete_mask` already has every bit required by `focus_mode`（FOCUS count green）but `binding_complete_mask` does **not** yet have every required BIND bit, the machine is **not** `COMPLETE` and must **not** set `COMPLETE_READY`。`phase` remains in BIND set(`focus_mode`)（or earlier）with sticky absent。If `session.state` is `EXHAUSTED` in that incomplete shape（including a test-only copy forced to `EXHAUSTED` while the live session is still `OPEN` mid-BIND）, `ninlil_domain_scan_finalize` **must** return `NINLIL_E_INVALID_STATE` with **Port 0**, no cleanup tree, and no `out_result` / session / context mutation — the ordinary incomplete-machine gate（not the evaluator-off exemption, not a sticky CORRUPT note path）。Ordinary drive must still finish BIND set(`focus_mode`) before `COMPLETE` / adopt。This is mode-scoped（that mode’s BIND set only; not “all six modes”）。

#### 18.13.10 H2 EXHAUSTED hook / Port / future / cleanup precedence

| Hook | When | Duty |
| --- | --- | --- |
| **H1 `d3s2_on_row`** | after S3 success, before `previous_key` update（and before any frozen-counter mutation attempt） | update focus **stream** counters / SELECT predicates; does not alone close focus; **must not** touch frozen D2 counters under PASS_INTERNAL |
| **H2 `d3s2_on_exhausted`** | inside `advance`, after NOT_FOUND validated, **after** `state=EXHAUSTED`, **before** return OK | **FOCUS stream only**（B6）: close focus count（compare or cleanup_skip）**only on true EXHAUSTED**, not on budget stop（B5）。**Not** the close path for FOCUS known-slot（Modes 23–25 use **B6k** after exact_get matrix）。`exact_get` still legal on EXHAUSTED |
| **H3 Port failure** | sticky FAILED from iter_next/get（including BIND carrier/primary/pair gets） | **no** undercount note; **no** orphan note; incomplete focus/bind is not corrupt-by-undercount |
| **H4 note during H2/B6k/BIND** | real finding | legal OPEN/EXHAUSTED → `note_terminal_corrupt` → FAILED; first sticky wins |
| **H5 finalize/abort** | cleanup tree | **must not** be the first place count is compared if compare needs live txn; **stream focus close = H2 mandatory**; **known-slot focus close = B6k mandatory**（not H2/EXHAUSTED）; BIND still while txn live |
| **H6 abort with open focus** | unadopted | no synthetic count corrupt |

**Precedence ladder（S2-applied; same spirit as S1）:**

1. Port / shape / lex / S3 terminal → D2 sticky, **note 0**, phase FAILED。
2. Real S2 finding（missing/extra/**carrier orphan**/binding/pair/illegal slot/counter equation）→ `note_terminal_corrupt` → sticky `STORAGE_CORRUPT`。
3. `profile_exact_active` false / future_profile → S2 evaluator **off** entire machine。
4. Sticky CORRUPT **outranks** future candidate at finalize（baseline future/profile flags remain frozen under INTERNAL）。
5. First sticky wins; finalize does not invent a second D3 pass。

**Evaluator-off terminal shape（Normative）:** baseline が true `EXHAUSTED` に到達し、`profile_exact_active == 0` かつ `profile_mismatch` / `future_profile_candidate` の**どちらか一方だけ**が1の candidate だけが残る場合、S2 は `PASS_INTERNAL` へ遷移せず second iterator を reopen しない。context は `phase=BASELINE`、`pass_kind=BASELINE`、`flags=BASELINE_DONE` **のみ**、`count_complete_mask=0`、`binding_complete_mask=0` のまま保持する。`COMPLETE` / `COMPLETE_READY` は count + BIND proof の権威を表すため、この経路では禁止する。`finalize` は `EXHAUSTED`、sticky なし、上記 exact shape、かつ相互排他的な mismatch/future candidate のときだけ通常の `COMPLETE + COMPLETE_READY` gate を免除し、既存 aggregate precedence により cleanup 後 `NINLIL_E_UNSUPPORTED` / `adopted=0` を返す。`recognizable_future_seen` 単独、単なる `!profile_exact_active`、両candidate flag同時、mask/flag/phase の不一致は免除しない。terminal family1-4 / Port / shape / lex / reconciliation failure はこの candidate を override し、通常の sticky failure 経路を取る。terminal 後の再 `d3s2_drive` は Port 0 の `NINLIL_E_INVALID_STATE` とする。

**Cleanup / fence tree（unchanged D2 order）:** `iter_close` if live → `rollback` RO txn → optional fence → `DONE`。S2 context is caller-owned。

**Doc-first D2 amendment for S2:** D2-only sessions retain `iter_open` count == 1。S2 Normatively: **exactly one live iterator; sequential reopen on the same txn after baseline is legal; concurrent live iterators remain 0。**

#### 18.13.11 Honest cost and fixed memory

| Item | Freeze |
| --- | --- |
| Per-session cost | **O(Fₘ·N + Σ_{t ∈ BIND subtypes(mode)} N_t)** wall time |
| `Fₘ` | data-dependent carrier focus count for **this mode**（profile-bounded by max TX/DELIVERY/RETRY capacity; document as `Fₘ`, not fake O(N)） |
| D3-S2 complete cost | **sum over modes 21..26**（six baselines; no free lunch） |
| Quadratic-class | **allowed** when Fₘ ~ N（same honesty class as S9） |
| False claims | **forbidden:** O(k₂·N) one-pass overall; one session proves all six modes; owner contiguous-run; false O(N) for all D3 |
| Memory | **fixed** S2 context only; **no** heap / VLA / full-ID set / second 4096 value buffer / second concurrent iterator |
| Get budget | FOCUS setup ≤2; stream row 0; known-slot 1 presence get / expected slot or kind; BIND **≤1 primary + ≤1 carrier companion + ≤1 pair peer** per secondary row（**max 3** for ATTEMPT; Mode21 INDEX / Modes23–26 use fewer; not all rows use all three） |

#### 18.13.12 Fixed S2 context layout（sizeof 306 / align 1 / ceiling 320）

**Object name（contract only; code 未 claim）:** private fixed D3-S2 multipass context。scanner workspace および S1 context とは **separate**。natural packing **align 1**（全 field `uint8_t` / byte array）。

```text
/* cursor / focus */
last_carrier_key[45]                         /* off 0..44 */
last_carrier_key_len          : u8           /* off 45; 0 = none */
focus_raw80[80]                              /* off 46..125; TX: first 16 used; DLV: 80; BIND: secondary raw */
focus_raw_len                 : u8           /* off 126; 0 | 16 | 80 */
focus_tx_id[16]                              /* off 127..142; always filled when focus/bind needs tx */
focus_primary_key_digest[32]                 /* off 143..174; FOCUS: carrier KEY_DIGEST; BIND: expected PVD */
focus_owner_kind              : u8           /* off 175; 1 TX | 2 DLV | 0 none */
focus_family_gate             : u8           /* off 176; DesiredState/EventFact/… closed */

/* declared mode-local counters (generic A/B/C; u64 BE) — NOT fixed attempt/index/mgmt names */
declared_a[8]                                /* off 177..184 */
declared_b[8]                                /* off 185..192 */
declared_c[8]                                /* off 193..200 */

/* small auxiliaries (mode-local; sizes fixed) */
declared_reply_count[4]                      /* off 201..204; u32 BE 0..4; Mode24 mirror of A */
declared_L                    : u8           /* off 205; 1..8; 0 = no evidence set */
declared_retry_recent_n       : u8           /* off 206; 0..4; Mode25 must equal declared_b */
declared_flags                : u8           /* off 207; diagnostic only; need_* derived from focus_mode at begin */

/* observed mode-local counters (generic A/B/C; u64 BE) */
observed_a[8]                                /* off 208..215 */
observed_b[8]                                /* off 216..223 */
observed_c[8]                                /* off 224..231 */

/* observed small */
observed_reply_mask           : u8           /* off 232; bit per closed reply kind present */
evidence_slot_mask[2]                        /* off 233..234; bits 0..8 for slots 0..L */
retry_slot_mask               : u8           /* off 235; bit0 CUMULATIVE; bits1..4 RECENT 0..3 */

/* rebuild scratch (no second 4096) */
peer_key[45]                                 /* off 236..280 */
peer_key_len                  : u8           /* off 281 */
source_aux[16]                               /* off 282..297; slot BE4 / kind BE4 / attempt_id etc. */
source_aux_len                : u8           /* off 298 */

/* phase machine / controls (7 u8) */
phase                         : u8           /* off 299 */
pass_kind                     : u8           /* off 300; 0 PASS_BASELINE | 1 PASS_INTERNAL */
flags                         : u8           /* off 301; bit0 baseline_done; bit1 focus_live;
                                                bit2 bind_phase_active; bit3 complete_ready…
                                                (binding_complete_mask is authority for bind done) */
count_complete_mask           : u8           /* off 302; FOCUS bits done for current carrier */
binding_complete_mask         : u8           /* off 303; BIND bits done for this session */
focus_mode                    : u8           /* off 304; copy of begin mode 21..26; immutable after begin */
cleanup_skip                  : u8           /* off 305; 0|1; Mode21/22 plan PRESENT only */
```

| Property | Exact contract |
| --- | ---: |
| **sizeof** | **306** = 46+81+16+32+2+24+4+3+24+4+46+17+7 |
| **alignment** | **1**（byte layout; padding 0） |
| **object ceiling** | **320**（fixed headroom 14; silent grow 禁止） |
| peer_key capacity | 45（complete Domain key max） |
| focus raw capacity | **80**（delivery contents exact） |
| BIND phases | reuse former ORPHAN control slots as `BIND_*`（same u8 `phase`）; scratch reuses `focus_raw80` / `focus_primary_key_digest` / `source_aux` |
| pair state | **none retained**（streaming proof only） |

**Exact offset map（natural pack; padding 0）:**

| Offsets | Size | Field |
| ---: | ---: | --- |
| 0..44 | 45 | `last_carrier_key` |
| 45 | 1 | `last_carrier_key_len` |
| 46..125 | 80 | `focus_raw80` |
| 126 | 1 | `focus_raw_len` |
| 127..142 | 16 | `focus_tx_id` |
| 143..174 | 32 | `focus_primary_key_digest` |
| 175 | 1 | `focus_owner_kind` |
| 176 | 1 | `focus_family_gate` |
| 177..184 | 8 | `declared_a` |
| 185..192 | 8 | `declared_b` |
| 193..200 | 8 | `declared_c` |
| 201..204 | 4 | `declared_reply_count` |
| 205 | 1 | `declared_L` |
| 206 | 1 | `declared_retry_recent_n` |
| 207 | 1 | `declared_flags` |
| 208..215 | 8 | `observed_a` |
| 216..223 | 8 | `observed_b` |
| 224..231 | 8 | `observed_c` |
| 232 | 1 | `observed_reply_mask` |
| 233..234 | 2 | `evidence_slot_mask` |
| 235 | 1 | `retry_slot_mask` |
| 236..280 | 45 | `peer_key` |
| 281 | 1 | `peer_key_len` |
| 282..297 | 16 | `source_aux` |
| 298 | 1 | `source_aux_len` |
| 299 | 1 | `phase` |
| 300 | 1 | `pass_kind` |
| 301 | 1 | `flags` |
| 302 | 1 | `count_complete_mask` |
| 303 | 1 | `binding_complete_mask` |
| 304 | 1 | `focus_mode` |
| 305 | 1 | `cleanup_skip` |
| **Σ** | **306** | |
| ceiling | **320** | headroom **14** |

##### 18.13.12.1 Mode-local counter map（generic A/B/C）

Three declared u64 lanes and three observed u64 lanes are **mode-local generic counters** — **not** fixed attempt/index/management names. Unused lanes for a mode must be written **0** at carrier install and must remain 0 at close（cross-mode residue defense）。

| Mode | declared A | declared B | declared C | observed A | observed B | observed C |
| ---: | --- | --- | --- | --- | --- | --- |
| **21** | application ATTEMPT count（`STATE.cumulative_attempts` / §9 app rules） | CANCEL ATTEMPT count **0\|1**（§9; prefer in-band `attempt_kind`） | INDEX total **= A+B**（TX-local INDEX = local ATTEMPT total） | stream-matched application ATTEMPT count | stream-matched CANCEL ATTEMPT count | stream-matched INDEX total |
| **22** | application ATTEMPT count（APPLICATION_FIRST: `application_attempt_count`; CANCEL_FIRST: 0） | cancel ATTEMPT count（APPLICATION_FIRST: 0\|1 if cancel attempt present; CANCEL_FIRST: 1） | **MBZ 0** | stream-matched application ATTEMPT count | stream-matched cancel ATTEMPT count | **MBZ 0** |
| **23** | SUMMARY@0 `valid_material_count`（0 if SUMMARY ABSENT / CANCEL_FIRST empty set） | SUMMARY@0 `raw_overflow_count` | SUMMARY@0 `late_evidence_count` | **`M`** = count RAW slots ∈\[1,L\] with MATERIALIZED | **MBZ 0** | count RAW ∈\[1,L\] with `late_material==1` |
| **24** | `reply_count` as u64（mirror `declared_reply_count`） | **MBZ 0** | **MBZ 0** | `popcount(observed_reply_mask)` as u64 | **MBZ 0** | **MBZ 0** |
| **25** | CUM body `total_completed_cycle_count` when CUM PRESENT; else 0 | `min(A, 4)` expected RECENT n | CUM expected **1** if retained TX requires CUM; else 0 | RECENT PRESENT count（slots 0..3） | **MBZ 0** | CUM PRESENT **0\|1** |
| **26** | `successful_resume_count + discard_committed`（0..9） | **MBZ 0** | **MBZ 0** | stream-matched same-tx MANAGEMENT count | **MBZ 0** | **MBZ 0** |

**Mode 22 INDEX absence（not C）:** INDEX expect 0 is proven only inside `BIND_ATTEMPT` ABSENT-peer probes — **not** via declared/observed C。C remains MBZ 0。

**Mode 23 close predicates（Normative; plan does not skip 23）:**

```text
1. Slot matrix: expected L+1 keys for slots 0..L (APPLICATION_FIRST / TX retained)
   or exact 0 cells (CANCEL_FIRST) — presence vs evidence_slot_mask / known-slot gets.
2. Identity: SUMMARY if any material path requires slot0 PRESENT with SUMMARY shape.
3. Counter equation (when SUMMARY PRESENT):
     declared_a == observed_a + declared_b
     i.e. valid_material_count == M + raw_overflow_count
4. Late coherence (no false equality):
     observed_c <= declared_c <= declared_a
     declared_b <= declared_a
     overflow materials may be late without a corresponding RAW late_material=1 cell,
     so declared_c == observed_c is NOT required.
5. Carrier late projection per existing §9 where applicable:
     SUMMARY late_material aggregate == (late_evidence_count > 0) already D1;
     STATE.has_late_evidence / RESULT evidence projection rules stay §9 —
     S2 notes only snapshot incoherence against those existing projections;
     S2 does not invent a new late-equality law beyond (3)(4).
6. Under/over on slot presence or equation fail → real S2 finding → note_terminal_corrupt.
```

**Mode 25 install:** `declared_retry_recent_n` must equal `declared_b` at install。

**Mode 25 close predicates（Normative; plan does not skip 25）:**

```text
1. Slot/kind matrix via FOCUS known-slot exact_gets (B6k): CUM + RECENT 0..3
   presence per D1 kind/slot rules for this carrier.
2. RECENT count: observed_a == declared_b
   (observed_a = RECENT PRESENT count; declared_b = min(A, 4) expected RECENT n).
3. CUM presence: observed_c == declared_c
   (observed_c = CUM PRESENT 0|1; declared_c = expected CUM 0|1).
4. observed_b remains 0 (MBZ lane).
5. declared_retry_recent_n must still equal declared_b at close.
6. Fail any of (1)–(5) → real S2 finding → note_terminal_corrupt.
```

**Mode 24 install:** `declared_reply_count` must equal `declared_a`（0..4）；close compares `observed_a` to `declared_a` and mask popcount consistency。

**Mask bit assignments（closed; same positions for count and binding）:**

```text
count_complete_mask / binding_complete_mask family bits:
  bit0 ATTEMPT
  bit1 INDEX
  bit2 EVIDENCE
  bit3 REPLY
  bit4 RETRY
  bit5 MANAGEMENT
  bit6–7 MBZ = 0

Required count bits by focus_mode (per carrier close; empty-carrier skips count bits
  but still requires BIND mask complete):
  21 → bit0|bit1
  22 → bit0
  23 → bit2
  24 → bit3
  25 → bit4
  26 → bit5

Required binding_complete_mask by focus_mode:
  21 → bit0|bit1
  22 → bit0
  23 → bit2
  24 → bit3
  25 → bit4
  26 → bit5
```

#### 18.13.13 Memory ceilings（doc-first aggregate 9152 path）

| Object | Ceiling freeze |
| --- | ---: |
| scanner workspace | **8192**（**unchanged**） |
| Stage5-seam-alone | **8704**（**unchanged**） |
| D3-S1 context | sizeof 421 / ceiling **448**（**unchanged**） |
| S1 aggregate arena（historical S1a） | **8832**（**unchanged** as S1-only path） |
| D3-S2 context | sizeof **306** / ceiling **320** |
| **Outer future aggregate（S1+S2 co-resident）** | **9152**（= 8384 + 448 + 320） |

Packed sum if Stage5 future holds both contexts: `8384 + 421 + 306 = 9111`；outer align8 **9112** ≤ **9152**。scanner / Stage5-alone / S1 sizes は silent 変更禁止。

**S1/S2 mutually exclusive per scanner session:** session binds **only** `bound_d3s2_context` during S2; not `bound_d3s1` concurrently（**dual-bound forbidden**）。Stage5 S12 co-residence may use dual pointers only with the **9152** aggregate path doc-first, still **one evaluator active per session**。Stage5 seam **still** does not allocate/bind/run D3 contexts until S12（§18.9）。

#### 18.13.14 Private API / seams（contract names only）

| API（contract name only） | Normative rule |
| --- | --- |
| **`ninlil_domain_scan_begin_profiled`** | D2-only のまま。S2 mode/context を受け付けない |
| **`ninlil_domain_scan_begin_profiled_d3s1`** | modes **1..20 only**。S2 へ silent 拡張禁止 |
| **`ninlil_domain_scan_begin_profiled_d3s2`** | S2 production private begin。prevalidation（mutation / Port 前）: mode ∈ **21..26**、S2 context non-NULL、pairwise disjoint session/workspace/ops/handle/candidate/context、context within object ceiling。成功時 `focus_mode := mode`（immutable）。違反は Port 0・`INVALID_ARGUMENT`・状態不変 |
| **`ninlil_domain_scan_reopen_zero_prefix_iter`** | same-txn sequential reopen; pass-local lex reset only; legal OPEN/EXHAUSTED + txn live + no sticky |
| **`ninlil_domain_scan_d3s2_drive` / advance integration** | apply `PASS_INTERNAL` fence inside process_ok_row when S2 bound + INTERNAL phase; obey B0–B11 |
| **`ninlil_domain_scan_d3s2_on_row` / H2 exhausted hook** | SELECT / FOCUS stream / BIND predicates + note; H2 only on true EXHAUSTED |
| **nullable / optional skip** | **禁止**。null context で S2 skip、mode 0 disabled は fail-closed |
| **Stage5 until S12** | seam は旧 `begin_profiled` のみ。`begin_profiled_d3s2` を呼ばない |
| **TEST transport begin** | 引き続き tests-OFF / Stage5 から absent |

本 freeze はこれらの symbol が **現 branch に存在する** とは述べない。D3-S2 implementation が doc-first 契約に従って追加する。

#### 18.13.15 Sibling oracle architecture（append-only d3s2; JSON は作らない）

S2a は `spec/vectors/domain-scan-crossrow-v1.json` を **作成・改変しない**（§18.7 継続）。後続 D3-S2 oracle が満たすべき architecture:

| Rule | Exact contract |
| --- | --- |
| Evolution | **append-only** on single sibling path; retain exact **94-vector d3s1 prefix** identity / expected values |
| Format | `ninlil-domain-scan-crossrow-v1-d3s2`（suffix advance; no destructive fork） |
| Frozen upstream pins | D1 + S1–S5 path/format/full sha256/`vector_count` **read-only**（§18.7 表）; d3s1 full sha256 / content_sha256 / 94 kinds **retain** |
| Mutation | `mutation_calls=0` |
| Same-txn Port trace | multi sequential `iter_open` on **one** txn; harness that uses two txns for list-then-count must **fail** |
| Mode product | each vector session binds **one** mode 21..26; complete product coverage requires **all six** modes across vectors/sessions |
| Independent generator | production C 非 invoke（§18.7） |
| Production bridge | real private S2 phase machine + production scanner seams |

**Exhaustive case classes / anti-false-pass（minimum; mode-scoped）:**

1. Modes 21–26 positive ordinary counts（plan ABSENT）— **one mode per session**
2. SHA non-contiguous multi-owner interleave（same subtype band, different owners）
3. Known-slot evidence/reply/retry presence matrix + illegal slot/kind
4. Stream attempt/index/management under/over count（Mode21 includes app/cancel/INDEX A/B/C; Mode22 app/cancel only）
5. CLEANUP_PLAN PRESENT → Mode21/22 ordinary skip（no false note）; 23–26 still ordinary
6. Carrier cursor no-skip / no-dup; last_carrier_key frontier; **mode-dependent carrier set**
7. Same-txn multipass Port trace（baseline + internal reopens）; two-txn harness fail
8. BIND missing **true primary** / PVD mismatch / raw mismatch / Mode21 ATTEMPT↔INDEX pair fail / Mode22 unexpected INDEX
9. BIND missing **declared-count carrier** / wrong carrier body subject（orphan secondary without STATE/RESULT/CUM/SPOOL as required）— **must fail**; true-primary-only success is a false pass
10. Count green without **that mode’s BIND set** → must not pass（not “all six BINDs”）
11. Port terminal mid-FOCUS/BIND（including carrier/primary/pair gets）→ note 0, no fabricated undercount / no orphan note
12. Profile mismatch / future candidate → S2 evaluator 0; baseline-only evaluator-off terminal shape（no INTERNAL reopen / no COMPLETE authority）; baseline future/profile flagsを保持
13. Budget mid-focus resume（same session B5, not restart B11）
14. Empty secondary vs declared>0（plan ABSENT）→ corrupt; empty-carrier still runs BIND; **empty-carrier + non-empty secondary band fails through BIND carrier-ABSENT orphan**（must not COMPLETE green）
15. Mode22 INDEX expect 0 via BIND_ATTEMPT ABSENT only / unexpected index; Mode21 BIND_INDEX has no separate STATE companion get
16. Mode25 RECENT-without-CUM → BIND_RETRY carrier fail; CUM self-carrier uses primary-only get budget
17. DSD1 composition fixtures（**multi-session** S1+S2 chain; not Mode 28; not dual-bound）
18. exact 94 d3s1 prefix retained after append
19. Mode23 `valid = M + overflow` equation + late coherence without false late equality
20. Six-session product: harness must not assume one baseline covers six modes
21. Get-budget freeze: BIND ≤1 primary + ≤1 carrier companion + ≤1 pair peer（max 3 ATTEMPT; oracle must not assume unbounded gets）

#### 18.13.16 DSD1 composition（not a new mode; multi-session）

`DSD1_LOGICAL_DELIVERY` snapshot product is **composition only** — **no Mode 28 / no S2-owned DSD1 mode**。

| Piece | Owner |
| --- | --- |
| RESULT exact-1, CANCEL gate, CALLBACK gate | S1 Modes 11/14/19 |
| DELIVERY↔RESULT PVD | Mode 17 |
| App/cancel attempt cardinalities | Mode **22** + BIND_ATTEMPT |
| EVIDENCE 0 vs L+1 | Mode **23** + BIND_EVIDENCE |
| reply_count | Mode **24** + BIND_REPLY |
| Writer E2E / public ABSENT projection | **D4** / later |

Oracle: **multi-session orchestration** harness vectors that chain S1 sessions + S2 sessions on the same fixture（cleanup `DONE` between sessions as needed）。**Never dual-bound** S1+S2 contexts in one scanner session。S2 alone does not claim DSD1 complete。

**P2-A composition sibling（implementation artifact; not Mode 28）:** `spec/vectors/domain-scan-dsd1-composition-v1.json` / format `ninlil-domain-scan-dsd1-composition-v1-d3s2` + independent generator `tools/domain_scan_dsd1_composition_vector_gen.py` + production bridge. Chains **S1 modes 11/14/17/19** + **S2 modes 22/23/24** as **seven** self-contained sessions on one D1-valid fixture（1 session = 1 mode = 1 `READ_ONLY` txn; independent baseline each; `mutation_calls=0`）。Does **not** rewrite the crossrow authority JSON。Does **not** claim D3-S2 overall complete / Stage 5 / D4 / public Runtime / ESP-IDF / hardware。

#### 18.13.17 Explicit exclusions and non-claims

| Exclusion | Owner |
| --- | --- |
| Exact-1 presence/PVD/raw as S2 success | **S1**（do not re-claim） |
| Owner contiguous-run algorithm / false O(k₂·N) / one-session-all-six-modes | **forbidden** |
| Fresh-session list-then-count multipass | **forbidden** for S2 cardinality |
| Non-zero prefix iterators for S2 production | **forbidden** |
| Full-ID set / heap / VLA / second 4096 / concurrent iterators | **forbidden** |
| Dual-bound S1+S2 contexts in one session | **forbidden** |
| `KEY_DIGEST` reverse | **forbidden**（§18.5） |
| BLOB lifecycle / stream digest | **S3** |
| Witness old/new / supersede / retire | **S4–S6** |
| Family-3 counters / 11-capacity / health | **S7 / S8 / S10** |
| SERVICE_QUOTA multipass | **S9** |
| CLEANUP phase remaining / fence aggregate / pair-erase partials | **S11** |
| INDEX creation digest == CREATE witness new digest | **S4/S5 or D4**（not body-only S2） |
| Grant / deadline / clock truth | **not S2** |
| Writer E2E / mutation / transfer history | **D4** |
| Stage5 D3 bind / public Runtime / ESP-IDF / hardware | **not this freeze** |
| New public ABI / new ADR | **not this freeze** |

#### 18.13.18 Completion boundary / non-claims（S2a）

| Claim | After D3-S2a docs freeze |
| --- | --- |
| D3-S0 architecture freeze | **yes**（historical; §18 冒頭–§18.11 meaning unchanged） |
| D3-S1a Normative freeze | **yes**（historical docs only; §18.12 unchanged as freeze text） |
| D3-S1 implementation complete | **yes**（prior; not rewritten） |
| D3-S2a Normative freeze（declared multi-count / same-txn machine / 1 session=1 mode） | **yes**（本節） |
| D3-S2 implementation complete | **no**（requires six mode sessions + code/oracle） |
| Crossrow d3s2 JSON / generator / bridge | **no**（architecture only; 94-vector d3s1 prefix retained as pin） |
| D3 complete / S12 | **no** |
| Stage 5 complete / `storage_recovery_complete=1` | **no** |
| Stage5 allocates/binds/runs D3 context | **no until S12** |
| public Runtime / D4 / ESP-IDF / hardware | **no** |
| Implemented private APIs/types/constants exist | **no claim** |

S2a historical row を後から「implementation complete」へ書き換えてはならない。D3-S2 実装 PR は別 change set で S2 行だけを進める。D3-S0 / D3-S1a historical freeze text は **preserve** する。

#### 18.13.19 Current status after D3-S2 implementation (separate row; does not rewrite the S2a table above)

| Claim | After D3-S2 implementation |
| --- | --- |
| D3-S0 architecture freeze | **yes**（historical docs only; preserved） |
| D3-S1a Normative freeze | **yes**（historical docs only; preserved — **not** re-labeled as implementation） |
| D3-S2a Normative freeze | **yes**（historical docs only; §18.13.18 NO table preserved — **not** rewritten） |
| D3-S1 implementation complete | **yes**（prior exact-1; §18.2 / §18.12.9） |
| D3-S2 implementation complete | **yes**（modes 21..26 = **6** self-contained sessions; 1 session = 1 mode = 1 same `READ_ONLY` txn; context **306/320**; §18.13.15 cases 1..21 closed） |
| Crossrow authority | format `ninlil-domain-scan-crossrow-v1-d3s2` / `vector_count` **144** = prefix **94** + suffix **50** / full JSON sha256 `e270743e99189a830b1b39d6c4b464fc3d2eb63ff8fe2b20dcfa7ae0f91d01ec` / canonical `content_sha256` `a9fccb12d932f0082111c94da3a23cd6680dc4bedecb2108e739bdca55d80fed` / independent generator + production bridge / mutation **0** |
| DSD1 composition | **7** sessions（S1 modes 11/14/17/19 + S2 modes 22/23/24）; format `ninlil-domain-scan-dsd1-composition-v1-d3s2`; not Mode 28; not dual-bound |
| D3-S3a / D3-S4a / D3-S5a Normative freeze | **yes**（historical docs only; §18.14 / §18.15 / §18.16 preserved） |
| D3-S3 / D3-S4 / D3-S5 implementation / D3-S6..S12 | **pending** |
| D3 complete / S12 outcome transition | **no** |
| Stage 5 D3 bind / Stage 5 complete / `storage_recovery_complete=1` | **no** |
| D4 / public Runtime / ESP-IDF / hardware / USB / LoRa HIL | **no** |
| SDK / field / V1 readiness | **no** |
| Production `note_count` call counter | **no claim**（P1-E / formal `note_count=0` is **reference model only**; H3 observable proof = sticky `STORAGE` + `FAILED` + incomplete masks + no observable fabricated undercount/orphan `CORRUPT` outcome/path; production note invocation count は測定しない） |

Fixed candidate / merge: implementation SHA `39e4752ba09637d40d1b2c4c64fbc17ccc872451` / merge `ca02e24ea7af29c0031366544158a0a21be899bb` / PR #105。Non-normative acceptance record: [2026-07-20 D3-S2 implementation accepted](reviews/2026-07-20-d3s2-implementation-accepted.md)。

### 18.14 Normative D3-S3a freeze（BLOB lifecycle / chunk stream / owner 0·1）

**Decision identifier: D3-S3a。** 本節は D3-S0（§18 冒頭–§18.11）、D3-S1a（§18.12）、D3-S2a（§18.13）を **上書きせず**、BLOB lifecycle / chunk stream を所有する **D3-S3** の **docs-only Normative freeze** を追加する。**docs only**: implementation / test / CMake / tools / vector JSON / ADR / code の追加・変更は本 slice で行わない。**D3-S3 implementation / D3 complete / Stage 5 / D4 / public Runtime / ESP-IDF / hardware は pending。** private API / type / constant の存在は claim しない。

**Design choice（Domain Store recovery validation; radio fragmentation ではない; 1 session = 1 mode）:** S3 は §8.4 / §9 の **snapshot** BLOB 参照 0·1、manifest→chunk exact index set、ordered stream `content_digest`、orphan/missing/extra を閉じる。BLOB **wire/radio fragmentation** は **範囲外**。**1 profiled S3 session = 1 mode `m` ∈ {27..30} = 1 bound `READ_ONLY` txn**。**`k₃=4`**（complete product = **4 sessions**）。S1/S2/S3 contexts は session ごとに **mutually exclusive**。

**P0 constructibility axiom（adjudication #0; KEY_DIGEST is one-way）:**

1. Owner / reverse-reply fields が保持するのは **`KEY_DIGEST(complete manifest key)` だけ**であり、complete manifest key bytes ではない（§5.1 / §8.3–§8.5）。
2. `KEY_DIGEST` から complete key / `blob_id` / raw identity を **reverse してはならない**（§18.5）。
3. DELIVERY / ANCHOR / INGRESS / REVERSE_REPLY body は `total_length` を持たないため、owner body だけでは `blob_id_digest` / complete manifest key を **再計算できない**（§8.5 DELIVERY 明示; 他 owner も同様）。
4. したがって **「owner digest から complete key を rebuild して ≤1 `exact_get`」は implementation-impossible** であり **禁止**。
5. 合法な locate は **same-txn BLOB subtype band walk** で、各 visited **complete key** について `KEY_DIGEST(complete_key) == focus_key_digest` を照合する（iterator が key bytes を供給; reverse ではない）。
6. Chunk の known-index `exact_get` は、live manifest body の `blob_id_digest` から `COMPOSITE(30, u8=2\|\|blob_id\|\|index)` を **forward rebuild** できる場合に限る（manifest が先に install 済み）。
7. §8.4 の historical 文「Owner が保持する BLOB key digest を manifest complete key へ」は、本 freeze では **SCAN で locate した complete key について `KEY_DIGEST(key)==referrer digest` を証明する**意味に **だけ** 解釈する。digest→key reverse や owner-body からの complete-key 推測は §8.4 の実装義務に含めない（本節が D3-S3 実行契約の正本）。

#### 18.14.1 Snapshot-only BLOB lifecycle scope

| In scope（S3） | Out of scope |
| --- | --- |
| Referrer field `*_blob_key_digest` / `body_blob_key_digest` → live manifest 0\|1 via **digest-match scan** | Rebuild complete key from KEY_DIGEST alone（**forbidden**） |
| Manifest → chunks exact `chunk_count` / index set `{0..count-1}` | Witness SUPERSEDED/RETIRED（**S4–S6**） |
| Ordered stream `content_digest` + `length_sum == total_length` | Global 11-capacity accounting（**S8**） |
| Owner primary PVD/raw; chunk→manifest PVD | SERVICE_QUOTA / health（**S9/S10**） |
| Orphan manifest/chunk; missing/extra live; shared REPLY referrers | Radio/Bearer/USB/LoRa fragmentation |
| Mode30 reply_kind companion matrix + semantic recompute | Mutation history（**D4**） |

**Boundary phrase:** S3 は **Domain Store recovery validation** である。`BLOB_CHUNK_DATA_MAX_BYTES=3072` は storage body chunk 上限であり radio MTU と同一視しない。

#### 18.14.2 Closed modes 27..30（k₃=4; 1 session = 1 mode）

| Mode | Name | Carrier（SELECT） | Referrer digest field | Declared live（§9; plan 非関与） | FOCUS set | BIND set |
| ---: | --- | --- | --- | --- | --- | --- |
| **27** | `TX_PAYLOAD_BLOB` | live `TRANSACTION_ANCHOR` | ANCHOR.`payload_blob_key_digest` | ACTIVE retained TX/SPOOL: manifest **1**（empty payload でも count-0 manifest; digest non-zero）。Released/terminal: manifest **0** + historical non-zero OK | `FOCUS_MANIFEST_SCAN` + `FOCUS_CHUNKS` | `BIND_MANIFEST` + `BIND_CHUNK` + untyped orphan rule |
| **28** | `INGRESS_BLOB` | live PENDING `ORDERED_INGRESS` | `payload_blob_key_digest` / `evidence_blob_key_digest` | empty view → **0**（digest zero; zero-length manifest 不作成）。non-empty → **1** | dual: PAYLOAD then EVIDENCE（各 SCAN+CHUNKS） | same BIND + untyped |
| **29** | `DLV_PAYLOAD_BLOB` | live `DELIVERY` | DELIVERY.`payload_blob_key_digest` | APPLICATION_FIRST: **1**（empty でも count-0）。CANCEL_FIRST: digest **zero** かつ **0**。Terminal release: **0** + historical OK | `FOCUS_MANIFEST_SCAN` + `FOCUS_CHUNKS` | same |
| **30** | `REPLY_BLOB` | live `REVERSE_REPLY` | RR.`body_blob_key_digest`（**not** DELIVERY.payload） | state **1..4**: REPLY manifest **1**。state **5**: **0** + historical non-zero OK | `FOCUS_MANIFEST_SCAN` + `FOCUS_CHUNKS` + companion matrix + semantic | `BIND_MANIFEST`（RR referrer proof）+ `BIND_CHUNK` + untyped |

**Session product:**

1. `begin_profiled_d3s3(..., mode=m, ctx)` binds **exact 1** mode; `focus_mode := m` immutable。
2. Only FOCUS/BIND set(m)。multi-mode orchestration API **禁止**。
3. Mode 28 dual-view mandatory（PAYLOAD + EVIDENCE inseparable）。
4. **D3-S3 implementation complete** = four self-contained sessions 27..30 all close。
5. Dropped inventions: Mode 31 orphan-as-mode、Mode 32 semantic-only、Mode 33 radio reassembly — **禁止**。

**Mode 30 referrer vs primary（adjudication #7; P0-3）:**

| Role | Record | Field / relation |
| --- | --- | --- |
| **Referrer**（digest holder） | `REVERSE_REPLY` | `body_blob_key_digest = KEY_DIGEST(complete REPLY manifest key)` |
| **Primary owner of REPLY manifest** | `DELIVERY` | manifest `blob_owner_kind=DELIVERY` + `owner_key_raw=delivery_key contents`; common PVD → DELIVERY value |
| **Not a REPLY referrer** | `DELIVERY` | `payload_blob_key_digest` は **COMMAND/EVENT payload only**（Mode 29）。REPLY を指さない |

**Shared REPLY manifest（Normative）:** 同一 `KEY_DIGEST` を複数 live RR（**同一 delivery** の別 `reply_kind`）が保持してよい。FOCUS は carrier ごとに digest-match + **#14 raw/tx binding**。**別 delivery** の共有 digest は raw 不一致で reject。BIND: ≥1 RR（digest+raw）。DELIVERY.payload で REPLY を証明しない。

#### 18.14.3 SHA256_COMPOSITE + KEY_DIGEST locate（adjudication #1）

| Fact | Contract |
| --- | --- |
| Manifest/chunk keys | SHA256_COMPOSITE → **not** owner/blob contiguous |
| Owner→manifest locate | **digest-match subtype scan only**（§18.14.7）; not exact_get-by-rebuild |
| Chunk index set after manifest install | known-index exact_get from `blob_id` **forward** rebuild |
| Chunk→manifest when proving orphan | complete manifest key = rebuild `COMPOSITE(30, u8=1 \|\| blob_id_digest)`（chunk body が `blob_id` を持つ）→ exact_get; then optional `manifest_key_digest` equality |

#### 18.14.4 Same-txn phase machine

**Illegal（P0）:** two-txn list-then-prove; concurrent iterators; full-ID set; baseline 二重加算; KEY_DIGEST reverse; heap/VLA/second 4096; one-session-all-four; Mode28 dual-view without view pin+re-SCAN; **finalize compare against workspace body after later exact_get overwrote it without a pinned expected digest or explicit re-get budget**; **owner PVD proof that requires a live owner value no longer in workspace and no pinned `expected_owner_pvd` / re-get**.

| Rule | Exact |
| --- | --- |
| Snapshot | single `READ_ONLY` txn |
| Baseline | D2 profiled begin **once** |
| Internal multipass | close→reopen zero-prefix only; live iterators ≤1 |
| Value buffer | single 4096; semantic prefix streamed into sha_*; **expected digests pin in context**（§18.14.7.4） |

```text
IDLE → BASELINE
  → (SELECT_CARRIER pure W（GET 0; pin first eligible）
       → [Mode27 / Mode29 APPLICATION_FIRST] SELECT_SETUP G（companion exact_get; typed CURRENT）
       → lifecycle classify from pins + setup results
       → [Mode28] pin view_a/view_b digests
       → FOCUS_MANIFEST_SCAN (install: expected_manifest_value_digest + expected_owner_pvd)
       → OWNER_PVD_PROOF (§18.14.7.2; Mode30 may defer to semantic DELIVERY get)
       → FOCUS_CHUNKS
       → Mode28: EVIDENCE SCAN+OWNER_PVD+CHUNKS
       → SEMANTIC (28 both units | 30 LIVE_REQUIRED):
            SEMANTIC_PREFIX_REGET:
              carrier re-get → pin expected_semantic_digest FIRST
              → stream prefix into sha_*
              → Mode30 companions in order (each may overwrite workspace)
            SEMANTIC_CHUNK_REWALK (28 re-SCAN views / 30 re-walk chunks)
            B6s: sha_final() == expected_semantic_digest  # from context pin
       → Mode27/29: no semantic
     )*
  → BIND_MANIFEST → BIND_CHUNK → COMPLETE | FAILED
```

| Phase | Duty |
| --- | --- |
| `FOCUS_MANIFEST_SCAN` | single match arm; pin expected digests from installed manifest |
| `OWNER_PVD_PROOF` | live owner VALUE_DIGEST == `expected_owner_pvd` |
| `FOCUS_CHUNKS` | content_digest stream; chunk header PVD == `expected_manifest_value_digest` |
| `SEMANTIC_PREFIX_REGET` | pin `expected_semantic_digest` then stream prefix; companions |
| `SEMANTIC_CHUNK_REWALK` | payload/evidence or reply bytes into sha_* |
| `BIND_*` | reverse + untyped orphan |

#### 18.14.5 PASS_INTERNAL + B0–B11 mapping

S2 §18.13.5 と同型。S1/S2 evaluators **off**。

```text
B0–B5, B9–B11: §18.13.5.1 spirit.
B4. exact_get never consumes row_budget (companions, chunks, OWNER_PVD_PROOF,
    SEMANTIC_PREFIX_REGET, BIND, Mode28 RESCAN is iter walk).
B6 / B6k / B6s / B5s: as prior; B6s compares to context pin expected_semantic_digest.
B7/B8: SELECT empty → BIND → COMPLETE.
```

#### 18.14.6 Carrier cursor / lifecycle / declared live

| Mode | Eligible carriers |
| ---: | --- |
| 27 | live `TRANSACTION_ANCHOR` |
| 28 | live PENDING `ORDERED_INGRESS` |
| 29 | live `DELIVERY` |
| 30 | live `REVERSE_REPLY` |

**Lifecycle class（u8）:** `NONE=0` / `LIVE_REQUIRED=1` / `HISTORICAL_ABSENT=2` / `ILLEGAL_CARRIER=3`。

**Adjudication #2 / #3 / #10:** unchanged（live vs historical; empty constructibility; Mode29 APPLICATION_FIRST always RESULT_CACHE setup）。

#### 18.14.7 FOCUS_MANIFEST_SCAN + stream + semantic + digest pins

##### 18.14.7.1 Digest-match scan — single authoritative match arm（P0-A）

```text
Pre: focus_key_digest := unit referrer (Mode28 uses view_a/view_b pins).
     match_count := 0
     zero-digest NONE path may skip walk.

For each OK row:
  skip non-manifest / future / optional mode prefilter
  if KEY_DIGEST(complete key) != focus_key_digest: continue
  # ----- single match arm only -----
  if match_count == 0:
    match_count := 1
    install ONCE:
      blob_id, total_length, chunk_count, content_digest (body),
      owner raw/kind, owner_primary_key_digest (body KEY_DIGEST material),
      expected_manifest_value_digest := VALUE_DIGEST(complete NLR1 manifest value)
      expected_owner_pvd := common_header.primary_value_digest
        # secondary BLOB: must equal VALUE_DIGEST(live owner primary value)
      peer_key := complete manifest key bytes
  else:
    match_count := 2; note duplicate sticky; do not re-install
  # ----- end arm -----
On EXHAUSTED: adjudication #2 on final match_count.
```

##### 18.14.7.2 OWNER_PVD_PROOF + content stream（adjudication #13）

**Two distinct digests（must not conflate）:**

| Context field | Source at SCAN install | Used for |
| --- | --- | --- |
| `expected_manifest_value_digest` | `VALUE_DIGEST(manifest complete value)` | each chunk common `primary_value_digest` must equal this |
| `expected_owner_pvd` | manifest common header `primary_value_digest` | live owner complete value `VALUE_DIGEST` must equal this |

**OWNER_PVD_PROOF（after match_count==1 install; before or immediately after CHUNKS start）:**

| Mode | Owner key | When | Budget |
| ---: | --- | --- | ---: |
| **27** | `last_carrier_key` = ANCHOR | after SCAN install（workspace holds manifest → must re-get ANCHOR） | **≤1** exact_get |
| **28** | `last_carrier_key` = ORDERED_INGRESS | after each view SCAN install（payload unit and evidence unit each） | **≤1** per view |
| **29** | `last_carrier_key` = DELIVERY | after SCAN install | **≤1** exact_get（DELIVERY is primary → its own common PVD is zero; proof is VALUE_DIGEST(DELIVERY value)==expected_owner_pvd） |
| **30** | DELIVERY rebuilt from manifest `owner_key_raw` | **deferred** to Mode30 semantic companion DELIVERY get（setup 0）— first DELIVERY PRESENT must prove VALUE_DIGEST==expected_owner_pvd before further companion gets | **0 extra**（folded into semantic DELIVERY get） |

Port fail → sticky FAILED note 0。ABSENT / digest mismatch → real S3 finding。

**FOCUS_CHUNKS:** known-index stream; each chunk common `primary_value_digest` == `expected_manifest_value_digest`; body fields match installed manifest; `sha_update` data; final == body `content_digest`。

##### 18.14.7.3 Semantic recompute + expected_semantic pin（adjudication #12; closes remaining P0）

**禁止:** finalize `sha_final() == workspace.body.semantic_*` after later exact_get overwrote that body without a **context pin** or **budgeted carrier re-get at finalize**。本 freeze は **pin 方式**を正とし、finalize 時の extra carrier re-get は **要求しない**（budget 0）。

**Pin rule（authoritative）:**

```text
At the FIRST successful carrier exact_get of SEMANTIC_PREFIX_REGET,
BEFORE any companion exact_get and BEFORE any chunk rewalk:
  Mode28: expected_semantic_digest := ORDERED_INGRESS.message_semantic_digest
  Mode30: expected_semantic_digest := REVERSE_REPLY.semantic_digest
  (32-byte context field; survives all later workspace overwrites)

Then stream prefix fields into sha_* from that same PRESENT value
(copy-before-next-get only for small scalars already covered by pin+stream).
Then Mode30 companions may exact_get (workspace overwrite OK).
Then SEMANTIC_CHUNK_REWALK.
B6s finalize: sha_final() == expected_semantic_digest  # context only
```

**Phase-repurpose note:** `expected_manifest_value_digest` / `expected_owner_pvd` are **not** repurposed for semantic expected; they retain install meaning through the carrier's content+PVD proof. Semantic uses dedicated `expected_semantic_digest`。

###### Mode28

```text
Carrier install: pin view_a_key_digest / view_b_key_digest; last_carrier_key.

After both content units green:
  SEMANTIC_PREFIX_REGET (budget 1):
    exact_get(last_carrier_key) → ORDERED_INGRESS
    pin expected_semantic_digest := message_semantic_digest   # FIRST
    stream §5.1 prefix into sha_* from this value
  SEMANTIC_CHUNK_REWALK_VIEW_A:
    zero view_a → Update payload_length=0 only
    else re-SCAN view_a + known-index chunk data into sha_*
  SEMANTIC_CHUNK_REWALK_VIEW_B: symmetric for evidence
  B6s: sha_final() == expected_semantic_digest
```

###### Mode30

**Adjudication #14（RR ↔ REPLY manifest ↔ DELIVERY binding; P0-1）:**
Mode30 carrier は **current** live `REVERSE_REPLY` 1 件。digest-match した REPLY manifest および companion DELIVERY は **同一 delivery** に属さねばならない。

```text
After SCAN match install (REPLY manifest):
  require manifest.blob_owner_kind == DELIVERY(3)
  require manifest.blob_kind == REPLY(5)
  require manifest.owner_key_raw contents exact 80
       == RR.delivery_key_raw contents exact 80
       (RR raw pinned at carrier install into focus_raw80)
  # shared digest across deliveries rejected: wrong-delivery RR fails raw equality

On semantic DELIVERY exact_get (first companion):
  rebuild DELIVERY key from that same 80-byte raw
  require PRESENT
  require DELIVERY.delivery_key_raw contents == focus_raw80 (same 80)
  require DELIVERY.transaction_id == RR.transaction_id
       == delivery_key component [32,48)
  VALUE_DIGEST(DELIVERY) == expected_owner_pvd  # OWNER_PVD_PROOF
```

共有 `body_blob_key_digest` を持つ **別 delivery** の RR が同一 manifest を SCAN で見つけても raw/transaction 不一致で **corrupt**（混線拒否）。同一 delivery の複数 `reply_kind` が同一 digest を共有することは合法。

**Adjudication #15（reply_kind → REPLY BLOB length; P0-2）:**
carrier install で pin した `reply_kind` と SCAN 後 manifest:

| `reply_kind` | `total_length` | `chunk_count` / chunks | `content_digest` |
| ---: | --- | --- | --- |
| **1 RECEIPT** | **0..128** | §8.4 ceil from total_length | stream SHA of chunk data |
| **2 DISPOSITION** | **exact 0** | **exact 0**; chunk rows for blob_id **forbidden** | **SHA-256(empty)** exact |
| **3 CUSTODY** | **exact 0** | **exact 0**; chunks forbidden | **SHA-256(empty)** exact |
| **4 CANCEL_RESULT** | **exact 0** | **exact 0**; chunks forbidden | **SHA-256(empty)** exact |

上表不一致 → S3 finding。non-RECEIPT で semantic が `evidence_length=0` だけを SHA に入れることは **#15 を代替しない**。non-empty blob を見逃す実装は **禁止**。

**Adjudication #16（RECEIPT 三方一致; P0-3）:**

| Check | Exact |
| --- | --- |
| stage | `RESULT.evidence_stage == EVIDENCE_CELL.material_receipt_stage` |
| length | manifest `total_length == cell.evidence_length`（0..128） |
| digest | manifest `content_digest == cell.evidence_digest` |
| bytes | ordered REPLY chunk stream **byte-exact** `== cell.evidence_bytes[0,len)` |

**RECEIPT constructible procedure（pin cell ≤128 then stream-compare; single 4096）:**

```text
SELECT RR → pin reply_kind=1, delivery raw80, tx16, last_carrier_key
FOCUS_MANIFEST_SCAN → REPLY install; #14 vs RR raw; #15 length 0..128
FOCUS_CHUNKS → content_digest stream vs manifest
SEMANTIC_PREFIX_REGET:
  1. exact_get(RR) → pin expected_semantic_digest FIRST
  2. exact_get(DELIVERY) → #14 + OWNER_PVD; SHA binding from DELIVERY
  3. exact_get(RESULT) → (a) POSITIVE_EVIDENCE matrix;
       pin pinned_receipt_stage := evidence_stage
  4. exact_get(EVIDENCE_CELL SUMMARY@0):
       require material_receipt_stage == pinned_receipt_stage
       require evidence_length == total_length (installed)
       require evidence_digest == content_digest (installed)
       pin receipt_evidence_len + receipt_evidence_bytes[0,len)
         (copy-before-get; max 128 fixed context)
       feed evidence_time into semantic sha_* from cell
SEMANTIC_CHUNK_REWALK / RECEIPT_BYTE_COMPARE:
  offset:=0
  for each chunk index 0..count-1 exact_get:
    for each data byte:
      require offset < receipt_evidence_len
      require byte == receipt_evidence_bytes[offset]
      sha_update(byte)  # semantic evidence portion
      offset++
  require offset == receipt_evidence_len
B6s: sha_final() == expected_semantic_digest
```

non-RECEIPT: no cell pin; #15 forces empty blob; semantic evidence_length=0 only; any chunk for blob_id → corrupt.

```text
After LIVE_REQUIRED CHUNKS:
  SEMANTIC_PREFIX_REGET:
    1. exact_get(RR) → pin expected_semantic_digest FIRST; reply_kind already pinned
    2. companions (DELIVERY first: #14+PVD; then kind matrix)
  SEMANTIC_CHUNK_REWALK:
    payload_length always 0
    RECEIPT: stream-compare pin + sha_update evidence bytes
    non-RECEIPT: evidence_length=0 only (#15 already empty)
  B6s: sha_final() == expected_semantic_digest
```

**Split rule（P1）:** (a) check vs (b) SHA feed は別集合。`RESULT.reason` / `application_result_kind` / `CANCEL_STATE.reason` 等は **SHA 禁止**（mapping 検査のみ）。

**Domain `reply_kind` → Bearer `kind`:**

| Domain | Bearer kind (SHA) |
| ---: | --- |
| 1 RECEIPT | RECEIPT (2) |
| 2 DISPOSITION | DISPOSITION (3) |
| 3 CUSTODY | CUSTODY_ACCEPTED (5) |
| 4 CANCEL_RESULT | CANCEL_RESULT (6) |

**Shared (b) binding from DELIVERY（only after #14）:** flags=0; transaction_id/attempt_id/event_id/generation; reverse source/target; service/content_digest/deadlines/grace/required_evidence — DELIVERY exact echo / RR.attempt_id。

**Mode30 per-kind matrix:**

| Kind | Gets | **(a) check only（not SHA）** | **(b) SHA scalars + lengths** |
| --- | --- | --- | --- |
| **1 RECEIPT** | DLV→RESULT→CELL@0 | #14;#15 0..128;#16 stage/length/digest/bytes; RESULT POSITIVE_EVIDENCE+NONE tuple; cell SUMMARY | kind=2; receipt_stage:=RESULT.evidence_stage; disp/cert/guide/delay/cancel=0; evidence_time from **cell**; payload_len=0; evidence from stream **== pin** |
| **2 DISPOSITION** | DLV→RESULT | #14;#15 empty; RESULT DISPOSITION+§12 §7.2（**reason (a) only**） | kind=3; receipt_stage=0; disp/cert/guide/delay from RESULT; cancel=0; evidence_time 0; lengths 0; **reason not SHA** |
| **3 CUSTODY** | DLV→RESULT | #14;#15 empty; RESULT 矛盾検査のみ（tuple not SHA） | kind=5; fixed zero tuple §12 5.4; lengths 0 |
| **4 CANCEL_RESULT** | DLV→RESULT→CANCEL | #14;#15 empty; CANCEL bijection; cancel_kind∈{1,3}; **reason (a) only** | kind=6; zero disp tuple; cancel_kind from CANCEL_STATE; lengths 0 |

**SHA feed order:** §5.1 exact order after ASCII label（kind… evidence_length ‖ evidence bytes）。

**Non-SHA checklist:** RESULT.reason / application_result_kind / cancel_result_kind（map only）; CANCEL reason/state/gate; token/timer fields。

EVIDENCE_CELL key: `COMPOSITE(32, DELIVERY || delivery_key_raw:RAW16 || slot_index=0)`。

Modes 27/29: no full Bearer semantic; owner content_digest match only。

##### 18.14.7.4 Digest pin lifetime table（constructibility checklist）

| Field | Pin when | Valid until | Consumed by |
| --- | --- | --- | --- |
| `view_a_key_digest` / `view_b_key_digest` | Mode28 carrier install | carrier advance | Mode28 FOCUS + re-SCAN |
| `reply_kind` | Mode30 RR carrier install | carrier advance | #15 + kind matrix |
| `focus_raw80` + `focus_id16` | Mode30 RR install（DLV raw80 + tx16） | carrier advance | #14 binding |
| `expected_manifest_value_digest` | SCAN install | CHUNKS complete | chunk PVD |
| `expected_owner_pvd` | SCAN install | OWNER_PVD / Mode30 DELIVERY get | owner VALUE_DIGEST |
| `expected_semantic_digest` | PREFIX RR get **before** companions | B6s | sha_final == pin |
| `pinned_receipt_stage` | RESULT get（RECEIPT） | cell stage check | #16 |
| `receipt_evidence_len` / `receipt_evidence_bytes[128]` | EVIDENCE_CELL get（RECEIPT） | byte-compare done | #16 stream-compare + SHA |
| `content_digest` / `total_length` / `blob_id` / `chunk_count` | SCAN install | Mode30 through rewalk | CHUNKS + #15/#16 |

#### 18.14.8 Exact companion / get-budget table

| Mode / situation | Setup exact_gets（before FOCUS） | Budget |
| --- | --- | ---: |
| **27** DesiredState TX | `TRANSACTION_STATE` | **1** |
| **27** EventFact TX | `TRANSACTION_STATE` + `EVENT_SPOOL` | **2** |
| **28** any | none（pin view digests from carrier） | **0** |
| **29** APPLICATION_FIRST | **RESULT_CACHE always** | **1** |
| **29** CANCEL_FIRST | none for payload path | **0** |
| **30** LIVE any kind | none at setup | **0** |
| **30** HISTORICAL/NONE | none | **0** |

**Post-SCAN OWNER_PVD_PROOF budget:** Mode27/28/29 ≤1 owner re-get per install unit; Mode30 0 extra（semantic DELIVERY）。

**Semantic exact_get budget（includes carrier re-get; pin expected_semantic on carrier get）:**

```text
Mode28: 1 carrier re-get only (PREFIX); RESCAN is iter walk
Mode30 RECEIPT:       1 RR + 1 DLV + 1 RESULT + 1 EVIDENCE_CELL(slot0) = 4
Mode30 DISPOSITION:   1 RR + 1 DLV + 1 RESULT = 3
Mode30 CUSTODY:       1 RR + 1 DLV + 1 RESULT = 3
Mode30 CANCEL_RESULT: 1 RR + 1 DLV + 1 RESULT + 1 CANCEL_STATE = 4
Finalize carrier re-get for expected semantic: 0 (pin required)
```

**Other budgets:** FOCUS_CHUNKS = chunk_count; Mode28 semantic RESCAN ≤2 band walks + chunk re-gets; BIND Port packing and per-unit get budgets are **§18.14.9 / §18.14.19**（BIND-WG / Mode30 pure-W）。

#### 18.14.9 BIND + untyped orphan chunk

**L1 obligations**（portable semantic correctness）and **REP1-L2 packing**（§18.14.19 micro-units **W / G / WG**）are joint. A pre-acceptance draft that required BIND formal walks with **Port GET count = 0** while still claiming full reverse-owner / untyped-orphan proof for **arbitrary** formal rows under fixed **754**-byte context / no full-ID set / one iterator+txn was **non-constructible**; that draft authority/oracle shape is **withdrawn**（§18.14.19）。The next formal authority regeneration must implement BIND-WG / Mode30 pure-W as below.

##### 18.14.9.1 Micro-unit packing pointer

| Mode / phase | Unit kind | Notes |
| --- | :---: | --- |
| Mode27–29 `BIND_MAN`（phase 11） | **WG** | walk + per eligible man owner `exact_get` |
| Mode30 `BIND_MAN` outer select / empty outer | **W** | pure walk; no owner reverse get |
| Mode30 RR-band（entry `semantic_pass=5`） | **W** | pure walk; boolean latch `observed_live` 0/1（§18.14.9.3） |
| Mode27–30 `BIND_CHUNK`（phase 12） | **WG** | walk + per valid chunk man-presence `exact_get` |

Exact Port event grammar, fault last-event, session state, and `d3_peer_get_count` rules: **§18.14.19.3 / .6 / .8 / .10**。

##### 18.14.9.2 Mode-scoped BIND_MANIFEST（Modes 27–29 = WG）

**Common eligibility base（all modes）:** typed CURRENT success **and** family = DOMAIN **and** subtype = BLOB **and** common flags = MANIFEST（`1`）。

**Exact numeric pair eligibility（closed; else non-eligible → visit only, GET 0）:**

| Mode | `blob_owner_kind` | `blob_kind` |
| ---: | ---: | --- |
| **27** | TRANSACTION（`1`） | COMMAND_PAYLOAD（`1`） or EVENT_PAYLOAD（`2`） |
| **28** | INGRESS（`2`） | INGRESS_PAYLOAD（`3`） or EVIDENCE（`4`） |
| **29** | DELIVERY（`3`） | COMMAND_PAYLOAD（`1`） or EVENT_PAYLOAD（`2`） |

Mode30 BIND_MAN is **not** WG owner-reverse; see §18.14.9.3（outer eligibility uses DELIVERY/`3` + REPLY/`5`）。

**Phase-local pin map（BIND_MAN WG; layout 754 unchanged）— exact fields only:**

| Context field | Pin source / meaning |
| --- | --- |
| `last_carrier_key` / `last_carrier_key_len` | actual man **complete key** bytes / length |
| `focus_key_digest` | `KEY_DIGEST(man complete key)` |
| `focus_raw80` / `focus_raw_len` | man body `owner_key_raw` contents; length exact **16**（mode27）/ **8**（mode28）/ **80**（mode29） |
| `owner_kind` | man body `blob_owner_kind` |
| `blob_kind` | man body `blob_kind` |
| `owner_primary_key_digest` | man body `owner_primary_key_digest` |
| `expected_owner_pvd` | man common header **primary_value_digest** |
| `peer_key` / `peer_key_len` | forward-rebuilt **owner request complete key** |

Do **not** require BIND_MAN pins of man `blob_id_digest`, `total_length`, or `chunk_count`。After each eligible row’s proof finishes, these phase-local pins may be **overwritten** by the next eligible row。

**Proof steps（after visit commit §18.14.9.5; pins above; before/around get）:**

1. Forward-rebuild owner complete key from pinned `owner_kind` + `focus_raw80`/`focus_raw_len`（D1 pure; no digest→key reverse）。
2. Write rebuilt key into `peer_key`/`peer_key_len`。Require **`KEY_DIGEST(rebuilt owner complete key) ==` pinned `owner_primary_key_digest`**。
3. **`exact_get(peer_key)`**（D2-S4: value overwrite only; iterator position/key unchanged）。Require PRESENT。
4. Returned row typed CURRENT; subtype exact: mode27 TRANSACTION_ANCHOR; mode28 ORDERED_INGRESS; mode29 DELIVERY。
5. **Returned owner raw identity exact:**
   - mode27: ANCHOR `transaction_id` exact 16 == pinned raw16;
   - mode28: ORDERED_INGRESS `ordered_sequence` as u64be exact 8 == pinned raw8;
   - mode29: DELIVERY body delivery logical raw / `delivery_key_raw` contents exact 80 == pinned raw80。
6. **Referrer digest exact**（must equal pinned `focus_key_digest` = man key digest）:
   - mode27: ANCHOR `payload_blob_key_digest`;
   - mode28: if pinned `blob_kind`=INGRESS_PAYLOAD（`3`）then ORDERED_INGRESS `payload_blob_key_digest`; if pinned `blob_kind`=EVIDENCE（`4`）then `evidence_blob_key_digest`。**Forbidden:** accepting the other view’s digest as a match for the wrong `blob_kind`;
   - mode29: DELIVERY `payload_blob_key_digest`。
7. **`VALUE_DIGEST(returned owner complete value) ==` pinned `expected_owner_pvd`**。

Failure → sticky semantic/Port mapping per §18.14.10 / §18.14.19.10; **no residual `iter_next` after a natural GET fault** in the same drive。Non-eligible rows: **GET 0**。

##### 18.14.9.3 Mode30 BIND_MANIFEST（pure W only; frontier + boolean latch）

**Outer eligible REPLY man:** typed CURRENT + family DOMAIN + subtype BLOB + flags MANIFEST（`1`）+ `blob_owner_kind`=DELIVERY（`3`）+ `blob_kind`=REPLY（`5`）。

**Derived control state（Normative even though `peer_key` is not a checkpoint field）:**

| Field | Role |
| --- | --- |
| `last_carrier_key` / `last_carrier_key_len` | **proven BLOB-manifest frontier only**（empty after BIND-entry init; advanced only after successful RR） |
| `peer_key` / `peer_key_len` | **selected candidate** man complete key while outer→RR in flight |
| `focus_key_digest` | `KEY_DIGEST(selected man complete key)` while selected |
| `focus_raw80` / `focus_raw_len` | selected man owner raw **exact 80** while selected |
| `owner_kind` / `blob_kind` | DELIVERY（`3`）/ REPLY（`5`）while selected |
| `observed_live` | boolean latch **0/1 only**（never a count; never increments past 1） |

**No** full-ID set; **no** multiset of bound mans。

**BIND-entry initialization（Mode30 only; exactly once on SELECT → BIND transition）:**

When SELECT true-exhausts with **no more carriers** and the OK exit enters Mode30 `phase=11` BIND_MAN（§18.14.19.8 empty-SELECT row）, **before the first Mode30 outer W** and **not** before each later outer W, apply **exactly** this initialization（byte-exact）:

| Action | Exact |
| --- | --- |
| `last_carrier_key[0..44]` | all **45** bytes **0**; `last_carrier_key_len := 0`（empty **BLOB-manifest** frontier） |
| `peer_key[0..44]` | all **45** bytes **0**; `peer_key_len := 0` |
| `focus_key_digest[0..31]` | all **32** bytes **0** |
| `focus_raw80[0..79]` | all **80** bytes **0**; `focus_raw_len := 0` |
| `owner_kind` | `0` |
| `blob_kind` | `0` |
| `observed_live` | `0` |
| `semantic_pass` | `0` |

**Preserve unchanged** every context field **not** listed above, including **`focus_id16[16]`**, count/binding masks, flags bits other than those already set by the SELECT exit tuple, digests/SHA state, and all other §18.14.12 fields。

**Rationale:** at SELECT exit, `last_carrier_key` still holds the prior SELECT **carrier** complete key（REVERSE_REPLY namespace for Mode30）。Without this BIND-entry reset, outer W would compare BLOB **manifest** keys against a RR key frontier and may skip all manifests。First outer W therefore always starts with an empty BLOB-manifest frontier; later outer walks use only frontiers **promoted from proven REPLY man keys** after successful RR。

**Outer W（entry `phase=11`, `semantic_pass=0`）— exact algorithm:**

1. Walk zero-prefix to true NOT_FOUND（or Port fault）。
2. Selection: among eligible REPLY mans visited, choose **exactly the first** complete key that is **strictly greater than** the current proven BLOB-manifest frontier `last_carrier_key`（lex complete-key order）。If `last_carrier_key_len==0`, the first eligible REPLY man in walk order is selected。
3. On selection（at most one per outer W）:
   - `peer_key`/`peer_key_len` := selected complete key;
   - pin `focus_key_digest`, `focus_raw80`/`focus_raw_len`, `owner_kind`, `blob_kind` from that man;
   - `observed_live := 0`;
   - **`last_carrier_key` remains the prior proven BLOB-manifest frontier**（does **not** advance at selection）。
4. True exhaustion **with** a selected candidate → exit to RR W: keep `phase=11`, set `semantic_pass=5`, preserve `peer_key` and selected proof pins, `observed_live=0`, set `NEED_REOPEN` per exit tuple（`F_BIND_REOPEN`）。
5. True exhaustion **with no** candidate → **only** this path enters BIND_CHUNK（`binding` man bit set per §18.14.19.8）。

**RR-band W（entry `phase=11`, `semantic_pass=5`）— exact algorithm:**

1. Pure zero-prefix walk; GET 0。Using only preserved selected pins, a row **qualifies** iff typed CURRENT REVERSE_REPLY **and** `body_blob_key_digest == focus_key_digest` **and** delivery raw80 exact-equal pinned `focus_raw80`/`focus_raw_len` **and** `send_state ∈ {1,2,3,4}`。
2. For any qualifying RR: set **`observed_live := 1` idempotently**（if already 1, leave 1; **never** increment / multi-count）。
3. True NOT_FOUND with **`observed_live == 0`** → CORRUPT sticky; **frontier does not advance**; selected pins may remain failure-point capture values。
4. True NOT_FOUND with **`observed_live == 1`** → **atomic success promotion**（exact clear set after frontier copy）:
   - copy `peer_key`/`peer_key_len` → `last_carrier_key`/`last_carrier_key_len`（new proven BLOB-manifest frontier; length and all selected key bytes）;
   - then **exact clear**（all bytes of each array, then lengths/kinds）:
     - `peer_key[0..44] := 0`; `peer_key_len := 0`;
     - `focus_key_digest[0..31] := 0`;
     - `focus_raw80[0..79] := 0`; `focus_raw_len := 0`;
     - `owner_kind := 0`; `blob_kind := 0`; `observed_live := 0`。
   - **`focus_id16` and every context field not listed in this clear set remain unchanged**。
   - `semantic_pass := 0`; set `NEED_REOPEN`; remain `phase=11` for next outer W。
5. Next outer W may select only keys **strictly greater than** the new frontier ⇒ **no same-man loop / nontermination** under finite fixtures。

Harness that invents RR complete keys from digest alone **must fail**（AFP #8）。

##### 18.14.9.4 BIND_CHUNK（Modes 27–30 = WG）

**Eligible row predicate（closed）:** typed CURRENT success **and** family = DOMAIN **and** subtype = BLOB **and** common flags = CHUNK（`2`）。  
Malformed / non-CURRENT domain rows fail under existing D1/structural authority **before** any BIND get。Non-eligible OK rows: visit only, **GET 0**。

**Phase-local pin map（BIND_CHUNK WG; exact）:**

| Context field | Pin source / meaning |
| --- | --- |
| `last_carrier_key` / `last_carrier_key_len` | actual chunk **complete key** |
| `blob_id_digest` | chunk body `blob_id_digest` |
| `focus_key_digest` | chunk body `manifest_key_digest`（pinned as-is） |
| `next_chunk_index` | chunk body `chunk_index`（u32） |
| `chunk_count` | chunk body `chunk_count`（u32） |
| `total_length` | chunk body `total_length`（u64） |
| `content_digest` | chunk body `content_digest` |
| `expected_manifest_value_digest` | chunk common header **primary_value_digest** |
| `peer_key` / `peer_key_len` | forward-rebuilt man complete key `COMPOSITE(BLOB, u8=1 ‖ blob_id_digest)` |

Do **not** pin chunk payload bytes（D1 typed CURRENT validation of the chunk row is already authority for local chunk shape/length/single-chunk hash）。Pins may be overwritten by the next eligible chunk after the current proof completes。

**Proof steps（after visit commit; pins above）:**

1. Rebuild man complete key from pinned `blob_id_digest` into `peer_key`/`peer_key_len`。
2. **`exact_get(peer_key)`** → must be **PRESENT**（ABSENT ⇒ untyped orphan CORRUPT）。
3. Returned row: typed CURRENT + family DOMAIN + subtype BLOB + flags MANIFEST（`1`）。
4. Returned man body fields **exact equal** to pins: `blob_id_digest`, `chunk_count`, `total_length`, `content_digest`。
5. Pinned `next_chunk_index` is strictly less than returned man `chunk_count`。
6. Pinned actual chunk complete key **exact equal** forward formula `COMPOSITE(BLOB, u8=2 ‖ blob_id_digest ‖ index:u32be)` with pinned index/blob_id。
7. Digest equality on the **request / rebuild path only**（GET returns **value**; Port output key fields empty per §18.14.19.7）:  
   pinned `focus_key_digest` **exact equal** `KEY_DIGEST(peer_key request)` **exact equal** `KEY_DIGEST(forward-rebuilt man complete key)`。  
   Do **not** derive a complete-key identity from the get response（value-only）。
8. Returned value is typed CURRENT domain BLOB MANIFEST（flags `1`）and body fields match pins as in steps 3–5。  
   **`VALUE_DIGEST(returned man complete value) ==` pinned `expected_manifest_value_digest`**。  
   Do **not** compare against the returned man’s own common header primary_value_digest field for this step（that man-header field is the owner-value digest role; the BIND_CHUNK pin is the chunk common PVD）。
9. Fully consume get result **before** the next `iter_next`。

##### 18.14.9.5 Visit commit / copy-before-get / reentrancy（PASS_INTERNAL freeze preserved）

**Preserve §18.13.5 / S3 PASS_INTERNAL freeze:** under `pass_kind=INTERNAL`, every internal **W** and **WG** keeps public D2 counters frozen at their post-BASELINE values:

- `ok_row_count`, `current_domain_key_count`,
- `family14_row_count` / `family14_iter_seen_mask` / reconciliation masks,
- profile / future diagnostics  

**must not** re-increment, re-reconcile, or re-run baseline accounting。REP1-v1 does **not** introduce a separate public internal-visit counter; if one is needed later it is out of REP1-v1 scope。

**Pass-local visit commit（exactly once, before any BIND get for that row）:**

After successful structural current-row acceptance of an `iter_next` OK and **before** the S3 cross-row hook / BIND get, commit **only**:

- `has_previous`, `previous_key` / `previous_key_length`（pass-local lex）。

**No** public `ok_row_count` / `current_domain_key_count` increment on this path。Natural GET fault and semantic mismatch after get retain that **lex-only** commit; still **no** public counter increment。

**Copy-before-get:** for every BIND WG get, install only the exact phase-local pin tables of §18.14.9.2 / .4 **before** get; after get, **forbid** use of pre-get typed/borrowed pointers into `workspace->value`。

**Internal hook exception:** private H1/BIND path may call `exact_get` under WG; **public/user callback reentrancy into scanner APIs is forbidden**。

**Implementation note:** production/scanner hook order that currently defers lex commit past get, or re-increments frozen public counters under INTERNAL, is a **follow-on implementation defect**. The current deterministic oracle candidate does not claim that production/scanner repair complete.

**Port-only decision rule:** WG eligibility, pin fill, rebuild request key, and post-get compares are determined **only** from the current typed row + phase-local pins + get response。They **must not** consult fixture `idx` / offline full `rows[]` / full-ID sets。

#### 18.14.10 Precedence / hooks

Unchanged spirit: H1–H5; sticky first wins; finalize not first compare needing live txn without pins。BIND WG natural GET fault: sticky / FAILED / phase14 per §18.14.19.10; cleanup only in finalize。

#### 18.14.11 Honest cost / ESP32 memory

| Item | Freeze |
| --- | --- |
| Per-session | O(Fₘ·N_BLOB + chunks + semantic_rescans + OWNER_PVD gets + BIND) |
| Mode27–29 BIND_MAN **WG** | **O(N + M)** Port events class: one full walk over N rows + **one owner get per mode-scoped man M** |
| Mode27–30 BIND_CHUNK **WG** | **O(N + C)** : one full walk + **one man-presence get per valid chunk C** |
| Mode30 BIND | outer man select **W** + per-man **RR-band pure W**（each band is a full zero-prefix walk; honest multi-walk cost **Θ(N_REPLY · N)** class, not one-shot O(N)）+ BIND_CHUNK WG |
| Mode28 semantic | 1 carrier re-get + ≤2 band SCANs + chunk re-gets |
| Mode30 semantic | 3..4 prefix gets + chunk re-gets; owner PVD folded into DELIVERY get |
| Memory | fixed context **754** + single 4096; expected digests in context pins; **no** full-ID set / heap / VLA / second txn / second iterator |

#### 18.14.12 Fixed S3 context layout（sizeof **754** / align 1 / ceiling **768**）

**Adjudication #11–#16:** dual-view + owner/semantic pins + **RECEIPT evidence byte pin (128)** for stream-compare under single 4096。

| Offsets | Size | Field |
| ---: | ---: | --- |
| 0..44 | 45 | `last_carrier_key` |
| 45 | 1 | `last_carrier_key_len` |
| 46..125 | 80 | `focus_raw80`（Mode30: RR delivery raw） |
| 126 | 1 | `focus_raw_len` |
| 127..142 | 16 | `focus_id16`（Mode30: RR.transaction_id） |
| 143..174 | 32 | `focus_key_digest` |
| 175..206 | 32 | `blob_id_digest` |
| 207..238 | 32 | `content_digest` |
| 239..270 | 32 | `owner_primary_key_digest` |
| 271..302 | 32 | `expected_manifest_value_digest` |
| 303..310 | 8 | `total_length` |
| 311..314 | 4 | `chunk_count` |
| 315..318 | 4 | `next_chunk_index` |
| 319..326 | 8 | `length_sum` |
| 327..358 | 32 | `sha_state` |
| 359..366 | 8 | `sha_bitcount` |
| 367..430 | 64 | `sha_block` |
| 431 | 1 | `sha_block_len` |
| 432..476 | 45 | `peer_key` |
| 477 | 1 | `peer_key_len` |
| 478 | 1 | `owner_kind` |
| 479 | 1 | `blob_kind` |
| 480 | 1 | `expected_live` |
| 481 | 1 | `observed_live` |
| 482 | 1 | `lifecycle_class` |
| 483 | 1 | `phase` |
| 484 | 1 | `pass_kind` |
| 485 | 1 | `flags` |
| 486 | 1 | `count_complete_mask` |
| 487 | 1 | `binding_complete_mask` |
| 488 | 1 | `focus_mode` |
| 489 | 1 | `focus_sub` |
| 490 | 1 | `semantic_pass` |
| 491 | 1 | `reply_kind`（Mode30 1..4; else 0） |
| 492..523 | 32 | `view_a_key_digest` |
| 524..555 | 32 | `view_b_key_digest` |
| 556..587 | 32 | `expected_owner_pvd` |
| 588..619 | 32 | `expected_semantic_digest` |
| 620..747 | 128 | `receipt_evidence_bytes` |
| 748 | 1 | `receipt_evidence_len` |
| 749 | 1 | `pad0`（MBZ 0） |
| 750..753 | 4 | `pinned_receipt_stage`（u32 BE） |
| **Σ** | **754** | |
| ceiling | **768** | headroom **14** |

**Python oracle product-path memory（R9–R24; constructibility evidence only — not a C sizeof proof; not production C / bridge GO）:** product call-spanning state is **1:1-mappable** onto §18.14.12 slots via an **executable** pin/man → `(offset,size)` map. `active_pins` / `active_man` are temporary projections; simultaneous live keys with unequal values **must not** claim overlapping byte ranges. Drive-end assert rejects unmapped keys, OOB ranges, pin≠context, and unequal collisions.

**R12 owner_raw identity gate（FOCUS dig-match; immediate abort）:** when a selected carrier's dig-matching manifest body has `owner_raw` that does **not** equal the SELECT carrier identity (Mode27: ANCHOR.tx16; Mode29: DELIVERY raw80; Mode30: RR delivery raw80), the oracle must sticky **CORRUPT / phase14 / adopted=0** at the **exact mismatch row** — **before** installing the man into call-spanning `active_man` / context slots — and **abort the walk immediately** via the `_walk_abort` / SEMANTIC path (not a Port-fault reclassification). No residual `iter_next` / `NOT_FOUND` after the mismatch row. First sticky wins: a NATURAL fault scheduled on the next event must not overwrite CORRUPT. FAILED releases `active_pins`, `active_man`, and the single product SHA bank.

**R13–R24 independent unit grammar / formal fault & type closure（Port mechanics; not circular expected-trace copy）:**

1. **W / G schedule (R13+):** successful non-B5 **W** requires a terminal operational `iter_next NOT_FOUND`. **Every G window** re-derives GET **count / order / request keys** from fixture rows + entry checkpoint only (never by copying `port_trace`): (a) **success** → full planned exact schedule; (b) **natural Port fault** → exact planned prefix through the failing attempt (fixture must not have required an earlier stop; prior OK GETs are a **proper** prefix of the fixture-realized schedule so a natural GET after a semantic-stop row is forbidden); (c) **GET NOT_FOUND/ABSENT** → exact prefix through the first fixture-missing request; (d) **GET OK then early semantic failure** → exact prefix through the GET whose returned value first fails product semantic checks (inspect value; no arbitrary shortening; no residual GET after the stop). In **WG**, GET `NOT_FOUND` or any non-OK NATURAL GET is unconditionally the last operational event of that drive window.

2. **G GET `storage_status` column (R15; Normative):** for every product G GET, the expected Storage status is derived **independently** from fixture rows' complete-key presence column — **present ⇒ `OK`**, **absent ⇒ `NOT_FOUND`**. This applies to **every** GET in success, ABSENT, and semantic-stop schedules. On a **natural Port fault** G window, only the **last** fault attempt may carry the configured NATURAL status; **all prior** GET statuses in that window must match the fixture presence column exactly. Expected keys **and** statuses must never be copied from `port_trace` itself.

3. **Formal faults length 0|1 binding (R14+; Normative):** when `faults` has length **1**, the full `port_trace` contains **exactly one** natural Port event, and that event's `op` / `on_call` / `storage_status` equal `faults[0].op` / `on_call` / `status` exactly, with `faults_expected_used=1` and `shape="natural"`. When `faults` has length **0**, there is **no** natural Port event and `faults_expected_used=0`. Configured-but-unobserved faults and natural events without a configured fault are ill-formed. **Applies only to `rep1_l2` product vectors**（exact call/Port grammar is `rep1_l2` only; see R18 formal_precheck lane）。

4. **zero-Port on formal_precheck (R18; Normative):** the single formal-precheck vector is **pre-generation validator-only**. It **must not** call any production API and **must not** synthesize runtime `status` / `session` / `checkpoint` / `result`. Its `port_trace=[]` is the consequence of the **bridge not invoking production**, not a runtime product walk. Configured faults, unobserved faults, natural Port events, and `faults_expected_used=1` remain **forbidden** on that shape (`faults=[]`, `faults_expected_used=0`). Runtime duplicate-complete-key defense is a **separate nonzero-Port** product test — not this formal_precheck lane.

5. **JSON array type strictness (R16; Normative):** `expected.port_trace` and top-level `faults` **must** be JSON arrays. Falsy non-array values (e.g. `{}`, `""`) **must not** be coerced to empty arrays; they are type-invalid and reject.

6. **Candidate lane split + bridge RED (R18; R26 Normative inventory):** D3-S3 suffix **129** = **`rep1_l2` 128** + **`formal_precheck` 1**. Exact call/Port grammar and REP1-L2 transcript equality bind **only** the 128 `rep1_l2` vectors. Formal ID of the precheck vector: **`D3S3_M27_DUPLICATE_DIGEST_MATCH_CORRUPT`** with `precheck_error` **`DUPLICATE_COMPLETE_KEY`**. Bridge is **two-lane**; unknown scope, count drift, and silent skip are **RED**.

7. **Independent D1-legality gate (R19–R24; Normative constructibility):** every suffix fixture row（`rep1_l2` and `formal_precheck`）must be **locally D1-legal** under a generator-time pure gate that does **not** invoke production C（production C is **not** oracle authority; a production typed diagnostic may be used only as a **non-authoritative cross-check**）. The gate is **complete independent Normative D1** for every used family6 subtype/variant — **not** a partial subset:
   - family1–4 profile rows: exact membership in the independent canonical catalog from `encode_all_profile_rows(default_binding)`（byte pair equality）
   - family6 common key: value **record_type exact 6**（record_type 5 is **RED** on family6 keys）
   - family6 BLOB man/chunk (**0x30**): full same-record（count/index/total/chunk length/key formula/digests/CRC; **common primary_id from owner** — TX=owner_raw16, INGRESS=left-pad u64, DELIVERY=composite identity first 16; chunk primary_id = man composite first 16; **immutable `record_revision=1`**）; **owner_key_raw full canonical identity** — TRANSACTION exact **nonzero** 16-byte ID; INGRESS exact BE8 ordered_sequence **>0**; DELIVERY exact 80-byte raw with **each of five 16-byte IDs nonzero**（length-only acceptance is **RED**）
   - family6 **0x20 TRANSACTION_ANCHOR**: party/target/service validity; family∈{EventFact,DesiredState} with service.family match; EventFact deadline epoch **zero** / absolute deadline **`NINLIL_NO_DEADLINE` (`UINT64_MAX`)** / grace **0** / generation **0** / event_id non-zero; DesiredState opposite deadline shape; required_evidence known non-zero; scope = app_instance‖namespace‖service; scheduler sequences equal; complete derived digests seq/im/event_map/reservation; EventFact `event_map_key_digest=KEY_DIGEST(complete EVENT_ID_MAP key)`; **immutable `record_revision=1`**
   - family6 **0x22 TRANSACTION_STATE**: **closed family×state×outcome×deadline×reason×evidence×dependent product** re-extracted from docs/12 public snapshot + **docs/13 Normative reducers** + Disposition matrix + clock-uncertainty recovery（**not** mere enum range-checks; **not** production C; docs/12/13 are Normative authority; this section must stay 矛盾0 with them）:
     - nonterminal states READY/DISPATCHING/AWAITING/PARKED/WAITING require outcome **NONE**; TERMINAL requires exactly the five reachable non-zero Outcomes（SUPERSEDED_RESERVED never stored）
     - READY/DISPATCHING reason NONE + park NONE; DS deadline PENDING only
     - **AWAITING** reason ∈ {NONE(0), EFFECT_POSSIBLE_EVIDENCE_PENDING(68), CANCEL_AFTER_EFFECT(83), CANCEL_PENDING_REMOTE_FENCE(86), APPLICATION_FAILED(128), OUTCOME_UNKNOWN(129)} — effect-possible Disposition may remain AWAITING; **REQUIRED_EVIDENCE_MET(64) illegal here**
     - PARKED (EventFact only) reason `EVENT_RETRY_CYCLE_PARKED` + park∈1..5 + EF retry/es_rev shapes
     - **WAITING** reason ∈ {CAPACITY_EXHAUSTED(11), TRANSPORT_RETRY(85), APPLICATION_FAILED(128), RECEIVER_UNAVAILABLE(130), RECONCILE_RETRY_LATER(132)} **only**（retry-window creators from docs/13; terminal-only 82/83/69/129 and AWAITING-only 68/86 are **RED**）
     - **TERMINAL outcome↔reason exclusive** (docs/13):
       - SATISFIED = {REQUIRED_EVIDENCE_MET(64)} only; deadline MET; latest∈1..4
       - EXPIRED = {REQUIRED_EVIDENCE_LATE(65), DEADLINE_ELAPSED_BEFORE_DISPATCH(66), CLOCK_UNCERTAIN(20)}; 65/66 ⇒ MISSED (+65 requires latest∈1..4); 20 ⇒ INDETERMINATE
       - OUTCOME_UNKNOWN terminal = {EFFECT_POSSIBLE_EVIDENCE_MISSING(69), CLOCK_UNCERTAIN(20)} only — Disposition reason OUTCOME_UNKNOWN(129) is AWAITING-only (docs/13 reducer; terminalize via evidence close 69 / clock 20); deadline INDETERMINATE
       - CANCELLED = {CANCEL_FENCED_BEFORE_DISPATCH(82)} only; **CANCEL_AFTER_EFFECT(83) is AWAITING-only, not terminal CANCELLED**
       - FAILED = {TARGET_UNAUTHORIZED(22), RETRY_BUDGET_EXHAUSTED_NO_EFFECT(70), OPERATOR_DISCARDED(80), APPLICATION_FAILED(128)}; FAILED excludes 69/20
       - CLOCK_UNCERTAIN(20) is legal for EXPIRED **and** UNKNOWN only (shared; not exclusive either way)
     - EventFact forbids terminal EXPIRED/CANCELLED — terminal is **Receipt SATISFIED+64** or **audited discard FAILED+80** only; `explicitly_discarded=1` iff TERMINAL+FAILED+OPERATOR_DISCARDED
     - DS counters retry/attempt/es_rev all 0; EF es_rev≥1 and retry≥1; cumulative_attempts≥attempt_in_cycle; has_late=1⇒latest≠NONE; target_* mirrors exact; mutable `record_revision≥1`
     - Permanent RED + false-red guards; **28** legal positives (DS **23** + EF **5**)
     - **Mode27 EventFact lifecycle** (state-class × spool): nonterminal+ACTIVE/PARKED → LIVE; receipt(SATISFIED+64)+RELEASED → HISTORICAL; discard(FAILED+80)+DISCARDED → HISTORICAL; **all other cross-pairs CORRUPT** (including receipt+DISCARDED, discard+RELEASED, nonterminal+DISCARDED/RELEASED). Permanent self-test enumerates **4×4=16** cells (nonterminal/parked/receipt/discard × spool); **7** permanent cross-row CORRUPT product vectors
     - **D3-S1 prerequisite boundary (honest):** same-record D1 gate + Mode27 lifecycle classifier close constructibility for ANCHOR/STATE/SPOOL/BLOB under this product; live owner cardinality, SERVICE mask, retention/cleanup, and production bridge REP1-L2 field equality remain **D3 / production** and are **not** claimed closed by this oracle-candidate lane
   - family6 **0x27 ORDERED_INGRESS**: **immutable `record_revision=1`**; owner_sequence≥1; binding-by-kind exact（APP/CANCEL_REQUEST→EXISTING_DLV|NEW_DLV; RECEIPT/DISPOSITION/CUSTODY/CANCEL_RESULT→EXISTING_TX）; IDs/enums/MBZ; family-deadline; service; evidence+controller clocks; **DISPOSITION closed disposition/effect/guidance/delay tuple** (docs/12 §7.2); **APPLICATION empty payload requires `content_digest=SHA-256(empty)`** even when MSD is recomputed; reservation dig / MSD / view-dig matrix; **DesiredState-only kinds are CANCEL_REQUEST (kind4) and CANCEL_RESULT (kind6) only** — **not** CUSTODY (kind5); EventFact CUSTODY is legal when binding/enums/MSD close
   - family6 **0x32 EVIDENCE_CELL**: primary_key_digest recompute / target_digest non-zero / issuer; **TRANSACTION owner_raw exact nonzero 16-byte transaction ID** (all-zero raw **RED** even with length 16); SUMMARY material known stage **1..4** triple-equal + late bit + service/content/durable/epoch/trust known **{1,2} only** (unknown nonzero trust **RED**) + family-generation + counters; RAW MATERIALIZED exact material tuple (stage 1..4, late 0/1, service/content/durable/epoch/trust/issuer/digest; aggregate counters 0) with **mandatory baseline** before field mutations; ABSENT/empty SUMMARY/RAW UNUSED identity-only zero; mutable `record_revision≥1`
   - family6 **0x33 CANCEL_STATE**: owner/key/primary_kd + closed state-kind-reason-effect bijection + send-gate/attempt-digest/timeout **seven-shape** matrix
   - family6 **0x40 DELIVERY**: **immutable `record_revision=1`**; raw five components + bijection / reservation dig / family-deadline / service / payload/result digests
   - family6 **0x41 RESULT_CACHE**: every field enum surface + full state/token/reply product; **exact E_DISP** disposition closed product + reason mapping; **exact E_REC** reason×default-guidance×token-state allocation for physical state **6/7** (docs/17 §8.5 tables 574–630); recovery ACTIVE / non-E_REC reason **RED**
   - family6 **0x42 REVERSE_REPLY**: reply_key_raw = delivery RAW16‖kind / send-state/counter/availability/timer closed matrix
   - family6 **0x50 EVENT_SPOOL**: state×cause; **common `record_revision` equals body `spool_revision`** (both ≥1); event / retry / blob dig / reservation / resume / discard closed tuples
   - **exact body length / no trailing bytes** retained for every used subtype; **`d1_independent_row_legality` is total and fail-closed** for every bytes input and every used subtype/variant — validate min/exact body length **before** any `struct.unpack`/slice requiring a minimum（R24 closed EVIDENCE_CELL/CANCEL_STATE/DELIVERY empty-body `struct.error` holes）. Permanent **boundary sweep**: for each accepted baseline variant, body length every value from `0` through `exact_length-1` and `exact_length+1` with outer lengths/CRC/header recomputed; every case returns a deterministic D1 reason string and **never raises**. Pinned boundary totals: **4380** across variants `20:670,22:225,27:646,30c:118,30m:131,32:799,33:227,40:553,41:379,42:331,50:301` (each = exact+1). Malformed Python types / empty key/value return a reason, not an uncaught exception
   - unknown family6 subtypes: **fail closed**（not framing-accepted）
   - **R22–R24 anti-false-green secondary authority:** permanent self-test runs the independent row validator against shipped `spec/vectors/domain-store-v1.json` used-subtype rows（never production C as oracle）: **`typed_record` pos=74 accept / neg=60 reject**; **`body_decode` wrap into legal family6 common envelope+complete key — checked=306 / non_app=0 / neg_ok=306** (no silent skip; unknown ID/schema/count drift **RED**); **`body_roundtrip` pos=132 accept**; unknown expectation shapes fail closed
   - **CLI closed failure contract (R24):** `check` validates top-level **object** and required field shapes **before** `.get` / authority pins. Malformed/input failures（`[]` / `null` / string / number / `{}` / malformed JSON / missing file / wrong vector field shapes）**exit 2**, one short stderr line starting with `error:`, **no traceback**, no success stdout. Authority RED remains exit 1. Explicit input-shape validation only — not a broad catch that hides programming errors
   `formal_precheck` may duplicate complete keys, but each individual row remains local-D1. D1-invalid constructions are **forbidden**; intended D3 failures must use **D1-valid** rows with **cross-row** disagreement（including CANCEL_RESULT↔CANCEL_STATE bijection via two legal rows）. BIND_CHUNK step5 index-only is **non-constructible** given D1 + step4 equality. Production must **not** defer or weaken D1. **Sol high on R21 was NO-GO**. **Sol high on R22 was NO-GO**. **Sol high on R23 was NO-GO** (TRANSACTION_STATE enum-only false-green; empty-body `struct.error` on CELL/CANCEL/DELIVERY; CLI `[]` AttributeError). **R24 Proposed** repaired some R23 residuals (Sol high NO-GO); **R25 Proposed** repaired R24 residuals and was **Sol high NO-GO**; **R26 Proposed** repaired R25 residuals and Root QA found residual STATE matrix NO-GO holes; **R27 Proposed** re-extracts the full TRANSACTION_STATE reachable public snapshot matrix from docs/12+docs/13 reducers and closes those holes without weakening R16–R26. **R23–R26 did not complete D1.** **Accepted / GO forbidden.**

##### Exhaustive pin → §18.14.12 slot map

| Pin key | Slot | Offsets | Lifetime |
| --- | --- | ---: | --- |
| `carrier_key` | `last_carrier_key` (+len) | 0..45 | live carrier path; `== last_carrier_key` |
| `focus_dig` | `focus_key_digest` | 143..174 | SELECT referrer; after FOCUS man match equals `man.key_digest` (27/29/30) |
| `tx16` | `focus_id16` | 127..142 | Mode27 only |
| `view_a` | `view_a_key_digest` | 492..523 | Mode28 |
| `view_b` | `view_b_key_digest` | 524..555 | Mode28 |
| `semantic_stored` / `semantic_digest` | `expected_semantic_digest` | 588..619 | Mode28 / Mode30 (same slot; mode-exclusive live) |
| `owner_raw` | `focus_raw80` (+len) | 46..126 | Mode29 |
| `focus_raw80` | `focus_raw80` (+len) | 46..126 | Mode30 |
| `transaction_id` | `focus_id16` | 127..142 | Mode30 |
| `reply_kind` | `reply_kind` | 491 | Mode30 |
| `send_state` | `next_chunk_index` (u32 holds u8) | 315..318 | Mode30 SELECT→PREFIX only (non-checkpointed) |
| `receipt_evidence_bytes` | `receipt_evidence_bytes` | 620..747 | Mode30 RECEIPT after PREFIX |
| `receipt_evidence_len` | `receipt_evidence_len` | 748 | Mode30 RECEIPT |
| `pinned_receipt_stage` | `pinned_receipt_stage` | 750..753 | Mode30 RECEIPT |

**Not call-spanning (removed after use / never pinned):** `needs_setup` (install_kind only); `is_event_fact` / Mode29 `creation_kind` held briefly in `owner_kind` until SELECT_SETUP then overwritten by man; `state_discarded` / `spool_present` / `rc_delivery_state` drive-local in SELECT_SETUP G.

##### Exhaustive man → §18.14.12 slot map

| Man key | Slot | Offsets | Alias notes |
| --- | --- | ---: | --- |
| `key_digest` | `focus_key_digest` | 143..174 | M28: must equal selected `view_a`/`view_b` for active arm |
| `blob_id` | `blob_id_digest` | 175..206 | |
| `content_digest` | `content_digest` | 207..238 | |
| `owner_primary_key_digest` | `owner_primary_key_digest` | 239..270 | |
| `expected_manifest_value_digest` | `expected_manifest_value_digest` | 271..302 | |
| `total_length` | `total_length` | 303..310 | |
| `chunk_count` | `chunk_count` | 311..314 | |
| `owner_kind` / `blob_kind` | same | 478 / 479 | |
| `expected_owner_pvd` | `expected_owner_pvd` | 556..587 | |
| `owner_raw` | M27→`focus_id16`; else→`focus_raw80` | 127..142 / 46..126 | equals carrier identity (tx / raw80 / INGRESS BE8) |

##### Phase release

| Surface | pins/man / SHA |
| --- | --- |
| SELECT sem=6 | pins live; man absent |
| FOCUS…SEM_CHUNK | pins live; man live after dig-match |
| SELECT sem=0 / BIND / COMPLETE | **both None** |
| FAILED (sticky) | **both None before drive-end assert**; product SHA abandoned. Normative failure-point is flags/masks/`focus_id16`/`last_carrier_key`/checkpoint fields — not Python pin/man dicts. **No FAILED exemption** for live unequal slot claims. |

**SELECT frontier:** no `carrier_queue`/`carriers_seen`; next carrier = Port row + `last_carrier_key` (empty=−∞). Offline `rows`/`idx` = Storage simulators only. Mode28 both-nonzero → SELECT CORRUPT/no-adopt. Concurrent SHA=1; abandon on every failure.

**flags / masks:** count bit0/1/2; binding bit3/4（unchanged）。

#### 18.14.13 Memory ceilings（**9920** path; recalculated after #16）

| Object | Ceiling |
| --- | ---: |
| scanner | **8192** unchanged |
| Stage5-alone | **8704** unchanged |
| S1 | 421 / **448** unchanged |
| S2 | 306 / **320** unchanged |
| S1+S2 outer | **9152** unchanged |
| S3 | sizeof **754** / ceiling **768** |
| **S1+S2+S3 outer** | **9920** = 8384+448+320+768 |

Packed: `8384+421+306+754=9865`；align8 **9872** ≤ **9920**。dual/triple-bound **forbidden**。Stage5 no D3 bind until S12。

#### 18.14.14 Private API（contract names only）

| API | Rule |
| --- | --- |
| `begin_profiled` | D2-only |
| `begin_profiled_d3s1` | modes 1..20 only |
| `begin_profiled_d3s2` | modes 21..26 only |
| `begin_profiled_d3s3` | mode ∈ 27..30; context ≤**768**; pairwise disjoint; not dual-bound; Port0 INVALID on violation |
| `reopen_zero_prefix_iter` | same-txn sequential reopen |
| `d3s3_drive` / on_row / H2 | PASS_INTERNAL + B0–B11 mapping; SCAN on H2 |
| Stage5 until S12 | no `begin_profiled_d3s3` |
| null skip / mode 0 | **禁止** |

#### 18.14.15 Sibling oracle architecture（append-only d3s3; no JSON in S3a）

Same evolution rules as prior: retain d3s1+d3s2 prefix; format `…-d3s3`; mutation 0; one mode per session; independent generator; production bridge。

**REP1（§18.14.19; Proposed）:** formal sibling oracle / portable Core **shipped reference** bridge that claim **exact Port transcript** equality must implement **Reference Execution Profile v1**（**REP1-L2**）including closed micro-units **W / G / WG**（BIND-WG; Mode30 RR pure W）。**REP1-L1** alone is **not** sufficient to claim REP1. See ADR-0015。A pre-acceptance draft authority that packed BIND with **GET=0** while claiming full §18.14.9 reverse/orphan proofs is **withdrawn**（non-constructible under 754 / no full-ID set）and must not be treated as SHA-pinned Accepted truth; regenerate authority after Normative WG text。

**Anti-false-pass additions（minimum）:**

1. KEY_DIGEST reverse / owner-body key rebuild harness **must fail**
2. DELIVERY total_length-less payload locate still greens via SCAN
3. Mode30 REPLY uses `body_blob_key_digest` not `payload_blob_key_digest`
4. Mode30 #14 binding RR↔manifest↔DELIVERY raw/tx; cross-delivery shared digest fail
5. Mode30 #15 non-RECEIPT empty blob mandatory; RECEIPT total_length 0..128
6. Mode30 #16 RECEIPT stage/length/digest/bytes; stream-compare via receipt_evidence_bytes pin
7. Shared REPLY manifest with 2 RR kinds OK; 0 RR orphan
8. Mode30 BIND_MANIFEST is RR-band SCAN（not RR key rebuild from digest）; harness that invents RR key from digest **must fail**
9. Untyped orphan chunk (manifest ABSENT) fails in every mode session
10. Mode30 companion matrix: RECEIPT missing EVIDENCE_CELL/RESULT/DELIVERY → CORRUPT; CANCEL missing CANCEL_STATE → CORRUPT; state5 HISTORICAL semantic 0
11. SCAN match_count: single arm only; second hit → CORRUPT
12. expected_semantic_digest pinned at PREFIX carrier get BEFORE companions; finalize compares pin not overwritten workspace
13. expected_owner_pvd pinned at SCAN; Mode30 proved on semantic DELIVERY get; Mode27/28/29 post-SCAN ≤1 owner re-get
14. Mode28: view_a/view_b pin; semantic PREFIX re-get + re-SCAN both views
15. Mode29 APPLICATION_FIRST always RESULT setup; terminal-only RESULT harness must fail
16. Four-session product; no one-baseline-all-four
17. Zero-length TX vs INGRESS empty; historical ABSENT; stream length/digest fails

#### 18.14.16 Mutation / D4 / constructibility

| Concern | Owner |
| --- | --- |
| Snapshot SCAN/stream/0·1/orphan | **S3** |
| Witness group create/erase history | **D4** |
| Capacity bytes | **S8** |
| CLEANUP decreasing including BLOB | **S11** + **D4** |

Constructible fixtures: D1-legal only; no speculative complete-key-from-digest vectors。R19–R24 independent generator-time D1-legality gate enforces this on every suffix row（§18.14.19.12 item 7 / §18.14.16）。

#### 18.14.17 Explicit exclusions

| Exclusion | Owner |
| --- | --- |
| KEY_DIGEST reverse / digest→exact_get rebuild（owner or RR） | **forbidden** |
| DELIVERY.payload as REPLY referrer | **forbidden** |
| Mode30 semantic with RR+DELIVERY only（no RESULT/CANCEL/EVIDENCE matrix） | **forbidden** |
| Mode30 BIND inventing RR complete key from `body_blob_key_digest` | **forbidden**（RR-band SCAN only） |
| Mode28 semantic without view_a/view_b pin + re-SCAN | **forbidden** |
| Mode29 APPLICATION_FIRST without RESULT_CACHE setup get | **forbidden**（#10） |
| match_count double-increment / dual match arms | **forbidden**（#P0-A single arm） |
| Semantic finalize vs workspace body after overwrite without pin | **forbidden**（#12 pin） |
| Owner PVD without expected_owner_pvd pin / budgeted proof | **forbidden**（#13） |
| Mode30 RR/manifest/DELIVERY raw or tx mismatch / cross-delivery digest alias | **forbidden**（#14） |
| non-RECEIPT REPLY blob with total_length≠0 or chunks present | **forbidden**（#15） |
| RECEIPT without RESULT↔cell↔BLOB stage/length/digest/bytes match | **forbidden**（#16） |
| Mode-filter orphan chunk without manifest body kinds | **forbidden**（use untyped rule） |
| Radio fragmentation claim | **forbidden** |
| S1/S2 re-claim; S4–S11/D4 scopes | as prior |
| public ABI / wire / D1 codec change | **not this freeze** |

#### 18.14.18 Completion boundary / non-claims（S3a）

| Claim | After this freeze |
| --- | --- |
| D3-S0 / S1a / S2a historical freezes | **preserved** |
| D3-S1 implementation complete | **yes**（prior） |
| D3-S3a Normative freeze（KEY_DIGEST SCAN + pins + Mode30 #14/#15/#16 + Mode28 re-SCAN + untyped orphan） | **yes**（本節） |
| D3-S2 / D3-S3 implementation complete | **no** |
| Crossrow d3s3 JSON | **no** |
| D3 / Stage5 / public Runtime / D4 / ESP / USB / LoRa | **no** |
| Private APIs exist on branch | **no claim** |

S3a を後から implementation complete へ書き換えてはならない。S0/S1a/S2a historical text は **preserve**。

#### 18.14.19 D3-S3 Reference Execution Profile v1（REP1; Proposed oracle candidate）

**Status:** **Proposed oracle candidate**（deterministic generator + candidate JSON self-check済み; production implementation / bridge / Accepted **not claimed**）。  
**Decision companion:** [ADR-0015](adr/0015-d3s3-reference-execution-profile-v1.md)。  
**Does not amend** §18.14.1–§18.14.18 semantic freezes except where this section and §18.14.9 jointly specify BIND **WG** Port packing; those remain portable **REP1-L1** meaning for findings. REP1-v1 is the deterministic **transcript** profile for the **shipped** portable Core reference implementation and formal sibling oracle/bridge（**REP1-L2**）。  
Shipped reference Core **must** implement the phase/substate/mask numeric values of this section even if current production private S3 uses different internal integers（Proposed; implementation change is required for REP1-L2）。

**Withdrawn pre-acceptance draft:** any uncommitted / non-Accepted authority JSON (including historical full SHA `0658cbe092313e19dbb4498dcd5a786517651cb984ddfc7f97f2a47b372cf36f` and related 228/84 drafts) that required **BIND GET=0** while claiming full reverse-owner / untyped-orphan L1 for arbitrary rows is **non-constructible** under fixed **754** / no full-ID set and is **withdrawn as a pre-acceptance draft**. Do **not** treat that SHA as Normative or Accepted. The generator candidate now regenerates the **same authority path** `spec/vectors/domain-scan-crossrow-v1.json` under this WG text; its current **R27-Sol Proposed** candidate is **280 = frozen D3-S2 prefix 144 (exact invariant) + D3-S3 suffix 136**, where suffix **136 = `rep1_l2` production 135 + `formal_precheck` 1**, content SHA `93edadc3b262fb1cb5717d0895769e686055c2ee7bef7fbda6e8ffe07c9e572c`, full-file raw SHA `1506f43229b27254e70cc8fc54faa039711007924d015c451a3fd23114d59fe2` (**vector body changed vs R26/R27-base**: +7 Mode27 EF cross-row CORRUPT — R27 is oracle/spec gate repair: TRANSACTION_STATE reachable public snapshot matrix re-extracted from docs/12+docs/13 reducers; Mode27 EventFact lifecycle permanent 3×4 spool enumeration; product fixture bytes unchanged). Historical R25 SHAs `bb56954f…` / `997f64e5…`, R24 SHAs `12d1729e…` / `1b210e29…`, and R23 SHAs `bdaed45d…` / `3aeb1b02…` remain **superseded** as incomplete authority. Formal precheck ID `D3S3_M27_DUPLICATE_DIGEST_MATCH_CORRUPT` / `precheck_error=DUPLICATE_COMPLETE_KEY` is validator-only（no production API; no synthesized runtime status/session/checkpoint/result; zero Port because bridge does not call production）. Exact call/Port grammar is **`rep1_l2` only**. Independent generator-time D1-legality on every suffix row is **no production C as oracle** and **no D1 deferral**. **Honest chronology:** R21 claimed complete independent Normative D1 and was **Sol high NO-GO**. R22 repaired several R21 holes with typed differential pos74/neg60 and was **Sol high NO-GO**. **R23** repaired R22 residuals and was **Sol high NO-GO** again — **R23 did not complete D1** (TRANSACTION_STATE enum-only false-green; CELL/CANCEL/DELIVERY empty-body `struct.error`; CLI `check []` AttributeError). **R24** partially repaired R23 and was **Sol high NO-GO P1=2 P2=1**. **R25** repaired R24 residuals and was **Sol high NO-GO**. **R26** repaired R25 residuals but Root QA found residual STATE matrix NO-GO holes (FAILED+22 false-red; EXPIRED/UNKNOWN+20 false-red; WAITING accepting terminal-only reasons; SATISFIED+65 wrong outcome; CANCEL_AFTER_EFFECT(83) terminal; AWAITING missing 128/129; Mode27 spool cross-pair incomplete enumeration). **R27** closes those holes without weakening R16–R26 by re-extracting the full family×state×outcome×reason×deadline×evidence×dependent product from docs/12+docs/13（SATISFIED={64}; EXPIRED={65,66,20}; UNKNOWN={69,20} (129 AWAITING-only); CANCELLED={82}; FAILED={22,70,80,128}; AWAITING={0,68,83,86,128,129}; WAITING={11,85,128,130,132}; STATE legal positives **28**; Mode27 lifecycle 3×4=12 permanent cells）. COMMIT_UNKNOWN five fence paths + boundary **4380** + secondary differential typed 74/60, body_decode 306/0/306, body_roundtrip 132 retained. Production typed diagnostic remains cross-check only. **R27-Sol:** Mode27 D3-S3 exact cross-row (family/avd/pvd/rev/state×park); generate full-document adopt (suffix rows={} / vector_count=true → exit2); check closed nested known-integer schema (faults_expected_used bool/u32 overflow → exit2). **Production / bridge are not yet following this R27-Sol oracle gate.** Production / bridge / Sol re-review remain incomplete; **Accepted / GO forbidden**. No historical giant JSON duplicate is required in-tree.

##### 18.14.19.0 Conformance layers

| Layer | Name | What it proves | Who must meet it |
| --- | --- | --- | --- |
| **REP1-L1** | Semantic conformance | §18.14.1–.14/.16–.17 finding correctness | Any portable Core that claims S3 semantics |
| **REP1-L2** | REP1 transcript conformance | Same formal inputs + call schedule + NATURAL fault schedule → identical ordered Port events + per-call checkpoints | **Shipped** portable Core **reference** in the public tree + formal oracle/bridge claiming “REP1” / “exact Port equality” |

Claiming **REP1** requires **REP1-L1 and REP1-L2**. **REP1-L2 acceptance** uses only the **shipped reference Core** artifact; a private rebuild is **not** a substitute.  
A production-drive→many-micro-steps **mapping table** is **non-REP1 diagnostics only** and never substitutes for REP1-L2 equality.

##### 18.14.19.1 Formal inputs / non-inputs

**Inputs（closed）:**

1. `mode ∈ {27,28,29,30}`
2. Ordered fixture `rows[]` of complete-key/value pairs. Walk order is **D2 complete-key lexicographic ascending**. Duplicate complete keys are a **D2 lex / same-key residual failure** and make the vector **ill-formed for REP1-v1**（not multiset-stable ordering）。
3. Formal call schedule（§18.14.19.2）with `row_budget` column。
4. NATURAL fault schedule **`faults`**: JSON **array** of length **0 or 1**（§18.14.19.6; R14–R18 binding; **`rep1_l2` only**）。Length 1 ⇒ exactly one natural Port event in `port_trace` with exact `op`/`on_call`/`status` match and `faults_expected_used=1`。Length 0 ⇒ no natural Port event and `faults_expected_used=0`。Falsy non-array values are ill-formed（not empty）。
5. Candidate binding object used by profiled begin（same closed binding as existing oracle）。
6. `expected.port_trace`: JSON **array** only（R16+）。Empty array is legal for the closed **`formal_precheck`** vector（R18: pre-generation validator-only; bridge does not call production; `faults=[]` and `faults_expected_used=0`; no synthesized runtime status/session/checkpoint/result）。Falsy non-array (`{}` / `""`) is ill-formed。Exact call/Port grammar does **not** apply to `formal_precheck`。

**Representability gate（ill-formed otherwise）:** let `N=|rows|`。`0 ≤ N ≤ UINT32_MAX-1` so every ordinary `row_budget=N+1` is an exact non-zero `u32`。The complete derived formal schedule must also satisfy: formal call count `≤UINT32_MAX`; total Port event count `≤UINT32_MAX`; every per-op `on_call` total, `event_start` / `event_end` / `trace_count`, reopen counter, and other `u32` checkpoint counter `≤UINT32_MAX`; every `u64` checkpoint total is representable without wrap。These are pre-generation validity checks, not runtime truncation rules。A vector requiring any overflow, modulo conversion, or `trace_overflow=1` is not a REP1-v1 input。

**Profile-exact gate（after successful begin + successful true-exhaustion BASELINE W）:**

- `profile_exact_active = 1`
- `profile_mismatch = 0`
- `future_profile_candidate = 0`
- formal product vectors must be able to reach context phase `COMPLETE`（13）or `FAILED`（14）under this schedule
- evaluator-off / mismatch / future-only hold shapes are **outside** REP1-v1 formal product

**Non-inputs:**

- Absolute Port handle pointer values
- Wall-clock / host scheduling
- Implementation-private workspace addresses / C padding
- Provider-internal buffer sizes beyond caller-visible capacities recorded on Port events

**Caller capacities（normative derived Port outputs; N/A = 0）:**

| Op | Capacity fields allowed non-zero |
| --- | --- |
| `get` | `value_capacity` only（caller value descriptor capacity） |
| `iter_next` | `key_capacity` and `value_capacity` only |
| all other ops | every capacity field is exact **0** |

Provider-internal sizes are non-input.

**Logical handles:**

| Label | Meaning |
| --- | --- |
| `H1` | caller-owned open storage handle at profiled begin; retained unless finalize fences it |
| `T1` | sole `READ_ONLY` txn from successful `begin(H1, READ_ONLY)` |
| `I1`…`Ik` | successive live iterators; successful `iter_open` allocates next `Ik`; `iter_close` retires current live `Ik` |

Bridge maps spy pointer → label; JSON never stores raw pointers.

**Successful begin Port sequence（fixed; guarantees begin success for formal product）:**

```text
begin(H1, READ_ONLY) → T1
17× get(T1, profile_key_i)   # family-1..4 catalog order
iter_open(T1, zero-prefix) → I1
```

Successful begin control tuple: §18.14.19.8 **B0**. BASELINE W consumes `I1`（no reopen before first BASELINE advance）。

##### 18.14.19.2 Formal call column

```text
begin_profiled_d3s3(mode)  → Runtime returned_status
d3s3_drive(row_budget)*    → until first phase ∈ {COMPLETE=13, FAILED=14}
finalize()                 → Runtime returned_status; Port cleanup once
```

**Closed rules:**

1. Exactly one `begin_profiled_d3s3`.
2. After successful begin: one or more `d3s3_drive` until first terminal phase 13 or 14.
3. Exactly one `finalize` after that terminal（no ordinary `abort`）。
4. No drive after first terminal phase.
5. No invented walk after a failing Port event in the same drive.
6. Fault schedule length 0 or 1; if 1, that fault is used **exactly once** when the named `(op,on_call)` is reached（§18.14.19.6）。

**`row_budget`:** let `N = |rows|`。

| Vector class | Budgets |
| --- | --- |
| Ordinary | every **W** and every **WG** uses **`N+1`**（all OK rows + terminal `NOT_FOUND`）; **G** uses **`row_budget=0`** |
| B5-only formal（explicit kind） | **BASELINE W only:** first drive `row_budget=N`（midwalk stop）; resume drive `row_budget=N+1` to true NOT_FOUND. **B5 is forbidden on every non-BASELINE W and on every WG/G.** |

**Per-call event window:** `port.event_start` / `port.event_end` are **0-based half-open** `[start,end)` into `port_trace[]`。`event_end == event_start` ⇒ zero Port events on that call. After the call, `port.trace_count == event_end`。

**`returned_status`（checkpoint top-level; Runtime status symbol string; closed enum）:**

| Symbol | Meaning in REP1-v1 formal product |
| --- | --- |
| `NINLIL_OK` | successful begin / every successful drive（including the BIND_CHUNK drive entering `COMPLETE=13`）/ successful finalize with sticky=0 complete path |
| `NINLIL_E_STORAGE_CORRUPT` | sticky semantic finding or mapped shape/port corrupt terminal |
| `NINLIL_E_STORAGE` | sticky Port IO-class failure（maps from Storage `IO_ERROR` / natural fault IO） |
| `NINLIL_E_STORAGE_COMMIT_UNKNOWN` | sticky/mapped from Storage `COMMIT_UNKNOWN` |
| `NINLIL_E_CAPACITY_EXHAUSTED` | sticky/mapped from Storage `NO_SPACE` |
| `NINLIL_E_WOULD_BLOCK` | sticky/mapped from Storage `BUSY` |
| `NINLIL_E_UNSUPPORTED` | sticky/mapped from Storage `UNSUPPORTED_SCHEMA` |
| `NINLIL_E_INVALID_STATE` | illegal call after terminal / incomplete machine misuse（not ordinary product success path） |
| `NINLIL_E_INVALID_ARGUMENT` | begin/drive/finalize prevalidation failure（outside ordinary formal product success paths） |

No other `returned_status` string is legal in REP1-v1 formal checkpoints. Storage Port `storage_status` uses the Storage names of §18.14.19.6 / §18.14.19.7, not Runtime names.

##### 18.14.19.3 Micro-step discipline（one drive = one unit; closed **W / G / WG**）

Unit kind is a **Normative schedule classification** used to derive the formal call column and Port windows. It is **not** a required string field in the closed checkpoint JSON schema of §18.14.19.9（do not add a checkpoint `unit` key）。

| Kind | Code | Contents of one `d3s3_drive` |
| --- | :---: | --- |
| Walk | **W** | (1) **Reopen exact**（§ below）。(2) Zero-prefix walk via `iter_next` until true EXHAUSTED（terminal `NOT_FOUND`）or B5 midwalk stop on BASELINE only. (3) Stream H2 / on_exhausted only on true EXHAUSTED. (4) **No** `exact_get` in the same drive（OWNER/CHUNKS/SEMANTIC matrices are separate **G** units; Mode30 RR-band is pure **W**）。BASELINE uses begin `I1` with no reopen. |
| Get | **G** | Closed `exact_get` burst for the **entry** phase only（**SELECT_SETUP** / OWNER / CHUNKS / SEM_*）。No `advance` / no `iter_next`。May set `NEED_REOPEN` for a **later** W/WG; does not reopen itself. `row_budget=0`。 |
| BIND walk+get | **WG** | **BIND only**（Modes27–29 BIND_MAN; Modes27–30 BIND_CHUNK）。**Not** SELECT。Exact Port event grammar of one successful WG drive: |

```text
[ if NEED_REOPEN=1: iter_close(current Ik) exactly once; iter_open → next Ik exactly once ]
( iter_next → storage_status=OK
    , if row is unit-eligible: exact_get(request_key) → then fully consume result
  )*
iter_next → storage_status=NOT_FOUND
```

**Reopen / iterator liveness exact（every formal W/WG entry, including BASELINE）:**

Before **any** Port event of a W/WG drive:

| Entry flags | `iter_live` | Required Port prefix / outcome |
| --- | ---: | --- |
| `NEED_REOPEN=0` | **1** | emit **neither** `iter_close` nor `iter_open` |
| `NEED_REOPEN=0` | **0** | **`INVALID_STATE` before any Port event** |
| `NEED_REOPEN=1` | **1** | emit **exactly one** void `iter_close(current Ik)`, then **exactly one** `iter_open` → next `Ik`; then clear `NEED_REOPEN` before first `iter_next` |
| `NEED_REOPEN=1` | **0** | **`INVALID_STATE` before any Port event**（do not partially close/open） |

BASELINE uses begin `I1` with `NEED_REOPEN=0` and must enter with `iter_live=1`。Optional close-before-open grammar is **forbidden**（always both ops or neither per the table）。

**G entries（REP1 exact）:** before any Port event require
`session.state=EXHAUSTED && txn_live=1 && iter_live=1` and the sole iterator is
the bound D2-S4 iterator under §15.11。Any other state/liveness combination ⇒
**`INVALID_STATE` before any Port event**。A product G unit never enters from
`OPEN`, never closes/reopens, and never treats `iter_live=0` as legal。

Normative WG rules（detail tables in §18.14.9 — this subsection only packs Port units）:

1. **Eligibility / GET request key / post-get compares:** exact predicates and phase-local pin maps in **§18.14.9.2**（BIND_MAN）and **§18.14.9.4**（BIND_CHUNK）。Non-eligible OK rows: visit/lex only; **GET 0**。
2. **Port-only:** eligibility, pin fill, rebuild request key, and proof compares are decided from **current typed row + phase-local 754 pins + get response only**。**Forbidden:** fixture `idx`, offline full `rows[]`, or full-ID sets as proof inputs。
3. **Copy-before-get / visit commit:** **§18.14.9.5** — under `PASS_INTERNAL`, public `ok_row_count` / `current_domain_key_count` / family14 / profile diagnostics stay **frozen**; visit-before-GET commits **only** pass-local `has_previous` + `previous_key`/`length`。After get, never read pre-get typed/borrowed value pointers。
4. **Internal hook exception:** private H1/BIND path may call `exact_get` under WG; **public/user callback reentrancy into scanner APIs is forbidden**。
5. **D2-S4 shape:** get overwrites **value** only; iterator position and current key descriptor remain; sole iterator stays live until true NOT_FOUND or fault。GET output key fields empty。
6. **Natural GET fault:** the failing get is the **last operational Port event** of that drive; **no further `iter_next`**, no cleanup in-drive; cleanup only finalize（§18.14.19.11）。Lex visit commit of the preceding OK `iter_next` remains; public counters unchanged。
7. **Mode30** BIND_MAN outer and RR-band are **not** WG（pure **W** only; frontier/latch **§18.14.9.3**）。
8. **SELECT packing（design B; P0）:** phase **2** `semantic_pass=0` is **pure W** for all modes — zero-prefix walk to true `NOT_FOUND`, **GET count = 0** in that drive。On the first mode-eligible carrier, copy only the **phase-local pin fields** needed for later units（complete key / digests / raw / kind bits that fit in the 754-byte context）and **continue the walk** to true exhaustion。**Forbidden** in SELECT W: any `exact_get`; offline fixture `idx` / full `rows[]` / full-ID set as lifecycle authority。
9. **SELECT_SETUP G（phase 2, `semantic_pass=6`）:** after a successful SELECT W that installed a carrier requiring companion proof, the **next** unit is pure **G** on the **same phase=2** with **`semantic_pass=6`**（named `SELECT_SETUP`）。Entry requires `EXHAUSTED && txn_live=1 && iter_live=1`; `row_budget=0`; no reopen in this G。
   - **Mode27:** exact GET order **TRANSACTION_STATE** then, if and only if the pinned carrier is EventFact, **EVENT_SPOOL**。After each successful GET, validate **returned value** as typed CURRENT（envelope / version / family / subtype / flags）before decode; copy any fields needed for the next GET **into context pins before** the next GET overwrites the single 4096-byte workspace。
   - **Mode29 APPLICATION_FIRST only:** exact GET **RESULT_CACHE** once; same returned-value typed CURRENT gate; then lifecycle from returned RC + pins。
   - **No SELECT_SETUP unit**（Port 0 extra drive forbidden）when the SELECT W carrier is Mode29 **CANCEL_FIRST**, or Mode **28**, or Mode **30**, or when SELECT W empties with no carrier: lifecycle / next phase is decided at SELECT W true exhaustion from **typed carrier pins only**。
10. **After successful SELECT_SETUP G:** set `NEED_REOPEN` exactly when the next product unit is a **W** or **WG**; clear `semantic_pass` to the destination substate（usually 0）and advance `phase` to the mode-legal next（FOCUS / complete-carrier paths per existing exits）。Natural GET fault or ABSENT/`NOT_FOUND` on SELECT_SETUP: the failing GET is the **last** operational Port event of that drive; failure-point checkpoint keeps **entry** `phase=2` / `semantic_pass=6` under FAILED/phase14 rules。
11. **Returned-value typed CURRENT gate（all product GETs）:** for every product-path `exact_get` that is expected PRESENT（SELECT_SETUP companions, OWNER, CHUNKS, SEMANTIC companions, BIND_MAN owner reverse, BIND_CHUNK man presence）, after `storage_status=OK` and **before** body-field compares, require the **returned complete value**（not the request key alone）to be NLR1 domain **family=6**, **record_version=1**, outer payload length ≥96 with exact total framing, **domain_format=1**, fixed domain header **108** bytes before body, inner body_length exact, **CRC32C trailer valid**, subtype equal to the Normative expected subtype for that get, and **exact flags**（non-BLOB **0**; BLOB MANIFEST **1**; BLOB CHUNK **2** unless a more specific Normative value applies）。Then apply identity/raw → referrer → PVD/value-digest compares in the Normative order for that unit on **returned bytes only**。Request-key subtype checks alone are **not** sufficient。Offline `rows[]` / fixture omniscience must not adjudicate post-GET meaning。G entry preflight（EXHAUSTED+txn1+iter1）is **executable before any Port event** on every G unit including Mode30 PREFIX。

**Session state rule:** after every successful true-exhaustion **W** or **WG**, `session.state = EXHAUSTED`. Every subsequent successful **G** leaves `session.state = EXHAUSTED`. The **only** successful formal midwalk with `session.state = OPEN` is B5 BASELINE stop（§18.14.19.8 B5）。

**Port failure:** failing Port event is the last operational event of that drive. No cleanup inside the failing drive. Cleanup only in finalize（§18.14.19.11）。

**Rejected packing（withdrawn）:** “BIND W with GET=0 + offline fixture omniscience” as REP1-L2 evidence。
**Rejected packing（P0）:** “SELECT W with mid-walk setup `exact_get` in the same drive”（iter_next→GET→iter_next）— violates pure **W** and is **not** BIND **WG**。

##### 18.14.19.4 Control vocabulary（numeric; closed）

**`phase` enum（u8; exact）:**

| Value | Name |
| ---: | --- |
| 0 | `IDLE` |
| 1 | `BASELINE` |
| 2 | `SELECT` |
| 3 | `FOCUS_SCAN` |
| 4 | `OWNER` |
| 5 | `CHUNKS` |
| 6 | `FOCUS_SCAN_B` |
| 7 | `OWNER_B` |
| 8 | `CHUNKS_B` |
| 9 | `SEM_PREFIX` |
| 10 | `SEM_CHUNK` |
| 11 | `BIND_MAN` |
| 12 | `BIND_CHUNK` |
| 13 | `COMPLETE` |
| 14 | `FAILED` |

Values outside 0..14 are invalid for REP1-v1.

**`pass_kind`（u8; exact）:** `BASELINE=0`, `INTERNAL=1`. Values ≥2 invalid.

**`focus_sub`（u8; exact）:**

| Mode | Rule |
| ---: | --- |
| 27, 29, 30 | always `0` |
| 28 | `0` = view-A first-focus not yet completed; `1` = view-A first-focus completed（remains `1` through B first-focus, semantic, and later phases of that carrier） |

**`semantic_pass`（u8; global closed）:**

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | `NONE` | no pending semantic micro-step |
| 1 | `M28_RESCAN_A_W_PENDING` | next unit is Mode28 RESCAN_A **W** |
| 2 | `M28_VIEW_A_CHUNKS_G_PENDING` | next unit is Mode28 VIEW_A_CHUNKS **G** |
| 3 | `M28_RESCAN_B_W_PENDING` | next unit is Mode28 RESCAN_B **W** |
| 4 | `M28_VIEW_B_CHUNKS_G_PENDING` | next unit is Mode28 VIEW_B_CHUNKS **G** |
| 5 | `M30_BIND_RR_W_PENDING` | next unit is Mode30 BIND RR-band **W** |
| 6 | `SELECT_SETUP_G_PENDING` | next unit is SELECT_SETUP **G**（Modes27 / Mode29 APPLICATION_FIRST only） |
| 7..255 | invalid | ill-formed checkpoint |

**`focus_mode` legality after successful begin:** `focus_mode ∈ {27,28,29,30}` and equals the bound session mode。Any other value ⇒ **`INVALID_STATE` before any Port event**。

**Non-terminal drive-entry `pass_kind` legality（exact）:**

| `phase` | Required `pass_kind` | Notes |
| ---: | ---: | --- |
| 0 IDLE | — | pre-begin only; **no** product drive |
| 1 BASELINE | **0** | BASELINE |
| 2..12 | **1** | INTERNAL |
| 13 COMPLETE | — | terminal checkpoint only; **no** product drive |
| 14 FAILED | — | terminal failure checkpoint only; **no** product drive |

For a non-terminal drive entry（phase 1..12）, wrong `pass_kind` ⇒
**`INVALID_STATE` before any Port event**。Phase 13/14 reject every later drive
before Port regardless of their captured terminal fields; this drive rejection
does **not** make a reachable terminal checkpoint illegal。

**Terminal checkpoint legality（exact; no next unit）:**

| terminal phase | mode(s) | `pass_kind` | legal `semantic_pass` | source |
| ---: | --- | ---: | --- | --- |
| 13 COMPLETE | 27–30 | **1** | **0** | successful BIND_CHUNK WG exhaustion |
| 14 FAILED | 27,29 | **0** | **0** | BASELINE failure capture |
| 14 FAILED | 27,29 | **1** | **0,6** | INTERNAL failure capture（incl. SELECT_SETUP entry sem=6） |
| 14 FAILED | 28 | **0** | **0** | BASELINE failure capture |
| 14 FAILED | 28 | **1** | **0,1,2,3,4** | exact failing INTERNAL entry substate |
| 14 FAILED | 30 | **0** | **0** | BASELINE failure capture |
| 14 FAILED | 30 | **1** | **0,5** | exact failing INTERNAL entry substate |

FAILED never normalizes `pass_kind` or `semantic_pass`: §18.14.19.10 captures
the values immediately before the failure and changes only `phase→14` where
specified。A phase-14 tuple absent from this terminal table is invalid as a
checkpoint; there is still no legal drive from phase 14。

**Closed allowed non-terminal next-unit matrix:** for phase **1..12**, the triple
`(phase, focus_mode, semantic_pass)` maps to **exactly one** unit/subschedule via
the closed matrix below（each matrix row is a unique triple; no overlapping mode
sets on the same phase+sem）。Any non-terminal tuple **absent** from the matrix is
**`INVALID_STATE` before any Port event** on that drive（session/context unchanged）。
Phase 13/14 use the terminal checkpoint table above and have no next unit。
Ambiguous “FOCUS path / W+ / as applicable / see rows” language is **forbidden**。

Legend: unit codes **W** / **G** / **WG**; “—” = no next formal drive unit（terminal）。Unless listed otherwise, `semantic_pass` must be **0**。

| `phase` | mode(s) | `semantic_pass` | unit | subschedule |
| ---: | --- | ---: | :---: | --- |
| 1 BASELINE | 27–30 | 0 | **W** | BASELINE（B5 only on this phase） |
| 2 SELECT | 27–30 | 0 | **W** | pure SELECT walk（GET 0; pin first eligible; true exhaust） |
| 2 SELECT | **27,29** | **6** | **G** | SELECT_SETUP companion exact_get burst（Mode29: APPLICATION_FIRST only） |
| 3 FOCUS_SCAN | 27,29,30 | 0 | **W** | first-focus SCAN |
| 3 FOCUS_SCAN | 28 | 0 | **W** | first-focus view-A SCAN |
| 3 FOCUS_SCAN | 28 | 1 | **W** | semantic RESCAN_A |
| 4 OWNER | **27,29** | 0 | **G** | owner PVD |
| 4 OWNER | **28** | 0 | **G** | owner PVD view-A path |
| 5 CHUNKS | 27–30 | 0 | **G** | known-index chunk stream |
| 6 FOCUS_SCAN_B | 28 | 0 | **W** | first-focus view-B SCAN |
| 6 FOCUS_SCAN_B | 28 | 3 | **W** | semantic RESCAN_B |
| 7 OWNER_B | 28 | 0 | **G** | owner PVD view-B |
| 8 CHUNKS_B | 28 | 0 | **G** | view-B chunks |
| 9 SEM_PREFIX | 28,30 | 0 | **G** | semantic PREFIX companions |
| 10 SEM_CHUNK | 30 | 0 | **G** | semantic chunk/receipt stream |
| 10 SEM_CHUNK | 28 | 2 | **G** | VIEW_A_CHUNKS |
| 10 SEM_CHUNK | 28 | 4 | **G** | VIEW_B_CHUNKS |
| 11 BIND_MAN | 27–29 | 0 | **WG** | owner-reverse BIND_MAN |
| 11 BIND_MAN | 30 | 0 | **W** | outer REPLY select（§18.14.9.3; after BIND-entry init once） |
| 11 BIND_MAN | 30 | 5 | **W** | RR-band boolean latch（§18.14.9.3） |
| 12 BIND_CHUNK | 27–30 | 0 | **WG** | untyped orphan / man presence |

**Explicit INVALID examples（non-exhaustive; non-terminal matrix and terminal table are authoritative）:** mode30 × phase4/6/7/8; mode27/29 × phase6/7/8; mode27–30 × phase3 with `semantic_pass∈{1,3}` except mode28; mode28 × phase10 with `semantic_pass=0`; mode30 × phase11 with `semantic_pass∉{0,5}`; mode28/30 × phase2 with `semantic_pass=6`; mode27/29 × phase2 with `semantic_pass∉{0,6}`; any non-terminal phase with `semantic_pass` not listed for that phase/mode; COMPLETE with nonzero `semantic_pass`; FAILED tuple absent from the terminal table; non-terminal `pass_kind` mismatch; `focus_mode∉{27..30}` after begin。

Mode28 ordinary first-focus uses phase3/6 with **sem=0**; semantic rescans use the **same phase numbers** with **sem=1/3** so the triple alone distinguishes unit without prose branches。

**Flags bits（existing §18.14.12; exact）:**

| Bit | Name | Value |
| --- | --- | ---: |
| 0 | `BASELINE_DONE` | `0x01` |
| 1 | `FOCUS_LIVE` | `0x02` |
| 2 | `BIND_ACTIVE` | `0x04` |
| 3 | `COMPLETE_READY` | `0x08` |
| 4 | `NEED_REOPEN` | `0x10` |
| 5 | `CARRIER_INSTALLED` | `0x20` |
| 6 | `MATCH_INSTALLED` | `0x40` |
| 7 | `MATCH_DUPLICATE` | `0x80` |

**Successful formal-call checkpoint flag normal forms（only these appear on OK exits）:**

| Name | Value | Bits |
| --- | ---: | --- |
| `F0` | `0x00` | none |
| `F_CARRIER_G` | `0x03` | `BASELINE_DONE\|FOCUS_LIVE` |
| `F_COMPLETE` | `0x09` | `BASELINE_DONE\|COMPLETE_READY` |
| `F_SELECT` | `0x11` | `BASELINE_DONE\|NEED_REOPEN` |
| `F_FOCUS_W` | `0x13` | `BASELINE_DONE\|FOCUS_LIVE\|NEED_REOPEN` |
| `F_BIND_REOPEN` | `0x15` | `BASELINE_DONE\|BIND_ACTIVE\|NEED_REOPEN`（docs label only; wire/value unchanged） |
| `F_FOCUS_G` | `0x43` | `BASELINE_DONE\|FOCUS_LIVE\|MATCH_INSTALLED` |

Transient `CARRIER_INSTALLED` / `MATCH_DUPLICATE` **must not** remain set on a successful formal-call checkpoint. On failure, flags/masks/substates equal the values **immediately before** the failing event（failure-point capture）。

**Count mask bits:** man=`0x01`, chunks=`0x02`, semantic=`0x04`。

| Situation | `count_complete_mask` |
| --- | ---: |
| New carrier install | reset to `0` |
| Mode27/29 normal focus complete **or** NONE zero-dig completed | `0x03` |
| Mode28 after **both** first-focus A and B completed | `0x03`（A complete with B still pending ⇒ `0`） |
| Mode28 after semantic finalize | `0x07` |
| Mode30 after focus+semantic finalize **or** HIST/NONE completed unit | `0x07` |
| Zero carriers（vacuous） | `0` is legal through SELECT-empty → BIND |
| BIND phases | do **not** alter count mask |

**Binding mask bits:** man=`0x08`, chunk=`0x10`。

| Situation | `binding_complete_mask` |
| --- | ---: |
| Before any BIND unit（W/WG）completes | `0` |
| After successful BIND_MAN exhaustion **WG**（mode27–29）or Mode30 empty-outer **W** completion | `0x08` |
| After successful BIND_CHUNK **WG** | `0x18` |

##### 18.14.19.5 Mode28 view totals pin（754 layout unchanged）

Context layout §18.14.12 **unchanged**（754/768）。When `focus_mode=28`, `focus_id16[16]` is **aux totals**（not Mode30 tx）:

| Bytes | Field | Encoding |
| ---: | --- | --- |
| `[0..7]` | `view_a_total_length` | **u64 big-endian** |
| `[8..15]` | `view_b_total_length` | **u64 big-endian** |

Rules:

1. Full **u64** range is stored **lossless** at the pin step; the pin itself has no truncation or conversion。This storage rule does not bypass the later semantic checked-u32 gate in rule 6。
2. Zero view dig ⇒ pin that view’s total as **0** at SELECT install of the carrier（before SEM_PREFIX）。
3. Non-zero view dig ⇒ pin the manifest `total_length` as **u64be** at successful first-focus match install for that view（FOCUS_SCAN / FOCUS_SCAN_B install）。
4. PREFIX G and every SEMANTIC_VIEW_CHUNKS G stream using **only** these pins（never a later re-read of a man body total after workspace overwrite）。
5. Modes 27/29/30: `focus_id16` retains §18.14.12 meaning（Mode30: RR.transaction_id; Mode27/29: 0 unless already specified）。
6. The pins remain lossless `u64`, but the Mode28 semantic preimage fields `payload_length` / `evidence_length` are exact `u32`。At entry to the phase-9 PREFIX **G**, **before any Port event in that drive**, both pinned totals must be `≤UINT32_MAX`。If either is larger: emit no Port event, set the first sticky to `NINLIL_E_STORAGE_CORRUPT`, enter `FAILED/phase=14`, and apply the no-Port semantic-finding checkpoint rule。If both fit: checked-convert each pin exactly once and encode it as `u32be`; truncation, low-32-bit selection, saturation, or direct `u64be` feed is forbidden。

##### 18.14.19.6 NATURAL fault schedule（REP1-v1）

Formal vector field `faults` is an array of length **0 or 1**.

If length 1, the sole object has **exactly** these keys:

| Key | Type | Exact constraint |
| --- | --- | --- |
| `op` | string | closed: `get` \| `iter_open` \| `iter_next` \| `rollback` |
| `on_call` | u32 | 1-based per-op counter; see floors below |
| `status` | string | closed Storage status set below |
| `shape` | string | exact `"natural"` |

**`status` closed set（Storage names on Port `storage_status`）:**

`NO_SPACE` | `IO_ERROR` | `CORRUPT` | `COMMIT_UNKNOWN` | `BUSY` | `UNSUPPORTED_SCHEMA`

**Excluded from formal faults:** `OK`, `NOT_FOUND`, `BUFFER_TOO_SMALL`, and any unknown status string. Therefore every formal fault produces returned length fields exact **0**（no BTS required-length path）。

**`on_call` floors（begin success is guaranteed; profile 17 gets + I1 open always succeed）:**

| `op` | Required `on_call` |
| --- | --- |
| `get` | `≥ 18`（post-profile product gets） |
| `iter_open` | `≥ 2`（post-I1 reopens） |
| `iter_next` | `≥ 1` |
| `rollback` | exact `1`（finalize cleanup） |

The configured fault must be **reachable** on the vector’s schedule and is applied **exactly once**. Shape faults and faults on `begin` / `iter_close` / `close` are **outside** REP1-v1 formal product.

**Failed event field rules:** see §18.14.19.7 per-op table（fault row）。


**Formal authority Cartesian coverage（O1b-R2; Normative for suffix regen）:** the
D3-S3 independent formal suffix **must** include at least one executable natural
fault vector for **every** pair in the exact closed product

`{get, iter_next, iter_open, rollback} × {NO_SPACE, IO_ERROR, CORRUPT, COMMIT_UNKNOWN, BUSY, UNSUPPORTED_SCHEMA}`

= **24** unique `(op, status)` pairs. Coverage is **set equality** against this
product（subset is insufficient; extra pairs outside the product are forbidden as
formal NATURAL authority）。Each such vector: faults length 1, fault used exactly
once, and the injected failing Port event is the last operational event of its
drive window（finalize may void-`close` after a natural `rollback`）。Self-tests
alone do not satisfy this authority requirement。BIND_MAN / BIND_CHUNK GET natural
vectors remain required specific coverage in addition to the Cartesian floor。

##### 18.14.19.7 Port event schema + per-op exact value table

Every `port_trace[i]` object has **exactly** these keys（all present）:

| Key | Type |
| --- | --- |
| `seq` | u32（0-based absolute） |
| `api_call_index` | u32（0-based formal call index） |
| `op` | string: `begin`\|`get`\|`iter_open`\|`iter_next`\|`iter_close`\|`rollback`\|`close` |
| `on_call` | u32（1-based per-op） |
| `storage_status` | string\|null |
| `input_handle_id` | string\|null |
| `output_handle_id` | string\|null |
| `mode` | string\|null |
| `prefix_hex` | string |
| `prefix_length` | u32 |
| `request_key_hex` | string |
| `request_key_length` | u32 |
| `key_hex` | string |
| `key_capacity` | u32 |
| `key_length` | u32 |
| `value_capacity` | u32 |
| `value_length` | u32 |

**Per-op exact values（success / NOT_FOUND / natural fault）:**

| `op` | handles | `mode` | request key | output key (`key_*`) | value | `storage_status` |
| --- | --- | --- | --- | --- | --- | --- |
| `begin` | in=`H1`, out=`T1` on OK | `"READ_ONLY"` | `""` / 0 | `""` / 0 / 0 | cap=0,len=0 | Storage begin status string |
| `get` | in=`T1`, out=`null` | `null` | **always** nonempty request: `request_key_hex` + `request_key_length=actual` | **always** `key_hex=""`, `key_capacity=0`, `key_length=0`（GET has no output key） | `value_capacity`=caller; `value_length`=returned on OK; **0** on `NOT_FOUND`; **0** on fault | Storage get status |
| `iter_open` | in=`T1`; out=`Ik` on OK; out=`null` on fault | `null` | `""` / 0 | `""` / 0 / 0 | 0 / 0 | Storage open status |
| `iter_next` | in=`Ik`, out=`null` | `null` | **always** `""` / 0 | OK: returned key + caller `key_capacity` + returned `key_length`; `NOT_FOUND`/fault: `key_hex=""`, lengths 0, capacities still caller | OK: caller `value_capacity` + returned len; `NOT_FOUND`/fault: len 0, cap caller | Storage next status |
| `iter_close` | in=`Ik`, out=`null` | `null` | `""` / 0 | `""` / 0 / 0 | 0 / 0 | JSON **`null`**（void） |
| `rollback` | in=`T1`, out=`null` | `null` | `""` / 0 | `""` / 0 / 0 | 0 / 0 | Storage rollback status |
| `close` | in=`H1`, out=`null` | `null` | `""` / 0 | `""` / 0 / 0 | 0 / 0 | JSON **`null`**（void） |

For every op, the formal profile uses `prefix_hex=""` and `prefix_length=0`（the only prefix-bearing op is zero-prefix `iter_open`）。For ops other than `get`, `request_key_hex=""` and `request_key_length=0`. For ops other than `iter_next`, output key capacities/lengths follow the table（N/A ⇒ 0）。

##### 18.14.19.8 Control-tuple transition table（OK exits）

**Tuple notation**（every successful formal-call checkpoint publishes exactly）:

```text
T = (session.state, phase, pass_kind, focus_sub, semantic_pass, flags, count_mask, binding_mask)
```

`session.state` ∈ {`OPEN`,`EXHAUSTED`,`FAILED`,`DONE`}（`IDLE` only pre-begin）。  
Fault exits: §18.14.19.10. Terminal stop when `phase∈{13,14}`。

###### B0 begin success（not a drive）

| Entry | Port | OK exit `T` |
| --- | --- | --- |
| pre-begin | begin+17×get+iter_open→I1 | (`OPEN`, **1**, **0**, **0**, **0**, **0x00**, **0**, **0**) |

###### B1 BASELINE true exhaustion

| Entry | Port | OK exit `T` |
| --- | --- | --- |
| (`OPEN`,1,0,0,0,0x00,0,0) with I1 live | **W** `row_budget=N+1` to NOT_FOUND | (`EXHAUSTED`, **2**, **1**, **0**, **0**, **0x11**, **0**, **0**) |

Also: `profile_exact_active=1`, mismatch=0, future=0 after this OK exit.

###### B5 BASELINE midwalk only（B5-only vectors）

| Step | Port | OK exit `T` |
| --- | --- | --- |
| first BASELINE stop | **W** `row_budget=N` after N OK rows | (`OPEN`, **1**, **0**, **0**, **0**, **0x00**, **0**, **0**); I1 still live; no on_exhausted |
| resume | **W** `row_budget=N+1` to NOT_FOUND | same as **B1** |

B5 on SELECT/FOCUS/BIND/SEMANTIC **W** or any **WG**/**G** is **ill-formed**.

###### SELECT W（entry phase=2, pass=1; reopen first if `flags&0x10`）

One SELECT **W** installs **at most one** carrier. Residual OK rows after that install are advanced for **pass-local lex only**（`has_previous` / `previous_key` under `PASS_INTERNAL` freeze; **no** public `ok_row_count` / `current_domain_key_count` re-increment）and **never** install a second carrier in the same W. W ends at true NOT_FOUND ⇒ `session.state=EXHAUSTED`。

Let `Za=(view_a_key_digest==0)`, `Zb=(view_b_key_digest==0)` for Mode28. Let `Cprev` be count mask before this SELECT install（0 for first carrier or after prior carrier finalized back to SELECT）。

| Case | OK exit `T` |
| --- | --- |
| no more carriers（empty SELECT） | (`EXHAUSTED`, **11**, 1, 0, 0, **0x15**, **Cvac**, 0) where `Cvac=0` if zero carriers ever completed, else last completed carrier’s final count mask. **Mode30 only:** apply §18.14.9.3 **BIND-entry initialization** exactly once on this transition（empty BLOB-manifest frontier; clear peer/selected pins/latch）**before** the first outer BIND W. Modes 27–29: no Mode30 BIND-entry init. |
| Mode27/29 LIVE or HIST nonzero dig | (`EXHAUSTED`, **3**, 1, 0, 0, **0x13**, **0**, 0) |
| Mode30 LIVE or HIST nonzero dig | (`EXHAUSTED`, **3**, 1, 0, 0, **0x13**, **0**, 0) |
| Mode27/29 NONE zero dig | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x03**, 0) |
| Mode30 NONE zero dig | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x07**, 0) |
| Mode28 Za=1,Zb=1 | (`EXHAUSTED`, **9**, 1, **1**, 0, **0x03**, **0x03**, 0); pin both totals 0 |
| Mode28 Za=0（A nonzero） | (`EXHAUSTED`, **3**, 1, **0**, 0, **0x13**, **0**, 0) |
| Mode28 Za=1,Zb=0 | (`EXHAUSTED`, **6**, 1, **1**, 0, **0x13**, **0**, 0); pin view_a total 0 |

###### FOCUS_SCAN / FOCUS_SCAN_B W（entry phase 3 or 6）

| Case | OK exit `T` |
| --- | --- |
| LIVE match Mode27 entry phase3 → OWNER | (`EXHAUSTED`, **4**, 1, 0, 0, **0x43**, **0**, 0); pin man digests |
| LIVE match Mode29 entry phase3 → OWNER | (`EXHAUSTED`, **4**, 1, 0, 0, **0x43**, **0**, 0); pin man digests |
| LIVE match Mode28 entry phase3（A）→ OWNER | (`EXHAUSTED`, **4**, 1, **0**, 0, **0x43**, **0**, 0); pin man digests; pin view_a total u64be |
| LIVE match Mode28 entry phase6（B）→ OWNER_B | (`EXHAUSTED`, **7**, 1, **1**, 0, **0x43**, **0**, 0); pin man digests; pin view_b total u64be |
| LIVE match Mode30 entry phase3 → CHUNKS | (`EXHAUSTED`, **5**, 1, 0, 0, **0x43**, **0**, 0); pin man digests |
| HISTORICAL_ABSENT match_count=0 Mode27/29 | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x03**, 0); semantic none |
| HISTORICAL_ABSENT match_count=0 Mode30 | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x07**, 0); semantic none; semantic_pass stays 0 |

###### OWNER / OWNER_B G

| Entry phase | OK exit `T` |
| ---: | --- |
| 4 Mode27 | (`EXHAUSTED`, **5**, 1, **0**, 0, **0x43**, **0**, 0) |
| 4 Mode29 | (`EXHAUSTED`, **5**, 1, **0**, 0, **0x43**, **0**, 0) |
| 4 Mode28-A | (`EXHAUSTED`, **5**, 1, **0**, 0, **0x43**, **0**, 0) |
| 7（Mode28-B） | (`EXHAUSTED`, **8**, 1, **1**, 0, **0x43**, **0**, 0) |

Mode30 has **no** OWNER G row（skipped by schedule）。

###### CHUNKS / CHUNKS_B G

| Case | OK exit `T` |
| --- | --- |
| Mode27/29 CHUNKS done | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x03**, 0) |
| Mode28 CHUNKS_A done, Zb=0（B pending） | (`EXHAUSTED`, **6**, 1, **1**, 0, **0x13**, **0**, 0) |
| Mode28 CHUNKS_A done, Zb=1（B zero） | (`EXHAUSTED`, **9**, 1, **1**, 0, **0x03**, **0x03**, 0) |
| Mode28 CHUNKS_B done（A was zero or already done） | (`EXHAUSTED`, **9**, 1, **1**, 0, **0x03**, **0x03**, 0) |
| Mode30 CHUNKS done | (`EXHAUSTED`, **9**, 1, 0, 0, **0x03**, **0x03**, 0) |

Empty chunk_count still runs the G unit（zero gets）and takes the same exit.

###### Mode28 semantic units

| Entry | Port | OK exit `T` |
| --- | :---: | --- |
| phase9, sem0, Za=1,Zb=1 | PREFIX **G**（first perform §18.14.19.5 checked-u32 gate; finalize SHA） | (`EXHAUSTED`, **2**, 1, 1, **0**, **0x11**, **0x07**, 0) |
| phase9, sem0, Za=0 | PREFIX **G**（no SHA finalize） | (`EXHAUSTED`, **3**, 1, 1, **1**, **0x13**, **0x03**, 0) |
| phase9, sem0, Za=1,Zb=0 | PREFIX **G**（no SHA finalize） | (`EXHAUSTED`, **6**, 1, 1, **3**, **0x13**, **0x03**, 0) |
| phase3, sem1 | RESCAN_A **W** | (`EXHAUSTED`, **10**, 1, 1, **2**, **0x03**, **0x03**, 0) |
| phase10, sem2, Zb=0 | VIEW_A_CHUNKS **G** | (`EXHAUSTED`, **6**, 1, 1, **3**, **0x13**, **0x03**, 0) |
| phase10, sem2, Zb=1 | VIEW_A_CHUNKS **G**（finalize） | (`EXHAUSTED`, **2**, 1, 1, **0**, **0x11**, **0x07**, 0) |
| phase6, sem3 | RESCAN_B **W** | (`EXHAUSTED`, **10**, 1, 1, **4**, **0x03**, **0x03**, 0) |
| phase10, sem4 | VIEW_B_CHUNKS **G**（finalize） | (`EXHAUSTED`, **2**, 1, 1, **0**, **0x11**, **0x07**, 0) |

Rules: order A then B; each nonzero view is exactly RESCAN W → VIEW_CHUNKS G; zero view has neither; semantic band rescans ≤2 W total; PREFIX always once per LIVE carrier after first-focus complete（or immediately if both zero）。
The checked-u32 gate is part of every Mode28 phase-9 PREFIX G row, including the two non-zero-view rows above; an oversized pin takes the §18.14.19.10 semantic-finding exit before the carrier re-get。

###### Mode30 semantic units

| Entry | Port | OK exit `T` |
| --- | :---: | --- |
| phase9, sem0 | PREFIX **G**（RR→DELIVERY→RESULT→CELL/CANCEL as mode rules; no SHA finalize if chunks follow） | (`EXHAUSTED`, **10**, 1, 0, 0, **0x03**, **0x03**, 0) |
| phase10, sem0 | SEM_CHUNK **G**（RECEIPT known-index gets or empty compute; SHA finalize） | (`EXHAUSTED`, **2**, 1, 0, 0, **0x11**, **0x07**, 0) |

###### BIND units

Mode27–30: BIND_MAN / BIND_CHUNK inventory is **exactly one formal unit per drive**（no multi-unit batching inside one drive）。Modes27–29 BIND_MAN and all BIND_CHUNK use **WG** Port grammar（§18.14.19.3）。Mode30 outer/RR remain pure **W** with BIND-entry empty BLOB-manifest frontier + boolean latch（§18.14.9.3）。

For the **first** Mode30 outer W, the once-only BIND-entry initialization has
already been applied by the SELECT-empty transition。If it selects a candidate,
the candidate row is the exact transition; if it selects none, the no-candidate
row is the exact transition。There is no third “first outer” transition。

| Case | Unit | Port | OK exit `T` |
| --- | :---: | :---: | --- |
| Mode27–29 BIND_MAN true exhaustion | **WG** | exact reopen prefix（§18.14.19.3）+ (iter_next OK [, owner exact_get if eligible])* + NOT_FOUND | (`EXHAUSTED`, **12**, 1, 0, 0, **0x15**, **Cb**, **0x08**) |
| Mode30 outer selects first REPLY man with key `>` BLOB-manifest frontier（including first outer after once-only init） | **W** | pure walk; GET 0; pin peer/selected pins; `observed_live=0`; frontier **not** advanced | (`EXHAUSTED`, **11**, 1, 0, **5**, **0x15**, **Cb**, **0**) |
| Mode30 RR-band true NOT_FOUND with `observed_live=1` | **W** | pure walk; GET 0; latch idempotent; promote frontier from peer; **exact clear** peer+selected pins per §18.14.9.3; `sem=0` | (`EXHAUSTED`, **11**, 1, 0, **0**, **0x15**, **Cb**, **0**) |
| Mode30 outer true exhaustion with **no** candidate（including first outer after once-only init） | **W** | pure walk; GET 0 | (`EXHAUSTED`, **12**, 1, 0, 0, **0x15**, **Cb**, **0x08**) |
| Mode27–30 BIND_CHUNK true exhaustion | **WG** | exact reopen prefix + (iter_next OK [, man exact_get if eligible chunk])* + NOT_FOUND | (`EXHAUSTED`, **13**, 1, 0, 0, **0x09**, **Cb**, **0x18**) |

Mode30 RR true NOT_FOUND with `observed_live=0` is a **fault exit**（CORRUPT; frontier not advanced）, not an OK row。Only outer empty exhaustion enters BIND_CHUNK。BIND-entry initialization is **not** repeated before each outer W。

`Cb` is the count mask frozen at BIND entry and unchanged by BIND: `0` if zero carriers（vacuous）; else the last completed carrier’s final count（Mode27/29: `0x03`; Mode28/30: `0x07`）。Phase 13 stops drives（COMPLETE）。

**BIND GET accounting:** every owner/man-presence get inside WG increments `port.get_count` and **`d3_peer_get_count`**（post-profile rule of §18.14.19.9）。NATURAL fault on a BIND get uses floors of §18.14.19.6（`get.on_call≥18`）and must be **reachable** on the WG schedule。

**Failure-point tuples（BIND）:** on sticky semantic finding during WG, `phase→14` with flags/masks/substates equal to the pre-finding values **except** `phase=14`（§18.14.19.10）。On natural GET fault mid-WG, fields equal values **immediately before** the failing get（including visit commit of the preceding OK `iter_next`）。Mode30 outer/RR faults follow pure-W failure rules（no get）。

###### Reopen counters（W / WG that consume NEED_REOPEN; exact §18.14.19.3）

| Case | Port sequence | Counters |
| --- | --- | --- |
| `NEED_REOPEN=1` and `iter_live=1` success | **exactly one** void `iter_close(current Ik)` then **exactly one** `iter_open` OK → new `Ik`; then clear NEED_REOPEN | `reopen_attempt_count += 1`; `reopen_success_count += 1` |
| `NEED_REOPEN=1` and `iter_live=0` | **no Port events**; `INVALID_STATE` | counters unchanged |
| `NEED_REOPEN=0` and `iter_live=1` | emit **neither** close nor open | counters unchanged |
| `NEED_REOPEN=0` and `iter_live=0` | **no Port events**; `INVALID_STATE` | counters unchanged |
| `iter_open` natural fault after the mandatory close | close emitted; open fails; out=null; NEED_REOPEN cleared | attempt +=1; success unchanged; then §18.14.19.10 |
| BASELINE | uses I1; `NEED_REOPEN=0` and `iter_live=1`; no reopen | neither counter increases for I1 |

Definitions: `reopen_attempt_count` = number of `iter_open` calls **after** successful begin `I1`. `reopen_success_count` = those post-I1 opens that returned OK and produced a new `Ik`.

##### 18.14.19.9 Checkpoint schema（closed objects）

Top-level checkpoint keys **exactly**: `returned_status`, `session`, `d3s3`, `port`, `result`.

**`session` keys（exactly; all present）:**

| Key | Type |
| --- | --- |
| `state` | string enum `IDLE`\|`OPEN`\|`EXHAUSTED`\|`FAILED`\|`DONE` |
| `txn_live` | u8 0/1 |
| `iter_live` | u8 0/1 |
| `has_sticky_primary` | u8 0/1 |
| `sticky_primary` | exact `""` iff `has_sticky_primary=0`; otherwise one of the six mapped Runtime error symbols listed in §18.14.19.10 |
| `cleanup_status` | JSON `null` before finalize and after rollback `OK`; otherwise one of the six Storage fault symbols from §18.14.19.6 |
| `reopen_required` | u8 0/1（session fence flag; not D3 NEED_REOPEN） |
| `fence_pending` | u8 0/1 |
| `profile_exact_active` | u8 0/1 |
| `profile_mismatch` | u8 0/1 |
| `future_profile_candidate` | u8 0/1 |
| `recognizable_future_seen` | u8 0/1 |
| `family14_row_count` | u32 |
| `family14_iter_seen_mask` | u32 |
| `profile_get_present_mask` | u32 |
| `ok_row_count` | u64 |
| `current_domain_key_count` | u64 |
| `has_previous` | u8 0/1 |
| `previous_key_hex` | string |
| `previous_key_length` | u32 |

**`d3s3` keys（exactly; all present）:**

| Key | Type |
| --- | --- |
| `phase` | u8（0..14） |
| `pass_kind` | u8（0..1） |
| `focus_mode` | u8 |
| `focus_sub` | u8 |
| `semantic_pass` | u8（0..6） |
| `lifecycle_class` | u8 |
| `expected_live` | u8 |
| `observed_live` | u8 |
| `reply_kind` | u8 |
| `flags` | u8 |
| `count_complete_mask` | u8 |
| `binding_complete_mask` | u8 |
| `last_carrier_key_hex` | string |
| `last_carrier_key_len` | u8 |
| `focus_id16_hex` | string length 32 hex（Mode28: two u64be totals; Mode30: tx16; else 0） |

`peer_key` / `peer_key_len` are **not** REP1 checkpoint fields（not serialized in `d3s3` checkpoint JSON）。They **are** Normative **derived control state** for BIND-WG request keys and Mode30 selection/frontier promotion（§18.14.9.2–.4）：selection, preservation across outer→RR, and frontier promotion **must** follow those algorithms because they determine the Port transcript and subsequent unit eligibility。Every externally observable GET request key is frozen by `port_trace[].request_key_hex/request_key_length`。

**`port` keys（exactly; all present）:**

| Key | Type |
| --- | --- |
| `event_start` | u32 half-open start |
| `event_end` | u32 half-open end |
| `trace_count` | u32（= `event_end` after call） |
| `begin_count` | u32 |
| `get_count` | u32 |
| `iter_open_count` | u32 |
| `iter_next_count` | u32 |
| `iter_close_count` | u32 |
| `rollback_count` | u32 |
| `close_count` | u32 |
| `d3_peer_get_count` | u64; exact product GET-attempt count defined below |
| `reopen_attempt_count` | u32 |
| `reopen_success_count` | u32 |
| `mutation_calls` | u32（0 on success paths） |
| `trace_overflow` | u8（must be 0） |
| `storage_handle_id` | string\|null（`H1` if authoritative） |
| `txn_handle_id` | string\|null（`T1` if live） |
| `iter_handle_id` | string\|null（current `Ik` if live） |

**`d3_peer_get_count` exact rule:** after successful profiled begin it is `0`。For every subsequent product `get` Port invocation, increment exactly once **when the event is emitted, before its Storage status is interpreted**。Thus OK, `NOT_FOUND`, and a natural failed GET each count one; the 17 profile-catalog GETs never count。**BIND-WG owner/orphan gets are product gets and count**。At every checkpoint after successful begin, `d3_peer_get_count == port.get_count - 17`。No non-GET op changes it。

**`result`:** JSON `null` before finalize. After finalize, object with **exactly**:

| Key | Type |
| --- | --- |
| `status` | string（same Runtime closed enum as `returned_status`） |
| `adopted` | u8 0/1 |
| `state_after` | string exact `"DONE"` |
| `has_sticky_primary` | u8 |
| `sticky_primary` | same exact empty-or-six-Runtime-symbol rule as `session.sticky_primary` |
| `reopen_required` | u8 |
| `cleanup_status` | same exact null-or-six-Storage-symbol rule as `session.cleanup_status` |
| `mutation_calls` | u32 |
| `profile_exact_active` | u8 |
| `profile_mismatch` | u8 |
| `future_profile_candidate` | u8 |
| `recognizable_future_seen` | u8 |
| `family14_row_count` | u32 |
| `family14_iter_seen_mask` | u32 |
| `profile_get_present_mask` | u32 |
| `ok_row_count` | u64 |
| `current_domain_key_count` | u64 |
| `d3_peer_get_count` | u64 |

After finalize, `result.status == returned_status` and `result.adopted=1` **iff** the pre-finalize phase was `COMPLETE=13`, no sticky primary exists, rollback returned `OK`, `fence_pending` was 0 at finalize entry, final `reopen_required=0`, and final status is `NINLIL_OK`。Every other path（including any rollback fault or fence）has `adopted=0`。

##### 18.14.19.10 Failure / fault exits（exact）

Every faulted drive ends at the failing event. Cleanup is finalize-only.

| Kind | `session.state` | `phase` | liveness | flags/masks/substates | notes |
| --- | --- | ---: | --- | --- | --- |
| Semantic finding（no Port fault） | `FAILED` | **14** | txn/iter unchanged | equal to values at finding point **except** `phase=14` | sticky first Runtime status; earlier Port events of the drive persist |
| GET natural fault（**G** or mid-**WG**） | `FAILED` | **14** | `txn_live=1`; `iter_live` unchanged | equal to values **immediately before** failing get | earlier events in same drive persist; **WG:** prior OK `iter_next` **lex-only** visit commit（`has_previous`/previous_key）already applied; public `ok_row_count`/`current_domain_key_count` **unchanged** under INTERNAL freeze; failing get commits **no** further semantic install; lengths 0; **no residual iter_next** |
| ITER_NEXT natural fault | `FAILED` | **14** | `txn_live=1`, `iter_live=1` | immediately before failing next | no on_row/on_exhausted for failing event; prior successful rows persist |
| reopen `iter_open` natural fault | `FAILED` | **14** | `txn_live=1`, `iter_live=0` | NEED_REOPEN already cleared after `iter_close`; other fields pre-open | old Ik closed first; attempt+1; success unchanged |
| rollback natural fault in finalize | `DONE` after cleanup | d3s3 keeps last drive phase value（not rewritten to 14 by finalize） | `txn_live=0`, `iter_live=0` | last drive tuple retained in d3s3 snapshot | order: iter_close if live → rollback(T1) fails → close(H1) → `reopen_required=1`; `cleanup_status`=the Storage fault; `adopted=0` |

Sticky Runtime mapping from Storage fault status:

| Storage `status` | mapped Runtime status family |
| --- | --- |
| `NO_SPACE` | `NINLIL_E_CAPACITY_EXHAUSTED` |
| `IO_ERROR` | `NINLIL_E_STORAGE` |
| `CORRUPT` | `NINLIL_E_STORAGE_CORRUPT` |
| `COMMIT_UNKNOWN` | `NINLIL_E_STORAGE_COMMIT_UNKNOWN` |
| `BUSY` | `NINLIL_E_WOULD_BLOCK` |
| `UNSUPPORTED_SCHEMA` | `NINLIL_E_UNSUPPORTED` |

**Drive-time `COMMIT_UNKNOWN` fence（exact; aligns §15.11.5）:** when a product-path natural `get` / `iter_open` / `iter_next` returns Storage `COMMIT_UNKNOWN`, the failing drive **maps** sticky to `NINLIL_E_STORAGE_COMMIT_UNKNOWN` **and sets `fence_pending=1` at the failing drive checkpoint**。There is **no cleanup inside the failing drive**（no `rollback` / `close` / residual `iter_next`）。H1 remains live until finalize。Finalize with rollback `OK` then **closes original H1 exactly once**, nulls the caller handle slot, sets `reopen_required=1`, clears `fence_pending` to **0** after the fence close, retains sticky `COMMIT_UNKNOWN`, keeps `cleanup_status=null`（rollback was OK）, and `adopted=0`。Other natural statuses（`NO_SPACE` / `IO_ERROR` / `CORRUPT` / `BUSY` / `UNSUPPORTED_SCHEMA`）map sticky only and **do not** set drive-time `fence_pending` unless a separately Normative fence condition applies（descriptor rewrite / unknown raw / handle drift — not ordinary natural product faults）。

**Sticky / cleanup precedence（exact）:** a drive-time `get` / `iter_open` / `iter_next` natural fault sets the first sticky to the mapped Runtime status and returns it（`COMMIT_UNKNOWN` also sets `fence_pending` as above）。A rollback fault occurs only in finalize and **never creates, clears, or overwrites** `has_sticky_primary/sticky_primary`。It sets `cleanup_status` to its Storage symbol and fences H1。If a sticky already exists, finalize `returned_status` / `result.status` is that prior sticky; otherwise it is the rollback fault’s mapped Runtime status。With no rollback fault, `cleanup_status=null`; a prior sticky still wins, otherwise a valid COMPLETE finalize returns `NINLIL_OK`。

##### 18.14.19.11 Finalize cleanup order

```text
finalize:
  if iter_live && txn_live: iter_close(Ik)      # void; storage_status=null
  else if iter_live && !txn_live: drop iter without Port close
  if txn_live: rollback(T1) → record storage_status
  if (rollback_status != OK) OR (fence_pending != 0):
      close(original H1)                       # void; storage_status=null
      session.reopen_required := 1
  session.state := DONE
  publish result（status / adopted use §18.14.19.9–.10 exact precedence）
```

Fence condition is exactly **`rollback_status != OK` OR existing `fence_pending`**. No cleanup inside sticky drive failure. Successful COMPLETE path with OK rollback and `fence_pending=0` does **not** close H1（caller retains H1）。The pseudocode's publish step uses the exact status/adoption precedence in §18.14.19.9–.10; in particular, rollback failure always forces `adopted=0` and never overwrites an earlier sticky。

##### 18.14.19.12 Mode schedule summary（normative pointer）

| Mode | Schedule |
| ---: | --- |
| **27** | SELECT setup STATE（+ES iff EventFact）; FOCUS_SCAN W → OWNER G → CHUNKS G → SELECT; no semantic; **BIND_MAN WG** → **BIND_CHUNK WG** → COMPLETE |
| **28** | §18.14.19.8 Mode28 rows; focus_id16 = two u64be totals; ≤2 semantic band W; BIND_MAN **WG** → BIND_CHUNK **WG** |
| **29** | APP_FIRST RESULT setup on SELECT W; CANCEL_FIRST setup 0; OWNER on DELIVERY; same CHUNKS/SELECT; BIND_MAN **WG** → BIND_CHUNK **WG** |
| **30** | no OWNER G; FOCUS_SCAN W → CHUNKS G → SEM_PREFIX G → SEM_CHUNK G → SELECT; HISTORICAL_ABSENT → SELECT count 0x07, semantic none; BIND outer **W**（first REPLY man `>` frontier; latch0）→ RR **W**（sem=5; `observed_live` boolean latch; promote frontier only if latch1）→ … → empty outer → BIND_CHUNK **WG** → COMPLETE |

##### 18.14.19.13 Explicit non-claims

REP1-v1 **does not**:

- redefine D1 wire or non-BIND §18.14 semantic findings beyond the BIND-WG packing clarification in §18.14.9
- require non-REP1 implementations to match Port transcripts
- accept private builds as REP1-L2 evidence
- allow mapping tables as a substitute for micro-step equality
- treat **withdrawn** pre-acceptance GET=0 BIND authority SHAs as Accepted or Normative
- claim D3 complete / Stage 5 / public Runtime / ESP / hardware / security audit
- claim production bridge green, implementation complete, or candidate JSON as Accepted authority（**Proposed oracle candidate**）
- claim ADR Accepted

##### 18.14.19.14 Follow-on work（non-normative）

| Work item | Owner |
| --- | --- |
| Generator regenerates candidate authority with BIND-WG Port events + control-tuple checkpoints + R19–R27 D1-legality gate（same path; R27 content `ccf056de…` / raw `a88ffb4f…` object-identical to R26 vector body; suffix129=`rep1_l2`128+`formal_precheck`1; boundary **4380**; STATE positives **28**; Mode27 lifecycle 3×4） | O1b — candidate emitted/self-check済み; acceptance pending |
| Shipped reference Core W/G/**WG** split + visit-commit-before-get + BIND hooks | production private S3 |
| Spy structured events + H1/T1/Ik map + BIND gets | test spy |
| Bridge two-lane field-for-field（`rep1_l2` exact Port; `formal_precheck` validator-only zero Port; unknown scope/count drift/silent skip RED） | O1c |
| Sol independent re-review of R27 candidate (R21–R26 were Sol high / Root residual NO-GO); production/bridge evidence; ADR-0015 Accepted only after GO | governance（**not** claimed; Accepted/GO forbidden） |

### 18.15 Normative D3-S4a freeze（DSW1_ALL_OLD_NEW / witness member group）

**Decision identifier: D3-S4a。** 本節は D3-S0 / S1a / S2a / **S3a（§18.14）** を **上書きせず**、§10 **`DSW1_ALL_OLD_NEW`** の **docs-only Normative freeze** を追加する。§18.14（S3: **754/768**, outer **9920**）は **origin/main と byte-equivalent に保持**。**docs only**（code/tests/CMake/JSON/ADR 0）。implementation / D3 / Stage5 / D4 / public Runtime / ESP / hardware **pending**。private symbol 存在 **未 claim**。

**Design choice:** 1 session = 1 mode `m` ∈ {31..34}; **k₄=4**; single `READ_ONLY` txn; **single 4096**; fixed S4 context; no full-ID set; no heap/VLA/second 4096/two-txn list-prove; **no S1 separate-session delegation** for primary bind。**successor → S5; retire → S6; mutation → D4**。Modes 31/32 は **2M chunk re-get**、Mode33 は RETIRED-header inventory→chunk bind の sequential same-txn subpasses、Mode34 は disjoint A/B/C carrier と dual raw/digest pins を使い、各 get 後の cursor progress を本節だけで閉じる。

**Composite key rule:** witness header / HEAD_INDEX / manifest chunk の complete key は、その時点で実バイトとして pin 済みの operation raw / witness composite identity / member `KEY_DIGEST` / chunk index から **forward rebuild** する。`KEY_DIGEST` から raw identity を reverse することは **禁止**。

#### 18.15.0 Value lifetime / pin discipline

| Rule | Exact |
| --- | --- |
| Borrow | `value[4096]` は **直近 1 回** successful `exact_get` / iter value のみ valid |
| Invalidate | 次の `exact_get` / value 供給 / cleanup で **即 invalid** |
| Pin before overwrite | 後続 get 後に必要な digest / **complete primary key bytes + source raw/raw2/aux** / membership expected digests は **get 前**に fixed context へ copy |
| Forbidden | invalid value を VALUE_DIGEST / body raw rebuild / raw bijection 入力に使う |

#### 18.15.1 Snapshot-only DSW1 scope

| In scope | Out |
| --- | --- |
| all-old/all-new/mixed/partial/dup/missing/extra; 2M stream | S5 chain; S6 retire; D4 commits |
| Mode34 A/B/C + **dual-target membership full-M** with **two digest pins** | S1 separate session as substitute for primary bind |
| **same-txn** primary PVD + **byte-exact primary body raw/raw2/aux**（S4 closed table: Mode17 pure rows + BLOB manifest/chunk rows） | public Runtime |
| finalize / evaluator-off / incomplete-mask / **quota=1 substep progress** | |

#### 18.15.2 Closed modes 31..34

| Mode | Carrier | Core |
| ---: | --- | --- |
| **31** | every ACTIVE WITNESS_HEADER | FOCUS_MEMBERS_2M+P + ACTIVE GROUP_CLOSE |
| **32** | every SUPERSEDED WITNESS_HEADER | FOCUS_MEMBERS_2M+P + local progression classification; successor proof is S5 |
| **33** | every WITNESS_MANIFEST_CHUNK | forward-build its header key and bind the chunk to that header |
| **34** | disjoint arms A/B/C in §18.15.8.0 | carrier pins → known forward gets → MEMBERSHIP_DUAL full-M |

#### 18.15.3 Group identity / framing + exact member set

Header install copies `witness_digest`, state, `member_count=M`, `chunk_count=C`, and `manifest_digest` while the header value is live. The following is exact:

1. `1 ≤ M ≤ 256`; `C = ceil(M/8)` and `1 ≤ C ≤ 32`.
2. For ordinal `i`, rebuild `chunk_key(witness_digest, floor(i/8))` and exact-get it. Decoded chunk `witness_digest`, returned `chunk_index`, and `chunk_count` must equal the installed header / **exact requested `floor(i/8)`** / `C`. The same returned index is therefore required and legal for all ordinals in that chunk（at most eight consecutive gets; exactly eight except the final chunk）。A returned-index duplicate is corruption only when it repeats across a **chunk boundary** where `floor(i/8)` advanced, when an iterator supplies a duplicate complete chunk row/key, or when the returned index differs from the current requested `floor(i/8)`; the normal within-chunk re-get is not a duplicate finding.
3. Non-final chunks have exactly 8 entries; the final chunk has exactly `M-8*(C-1)` entries. `i%8` must exist. Missing expected chunk/slot is CORRUPT.
4. Across all `M` entries, keys are strict unsigned-byte increasing. `prev_member_key` spans chunk boundaries; equality is duplicate and decreasing order is CORRUPT. No full member-key set is retained.
5. The manifest SHA uses §5.1's exact domain-separated formula and exact encoded chunk bodies in index order. Modes 31/32 and Mode34 `MEMBERSHIP_DUAL` each re-get one chunk per member in their **own same-transaction session**; in every such stream a chunk body enters SHA **only when `i%8==0`**. After `M`, final SHA must equal that session's pinned `expected_manifest_digest`. A successful Modes31/32 session from another snapshot is never authority for the Mode34 comparison.
6. Modes31/32 `streamed_members` and Mode34 `membership_i` must respectively become exactly `M`; observed expected chunks are exactly indices `{0..C-1}` in each session. Mode33 first inventories every RETIRED header and then rejects a chunk whose header is absent or whose header count/index framing does not include it; therefore a RETIRED header with zero/partial chunks still creates S6 work, while an extra/orphan chunk cannot hide outside the Modes 31/32 expected set.

All checks above use D1-valid decoded rows. A local D1 failure remains D2 corruption and is not reclassified by S4.

#### 18.15.4 Same-txn phase machine

```text
IDLE → BASELINE (D2 once)
  → Mode 31/32:
      (SELECT_HEADER → install header
         → for i in 0..M-1: MEMBER_I_PIPELINE  (#P1 substeps)
         → GROUP_CLOSE)*
  → Mode 33: (SELECT_RETIRED_HEADER)*
             → close/reopen the sole zero-prefix iterator in the same txn
             → (SELECT_CHUNK → BIND_CHUNK_HEADER)*
  → Mode 34: (SELECT arm → PIN raw+digests → forward known-key gets → MEMBERSHIP_DUAL)*
  → COMPLETE | FAILED | mid-drive yield (not terminal)
```

#### 18.15.5 PASS_INTERNAL / B5s drive quota + **substep progress**（P1）

| Item | Contract |
| --- | --- |
| `drive_get_quota` | each drive/advance: default **32**; legal **1..256**（**1 is legal**） |
| `drive_gets_used` | +1 per S4 `exact_get` attempt |
| Yield | used==quota mid work → OPEN, `flags.need_resume=1`, **no sticky**; preserve all pins/cursors/substeps |
| Resume | refill quota; continue **same substep cursor** — **must not re-issue a completed get** |

**`member_substep`（Mode 31/32; per ordinal `streamed_members` = i）:**

| Value | Meaning | Next action | On success |
| ---: | --- | --- | --- |
| **0** | need chunk re-get for i | forward-build request into `peer_key`; `exact_get(chunk[i/8])`; then overwrite `peer_key` with entry[i%8] key scratch; lex/dup | → **1**（entry pins ready; value may die） |
| **1** | need member get | `exact_get(member key from scratch)` | classify; if primary required: pin PVD + complete primary key in `peer_key` + normalized **source raw/raw2/aux** while value live → **2**; else → **3** |
| **2** | need primary get | `exact_get(peer_key)`; compare PVD + returned primary body **raw/raw2/aux byte-exact** vs pins | → **3** |
| **3** | member i complete | i+1; `streamed_members:=i+1`; `member_substep:=0` | |

**Forbidden with quota=1:** looping substep 0 forever（re-getting same chunk without advancing）。Each successful get **must** advance `member_substep` or `streamed_members`。

**`membership_substep`（MEMBERSHIP_DUAL; per `membership_i`）:**

| Value | Meaning | On success |
| ---: | --- | --- |
| **0** | need chunk re-get for membership_i | extract entry; update found_count_a/b vs **pin_digest_a/b**; increment membership_i; if it becomes M → **1**, else stay 0 |
| **1** | all M entries consumed; no get | close dual: require exact M/C/framing + final manifest SHA and found_count==1 per need bit; set arm_cursor 6 |

Values 2..255 are invalid. Close substep 1 performs no Port call and cannot consume a new drive quota unit.

Pseudocode (quota-aware):

```text
MEMBER_I_PIPELINE while i < M and quota remains:
  if member_substep == 0:
    forward-build chunk request key into peer_key
    exact_get(chunk); used++
    fill entry scratch; overwrite peer_key with decoded entry key; member_substep = 1; continue
  if member_substep == 1:
    exact_get(member); used++;
    classify match_old/new/neither; head surface on live value
    if needs_primary_pvd_raw:
      expected_primary_pvd := common.pvd
      normalize source body as S1 Mode17 tuple
        → expected_primary_raw/raw2/aux + exact lengths
      rebuild complete primary key → peer_key[0..L), L=len ≤45
      member_substep = 2
    else:
      member_substep = 3
    continue
  if member_substep == 2:
    exact_get(peer_key); used++;
    ABSENT → finding; PRESENT →
      VALUE_DIGEST(primary)==expected_primary_pvd
      normalize returned primary body and require
        raw/raw2/aux bytes + lengths == expected pins         # collision defense
    member_substep = 3; continue
  if member_substep == 3:
    i++; streamed_members=i; member_substep=0
if quota exhausted mid-pipeline: yield with cursors (i, member_substep, pins intact)
```

#### 18.15.6 Member match / GROUP_CLOSE + **same-txn primary PVD/raw**

For an ordinary entry, compare current presence and `VALUE_DIGEST(current)` against the entry's exact old/new pair:

| Local class | Exact predicate |
| --- | --- |
| `OLD` | current presence/digest equals `old_present/old_value_digest` |
| `NEW` | current presence/digest equals `new_present/new_value_digest` |
| `NEITHER` | neither exact pair matches |
| `INVALID` | present row fails D1/D2 local decode, PVD/raw proof, or an applicable head predicate |

For present family 5/6 semantic values, the applicable head is the live common `head_witness_digest`. For family 3/4, head truth is carried by its WITNESS_HEAD_INDEX and is closed by Mode34 B/C; a Mode32 `NEITHER` is therefore **never accepted as success** merely because S4 cannot retain a full pairing set. It becomes `PROGRESSED_S5_REQUIRED`, and final D3 success requires Mode34 plus S5 to prove the exact successor path. Absent values have no head surface.

Head/lifecycle rules are exact:

| Header mode | Current member surface | S4 result |
| --- | --- | --- |
| ACTIVE | `NEW`, and every applicable non-zero head equals this `witness_digest` | `NEW_THIS` |
| ACTIVE | `OLD`, `NEITHER`, zero/wrong applicable head, or any `INVALID` | CORRUPT |
| SUPERSEDED | `NEW` and applicable head still equals this witness; expected-new absence is also local NEW | `NEW_THIS` |
| SUPERSEDED | different current digest/presence with a non-zero different current head, or family 3/4 `NEITHER` awaiting its index surface | `PROGRESSED_S5_REQUIRED`; **not success**, defer exact successor proof to S5 |
| SUPERSEDED | `OLD`, `NEITHER` with zero/this/invalid head, rollback to an old digest, or any `INVALID` | CORRUPT |

`SUPERSEDE_WITNESS` entries use §10.1's own progression **independently of whether the installed successor carrier is Mode31 ACTIVE or Mode32 SUPERSEDED**: exact new SUPERSEDED predecessor header is local `NEW`; a D1-valid RETIRED predecessor whose successor equals this installed witness, or a fully-ABSENT predecessor shape（header ABSENT locally; Mode33 must independently reject any orphan chunk）, is local **`S5_AND_S6_REQUIRED`** progression, folds as `PROGRESSED_S5_REQUIRED`, and in the same member-classification transition atomically sets both sticky authorities `flags.bit7` and `binding_complete_mask.bit5`. ACTIVE predecessor, different successor, or header-absent with an orphan chunk is CORRUPT. S4 does not perform a successor exact-get/walk, incoming-reference walk, or retirement eligibility proof; S5/S6 own that correlation.

`group_class` is a closed fold: **0 UNSET, 1 ALL_NEW, 2 ALL_OLD, 3 MIXED_OLD_NEW, 4 PROGRESSED_S5_REQUIRED, 5 CORRUPT**. `NEW+PROGRESSED` remains 4; any `OLD` combined with NEW/PROGRESSED becomes 3; any invalid becomes 5.

**GROUP_CLOSE exact outcomes:**

| Mode | Required before close | Outcome |
| ---: | --- | --- |
| 31 ACTIVE | identity/framing/SHA exact; `streamed_members==M`; `group_class==ALL_NEW`; every required primary proof complete | local VALID ACTIVE/all-new |
| 31 ACTIVE | same exact gates; every ordinary semantic member remains `NEW_THIS`; `group_class==PROGRESSED_S5_REQUIRED` only because one or more `SUPERSEDE_WITNESS` predecessors are same-successor RETIRED/fully-ABSENT | local traversal valid only as `S5_AND_S6_REQUIRED`; never local D3 success |
| 31 ACTIVE | ALL_OLD, MIXED, CORRUPT, ordinary semantic progression, incomplete member/chunk/SHA, missing/extra | CORRUPT; active witness beside old/mixed ordinary semantic truth is never not-applied |
| 32 SUPERSEDED | identity/framing/SHA exact; no OLD/MIXED/CORRUPT; all primary proofs complete | local traversal valid only as `S5_REQUIRED`, or `S5_AND_S6_REQUIRED` when a SUPERSEDE predecessor progressed to RETIRED/ABSENT; even ALL_NEW must have header successor and successor replacement proved by S5 |
| 32 SUPERSEDED | OLD/MIXED/CORRUPT, invalid/zero successor, incomplete member/chunk/SHA | CORRUPT before S5 |

Every non-corrupt Mode32 `GROUP_CLOSE`（ALL_NEW を含む）は **同じ transition で `flags.bit7=s5_required_seen` を set** してから次 header へ進む。Mode31/32のどちらでも上記 `SUPERSEDE_WITNESS` RETIRED/ABSENT progression が1件でもあれば、その member classification transition でbit7と`binding_complete_mask.bit5=s6_required_seen`をatomic setし、GROUP_CLOSE/pass exhaustion/yield は両bitを保存する。Mode31はこの例外以外のordinary semantic memberをALL_NEWのまま要求する。`group_class=PROGRESSED_S5_REQUIRED` は per-header classification、sticky bits は session composition authority であり、いずれかを他方の代用にしない。

Precedence is: D2/local decode or framing CORRUPT > PVD/raw/head CORRUPT > missing/duplicate/extra/SHA CORRUPT > `S5_AND_S6_REQUIRED` / `S5_REQUIRED` deferred authority > local valid. A deferred result is not `COMPLETE_READY`; internal traversal completion後は §18.15.10 の **DEFERRED_READY** として finalize し、named S5/S6 successful composition 前に D3 success へ昇格しない。Deferred bits は既存 corruption を suppress しない。

**Primary path（Modes 31/32; present secondary with non-zero `primary_value_digest`; zero-PVD set skip）:**

S1 正本の **byte-exact collision defense** は「derived key と PVD が一致」だけでは足りない。`exact_get` は value だけを返すため、異なる source body raw A / returned primary body raw B が同じ SHA-composite keyへ衝突した場合、要求キーの再比較はBを検出できない。そこで member body が live の間に、下表の **S4 closed primary normalization** で source raw/raw2/aux + lengths + source role + owner-kind/body-variant aliasをcontextへpinする。complete primary key（current Domain max **45**）は同じraw tupleから `peer_key` へ forward rebuildする。primary get後は live returned primary bodyを同じtable rowへnormalizeし、**raw/raw2/aux byte列・長さ + VALUE_DIGEST** をすべて照合する。§18.12 Mode17 evaluatorを起動・拡張せず、そのclosed reverse rowsのpure normalizationだけをreuseする。

**S4 closed primary normalization table（他rowはnon-zero PVDで到達するとCORRUPT before get）:**

| Source role / body variant | `expected_primary_owner_kind` alias | Source tuple pinned while live | True primary / returned-body exact normalization |
| --- | ---: | --- | --- |
| §18.12 Mode17 reverse tableの全source secondary（BLOB以外） | Mode17 rowのexact role-specific owner kind。owner kindを持たないrowだけ0 | Mode17 pure normalizationのraw/raw2/aux + exact lengths。IDEMPOTENCYはscope + key dual RAW16、CALLBACK等はtableのfixed auxを省略不可 | 同じMode17 rowのtrue primary。returned bodyを同じrowでnormalizeし全tuple/lengthをbyte-exact比較 |
| BLOB manifest（family6 subtype `30`, common flags/body variant exact `1`） | BLOB固有 `blob_owner_kind`: 1 TRANSACTION / 2 INGRESS / 3 DELIVERY | `raw=owner_key_raw` contents exact（16 / 8 / 80 bytes）、`raw2_len=0`, `aux_len=0`。role+alias `(0x0630,1..3)` がmanifest variantをpin | kind1 → TRANSACTION_ANCHOR transaction_id 16、kind2 → ORDERED_INGRESS ordered_sequence BE8、kind3 → DELIVERY `delivery_key_raw` contents 80。same rawからcomplete keyをforward rebuildし、returned primary bodyのexact identity raw/length + PVDを比較 |
| BLOB chunk（family6 subtype `30`, common flags/body variant exact `2`） | exact `0`（role `(0x0630,0)` はchunk専用でmanifest kindとdisjoint） | `raw=blob_id_digest[32]`, `raw2_len=0`, `aux_len=0`。source `manifest_key_digest` はD1 same-recordでこのrawからbuildしたmanifest complete keyのKEY_DIGESTと一致済み | BLOB manifest key `COMPOSITE(30, u8=1 || blob_id_digest)` をrawからforward rebuild。returned rowはD1-valid manifest variant flags=1かつbody `blob_id_digest` exact同値、VALUE_DIGEST(manifest)==source PVD |

The source common flags/body variant is D1-validated before pinning; `entry_record_role` plus owner-kind alias pins which table row is live. In particular family/subtype `0x0630` alone is insufficient and may never choose manifest vs chunk. A returned BLOB manifest is decoded as manifest independently of the source alias before its body digest is compared. `manifest_key_digest`, `owner_primary_key_digest`, KEY_DIGEST, truncated identity, or request-key equality is never a substitute for the raw tuple comparison.

```text
While member value live (substep 1 success, before next get):
  expected_primary_pvd := common.primary_value_digest          # PIN 32
  expected_primary_raw/raw2/aux := S4-closed-normalize(member body, role, owner-kind/body-variant)
  expected_primary_raw_len/raw2_len/aux_len := exact lengths
  rebuild complete primary key from that same normalized tuple
  L := complete_key.length   # 0 < L ≤ 45
  peer_key[0..L) := complete_key.bytes
  peer_key_len := L
  expected_primary_owner_kind := normalized role-specific owner kind
    # phase-disjoint alias of entry_flags; entry_record_role retains family/subtype
  # dual64: pin_digest fields are NOT a substitute for this key pin;
  # they serve Mode34 membership only
exact_get(peer_key[0..L)):
  ABSENT → S4 finding
  PRESENT →
    VALUE_DIGEST(primary) == expected_primary_pvd
    S4-closed-normalize(returned primary body, entry_record_role, owner-kind/body-variant)
      == expected_primary_raw/raw2/aux + exact lengths                # byte-exact
```

`expected_primary_raw2_len=0` / `expected_primary_aux_len=0` means the applicable normalized component is absent; a role requiring that component may not use zero to skip it. `expected_primary_raw_len` is always non-zero for this path. The normalized tuple must prove the table's exact raw bijection, including dual RAW16 IDEMPOTENCY scope+key, fixed auxiliary identity, BLOB manifest owner raw, and BLOB chunk `blob_id_digest` where applicable; hash/truncated identity substitution is forbidden.

**Lifetime of primary pins:** `expected_primary_pvd`, `peer_key`, raw/raw2/aux, lengths, role and owner-kind alias are set together at substep 1 and cleared together only after substep 2 closes（member i）。next i may overwrite。

**Forbidden:** primary PVD/raw only via later S1 session; primary get then re-read member body; request-key equality as a substitute for returned-body raw comparison; digest-only “bind” when source raw was available。

Family 3/4: no common header PVD path; Mode34 index arms。

#### 18.15.7 Mode 33 CHUNK_ORPHAN / header binding

Mode33 is two **sequential same-txn zero-prefix subpasses** with at most one live iterator. `arm_cursor=0` is `RETIRED_HEADER_INVENTORY`; after its sole iterator exhausts, close/reopen without rollback and atomically move to `arm_cursor=1` `CHUNK_BIND`. The transition cannot be entered through public input or skipped. Only CHUNK_BIND exhaustion sets `binding_complete_mask.bit0` and enters COMPLETE.

**RETIRED_HEADER_INVENTORY:** enumerate every WITNESS_HEADER. ACTIVE/SUPERSEDED are locally skipped after the already-required D1 decode. Every D1-valid RETIRED header atomically sets sticky `binding_complete_mask.bit5=s6_required_seen`, even when it has **zero chunks or only a partial retained chunk set**. This subpass performs **zero `exact_get`**, does not inspect successor targets, does not walk incoming references, and does not decide retirement eligibility. Those are S5/S6 correlation duties.

**CHUNK_BIND:** for every iterated WITNESS_MANIFEST_CHUNK, copy its actual complete key into `last_carrier_key` and copy body `witness_digest`, `chunk_index`, and `chunk_count` while live. The chunk body/key local D1 check has already proved that `witness_digest` is the exact 32-byte WITNESS_HEADER **composite identity**. Build `peer_key` as current root + family6 + subtype `7f` + identity-kind COMPOSITE + identity bytes=`witness_digest`, then perform exactly one header `exact_get(peer_key)`. This is constructible from raw composite identity bytes present in the chunk body; it is not `KEY_DIGEST` reverse and does not require header operation RAW16.

| Header get/result | Exact Mode33 outcome |
| --- | --- |
| ABSENT | CORRUPT orphan chunk; it is not cleanup debris |
| ACTIVE or SUPERSEDED | header `witness_digest`/key binding exact, `header.chunk_count==chunk.chunk_count`, `chunk_index<header.chunk_count`, and expected entry count exact; otherwise CORRUPT |
| RETIRED | local header/chunk binding must still be exact; bit5 is already required by RETIRED_HEADER_INVENTORY and may be idempotently set again. S4 does not decide whether a zero/partial retained set is eligible |
| other/future/current-invalid | normal D2 precedence; unsupported only under the already-frozen recognizable-future rule, otherwise CORRUPT |

Missing expected chunks for ACTIVE/SUPERSEDED are found by Modes31/32 exact index set. RETIRED zero/partial sets are never treated as locally complete: the inventory bit requires S6. A chunk beyond a live header's count, count mismatch, or header-absent chunk is Mode33 CORRUPT. Duplicate complete chunk keys cannot coexist in one storage snapshot; duplicate member keys across different chunks are caught by §18.15.3 lex streaming.

`s6_required_seen` is preserved across header→chunk reopen, chunk advance/yield, Mode31/32 GROUP_CLOSE/pass exhaustion, and is cleared only by fresh-begin initialization, by finalize cleanup **after disposition sampling**, or by abort cleanup。Mode33 CHUNK_BIND exhaustion sets binding-complete bit0 but must not clear bit5。bit5 is a deferred composition requirement, not corruption and not permission to accept a partial RETIRED set locally。Mode33 must not add a successor `exact_get`, successor/incoming walk, or hidden retirement proof.

#### 18.15.8 Mode 34 HEAD_BACKLINK + **dual digest pins**（P0）

**`pin_digest_a` / `pin_digest_b`（32+32 = dual64 digest pair）** は membership 終了まで **独立保持**。`carrier_value_digest` 単一フィールドの上書きで両 target を兼ねることは **禁止**。

##### 18.15.8.0 Closed disjoint carrier inventory

Each current row selects **at most one** arm:

| Arm | Exact carrier set | Explicit exclusion |
| --- | --- | --- |
| **A** | current family 5/6 semantic row with non-zero common `head_witness_digest` | family6 subtype `7d` HEAD_INDEX and witness metadata `7e/7f`; any zero-head row |
| **B** | every family6 subtype `7d` WITNESS_HEAD_INDEX, BASELINE or WITNESSED | all other family5/6 rows |
| **C** | every current family3 counter or family4 capacity row | family1/2 and family5/6 |

Thus WITNESSED HEAD_INDEX is **B only**, never A+B. Family6 `7e/7f` is owned by Modes31–33/S5/S6, not by Mode34 A. Rows outside A/B/C create no Mode34 work item.

##### 18.15.8.1 Arm A — semantic family 5/6 non-zero head

```text
While carrier live:
  pin_digest_a := VALUE_DIGEST(carrier)     # membership target A expected new
  pin_digest_b := 0                         # need bit1 clear
  last_carrier_key := carrier key           # exact raw pin
  membership_key_a := last_carrier_key      # raw target A pin
  witness_digest := head
  if secondary non-zero PVD:
    pin entry_record_role + expected_primary_owner_kind/body-variant alias together with
      S4-closed-normalized source raw/raw2/aux and primary peer_key
    pin expected_primary_pvd while carrier value is live; arm_cursor := 1
  else: arm_cursor := 4
arm_cursor 1:
  exact_get(peer_key); prove PVD + returned-body raw/raw2/aux
  clear peer_key_len, expected primary raw tuple/lengths/owner-kind, and PVD
    before arm_cursor := 4
arm_cursor 4:
  forward-build header complete key into request_key_scratch; exact_get(header):
  ABSENT/RETIRED → corrupt
  ACTIVE|SUPERSEDED:
    membership_need_mask := bit0
    peer_key_len := 0                       # B target absent
    arm_cursor := 5
    MEMBERSHIP_DUAL full-M
    on hit A: entry.new_value_digest == pin_digest_a
```

##### 18.15.8.2 Arm B — every HEAD_INDEX（BASELINE+WITNESSED）

```text
While index value live:
  pin_digest_b := VALUE_DIGEST(index complete value)   # INDEX live digest PIN
  copy index body: state, member_key → membership_key_a,
                   member_key_digest → focus_key_digest,
                   member_value_digest, member_head
  last_carrier_key := index complete key               # actual B raw pin
  peer_key := rebuild HEAD_INDEX key from focus_key_digest
  require peer_key == last_carrier_key byte-exact       # body/key raw bijection
  arm_cursor := 2
arm_cursor 2:
exact_get(member = membership_key_a):
  ABSENT → corrupt
  PRESENT while member live:
    pin_digest_a := VALUE_DIGEST(member)               # SEMANTIC member digest PIN
    pin_digest_a must equal body.member_value_digest
  BASELINE: head zero; arm_cursor := 6; no membership
  WITNESSED:
    witness_digest := body.member_head
    arm_cursor := 4
    forward-build header key into request_key_scratch; exact_get(header from member_head)
    membership_need_mask := bit0|bit1
    key_a := membership_key_a; key_b := peer_key
    arm_cursor := 5
    MEMBERSHIP_DUAL:
      hit A → entry.new == pin_digest_a   # semantic member entry
      hit B → entry.new == pin_digest_b   # HEAD_INDEX entry in same manifest
```

##### 18.15.8.3 Arm C — every live family 3/4

```text
While carrier (f3/4) live:
  pin_digest_a := VALUE_DIGEST(carrier)                # SEMANTIC PIN
  last_carrier_key := carrier                          # actual A raw pin
  membership_key_a := last_carrier_key                 # raw target A pin
  focus_key_digest := KEY_DIGEST(carrier)
  peer_key := build HEAD_INDEX key(focus_key_digest)   # raw target B pin
  arm_cursor := 3
arm_cursor 3:
exact_get(index_key = build HEAD_INDEX key):
  ABSENT → corrupt
  PRESENT while index live:
    pin_digest_b := VALUE_DIGEST(index)                # INDEX live PIN
    body.member_value_digest == pin_digest_a
    body.member_key == membership_key_a byte-exact
    body.member_key_digest == focus_key_digest
    got index complete key == peer_key byte-exact
  BASELINE: body head zero; arm_cursor := 6; no membership
  WITNESSED:
    witness_digest := body.member_head; arm_cursor := 4
arm_cursor 4:
  forward-build header key into request_key_scratch; exact_get(header from witness_digest); validate live state/counts
  membership_need_mask := bit0|bit1
  key_a := membership_key_a; key_b := peer_key
  arm_cursor := 5; MEMBERSHIP_DUAL with pin_digest_a/b
```

##### 18.15.8.4 `arm_cursor` closed enum + quota=1 progress

| Value | Meaning | Successful get transition |
| ---: | --- | --- |
| **0** | SELECT next disjoint carrier | carrier install sets 1/2/3/4; no get |
| **1** | Arm A needs optional primary proof | primary get → **4** |
| **2** | Arm B needs semantic member | member get → BASELINE **6**, WITNESSED **4** |
| **3** | Arm C needs HEAD_INDEX | index get → BASELINE **6**, WITNESSED **4** |
| **4** | needs witness header | header get → **5** |
| **5** | MEMBERSHIP_DUAL active | each chunk get increments `membership_i`; after exact M close → **6** |
| **6** | current carrier complete | preserve `last_carrier_key` as global successor cursor, clear other per-carrier pins, then → **0** without get; **do not** set any arm-complete bit here |

Quota exhaustion preserves `arm_cursor`, both raw target keys, both digest pins, `membership_i`, and found counts. Every successful Mode34 get changes `arm_cursor` or increments `membership_i`; with quota=1 a completed member/index/header/primary/chunk get is never re-issued. Invalid cursor 7..255 is CORRUPT/terminal with Port 0.

For cursor 4/5 requests, set `request_key_scratch_len` immediately before the synchronous `exact_get` and clear it immediately after return（success, ABSENT, or Port failure）after the Port has consumed the request bytes. The borrowed returned value has its separate 4096-byte lifetime, so clearing request length does not invalidate response decoding.

Mode34 owns one global full-domain iterator. At `arm_cursor=0`, it resumes strictly after `last_carrier_key`, selects every eligible A/B/C carrier in complete-key lexicographic order, and skips only rows outside §18.15.8.0. `arm_cursor=6` closes one carrier only. Only a successful iterator-exhaustion transition with `arm_cursor=0` and no live carrier proves the whole disjoint inventory exhausted; that transition atomically sets `count_complete_mask.bit2` and `binding_complete_mask.bits1|2|3|4`. Bits1/2/3 therefore include a vacuously empty arm. A bootstrap snapshot with Arm A empty and valid B/C rows can complete; observing one carrier, one arm, or an arm-boundary can never set a global completion bit.

##### 18.15.8.5 MEMBERSHIP_DUAL full-M

Every Arm A/B/C WITNESSED header get that enters `MEMBERSHIP_DUAL` independently installs `member_count=M`, `chunk_count=C`, and `expected_manifest_digest` while that header value is live, checks `C=ceil(M/8)`, and initializes the context SHA state. This proof belongs to the **current Mode34 READ_ONLY transaction**. A prior Mode31/32 result, cached manifest result, or another-session snapshot is not a substitute.

For each ordinal `i`, the requested chunk key is built from the installed header's raw `witness_digest` and **exact index `floor(i/8)`**. The returned D1-valid chunk must additionally match that requested witness/index, installed `C`, and the exact non-final/final entry count from §18.15.3 before its slot is consumed. ABSENT, a returned index other than `floor(i/8)`, count/framing mismatch, or missing slot is CORRUPT. Re-getting the same chunk produces the same returned index for up to eight consecutive ordinals and is **required/合法**, not a duplicate finding. A duplicate-index mutation means only: (a) the returned index repeats after the ordinal crosses a chunk boundary and the requested `floor(i/8)` advanced, (b) an iterator yields a duplicate complete chunk row/key, or (c) a returned index mismatches the current requested `floor(i/8)`; skip at a boundary is equally CORRUPT. Since one chunk is re-fetched for each member, the exact encoded chunk body is fed to SHA only on `i%8==0`. Strict `membership_i` progress from 0 through M proves every expected index `0..C-1` was visited; duplicate complete Storage keys cannot coexist, and Mode33 independently owns extra/orphan chunk detection. The no-get close substep requires `membership_i==M`, the implied visited chunk count exactly `C`, and final SHA equal to the pinned `expected_manifest_digest` before evaluating target found-counts.

```text
found_count_a/b := 0; membership_i := 0; membership_substep := 0
need := membership_need_mask
key_a := membership_key_a; key_b := peer_key
For i = 0 .. M-1  (full M; early exit forbidden):
  quota yield preserves membership_i + found_count_* + pin_digest_a/b + key_a/b
  forward-build chunk key into request_key_scratch; exact_get(chunk[i/8]); used++
  require returned chunk witness/index/count/framing
    == installed witness / floor(i/8) / C / exact entry count
  if i%8 == 0: SHA_feed(exact encoded chunk body)       # exactly once/chunk
  entry := slot i%8
  if need bit0 and keys_equal(entry, key_a):
    found_count_a = min(2, found_count_a+1)
    if found_count_a==1 and entry.new != pin_digest_a → corrupt
  if need bit1 and keys_equal(entry, key_b):
    found_count_b = min(2, found_count_b+1)
    if found_count_b==1 and entry.new != pin_digest_b → corrupt
After M: require membership_i==M, exact C visited, SHA_final==expected_manifest_digest
  require found_count_x==1 for each need bit (0=missing, ≥2=duplicate)
  then arm_cursor := 6
```

Get budget membership: **exactly M** chunk re-gets。

#### 18.15.9 Exact get-budget table

| Situation | exact_gets |
| --- | --- |
| **31/32** per header | **2M+P** = M chunk + M member + P primary（0≤P≤M） |
| **33** | RETIRED_HEADER_INVENTORY = 0 gets/header; CHUNK_BIND = 1 header get/chunk row |
| **34 arm A** | ≤1 primary + 1 header + **M** membership |
| **34 arm B BASELINE** | 1 member |
| **34 arm B WITNESSED** | 1 member + 1 header + **M** |
| **34 arm C BASELINE** | 1 index |
| **34 arm C WITNESSED** | 1 index + 1 header + **M** |

#### 18.15.10 Precedence / finalize gates

| Gate | Exact |
| --- | --- |
| Traversal complete | phase COMPLETE + current mode required masks + no sticky corruption + INTERNAL done（or a proved vacuous-empty inventory） |
| COMPLETE_READY | traversal complete + `flags.bit7==0` + `binding_complete_mask.bit5==0`; set `flags.bit3=1` |
| DEFERRED_READY | traversal complete + at least one of `flags.bit7` / `binding_complete_mask.bit5`; `flags.bit3` **must remain 0** |
| Finalize result | COMPLETE_READY and DEFERRED_READY both sample the private disposition below, perform normal cleanup, publish one complete private result with a single commit-style copy, and return `NINLIL_OK`; a deferred disposition is **not D3 success** until the named S5/S6 composition succeeds |
| Incomplete masks / mid-yield | finalize → INVALID_STATE Port 0; no cleanup |
| Evaluator-off | baseline candidate only; both READY shapes forbidden; finalize follows the frozen D2 unsupported/corrupt aggregate path and publishes canonical `d3s4_disposition_present=0`, `d3s4_disposition=0` only when cleanup succeeds |
| Sticky terminal | further d3s4_drive → INVALID_STATE Port 0 |
| Cleanup | iter_close → rollback → optional fence → DONE |

The private finalize disposition is derived entirely from existing sticky bits; it is not another context field: **0 LOCAL_COMPLETE** (`bit7=0, bit5=0`), **1 S5_REQUIRED** (`1,0`), **2 S6_REQUIRED** (`0,1`), **3 S5_AND_S6_REQUIRED** (`1,1`). The local (`1,1`) shape is valid in **Mode31 or Mode32 only** when one or more `SUPERSEDE_WITNESS` members progressed to same-successor RETIRED or ABSENT predecessor candidates; Mode31 otherwise cannot set either deferred bit, while Mode32 may also produce `(1,0)` for its ordinary successor proof. Mode33 may produce only `(0,1)` and Mode34 only `(0,0)`; any other local shape is INVALID_STATE. A higher D3 composition accumulator may also combine dispositions 1 and 2 into 3. Invalid enum/MBZ/mode-bit shape or sticky corruption is never converted to a deferred result.

**Closed private result carrier（implementation-required）:** append the following exact declaration-order fields after `ninlil_domain_scan_result_t.family14_iter_seen_mask`; do not add them to a public ABI/wire/storage type and do not use `packed`.

```c
uint8_t d3s4_disposition_present; /* exact 0 or 1 */
uint8_t d3s4_disposition;         /* present=1: exact 0..3; present=0: exact 0 */
```

`present=1, disposition=0` is LOCAL_COMPLETE and is observably different from `present=0, disposition=0`（no D3-S4 disposition）。`present=0` with non-zero disposition, `present>1`, or `present=1` with disposition>3 is invalid and may never be published. Higher D3 composition accepts a disposition **only when the finalize call returned `NINLIL_OK` and `d3s4_disposition_present==1`**; it ignores both bytes on every non-OK status and ignores `d3s4_disposition` when present is zero. Thus evaluator-off, failed traversal, abort, or cleanup failure cannot accidentally contribute LOCAL_COMPLETE.

**Output/cleanup mutation matrix（the whole `ninlil_domain_scan_result_t`, including padding, is the output unit）:**

| Call/path | Port calls | `out_result` | S4 context/session |
| --- | ---: | --- | --- |
| finalize, evaluator-on READY, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=1`, disposition exact 0..3; return `NINLIL_OK` | sample disposition to a scalar before cleanup; after publish, zero entire S4 context and finish DONE |
| finalize, evaluator-off frozen aggregate, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=0`, disposition=0; return frozen aggregate status | after publish, zero entire S4 context and finish DONE |
| finalize from FAILED, cleanup success | cleanup tree | publish diagnostics with `present=0`, disposition=0 and the sticky non-OK status | after publish, zero entire S4 context and finish DONE |
| finalize, any cleanup failure | cleanup tree/fence as required | **all bytes unchanged** from caller poison; sampled disposition is discarded | zero entire S4 context after Port cleanup; finish terminal DONE/reopen-required authority in session |
| abort from legal OPEN/EXHAUSTED/FAILED | cleanup tree/fence as required | **all bytes unchanged**, regardless of cleanup outcome | zero entire S4 context after Port cleanup; finish terminal DONE |
| NULL, output alias, invalid state, incomplete masks/mid-yield, invalid enum/MBZ/mode shape | **0** | **all bytes unchanged** | session/context/workspace unchanged |

Prevalidation checks all required pointers/state/shape and requires the complete result range to be disjoint from the session, bound workspace, bound ops object, bound handle slot, and bound S4 context **before** any Port call, output write, or cleanup. On a publishable path, construct a zero-initialized local `ninlil_domain_scan_result_t candidate`, fill every legacy field plus the two carrier bytes, and perform exactly one non-overlapping full-object copy to `out_result` only after cleanup succeeds. The exact order is: **derive/sample scalar disposition → Port cleanup outcome → build/publish complete output → zero S4 context**. Cleanup failure and abort perform no candidate publication. This deliberate D3-S4 rule is stricter than the pre-S4 generic abort/direct-publication implementation and must be applied when S4 is bound.

**Private-result size/stack accounting:** the current host layout is named bytes through offset 51, natural `sizeof=56`, alignment 8. Appending the two `uint8_t` fields at declaration offsets **52/53** consumes two existing tail-padding bytes on that host, so host `sizeof` remains **56**（2 tail-padding bytes remain）。The logical result payload grows by exactly 2 bytes. Target ABI padding is not assumed: implementation must `_Static_assert(sizeof(ninlil_domain_scan_result_t) <= 64)` and record host plus ESP32-S3 target `sizeof`/alignment in the implementation oracle; an align-4 target may grow from 52 to 56（worst current-to-new object delta 4）。The caller-owned Stage5 local therefore remains 56 on the measured host and is bounded by 64 on target. Commit-style candidate publication adds at most **64 bytes** of finalize function stack; no record/value buffer is placed there. This result is caller output/temporary, not part of the S4 context or co-resident D3 arena, so S4 **949/960**, outer **10880**, and packed aggregate arithmetic remain unchanged. ESP task-stack sizing/high-water verification must include the +64-byte finalize temporary. The single copy is a publication boundary for this non-concurrent private call contract, not a C11 lock-free atomicity claim.

#### 18.15.11 Honest cost

| Mode | Baseline | Internal | Session |
| ---: | --- | --- | --- |
| 31/32 | **Θ(N)** | **Θ(N + Σ(2M+P))**（header selection full scan + gets） | **Θ(2N+Σ(2M+P))** |
| 33 | **Θ(N)** | **Θ(2N + N_chunk)**（header inventory full scan + chunk bind full scan + one get/chunk） | **Θ(3N+N_chunk)** |
| 34 | **Θ(N)** | **Θ(N + N_arm + Σ M_grp)** | **Θ(2N+…)** |

D3-S4 complete = **4 × baseline + every internal full scan/get walk**；`Θ(4N+W)` の `W` は上表の追加 full-domain scans と exact-get/member workをすべて含む。internal scanをhideして `W=members only` とすることは **forbidden**。

#### 18.15.12 Fixed S4 context layout（sizeof **949** / align 1 / ceiling **960**）

| Offsets | Size | Field |
| ---: | ---: | --- |
| 0..44 | 45 | `last_carrier_key` |
| 45 | 1 | `last_carrier_key_len` |
| 46..77 | 32 | `witness_digest` |
| 78..79 | 2 | `member_count` u16 BE |
| 80..81 | 2 | `chunk_count` u16 BE |
| 82..83 | 2 | `streamed_members`（FOCUS next i） |
| 84..85 | 2 | `membership_i` |
| 86..117 | 32 | `expected_manifest_digest` |
| 118..149 | 32 | `focus_key_digest` |
| 150..181 | 32 | **`pin_digest_a`**（membership/semantic expected new） |
| 182..213 | 32 | **`pin_digest_b`**（membership/index expected new; dual64 pair with a） |
| 214..245 | 32 | `entry_old_value_digest` |
| 246..277 | 32 | `entry_new_value_digest` |
| 278..309 | 32 | `entry_prior_head_witness_digest` |
| 310..341 | 32 | **`expected_primary_pvd`** |
| 342..596 | 255 | phase-disjoint **`expected_primary_raw` / `request_key_scratch`**（raw contents / complete request; max 255） |
| 597..660 | 64 | **`expected_primary_raw2`**（S4 closed-normalized second raw; max 64） |
| 661..676 | 16 | **`expected_primary_aux`**（S4 closed-normalized fixed auxiliary identity; max 16） |
| 677..678 | 2 | phase-disjoint **`expected_primary_raw_len` / `request_key_scratch_len`** u16 BE（0..255） |
| 679 | 1 | **`expected_primary_raw2_len`**（0..64） |
| 680 | 1 | **`expected_primary_aux_len`**（0..16） |
| 681..725 | 45 | `prev_member_key` |
| 726 | 1 | `prev_member_key_len` |
| 727..771 | 45 | `peer_key`（primary-liveではcomplete primary key） |
| 772 | 1 | `peer_key_len` |
| 773..817 | 45 | `membership_key_a` |
| 818 | 1 | `membership_key_a_len` |
| 819..850 | 32 | `sha_state` |
| 851..858 | 8 | `sha_bitcount` |
| 859..922 | 64 | `sha_block` |
| 923 | 1 | `sha_block_len` |
| 924 | 1 | `entry_action` |
| 925 | 1 | `entry_old_present` |
| 926 | 1 | `entry_new_present` |
| 927 | 1 | `entry_flags` / phase-disjoint **`expected_primary_owner_kind`** |
| 928 | 1 | `group_class` |
| 929 | 1 | `phase` |
| 930 | 1 | `pass_kind` |
| 931 | 1 | `flags` |
| 932 | 1 | `count_complete_mask` |
| 933 | 1 | `binding_complete_mask` |
| 934 | 1 | `focus_mode` |
| 935 | 1 | `arm_cursor` |
| 936 | 1 | `membership_need_mask`（bit0 A; bit1 B） |
| 937 | 1 | `found_count_a`（0..2 sat） |
| 938 | 1 | `found_count_b` |
| 939 | 1 | **`member_substep`**（0 chunk / 1 member / 2 primary / 3 done） |
| 940 | 1 | **`membership_substep`** |
| 941..942 | 2 | `drive_get_quota` u16 BE |
| 943..944 | 2 | `drive_gets_used` u16 BE |
| 945..946 | 2 | `entry_record_role` u16 BE |
| 947..948 | 2 | `entry_key_length` u16 BE |
| **Σ** | **949** | |
| ceiling | **960** | headroom **11** |

**flags:** bit0 baseline_done; bit1 focus_live; bit2 bind_phase_active; bit3 complete_ready; bit4 need_resume; bit5 header_installed; bit6 manifest_sha_open; bit7 **s5_required_seen**。All eight bits are assigned; no flag bit is MBZ.

**Exact state-byte / bit ownership（no hidden booleans）:**

| Byte | Bits / values |
| --- | --- |
| `phase` | 0 IDLE; 1 BASELINE; 2 SELECT; 3 MEMBER_PIPELINE; 4 GROUP_CLOSE; 5 MODE33_BIND; 6 MODE34_ARM; 7 COMPLETE; 8 FAILED; 9..255 invalid |
| `pass_kind` | 0 PASS_BASELINE; 1 PASS_INTERNAL; 2..255 invalid |
| `focus_mode` | 0 only before begin / after cleanup; 31,32,33,34 only while active; 1..30 and 35..255 invalid |
| `flags` | bits0..7 exactly as the preceding paragraph; `bit3` only COMPLETE_READY, never DEFERRED_READY |
| `group_class` | 0 UNSET; 1 ALL_NEW; 2 ALL_OLD; 3 MIXED_OLD_NEW; 4 PROGRESSED_S5_REQUIRED; 5 CORRUPT; 6..255 invalid |
| `flags.bit7` | sticky within Mode32 once any header/member requires successor proof; in Mode31 it may be set only atomically with bit5 by `SUPERSEDE_WITNESS` RETIRED/ABSENT progression; preserved across carrier reset/GROUP_CLOSE/pass exhaustion/yield; clear only by fresh-begin initialization, finalize cleanup after disposition sampling, or abort cleanup |
| `count_complete_mask` | bit0 Mode31 all-header/group pass complete; bit1 Mode32 all-header local pass complete; bit2 Mode34 carrier enumeration complete; bits3..7 MBZ |
| `binding_complete_mask` | bit0 Mode33 RETIRED-header inventory then all chunks bound/deferred exactly; bits1/2/3 Mode34 global pass proved Arm A/B/C exhausted（empty included）; bit4 all three exhaustion bits set; bit5 sticky `s6_required_seen`（Mode31/32 SUPERSEDE progression or Mode33 RETIRED inventory）; bits6..7 MBZ |
| `arm_cursor` | Mode33: 0 RETIRED_HEADER_INVENTORY, 1 CHUNK_BIND only; Mode34: exact 0..6 from §18.15.8.4; Modes31/32: 0 only; every other mode/value combination invalid |
| `member_substep` | exact 0..3 from §18.15.5; 4..255 invalid |
| `membership_substep` | 0 NEED_CHUNK, 1 CLOSE; 2..255 invalid |
| `membership_need_mask` | bit0 target A, bit1 target B; values 0..3 only; bits2..7 MBZ |
| `found_count_a/b` | saturating exact values 0,1,2; 3..255 invalid |
| `entry_action` | 0 NONE/cleared; 1 CREATE; 2 REPLACE; 3 ERASE; 4 SUPERSEDE_WITNESS（§10.1）; 5..255 invalid |
| `entry_old_present` / `entry_new_present` | each exact 0 or 1; 2..255 invalid |
| `entry_flags` | ordinary manifest scratch: 0; while aliased for HEAD_INDEX: 1 BASELINE, 2 WITNESSED; while primary-live: `expected_primary_owner_kind` is the exact S4 normalization-table alias（Mode17 row owner kind、BLOB manifest kind 1..3、BLOB chunk 0）; the three lifetimes are disjoint and the byte is cleared with its owner |
| `entry_record_role` | 0 when no entry/carrier role is live; while entry scratch or primary proof is live, high byte = key family and low byte = subtype for family5/6 or zero for family3/4, exactly as §10.1; mismatch/other value invalid。Primary close clears it |
| `entry_key_length` | while entry-key scratch is live, exact 10 for family3/4 or 13..45 satisfying the actual family5/6 key grammar; it is cleared after member get even when `entry_record_role` remains for primary normalization。Other values invalid（255 remains wire capacity, not an acceptance range） |
| key-length fields | each matching key/raw length is 0 iff that pin/scratch component is absent; otherwise within its declared array and applicable complete-key/raw grammar。primary-live requires `peer_key_len=13..45`, `expected_primary_raw_len=1..255`, raw2 ≤64, aux ≤16 and role-specific presence; request-live requires raw2/aux lengths zero。length/data disagreement invalid |
| `sha_block_len` | 0..63 while SHA is open; 64..255 invalid |
| `drive_get_quota` / `drive_gets_used` | quota exact 1..256 while driving; used 0..quota; used>quota, quota 0, or quota>256 invalid |

At `begin_profiled_d3s4`, all state/masks/pins are zero, then `focus_mode` is installed and phase enters BASELINE. SELECT_HEADER resets per-header `group_class`, member/SHA/entry scratch and counts but preserves flags.bit7, binding bit5, and mode completion masks. SELECT arm resets `arm_cursor`, membership need/found/i/substep, raw targets, digest pins, and primary pins for that carrier only（Mode33's subpass cursor is not an Arm reset）。Mid-yield preserves every field. Mode33 header-inventory exhaustion alone advances cursor and reopens; only subsequent chunk-bind exhaustion sets bit0. Mode34 carrier close does not write completion bits; only global iterator exhaustion performs the atomic completion transition in §18.15.8.4. Mode pass exhaustion sets the applicable count/binding completion bits, then phase becomes COMPLETE. COMPLETE can be either COMPLETE_READY or DEFERRED_READY under §18.15.10. Any invalid/MBZ value is terminal corruption before readiness derivation. Finalize samples the derived disposition first; on cleanup-success finalize it publishes the complete result before zeroing the entire S4 context, while abort/cleanup-failure publishes nothing; every terminal cleanup zeros that context after Port cleanup（§18.15.10）。

**Pass-scoped raw inventory / aliases（closed; simultaneous dual raw is explicit）:**

| Pass | Raw field ownership |
| --- | --- |
| Modes31/32 member stream | `prev_member_key` = previous ordinal key for global lex check; before substep-0 get, `peer_key` = forward-built chunk request, then after successful get it is overwritten by current decoded entry key scratch; after substep-1 member get it may be overwritten again by the complete primary key（≤45）。`entry_*` = current entry action/presence/digests/role/length. Current entry key is copied before chunk value dies. |
| Mode31/32 primary proof | `peer_key[45]+len` = complete primary key rebuilt while member body is live; `expected_primary_raw[255]` + `raw2[64]` + `aux[16]` + lengths = same member's S4-closed-normalized source tuple; `expected_primary_pvd` = same member's live PVD; `entry_record_role` + `entry_flags` owner-kind/body-variant alias select the exact returned-primary normalization, including BLOB manifest/chunk. |
| Mode33 | header inventory retains no per-header raw after each row and only sets bit5; chunk bind uses `last_carrier_key` = actual chunk complete key, `witness_digest` = chunk composite identity, `peer_key` = forward-built WITNESS_HEADER complete key. |
| Mode34 Arm A | `last_carrier_key` = actual semantic carrier raw/global iterator successor; `membership_key_a` = exact copied target A raw; `peer_key_len=0` because B is absent except while an optional primary proof is live. A non-zero primary PVD uses `peer_key` + expected raw/raw2/aux only until cursor 1 closes. |
| Mode34 Arm B | `membership_key_a` = index-body member raw target A; `last_carrier_key` = actual HEAD_INDEX raw; `peer_key` = forward rebuilt HEAD_INDEX raw target B; rebuilt B must byte-equal `last_carrier_key`. |
| Mode34 Arm C | `last_carrier_key` and `membership_key_a` = actual family3/4 raw target A; `peer_key` = forward-built HEAD_INDEX raw target B. Index body raw must bind both. |
| Mode34 request key | the 255 bytes at offsets 342..596 and u16 at 677..678 are named `request_key_scratch` / `_len` only when no primary raw tuple is live. Header/chunk complete request keys are forward-built there immediately before each `exact_get`; the request length is cleared immediately after that call. It is distinct from simultaneous live `last_carrier_key`, `membership_key_a`, and `peer_key`; raw2/aux lengths must be zero in request-live shape. |

`membership_key_a` and `peer_key` are live together from header proof through all M membership entries in Arm B/C. Neither may alias the borrowed 4096 value, the 255-byte primary-raw/request slot, or the other raw target. `expected_primary_raw` and `request_key_scratch`（including their phase-disjoint length name）must never be live simultaneously. Primary-live shape is exactly member_substep 2 or Mode34 arm_cursor 1 with non-zero expected PVD, `peer_key_len`, primary raw length and role-specific optional raw2/aux lengths; request-live shape is the synchronous Mode34 exact-get call at cursor 4/5 with no primary-live shape. No hidden alias-live boolean exists. `entry_new_value_digest` temporarily holds HEAD_INDEX `member_value_digest`; `entry_flags` holds `index_state` outside primary-live and `expected_primary_owner_kind` only during primary-live; `witness_digest` holds `member_head_witness_digest`. Each alias is assigned while its source value is live and cleared at the named close.

**Pin lifetimes:**

| Pin | Set when | Valid until |
| --- | --- | --- |
| `expected_primary_pvd` / `peer_key` / primary raw+raw2+aux tuple / role+owner-kind | member PRESENT substep 1 | primary substep 2 close; all clear together |
| Arm A primary PVD / `peer_key` / raw+raw2+aux tuple / role+owner-kind | carrier install while value is live | cursor 1 close; all clear before cursor 4 |
| `request_key_scratch` / `_len` | immediately before a Mode34 header/chunk `exact_get`, only with no live primary pin | that exact_get returns; clear length and rebuild for every later request |
| `pin_digest_a` / `pin_digest_b` | arm install / forward known-key gets | MEMBERSHIP_DUAL close for that carrier |
| Mode34 `expected_manifest_digest` / M / C / SHA state | live ACTIVE/SUPERSEDED header get immediately before MEMBERSHIP_DUAL | same-transaction full-M close after exact framing/index-set/final-SHA proof |
| entry action/presence/digest/key-length scratch | chunk substep 0 | member substep 1 consume; `entry_record_role` and owner-kind alias alone remain when a primary proof follows |

**Required exact masks by session:** Mode31 → count bit0 only; normally deferred bits zero, but a `SUPERSEDE_WITNESS` same-successor RETIRED/ABSENT progression requires exactly `(bit7,bit5)=(1,1)` and no other binding bit。Mode32 → count bit1 only, binding completion bit0/1..4 zero, `flags.bit7` mandatory after every non-corrupt group（vacuous empty inventory may leave it zero）, and binding bit5 optional only for the same progression; `(1,1)` means S5_AND_S6_REQUIRED。Mode33 → count zero, binding bit0 plus optional deferred bit5 S6, `flags.bit7=0`; Mode34 → count bit2 + binding bits1|2|3|4 exactly, deferred bits zero. Mode34 writes its five completion bits only on global iterator exhaustion. A mode never writes another mode's completion bit; extra completion/deferred bits、Mode31 `(1,0)` / `(0,1)`、or Mode33/34 `(1,1)` make the shape invalid. Deferred bits are composition authority, not substitutes for required masks.

**key_b:** rebuild HEAD_INDEX complete key into `peer_key` from `focus_key_digest` before the borrowed carrier/index value is overwritten; retain it through MEMBERSHIP_DUAL（pure; not a second 255 array）。

#### 18.15.13 Memory ceilings（S3 **768** fixed from main）

| Object | Ceiling |
| --- | ---: |
| scanner / Stage5-alone | **8192** / **8704** unchanged |
| S1 / S2 | **448** / **320** unchanged |
| S1+S2 | **9152** unchanged |
| S3（§18.14 main） | **754 / 768**; outer **9920** |
| **S4** | sizeof **949** / ceiling **960** |
| private scan result | host **56** before/after two-byte append; target ceiling **64**; finalize temporary stack ≤**64**; not in arena |
| S1+S2+S4 | **10112** = 8384+448+320+960 |
| **S1+S2+S3+S4 full** | **10880** = 8384+448+320+768+960 |

Packed full: `8384+421+306+754+949=10814`；align8 **10816** ≤ **10880**。
Packed S1+S2+S4: `8384+421+306+949=10060`；align8 **10064** ≤ **10112**。

dual-bound **forbidden**。Stage5 no D3 bind until S12。

#### 18.15.14 Private API（contract names only）

| API | Rule |
| --- | --- |
| `begin_profiled_d3s4` | mode 31..34; ctx ≤**960**; disjoint; not dual-bound |
| `d3s4_drive` / advance | enforce quota; **substep progress**; mid yield |
| finalize/abort | §18.15.10 exact private carrier, whole-output publication/poison, cleanup, alias and zero order |
| Stage5 until S12 | no begin_d3s4 |

#### 18.15.15 Oracle architecture / constructible positives / anti-false-pass

The implementation change set shall add the append-only authority format **`ninlil-domain-scan-crossrow-v1-d3s4`**. It retains the D3-S1 exact 94-vector prefix and the then-current D3-S2/D3-S3 prefix byte-for-byte; this docs-only freeze does **not** edit the existing JSON. An independent deterministic generator, separate from production scanner control flow, must emit both (a) Port fixture records/scripts and (b) the expected per-drive state transition, exact-get key sequence, masks, disposition, and terminal result. The production bridge must run those generated scripts through the private D3-S4 implementation; a hand-authored C-only positive oracle that can drift independently is insufficient.

Minimum constructible positive catalog:

1. Mode31, `M=1`, ACTIVE, all-new, zero primary PVD → `LOCAL_COMPLETE`.
2. Mode31, `M=2`, one present secondary with non-zero primary PVD, `drive_get_quota=1` → exact chunk/member/primary/done cursor sequence, byte-exact primary raw/raw2/aux + PVD proof, no repeated get. A companion fixture uses a test digest oracle that makes source raw A and returned primary raw B derive the **same complete key and PVD**; raw tuple mismatch still produces a finding.
3. The S4 primary-normalization table is **closed-set covered**, not sampled: every imported Mode17 source role/owner-kind, dual-raw and aux-bearing shape, BLOB manifest owner kinds 1/2/3, and BLOB chunk→manifest has a constructible positive. BLOB manifest positives prove returned TRANSACTION_ANCHOR 16 / ORDERED_INGRESS BE8 / DELIVERY raw80 identity; the chunk positive proves forward manifest-key rebuild, returned manifest flags=1/body `blob_id_digest`, and PVD. At least one BLOB path is driven through Mode31 and one through Mode34 Arm A so neither caller may skip the shared normalizer.
4. Mode31 ACTIVE successor with a `SUPERSEDE_WITNESS` predecessor that is (a) same-successor RETIRED and (b) fully ABSENT with no orphan chunk: every ordinary semantic member remains ALL_NEW, both sticky bits are set atomically, and finalize returns `S5_AND_S6_REQUIRED` rather than CORRUPT/local complete.
5. Mode32 ALL_NEW with valid successor field, and separately a progressed different-head member → `S5_REQUIRED`, never COMPLETE_READY/local D3 success. A `SUPERSEDE_WITNESS` whose predecessor is same-successor RETIRED and a fully-ABSENT predecessor candidate each set both bits and finalize `S5_AND_S6_REQUIRED` locally（S5/S6 correlation still pending）。
6. Mode33 exact ACTIVE and SUPERSEDED header binds → `LOCAL_COMPLETE`; RETIRED header inventory with (a) zero chunks and (b) only a strict prefix of declared chunks → `S6_REQUIRED` with bit5 preserved through header→chunk reopen and exhaustion. A RETIRED header with an incoming-reference fixture still produces the same deferred S6 authority（S4 performs no incoming walk; S6 later rejects/accepts）。
7. Mode34 valid bootstrap: Arm A empty, fifteen BASELINE Arm-B indexes and fifteen family3/4 Arm-C carriers → global exhaustion atomically proves empty A plus B/C and completes.
8. Mode34 WITNESSED B/C pair has two positive fixtures: **M=2/C=1** returns chunk index sequence `[0,0]`; **M=9/C=2** returns `[0,0,0,0,0,0,0,0,1]`. Both prove that within-chunk repeated returned indexes are required/合法, each requested/returned index is exact `floor(i/8)`, SHA feeds at ordinals 0 and（for M=9）8 only, both raw targets and distinct `pin_digest_a/b` are found exactly once, and final framing/SHA close succeeds.
9. Mode34 Arm A with non-zero primary PVD → primary raw/PVD pin closes before the same bytes become header/chunk request scratch, followed by successful same-transaction membership + manifest proof.
10. A Mode32 session returning S5_REQUIRED plus a Mode33 session returning S6_REQUIRED → higher composition accumulator yields `S5_AND_S6_REQUIRED`; separately, Mode31 and Mode32 SUPERSEDE progression fixtures each return disposition 3 directly. Neither sticky bit is lost at carrier/pass close.
11. Finalize output carriers include evaluator-on LOCAL_COMPLETE as exact `(present,disposition)=(1,0)`, each deferred value `(1,1..3)`, and evaluator-off as exact `(0,0)`. Higher composition consumes only status `NINLIL_OK` + present 1. Every fixture starts the whole output object as non-zero poison and proves one full-object publication only on a cleanup-success finalize.

Each positive fixture must be materialized, reproducible from a pinned seed/version, and self-check its expected get keys against keys independently reconstructed from fixture raw fields. CI must reject stale generated output, changed prefix vectors, duplicate vector IDs, nondeterministic regeneration, or a production result/state trace differing from the generated expectation.

Minimum negative/mutation catalog:

1. Primary get with only derived key/PVD pin, including a same-key+same-PVD collision fixture whose returned body differs in **exactly one** of raw bytes、raw2 bytes、aux bytes、each corresponding length、source role、or owner-kind/body-variant alias → **must fail**。Required raw2/aux may not be converted to zero-length skip.
2. BLOB manifest wrong owner kind/raw/returned primary type、BLOB chunk treated as manifest、wrong source/returned `blob_id_digest`、returned flags≠1、KEY_DIGEST-only/request-key-only comparison、or chunk PVD not compared with returned manifest VALUE_DIGEST → **must fail**.
3. Arm B membership compares the index entry with `pin_digest_a` → **must fail**（wrong target digest）.
4. Arm C omits `pin_digest_b` or reuses `pin_digest_a` for index → **must fail**.
5. `quota=1` re-gets the same chunk without substep advance → **must fail**.
6. Dual first-hit early exit → **must fail**.
7. Per-carrier close sets an Arm completion bit, or empty Arm A prevents global completion → **must fail**.
8. Mode33 skips RETIRED_HEADER_INVENTORY, misses a RETIRED zero/partial-chunk header, loses bit5 at subpass transition/exhaustion, performs successor/incoming exact-get/walk, or finalize reports local complete → **must fail**.
9. Header/chunk request scratch overwrites a live primary or either live raw membership target → **must fail**.
10. Any invalid enum/MBZ bit, incomplete required mask, or COMPLETE_READY with a deferred bit → **must fail**.
11. Mode31 or Mode32 same-successor RETIRED/ABSENT SUPERSEDE progression sets only S5 or only S6, treats `(1,1)` as invalid, accepts ACTIVE/different-successor, or locally proves retirement eligibility → **must fail**.
12. Mode31 accepts ordinary semantic OLD/NEITHER/progression under the SUPERSEDE exception, or returns deferred for a group with no progressed `SUPERSEDE_WITNESS` → **must fail**.
13. Mode34 accepts a prior Mode31/32 result instead of its own manifest proof, or misses a mutation of header `manifest_digest`, returned chunk `witness_digest`/count/entry-count, missing expected chunk/slot, or final SHA → **must fail**. Returned-index mutations are exact: at the M=9 boundary request `floor(8/8)=1`, returning 0 is a boundary repeat; returning 2 is a skip/mismatch; an iterator duplicate of the complete index-0 or index-1 row/key is corrupt/orphan inventory; any ordinal whose returned index differs from requested `floor(i/8)` fails. The legal M=2 `[0,0]` and M=9 first-eight `[0×8]` sequences must **not** fail as duplicates.
14. Prior 2M / BASELINE stale / orphan / incomplete-finalize cases remain, and all four sessions independently prove their baseline Θ(N) pass.
15. Whole-result poison tests prove abort（cleanup success and failure）、finalize cleanup failure、NULL/alias/prevalidation/invalid-state/incomplete-shape all leave every output byte unchanged. Alias mutations cover overlap with session, workspace, ops, handle slot, and bound S4 context. Invalid carrier combinations `(present>1)`, `(present=0, disposition!=0)`, and `(present=1, disposition>3)` are never published; a non-OK or present-0 result is never composed.

#### 18.15.16 Mutation / D4 boundary

Snapshot finding **S4**; chain **S5**; retire **S6**; commits **D4**。

#### 18.15.17 Explicit exclusions

| Exclusion | |
| --- | --- |
| Primary raw/key only via S1 session | forbidden |
| Single carrier_value_digest for dual membership targets | forbidden |
| quota=1 infinite same-get loop | forbidden |
| Chunk borrow; C+M fiction; dual first-hit | forbidden |
| public ABI/wire/D1 change | not this freeze |

#### 18.15.18 Completion boundary / non-claims

| Claim | |
| --- | --- |
| D3-S4a Normative freeze §18.15（S4 closed primary raw/raw2/aux pins incl. BLOB; Mode31/32 SUPERSEDE progression; dual digest pins; Mode33 RETIRED inventory; Mode34 same-txn manifest proof + legal within-chunk re-get; closed private result carrier/publication; substep progress; 949/960; full outer 10880） | **yes** |
| S3a §18.14 main-equivalent 754/768/9920 | **preserved** |
| S4 / D3 / Stage5 / Runtime / ESP implementation | **no** |
| Crossrow d3s4 JSON | **no** |

S4a を implementation complete へ書き換えない。S0/S1a/S2a/S3a historical は **preserve**。

### 18.16 Normative D3-S5a freeze（DSW2_SUPERSEDE_CHAIN / successor chain bounded walk）

**Decision identifier: D3-S5a。** 本節は D3-S0 / S1a / S2a / S3a（§18.14）/ **S4a（§18.15）** を **上書きせず**、§10.1 **`DSW2_SUPERSEDE_CHAIN`** の **docs-only Normative freeze** を追加する。§18.15（S4: **949/960**, outer **10880**）は **origin/main と byte-equivalent に保持**。**docs only**（code/tests/CMake/JSON/ADR 0）。implementation / D3 / Stage5 / D4 / public Runtime / ESP / hardware **pending**。private symbol 存在 **未 claim**。

**Design choice:** 1 session = 1 mode = **Mode35**; **k₅=1**; single `READ_ONLY` txn; **single 4096**; fixed S5 context; no full-ID set; no heap/VLA/second 4096/two-txn list-prove。**retire/cleanup physical erase truth → S6; mutation → D4**。Mode35 は SUPERSEDED header ごとに successor exact_get + successor manifest SUPERSEDE_WITNESS entry full-M 検証 + **bounded chain walk（cycle detection）** を行う。各 get 後の cursor progress を本節だけで閉じる。

**ACTIVE successor-zero は S5 scope 外:** ACTIVE header の `successor_witness_digest==zero` は §10.1 の header-local same-record invariant であり、§18.6 が D1/D2-S3 所有とする。S5 は cross-row bounded walk だけを所有し、header-local invariant を再発明しない。

**Composite key rule:** witness header の complete key は、その時点で実バイトとして pin 済みの `witness_digest`（composite identity 32 bytes）から **forward rebuild** する（root[8] + family6 + subtype `7f` + identity-kind COMPOSITE + identity bytes）。`KEY_DIGEST` から raw identity を reverse することは **禁止**。

**S4 deferred authority との関係:** S4（§18.15）が `S5_REQUIRED` / `S5_AND_S6_REQUIRED` disposition を finalize したとき、D3 success への昇格は本 S5 の successful composition を要求する。S5 は S4 の deferred bit を **消費する側** であり、S4 disposition を再発行・上書きしない。S5 単独の local complete は S4 deferred を自動的に解決しない（higher D3 composition accumulator が両 slice の disposition を合成する）。

**Digest collision / raw bijection:** S5 は SHA-256 collision resistance を **assumption** として依存する。D1 が証明できるのは「返された key/body raw が同じ composite digest を再計算する」ことまでであり、真の SHA-256 collision を検出できない。S5 は各 hop で successor header の D1-valid complete key と body `witness_digest` の **raw/key bijection** を独立に検証し、digest equality だけで同一性を決めない。Collision resistance が破られた場合、本 freeze の保証は SHA-256 のそれを超えない。

#### 18.16.0 Value lifetime / pin discipline

| Rule | Exact |
| --- | --- |
| Borrow | `value[4096]` は **直近 1 回** successful `exact_get` / iter value のみ valid |
| Invalidate | 次の `exact_get` / value 供給 / cleanup で **即 invalid** |
| Pin before overwrite | 後続 get 後に必要な digest / complete key bytes / manifest framing / canonical old digest は **get 前**に fixed context へ copy |
| Forbidden | invalid value を VALUE_DIGEST / body raw rebuild / entry comparison / canonical SHA 入力に使う |

#### 18.16.1 Snapshot-only DSW2 scope

| In scope | Out |
| --- | --- |
| SUPERSEDED successor chain bounded walk / cycle / missing successor | S6 retire/cleanup physical erase truth |
| successor manifest SUPERSEDE_WITNESS entry full-M exact 検証（canonical old/new header digest + state transition） | D4 commits / mutation |
| self-reference / cycle / missing successor / re-supersede detection | incoming predecessor reference walk（S6） |
| RETIRED successor 到達時の manifest proof + S6 handoff | RETIRED retirement eligibility proof（S6） |
| finalize / evaluator-off / incomplete-mask / quota=1 substep progress | ACTIVE successor-zero（D1/D2-S3 header-local） |
| | public Runtime |

#### 18.16.2 Closed mode 35

| Mode | Carrier | Core |
| ---: | --- | --- |
| **35** | every SUPERSEDED WITNESS_HEADER | bounded successor chain walk: successor exact_get + manifest SUPERSEDE_WITNESS entry full-M 検証 + cycle bound + RETIRED handoff |

**k₅=1** は D3-S5 **complete** の closed mode 集合（**1 self-contained session**）。S1 exact-1 modes 1..20、S2 modes 21..26、S3 modes 27..30、S4 modes 31..34 は維持。S5 mode は **35** だけ。36..255 は invalid。

#### 18.16.3 Same-txn phase machine

```text
IDLE → BASELINE (D2 once; count witness headers → walk_bound u64)
  → close sole iterator; reopen zero-prefix in same txn
  → Mode 35:
      (SELECT_HEADER → install SUPERSEDED header; pin canonical old digest
         → CHAIN_HOP loop:
            (substep 0: successor exact_get → verify existence/state/raw bijection
             substep 1..2: MANIFEST_ENTRY_PROOF: stream successor manifest chunks
               full-M; find SUPERSEDE_WITNESS entry matching predecessor key exact 1
               verify canonical old/new digests + framing + SHA
             substep 3: advance hop:
               prev_hop := current; current := successor;
               if successor ACTIVE → substep 4 WALK_CLOSE
               if successor SUPERSEDED → substep 0 next hop
               if successor RETIRED → manifest proof complete → S6_REQUIRED set → WALK_CLOSE)*
         → WALK_CLOSE: chain valid or CYCLE/MISSING corrupt
         → preserve last_carrier_key; next SELECT)*
   → COMPLETE | FAILED | mid-drive yield (not terminal)
```

**BASELINE:** D2 structural scan と同じ single full-domain iterator walk。witness header（family6 subtype `7f`）を **checked-u64** count し `walk_bound` に install する。`walk_bound == 0` の snapshot は witness header 不在であり、carrier 0 で vacuous complete。BASELINE 完了後、sole iterator を close し、same txn で zero-prefix iterator を reopen する（§18.3 S2a/S3a/S4a と同型の sequential zero-prefix reopen）。

**SELECT_HEADER:** reopen した iterator を `last_carrier_key` の strictly after から resume し、次の SUPERSEDED WITNESS_HEADER を select。D1-valid SUPERSEDED header を install:
- `witness_digest` := header composite identity（body から; key/body raw bijection 検証済み）
- `successor_witness_digest` := body field（non-zero 必須; zero は **MISSING_SUCCESSOR CORRUPT**）
- `predecessor_complete_key` := header complete key bytes（live value から copy）
- `expected_entry_new_digest` := `VALUE_DIGEST(live SUPERSEDED complete value)`
- **canonical old digest 導出**（§18.16.5.1）
- `record_revision` == 2 必須（§18.16.5.1）
- `last_carrier_key` := header complete key（iterator position）

**Substep 0 next-hop pinning（successor value live 中に必須）:** successor header を exact_get した後、その value が live の間に次を pin する:
- **`hop_witness_digest` := successor の composite identity**（= exact_get に使った identity; chunk key 構築・owner 要求に使用。`successor_witness_digest` とは **別 pin**）
- **`header_state` := decoded successor `witness_state`**（1 ACTIVE / 2 SUPERSEDED / 3 RETIRED）。**substep 3 完了まで保持**（quota=1 を含む call-spanning manifest proof 後に分岐を再現するため）
- successor framing: `member_count`, `chunk_count`, `expected_manifest_digest`
- `successor_witness_digest` := successor body の successor field（**次 hop の get 用**; ACTIVE なら zero）
- **`header_state == 2`（SUPERSEDED）の場合のみ:**
  - `next_old_digest` := successor の canonical ACTIVE 合成（§18.16.5.1; incremental SHA）
  - `next_new_digest` := `VALUE_DIGEST(successor complete value)`
- **`header_state == 1`（ACTIVE）または `header_state == 3`（RETIRED）の場合:** `next_old_digest` / `next_new_digest` は計算しない（chain 停止のため不要）

pin 完了後、successor value は chunk get で失効してよい。

**`hop_witness_digest` と `successor_witness_digest` の区別（必須）:**
- `hop_witness_digest` = 「今 manifest を検証している successor header 自身の identity」。substep 1-2 の chunk key 構築（`chunk_key(hop_witness_digest, floor(i/8))`）と owner 照合に使う。
- `successor_witness_digest` = 「その successor header の body に記録された次 hop の target」。substep 3 promotion 後の次 substep 0 で exact_get に使う。
- 両者は **同時に live** であり、alias / 上書きは **禁止**。

**Hop promotion（substep 3 → next hop substep 0）:** digest shift は exact:
```text
prev_hop_witness_digest := witness_digest        # OLD current (W1) becomes prev
witness_digest := hop_witness_digest             # W2 becomes new current
predecessor_complete_key := forward-rebuild from hop_witness_digest (W2's key)
expected_entry_old_digest := next_old_digest     # W2's canonical old (pinned at substep 0)
expected_entry_new_digest := next_new_digest     # W2's live new (pinned at substep 0)
walk_steps := walk_steps + 1
# reset for next manifest stream:
streamed_members := 0; entry_found := 0
SHA state := domain separator init (§18.16.6 rule 10)
prev_member_key_len := 0
# successor_witness_digest (= W3) is already pinned from previous substep 0; unchanged
# hop_witness_digest will be overwritten at NEXT substep 0 with W3's identity
```
`prev_hop_witness_digest` には **旧 `witness_digest`**（上書き前の current）を代入する。`hop_witness_digest` を代入してはならない（両方が新 current になると immediate-bounce 検出が破綻する）。`origin_witness_digest` は SELECT 時から不変。`next_old_digest` / `next_new_digest` は substep 0 で successor live 中に pin 済みであり、substep 3 で successor value を再取得しない（**re-get 禁止**; get budget 不変）。

#### 18.16.4 PASS_INTERNAL / drive quota + substep progress

| Item | Contract |
| --- | --- |
| `drive_get_quota` | each drive/advance: default **32**; legal **1..256**（**1 is legal**） |
| `drive_gets_used` | +1 per S5 `exact_get` attempt |
| Yield | used==quota mid work → OPEN, `flags.need_resume=1`, **no sticky**; preserve all pins/cursors/substeps |
| Resume | refill quota; continue **same substep cursor** — **must not re-issue a completed get** |

**`walk_substep`（Mode35; per hop）:**

| Value | Meaning | Next action | On success |
| ---: | --- | --- | --- |
| **0** | need successor header get | forward-build successor key from `successor_witness_digest` into `peer_key`; `exact_get`; verify existence + state + raw/key bijection; **pin `header_state` := decoded successor witness_state**; pin successor framing（M, C, manifest_digest）; pin `successor_witness_digest` from body; **if `header_state==2`: compute + pin `next_old_digest` / `next_new_digest` while live**（§18.16.3）; init SHA domain separator | → **1**（successor value may die; `header_state` retained） |
| **1** | manifest entry proof: chunk re-get for `streamed_members` | forward-build chunk key from **`hop_witness_digest`** + `floor(streamed_members/8)`; `exact_get(chunk)` | → **2**（chunk live） |
| **2** | inspect entry at `streamed_members % 8`; SHA feed（`i%8==0` only）; if SUPERSEDE_WITNESS + key match → verify old/new digests + require `entry_found==0`（duplicate reject）→ set `entry_found=1`; advance `streamed_members` | if `streamed_members == M` → **3**; else → **1**（next member） | |
| **3** | full-M close: require `entry_found==1` + framing exact + final SHA == `expected_manifest_digest`; then branch on **pinned `header_state`** | `walk_steps++`; if `header_state==1`（ACTIVE）→ **4**; if `header_state==2`（SUPERSEDED）→ promote（§18.16.3）→ **0**; if `header_state==3`（RETIRED）→ set `binding_complete_mask.bit5` → **4** | |
| **4** | WALK_CLOSE: chain walk complete for this origin | no get; header complete → next SELECT | |

**Forbidden with quota=1:** looping substep 1 forever（re-getting same chunk without advancing `streamed_members`）。Each successful get **must** advance `walk_substep` or `streamed_members` or `walk_steps`。

Values 5..255 are invalid。

#### 18.16.5 Successor chain walk / cycle detection

**Bounded walk contract（§18.5 category E）:**

| Rule | Exact |
| --- | --- |
| Origin | Mode35 SELECT_HEADER で install した SUPERSEDED header の `witness_digest` を `origin_witness_digest` へ pin |
| Hop | 各 hop で current header の `successor_witness_digest` から successor を exact_get |
| Bound | `walk_steps`（u64）が `walk_bound`（u64; = baseline で checked count した witness header 総数）に **達したら**（≥） **CYCLE CORRUPT** |
| Self-reference | successor_witness_digest == own witness_digest → **SELF_REFERENCE CORRUPT**（substep 0 で検出） |
| Origin cycle | successor_witness_digest == `origin_witness_digest` → **CYCLE CORRUPT** |
| Immediate bounce | successor_witness_digest == `prev_hop_witness_digest`（直前 hop と同じ）→ **CYCLE CORRUPT** |
| ACTIVE terminus | successor state == ACTIVE → chain valid; WALK_CLOSE |
| SUPERSEDED continuation | successor state == SUPERSEDED → 次の hop へ進み、その successor manifest も full-M 検証 |
| RETIRED successor | substep 0 で successor header + manifest entry を **full-M で証明した後**、`binding_complete_mask.bit5=s6_required_seen` を set し WALK_CLOSE。RETIRED node 自身の successor suffix・retirement eligibility・incoming reference・partial chunk truth は **S6 へ明示移管**。manifest proof 前の停止は **禁止** |
| Missing successor | exact_get ABSENT → **MISSING_SUCCESSOR CORRUPT** |
| Invalid successor state | successor state が ACTIVE/SUPERSEDED/RETIRED 以外（D1-invalid / future）→ normal D2 precedence; unsupported only under recognizable-future rule, otherwise **CORRUPT** |

**Walk は全 header 集合を RAM へ置かない。** 起点ごとの bounded walk と fresh exact_get だけで行う（§10.1）。visited set / full-ID set / hash table は **禁止**。

##### 18.16.5.1 Canonical old ACTIVE digest 導出

SUPERSEDED carrier は common `record_revision == 2` を **必須** とする（revision ≠ 2 は **CORRUPT**; §10.1: ACTIVE creation revision=1, ACTIVE→SUPERSEDED replacement で exactly +1）。

`expected_entry_old_digest`（SUPERSEDE_WITNESS entry の `old_value_digest` 期待値）は、live SUPERSEDED complete `NLR1` value から **canonical 変換** で導出する:

1. Live value を decode（D1-valid 済み）。body 内の `operation_identity` length を含む exact field offsets を確定。
2. 以下の **3 field だけ** を canonical 値へ置換し、他は byte-equivalent:
   - common header `record_revision`: 2 → **1**（u64 BE）
   - body `witness_state`: 2 → **1**（u16 BE; ACTIVE）
   - body `successor_witness_digest`: non-zero → **zero[32]**
3. `payload_length` は不変（field size 不変）。NLR1 envelope magic/type/version 不変。
4. 置換後 byte 列の **CRC32C** を再計算（§12 6.2: Castagnoli, checksum field 除く先頭〜payload 末尾）。
5. `magic || type || version || payload_length || modified_payload || new_CRC` の complete NLR1 encoded bytes へ **SHA-256** を適用。
6. 結果が `expected_entry_old_digest`。

**Second 4096 buffer 禁止:** canonical SHA は incremental feed で行う。live value の byte 列を offset 順に SHA/CRC へ投入し、3 field の offset 位置で canonical byte を substitute する。field offset は D1 decoded view から確定済み。

`expected_entry_new_digest` は `VALUE_DIGEST(live SUPERSEDED complete value)`（trivial; live value 全体の SHA-256）。

##### 18.16.5.2 Re-supersede detection

`SUPERSEDE_WITNESS` entry に successor field は **存在しない**（§10.1 entry encoding: record_role / action / key / old_present / new_present / prior_head / old_value_digest / new_value_digest のみ）。存在しない field の比較は **禁止**。

Re-supersede / successor identity の束縛は以下の **組合せ** で検出する:

1. `record_revision == 2`（exactly once superseded）
2. `expected_entry_old_digest`（canonical ACTIVE 合成）== entry `old_value_digest`
3. `expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST）== entry `new_value_digest`
4. target entry **exact 1 件**（duplicate reject）
5. successor header の `witness_digest` == predecessor body `successor_witness_digest`（raw/key bijection）

この組合せにより、predecessor が記録した successor identity と実際に取得した successor header の manifest owner が一致することを証明する。異なる successor への差し替え（別successor）は条件 5 で検出される。

#### 18.16.6 SUPERSEDE_WITNESS manifest entry full-M verification

各 hop で successor header の manifest を **full-M** stream し、predecessor の SUPERSEDE_WITNESS entry を exact 検証する（§18.15.3 と同等の厳密度）:

1. Successor header value が live の間に `member_count=M`, `chunk_count=C`, `manifest_digest` を pin。`1 ≤ M ≤ 256`; `C = ceil(M/8)` and `1 ≤ C ≤ 32`。
2. `streamed_members = 0`, `entry_found = 0`, `prev_member_key_len = 0` から開始。
3. 各 ordinal `i`（0..M-1）に対し `chunk_key(hop_witness_digest, floor(i/8))` を forward-build し exact_get。
4. 返された chunk の `witness_digest`, `chunk_index`, `chunk_count` が installed successor header / exact `floor(i/8)` / `C` と一致しなければ CORRUPT。
5. **非末尾 chunk は exact 8 entries、末尾 chunk は exact `M - 8*(C-1)` entries**（1..8）。entry count 不一致は CORRUPT。
6. **Strict unsigned-byte lex order（§18.15.3 同型）:** 全 M entries は key unsigned-byte lexicographic 昇順でなければならない。`prev_member_key` は chunk 境界をまたいで保持する。current entry key ≤ `prev_member_key` は **ORDER_CORRUPT**（equality = duplicate, decreasing = out-of-order）。`prev_member_key` は各 entry 検査後に更新。
7. Entry slot `i%8` を検査: `action == 4`（SUPERSEDE_WITNESS）かつ `key_bytes == predecessor_complete_key`（byte-exact, `key_length` 含む）の entry を探す。
8. **Target entry duplicate reject:** `entry_found == 1` の状態で 2 件目の match を発見したら **DUPLICATE_ENTRY CORRUPT**。
9. 該当 entry が見つかったら（`entry_found == 0` の場合のみ）:
   - `old_present == 1`, `new_present == 1`
   - `old_value_digest == expected_entry_old_digest`（canonical ACTIVE 合成; §18.16.5.1）
   - `new_value_digest == expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST）
   - `record_role` high byte == family6（`0x06`）, low byte == subtype `7f`
   - `prior_head_witness_digest == zero`（SUPERSEDE_WITNESS は witness metadata member; §10.1）
   - `entry_found := 1`
10. **SHA domain separator + feed:** manifest SHA は §5.1 の exact domain-separated formula: `SHA-256(ASCII("NINLIL-DOMAIN-MANIFEST-V1") || chunk_body_0 || ... || chunk_body_n)`。**substep 0 の pin 完了時に SHA state を初期化し、domain separator `ASCII("NINLIL-DOMAIN-MANIFEST-V1")`（exact 25 bytes）を最初の feed として投入する**（exact transition; chunk body 投入前）。`i%8 == 0` のときだけ exact encoded chunk body を SHA へ投入（同一 chunk の within-chunk re-get は 8 ordinal 連続で合法だが、SHA 投入は chunk 境界の一度だけ）。
11. **Full-M close:** `streamed_members == M` に達したとき:
    - `entry_found == 1` 必須（0 は **MISSING_ENTRY CORRUPT**）
    - implied visited chunk count == C
    - final SHA == `expected_manifest_digest`（不一致は **MANIFEST_SHA CORRUPT**）
12. Within-chunk re-get（同じ chunk を 8 ordinal 連続で再取得）は **required/合法**（S4 §18.15.3 と同型）。A returned-index duplicate is corruption only when it repeats across a chunk boundary where `floor(i/8)` advanced, when an iterator supplies a duplicate complete chunk row/key, or when the returned index differs from the current requested `floor(i/8)`。

All checks use D1-valid decoded rows。A local D1 failure remains D2 corruption and is not reclassified by S5。

#### 18.16.7 Exact get-budget table

| Situation | exact_gets |
| --- | --- |
| **35** per hop（successor header get） | **1** |
| **35** per hop（manifest entry full-M proof） | **M_successor** chunk re-gets |
| **35** per origin total | **Σ_hops (1 + M_hop)**; hops ≤ walk_bound |
| **35** session total（all SUPERSEDED origins） | **Σ_origins Σ_hops (1 + M_hop)** |

#### 18.16.8 Precedence / finalize gates

| Gate | Exact |
| --- | --- |
| Traversal complete | phase COMPLETE + Mode35 required masks + no sticky corruption + INTERNAL done（or vacuous-empty carrier set） |
| COMPLETE_READY | traversal complete + `binding_complete_mask.bit5==0`; set `flags.bit3=1` |
| DEFERRED_READY | traversal complete + `binding_complete_mask.bit5==1`（RETIRED successor encountered; S6 correlation pending）; `flags.bit3` **must remain 0** |
| Finalize result | COMPLETE_READY and DEFERRED_READY both sample the private disposition, perform normal cleanup, publish one complete private result, return `NINLIL_OK`; deferred disposition is **not D3 success** until S6 composition succeeds |
| Incomplete masks / mid-yield | finalize → INVALID_STATE Port 0; no cleanup |
| Evaluator-off | baseline candidate only; both READY shapes forbidden; frozen D2 unsupported/corrupt aggregate path; publishes `d3s5_disposition_present=0`, `d3s5_disposition=0` only when cleanup succeeds |
| Sticky terminal | further d3s5_drive → INVALID_STATE Port 0 |
| Cleanup | iter_close → rollback → optional fence → DONE |

**Precedence order:** D2/local decode CORRUPT > MISSING_SUCCESSOR / CYCLE / SELF_REFERENCE / MISSING_ENTRY / DUPLICATE_ENTRY / ORDER_CORRUPT / MANIFEST_SHA / revision CORRUPT > `S6_REQUIRED` deferred > local valid。Deferred bit は既存 corruption を suppress しない。

**Required exact masks by session（Mode35 only）:**

| Shape | Required |
| --- | --- |
| Mode35 normal complete | `count_complete_mask.bit0==1`（all SUPERSEDED headers walked）; `binding_complete_mask.bit0==1`（chain walk binding complete）; `binding_complete_mask.bit5==0` |
| Mode35 with RETIRED handoff | same + `binding_complete_mask.bit5==1`（S6 deferred） |
| Vacuous（walk_bound==0, no SUPERSEDED carrier） | `count_complete_mask.bit0==1` + `binding_complete_mask.bit0==1`（vacuous-empty inventory proves both）; bit5==0 |
| Invalid extra bits | `count_complete_mask` bits1..7 set, or `binding_complete_mask` bits1..4/6/7 set → **INVALID_STATE** |

**Private finalize disposition:**

- **0 LOCAL_COMPLETE**（bit5==0）
- **2 S6_REQUIRED**（bit5==1; RETIRED successor encountered）

S5 は `S5_REQUIRED`（disposition 1）を **生成しない**（S5 自身が successor proof であるため）。S5 が生成し得るのは 0 と 2 だけ。Invalid enum/MBZ/mode-bit shape or sticky corruption is never converted to a deferred result。

**Closed private result carrier（implementation-required）:** append the following exact declaration-order fields after the D3-S4 carrier bytes（`d3s4_disposition` at offset 53）in `ninlil_domain_scan_result_t`:

```c
uint8_t d3s5_disposition_present; /* declaration offset 54; exact 0 or 1 */
uint8_t d3s5_disposition;         /* declaration offset 55; present=1: exact 0 or 2; present=0: exact 0 */
```

`present=1, disposition=0` is LOCAL_COMPLETE。`present=1, disposition=2` is S6_REQUIRED。`present=0` with non-zero disposition, `present>1`, `present=1` with disposition==1 or disposition>2 is invalid and may never be published。Higher D3 composition accepts a disposition **only when finalize returned `NINLIL_OK` and `d3s5_disposition_present==1`**。

**Private-result size/stack accounting:** S4 append 後 host layout は named bytes through offset 53, natural `sizeof=56`, alignment 8。S5 の 2 bytes は declaration offsets **54/55** に append し、host tail-padding 内で `sizeof` は **56** を維持（S4 と同型）。Target ABI padding は仮定しない: implementation must `_Static_assert(sizeof(ninlil_domain_scan_result_t) <= 64)` and record host plus ESP32-S3 target `sizeof`/alignment in the implementation oracle。Commit-style candidate publication adds at most **64 bytes** of finalize function stack; no record/value buffer is placed there。This result is caller output/temporary, not part of the S5 context or co-resident D3 arena, so S5 **651/656**, outer **11536**, and packed aggregate arithmetic remain unchanged。

**Output/cleanup mutation matrix（whole `ninlil_domain_scan_result_t` as output unit）:**

| Call/path | Port calls | `out_result` | S5 context/session |
| --- | ---: | --- | --- |
| finalize, evaluator-on READY, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=1`, disposition exact 0 or 2; return `NINLIL_OK` | sample disposition to scalar before cleanup; after publish, zero entire S5 context and finish DONE |
| finalize, evaluator-off frozen aggregate, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=0`, disposition=0; return frozen aggregate status | after publish, zero entire S5 context and finish DONE |
| finalize from FAILED, cleanup success | cleanup tree | publish diagnostics with `present=0`, disposition=0 and the sticky non-OK status | after publish, zero entire S5 context and finish DONE |
| finalize, any cleanup failure | cleanup tree/fence | **all bytes unchanged** from caller poison; sampled disposition discarded | zero entire S5 context after Port cleanup; finish terminal |
| abort from legal OPEN/EXHAUSTED/FAILED | cleanup tree/fence | **all bytes unchanged** | zero entire S5 context after Port cleanup; finish terminal DONE |
| NULL, output alias, invalid state, incomplete masks/mid-yield, invalid enum/MBZ | **0** | **all bytes unchanged** | session/context/workspace unchanged |

Prevalidation checks all required pointers/state/shape and requires the complete result range to be disjoint from the session, bound workspace, bound ops object, bound handle slot, and bound S5 context **before** any Port call, output write, or cleanup。Exact order: **derive/sample scalar disposition → Port cleanup outcome → build/publish complete output → zero S5 context**。

#### 18.16.9 Honest cost

| Mode | Baseline | Internal | Session |
| ---: | --- | --- | --- |
| 35 | **Θ(N)** | **Θ(N + Σ_origins Σ_hops (1 + M_hop))** | **Θ(2N + W_chain)** |

**Worst-case chain topology:** 単一 long chain of length L（W1→W2→…→WL ACTIVE, L-1 SUPERSEDED origins）。各 origin W_i は hop i→i+1, i+1→i+2, …, L-1→L を walk し、各 hop j で successor manifest M_j を full-M stream する。Hop j は j 件の origin（W1..Wj）から再走査されるため:

**Total = Σ_{j=1}^{L-1} j·(1 + M_{j+1})**

一様 M では **Θ(L²·(1 + M_avg))**。これは **honest quadratic-class wall time**（§18.5 honest cost 規則）であり、memory は fixed（full-ID set なし）。

**False O(N) claim 禁止:** S5 の chain walk cost を「O(N) one-pass」や「Θ(L² + L·M_avg)」と偽らない。各 manifest が複数 origin から再走査される事実を隠してはならない。

D3-S5 complete = **1 × baseline + every internal walk/manifest stream**。

#### 18.16.10 Fixed S5 context layout（sizeof **651** / align 1 / ceiling **656**）

全 physical field は `uint8_t` scalar/array。multi-byte 値は big-endian byte array。`alignof == 1` と exact sizeof を `_Static_assert` で検証する。Natural alignment padding は存在しない。

| Offsets | Size | Field |
| ---: | ---: | --- |
| 0..44 | 45 | `last_carrier_key` |
| 45 | 1 | `last_carrier_key_len` |
| 46..77 | 32 | `witness_digest`（current hop header composite identity; cycle detection 用） |
| 78..109 | 32 | `origin_witness_digest`（walk origin; cycle detection） |
| 110..141 | 32 | `successor_witness_digest`（current header body の次 hop target; substep 0 get 用） |
| 142..173 | 32 | **`hop_witness_digest`**（現在 manifest を検証中の successor 自身の identity; chunk key 構築・owner 照合用。`successor_witness_digest` と同時 live・別 pin） |
| 174..205 | 32 | `prev_hop_witness_digest`（immediate previous hop; bounce detection） |
| 206..237 | 32 | `expected_manifest_digest`（successor's manifest digest for SHA） |
| 238..269 | 32 | `expected_entry_old_digest`（canonical ACTIVE 合成; §18.16.5.1） |
| 270..301 | 32 | `expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST） |
| 302..333 | 32 | `next_old_digest`（successor's canonical ACTIVE; pinned at substep 0 while successor live; next hop 用） |
| 334..365 | 32 | `next_new_digest`（successor's live VALUE_DIGEST; pinned at substep 0; next hop 用） |
| 366..410 | 45 | `predecessor_complete_key`（current origin header's complete key for entry matching） |
| 411 | 1 | `predecessor_complete_key_len` |
| 412..456 | 45 | `peer_key`（successor header get / chunk request） |
| 457 | 1 | `peer_key_len` |
| 458..502 | 45 | `prev_member_key`（manifest lex order check; chunk 境界をまたぐ） |
| 503 | 1 | `prev_member_key_len` |
| 504..535 | 32 | `sha_state` |
| 536..543 | 8 | `sha_bitcount` |
| 544..607 | 64 | `sha_block` |
| 608 | 1 | `sha_block_len` |
| 609..610 | 2 | `member_count` u16 BE（successor's M） |
| 611..612 | 2 | `chunk_count` u16 BE（successor's C） |
| 613..614 | 2 | `streamed_members` u16 BE（manifest entry proof ordinal） |
| 615..622 | 8 | `walk_steps` **u64 BE** |
| 623..630 | 8 | `walk_bound` **u64 BE**（= baseline witness header checked count） |
| 631..632 | 2 | `drive_get_quota` u16 BE |
| 633..634 | 2 | `drive_gets_used` u16 BE |
| 635 | 1 | `phase` |
| 636 | 1 | `pass_kind` |
| 637 | 1 | `focus_mode` |
| 638 | 1 | `flags` |
| 639 | 1 | `count_complete_mask` |
| 640 | 1 | `binding_complete_mask` |
| 641 | 1 | `walk_substep` |
| 642 | 1 | `header_state`（current hop: 0 none / 1 ACTIVE / 2 SUPERSEDED / 3 RETIRED） |
| 643 | 1 | `entry_found`（0/1; SUPERSEDE_WITNESS entry located） |
| 644..645 | 2 | `entry_key_length` u16 BE |
| 646..647 | 2 | `entry_record_role` u16 BE |
| 648..650 | 3 | reserved MBZ（exact 0） |
| **Σ** | **651** | |
| ceiling | **656** | headroom **5** |

**flags:** bit0 baseline_done; bit1 focus_live; bit2 bind_phase_active; bit3 complete_ready; bit4 need_resume; bit5 header_installed; bit6 manifest_sha_open; **bit7 MBZ**（S5 は `S5_REQUIRED` を生成しないため不要; 確定）。

**Exact state-byte / bit ownership:**

| Byte | Bits / values |
| --- | --- |
| `phase` | 0 IDLE; 1 BASELINE; 2 SELECT; 3 CHAIN_HOP; 4 MANIFEST_PROOF; 5 WALK_CLOSE; 6 COMPLETE; 7 FAILED; 8..255 invalid |
| `pass_kind` | 0 PASS_BASELINE; 1 PASS_INTERNAL; 2..255 invalid |
| `focus_mode` | 0 only before begin / after cleanup; 35 only while active; 1..34 and 36..255 invalid |
| `flags` | bits0..6 as above; bit7 MBZ（non-zero is invalid） |
| `count_complete_mask` | bit0 Mode35 all-SUPERSEDED-header walk pass complete; bits1..7 MBZ |
| `binding_complete_mask` | bit0 Mode35 chain walk binding complete; bit5 sticky `s6_required_seen`（RETIRED successor encountered）; bits1..4, 6..7 MBZ |
| `walk_substep` | exact 0..4 from §18.16.4; 5..255 invalid |
| `header_state` | 0 none/cleared（SELECT reset）; **substep 0 success で decoded successor witness_state を代入**; substep 3 完了まで保持（quota yield をまたぐ）; 1 ACTIVE; 2 SUPERSEDED; 3 RETIRED; 4..255 invalid |
| `entry_found` | exact 0 or 1; 2..255 invalid |
| `sha_block_len` | 0..63 while SHA is open; 64..255 invalid |
| `drive_get_quota` / `drive_gets_used` | quota exact 1..256 while driving; used 0..quota; used>quota, quota 0, or quota>256 invalid |

At `begin_profiled_d3s5`, all state/masks/pins are zero, then `focus_mode=35` is installed and phase enters BASELINE。SELECT_HEADER resets per-header walk state（walk_steps, walk_substep, streamed_members, SHA, entry_found, header_state, digest pins, predecessor key）but preserves count/binding completion masks and sticky bit5。Mid-yield preserves every field。Mode35 pass exhaustion sets count bit0 + binding bit0, then phase becomes COMPLETE。Any invalid/MBZ value is terminal corruption before readiness derivation。Finalize samples disposition; cleanup-success publishes; every terminal cleanup zeros entire S5 context after Port cleanup。

#### 18.16.11 Memory ceilings（S4 **960** fixed from main）

| Object | Ceiling |
| --- | ---: |
| scanner / Stage5-alone | **8192** / **8704** unchanged |
| S1 / S2 | **448** / **320** unchanged |
| S3（§18.14 main） | **754 / 768**; outer **9920** |
| S4（§18.15 main） | **949 / 960**; full S1+S2+S3+S4 **10880** |
| **S5** | sizeof **651** / ceiling **656** |
| S1+S2+S5 | 8384+448+320+656 = **9808** |
| **S1+S2+S3+S4+S5 full** | 8384+448+320+768+960+656 = **11536** |

Packed full: `8384+421+306+754+949+651=11465`；align8 **11472** ≤ **11536**。
Packed S1+S2+S5: `8384+421+306+651=9762`；align8 **9768** ≤ **9808**。

dual-bound **forbidden**。Stage5 no D3 bind until S12。

#### 18.16.12 Private API（contract names only）

| API | Rule |
| --- | --- |
| `begin_profiled_d3s5` | mode 35 only; ctx ≤**656**; disjoint; not dual-bound |
| `d3s5_drive` / advance | enforce quota; **substep progress**; mid yield |
| finalize/abort | §18.16.8 exact private carrier, whole-output publication/poison, cleanup, zero order |
| Stage5 until S12 | no begin_d3s5 |

#### 18.16.13 Oracle architecture / constructible positives / anti-false-pass

The implementation change set shall add the append-only authority format **`ninlil-domain-scan-crossrow-v1-d3s5`**。It retains the D3-S1 exact 94-vector prefix and the then-current D3-S2/D3-S3/D3-S4 prefix byte-for-byte; this docs-only freeze does **not** edit the existing JSON。An independent deterministic generator, separate from production scanner control flow, must emit both (a) Port fixture records/scripts and (b) the expected per-drive state transition, exact-get key sequence, masks, disposition, and terminal result。The production bridge must run those generated scripts through the private D3-S5 implementation。

**Minimum constructible positive catalog:**

1. Mode35, single SUPERSEDED header W1（revision=2）→ successor W2 ACTIVE, W2 manifest M=2（entry 0: ordinary semantic member, entry 1: SUPERSEDE_WITNESS for W1）, canonical old digest matches → `LOCAL_COMPLETE`。walk_steps=1, no cycle。
2. Mode35, chain W1→W2→W3（W1/W2 SUPERSEDED, W3 ACTIVE）, `drive_get_quota=1` → exact hop/chunk/substep cursor sequence, no repeated get, walk_steps=2 from W1 origin。Each hop verifies its own successor manifest entry with canonical old digest。
3. Mode35, multiple predecessors W1/W2 both SUPERSEDED with same successor W3 ACTIVE → both origins independently verify W3 manifest contains their respective SUPERSEDE_WITNESS entries（M≥2）。
4. Mode35, successor W2 is SUPERSEDED（chain continues）→ hop advances, W2's successor W3 ACTIVE reached, both manifest entries verified。Digest shift（prev/current/successor）at each hop promotion is exact。
5. Mode35, RETIRED successor: W1 SUPERSEDED → W2 RETIRED。W2 header + manifest entry full-M proved **before** S6_REQUIRED set。Finalize returns disposition 2。W2's own successor suffix is not walked。
6. Mode35, bootstrap snapshot with zero witness headers → vacuous complete（count bit0 + binding bit0 set by empty inventory）。
7. Mode35, M=9/C=2 successor manifest → chunk index sequence `[0,0,0,0,0,0,0,0,1]`; SHA feeds at ordinals 0 and 8 only; within-chunk re-get legal。
8. Finalize output carriers: evaluator-on LOCAL_COMPLETE `(present,disposition)=(1,0)`; S6_REQUIRED `(1,2)`; evaluator-off `(0,0)`。

**Minimum negative/mutation catalog:**

1. SUPERSEDED header with `successor_witness_digest == zero` → **must fail**（missing successor）。
2. Successor exact_get ABSENT → **must fail**（missing successor）。
3. Self-reference: `successor_witness_digest == own witness_digest` → **must fail**（cycle）。
4. Two-header cycle: W1→W2→W1 → **must fail**（origin cycle detection）。
5. Long cycle exceeding `walk_bound` → **must fail**（bounded walk; u64 counter）。
6. Successor manifest missing SUPERSEDE_WITNESS entry for predecessor key after full-M → **must fail**（missing entry; `entry_found==0` at close）。
7. SUPERSEDE_WITNESS entry with wrong `old_value_digest`（canonical ACTIVE 合成不一致）→ **must fail**。
8. SUPERSEDE_WITNESS entry with wrong `new_value_digest`（live SUPERSEDED VALUE_DIGEST 不一致）→ **must fail**。
9. SUPERSEDE_WITNESS entry with wrong `record_role`（not family6/7f）→ **must fail**。
10. Manifest SHA mismatch after full stream → **must fail**。
11. `quota=1` re-gets same chunk without `streamed_members` advance → **must fail**。
12. Full-ID set / visited hash table in context → **must fail**（architecture violation）。
13. Two-snapshot list-then-prove → **must fail**（§18.3 prohibition）。
14. Unbounded walk without `walk_bound` check → **must fail**。
15. Any invalid enum/MBZ bit, incomplete required mask → **must fail**。
16. **RETIRED handoff:** manifest proof 前に S6_REQUIRED set / walk 停止 → **must fail**。RETIRED successor の manifest entry を skip して停止 → **must fail**。
17. **revision ≠ 2:** SUPERSEDED carrier with `record_revision==1` or `record_revision==3` → **must fail**。
18. **Canonical ACTIVE digest 不一致:** synthetic old digest computation で successor field を zero にしない / revision を 1 にしない / CRC を再計算しない → **must fail**。
19. **Target entry duplicate:** 同一 predecessor key の SUPERSEDE_WITNESS entry が 2 件 → **must fail**（`entry_found` duplicate reject）。
20. **Wrong final entry-count:** 末尾 chunk の entry_count が `M-8*(C-1)` と不一致 → **must fail**。
21. **Tail-into-cycle:** chain の末尾 SUPERSEDED が origin を指す（3+ hop cycle）→ **must fail**。
22. **Successor state invalid:** successor header state が ACTIVE/SUPERSEDED/RETIRED 以外 → **must fail**（D2 precedence; recognizable-future 以外）。
23. **SHA duplicate-feed:** `i%8 != 0` で chunk body を SHA に再投入 → **must fail**。
24. **Lex order violation:** manifest entry key が `prev_member_key` 以下（decreasing or duplicate across chunks）→ **must fail**（ORDER_CORRUPT）。
25. **Next-hop pin missing:** successor SUPERSEDED の substep 0 で `next_old_digest` / `next_new_digest` を pin せず hop promotion → **must fail**（positive #2/#4 構成不能）。
26. **SHA domain separator skip:** manifest SHA 初期化時に `ASCII("NINLIL-DOMAIN-MANIFEST-V1")` を投入せず chunk body から開始 → **must fail**。
27. Whole-result poison tests: abort（cleanup success and failure）、finalize cleanup failure、NULL/alias/prevalidation/invalid-state/incomplete-shape all leave every output byte unchanged。Alias mutations cover overlap with session, workspace, ops, handle slot, and bound S5 context。Invalid carrier combinations `(present>1)`, `(present=0, disposition!=0)`, `(present=1, disposition==1)`, `(present=1, disposition>2)` are never published。

Each positive fixture must be materialized, reproducible from a pinned seed/version, and self-check its expected get keys against keys independently reconstructed from fixture raw fields。CI must reject stale generated output, changed prefix vectors, duplicate vector IDs, nondeterministic regeneration, or a production result/state trace differing from the generated expectation。

#### 18.16.14 Mutation / D4 boundary

Snapshot finding **S5**; retire/cleanup **S6**; commits **D4**。S5 は Storage mutation 0（D2/S4 と同）。

#### 18.16.15 Explicit exclusions

| Exclusion | |
| --- | --- |
| Full-ID set / visited hash table / unbounded walk | forbidden |
| Two-snapshot list-then-prove（§18.3） | forbidden |
| quota=1 infinite same-get loop | forbidden |
| KEY_DIGEST reverse | forbidden（§18.5） |
| ACTIVE successor-zero check（D1/D2-S3 header-local） | not S5 |
| S6 retire/cleanup physical erase truth | not this freeze |
| D4 mutation / commits | not this freeze |
| Incoming predecessor reference walk（S6 duty） | not this freeze |
| RETIRED retirement eligibility proof | not this freeze |
| RETIRED node's own successor suffix walk | not this freeze（S6 handoff） |
| public ABI/wire/D1 change | not this freeze |
| S4 deferred disposition re-issue/overwrite | forbidden |
| Non-existent wire field comparison（entry successor field） | forbidden |

#### 18.16.16 Completion boundary / non-claims

| Claim | |
| --- | --- |
| D3-S5a Normative freeze §18.16（DSW2 bounded walk; cycle/missing/self detection; SUPERSEDE_WITNESS manifest entry full-M proof + lex order; canonical NLR1 old digest; hop_witness_digest 別 pin; RETIRED handoff; 651/656; full outer 11536） | **yes** |
| S4a §18.15 main-equivalent 949/960/10880 | **preserved** |
| S5 / D3 / Stage5 / Runtime / ESP implementation | **no** |
| Crossrow d3s5 JSON | **no** |

S5a を implementation complete へ書き換えない。S0/S1a/S2a/S3a/S4a historical は **preserve**。

#### 18.16.17 Worked example: W1→W2→W3（positive #2/#4 構成可能性確認）

Chain: W1(SUPERSEDED, rev=2, successor=W2) → W2(SUPERSEDED, rev=2, successor=W3) → W3(ACTIVE, successor=zero)。W2 manifest M=2（entry 0: semantic member, entry 1: SUPERSEDE_WITNESS for W1）。W3 manifest M=2（entry 0: semantic member, entry 1: SUPERSEDE_WITNESS for W2）。

**SELECT_HEADER（origin W1）:**
```
witness_digest        := W1
origin_witness_digest := W1
successor_witness_digest := W2        (from W1 body)
predecessor_complete_key := key(W1)
expected_entry_old_digest := canonical_old(W1)   (rev=1,state=ACTIVE,succ=zero,CRC,SHA)
expected_entry_new_digest := VALUE_DIGEST(W1 live SUPERSEDED value)
last_carrier_key := key(W1)
```

**Hop 1 substep 0（get W2）:**
```
peer_key := build_header_key(successor_witness_digest=W2)
exact_get(peer_key) → W2 live
# cycle checks: W2 != W1(origin), W2 != prev_hop(none) → OK
hop_witness_digest := W2              ← W2 自身の identity（chunk key 用）
header_state := 2                     ← W2 decoded witness_state (SUPERSEDED); substep 3 まで保持
successor_witness_digest := W3        ← W2 body の successor field（次 hop 用）
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W2)
header_state==2 (SUPERSEDED) →
  next_old_digest := canonical_old(W2)
  next_new_digest := VALUE_DIGEST(W2)
SHA init: feed ASCII("NINLIL-DOMAIN-MANIFEST-V1") (25 bytes)
# W2 value dies hereafter; header_state=2 retained
```

**Hop 1 substep 1-2（stream W2 manifest, M=2, C=1）:**
```
i=0: chunk_key(hop_witness_digest=W2, floor(0/8)=0) → exact_get → chunk live
     SHA feed chunk body (i%8==0)
     entry[0]: action=2(REPLACE), key=semantic_member_key → not target; lex OK (prev=∅)
     prev_member_key := semantic_member_key; streamed_members=1
i=1: same chunk re-get (i%8=1, no SHA feed)
     entry[1]: action=4(SUPERSEDE_WITNESS), key=key(W1) == predecessor_complete_key → MATCH
       entry_found==0 → verify:
         old_value_digest == expected_entry_old_digest (W1 canonical old) ✓
         new_value_digest == expected_entry_new_digest (W1 live new) ✓
         record_role == 0x067f ✓; prior_head == zero ✓
       entry_found := 1
     lex: key(W1) > semantic_member_key ✓; prev_member_key := key(W1); streamed_members=2
```

**Hop 1 substep 3（full-M close + promotion）:**
```
streamed_members==2==M ✓; entry_found==1 ✓; visited chunks==1==C ✓
final SHA == expected_manifest_digest ✓
# branch on pinned header_state==2 (SUPERSEDED) → promote:
prev_hop_witness_digest := witness_digest = W1   # OLD current becomes prev
witness_digest := hop_witness_digest = W2        # new current
predecessor_complete_key := build_header_key(W2) = key(W2)
expected_entry_old_digest := next_old_digest (W2 canonical old)
expected_entry_new_digest := next_new_digest (W2 live new)
walk_steps := 1
streamed_members := 0; entry_found := 0; prev_member_key_len := 0
SHA re-init: feed domain separator (25 bytes)
# successor_witness_digest = W3 (unchanged from substep 0 pin)
→ substep 0 (next hop)
```

**Hop 2 substep 0（get W3）:**
```
peer_key := build_header_key(successor_witness_digest=W3)
exact_get(peer_key) → W3 live
# cycle checks: W3 != W1(origin) ✓, W3 != W2(prev_hop) ✓ → OK
hop_witness_digest := W3              ← W3 自身の identity
header_state := 1                     ← W3 decoded witness_state (ACTIVE); substep 3 まで保持
successor_witness_digest := zero      ← W3 body successor (ACTIVE → zero)
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W3)
header_state==1 (ACTIVE) →
  next_old_digest / next_new_digest: NOT computed (chain stops)
SHA init: feed domain separator
# W3 value dies; header_state=1 retained
```

**Hop 2 substep 1-2（stream W3 manifest, verify W2's entry）:**
```
i=0: chunk_key(hop_witness_digest=W3, 0) → exact_get → chunk live
     SHA feed; entry[0]: semantic → not target; lex OK; streamed_members=1
i=1: re-get; entry[1]: SUPERSEDE_WITNESS, key=key(W2)==predecessor_complete_key → MATCH
       old == W2 canonical old ✓; new == W2 live new ✓; role/head ✓
       entry_found := 1; lex OK; streamed_members=2
```

**Hop 2 substep 3（full-M close + WALK_CLOSE）:**
```
full-M close ✓ (entry_found=1, SHA match)
# branch on pinned header_state==1 (ACTIVE) → WALK_CLOSE (no promotion)
walk_steps := 2
→ phase WALK_CLOSE → W1 origin header complete → next SELECT
```

**SELECT_HEADER（W2 as independent carrier）:**
W2 も SUPERSEDED なので、iterator は `last_carrier_key=key(W1)` の strictly after から resume し、W2 を次の carrier として select する。
```
witness_digest        := W2
origin_witness_digest := W2            # new origin
successor_witness_digest := W3         (from W2 body)
predecessor_complete_key := key(W2)
expected_entry_old_digest := canonical_old(W2)
expected_entry_new_digest := VALUE_DIGEST(W2)
last_carrier_key := key(W2)
walk_steps := 0 (reset per origin)
```

**W2 origin Hop 1 substep 0（get W3）:**
```
peer_key := build_header_key(successor_witness_digest=W3)
exact_get(peer_key) → W3 live
# cycle checks: W3 != W2(origin) ✓, W3 != prev_hop(none) ✓
hop_witness_digest := W3
header_state := 1                     ← W3 ACTIVE; substep 3 まで保持
successor_witness_digest := zero (W3 ACTIVE)
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W3)
header_state==1 → next_old/new NOT computed
SHA init: feed domain separator
```

**W2 origin Hop 1 substep 1-2（stream W3 manifest, verify W2's entry）:**
```
i=0: chunk_key(hop_witness_digest=W3, 0) → exact_get → chunk live
     SHA feed; entry[0]: semantic → not target; lex OK; streamed_members=1
i=1: re-get; entry[1]: SUPERSEDE_WITNESS, key=key(W2)==predecessor_complete_key → MATCH
       old == W2 canonical old ✓; new == W2 live new ✓; role/head ✓
       entry_found := 1; lex OK; streamed_members=2
```

**W2 origin Hop 1 substep 3（WALK_CLOSE）:**
```
full-M close ✓; branch on pinned header_state==1 (ACTIVE) → WALK_CLOSE
walk_steps := 1
→ W2 origin header complete → next SELECT
→ iterator: no more SUPERSEDED carriers after key(W2)
→ COMPLETE; count_complete_mask.bit0=1; binding_complete_mask.bit0=1; bit5=0
→ finalize: disposition (1, 0) = LOCAL_COMPLETE
```

**Complete session get sequence（M=2, C=1）:**
- W1 origin: `H(W2), C(W2,0)×2, H(W3), C(W3,0)×2`（6 gets）
- W2 origin: `H(W3), C(W3,0)×2`（3 gets）
- Total: 9 exact_gets

**構成可能性確認:** positive #1（single hop W1→W2 ACTIVE, M=2）は W1 origin だけで W2 ACTIVE なら substep 3 で WALK_CLOSE。positive #2/#4（W1→W2→W3 multi-hop）は W1 origin の Hop 1→Hop 2 digest shift + W2 independent carrier の両方で構成可能。positive #5（RETIRED）は W1→W2 RETIRED で `hop_witness_digest=W2` を使い W2 manifest を full-M 検証後 bit5 set → WALK_CLOSE → disposition (1,2)。全 positive が構成可能であることを確認した。
