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

BLOBのsame-record wire contractは次をexactとします。Common flagsはmanifest=`1`、chunk=`2`のどちらか1つだけでbody variantと一致し、両variantともimmutable `record_revision=1`、head witness digest / primary value digestはnon-zeroです。`blob_owner_kind`はBLOB固有enumでTRANSACTION=1、INGRESS=2、DELIVERY=3とし、reservation/scheduler enumを流用しません。`owner_key_raw` contentsは順にtransaction ID exact 16 bytes、ordered sequence BE8 exact 8 bytes、`delivery_key_raw` contents exact 80 bytesです。Allowed `(owner, blob_kind)`はTRANSACTION/DELIVERY×COMMAND_PAYLOAD/EVENT_PAYLOAD、INGRESS×INGRESS_PAYLOAD/EVIDENCE、DELIVERY×REPLYだけで、他はcorruptです。

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
| **D3** | cross-row semantic / partial group / orphan / cardinality / counter / capacity / health の相互validation。**step 5のうち witness member old/new・partial witness group・successor/supersede chain および他cross-row witness validation**。そのfindingを§16 precedenceへ投入 |
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

### 15.8 L2b1 oversized allocator re-read（non-authoritative legacy）

現行L2b1 bootstrap orchestrator（`src/runtime/runtime_store_orchestrator.c`）には、caller-owned 4096-byte value scratchへの`BUFFER_TOO_SMALL`に対し、temporary allocatorで最大Storage ABI上限付近まで確保して`iter_next`を再読するpathが残っています。これは次の理由で**D2の正本ではない**既知legacyです。

1. 本章§2 / §15および12/14章はprivate namespace single value上限4096と、required key>255またはvalue>4096の`BUFFER_TOO_SMALL`→`STORAGE_CORRUPT`（reread/allocationなし）を固定している
2. D2 scannerは当該pathをcopyしてはならない
3. Stage 5 completion前のhardeningで、L2b1 legacy re-read/65,536-class temporary allocation pathは除去し、本D2 contractへ収束させる

L2b1 successはStage 5完了でもD2完了でもありません（14章L2b1 boundaryと同じ）。

### 15.9 Ordered D2 slice ledger（D2-S0..S6）

| Slice | 内容 | D2完了証明 |
| --- | --- | --- |
| **D2-S0** | 本節のNormative contract freeze。実装/vector変更なし。**Historical S0 freeze status:** S0 alone did not complete D2 / DSR1 / DSR2 at freeze time（spec only）。**Current status after S5:** D2 bounded scanner / DSR1_SCAN / DSR2_ESP_BOUND are complete via S1–S5 composition; this S0 row remains the historical freeze record and is not retroactively rewritten as implementation-complete | 否（S0単独） |
| **D2-S1** | scanner core: state machine、begin binds Port/handle/workspace、advance(row_budget)/finalize|abort(result) only、iter buffer、`has_previous` lex、§15.4 coarse class、mutation 0、uint64 checked counters。独立oracle + production bridge。**実装済み（D2 incomplete）** | 否 |
| **D2-S2** | **実装済み（D2 incomplete）:** production profiled begin only（required candidate; TEST transport beginはtest macro専用）、same-txn 17 exact get + completeness/validate/compare、typed get capacities、iterator reconciliation masks、mismatch/future mode skip、private result diagnostics、sibling profile oracle `domain-scan-profile-v1.json` / `ninlil-domain-scan-profile-v1-d2s2` + independent generator + production bridge。D2 complete / DSR1/DSR2 complete / Stage 5 / public Runtime / ESP hardwareをclaimしない | 否 |
| **D2-S3** | **実装済み（D2 incomplete）:** exact-profile時 family 5/6 CURRENT structural same-recordをscan pathから到達。closed catalog family5 `01`+family6 §7 全29 current subtypes（`10,11,20-27,30-34,40-42,50-52,60-64,7d-7f`）REQUIRED。business+`7d` → `ninlil_model_domain_validate_typed_record`（workspace typed scratch; public APIに large local 無し）。`7e`/`7f` → parse key + envelope + pure witness decode + key/body/header bijection + independent header mutates（flags/PVD/primary/identity/subtype/rev0/rtype）scan到達。status: `UNSUPPORTED` future non-terminal、後続current corrupt precedence（record_version/domain_format）; profile mismatch/future_profile skip S3 decode; BTS 4097/unknown subtype/lex OOO。sibling oracle `domain-scan-structural-v1.json` / `ninlil-domain-scan-structural-v1-d2s3` + D1 d1b3o SHA/count pin composition + S1 transport body-nonvalidation hash/ID pin + independent generator + production bridge。**member old/new・partial group・successor chain・cross-row PVD/cardinalityはD3。S4 exact-get追加なし。** D2 complete / DSR1/DSR2 / Stage 5 / public Runtime / ESP hardwareをclaimしない | 否 |
| **D2-S4** | **実装済み（D2 incomplete）:** same-snapshot production-private exact `get`（`OPEN`/`EXHAUSTED`、sole iterator live、row_budget/counters 不変）+ presence enum / borrowed value view + fixed-memory proof（single 4096 value buffer reuse; session に unused xref digest/kind/count なし; 全ID集合非保持）。sibling oracle `domain-scan-exact-get-v1.json` / `ninlil-domain-scan-exact-get-v1-d2s4` + independent generator + production bridge。D3 relationship/cardinality/orphan/backlink semantics は所有しない。D2 complete / DSR1/DSR2 / Stage 5 / public Runtime / ESP hardware を claim しない | 否 |
| **D2-S5** | **実装済み（D2 bounded scanner complete; Stage 5 incomplete）:** S1〜S4 + deps composition。`DSR1_SCAN` complete + `DSR2_ESP_BOUND` complete。production-private `ninlil_domain_scan_note_terminal_corrupt`（D3 corruption injection/aggregation seam only; D3 finding correctness is D3）。profiled budget 1/64、same-snapshot exact_get lifecycle（per-call status + counter/previous/get snapshots）、fresh-session restart from front with first post-restart `advance` budget=1 + front-key assert（not same-session budget resume）、changed-snapshot restart asserts new front key、FAILED cleanup restart、rollback failure sticky + unknown rollback fence-once、handle drift closes original only、future/mismatch/structural candidates then note → sticky CORRUPT outranks、state gates、`note_then_reject` / `note_exhausted`、note then advance/exact_get reject Port0、close/fence once、mutation0、full Port-trace equality。sibling oracle `domain-scan-composition-v1.json` / `ninlil-domain-scan-composition-v1-d2s5`（22 vectors / 21 kinds）+ independent generator（per-call `expected_status` / anti-false-pass / exact kind set）+ production bridge + `tools/domain_scan_dsr2_gate.py` complete + compiler `-Wvla`。S1–S4 and D1 JSON byte-for-byte frozen。**Does not claim Stage 5 / D3 semantics / D4 mutation / S6 orchestration / public Runtime / ESP-IDF compile / hardware** | **S1〜S5+deps で D2（bounded scanner）のみ証明。Stage 5全体は証明しない** |
| **D2-S6** | Stage 5 orchestration hookup。scannerをcreate Stage 5へ接続。なおmutation 0（recovery mutation本体はD4） | D2を統合するだけで、S5未完了をD2完了に置換せず、D3/D4未完了をStage 5完了に置換しない |

**「S5 proves D2」の意味（D2-S0）:** S5 completionは、S1〜S5本体と、それらが要求する依存・vector/oracleが**すべて**完了していることの**bounded scanner composition**証明です。S4が未完了のまま（S1/S2/S3はimplementation completeでも **D2 incomplete**）、S5だけをcomplete宣言してはなりません。**D2 completionはS1〜S5 bounded scanner completeを意味し、Stage 5 / public Runtime completionはD3・D4および§1残gateが揃うまでfalseのままです。** S6は統合でありD2証明の代替でもStage 5証明でもありません。S0単独、L2a/L2b1、D1 codec完了、部分vector、body-only completeもD2完了宣言に使ってはなりません。

D3（cross-row semantic / cardinality / capacity / health / **witness member old/new・partial group・successor chain**）とD4（operation別mutation / convergence / FULL writer）は本ledgerの外です。§15 steps 1〜11の最終Stage 5 closed orderと§1 publish gateはD1+D2+D3+D4 compositionのRuntime objectiveのままです。

### 15.10 D2-S2 profile gateとone-iterator互換（D2-S2 Normative freeze）

**Decision identifier: D2-S2。** 本節はfamily 1〜4 integrity + exact profile gate + one-iterator reconciliationの**Normative freeze**であり、実装は production profiled begin / oracle / bridge / tests まで到達してよい。**S2 implementation complete ≠ D2 completion ≠ Stage 5 / public Runtime / ESP hardware completion。** S3–S6・D3・D4はincompleteのまま。L2b1 legacy oversized allocator re-read（§15.8）はD2正本ではなく本pathと分離したまま。

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
| D2-S5 | **実装済み:** `DSR1_SCAN` complete（**D2-detectable** corrupt>future + D3 corruption投入seam）+ `DSR2_ESP_BOUND` complete。sibling oracle **`spec/vectors/domain-scan-composition-v1.json`** / format **`ninlil-domain-scan-composition-v1-d2s5`**（§17.1.5）+ independent generator + production bridge + unit acceptance。S1〜S4 ownership vectorと依存D1 body pin | **S1〜S5+deps で D2（bounded scanner）証明。Stage 5 / D3 / D4 / S6 / public Runtime / ESP-IDF / hardware は証明しない** |
| D2-S6 | 新規D2 oracleを必須化しない。Stage 5 orchestration integration testはD2完了の代替にもStage 5完了の代替にもならない | S5未完了のままS6 successでD2 claim禁止 |

D0 completionは本章と12/13/14/16のmirror矛盾0です。D1 completionはPort call 0のkey/record/witness pure codecと全golden、**D2 completionはS1〜S5および依存が揃ったmutation 0 bounded scanner composition証明**です（partial group / orphan / counter / capacity / health の正しさは含まない）。D2-S0はNormative固定のみでimplementation pendingです。**Stage 5全体・public Runtime・SQLite recoveryの完成はD2完了後も、D3/D4および§1残gateが揃うまで主張しません。**

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
4. **S6** Stage 5 orchestration hookup
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
| Stage 5 / D3 / D4 / S6 / public Runtime / ESP-IDF / hardware | **still pending** |

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

**Explicit non-claims:** Stage 5 / D3 finding correctness / D4 mutation / S6 orchestration / public Runtime / ESP-IDF compile / hardware。
