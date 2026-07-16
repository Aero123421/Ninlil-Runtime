# 21. M3 slice: ESP-IDF durable storage port

状態: Informative / Normative-for-this-port（**M3 incomplete**）<br>
対象: ESP32-S3 向け `ninlil_storage_ops_t` production 候補 adapter<br>
実装: **PR #80 merged**（host conformance + target compile gates）。**power-cut HIL 未実行 / ESP FULL unproven**

## 1. 位置付けと非主張

本章は M3 の **durable storage port** を固定する。

**主張しない:**

- M3 complete / field-ready / V1 complete
- 実機 power-cut HIL の実行済み（harness と partition table は実装済みでも **HIL PASS ではない**）
- ESP flash 上の FULL commit success を HIL なしで production 保証すること
- NVS 単独での契約成立
- FreeRTOS / USB / radio / Site Membership・Attachment（Network Join umbrella） / KGuard
- compile success = HIL PASS

public ABI / wire は変更しない。

## 2. Backend 選定

| 候補 | 判定 |
| --- | --- |
| ESP-IDF NVS のみ | **不採用**（opaque key、multi-key FULL atomic、snapshot、COMMIT_UNKNOWN を閉じられない） |
| dual-slot + durable directory on ESP-IDF `wear_levelling` | **採用** |
| append journal | 将来候補。本 slice では不採用 |

Target の唯一の media authority は `wl_mount` で mount した logical media
である。read/write/erase はそれぞれ `wl_read` / `wl_write` /
`wl_erase_range`、終了は `wl_unmount` を通す。`esp_partition_write` /
`esp_partition_erase_range` へ直接書く二重経路は禁止する。Ninlil の
format 4 dual-slot は原子的checkpoint/recoveryを担い、ESP-IDF WL が
physical sector rotation / GC / wear distribution を担う。

## 3. 物理 media layout（固定 endian・固定 offset）

すべての persistent field は **little-endian**、**固定 offset** の byte 列として encode する。
**C struct の raw `memcpy` / `offsetof` CRC を persistent format に使わない。**

### 3.1 Top-level map

```text
offset 0:
  directory dual-slot region
    dir_slot_0  [NINLIL_PORT_ESP_STORAGE_DIR_BYTES]   # erase-aligned
    dir_slot_1  [NINLIL_PORT_ESP_STORAGE_DIR_BYTES]

offset 2 * DIR_BYTES:
  namespace data dual-slots
    for ns_index in 0 .. max_namespaces-1:
      data_slot_0 [SLOT_BYTES]
      data_slot_1 [SLOT_BYTES]
```

`DIR_BYTES = 4096`（SPI flash erase sector）。`SLOT_BYTES` は erase アライン済み。
これらは **WL logical offset** であり raw physical offset ではない。
reference partition は 4 MiB、`CONFIG_WL_SECTOR_SIZE_4096=y` を必須とする。
mount 後に `wl_sector_size()==4096` と `wl_size()>=logical media bytes` を
確認できなければ bind は失敗する。

### 3.2 Flash physical model（host も再現）

| 操作 | 規範 |
| --- | --- |
| erase | 領域を **0xFF** に。erase sector アライン必須 |
| program/write | **1→0 bit のみ**（`(old & new) == new`）。0→1 は失敗 |
| 新品 partition | 全域 0xFF = empty |
| host media | 上記 + erase/program/sync fault + 1024 physical-sector rotation accounting |

### 3.3 Wear / rotation budget

- host は 4 MiB / 4096-byte = 1024 physical sectors を round-robin rotation
  し、range erase を **sectorごと**に数える。full-slot 1 commit は18 sector
  eraseであり、1回と数えることは禁止する。
- target は ESP-IDF公式 `wear_levelling` の mount/read/write/erase/unmount
  のみを使用する。format 4 checkpointの片側が破損しても、他側のCRC-valid
  generationから復旧するobservable semanticsはhost/target共通である。
- WL metadata/rotation用に20%を保守的に除外し、erase endurance 10,000回、
  full snapshot 18 sectorsと初期seed reserveなら **454995 commits** が
  declared assumptions下のprofile estimate。
  これは無限寿命保証ではない。実flashのdatasheet enduranceと実測commit
  cadenceをリリースごとに掛け合わせる。例えば1 commit/10分なら約8.6年、
  1 commit/分なら約316日であり、後者をfield-readyとは認定しない。
- 頻度を説明上だけ下げて合格にしない。上記budgetを満たさないtraffic
  profileには、partition拡大または将来のdelta journalを仕様変更として
  選ぶ。現backendが18-sector checkpointである事実はgateで固定する。

Admissionは機械的である。target bindはreference定数でなく、mount後の
`wl_size()/wl_sector_size()` を `wl_usable_sector_count` として使用する。
`planned_full_commits_per_day * planned_service_days` が保守budgetを超える
configはinitを拒否する。`planned_full_commits_per_day` は **この物理 WL
partition / wear-budget domain で実際に発生する全 instance / 全 namespace
の FULL commit 合計**（1日あたり計画値）である。

- **別 physical partition（または別 wear-budget domain）** は各自が独立した
  budget と独立した `planned_full_commits_per_day` を持つ。他 partition の
  traffic を合算しない。
- **同一 domain 内**では namespace 数で掛けない。同一 traffic を、同じ
  partition を共有する複数 instance / 複数 config へ二重加算しない。
- 本 field は「1 instance あたり」でも「1 namespace あたり」でもなく、
  **その wear domain 全体で media に降りる FULL commit の計画合計**である。

production reference（当該 4 MiB domain で 200 FULL/day 合計、1825日）は
1 MiB（113329）/ 2 MiB（227218）で拒否、4 MiB（454995）で許可する。

ただしこれは **misconfiguration guard** であって保証下限や実wear消費telemetryではない。
ESP-IDF WLはphysical erase countを本portへ公開しない。またFormat 4には
power-cut atomicなdurable global usage counterがないため、namespace世代の和を
used/remainingとして偽装しない。FULL production acceptanceはpower-cut HILに加え、
delta journal / 実wear enforcement、または別途承認された耐久契約までpendingである。
既存どおりESP targetは `FULL` に `STORAGE_OK` を返さない。
WL内部metadataのerase/write amplificationもこのestimateから直接は観測できず、
実機delay sweep・flash datasheet・field cadenceの承認なしに耐久保証へ昇格しない。

### 3.4 Durable namespace directory（format **4**、P0）

Directory は **exact namespace bytes → fixed ns_index** の唯一の正本である。
RAM 上の `namespaces[]` は volatile cache であり、**reboot / object
zero+reinit 後は media directory からのみ復元**する。

Directory image（exact sector `DIR_BYTES=4096`）:

| offset | size | field | notes |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | `NILD` LE |
| 4 | 4 | format_version | u32 LE = **4** |
| 8 | 8 | directory_generation | u64 LE ≥1 |
| 16 | 4 | max_namespaces | u32 LE |
| 20 | 8 | max_entries_per_namespace | u64 LE |
| 28 | 8 | max_bytes_per_namespace | u64 LE |
| 36 | 4 | entry_capacity | hard max |
| 40 | 8 | reserved_zero | 0 |
| 48 | 4×272 | entries[i] | 全 entry CRC-bound |
| 1136 | 2952 | zero padding | CRC-bound（program 時 0x00） |
| 4088 | 4 | image_crc32c | over **`[0,4088)`** |
| 4092 | 4 | seal_marker | **0xFFFFFFFF=未 seal（erase 残）** / `0x4C414553`=committed |

Directory entry `entries[i]`（272 bytes）:

| offset | size | field |
| ---: | ---: | --- |
| 0 | 1 | state FREE/OCCUPIED |
| 1 | 1 | name_length |
| 2 | 2 | reserved_zero |
| 4 | 4 | schema |
| 8 | 255 | name |
| 263 | 8 | **data_seed_generation** u64 LE（OCCUPIED は ≥1、FREE は 0） |
| 271 | 1 | reserved_zero |

**Dual-slot recovery（directory）:** 片 slot が torn/CRC corrupt でも **他 slot が valid sealed** ならその世代を採用。両方 non-valid のみ empty（両 0xFF）または CORRUPT。

**OCCUPIED 新規 publish 前:** 当該 `ns_index` の data slot に **durable empty seed**（generation=`data_seed_generation`、entry_count=0）を書いてから directory を commit。
OCCUPIED で両 data slot invalid（両 erase または corrupt）→ **silent empty 禁止、CORRUPT/fail-closed**。

Directory commit:

1. erase inactive（0xFF）
2. encode seal=**0xFFFFFFFF**（CRC は entries+padding 込み）
3. full write + sync
4. seal 4-byte を `SEAL_COMMITTED` に program（1→0 のみ）+ sync

### 3.5 Namespace data slot image

Header exact 320 bytes、format_version **4**。empty seed は generation≥1 かつ entry_count=0 の **valid image**。
**全 0xFF = erased empty（decode 0）**。非 erase で CRC/identity 失敗 = corrupt（-1）。

**Dual-slot recovery（data）:** 片側 valid なら採用。OCCUPIED で両方 invalid → CORRUPT（empty と混同しない）。

## 4. Reboot / object lifetime（P0）

| 事象 | 必須挙動 |
| --- | --- |
| process reboot | storage object は zero。`init` は directory を読み exact name→index を復元 |
| `simulate_crash` | volatile handle/txn/iter/lease のみ破棄。**directory cache も捨ててよい**が、再 open 前に media から再ロード必須 |
| `simulate_full_reinit`（host test） | object 完全 zero + `init` 再実行。open 順 permutation でも同じ name が同じ index |

**禁止:** RAM `namespaces[].in_use` を durable index の正本にすること。
以前 index=1 の namespace を reinit 後に index=0 へ割当て、他 namespace の slot を empty と誤認して上書きすることは **P0 欠陥**であり禁止。

## 5. Workspace / production profile（P1）

### 5.1 Target assumptions（Seeed XIAO ESP32-S3）

| 資源 | 前提 |
| --- | --- |
| Internal SRAM | 約 512 KiB（.text/.data/.bss/heap/stack と共有） |
| PSRAM | 8 MiB（XIAO ESP32-S3 標準）。**production storage workspace は PSRAM 必須** |
| Flash | app + `ninlil_storage` data partition（partition table 同梱） |

同梱CSVの4 MiBは **8 MiB flash reference profile** であり、OTA slotとの併用を
保証しない。factory app 1.5 MiB + 4 MiB storageを基準とする。dual OTAが必要な
製品はflash容量・app slot・storage profileを再配分し、実`wl_size` admissionを
通すこと。4 MiBへのsilent拡大や任意のESP32-S3での成立claimは禁止する。

Internal SRAM だけに full view pool を置く profile は本 production default では **成立させない**。

### 5.2 Hard ceilings と production default

| 定数 | Hard ceiling | Production default |
| --- | ---: | ---: |
| namespaces | 4 | 2 |
| staged entries / txn | 64 | committed capacity 32 |
| staged logical bytes / txn | 139264 | committed capacity 69632（**single value 65536 を維持**） |
| live txns | 3 | 3（RW≤1 + RO） |
| live iters | 2 | 2 |

**Single value 上限 `NINLIL_M1A_MAX_STORAGE_VALUE_BYTES=65536` を silent clamp しない。**
max_bytes を下げて 65536 を不可能にする default は禁止。69632 は `16+1+65536` を含む。

Total entry/byte capacityはcommit時の**final-net view**だけへ適用する。`put`は
別のPSRAM scratchへsorted final viewを再構築し、成功時だけtransaction viewを
deep-copyで交換する。旧値と新値を同じappend-only blobへ同時蓄積しないため、
同一keyを任意回replaceしてもstaging bytesは増えない。失敗時はtransaction view
をbyte-for-byte変更しない。production上限いっぱいの状態での
`put(new) -> erase(old)`はentry/byteとも許可し、逆順と同じfinal viewをcommitする。

物理RAMは有限なので、commit capacityとは別にstaging hard ceilingを明示する。
14章のprovider-neutral minimum `2 * capacity.max_*`をproduction defaultへ適用した
inclusive ceilingが64 entries / 139264 logical bytesである。64件ちょうど、または
139264 bytesちょうどの中間viewは必ず受理する。65件目または139265 bytes目のcallは
M1a Core plan precondition外であり、本providerはtransaction viewを変更せず
`NO_SPACE`を返す。最大valueのold/new coexistenceと32件満杯からのput-before-eraseを
包含し、単なるmutation回数や過去の置換回数では消費しない。Coreはbegin/final view
のunion boundを事前検査するため、本ceiling超過callを生成しない。

この事前検査はテスト用predicateではなく、production private Core の
provider-neutral canonical planner/executorを唯一の書込みseamとして実装する。
plannerは、実際のbegin snapshotとcanonical final viewのsorted unique rowを受け、
`capacity()`をREAD_WRITE `begin`より前にexactly 1回呼ぶ。返却shapeを12章の
closed ruleで検査し、begin viewの件数/logical bytesが`used_*`とexactly一致する
こと、begin/finalが各`max_*`以内であること、およびchecked
`begin + final <= 2 * max_*`を確認してからだけexecutorを許可する。
callerが任意の「intermediate件数」だけを申告して通すAPIは禁止する。したがって
empty→empty planを64件/139264 bytesとして偽装するdegenerate false positiveは
成立しない。境界はinclusiveで、実begin/finalから得た64件/139264 bytesは受理し、
65件/139265 bytesは`begin`/`put`/`erase`/`commit`すべて0で拒否する。

executorはfinal rowを各key最大1回、final encoded valueで`put`し、finalにない
begin keyを各最大1回`erase`して、`FULL`でcommitする。全M1a READ_WRITE builder
（bootstrap、named operation、cleanup batch、destroy recovery groupを含む）は、
実装された時点からこの共通seamを経由し、独自に`begin`してはならない。本sliceで
production sourceに存在するREAD_WRITE builderはbootstrapだけであり、同builderを
本seamへ接続する。

`iter_open`はtransaction viewをiterator専用PSRAM snapshotへdeep-copyする。
open後のput/eraseは既存iteratorへ反映せず、新規iteratorだけが更新後を読む。

### 5.3 RAM 配置と stack 予算

- **Control + txn views (3) + iterator snapshot views (2) + dual load workspace views (2) + mutation scratch + pack/dir scratch** は単一 `ninlil_port_esp_storage_t`（LP64 host実測sizeof 1,334,736 bytes、object ceiling **1,572,864**）。view ceilingは172,032 bytes。**関数 automatic にviewを置かない**。
- 関数 stack 上限 **2048 bytes**（FreeRTOS 4–8 KiB task の半分未満。根拠: nested open/begin + ISR 余裕）。`-Wframe-larger-than=2048` と **`.su` 実 parse**（`tools/esp_storage_stack_gate.py --require-su`）で enforce。regex claim のみ禁止。
- ESP: object は **`esp_ptr_external_ram`（`esp_memory_utils.h`）**。internal BSS/DRAM は init 拒否。
- **PSRAM workspace ownership:** opaque flash binder が PSRAM workspace を所有する。
  caller は `flash_bind` 成功後に exactly 1 回 `flash_unbind` する責任がある。
  同一 partition への同時 live binding、unbind なしの二重 bind は禁止。
- smoke: binder 経由 `heap_caps_calloc(MALLOC_CAP_SPIRAM)`。sdkconfig: SPIRAMを有効にする。objectはheap allocationなのでexternal BSS/DATA segment配置optionへ依存しない。
- map gate: 実 `.map` を multiline-safe に parse し、required section/symbol の parse count 0 は必ず fail。large storage symbol の internal DRAM 配置と `.dram0.bss` overbudget も fail。target CI は **smoke map と HIL map の両方**を required で `esp_storage_map_gate.py` に通す。self-test は official map positive と synthetic missing/overbudget/malformed/0-match negative を含む。
- partition CSV: smoke project root 基準 **`../partitions/ninlil_storage.csv`**。
- host: placement 検査は常に OK。

### 5.4 seed → directory publish の COMMIT_UNKNOWN

1. seed または directory commit が indeterminate なら **RAM を OCCUPIED 正本にしない**。
2. `directory_cache_fenced=1` とし cache を invalidate。
3. 次 `open` は media 再読 + all-old/all-new 収束。

### 5.5 Sizeof / budget gates

- host: sizeof ceiling + **stack .su parse** + packaging partition path。
- target CI (official idf v5.5.3 image): partition resolve + smoke/HIL build + **smoke map と HIL map の両方を map gate** + public API **readelf visibility** + storage TU の stack `.su` **必須 parse**。欠落・空・解析不能は失敗でありskipしない。
- smoke: **実体 allocate + init + open + put + FULL commit**を実行し、ESP_UNPROVENが`COMMIT_UNKNOWN`であることを要求する（sizeofだけは禁止）。

## 6. Handle / txn / iter generation tokens（P1）

Opaque handle は **index+1 単独禁止**（ABA）。

```text
index_bits = ceil(log2(max_slots + 1))
packed = (generation << index_bits) | (index + 1)
```

- 32-bit targetでもhandleは29-bit世代、txn/iterは30-bit世代を持つ。
  旧16-bit固定field（約32768 lifecycleで枯渇）は禁止。
- live object は `generation` を保持。再割当時に1回だけstrict increment。
  close/consumeと再割当の二重incrementは禁止。
- 最大世代からwrapして0に戻る割当は **拒否**（`NO_SPACE` / fail-closed）。
  host 64-bit buildでも強制32-bit budget conformanceを実行する。
- stale close/put/rollback/iter_* は **CORRUPT**、mutation 0。

## 7. FULL durability boundary（P1）

### 7.1 ESP-IDF documented boundary（本 slice の閉じ方）

Production targetの公開port headerはstorage/media/workspaceのconcrete layout、
media operation table、FULL policy、汎用`init`、host simulator/reinit seam、
**HIL observer enum/callback/setter** を公開しない。HIL seam は
`ports/esp-idf/storage/private/esp_storage_hil_observer.h` のみに置き、
HIL app / host private tests が PRIV_INCLUDE でだけ利用する。private HIL
symbol は `visibility("hidden")` とする。
ESP targetの唯一のconstruction seamはopaqueなflash bindingであり、binderがPSRAM
workspace、WL media、`FULL_ESP_UNPROVEN`を内部所有する。callerがpolicyを渡すAPI、
`FULL_HOST_MODEL`をtarget compileへ持ち込むAPI、concrete objectを組み立てるAPIは
禁止する。HOST_MODELとhost mediaはhost testだけのprivate header/sourceへcompile
outし、ESP target archiveのpublic symbolにも含めない。

HIL attestation flagは本sliceでは定義しない。`ESP_PLATFORM`でcompileされる
`commit(FULL)`にはunattested mediaから`STORAGE_OK`へ到達するbranchを置かず、media
writeが完了しても必ず`COMMIT_UNKNOWN`とする。official target gateは、公開headerを
使ったHOST_MODEL/generic-init/concrete-workspace/HIL-observer remix bypassが
compile不能であること、旧bypass symbolがarchiveの`nm`に存在しないこと、
公式ELF/archiveを **xtensa `readelf -Ws` 実出力**で検査し
`private_set_hil_observer` / `flash_set_hil_observer` が **GLOBAL HIDDEN**、
`flash_bind` / `flash_unbind` が **GLOBAL DEFAULT** であること、および
smoke/HIL runtimeがFULL OKを受理しないことを同時に検査する。source文字列
の visibility 属性一致だけでは target 合格にしない。
（owner/cell 側の別readelf gateとは独立。rebase後に合成する。）

ESP-IDF `wl_write` / `wl_erase_range` は logical wear-levelled mediaを更新し、
成功 return は当該APIの完了境界である。logical offset/lengthはmount後の
`wl_size` 内、eraseは4096-byte alignedでなければならない。read/eraseの
失敗はinit失敗またはread-path `CORRUPT`、inactive eraseのdefinite失敗は
`IO_ERROR`、write/syncの着地が確定できない経路は`COMMIT_UNKNOWN` とする。
ただし本 repository の **multi-key FULL atomic + power-cut all-old/all-new** は、API 成功だけでは **実機で未証明**である。

したがって:

| media class | `commit(FULL)` success (`STORAGE_OK`) |
| --- | --- |
| host model media | 許可（host conformance が model を証明） |
| ESP flash **without** HIL attestation | **禁止**。write 経路を実行しても public には `COMMIT_UNKNOWN` を返すか、明示 development 経路以外では bind/init を fail-closed |
| ESP flash **with** HIL attestation flag（V1 条件） | 許可候補。本 slice では attestation を **立てない** |

**Production success に HIL 未実施を見せない。**
ESP smoke は allocate/init/open と「FULL OK を返さないこと」を検証する。

### 7.2 HIL harness（実装する / 実行は未）

同梱:

- `ports/esp-idf/partitions/ninlil_storage.csv` — `ninlil_st` data partition
- `ports/esp-idf/hil_app/` + `ports/esp-idf/storage/hil/` — build可能firmware、power-cut matrix、strict host runner
- docs に V1 完成条件: 実機 power-cut × named boundary × 両 truth

port-private observer は private HIL header 経由でのみ設定でき、productionと
同じstorage control flow内で次のexact eventを発行する。observer未設定時は
副作用0であり、public Storage ABI / public flash bind API /
`FULL_ESP_UNPROVEN` policyを変更しない。

| Scenario | armed exact event | Cut contract |
| --- | --- | --- |
| D0 | `DIR_BEFORE_ERASE` | event直後からerase callを跨ぐdelay sweep |
| D1 | `DIR_BEFORE_WRITE` | event直後からfull directory writeを跨ぐdelay sweep |
| D2 | `DIR_BEFORE_SEAL` | body sync後、seal program callを跨ぐdelay sweep |
| S0 | `DATA_BEFORE_ERASE` | event直後からinactive-slot eraseを跨ぐdelay sweep |
| S1 | `DATA_BEFORE_WRITE` | event直後からfull data writeを跨ぐdelay sweep |
| S2 | `DATA_AFTER_SYNC_BEFORE_RETURN` | sync成功後、public commit return前のHIL-only observation windowでcut |

Data truthは単一keyではない。OLD=`a:old-A, b:old-B, c:ABSENT`、NEW=
`a:new-A-long, b:ABSENT, c:new-C` とし、1 FULLでreplace+erase+addする。
reboot後はentry count、logical bytes、3 keyのpresence/length/bytesをexact比較し、
OLD/NEW以外（partial/mixed/missing/extra）は`INVALID`でrunnerが拒否する。
firmwareはcanonical snapshot SHA-256を出し、runnerはscenario/event/state別の
期待digestを独立再計算して一致を要求する。全atomic scenarioは各run前に
partition erase/resetする`--prepare-json`が必須で、HIL-NSは別手順である。
firmwareはexact eventで対象callを停止し、runnerがpower threadをarmした後、
host timerをreleaseして直ちにexact `CONTINUE <scenario> <event>`をwrite/flush
してcallを再開する。delay原点はtarget call直前を狙うhost側近似でありcycle
exactではない。delay=0はcall前に切れてOLDとなり得る。単一runや特定delayは
torn発生の証明ではないため、各eventでOLD側、NEW側、transition付近の反復を
含むsweepと全raw evidenceを保存する。power-off commandは4秒でtimeoutし、
最大delay 5秒との合計をS2の10秒target window内に制約する。timeout runは
evidenceとして受理しない。

**本 slice は HIL 未実行であり、M3 complete を名乗らない。**

## 8. Host conformance（必須）

1. 0xFF erase empty、新品 partition init、1→0 program reject、aligned erase、sector単位wear max/min/skew
2. dual-slot: 片側 corrupt でも他側 recovery（directory/data）
3. directory entry CRC bind、duplicate exact namespace拒否、unused namespace tail zero、seed_generation minimum、torn seal（seal=0xFF）、observer exact event順序
4. OCCUPIED 両 data invalid → CORRUPT（silent empty 禁止）
5. 29/30-bit generation ABA/wrap、FULL unproven、65536 replacement、entry/byte put-before-erase final-net、iterator deep snapshot、失敗put mutation-0、full reinit
6. target source gate: `wl_mount/read/write/erase/unmount`、raw write/erase二重authority禁止

## 9. Acceptance（本修正）

- [x] durable directory により reinit 後も name→index 安定（host）
- [x] persistent codec が struct ABI 非依存
- [x] production profile が 65536 value exact cold-reopenを維持しPSRAM fail-closed
- [x] smoke 実体 allocation+init source + host packaging gate
- [x] ESP FULL OK 非 claim + executable HIL harness/partition 同梱
- [x] 29/30-bit generation tokens + forced32-bit wrap conformance
- [x] WL profile estimate + host sector accounting
- [x] planned-profile admission。実wear used/remaining enforcementは非claim
- [x] host Debug / ASan / tests-OFF / package
- [ ] official ESP-IDF esp32s3 target CI（PRで実行）
- [ ] 実機power-cut HIL / actual wear acceptance / field-ready
