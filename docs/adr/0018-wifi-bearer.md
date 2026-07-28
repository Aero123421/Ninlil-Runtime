# ADR-0018: Wi-Fi Packet Link for the Fabric Bearer

状態: **Proposed — docs-only（SPEC_ACCEPTED / implementation / RELEASE_SUPPORTED pending）**  
提案日: 2026-07-28  
SPEC_ACCEPTED日: —（未受入）  
RELEASE_SUPPORTED日: —（未達）

## Context

ESP32-S3はWi-Fiを利用できるが、現行ESP-IDF componentはWi-Fi driver、IP session、
peer framingを実装していない。Wi-Fiを単なる「高速なら使う経路」とすると、association、
peer identity、Ninlil Attachment、custody、Application Receiptが混同され、切断時に
false successやsilent downgradeを起こす。

Wi-FiはLoRaより大きい帯域を提供できる一方、AP、DHCP、IP、backhaul、peer processの
failure domainを追加する。Runtime CoreへsocketやESP-IDF APIを持ち込まず、ADR-0017の
Fabric Bearerへpacket-linkとして接続する必要がある。

## Decision

1. Wi-FiをADR-0017 Fabric registryのpacket-link kindとして実装する。Runtimeからは
   Fabricが1 logical bearerに見え、`platform.h`単一Bearer ABIは変更しない。
2. V2 reference transportはauthenticated reliable byte-streamとする。POSIXはTCP、
   ESP32-S3はESP-IDF Wi-Fi station + TCPをreference portとする。UDP/datagram、SoftAP、
   Ethernet、cellularは別packet-link profileであり、本ADRからsupportを導出しない。
3. 状態を次の順で分離する。

   ```text
   DISABLED -> RADIO_READY -> ASSOCIATED -> IP_READY
            -> CHANNEL_AUTHENTICATED -> PEER_SESSION -> ATTACHED
   ```

   後段失敗を前段成功へ丸めず、Wi-Fi associationやTCP connectをpeer identity、Attachment、
   custody、Application Receiptの証拠にしない。
4. peer endpointはControllerが署名/認証したconfigurationで指定する。mDNS、broadcast discovery、
   last-known addressは補助候補にできるがauthorityにならない。未知peerへ自動attachしない。
5. production候補security profileは本ADRの
   [NINLIL-WIFI-TLS13-P256-V1](#ninlil-wifi-tls13-p256-v1-exact-profile)だけとする。
   pure ESP-TLS実装、backend default、best-effort negotiationからこのprofileを導出しない。
   secure channelがないprofileは`TEST/LAB_ONLY`に限定する。
6. Wi-Fi stream recordを**NWB1 framing version 1**候補とする。全整数はbig-endian。

   | Offset | Bytes | Field |
   | ---: | ---: | --- |
   | 0 | 4 | magic ASCII `NWB1` |
   | 4 | 2 | version = 1 |
   | 6 | 2 | header_length = 40 |
   | 8 | 4 | total_length |
   | 12 | 4 | payload_length |
   | 16 | 16 | authenticated non-zero session_id |
   | 32 | 4 | per-direction sequence |
   | 36 | 4 | CRC32C |

   payloadはexact 1個のNFL1 packetとし、`payload_length`は584..2048、
   `total_length = 40 + payload_length`で最大2088 bytesとする。CRC32Cはreflected Castagnoli
   polynomial `0x82F63B78`、initial `0xffffffff`、final XOR `0xffffffff`を用い、
   offset 36..39を0としてrecord全体を計算する。
7. `session_id`はTLS exporterからexactに導出する。

   ```text
   context =
     authority_id[16] || authority_term_u64_be || assignment_epoch_u32_be ||
     tls_client_role_u8(0x01) || tls_client_runtime_id[16] ||
     tls_server_role_u8(0x02) || tls_server_runtime_id[16] ||
     attachment_binding_digest[32]
   session_id =
     TLS-Exporter("EXPORTER-Ninlil-NWB1-v1", context, 16)
   ```

   `tls_client_runtime_id`と`tls_server_runtime_id`はauthenticated TLS handshake roleで固定し、
   client/server双方が同じ順序・同じrole byteでcontextを組み立てる。local/peer順への置換や
   runtime IDのlexicographic sortは禁止する。authority bindingはNFL1と同じclosed groupで、
   Wi-Fi profileがBOUNDを要求するflowでは3 fieldすべてnon-zero、controllerless profileを
   別途明示許可する場合だけ3 fieldすべてzeroとする。mixed groupはsession不成立とする。
   exporter失敗またはall-zero resultはsession不成立、NFL1 delivery 0とする。送受信方向は同じ
   session_idを使うが、sequence stateは方向ごとに独立する。
8. 各方向の最初のsequenceはexact 0、以後exact `previous + 1`とする。gap、duplicate、
   out-of-order、unknown version、header/total/payload不一致、CRC不一致、wrong session、
   invalid NFL1はrecord delivery 0でconnectionを閉じる。byte単位のmagic再走査で同じsessionを
   継続しない。`UINT32_MAX`は決して送信せず、`UINT32_MAX-1`送信後はclean closeしてfresh full
   handshake/session_id/sequence 0へ切り替える。wrapは禁止する。
9. incremental parserは40-byte header + 2048-byte payloadの固定buffer内でpartial read/writeを
   処理する。最大1 recordを超えて無制限にread-aheadせず、backpressureを上流予約へ伝える。
   NWB1 codec、queue、RX/TX record bufferはcaller-ownedで、heap growth、VLA、raw C struct、
   pointer/paddingの送信を禁止する。stock TLS backendのallocator contractは§14で別に固定し、
   TLS内部allocationをportable Coreのheap-free claimへ含めない。
10. NWB1 recordのsocket write完了、peer kernel ACK、TLS record成功はcustodyではない。
   U6 custodyは[26章](../26-u6-transport-custody.md)のdual FULL後だけ成立する。
   multi-frameはADR-0021の新versionを要する。
11. path selectionはADR-0017のdescriptor/security/availability/admission snapshotに従う。
    unknown/unattested profile、peer/Attachment binding不一致はineligibleである。Wi-Fi断時、
    LoRa/local pathがsecurity、payload/fragment、
    deadline、evidence、regulatory/airtime budgetを満たす場合だけnew attemptでfallbackする。
    満たさなければ明示的にunavailable/deadline failureを返す。
12. management bulk、application data、critical controlは別quota/queueとし、bulkがcritical trafficを
    starveしてはならない。per-peer frame/byte/inflight、reconnect rate、backoff、keepalive、
    session数は§14のexact boundを超えてはならない。
13. ESP sleep中のWi-Fi unavailableはavailability epochを進める。起床予定をavailableとして
    偽装せず、sleepy receive windowとdeadlineの交差をadmission時に検査する。

## NINLIL-WIFI-TLS13-P256-V1 exact profile

本節は**Proposed normative candidate**であり、まだ`SPEC_ACCEPTED`ではなく、実装済み、
target合格、`RELEASE_SUPPORTED`も意味しない。
本profileを名乗るclient/serverは本節の全条件を満たす。backend defaultへ条件を委ねず、
handshake完了後も全postconditionを検査してからだけ`CHANNEL_AUTHENTICATED`へ遷移する。

### 14. Backend splitとopaque channel

Portable CoreとFabric schedulerへTLS library型、socket、証明書parserを公開しない。private
`wifi_secure_channel_v1`はopaque handleと次の意味だけを共有する。

```text
client_init / server_init
handshake_step -> COMPLETE | WANT_READ | WANT_WRITE | CLOSED | FATAL
read_step / write_step -> byte_count + WANT_READ/WANT_WRITE/CLOSED/FATAL
authenticated_peer_binding
export_session_id
close
```

`WANT_READ/WANT_WRITE`後は同じ未完了operationを再開する。positive partial write後だけoffsetを
進め、0-byte writeを送信に使わない。`FATAL`後のhandle再利用は禁止する。deadline、socket readiness、
RX/TX reservationはadapter外から渡し、TLS backendがunbounded waitやqueueを所有しない。

Hostは§14.1.2でpinするOpenSSL `openssl-3.5.7`の`SSL` API、ESP32-S3はESP-IDF supplied mbedTLSを**directに**
使用し、片方だけをcompile/linkする。ESP-TLS public APIは次を同時に表現できないため、本profileの
channel implementationに使用してはならない。

- server-side exact TLS version/ciphersuite
- client/server exact groupとsignature scheme
- accepted authority clock/revocationを使うverify callback
- profile-owned allocator budgetとpeer binding検証

`esp_tls_get_ssl_context()`を用いたpost-handshake accessを上記pre-handshake設定の代替にしない。
pinはESP-IDF `v5.5.3` commit
`2c211b236707889e8400c4dc5644dd5c4ee071e0`、その`components/mbedtls/mbedtls`
gitlink `ffb280bb63c78bfec1e1ab55040671768c85c923`とする。どちらかが一致しないtarget buildは
profile不一致でconfigure failとする。

### 14.1 Exact TLS configuration

両backend、両roleの唯一の成功値は次とする。

| Parameter | Exact value |
| --- | --- |
| Protocol | TLS 1.3 only |
| Ciphersuite | `TLS_AES_128_GCM_SHA256` (`0x1301`) only |
| Key exchange group | `secp256r1` / P-256 (`0x0017`) only |
| Handshake signature scheme | `ecdsa_secp256r1_sha256` (`0x0403`) only |
| Authentication | authority-issued mutual X.509 during initial handshake |
| SNI/hostname | v1では送信・照合しない。authenticated endpoint configurationは接続先候補に限る |
| Renegotiation/post-handshake auth | disabled |

ESP adapterは`mbedtls_ssl_config_defaults()`後、`mbedtls_ssl_setup()`前にstatic-lifetimeの
singleton/zero-terminated listを使い、少なくとも次を呼ぶ。

```c
static const int wifi_suites[] = {
    MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0
};
static const uint16_t wifi_groups[] = {
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, 0
};
static const uint16_t wifi_sig_algs[] = {
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    MBEDTLS_TLS1_3_SIG_NONE
};

mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
mbedtls_ssl_conf_ciphersuites(conf, wifi_suites);
mbedtls_ssl_conf_groups(conf, wifi_groups);
mbedtls_ssl_conf_sig_algs(conf, wifi_sig_algs);
mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
mbedtls_ssl_conf_verify(conf, profile_verify_cb, snapshot);
```

上記listの終端値とstatic lifetimeを変えてはならない。client/server双方がtrust anchor、
role固有leaf chain、P-256 private keyを設定する。handshake成功後にversion、
ciphersuite、peer certificate、binding、full-handshake state、exporterを再検査する。
clientは`mbedtls_ssl_setup()`成功後、handshake前に
`mbedtls_ssl_set_hostname(ssl, NULL)`を明示的に呼び成功を確認する。これはpinned mbedTLSへ
hostname検査を意図的に使わないことを通知するためであり、server identity検査を省略する意味ではない。
server identityは§14.2のcritical bindingとprovisioning recordで置き換える。

ESP32-S3 imageは次の値をgenerated `sdkconfig`とCI artifactで照合する。記載していない
mbedTLS optionから追加profile capabilityを導出しない。

```text
CONFIG_ESP_TLS_USING_MBEDTLS=y
CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y
CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_EPHEMERAL=y
CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_PSK=n
CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_PSK_EPHEMERAL=n
CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y
CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y
CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS=n
CONFIG_MBEDTLS_SERVER_SSL_SESSION_TICKETS=n
CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS=n
CONFIG_ESP_TLS_SERVER_SESSION_TICKETS=n
CONFIG_MBEDTLS_DYNAMIC_BUFFER=n
CONFIG_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH=n
CONFIG_MBEDTLS_ASYMMETRIC_CONTENT_LEN=y
CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN=16384
CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN=4114
CONFIG_MBEDTLS_TLS_SERVER_AND_CLIENT=y
CONFIG_MBEDTLS_ECP_C=y
CONFIG_MBEDTLS_ECDH_C=y
CONFIG_MBEDTLS_ECDSA_C=y
CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED=y
CONFIG_MBEDTLS_AES_C=y
CONFIG_MBEDTLS_GCM_C=y
CONFIG_MBEDTLS_HKDF_C=y
CONFIG_MBEDTLS_SSL_RENEGOTIATION=n
CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC=y
CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=n
CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC=n
CONFIG_MBEDTLS_DEFAULT_MEM_ALLOC=n
CONFIG_MBEDTLS_IRAM_8BIT_MEM_ALLOC=n
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=n
CONFIG_MBEDTLS_ECP_RESTARTABLE=n
CONFIG_MBEDTLS_THREADING_C=n
CONFIG_MBEDTLS_THREADING_ALT=n
CONFIG_MBEDTLS_THREADING_PTHREAD=n
CONFIG_MBEDTLS_HARDWARE_AES=n
CONFIG_MBEDTLS_AES_USE_INTERRUPT=n
CONFIG_MBEDTLS_AES_USE_PSEUDO_ROUND_FUNC=n
CONFIG_MBEDTLS_HARDWARE_GCM=n
CONFIG_MBEDTLS_GCM_SUPPORT_NON_AES_CIPHER=n
CONFIG_MBEDTLS_HARDWARE_MPI=n
CONFIG_MBEDTLS_LARGE_KEY_SOFTWARE_MPI=n
CONFIG_MBEDTLS_MPI_USE_INTERRUPT=n
CONFIG_MBEDTLS_HARDWARE_SHA=n
CONFIG_MBEDTLS_HARDWARE_ECC=n
CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK=n
CONFIG_MBEDTLS_ROM_MD5=n
CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN=n
CONFIG_MBEDTLS_TEE_SEC_STG_ECDSA_SIGN=n
CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN_MASKING_CM=n
CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN_CONSTANT_TIME_CM=n
CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY=n
CONFIG_MBEDTLS_ATCA_HW_ECDSA_SIGN=n
CONFIG_MBEDTLS_ATCA_HW_ECDSA_VERIFY=n
CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL=n
CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL_BOOTLOADER=n
CONFIG_ESP_TLS_USE_SECURE_ELEMENT=n
CONFIG_ESP_TLS_USE_DS_PERIPHERAL=n
```

上記`n`はKconfig dependencyで非表示になるsymbolも含む**effective false**条件である。
generated `sdkconfig.h`に対応`CONFIG_*` macroが1個でも定義されるimageはconfigure failとする。
さらに`MBEDTLS_AES_ALT`、`MBEDTLS_GCM_ALT`、`MBEDTLS_SHA1_ALT`、`MBEDTLS_SHA256_ALT`、
`MBEDTLS_SHA512_ALT`、`MBEDTLS_MD5_ALT`、`MBEDTLS_MPI_EXP_MOD_ALT(_FALLBACK)`、
`MBEDTLS_MPI_MUL_MPI_ALT`、
`MBEDTLS_ECP_MUL_ALT(_SOFT_FALLBACK)`、`MBEDTLS_ECP_VERIFY_ALT(_SOFT_FALLBACK)`、
`MBEDTLS_ECDSA_SIGN_ALT`、`MBEDTLS_ECDSA_VERIFY_ALT`のpreprocessor definitionを0とする。
ESP32-S3でdependency上利用不能なECC/ECDSA symbolも、target変更時のsilent enableを防ぐため
同じabsence gateへ含める。

#### 14.1.1 ESP TLS crypto allocation closure

hard allocation claimのclosureはdirect ESP mbedTLS adapter、到達するpinned
`mbedtls`/`mbedx509`/`mbedcrypto` object、PSA、profile allocator callback、および同じlibraryを
共有する事前登録済みcrypto co-tenant adapterとする。現行V2 compositionで許可するco-tenantは
Accepted R7 private provider ABIのESP mbedTLS raw adapter 1 familyだけで、そのfactoryと
SHA-256、HKDF-Extract/Expand、AES-128-GCM Seal/Open callbackのexact source list/hashをclosure
reportへ固定する。R7 portable wrapperはbackend callerではなくprivate callback ABIのcallerである。
未知co-tenantや別のdirect mbedTLS callerはprofile revisionなしに追加しない。Wi-Fi/lwIP/socket
自体のallocationは別resource domainであり、このTLS budgetへ混ぜない。closure内のdynamic
allocationは`mbedtls_calloc/mbedtls_free`からprofile callbackへ到達する経路だけを許す。
profile callback object 1個だけがoverflow検査後の
`heap_caps_calloc(..., MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`と`heap_caps_free()`を呼べる。
owner、requested/actual size、alignment、canary、intrusive owner-list linkは各allocation前置headerへ
置き、別ledger heapを作らない。header/paddingを含む実確保byteをowner budgetへchargeし、
counter/list rootはfixed static storage、callback中のrecursive mbedTLS/PSA callは禁止する。
`malloc/calloc/realloc/free`、
別`heap_caps_*`、`esp_mbedtls_mem_*`へのdirect callはcallback objectを含め0とする。

machine-readable `CLOSURE_ROOTS_V1`はWi-Fi client/serverそれぞれの
`init/handshake/read/write/close` root、Accepted R7 ESP provider factory、R7
SHA-256/HKDF-Extract/HKDF-Expand/AES-128-GCM-Seal/AES-128-GCM-Open raw callbackのexact 16
entryとする。各entryはsymbol、defining source relative path、source SHA-256を持つ。entry欠落、
重複、extra root、hash mismatchをrejectし、以下のsource/link/final-ELF gateはすべてこの同じ
root集合のclosureを対象にする。

pinned `components/mbedtls/CMakeLists.txt`はSOC capabilityだけでAES/SHA/DS/HMAC port sourceを
archiveへcompileし得るため、sdkconfigだけをevidenceにしない。final ELF link map、archive member、
relocation/call-graph closureで次をhard gateする。

- `port/aes/`、`port/bignum/`、`port/sha/`、`port/ecc/`、`port/ecdsa/`、
  `port/esp_ds/`、`port/esp_hmac_pbkdf2.c`、`port/mbedtls_rom/`、`port/esp_mem.c`由来objectの
  reachable symbol 0
- `--wrap=mbedtls_ecdsa_*`、ROM/DS/ATECC/TEE crypto symbolと`MBEDTLS_*_ALT`実装のfinal link 0
- allocator callback以外から`heap_caps_*`、`malloc`、`calloc`、`realloc`、`free`へのrelocation 0
- `port/esp_hardware.c`のallocation-free entropy pollとtime/timingだけを明示allowlistし、
  それ以外のESP crypto port objectを追加しない

source token scan、preprocessed macro inventory、link map、`nm`/relocation inventoryのいずれかが
不明、tool非対応、またはclosure外allocationを検出した場合はhard budgetを主張せずprofile不適合とする。

このgateは目視reviewではなく、次の2 ELFを作るrelease build stepとして自動実行する。

1. adapter、pinned mbedTLS archives、profile allocatorを
   `-ffunction-sections -fdata-sections -fno-lto`でcompileする。compile commandに`-flto`が
   1個でもあればfailする。`CLOSURE_ROOTS_V1`から到達する全translation unitのpreprocessor
   macro inventoryとGCC
   `-fdump-tree-original`を保存し、call/address-reference nodeを構文解析する。profile allocator
   objectの前記2 heap callとbootstrapのsetter 1 call以外に禁止identifierを参照するsource node、
   unknown node kind、dump欠落があればlink前にfailする。client/serverの
   `init/handshake/read/write/close`全rootはvolatileなfake BIO/socketで、R7 factoryと上記
   5 primitive callback rootは全boundary inputで実行する専用
   `wifi_tls_closure_probe.elf`を、productionと同じ
   sdkconfig、archives、link orderで
   `-Wl,--gc-sections,--emit-relocs,--cref,-Map=wifi_tls_closure_probe.map`によりlinkする。
   probeへWi-Fi、lwIP、application objectを入れない。
2. archive index/link mapで禁止port objectのpull-inとunexpected closure memberをrejectしたうえで、
   `xtensa-esp32s3-elf-nm -an`、`xtensa-esp32s3-elf-objdump -dr`、map cross-referenceから、
   GC後にretainedなsection、archive member、symbol、caller→callee relocationを抽出する。
   allocator objectから`heap_caps_calloc`と`heap_caps_free`への各許可relocation、およびprofile
   bootstrapから`mbedtls_platform_set_calloc_free`へのexact 1 relocation以外に、
   前記allocation/ALT/port/ROM/DS/ATECC/TEE禁止targetが1個でもあればfailする。
3. production ELFも同じlinker audit optionで作り、`CLOSURE_ROOTS_V1`から到達するretained
   section/member/symbol集合のcanonical sorted SHA-256をprobeとbit-exact一致させる。
   productionの全retained callerからclosure集合へのrelocation/address referenceも走査し、
   private adapter allowlist外の
   callerをrejectする。caller allowlistはWi-Fi adapterとreport固定済みR7 raw adapterだけである。
   したがってapplicationからのdirect mbedTLS callや、別componentが追加したcrypto pathを、
   既存memberが偶然probeにも含まれる場合でも許さない。
4. 入力commit/sdkconfig、compile/link argv、retained集合、relocation、各判定をUTF-8/LF、
   bytewise sortしたmachine-readable reportへ出し、そのSHA-256をrelease artifactへ固定する。
   parserがunknown section/relocationをskipした場合、probe rootが欠落した場合、production ELFを
   audit後に再linkした場合はfailする。

production image全体のWi-Fi/lwIP/application allocationは別accountingであり、このprobeをその
heap-free証拠には使わない。一方、production closure集合とそこへのcaller edgeは上記exact gateから
除外できない。

Host adapterは`TLS_client_method()`または`TLS_server_method()`からrole固有`SSL_CTX`を作り、
return valueを持つsetterはdocumented success値を確認し、void controlはgetterまたはnegative
acceptanceでexact stateを確認する。

```text
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256")
SSL_CTX_set1_groups_list(ctx, "P-256")
SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256")
server: SSL_CTX_set1_client_sigalgs_list(ctx, "ecdsa_secp256r1_sha256")
client: SSL_VERIFY_PEER
server: SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
SSL_CTX_set_verify_depth(ctx, 1)
SSL_CTX_set_post_handshake_auth(ctx, 0)
SSL_CTX_set_num_tickets(ctx, 0)
SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF)
SSL_CTX_set_max_early_data(ctx, 0)
SSL_CTX_set_recv_max_early_data(ctx, 0)
SSL_CTX_set_max_cert_list(ctx, 4110)
SSL_CTX_set_max_send_fragment(ctx, 4096)
SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
```

Host clientはSNI setterと`X509_VERIFY_PARAM_set1_host()`を呼ばず、§14.2のraw extension/
provisioning検査をserver identityの唯一のcheckにする。
成功後は
`SSL_version()==TLS1_3_VERSION`、current cipher protocol ID `0x1301`、
`SSL_get_negotiated_group()==NID_X9_62_prime256v1`、
`SSL_session_reused()==0`を必須postconditionとする。

#### 14.1.2 Host pinned OpenSSL build closure

本profileのHost TLS backendはannotated tag `openssl-3.5.7`（tag object
`6ca677c395a4ae4472a12c5857c122ec33b36f66`、peeled commit
`8cf17aaeb4599f8af87fefd810b5b5fee90fe69e`、source date epoch
`1781006065`）だけとする。許可target tupleは次の2個だけで、他OS/CPU/ABI、macOS x86_64、
Linux arm64は別profile revisionを要する。

| target_id | OS / machine / ABI | OpenSSL Configure target | toolchain root / sysroot | word/endian |
| ---: | --- | --- | --- | --- |
| `0x01` | Linux / `x86_64` / `x86_64-linux-gnu` | `linux-x86_64` | `/opt/ninlil/toolchains/01` / `/opt/ninlil/toolchains/01/sysroot` | 64-bit / little |
| `0x02` | macOS / `arm64` / `arm64-apple-darwin` | `darwin64-arm64-cc` | `/opt/ninlil/toolchains/02` / `/opt/ninlil/toolchains/02/sysroot` | 64-bit / little |

source/build rootは`/build/openssl-src`と`/build/openssl-out/<target_id>`へ固定し、clean tree、
§14.1.2後段で列挙するexact environment以外を空にする。`UMASK=022`をenvironment fingerprintへ
含め、各processの実効umaskも022とする。`LANG=C`、`LC_ALL=C`、`TZ=UTC`、
`SOURCE_DATE_EPOCH=1781006065`をexactとする。各toolchain rootはcompiler、linker、`llvm-ar`、
`llvm-ranlib -D`だけを
実行するpinned `ninlil-ranlib` wrapper、Perl、make、shell、全build utility、target sysrootを
copy-ownしたhermetic release bundleである。symlinkはbundle内だけを指せる。
`CC`/`AR`/`RANLIB`/`PERL`/`MAKE`/`SHELL`は同bundle内のabsolute executableだけを渡す。
`PATH`は当該`<toolchain-root>/bin` 1個だけとし、host `/usr/bin`、SDK、compilerへfallbackしない。

pinned `Configure`は末尾でstring-form `system($cmd)`を使い、Perlがabsolute `/bin/sh`を起動する。
これをhost shellへ逃がさないため、両target buildを同じsealed build namespaceで実行し、
namespaceの`/bin/sh`を
`/opt/ninlil/toolchains/<target_id>/bin/sh`へのexact symlink 1個として作る。host rootの
`/bin`をmountせず、makeにも後述のcommand-line `SHELL=`を渡す。namespaceからread/execute可能な
pathはread-only source、target toolchain bundle、当該empty out/tmp root、このpinned
`/bin/sh` alias、`/dev/null`だけとする。tool executableのinterpreter/shared dependencyも
toolchain bundle内に置き、host filesystem accessとnetworkをdenyし、clockは
`1781006065`へvirtualize/fixし、nondeterministic/random inputをdenyする。
launcherは全exec/read dependencyとresolved content digestをcanonical report化し、unknown access、
alias target/hash mismatch、denyを観測できないplatformをbuild failにする。

両targetのordered Configure argvは次をexactとする。
ここで全path/manifest中の`<target_id>`は`0x`なしのASCII `01`または`02`へ展開する。

```text
CPPFLAGS=-DOPENSSL_API_COMPAT=30500
ARFLAGS=qcD
ZERO_AR_DATE=1

target 0x01:
CFLAGS=-O2 -fPIC -fvisibility=hidden -fno-common -fno-ident --target=x86_64-linux-gnu --sysroot=/opt/ninlil/toolchains/01/sysroot
LDFLAGS=--target=x86_64-linux-gnu --sysroot=/opt/ninlil/toolchains/01/sysroot

target 0x02:
CFLAGS=-O2 -fPIC -fvisibility=hidden -fno-common -fno-ident --target=arm64-apple-darwin -isysroot /opt/ninlil/toolchains/02/sysroot -mmacosx-version-min=14.0
LDFLAGS=--target=arm64-apple-darwin -isysroot /opt/ninlil/toolchains/02/sysroot -mmacosx-version-min=14.0

$PERL /build/openssl-src/Configure <Configure-target>
  no-shared no-module no-dso no-engine no-dynamic-engine no-legacy no-fips
  no-autoload-config no-apps no-docs no-tests
  no-threads no-thread-pool no-default-thread-pool
  no-asm no-secure-memory no-async no-ktls
  no-dgram no-dtls no-quic no-sctp no-psk no-srp
  no-comp no-zlib no-zlib-dynamic no-zstd no-zstd-dynamic
  no-brotli no-brotli-dynamic
  no-ssl3 no-tls1 no-tls1_1 no-tls1_2
  no-weak-ssl-ciphers no-deprecated no-stdio no-pinshared
  --api=3.5
  --prefix=/opt/ninlil/openssl-3.5.7/<target_id>
  --openssldir=/opt/ninlil/openssl-3.5.7/<target_id>/disabled

$MAKE -j1 SHELL=/opt/ninlil/toolchains/<target_id>/bin/sh build_sw
```

改行は表示上だけで、argvは上記順の1 tokenずつとする。source既定もpeeled commitの一部であり、
optionの追加、省略、並べ替え、`config`によるtarget自動検出を許さない。生成物はstatic
`libcrypto.a`/`libssl.a`だけをprivate linkし、dynamic `libssl`/`libcrypto`、DSO、provider module、
engine、system OpenSSLとのsymbol混在をfinal link mapで0とする。buildは空の固定out rootから
上記2 commandだけで行う。両commandのcwdは
`/build/openssl-out/<target_id>` exactとし、`MAKEFLAGS`はempty、localeやparallelismによるarchive member順の変更を
許さない。`ARFLAGS=qcD`とpinned `ninlil-ranlib`の`llvm-ranlib -D`によりarchive metadataを
deterministicにする。

buildごとに次のUTF-8/LF、lowercase hex、固定field順のmanifestを生成する。各`*_sha256`は
raw対象のSHA-256、`configure_argv`はabsolute `Configure` path、target、上記optionを表示順に
NUL区切りしたbytes、`build_argv`はabsolute `MAKE` path、`-j1`、
`SHELL=/opt/ninlil/toolchains/<target_id>/bin/sh`、`build_sw`を同様に
NUL区切りしたbytes、`toolchain`はbundle inventoryと指定executable本体および各
`--version`出力、`generated_headers`はrelative path + u64 length + bytesで
`include/openssl/configuration.h`、`include/openssl/opensslconf.h`を順に連結する。
固定build pathのためpath置換や行sortを行わない。

```text
OWF1
source_tag=openssl-3.5.7
source_tag_object=6ca677c395a4ae4472a12c5857c122ec33b36f66
source_commit=8cf17aaeb4599f8af87fefd810b5b5fee90fe69e
source_date_epoch=1781006065
source_tree_sha256=<64 lowercase hex>
target_id=<2 lowercase hex>
target_triple=<exact table value>
configure_target=<exact table value>
configure_argv_sha256=<64 lowercase hex>
build_argv_sha256=<64 lowercase hex>
build_env_sha256=<64 lowercase hex>
build_sandbox_policy_sha256=<64 lowercase hex>
build_dependency_report_sha256=<64 lowercase hex>
toolchain_bundle_sha256=<64 lowercase hex>
toolchain_sha256=<64 lowercase hex>
configdata_dump_sha256=<64 lowercase hex>
generated_headers_sha256=<64 lowercase hex>
libcrypto_a_sha256=<64 lowercase hex>
libssl_a_sha256=<64 lowercase hex>
```

`openssl_build_fingerprint = SHA-256(manifest bytes including final LF)`とする。releaseは各targetの
manifest、fingerprint、archives、link mapを署名artifactへ入れ、許可fingerprintを
machine-readable profileへFULL固定する。許可値が未固定、複数候補、manifest再現不一致なら
profileをclaimできない。compiler patchやarchiveが変われば同じsource/optionsでも別fingerprintで、
silent許可しない。

`build_env` hash inputはConfigure、make、`configdata.pm --dump`の各起動時に共通する
`PATH,LANG,LC_ALL,TZ,SOURCE_DATE_EPOCH,UMASK,ZERO_AR_DATE,TMPDIR,MAKEFLAGS,SHELL,CC,AR,ARFLAGS,RANLIB,PERL,MAKE,CFLAGS,CPPFLAGS,LDFLAGS`
をこの順にUTF-8 `NAME=value`と1-byte NULで連結し、最後のvalue後にもNULを置く。上記以外の
environment keyがいずれかの起動にあればbuild failとする。3 invocationで同じexact environmentと
`umask 022`を使い、差分を許さない。`TMPDIR=/build/tmp/<target_id>`は開始時empty、
`SHELL=/opt/ninlil/toolchains/<target_id>/bin/sh` exactとする。`configdata.pm --dump`はbuild完了後、
同じsealed namespace、同じcwd `/build/openssl-out/<target_id>`で下記exact argvにより1回だけ
実行する。

`build_sandbox_policy`は署名artifactのUTF-8/LF `BSP1` policy raw bytesとする。policyは上記
mount/path、read/write/execute、network、fixed clock、random deny、`/bin/sh` symlink targetを
exact列挙し、launcher source/binaryはtoolchain bundleへ含める。
`build_dependency_report`はASCII `BDR1` + NULの後へ、観測したunique dependencyを
`operation_u8 || logical_path_len_u64 || logical_path || resolved_path_len_u64 || resolved_path ||
kind_u8 || content_sha256[32]`として連結する。operationはexec `0x45`、read `0x52`、
kindはregular `0x46`、symlink `0x4c`、directory listing `0x44`、`/dev/null` `0x4e`だけとする。
content digestはregular file bytes、symlink target bytesに対するSHA-256とする。
directory content digestはASCII `DIR1` + 1-byte NULの後へ、各direct childを
`kind_u8 || name_len_u64 || name`として連結したbytesに対するSHA-256とする。kindはregular
`0x46`、symlink `0x4c`、directory `0x44`だけ、nameはslashを含まないraw UTF-8 bytes、
lengthはbig-endian、normalizationなしとする。entry record全bytesのunsigned lexicographic順で
sortし、duplicate/unknown/special childをbuild failにする。
`/dev/null` digestはSHA-256(empty)とする。同じpathが異なるcontentで読まれた場合は別recordとし、
record全bytesのunsigned lexicographic順でsortする。整数はbig-endian、pathはUTF-8 `/`区切り、
normalizationなしとする。2回のclean buildでpolicy/dependency reportもbit-exact一致させる。

`source_tree`はpeeled commitのrecursive Git treeを対象に、ASCII `SBF1` + 1-byte NULの後へ
relative pathのunsigned-byte昇順でfile/symlink recordを連結する。fileは
`0x46 || git_mode_u32 || path_len_u64 || path || content_len_u64 || blob`、symlinkは
`0x4c || git_mode_u32 || path_len_u64 || path || target_len_u64 || target`とする。submodule、
non-UTF-8 path、worktree差分をrejectする。`git_mode_u32`はGit tree modeのoctal bit value
（例: regular `0100644`）をunsigned integerとしてencodeする。
`toolchain_bundle`はASCII `TBF1` + 1-byte NULの後へ同じpath順で全descendantを連結する。
directoryは`0x44 || posix_permission_u32 || path_len_u64 || path`、regular fileは
`0x46 || posix_permission_u32 || path_len_u64 || path || content_len_u64 || file bytes`、
symlinkは`0x4c || posix_permission_u32 || path_len_u64 || path || target_len_u64 || target`
とする。root自身は含めず、special file、non-UTF-8 path/target、bundle外へ解決するsymlinkを
rejectする。`posix_permission_u32 = st_mode & 07777`、整数はすべてbig-endian、pathは`/`区切りで、
text normalizationを行わない。

`toolchain` hash inputは32-byte raw `toolchain_bundle_sha256`の後へ、CC、AR、RANLIB、PERL、
MAKE、SHELLの順に
`path_len_u64 || canonical absolute path || executable_len_u64 || executable bytes ||
version_stdout_len_u64 || stdout || version_stderr_len_u64 || stderr`
を連結する。version argvは各executableのabsolute path + `--version` exact、exit status 0を
必須とする。lengthはu64 big-endianで、NUL/text normalizationを行わない。
`configure_argv`/`build_argv`は各token後（最終token後を含む）にNULを置く。
`generated_headers`は各fileについて
`relative_path_len_u64 || relative_path || file_len_u64 || file bytes`を表示順に連結する。
`configdata_dump`はbundleのabsolute Perlを使った
`$PERL /build/openssl-out/<target_id>/configdata.pm --dump`のstdout exact bytesであり、stderrは
empty、exit statusは0を必須とする。manifest generator自身の
sourceとdigestも署名release artifactへ含める。

target gateはbundle内`llvm-readobj`で全archive memberを検査し、target `0x01`はELF64
x86-64、target `0x02`はMach-O 64-bit arm64だけを許す。compile probeのpreprocessor architecture/
LP64/little-endian macroとtable tupleも一致させる。unknown/member混在、host SDK pathの
include/library、sysroot外dependencyをbuild failにする。

process bootstrapは`CRYPTO_set_mem_functions()`を最初のOpenSSL callとして成功させた後、
`OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)`を1回だけ呼ぶ。`OPENSSL_*`環境変数、
`SSLKEYLOGFILE`、`RANDFILE`の存在をstartup rejectし、config/APIによるloadを禁止する。
`OSSL_LIB_CTX_new()`で本profile専用contextを作り、`OSSL_PROVIDER_load(libctx, "default")`
だけを許可し、`EVP_set_default_properties(libctx, "provider=default")`を設定する。
全fetchと`SSL_CTX_new_ex(libctx, "provider=default", method)`はこのcontextを使い、
NULL/global contextを使わない。provider enumerationはexact `default` 1個、module path/load 0を
必須とする。

startup runtime gateはembedded `openssl_build_fingerprint`とtarget_idをrelease allowlistへ照合し、
`OPENSSL_version_major/minor/patch()==3/5/7`、pre-release/build metadata空、
compile/runtime header version一致、static-only link inventory、config/provider/environment条件を
全検査する。1条件でも不一致ならsocketを開く前にprofile unavailableとする。

既存Ninlil Host SDKの汎用`find_package(OpenSSL 3)` / R7 OpenSSL 3.x条件は本profile pinを
満たさない。Wi-Fi profile processでR7を併用する場合は同じpinned static buildを使い、R7は別
isolated `OSSL_LIB_CTX`へ置く。system/generic OpenSSLを同じprocessへ追加linkする構成は不適合で、
必要なら別process/profile境界に分離する。

### 14.2 Exact leaf identity binding

leafはX.509 v3でroleごとに別credentialとする。同じRuntimeがclient/server双方を行う場合もleafを共有しない。
SubjectPublicKeyInfoは`id-ecPublicKey` + namedCurve
`1.2.840.10045.3.1.7`、65-byte uncompressed P-256 pointだけを許可する。leaf、提示intermediate、
trust anchorのpublic keyはP-256、certificate signatureは`ecdsa-with-SHA256`だけとする。

leafの必須X.509 extensionは次とし、これ以外のcritical/non-critical extensionを拒否する。

| Extension | Exact rule |
| --- | --- |
| basicConstraints | critical、`CA=FALSE` |
| keyUsage | critical、`digitalSignature`だけ |
| extendedKeyUsage | critical、role `0x01`は`clientAuth`だけ、`0x02`は`serverAuth`だけ |
| subjectAltName | critical、以下のbinding `otherName` exact 1個だけ |
| subjectKeyIdentifier | non-critical、exact 1個 |
| authorityKeyIdentifier | non-critical、exact 1個 |

全certificateのSKI valueは
`first_20_bytes(SHA-256(SubjectPublicKeyInfo DER))`とし、AKIは`keyIdentifier` fieldだけを含み、
そのvalueをissuer SKIと同一にする。authorityCertIssuer、authorityCertSerialNumber、
別長SKI/AKIは拒否する。

binding OIDはUUID namespace URL
`6ba7b811-9dad-11d1-80b4-00c04fd430c8`とASCII name
`urn:ninlil:wifi-tls13-p256-v1:leaf-binding-v1`からUUIDv5で導出した
`c349d6e3-2623-59b6-96cb-faca1fa0cbaa`、OID
`2.25.259582855280982876264288537151153425322`とする。

SubjectAltNameの`extnValue`が包むGeneralNames DERは次のexact formとする。

```text
30 6e
  a0 6c
    06 14 69 83 86 c9 eb b8 e4 e2 9a e6 ed 96 e5 fe d9 a1 fd 83 97 2a
    a0 54
      04 52
        binding_value[82]
```

Extension全体のDER prefixは
`30 7a 06 03 55 1d 11 01 01 ff 04 70`で、直後に上記112-byte
GeneralNamesが続く。indefinite length、非最短length、別tag、別ordering、trailing byteを拒否する。
`binding_value[82]`は次を連結する。整数はunsigned big-endian。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 1 | binding version = `0x01` |
| 1 | 1 | credential role: TLS client=`0x01`、TLS server=`0x02` |
| 2 | 16 | non-zero `runtime_id` |
| 18 | 32 | non-zero allowed Attachment binding digest |
| 50 | 16 | non-zero `authority_id` |
| 66 | 8 | non-zero `authority_term` |
| 74 | 4 | non-zero `credential_generation` |
| 78 | 4 | non-zero `revocation_generation` |

SAN GeneralNameの追加、binding OID重複、別version/role、zero required field、unknown field、
DNS/IP/CNだけのidentityはrejectする。SNI、DNS、IP、subject CNはrouting hintにも使わず、
authenticated peer identityはこのbindingとFULL provisioning recordの一致だけから得る。
pinしたmbedTLSではcustom OIDの`otherName`を
`mbedtls_x509_parse_subject_alt_name()`へ渡すと
`MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE`になり得る一方、
`mbedtls_x509_get_subject_alt_name_ext()`はそのraw tag/valueを
`subject_alt_names.buf`へ保持する。このreturnをauthenticated扱いせず、profile-owned parserが
original leaf DERの`v3_ext`からcritical SAN Extension全体を再走査し、上記124-byte form
（12-byte prefix + 112-byte GeneralNames）、唯一性、critical bit、全length/tag/OIDと
`binding_value`を検証する。OpenSSLもdecoded `GENERAL_NAME`だけでなくraw
`X509_EXTENSION` DERへ同じparserを適用する。raw SAN/extensionをbyte-exact取得できない
backend/versionはprofile不適合とする。

提示chainはleafだけ、またはleaf + 1 intermediateとし、trust anchorはlocal storeだけとする。
intermediateを提示する場合はX.509 v3、`basicConstraints` critical `CA=TRUE,pathLenConstraint=0`、
`keyUsage` critical `keyCertSign,cRLSign`だけ、`subjectKeyIdentifier`と
`authorityKeyIdentifier`を各1個non-criticalとし、SAN/EKUおよび他extensionを拒否する。
production trust storeはprovisioning recordが指定するX.509 v3 self-signed root 1個だけを
そのauthority termに対して有効にする。rootは`basicConstraints` critical
`CA=TRUE,pathLenConstraint=1`、`keyUsage` critical `keyCertSign,cRLSign`だけ、
`subjectKeyIdentifier`と同値の`authorityKeyIdentifier`を各1個non-criticalとし、SAN/EKUおよび
他extensionを拒否する。leaf/intermediateのAKIとissuer SKI、issuer/subject name、rootの
self-signatureをbyte/cryptographic exactに照合する。rootを含む全certificateは各DER
2048 bytes以下、提示chain DER合計4096 bytes以下、verification depthは1以下とする。
上限、extension allowlist、basicConstraints/pathLen、KU/EKU/SKI/AKI、P-256、signature、
role/bindingのどれかが不一致ならhandshake/session不成立、NFL1 delivery 0とする。

initial TLS 1.3 `Certificate`は`certificate_request_context` length/valueを0、
各`CertificateEntry.extensions` length/valueを0とする。OpenSSL
`SSL_CTX_set_max_cert_list(ctx, 4110)`が数えるCertificate message bodyは
`4 + Σ(3 + cert_DER_length + 2)` bytesである。したがってleafだけのframing overheadは9 bytes、
leaf + intermediateは14 bytes、2 DER合計4096 bytes時のbody上限は4110 bytesとなる
（4-byte Handshake headerはこの値の外）。backend limitとは別にprofile parserがcount `<=2`、
各DER `<=2048`、DER合計`<=4096`を検査する。1枚4096 bytesのようにbackend limit内でも
per-certificate boundを超えるchainをrejectする。
pinしたmbedTLSのTLS 1.3 Certificate writerはchain全体をfragmentせず、
4-byte Handshake headerとbodyをout content bufferへ一括encodeするため、ESPの
`CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN`は`4110 + 4 = 4114` exactとする。4096-byte上限はadapterが
application-data writeをchunkする別上限であり、Certificate handshake bufferへ適用しない。

### 14.3 Authority clock、revocation、rotation fence

handshake admissionは次の2構造をFULL durable recordからcopy-ownする。
`security_identity_snapshot`は記載field順のpaddingなし226-byte caller-owned bufferでchannel
lifetime中immutable、48-byte
`revocation_freshness_view`は§14.3.1の同一set refreshだけでatomic replaceできる。

```text
security_identity_snapshot:
authority_id[16] | authority_term_u64 | clock_epoch_id[16] |
peer_runtime_id[16] | peer_role_u8 | attachment_binding_digest[32] |
peer_leaf_der_sha256[32] | peer_provisioning_record_digest[32] |
clock_now_ms_u64 | clock_trust_u8 | credential_generation_u32 |
revocation_generation_u32 | revoked_set_digest[32] |
credential_manifest_generation_u64 |
snapshot_created_ms_u64 | snapshot_valid_until_ms_u64

revocation_freshness_view:
revocation_record_digest[32] | revocation_generated_at_ms_u64 |
revocation_valid_until_ms_u64
```

#### 14.3.1 NRV1 canonical revocation record

`NINLIL-WIFI-TLS13-P256-V1`の唯一のrevocation formatは`NRV1`とする。全整数はunsigned
big-endian、全長は`144 + 32 * revoked_count`、最大2192 bytesである。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NRV1` |
| 4 | 2 | version = `0x0001` |
| 6 | 2 | header_length = `0x0070` (112) |
| 8 | 4 | total_length = `144 + 32 * revoked_count` |
| 12 | 4 | flags = 0 |
| 16 | 16 | not-all-zero `authority_id` |
| 32 | 8 | non-zero `authority_term` |
| 40 | 16 | not-all-zero `clock_epoch_id` |
| 56 | 8 | `generated_at_ms` |
| 64 | 8 | `valid_until_ms` |
| 72 | 4 | non-zero `revocation_generation` |
| 76 | 2 | `revoked_count` = 0..64 |
| 78 | 2 | fingerprint_length = 32 |
| 80 | 32 | `revoked_set_digest` |
| 112 | `32 * count` | revoked leaf certificate DER SHA-256 fingerprints |
| `112 + 32 * count` | 32 | `record_digest` |

fingerprint列は32-byte unsigned lexicographicでstrict ascending、unique、all-zero禁止とする。
`revoked_set_digest = SHA-256(revoked_count_u16_be || fingerprint[0] || ... )`、
`record_digest = SHA-256(record bytes offset 0 through the final fingerprint)`とする。digest fieldを
zeroにして再計算する方式ではない。`record_digest`自身の32 bytesはhash inputの直後に位置し、
inputへ含まれないため循環参照はない。count 0でもset digestは`SHA-256(00 00)`であり、省略しない。
unknown magic/version/flag、非最短/不一致length、count 65以上、duplicate/out-of-order/zero entry、
digest mismatch、trailing byteをcorruptとしてrejectする。CRCやbackend-native serializationを
追加しない。

canonical KAT familyはauthority_id bytes `00..0f`、authority_term `1`、clock_epoch_id bytes
`10..1f`、generated_at `1000000`、valid_until `1300000`、generation `1`とする。count `N`の
fingerprint index `i = 0..N-1`は`31 * 00 || u8(i + 1)`である。headerのlength/count/set digestを
各Nに合わせ、末尾へrecord digestをappendした結果は次とbit-exact一致しなければならない。
`record_sha256`はfieldではなく、末尾digestを含むrecord全体に対するKAT確認値である。

| N | total | revoked_set_digest | record_digest | record_sha256 |
| ---: | ---: | --- | --- | --- |
| 0 | 144 | `96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7` | `6de701c0a46a2ee260ca31dee2fef87e33df36cdc4cf4db01b8d4444f32d773d` | `d7c93c38d33d4e30a7c6a76f523c9f8a58fee604ba95836e342b454b83f68586` |
| 1 | 176 | `2b5a7497e0f7519ce102d1e2e84c40e613873c200b78ecbdd5590155b732815e` | `78203272473f5f025b26a9c552ab8e2e7d94205adfd28ee54741c62d2941dcd6` | `f0a71e4af7ba39b19d34629518d3e895c2c7fef0d06e76c342f41bb295a67a01` |
| 64 | 2192 | `4df3cd7f3dbf911e5de1924ae9932201f0bec21e9782a95a9a40ea7333b046d9` | `78440d16794750a1ddc1a4f0af82a13f3ad40650e6103e7a7edeb8b43c0f1ef4` | `7586744b2698f6fc46d15a222e77d0e82384f3242e69c7da2df158c3a37a30a1` |

各authority termの初回generationは1とし、そのterm中は`clock_epoch_id`を固定する。
同じterm/clock epochの以後のdistinct recordは
`generated_at_ms > previous.generated_at_ms`かつ
`valid_until_ms >= previous.valid_until_ms`を必須とし、次のどちらかだけを許す。

- revoked setがprevious setのstrict supersetで、
  `generation = previous.generation + 1` exact
- fingerprint列、`revoked_set_digest`、generationがpreviousとbit-exact同じfreshness refresh

fingerprintの削除・置換は同じtermで行わず、strictly greater authority termへのrotationを要する。
set変更なしのgeneration変更、set変更ありのgeneration据置、generation wrap、generated clock
regression、valid-until regressionをrejectする。同一record bytesの再読は更新ではない。
`clock_epoch_id`だけの変更、authority termのrollback/wrapをrejectする。generationが
`UINT32_MAX`へ達した後の次更新はstrictly greater authority term、新しいnon-zero clock epoch、
credential/trust/NRVのController-authenticated FULL rotationを行い、generation 1から始める。

Accepted authority clock `now_ms`に対し、overflow/underflowを先に拒否して次をすべて満たす。

```text
generated_at_ms <= now_ms < valid_until_ms
age_ms = now_ms - generated_at_ms
age_ms <= 300000
0 < valid_until_ms - generated_at_ms <= 86400000
```

同じclock epochでauthority clockまたはinstalled `generated_at_ms`が前回accepted値より戻った場合は
corrupt/staleとする。future record、age 300001、`now == valid_until`、validity window超過を
許可しない。

set変更に伴うcredential activationは、可変個数のcredential blobをatomic transactionへ直接
入れず、bounded `NCM1` manifestで行う。全整数はunsigned big-endianで、headerは96 bytes、
active entryは56 bytes、retired tombstoneは96 bytes、末尾digestは32 bytes、全長は
`128 + 56 * credential_count + 96 * retired_count`である。
`credential_count + retired_count <= 64`のため最大6272 bytesである。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NCM1` |
| 4 | 2 | version = `0x0001` |
| 6 | 2 | header_length = `0x0060` (96) |
| 8 | 4 | total_length = `128 + 56 * credential_count + 96 * retired_count` |
| 12 | 4 | flags = 0 |
| 16 | 16 | `authority_id`、NRV1とbit-exact同じ |
| 32 | 8 | `authority_term`、NRV1とbit-exact同じ |
| 40 | 4 | `revocation_generation`、NRV1とbit-exact同じ |
| 44 | 2 | `credential_count` = 0..64 |
| 46 | 2 | entry_length = 56 |
| 48 | 8 | non-zero `credential_manifest_generation` |
| 56 | 2 | `retired_count` = 0..64 |
| 58 | 2 | retired_entry_length = 96 |
| 60 | 1 | `local_role_mask`: bit 0=`client`、bit 1=`server`。activatable bankは `1..3`、codec-only bankは0 |
| 61 | 3 | reserved = all zero |
| 64 | 32 | `revoked_set_digest`、NRV1とbit-exact同じ |
| 96 | `56 * count` | credential entries |
| `96 + 56 * count` | `96 * retired_count` | retired credential tombstones |
| `96 + 56 * count + 96 * retired_count` | 32 | `credential_manifest_digest` |

各entryは1個のactive credential subject + TLS roleを表す。選択credential-store profileでは
`runtime_id == local_runtime_id`のlocal signing identityも同じinventoryへ入り、それ以外が
authenticated peer identityである。
`runtime_id[16] || role_u8 || flags_u8 || reserved_u16 || credential_generation_u32 ||
provisioning_record_digest[32]` exactとする。roleは`0x01`/`0x02`だけ、flags/reservedは0、
runtime ID、generation、digestはnon-zeroとする。entryは
`runtime_id || role`のunsigned lexicographic順でstrict ascending、uniqueとする。
同じRuntimeのclient/serverは2 entryを消費する。上限は64 peerではなく
**local + peer合計64 active subject-role credentials**であり、dual-role 64 peersを保証しない。
65件目はcandidate全体を
`RESOURCE` rejectし、既存active setを変更しない。

`local_role_mask`はこのbankでRuntimeが公開するlocal TLS role setの唯一のdurable正本である。
Controller-authenticated management envelopeが要求するrole setはcandidate NCM1のmaskと
bit-exact一致しなければならないが、restart後の有効性をvolatile endpoint configuration、
process argument、Wi-Fi association stateから再導出しない。maskの各set bitについて
`runtime_id == NWS1.local_runtime_id`かつ対応roleのactive NCM1 entryとNWC1をexact 1個要求し、
maskにないlocal role entry、missing、duplicate、remote entry、retired tombstoneによる代用を
rejectする。mask 0、unknown bit、またはactive 0はbyte codecでは表現できるがpublishできない。
`credential_manifest_generation`をrole-set revisionとしても用い、同じauthority termでmaskを
変更するcandidateは他のNCM1 semantic updateと同様にprevious + 1 exactとする。別の独立role
revisionや外部設定revisionを設けない。trailing `credential_manifest_digest`と148-byte selectorが
maskを含むNCM1全bytesを拘束するため、role変更、credential activation、restart判定は同じ
selector FULL publishへlinearizeする。

retired tombstoneは
`runtime_id[16] || role_u8 || flags_u8 || reserved_u16 ||
last_credential_generation_u32 || removal_manifest_generation_u64 ||
leaf_der_sha256[32] || provisioning_record_digest[32]` exactとする。roleは`0x01`/`0x02`だけ、
flags/reservedは0、他fieldはnon-zeroである。active entryとtombstoneはそれぞれ
`runtime_id || role`でstrict ascending/uniqueとし、両sectionに同じkeyを置かない。
active + retiredの合計が64を超えるcandidateは`RESOURCE` rejectする。
`credential_manifest_digest = SHA-256(record bytes offset 0 through the byte immediately before
the trailing digest)`で、末尾digest自身をinputへ含めない。
unknown/mismatch/trailingをrejectする。

authority termごとの最初のNCM1は`credential_manifest_generation=1`とする。同じtermでentryの
追加、削除、`local_role_mask`変更、順序以外の1-byte変更を行うsemantic updateは
`credential_manifest_generation = previous + 1` exact、同じrecord bytesの再読は更新ではない。
同一revoked setのNRV1 freshness refreshではNCM1全bytes、generation、manifest digestを
bit-exact維持する。generation gap、rollback、同generation別bytes、old manifest replay、
`UINT64_MAX`からのwrapをrejectし、wrap後の変更はstrictly greater authority termへのFULL rotationと
generation 1を要する。ownerはselector内のhighest accepted manifest generationとNCM1 tombstoneを
authority term中のbounded high-watermarkとしてFULL保持する。
同じauthority termで初登場する`runtime_id || role`のcredential generationは1、既存entryの
credential/provisioning変更はprevious + 1 exact、未変更entryはbit-exact据置とする。entry削除は
同じsemantic updateでそのexact key/generation/leaf/digestとnew manifest generationをtombstoneへ
移す。tombstone keyの同term再追加は無条件rejectし、GCはstrictly greater authority termのFULL
rotation後だけ許す。65個目のdistinct active/retired keyはauthority term rotationを要する。
active entryのgeneration gap/rollback/wrap、tombstone削除/変更、削除前manifest replayをrejectする。

NCM1 canonical KAT familyはauthority/term/revocation generationを上記NRV1 KATと同じ、
`revoked_set_digest`をNRV1 count 0の
`96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7`
とする。active-only KATは`credential_manifest_generation=1`で、entry index `i=0..N-1`は
`runtime_id = 15 * 00 || u8(i+1)`、role `0x01`、flags/reserved 0、
credential generation 1、`provisioning_record_digest = 31 * 00 || u8(i+1)`、
`local_role_mask=1`である。
retired-only KATはactive count 0、retired count 64、manifest generation 2とし、
tombstone index `i=0..63`を同じruntime/role、flags/reserved 0、last credential generation 1、
removal manifest generation 2、
`leaf_der_sha256 = 30 * 00 || 01 || u8(i+1)`、
`provisioning_record_digest = 31 * 00 || u8(i+1)`、`local_role_mask=0`とする。
mixed 1/1 KATは上記active index 0と、runtime末尾/provisioning digest末尾を`02`、
leaf末尾2 bytesを`01 02`としたretired tombstone 1個をこの順に置き、manifest/removal
generationを2、`local_role_mask=1`とする。0/0 KATは`local_role_mask=0`である。
これらはNCM1 byte-codec KATであり、NWS1/NWC1とのlocal-role activation semantic positiveを
単独では主張しない。
`record_sha256`はfieldではなく末尾manifest digestを含むNCM1全bytesの確認値である。

| active / retired | total | credential_manifest_digest | record_sha256 |
| ---: | ---: | --- | --- |
| 0 / 0 | 128 | `876ad2c5c0af8f78e1b8ad94ff78faee25612cd1d7c2e5b527092f1af69cbabb` | `5a211f3150216e65d0dcc8a6a69282db8f2411542e8f07a699736d8ffbf2ed69` |
| 1 / 0 | 184 | `9f5826074fb3ab217fd5df84f9628bb500cc24e248297cae4159cc8e6ac68382` | `56d5aaec32c7bb0be4a3e9521f77503606134f13a01ccb2955854ad90cacbc7b` |
| 1 / 1 | 280 | `5cb500100f1579a4f370dc4d5248d455a2ac08d313b419dd30598e2b4f4fec98` | `aae2cfcf2ba3b03cfb744e8c62eaa6997154dbdd452c921b25f856f40111a1fc` |
| 64 / 0 | 3712 | `b7fe4fc3f924e3aff1dc2ffc37f925ce28a9bf8dbc7de4627bc6a9b9922c7dd3` | `e2a7184830e888addb5e3c4da52f7ec3e6c958bcddcf0c1d13c3d3bd8805880a` |
| 0 / 64 | 6272 | `6e686fa61f91b50798ded3f9e567f8e56e858ad9c96f416d83120db004213267` | `644568e94b4702902f32f9f20b7d7ef0fa6984bf939b332e603f5da1b9bc3304` |

各`provisioning_record_digest`が指すcredential recordは、NCM1 publish前に個別FULL stageされ、
record ownerがcanonical bytes、digest、entry identity/role/generation、authority/term、
revocation generation/set digest、§14.2 binding/certificateを全検証する。candidate setは最大64 record、
current + candidateの2 setだけとし、orphan stagingはactiveにならない。credential record自体の
canonical schema、private-key reference、per-record/aggregate durable byte boundは次の
`NINLIL-WIFI-CREDENTIAL-STORE-V1`だけを候補とする。

#### 14.3.2 NINLIL-WIFI-CREDENTIAL-STORE-V1 exact profile

本節も**Proposed normative candidate / docs-only**である。既存Foundation Storage ABI、
`NINLIL_STORAGE_SCHEMA_M1A=1`、key 1..255 bytes、single value 65536 bytes、FULL、
COMMIT_UNKNOWN、begin/final union staging規則を変更しない。profileは既存Runtime、control、
route、parent namespaceと共有せず、専用Storage provider instance/partitionへexact namespace
ASCII `ninlil.wifi.security.v1`（23 bytes、
hex `6e696e6c696c2e776966692e73656375726974792e7631`）を
`expected_schema=1`でopenする。port固有partition名、file path、NVS key、pointerはdurable identity
ではない。

profile内の全整数はunsigned big-endian、全reserved byteは0、全SHA-256は32 raw bytesである。
trailing digestは「そのdigest直前までのrecord bytes」へSHA-256を適用する。digestは
Controller-authenticated management envelopeの代替ではなく、stage ownerはsignature/authority
検証後だけFULL writeする。keyは次のbinary値だけを許し、unknown/duplicate keyはcorruptとする。

| Key bytes | Value |
| --- | --- |
| `01` | exact 1個の`NWS1` store header |
| `02` | current 148-byte selector。§14.3.1 layoutを変更しない |
| `03` | optional exact 1個の`NWM1` migration fence |
| `(0x10 + bank_id) 00` | `NWA1` authority/root record。`bank_id=0..1` |
| `(0x10 + bank_id) 01` | exact `NRV1` |
| `(0x10 + bank_id) 02` | exact `NCM1` |
| `(0x10 + bank_id) (0x10 + page_index)` | `NWP1` credential page。`page_index=0..7` |

##### NWS1 store header

`NWS1`は160 bytes fixedで、offset 0..127のSHA-256をoffset 128へ置く。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NWS1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 128 |
| 8 | 4 | total_length = 160 |
| 12 | 4 | flags = 0 |
| 16 | 16 | non-zero `local_runtime_id` |
| 32 | 16 | non-zero random `store_epoch_id` |
| 48 | 8 | profile_generation = 1 |
| 56 | 2 | bank_count = 2 |
| 58 | 2 | pages_per_bank = 8 |
| 60 | 2 | records_per_page = 8 |
| 62 | 2 | records_per_bank = 64 |
| 64 | 4 | max_credential_record_length = 4544 |
| 68 | 4 | max_page_length = 36480 |
| 72 | 4 | expected_storage_schema = 1 |
| 76 | 2 | profile key ceiling = 25 |
| 78 | 2 | reserved = 0 |
| 80 | 8 | profile logical-byte ceiling = 606003 |
| 88 | 8 | minimum provider staging entries = 50 |
| 96 | 8 | minimum provider staging logical bytes = 1212006 |
| 104 | 24 | reserved = 0 |
| 128 | 32 | `store_header_digest` |

fresh namespaceは全row absenceだけを許す。ownerはNWS1を1回FULL commitし、その結果を
authoritativeに解決してからcandidateをstageする。NWS1が存在するnamespaceのheader absence、
digest/profile/local Runtime/store epoch mismatchはfreshへ戻さずcorruptである。NWS1を別Runtimeへ
copyしてopenしてはならない。

##### NWA1 authority/root record

各bankは§14.2のroot 1個を次の`NWA1`でcopy-ownする。全長は`160 + root_der_length`、
最大2208 bytesである。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NWA1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 128 |
| 8 | 4 | total_length |
| 12 | 4 | flags = 0 |
| 16 | 16 | non-zero `authority_id` |
| 32 | 8 | non-zero `authority_term` |
| 40 | 16 | non-zero `clock_epoch_id` |
| 56 | 32 | SHA-256(root certificate DER) |
| 88 | 32 | SHA-256(root SubjectPublicKeyInfo DER) |
| 120 | 2 | `root_der_length` = 1..2048 |
| 122 | 2 | root SPKI DER length = 91 |
| 124 | 4 | reserved = 0 |
| 128 | `root_der_length` | root certificate DER |
| `128 + root_der_length` | 32 | `authority_record_digest` |

rootは§14.2のP-256 self-signed root、extension allowlist、signature、validityを満たし、parsed SPKIは
exact 91-byte canonical DER
`30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 04 || X[32] || Y[32]`
でなければならない。authority/termはselector、NRV1、NCM1と、clock epochはselector、NRV1と
bit-exact一致する
（NCM1にclock epoch fieldはない）。

##### NWC1 canonical credential record

1 active credential subject + TLS roleは次の`NWC1` 1個で表す。byte-codec全長は
`448 + leaf_der_length + intermediate_der_length`、449..4544 bytesである。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NWC1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 416 |
| 8 | 4 | total_length |
| 12 | 4 | flags = 0 |
| 16 | 16 | non-zero `authority_id` |
| 32 | 8 | non-zero `authority_term` |
| 40 | 16 | non-zero credential `runtime_id` |
| 56 | 1 | TLS role `0x01` client / `0x02` server |
| 57 | 1 | private-key ref kind `0x00` NONE / `0x01` OPAQUE_SIGNING_KEY |
| 58 | 1 | certificate_count = 1 or 2 |
| 59 | 1 | reserved = 0 |
| 60 | 4 | non-zero `credential_generation` |
| 64 | 4 | non-zero `revocation_generation` |
| 68 | 8 | non-zero `credential_manifest_generation` |
| 76 | 32 | non-zero Attachment binding digest |
| 108 | 32 | `revoked_set_digest` |
| 140 | 32 | SHA-256(leaf DER) |
| 172 | 32 | SHA-256(exact 91-byte leaf SPKI DER) |
| 204 | 32 | `chain_der_digest` |
| 236 | 32 | SHA-256(NWA1 root DER) |
| 268 | 16 | private-key provider ID |
| 284 | 32 | opaque private-key handle |
| 316 | 2 | `leaf_der_length` = 1..2048 |
| 318 | 2 | `intermediate_der_length` = 0..2048 |
| 320 | 2 | SPKI DER length = 91 |
| 322 | 2 | reserved = 0 |
| 324 | 91 | exact canonical leaf SPKI DER |
| 415 | 1 | reserved = 0 |
| 416 | `leaf_der_length` | leaf certificate DER |
| `416 + leaf_der_length` | `intermediate_der_length` | optional intermediate DER |
| `416 + leaf + intermediate` | 32 | `provisioning_record_digest` |

`certificate_count=1`ではintermediate length 0、count 2ではintermediate length 1..2048とし、
DER合計を4096以下にする。leaf/intermediate、SPKI、chain、role、critical binding、
authority/term/runtime/Attachment/credential/revocation generationは§14.2とbit-exact一致させる。

```text
chain_der_digest =
  SHA-256(certificate_count_u8 ||
          leaf_der_length_u16_be || leaf_der ||
          intermediate_der_length_u16_be || intermediate_der)
provisioning_record_digest =
  SHA-256(NWC1 bytes before the trailing digest)
```

NCM1 entryの`provisioning_record_digest`はこのtrailing digestそのものである。record内の
authority/term/revocation generation/set digest/manifest generation/runtime/role/credential
generationは参照NWA1/NRV1/NCM1と一致しなければならない。

handshakeはlocal側を
`{NWS1.local_runtime_id, handshakeでのlocal TLS role}`、peer側を
`{authenticated peer runtime_id, peer TLS role}`でlookupし、両方exact 1 entryを要求する。
同一entryをlocal/peer両方へ使わず、missing/duplicate/role inversionはhandshake 0である。
local entryも64上限とNCM1 generation/tombstone規則を消費するため、capacity表示でpeerだけ64件を
広告してはならない。

`runtime_id != NWS1.local_runtime_id`ではkey-ref kind 0かつprovider ID/handle all-zeroだけを許す。
local Runtimeのclient/server credentialではkind 1かつprovider IDとhandleをそれぞれnon-zeroとし、
raw private-key byte、PEM、filesystem path、pointerを本storeへ保存しない。provider ID/handleは
opaque fixed bytesで、ownerはactivation前にproviderから91-byte public SPKIを取得してrecordと照合し、
次の32-byte digestへP-256 ECDSAを**prehashed input（再SHA-256なし）**として署名させる。

```text
key_proof_digest =
  SHA-256(ASCII "Ninlil-WiFi-key-proof-v1" without NUL ||
          provisioning_record_digest)
```

private provider adapterの唯一のproof outputは64 bytes `r[32] || s[32]` unsigned big-endianで、
DER signatureをprofile ownerへ返さない。`1 <= r,s < n`かつlow-S
`s <= n/2`を必須とし、`n =
ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`、
`floor(n/2) =
7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8`
である。provider backendがDER/high-Sを返す場合はprivate adapter内でstrict DERをdecodeし、
high-Sを`n-s`へcanonicalizeしてfixed raw64を返す。zero/overflow/non-minimal DER、trailing、
wrong curve/hash、raw length 63/65をrejectする。ownerはrecord SPKIでraw64をverifyし、proof
signatureをdurable化せず直後にzeroizeする。private keyをexportできることを要件にせず、
resolve/sign/verify/zeroize failureはcandidate rejectとする。

`provider_id || handle`はprivate provider自身のFULL metadataで
`{NWS1.store_epoch_id, local_runtime_id, role, P-256 SPKI}`へimmutableにbindし、resolverは
この4 fieldをproofごとにcopy-ownして返す。ownerはNWS1/NWC1と全fieldを比較し、providerがhandleを
別store epoch/identity/role/keyへ再割当してはならない。このprovider bindingはcredential pageの
GC後もstore epoch破棄まで残るため、NCM1 tombstoneからhandle fieldが省略されてもalias historyを
失わない。同じcurrent/candidate inventory内で同一referenceを共有できるのは、
同じ`local_runtime_id || role`かつ同じSPKIのcredential rotationだけである。
別runtime、client/server別role、別SPKIの2 recordが同じreferenceを共有するcandidateはrejectする。
currentとcandidateのcross-bank照合にも同じ規則を適用し、removed/tombstoned recordのreferenceを
同じstore epoch中に別identityへaliasしない。strictly greater authority termでも同じidentity/role/
SPKIへの継続利用だけを許す。別identityへ同じreferenceを再利用してはならない。
同じRuntimeが両TLS roleを持つ場合も2 NWC1、2 NCM1 entryを消費し、leaf/key referenceを共有しない。

providerがreferenceごとに返しFULL保持する`key_binding_v1`はexact 128 bytes
`store_epoch_id[16] || runtime_id[16] || role_u8 || reserved_zero[4] || spki_der[91]`である。
同じstore epochで過去に使用したhandleを含め最大64 binding、8192 canonical metadata bytesを
別key-provider resource domainへreserveする。このhistory ceilingはNCM1のcurrent
active/retired countとは別である。V1内で65個目のdistinct handleが必要なcandidateは
terminal `RESOURCE`としてrejectし、current selector、bank、binding historyを変更しない。
authority termを上げる、同じnamespaceをerase/recreateする、NWS1だけを差し替える、
または新しい`store_epoch_id`を同じprofileへ書くことで回復してはならない。回復経路は、
将来`SPEC_ACCEPTED`になった別profile・別namespaceへのNWM1 migrationだけである。
そのmigrationはtarget側new handle/bindingのauthoritative FULL install、target selector publish、
source rollback fence、旧session drain、provider key cleanupとsecure eraseを順序付きで定義しなければ
ならず、単独のstore-epoch rolloverをV1から推測しない。private key materialとproviderの
physical journal/error-correction overheadはこの8192にもStorage ABIの606003にも含めず、C7の
provider profileでslot数、physical bytes、FULL/power-cut、zeroizeを固定する。new handle/keyは
binding+keyのauthoritative FULL install後にだけNWC1へstageし、install result unknownではresolve後
までcandidate publish 0とする。retired key materialは旧session終了後に破棄できるが128-byte binding
tombstoneはstore epoch終了まで保持する。

##### NWP1 pages and NCM1 relation

各bankは8個の`NWP1` pageを必ずFULL stageする。header 64 bytes、末尾digest 32 bytesで、
record_count 0..8、最大36480 bytesである。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NWP1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 64 |
| 8 | 4 | total_length |
| 12 | 4 | flags = 0 |
| 16 | 1 | bank_id = 0 or 1 |
| 17 | 1 | page_index = 0..7 |
| 18 | 2 | record_count = 0..8 |
| 20 | 16 | `authority_id` |
| 36 | 8 | `authority_term` |
| 44 | 8 | `credential_manifest_generation` |
| 52 | 2 | first_slot = `8 * page_index` |
| 54 | 10 | reserved = 0 |
| 64 | variable | rows |
| end - 32 | 32 | `page_digest` |

各rowは
`slot_index_u16_be || credential_record_length_u16_be || complete NWC1 bytes`である。
slotは`first_slot..first_slot+7`をgapなしstrict ascendingで使用する。全pageを連結したslot
0..`credential_count-1`はNCM1 active entryの`runtime_id || role`順とexact同じで、
各NWC1 digest/generation/identityを対応entryへ照合する。残りslotは存在せず、残りpageは
record_count 0の96-byte canonical empty pageである。NCM1 retired tombstoneにはNWC1を置かない。
removed recordがinactive bankに残ってもcurrent selectorから到達不能であり、same-term再追加禁止の
正本はcurrent NCM1 tombstoneである。active + retired 64上限、96-byte tombstone、6272-byte
NCM1最大を重複store schemaで変更しない。

##### Current/candidate bank、容量、FULL ordering

fresh installはbank 0を使う。以後、identity-changing update
（revoked set、credential set、manifest、authority term、root/Attachment/keyの変更）はcurrentと
反対bankへstageする。同一set NRV1 freshness refreshだけはcurrent bankのNRV1/NCM1/selectorを
atomic replaceし、NCM1 bytesを維持する。bank IDをselectorへ追加せず、restart時は2 bankをscanし、
selectorのauthority/term/revocation generation/set+record digest/manifest generation+digestへ
NRV1とNCM1が一致するbankを**exact 1個**要求する。0個または2個はcorrupt、old bankへfallbackしない。
selectorでpublishするbankは`credential_count >= 1`とNCM1 `local_role_mask in 1..3`を必須とする。
Controller-authenticated endpoint configurationはcandidateへ要求するmaskを運ぶ入力であり、
publish後とrestart時の正本はselected NCM1内のmaskである。そのmaskのclosed non-empty set
（client、server、または両方）ごとに、`runtime_id == NWS1.local_runtime_id`かつ同じrole、
`key_ref_kind=OPAQUE_SIGNING_KEY`のNWC1をexact 1個要求する。別role、remote NWC1、
retired tombstoneはこの要件を満たさない。configured roleのmissing/duplicate、
maskにない余分なlocal role、mask 0、unknown bit、またはactive count 0のbankはcandidate
stage/publishをrejectし、
restart時にselectorが指していればCORRUPT/profile unavailableとする。各required local NWC1の
offset 236 root DER SHA-256がselected NWA1と一致するため、NWA1は
selector→NCM1→NWC1から拘束される。active 0のNCM1、retired-only NCM1、
それらを組み合わせたselectorはbyte-codec/mutation KAT専用で、activatable setではない。
fresh headerでselectorがabsentの場合、両bankのNRV1/NCM1もabsentならUNPROVISIONEDであり、
どちらか1 valueでも存在すればcorruptである。candidate stageはfinal publishまでNRV1/NCM1を
書かない。

providerが常に予約する保守上限は次である。全valueはFoundationの65536-byte
single-value上限内である。この表は各valueの独立最大を同時に足したreservation ceilingであり、
semanticに同時到達可能なaggregate maximumではない。

| Item | Conservative provider reservation ceiling |
| --- | ---: |
| NWC1 | `416 + 4096 + 32 = 4544` |
| NWP1 | `64 + 8 * (4 + 4544) + 32 = 36480` |
| 1 bank values | `2208 + 2192 + 6272 + 8 * 36480 = 302512` |
| 2 bank + NWS1 + selector + optional NWM1 values | `2 * 302512 + 160 + 148 + 224 = 605556` |
| key/logical overhead | `3 * (16 + 1) + 22 * (16 + 2) = 447` |
| profile committed logical bytes | `605556 + 447 = 606003` |
| committed key count | 25 |
| provider begin/final union staging | 50 entries / 1212006 logical bytes |
| external private-key binding metadata | 64 × 128 = 8192 canonical bytes（private key material別domain） |

active countを`A`、retired countを`R`とすると`A + R <= 64`であり、1 bankの
constraint-aware bytesは`5296 + 4604*A + 96*R`、到達可能最大は
`A=64, R=0`の299952 bytesである。したがって2 bank、global values、key overheadを含む
semantic reachable maximumは600883 logical bytes、begin/final unionは1201766 bytesである。
実装はこの小さい値をprovider reservationへ使わず、上表の606003 / 1212006を固定reserveする。
oracleは保守予約境界とconstraint-aware境界を別々に検証する。

ownerは`capacity()`で少なくとも25 entries / 606003 logical bytesをreserveし、providerはAccepted
begin+final union規則により50 / 1212006をstageできなければならない。profile ownerはproviderの
余剰容量を利用して26件目や606004 byte目をadmitしない。現行M3 ESP storage production default
（32 entries / 69632 bytes、staging 64 / 139264）はこのprofileを満たさず、黙って上限を変えたり
同じpartitionへ押し込んではならない。ESP C7/C8では専用credential-store provider profile、
partition/workspace、PSRAM、FULL power-cut evidenceを別に実装・検証する。これは本docs-only
候補からtarget成立を導出するものではない。

Foundation private Runtime namespace scannerの4096-byte value workspaceは本専用namespaceへ
適用・再利用しない。Storage ABIのsingle value上限65536に従い、credential-store ownerは
storeごとにexact 1個のcaller-owned 36480-byte scratchをreserveし、NWA1/NRV1/NCM1/NWP1を
exclusive gate下で1 valueずつcopy-own、validate、encodeする。Storage `put: OK`後はproviderが
deep-copy済みなので同scratchを次valueへ再利用できる。sessionへpage pointerを渡さず274-byte
security snapshotだけを渡す。scratchのheap/stack/PSRAM配置、alignment、ESP peak/watermarkは
C7で固定・測定し、Foundation 4096-byte scanner成功やHost heapをtarget成立の証拠にしない。
namespace completeness scanはzero-prefix iterator、2-byte caller-owned key buffer、同scratchを使い、
unsigned-byte lexicographic順を検査する。`iter_next: BUFFER_TOO_SMALL`でrequired keyが3以上または
required valueが36481以上、unknown key、duplicate/out-of-order keyを検出した場合は、bytesを
推測せず再読・追加allocation 0でCORRUPTとする。

stage/publish orderは次のexact sequenceだけを許す。

1. Controller-authenticated candidateをcopy-ownし、management envelopeが要求するlocal role
   setとNCM1 `local_role_mask`をbit-exact照合したうえで、NWA1、8 NWP1、全NWC1と
   NCM1/NRV1参照をmemory上で完全検証する。current bank reader/sessionが残るbankを上書きしない。
2. inactive bankのNWA1と8 NWP1を、各keyのcomplete valueごとにFULL commitする。
   COMMIT_UNKNOWNではhandleを閉じてreopenし、intended bytes exactならそのkeyだけstage済み、
   old/absentなら未stageと解決する。別bytes、partial、digest mismatchはcorruptである。
3. 全9 staged valueを再読・再検証し、exclusive security gateを取得する。gate取得後にcurrent
   selectorがpreflight値から変わればcandidateをpublishしない。
4. inactive bankのNRV1、NCM1、global selectorだけを同じStorage transactionへputし、
   `commit(FULL)`する。owned value payload最大は既存どおり
   `2192 + 6272 + 148 = 8612` bytesで、NWA1/NWP1/NWC1やStorage key/16-byte accounting overheadを
   再包含しない。
5. OKならnew selectorをlinearization pointとし、role mask変更を含む旧identity sessionを
   gate解放前にfenceする。
   COMMIT_UNKNOWNならreopenしてselectorを唯一のauthorityとしてold全部またはnew全部へ解決する。
   oldならcandidateはinert、newならfenceを完了する。missing/mixed/unknownへfallbackしない。
6. old bankはgate reader 0かつ全旧session fence後だけ次candidateのinactive bankとして上書きできる。
   orphan/partial candidateはactiveにならず、bounded diagnostic後に同じbank全9 valueを再stageする。

credential/manifest/revocation/authority generationのgap、rollback、same-generation別bytes、wrap、
old selector replayは§14.3.1どおりrejectする。NWC1にも同じgenerationをcopyするため、古いpageを
新NCM1へ差し替えられない。same-term tombstone keyの再追加、tombstone削除/変更、old page replayを
rejectし、strictly greater authority termだけがgeneration 1、new root/clock epoch/NRV1/NCM1へ
移行できる。

##### NWM1 migration、rollback、unknown schema

v1 recordをin-placeで再解釈しない。将来profileは別exact namespaceを使い、source key `03`へ
次の224-byte `NWM1`をFULL publishして旧binaryを先にfenceする。

| Offset | Bytes | Field / exact rule |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NWM1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 192 |
| 8 | 4 | total_length = 224 |
| 12 | 4 | flags = 0 |
| 16 | 1 | state: PREPARED=`0x01` / DESTINATION_COMMITTED=`0x02` |
| 17 | 7 | reserved = 0 |
| 24 | 16 | non-zero `migration_id` |
| 40 | 16 | source NWS1 `store_epoch_id` |
| 56 | 32 | SHA-256(source 148-byte selector) |
| 88 | 32 | SHA-256(exact target namespace bytes) |
| 120 | 32 | non-zero target profile document/artifact digest |
| 152 | 4 | non-zero target storage schema |
| 156 | 4 | reserved = 0 |
| 160 | 32 | target selector SHA-256。PREPAREDはall-zero、COMMITTEDはnon-zero |
| 192 | 32 | `migration_record_digest` |

orderはsource PREPARED FULL → target initialize/copy/validate → target selector FULL →
source DESTINATION_COMMITTED FULLである。NWM1存在中は通常v1 Runtimeを起動せずmigration ownerだけが
openする。PREPARED COMMIT_UNKNOWNはreopenしmarker有無/bytesを解決する。PREPARED rollbackは、
target namespaceにselector/activation recordがなくtargetを完全消去したことを同じauthorityが
証明した場合だけ、source markerをFULL eraseして許す。target selectorが存在する、またはtruthが
unknownならeraseしない。DESTINATION_COMMITTED後のsource rollback/old selector利用は禁止する。
crash後はmarkerと両selectorを再読し、target activeならstate 2へ進め、sourceへ戻さない。

NWS1/NWA1/NWC1/NWP1/NWM1のknown magic + future versionはUNSUPPORTED_SCHEMA、known versionの
length/reserved/digest/semantic mismatchはCORRUPTとする。unknown key/magic、extra/trailing、
partial migration、source selector mismatchもCORRUPTである。future profileをv1 readerが
best-effort decodeしたり、missing selectorをfreshとして作り直したりしない。

##### Canonical KAT、independent oracle、S1〜S6 trace

codec KAT familyはauthority `00..0f`、term 1、clock epoch `10..1f`、local Runtime
`f0..ff`、store epoch `e0..ef`、peer Runtime `10..1f`、Attachment `20..3f`、
NRV1 count-0 set digestを用いる。91-byte SPKIはP-256 generator pointを上記canonical DERへ
encodeする。short KATのrootはbytes `00..7f`、leafはbytes `80..ff`、intermediateなしである。
これら2 synthetic DERは**byte codec/digest専用でX.509 semantic positiveではない**。
全NWC1 KATはrole client、credential/revocation/manifest generation各1とする。remote KATなので
key-ref kindはNONE、provider ID/handleはall-zero、shortのcertificate countは1である。
max KATのrootは`byte(i mod 256)` 2048 bytes、credential index `j`のleafは
`byte((i+j) mod 256)` 2048 bytes、intermediateは
`byte((0x80+i+j) mod 256)` 2048 bytes、runtimeは
`15 * 00 || u8(j+1)`、Attachment byte index `i`は
`byte((0x20+i+j) mod 256)`とする。他fieldはshort familyと同じで、certificate count 2、
page row/slotは`j=0..7` strict ascendingである。NWP1 shortはbank 0/page 0/slot 0の1 row、
emptyはbank 0/page 1、両方manifest generation 1である。

| Artifact | Length | Trailing digest | SHA-256(complete bytes) |
| --- | ---: | --- | --- |
| NWS1 | 160 | `d2d782ed6c6f434781f5f05bc62d2182bf3df1bc6cf2f99f1d649ca9c9066bc0` | `90b8c210c2249c4d3472338295d28362990871891d486cf8bf819b90ce693e12` |
| NWA1 short | 288 | `8fa81bdf8c774478f1c39af55364cc08629e869a12e2cc22fc0fbbd31eb306d8` | `2917dfa9039fcb4930ef1f7f2d32459cd43efc07d769b873a470469e266b8293` |
| NWC1 short | 576 | `b357046ef51bbaab75891cc1d5a587b61fe08afa64ef138f86d06d3aea1125e6` | `0eaeff06d0cb26e8a1642d115ee2d4597d0da23b279588f6d17b14d8a842c2b3` |
| NWP1 bank0/page0/1 row | 676 | `5d51f88ac1367cbac0a43d67c40f9593c4ea1fc07329806acc78016a016be6ef` | `113e204f457b9353a82945955e488c23f84a104e285940e50b2e9168865ad4c9` |
| NWP1 bank0/page1/empty | 96 | `548a73c7ae4908d94e413426e075614c8dcd435d06bb15be4f0b0db116d353cb` | `895104f1ed76aa394bfc8d5bba56d1ef437ea19862a9988ace1521046ededd85` |
| NWA1 max | 2208 | `5730a09bb5e6f566ed4197dff0371ccd5cf5cb74e2f164fc19721095087f09f4` | `3f867e60d3b18e7e29595d76f6bb328dc5ec0a70fe6f3e6688446561b4e95f11` |
| NWC1 max index 0 | 4544 | `cf55c1dd5d38c44fb56b2fb9bb69d7f9101e3113967fff3757aee734d2533954` | `f540060f4931f22dfd1cf66ec47a3ea04b68ff008d5b9e1a3c6a41907eccf8f6` |
| NWP1 max 8 rows | 36480 | `3d39f7e018b7dca581c2be7b9c33c6e7c2fb90fdf2be19910ca65625780c30d3` | `a79721eef26f533da9a7b6d1c09fd9dfebc911bdd53b64ee100b0f7d96589762` |
| NWM1 PREPARED | 224 | `d3aa18e461a77142faafbd99936242346cf28e0cfe6dc221cfd515d35c9258c0` | `0a971946b1821e8c33a2c755e67ed8c13d43d920e4f8fd3d600c31f7d76739b2` |

NWM1 KATはmigration ID `d0..df`、source store epoch `e0..ef`、上記short NWC1をactive
1/retired 0にしたintegration selector、target namespace ASCII
`ninlil.wifi.security.v2`、target profile identity ASCII
`NINLIL-WIFI-CREDENTIAL-STORE-V2`の各SHA-256、target storage schema 2、PREPARED、
target selector digest all-zeroを使う。

short componentsはroot SHA
`471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5`、
SPKI SHA
`5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`、
leaf SHA
`60ae23ee1dd9974d2f4036aa646f97b13f1a5a8b6304c31faea05c59cb363c65`、
chain digest
`0fe23a2f305a85244c78d4bf24d41b65023913634db096372c521d94267c00be`
である。short NWC1をNCM1 active 1/retired 0、`local_role_mask=0`へ入れた
remote credential byte-integration KAT（codec-only / non-activatable）はNCM1 digest
`7fe2ece8ef76a491ac906c13591ad400978bb835a52529e887bb5dea16d4ae31`、
NCM1全体SHA
`164177b6c9cca59755e3f044b77d9ca5953d4579c0c90cf3a91848c68796dfb1`、
NRV1 count 0と組み合わせた148-byte selector SHA
`9556217fc951674f3bf7070eabde76c4f61b8836da420f3cfcf781e8009b81e2`
である。上記値と4544/36480/302512/605556/447/606003/1212006の保守予約算術、
および299952/600883/1201766のconstraint-aware算術は、
Python `hashlib`/`struct`とNode `crypto`/Bufferの独立実装でbit-exact一致した。

key-proof verifier KATはshort NWC1のprovisioning digestを使い、proof digest
`5ba86332ee21169fe798ac9158bac2f0553194df1310c617fee9ae0d6e6b7d76`、
P-256 private scalar 1 / test nonce 1で得るlow-S raw64を
`6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296`
`393fcad930b2a7191faa6c8943a0fc1cf0b1e84d661ba4cc002ee36fb55ee545`
とする。これはverify/encoding oracleであり、production providerにnonce 1や同一signatureを
要求しない。対応high-S
`c6c03525cf4d58e7e0559376bc5f03e2cc35126040fbf9b8f38ae7534704400c`はowner境界でrejectする。

semantic oracleは§14.2のvalid leaf-only/leaf+intermediate/root DERを使い、short synthetic DERを
positiveへ流用しない。minimum/maximum、1/2 cert、local/remote key ref、64 active、
0/64 retired、active+retired 64/65、publish時のlocal role client/server/both、
mask 0/unknown/missing/extra role、role mask変更時のmanifest generation +1、
active 0 codec-only/publish拒否、NWA1 root置換、各field/length/digest/row/key mutation、
2 bank ambiguity、key-binding history 64/65、全FULL write crash、migration stateをclosed
vector catalogにする。capacity oracleは606003/1212006の保守provider reservation ceilingと、
600883/1201766のconstraint-aware semantic maximumを別artifactとして検証する。

| Gate | 本節で固定したもの | `SPEC_ACCEPTED`前の残り |
| --- | --- | --- |
| S1 | owner、専用failure domain、private key非保存、NCM1との責務分離 | ADR全体scope trace同期 |
| S2 | profile/NWS1/NWA1/NWC1/NWP1/NWM1 v1候補、exact namespace/key | [06章](../06-versioning-and-compatibility.md)とdecision index同期 |
| S3 | field、generation、2-bank、FULL/crash、capacity/migration、local-role/root bindingをexact化 | なし（本profile slice） |
| S4 | independent digest/arithmetic KATとmutation catalog | valid X.509 semantic fixture、machine-readable oracle artifact、全crash-vector生成 |
| S5 | old/future拒否、no in-place migration、rollback fence、docs-only nonclaim | mixed-version executable testはRELEASE gate |
| S6 | trace表 | 独立review、P0/P1=0、関連文書の最終整合 |

Controller-authenticated management envelopeを検証したownerだけがcandidateを受け入れる。
digestはauthority signatureの代替ではない。ownerはcandidate bytesとNCM1参照先を全検証してから、
NRV1 record、NCM1、148-byte current selector
`authority_id[16] || authority_term_u64 || clock_epoch_id[16] || generation_u32 ||
revoked_set_digest[32] || record_digest[32] || credential_manifest_generation_u64 ||
credential_manifest_digest[32]`を同一durable
transactionでFULL publishする。selector integerはunsigned big-endianである。atomic owned payloadは
最大`2192 + 6272 + 148 = 8612` bytesで、先にFULL stageしたcredential record bytesを再包含しない。
上記NRV1 count 0/NCM1 count 0 KATを組み合わせた148-byte selectorのSHA-256は
`c89d4ef475ed7a8b63bbdf023a13bcc0d473ca99619e8f7de952da2975f00c0f`である。
restart後はold FULLまたはnew FULLだけを認め、
partial/candidate、selector mismatch、missing current recordからprevious recordへsilent fallback
しない。selectorが示すNRV1/NCM1またはNCM1参照先がmissing/corruptならprofile unavailableとし、
old selectorへfallbackしない。readerは最大2192-byte NRV1と最大6272-byte NCM1をcaller-owned
bufferへcopy-ownしてdigest/time/order/referenceを再検証し、
immutable identity snapshotと48-byte freshness viewだけをhandshakeへ渡す。session identityの
`revoked_set_digest`はNRV1の同名fieldと一致させる。`revocation_record_digest`はhandshake
evidence/freshness検査へ残すが、identityが同じfreshness refreshによる
`record_digest/generated_at/valid_until`だけの変更ではsessionをfenceしない。full recordを
sessionごとに保持してはならず、NRV1/NCM1 current/candidate 2-bufferはprocess
globalである。

handshake中と各NWB1 publish直前のcurrent NRV1 checkは次の順で行う。

1. selector、NRV1、NCM1、当該peer-role entryと参照credential recordをcopy-ownし、
   length/order/all digest/reference/timeをすべて再検証する。
2. authority/term/clock epoch/revocation generation/set digestに加え、当該entryの
   manifest generation、credential generation/provisioning record digestと
   record内runtime/role/Attachment bindingを
   immutable identityへ比較し、提示leaf DER SHA-256もsnapshot値と照合する。
   1 byteでも違えばfreshness viewを変更せずfenceする。
3. current `record_digest`がsession freshness viewと同じならgenerated/valid-untilもbit-exact一致を
   必須とする。digestが違う場合は、global ownerがFULL transitionとして受理済みで、同一
   generation/set、`generated_at_ms` strict増加、`valid_until_ms`非減少を満たす場合だけ、
   `{record_digest, generated_at_ms, valid_until_ms}` 48 bytesをatomic replaceする。
4. replace後のviewでtimeを再評価してからleaf fingerprint lookupとpublishを行う。

step 1のselector copyからstep 4のPortable Core publish完了までは、authority/credential/NRV
ownerのbounded read gateを保持する。management FULL current switchは同じgateのexclusive owner
だけが行う。したがってrecord publishはsecurity view変更の前または後へlinearizeし、検査とpublish
の間のTOCTOUを許さない。deadlineまでにgateを取得できないrecordはpublishせず、既存security
viewへfallbackしない。identity-changing switchはexclusive gateを解放する前に、bounded session
tableの旧identity sessionをすべて`FENCED`へ遷移し、そのbearer availability epochを当該switchに
対してexact +1する。close I/Oはgate解放後でもよいが、fence後のpublishは0である。同一set
freshness refreshはこの一括fenceを行わない。

したがってidentity fenceに用いるset digestは`count || entries`だけから、freshness evidenceに
用いるrecord digestはself fieldを除くrecord prefixから独立に計算され、digest→state→digestの
循環はない。candidate不正時に旧freshness viewへfallbackしてpublishしてはならない。
set changeではsurviving peer用leaf/provisioning recordもnew `revocation_generation`と
`credential_generation = previous + 1` exactへ再発行し、各nodeでNRV1 selectorと同じmanagement
revisionのcandidate setへFULL stageする。全NCM1 entry/tombstoneと参照先を検証後、
上記8612-byte以下の
NRV1/NCM1/selector transactionだけでactive setを切り替える。旧setはexclusive gate readerが0に
なった後だけGCする。credential generation wrapは禁止してauthority term rotationを
要する。old generation leafをnew NRV1のまま許可せず、new credential未到着peerは
明示unavailableとする。同一set freshness refreshはleaf再発行を要しない。
revoked setを変えないcredential-only rotation/add/removeもNCM1 semantic updateであり、
NRV1全bytesをbit-exact据置、manifest generationをexact +1して同じtransactionを行う。
manifest generationがsession identityと変わるため、entryが未変更のpeerを含む旧sessionも
exclusive gate解放前にfenceする。

peer leaf DER SHA-256は`lo=0, hi=count`のhalf-open rangeから開始し、`mid=lo+(hi-lo)/2` floor、
compare equalならrevoked、target < entryなら`hi=mid`、それ以外は`lo=mid+1`とするbinary
searchでlookupする。`lo==hi`はnon-matchで、count 64のhit/missは最大7回、count 0は0回の
32-byte比較である。non-matchだけが継続候補である。NRV1 entryはleaf専用とし、provisioned certificate inventoryで
CA fingerprintの投入をrejectする。intermediate/rootのrevocation・compromiseはNRV1 entryで
表現せず、new trust chainとnew authority termをFULL installしてold term全体をineligible/fenceし、
new termのNRV1 generation 1をpublishする。

current NRV1がmissing、unknown、corrupt、oversize、stale、expired、clock-regressed、または
leaf matchならnew handshakeは`CHANNEL_AUTHENTICATED=0`、NFL1 delivery 0とする。確立済みsessionは
exclusive current switchまたは次のpublish前checkでavailability epoch exact +1、delivery 0、
closeとし、同じtransitionで二重加算しない。set changeによる
generation/`revoked_set_digest`変更、authority/clock epoch変更にも同じfenceを適用する。
handshake deadlineはadmission recordの
`{clock_epoch_id[16], handshake_deadline_ms_u64}`をcopy-ownし、Accepted authority snapshotと
clock epochがbit-exact一致した後だけ数値比較する。epoch不一致、または
`clock_now_ms >= handshake_deadline_ms`をrejectする。handshake完了時にもfresh authority
`clock_now_ms < handshake_deadline_ms`を必須とする。admissionでは
`revocation_valid_until_ms > handshake_deadline_ms`も必須とする。

`clock_trust`はAccepted authority timeだけを許可する。overflow/underflowを先にrejectし、
`snapshot_created_ms <= clock_now_ms < snapshot_valid_until_ms`、
`snapshot_age_ms = clock_now_ms - snapshot_created_ms <= 300000`、
`snapshot_valid_until_ms > handshake_deadline_ms`をすべて満たさなければならない。
leaf、提示intermediate、
local rootすべてのX.509 validityを`notBefore <= clock_now < notAfter`で評価する。backend OS
wall clockをauthority clockの代替にしない。OpenSSLはverify parameterへ
`X509_V_FLAG_NO_CHECK_TIME`を設定したうえでprofile callbackが全chainのtimeを検査する。
mbedTLS callbackはauthority time検査が成功したcertificateについてだけ
`MBEDTLS_X509_BADCERT_EXPIRED`/`MBEDTLS_X509_BADCERT_FUTURE`をclearできる。他のbackend
verification error/flagをclearしてはならず、profile-owned DER/identity/revocation検査は
errorを追加する方向にだけ働く。両backend callbackは同じimmutable snapshotとchain depthを使う。

leaf bindingのauthority、term、credential/revocation generation、leaf DER SHA-256、
runtime/Attachment bindingはFULL provisioning recordとbit-exact一致を必須とする。snapshotの
revocation generation/`revoked_set_digest`はcurrent valid NRV1と一致し、peer leaf fingerprintがNRV1に
存在しないことを必須とする。unknown/stale/corrupt NRV1、digest不一致、clock epoch変更はrejectする。
intermediate/rootは§14.3.1のauthority-term rotationだけで失効させる。

handshake中またはsession中にcurrent authority term、clock epoch、revocation generation/
`revoked_set_digest`、credential manifest generation、credential generation、
peer provisioning record digest、
Attachment bindingのどれかがsnapshotと変わった時点でsessionを
`FENCED`にし、以後のNWB1 deliveryを0、availability epochをexact +1、connectionをcloseする。
各NWB1 recordをPortable Coreへpublishする直前にもfresh immutable authority viewを再取得する。
そのview自身のageを`<=300000 ms`、`clock_now < valid_until`とし、session snapshotと同じ
authority term/clock epoch/revocation/credential/Attachment値、前回session clock以上の
`clock_now`、`clock_now < min(leaf, intermediate if present, root notAfter)`を必須とする。
current NRV1のage/validity/record digestも再検査する。取得不能、stale/corrupt NRV1、
clock rollback、chain expiryへ達した場合も同じfenceを適用し、そのrecordをpublishしない。
immutable identity snapshot自体をin-place更新せず、上記48-byte freshness viewとsession last
clockだけを進める。
rotationはnew credential FULL → new full handshake/peer binding/exporter → old session FENCED/close
→ old credential retireの順とする。ESP per-peer 2-session上限はこの重複期間だけを許す。

### 14.4 Resumption、0-RTT、KeyUpdate

v1は毎回certificate-authenticated `(EC)DHE` full handshakeを必須とする。ESPはPSK/
PSK-ephemeralとclient/server ticketをcompileしない。Host serverはticket発行0、cache off、
clientはsessionを再設定しない。backendがresumed sessionを報告した接続はrejectする。

peerがPSK identity/ticketをofferしても、backendがそれを無視してfresh full handshakeを完了する
場合だけ接続を継続できる。0-RTT byteは常にNWB1 delivery 0とし、early dataを受理、復号、
applicationへpublishした場合は接続を閉じる。full handshake完了前のapplication byte publishは0。

local adapterはKeyUpdate APIを呼ばない。Hostは`SSL_CTX_set_msg_callback()`を必須とし、
callbackが`SSL3_RT_HANDSHAKE`のinbound/outbound
`SSL3_MT_KEY_UPDATE` (`24`)を見た時点でfence flagを立てる。各`SSL_do_handshake()`/
`SSL_read_ex()`/`SSL_write_ex()` return後、application byteをpublishする前にflagを検査し、
inbound byteと同じcallで返ったplaintextも破棄してcloseする。outbound検出はadapter/backend
違反として同じくcloseする。

pinしたmbedTLS SHAにはKeyUpdate処理branchがなく、handshake後のKeyUpdateは
`ssl_tls13_handle_hs_message_post_handshake()`から
`MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE`を返す。ESP adapterは確立後のこのerrorをfenceとして
application delivery 0のままcloseする。target injection testでこのerror pathが変わった版、
またはKeyUpdateをsilent処理して上記hook/errorで観測できないbackend/versionはprofile不適合とする。
session lifetimeは最大3,600,000 msで、sequence上限、credential/authority fence、deadlineの
早い方でcloseし、rekeyはfresh TCP + fresh full handshake + fresh non-zero exporter
`session_id`だけで行う。

### 14.5 TLS record、certificate flight、allocator bounds

NWB1/Core資源とstock TLS資源を次の別accounting domainにする。

| Bound | ESP32-S3 | Host |
| --- | ---: | ---: |
| total TLS sessions | 2 | 64 |
| concurrent handshakes | 1 | 8 |
| sessions per peer | 2（rotation中のみ。通常1） | 2 |
| NWB1 RX buffer / session | 2088 bytes fixed | 2088 bytes fixed |
| NWB1 TX buffer / session | 2088 bytes fixed | 2088 bytes fixed |
| TLS inbound plaintext record | 16384 bytes max | 16384 bytes max |
| TLS emitted application-data plaintext fragment | 4096 bytes max | 4096 bytes max |
| TLS outbound content buffer | 4114 bytes fixed（4110-byte Certificate body + 4-byte Handshake header） | backend-owned、4114-byte Certificate handshakeを許容 |
| TLS record wire bytes / record | 16645 bytes max（5-byte headerを含む） | 16645 bytes max（5-byte headerを含む） |
| TLS wire bytes before Finished / direction | 32768 bytes max | 32768 bytes max |
| presented certificate count / each DER / DER sum | 2 / 2048 / 4096 bytes max | 2 / 2048 / 4096 bytes max |
| TLS 1.3 Certificate message body | 4110 bytes max | 4110 bytes max |
| NRV1 current/candidate buffers | 2 × 2192 bytes fixed | 2 × 2192 bytes fixed |
| NCM1 current/candidate buffers | 2 × 6272 bytes fixed | 2 × 6272 bytes fixed |
| NRV1/NCM1 active selector | 148 bytes fixed | 148 bytes fixed |
| management atomic owned payload | 8612 bytes max | 8612 bytes max |
| credential store | `NINLIL-WIFI-CREDENTIAL-STORE-V1`: local + peer active subject-role合計64/bank、published bankはactive local credential 1件以上、NWC1 4544 bytes/record、NWP1 8 × 36480/bank、NWA1 2208/bank、25 keys / 606003 committed logical bytes、provider staging 50 / 1212006（保守reservation。semantic maximum 600883 / 1201766）、scratch 36480/store、external key-binding history 64 × 128 = 8192（client/serverは各1 record） | 同左 |
| security identity + freshness / session | 226 + 48 = 274 bytes fixed | 226 + 48 = 274 bytes fixed |
| NRV1-owned subset / session | 84 bytes（generation 4 + set digest 32 + freshness view 48、上記274内で非加算） | 同左 |
| credential-owned subset / session | 44 bytes（manifest generation 8 + credential generation 4 + provisioning record digest 32、上記226内で非加算） | 同左 |
| TLS allocation budget / session | 98304 bytes | 262144 bytes |
| TLS session-pool budget / process | 196608 bytes | 16777216 bytes |
| crypto global/provider budget / process | 65536 bytes | 4194304 bytes |
| TLS + crypto total allocation budget / process | 262144 bytes | 20971520 bytes |
| minimum post-admission free internal heap | 65536 bytes | N/A |
| minimum TLS task stack watermark | 2048 bytes | N/A |

本表のTLS/crypto allocation値はmbedTLS/OpenSSL closureだけをboundし、ESP-IDF Wi-Fi driver、
event/task、LwIP、socket、netif、DHCP、PBUFのdynamic/static allocationを閉じない。Wi-Fi実経路全体を
`RELEASE_SUPPORTED`とするには、pinned ESP-IDFでそれらのexact sdkconfig、pool/count/byte ceiling、
owner、admission前reservation、peak/watermark、OOM/reconnect/sleep-wake動作を別resource profileへ
固定し、C7/C8でtarget traceを取る。未固定値をTLS totalへ推測加算したり、TLS allocator probeを
Wi-Fi driver/LwIP heap evidenceとして使ってはならない。

ESPの`mbedtls_platform_set_calloc_free()`はmbedTLS/PSA Cryptoの全entrypoint、自動初期化、
R7 crypto利用より前に1回だけinstallする。Hostの`CRYPTO_set_mem_functions()`はbootstrapの
**最初のOpenSSL call**とし、`OPENSSL_init_crypto()`、provider/config load、R7 crypto、
他componentのOpenSSL API、自動初期化より前に呼ぶ。各setterの成功をstartup gateとし、
既にlibrary allocation/initializationが発生してhookをinstallできないprocessはprofileを開始しない。

owner classは`TLS_SESSION(session_id)`、`CRYPTO_GLOBAL`（provider、config、property cache、
DRBGを含む）、`OTHER_REGISTERED(component_id)`とする。per-session budgetは
`TLS_SESSION` allocationだけを数え、session-pool budgetは全`TLS_SESSION`のcurrent bytes合計、
global/provider budgetは`CRYPTO_GLOBAL`、total budgetは3 owner classすべてのcurrent bytes合計を
数える。global/provider allocationをsessionへ誤帰属せず、初期化後baselineとpeakを
`CRYPTO_GLOBAL`へchargeする。いずれかの列上限を超えてはならない。同一processの他library利用者は
owner budgetを登録し、unowned allocation、TLS libraryのbackground threadをproductionで許可しない。
allocator owner切替とTLS/crypto backend callは直列化し、callbackを含むcall終了までownerを
保持する。free/reallocはallocation前置headerとintrusive ledgerに記録した元ownerへ
charge/refundし、ledger自身のunowned/dynamic allocationを禁止する。
bootstrapは`CRYPTO_GLOBAL` ownerでPSA/OpenSSL provider、RNG、P-256/ECDSA、AES-128-GCM、
SHA-256/HKDFとX.509 pathをprewarmし、provider/config/property setをsession admission前にfreezeする。
以後のsession call中に生じたallocationを事後にglobalへ付け替えず、その`TLS_SESSION`へchargeする。
lazy global cacheがsession ownerに残るbuildはsession owner-zero gateを満たさないため不適合とする。

session admission時にNWB1 fixed buffersとTLS session budgetを先にreserveする。reserve不能、
single allocation/累計/process budget超過、record/flight/certificate上限超過、allocator OOMでは
新sessionをfail-closedで閉じ、`CHANNEL_AUTHENTICATED`、NWB1 delivery、custody成功を0とする。
既存sessionのreservationを奪わない。全close pathで当該`TLS_SESSION` ownerのoutstandingが0、
last-session close後に`CRYPTO_GLOBAL`がstartup baselineへ戻ることを検査する。orderly backend
shutdown後は全owner outstandingを0にする。current/peak、minimum free heap、stack watermark、
reject reasonをbounded diagnosticsへ残す。
adapter transportは最初のTLS record byteからlocal Finished検証完了まで、5-byte record headerを
含むread/write wire byteを方向別に数え、32768 bytesを超える前にcloseする。record headerの
declared lengthが16640 bytesを超える場合もbackendへ渡す前にcloseする。この観測と遮断を
実装できないbackend/versionはprofile不適合とする。

これらはstock TLSがheap-freeであるというclaimではない。`SPEC_ACCEPTED`はexact bound、
exhaustion動作、構造gate、算術/KATを設計として固定するが、target成立を主張しない。
上記hard admission/accounting gateとtarget measurementの双方を満たすことは
`RELEASE_SUPPORTED`のC7/C8条件である。post-spec targetでreserved値が成立しない場合は、
値を黙って緩和せずProposed amendmentへ戻し、独立review後にre-`SPEC_ACCEPTED`する。

## Version、compatibility、migration

- NWB1 version 1は本ADRの`SPEC_ACCEPTED`とexact KAT固定まで未割当候補、以後はreservedである。
  reserved値はprivate/feature-gated implementationへ使用できるが、`RELEASE_SUPPORTED`前に
  production on-air supportやstable public wireとして広告しない。
- NRV1/NCM1と`NINLIL-WIFI-CREDENTIAL-STORE-V1`のNWS1/NWA1/NWC1/NWP1/NWM1 version 1も
  本ADRの`SPEC_ACCEPTED`まで未割当候補、以後は当該profile内のreserved local management
  formatである。NCM1だけでcredential record schemaやbyte boundを代替しない。
- `NINLIL-WIFI-TLS13-P256-V1`はsuite、credential/authority lifecycle、exporter/DER/NRV1 KAT、
  backend/build/allocator closure設計が`SPEC_ACCEPTED`になるまで候補である。実fingerprint allowlist、
  target-executed handshake、HILは`RELEASE_SUPPORTED` gateであり、設計受入を循環依存させない。
- NFL1 version 1を内包するが、NWB1とNFL1のversion domainを共有しない。
- NCG1/NCL1 control framing、U5/U6 control v2、NRW1 `0x11`を変更しない。
- NWB1非対応peerへraw POSIX loopback wire、NCG1、plain length-prefixでsilent fallbackしない。
- old Runtimeは従来Bearerを継続利用できる。Wi-Fi設定がないdeviceはregistryへinstanceを登録しない。
- credential、peer endpoint、link policyはrevision/digest付きnamespaceへ保存し、socket/fd、
  DHCP lease、pointerはdurable化しない。

## SPEC_ACCEPTED gate

本ADRのAcceptedはnormative designの`SPEC_ACCEPTED`だけを意味し、implementation、target、
HIL、production supportを意味しない。次をすべて閉じた時だけProposedから遷移できる。

1. scope、dependency direction、opaque Core境界、failure domain、custody/Attachment非混同、
   TEST/LAB_ONLY downgrade、old Runtimeとのcompatibility/nonclaimをexactに固定する。
2. NWB1 40-byte header、584..2048 payload、2088-byte record、CRC32C、sequence、exporter
   label/context、partial I/O、error/close規則を独立model/KATで再計算する。version 1はこの時点で
   **reserved**となるがstable public/production supportではない。
3. TLS exact suite/group/signature/mTLS、ESP-IDF/mbedTLS source pinとsdkconfig、
   `CLOSURE_ROOTS_V1` source/link/final-ELF gate、Host OpenSSL source pin、2 target tuple、
   ordered hermetic build recipe、OWF1 schema、static/provider/libctx/bootstrap条件を固定する。
   actual target archives、per-target fingerprint allowlist、runtime/HIL合格は未要求・未主張とする。
4. X.509 UUIDv5/OID/124-byte Extension/82-byte binding、Certificate body
   `2057/4110/4111` boundary、NRV1 `144/176/2192` KATとset/record digest、NCM1
   `128..6272` layout/manifest generation/digest/8612-byte atomic accounting、
   NWS1/NWA1/NWC1/NWP1/NWM1 short/max/integration KAT、age/update/fence state machineを
   2個以上の独立計算でbit-exact照合する。synthetic byte KATとvalid X.509 semantic KATを分離する。
5. NWB1/TLS/NRV1の全resource bound、exhaustion、allocator owner、certificate/flight/record
   arithmetic、crash FULL ordering、TOCTOU linearization、rotation/compatibilityをNormative値として
   固定する。credential storeは§14.3.2のcanonical schema、4544-byte record、2 bank、
   25 keys / 606003 committed / 50 keys / 1212006 stagingの保守reservation ceiling、
   600883 / 1201766のconstraint-aware semantic maximum、current/candidate各64 record、
   opaque private-key referenceを固定する。target feasibilityは設計reviewでriskを明示するが、
   target PASSを受入条件にしない。
6. [34章](../34-v2-runtime-fabric-completion.md)のS1〜S6、既存Accepted contract優先、
   version/migration文書、decision log、独立security reviewを同期し、未解決P0/P1を0にする。
7. `SPEC_ACCEPTED`後のimplementationはprivate/feature-gated、default OFFから開始し、
   `RELEASE_SUPPORTED`前のproduction on-air enable、stable public install、support claimを禁止する。

## RELEASE_SUPPORTED gate

`SPEC_ACCEPTED`後に実装を開始し、以下15項目と[34章](../34-v2-runtime-fabric-completion.md)の
C1〜C10をすべて閉じた時だけ`RELEASE_SUPPORTED`へ遷移できる。

1. source/config gateはESP-IDF commit
   `2c211b236707889e8400c4dc5644dd5c4ee071e0`、mbedTLS commit
   `ffb280bb63c78bfec1e1ab55040671768c85c923`、OpenSSL tag/peeled commit
   `openssl-3.5.7`/`8cf17aaeb4599f8af87fefd810b5b5fee90fe69e`、clean source tree、
   §14.1 sdkconfig/preprocessor inventoryを照合する。pure ESP-TLS symbol、ESP crypto ALT/ROM/
   DS/ATECC/TEE enable、片方への両backend混在をconfigure/link failにする。
2. ESP32-S3 target compile/linkはdirect mbedTLS client/server両role、Host Linux/macOSは
   §14.1.2 exact 2 tupleでpinned static OpenSSL client/server両roleを含む。Hostは同一clean
   source/tree digest/hermetic toolchain bundleを別々のclean build environmentへ展開し、fixed path、
   pinned `/bin/sh` alias、sandbox policy/dependency report、sysroot、ordered argv、`-j1`、
   deterministic archive条件でOWF1 fingerprintとarchivesを各tuple 2回buildしてbyte/digest一致、
   host `/bin/sh`/filesystem/network escape、wrong target/
   compiler/configdata/header/archive/fingerprint、dynamic/system OpenSSL、module/config/env、
   extra provider、NULL libctx、generic SDK OpenSSL 3.xだけのbuildをstartup/link rejectする。
3. X.509 KATは§14.2のUUIDv5/OID、full Extension DER、82-byte binding、P-256 SPKI、
   certificate signature、leaf/intermediate/rootのbasicConstraints/pathLen/KU/EKU/SKI/AKI/
   extension allowlist/self-signature、chainを独立DER oracleと照合する。各tag/length/OID/field/
   role/bit/byte mutation、duplicate/unknown SANまたはextension、DNS/IP/CN-only、SKI/AKI mismatch、
   custom `otherName`の`MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE` raw-preservation path、
   non-zero Certificate context/entry extensionを両backendがrejectする。1 DER 2048 + overhead 9 =
   2057、2 DER各2048 + overhead 14 = 4110をacceptし、1 DER 2049、DER合計4097/body 4111、
   3-certificate chainをrejectする。ESPは4110-byte body + 4-byte Handshake headerを
   4114-byte out content bufferから実送信し、4096-byte application chunk上限と混同しない。
4. TLS positive matrixはHost client↔Host server、ESP client↔Host server、
   Host client↔ESP serverをLinux x86_64/macOS arm64の両tupleで含む。packet transcriptと
   backend postconditionでTLS 1.3、
   `0x1301`、`0x0017`、`0x0403`、initial-handshake mTLS、non-resumedを両endpointで証明する。
   ESP clientのexplicit `mbedtls_ssl_set_hostname(NULL)`成功、SNI/DNS/IP/CN照合0、
   critical bindingによるserver identity成功も直接assertする。
5. TLS negative matrixはTLS 1.2、AES-256-GCM、ChaCha20-Poly1305、X25519、P-384、
   RSA-PSS、wrong/missing clientまたはserver certificate、wrong trust anchor、KU/EKU/role/
   runtime/Attachment/authority mismatchを1条件ずつ注入し、`CHANNEL_AUTHENTICATED=0`、
   NFL1 delivery 0を証明する。
6. NRV1 KATは§14.3.1表のcount `0/1/64`、total/set digest/record digest/record SHA-256を
   bit-exact照合し、sorted lookup hit/miss最大7比較、independent SHA-256 oracleを含む。
   count 65、total/header/
   fingerprint length/flag mutation、zero/duplicate/out-of-order entry、set/record digest mutation、
   trailing、generation gap/wrap/set removal、same-set refresh規則、future、age `300000/300001`、
   `now==valid_until`、86400000/86400001 window、clock/generated/valid-until regression、
   authority term増加なしのclock epoch変更をrejectする。
   全FULL write crash point、restart old/new only、missing/corrupt selector、leaf revoke、CA fingerprint
   entry reject、set change時のsurviving credential再発行/old generation拒否、
   intermediate/root authority-term rotationを検証する。さらにchainのnot-before/
   expiry boundary、clock epoch/authority term/revocation digest/credential generation/Attachment
   changeを含める。OS wall clockを過去/未来へ振り、OpenSSL
   `X509_V_FLAG_NO_CHECK_TIME` + profile checkと、mbedTLSでtime flag以外をclearしないことを
   直接assertする。同一set refreshはimmutable identityを維持して48-byte freshness viewだけを
   atomic replaceし、set/generation変更または不正candidateは旧view fallbackなしでfenceする。
   concurrent management FULL switchを全publish境界へ注入し、bounded read/exclusive gateにより
   recordがoldまたはnew viewへだけlinearizeし、exclusive gate解放前に全旧identity sessionが
   fenceされ、mixed/unchecked publish 0であることを証明する。
   NCM1 active/retired count `0/1/64`、active 0 publish拒否、durable `local_role_mask`
   0/client/server/both/unknown、management inputとのmask mismatch、missing/extra local role、
   role変更時のmanifest strict +1と旧session fence、selected NWA1 root置換、
   128/184/3712/6272 length、entry/tombstone
   ordering/duplicate/overlap/role/reserved/digest mutation、active + retired 64/65、
   same-term tombstone再追加/GC、missing/corrupt staged record、manifest generation
   gap/rollback/replay/wrap、current/candidate各64、atomic payload 8612/8613、
   全NCM1/selector write crash point、COMMIT_UNKNOWN、restart old/new、orphan stage GCを
   独立oracleで検証する。
   NWS1/NWA1/NWC1/NWP1/NWM1のshort/max KAT、4544/4545、36480/36481、
   25/26 key、保守reservation 606003/606004 bytes、staging 1212006/1212007、
   semantic maximum 600883/1201766、local opaque-key proof、
   key binding 64/65・8192/8193 canonical bytes、65番目でV1 epoch rollover 0、2-bank ambiguity、
   全stage/key-provider/publish/migration write crash、PREPARED rollback条件も検証する。
   handshake中と確立後の各fenceでdelivery 0、availability epoch exact +1、closeを証明する。
7. exporter KATはlabel `EXPORTER-Ninlil-NWB1-v1`、94-byte context、16-byte outputを
   OpenSSL/mbedTLS独立oracleで一致させる。両endpoint同一non-zero、client/server order、
   local/peer swap、各role byte/runtime/authority/Attachment byte mutation、all-zero/failure、
   fresh handshakeで別`session_id`を検証する。
8. resumption/0-RTT testはticket発行0、cache 0、`SSL_session_reused()==0`、ESP PSK mode 0を
   artifact化する。ticket/PSK offerがfresh full handshakeへ落ちる場合だけ通常dataを許可し、
   early byteはdelivery 0とする。OpenSSL message callbackのinbound/outbound flagと、pinned
   mbedTLSの`MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE`を直接assertし、local KeyUpdate emit 0、
   peer KeyUpdateと同じbackend callで返るplaintextを含むapplication delivery 0、closeを
   Host/ESP両roleで検証する。
9. NWB1 minimum-valid/maximum KAT、独立CRC32C oracle、1-byte partial read/write、
   concatenated record、truncation、trailing、全length/CRC/session mutationを行う。
   per-direction sequence 0、exact +1、gap/duplicate/out-of-order close、
   `UINT32_MAX` emit 0、fresh-session sequence 0を検証する。
10. TLS/NWB I/Oはfake nonblocking BIO/socketで全handshake stateとrecord byte境界の
    `WANT_READ/WANT_WRITE`、positive partial、same-argument retry、backpressure、peer closeを
    target-executed testする。disconnect at every NWB1 header/payload byteでもfalse custody 0とする。
11. resource testは§14.5の全boundaryと`+1`、allocation fail at every allocation site、
    concurrent handshake/session/peer上限、oversized TLS record/handshake flight/certificate、
    4110/4111 Certificate body、ESP out content 4114 exact、NRV1 2192/2193、
    NCM1 6272/6273、8612/8613 atomic payload、
    各2-buffer上限、credential-store profileのrecord/aggregate bound、close/reconnect反復を実行する。
    ESPは§14.1.1のprobe/production ELFを自動生成し、sdkconfig、ALT macro、source token、
    archive member、GC後section、final map、`nm`、`objdump -dr` relocation/call graphを照合し、
    profile allocator以外のdirect `heap_caps_*`/libc allocation、全crypto port/ROM/DS/ATECC/TEE
    reachable path 0、Wi-Fi + Accepted R7 raw adapter exact caller allowlist、closure report
    SHA-256を証明する。unknown parser inputやprobe/production
    closure集合/caller edge不一致もnegativeでfailさせる。OpenSSLはbootstrap-first hook、既初期化fail、
    `TLS_SESSION/CRYPTO_GLOBAL/OTHER_REGISTERED` owner分離、provider/R7 crypto allocation、
    prewarm後のprovider/property freeze、session中lazy global allocation 0をtraceで証明する。
    ESP peak per-session `<=98304`、session pool `<=196608`、
    crypto global `<=65536`、total `<=262144`、
    post-admission free internal heap `>=65536`、stack watermark `>=2048`、close後session
    outstanding 0、last close後global baseline復帰をraw allocator traceで証明する。Hostも
    per-session `<=262144`、session pool `<=16777216`、crypto global `<=4194304`、
    total `<=20971520`、session outstanding 0、global baseline復帰を証明する。
    ESP Wi-Fi driver/LwIP/socket/netif/DHCP/PBUFはTLS closureと別にexact config、pool/count/byte
    ceiling、peak/watermark、OOMをtarget artifact化し、未所有allocationとunbounded growthを0にする。
12. 2-process POSIX TCPで10,000 NFL1、bulk/critical fairness、backpressure、peer/process restart、
    rotation、1-hour session lifetime boundary、24h soakを行い、memory/resource high-watermarkが
    §14.5を超えないことを証明する。
13. ESP32-S3 HILは実AP/DHCP/TCPでESP client↔Host serverとHost client↔ESP serverを行い、
    強制AP断、IP変更、peer restart、sleep/wake、credential rotation、allocator OOM、
    Wi-Fi/LwIP pool exhaustion、watchdog、power/association/reconnectをraw timestamp、
    driver/LwIP heap・pool high-watermark付きで保存する。
14. Wi-Fi断時はeligible fallback継続と不適格fallback拒否を分ける。LoRa fallback HILは
    別compact-radio mapping `SPEC_ACCEPTED`後だけであり、本profileの代替evidenceにしない。
15. clean Linux/macOS example、ESP porting guide、credential/NRV1 generatorと独立DER/SHA oracle、
    OWF1 manifest/fingerprint/archives/link maps、diagnostic runbook、SBOM/source SHA、
    independent security reviewをrelease artifactへ含める。

## Consequences

- Wi-FiをLoRaの例外処理ではなく、同じFabric policyで選択できる。
- high-bandwidth transferとmanagement trafficをLoRa airtimeから分離できる。
- secure-channel provisioning、NWB1 codec、TCP/ESP adapters、HIL設備が新たに必要になる。
- Wi-Fiの存在だけではoffline運用やLoRa redundancyを保証しない。

## Rejected alternatives

- **Wi-FiをRuntime Coreへ直接実装:** POSIX/ESP差とsocket lifecycleがportable Coreへ混入する。
- **TCP connectをcustody扱い:** peer durable commitを証明しない。
- **raw `ninlil_bearer_message_t`送信:** ABI、pointer、padding、endian非互換。
- **無条件LoRa fallback:** payload、deadline、security、法規budgetを破る。
- **magic scanでsession継続:** corrupt record後の境界とsequence証拠が曖昧になる。

## 非主張

本ADRはProposed docs-onlyであり、NWB1/NRV1/NCM1/NWS1/NWA1/NWC1/NWP1/NWM1 reserved採番、
Wi-Fi/TCP/TLS/credential-store実装、ESP target execution、HIL、implementation security review、
production supportを主張しない。
将来の`SPEC_ACCEPTED`もexact design、KAT、reserved採番だけを主張し、実装済みや
`RELEASE_SUPPORTED`を意味しない。

## Related

- [ADR-0017: Fabric Bearer Registry and Path Selection](0017-bearer-registry-path-selection.md)
- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [U6 Transport Custody](../26-u6-transport-custody.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
