# ADR-0018: Wi-Fi Packet Link for the Fabric Bearer

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-28  
受入日: —（未受入）

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
5. 本ADRをAcceptedにする前に、最低1つのexact production候補security profileを同じreview
   trancheでfreezeする。基準候補`NINLIL-WIFI-TLS13-P256-V1`は次をすべて満たす。

   - TLS version exact 1.3、cipher suite exact `TLS_AES_128_GCM_SHA256`
   - key exchange group exact `secp256r1`、signature exact `ecdsa_secp256r1_sha256`
   - authority発行のmutual X.509。trust anchor、leaf credential、provisioning recordは
     `authority_id + authority_term + credential_generation + not_before/expiry +
     revocation_generation`へbindし、FULL durable installする
   - leaf SAN/critical extensionはlocal/peer `runtime_id`と許可Attachment binding digestを
     exact bindする。hostnameやIP addressだけをpeer identityにしない
   - accepted authority clockで有効期間とrevocationを検査する。unknown/stale revocation、
     expiry、authority/Attachment mismatchはhandshake/session不成立、NFL1 delivery 0
   - rotationはnew credential FULL install → new full handshake → old session close →
     old credential retire。TLS resumption/0-RTTはv1で禁止
   - TLS KeyUpdateによるin-place session継続をv1では使わない。rekeyはfresh full handshakeと
     fresh session_idで行う

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
   heap growth、VLA、raw C struct、pointer/paddingの送信は禁止する。
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
    session数をprofileでboundedにする。
13. ESP sleep中のWi-Fi unavailableはavailability epochを進める。起床予定をavailableとして
    偽装せず、sleepy receive windowとdeadlineの交差をadmission時に検査する。

## Version、compatibility、migration

- NWB1 version 1は本ADRがAcceptedされ、exact KATが固定されるまで未割当候補である。
- `NINLIL-WIFI-TLS13-P256-V1`はsuite、credential/authority lifecycle、exporter KAT、
  target-executed handshakeが同じacceptance trancheで固定されるまで未割当候補である。
- NFL1 version 1を内包するが、NWB1とNFL1のversion domainを共有しない。
- NCG1/NCL1 control framing、U5/U6 control v2、NRW1 `0x11`を変更しない。
- NWB1非対応peerへraw POSIX loopback wire、NCG1、plain length-prefixでsilent fallbackしない。
- old Runtimeは従来Bearerを継続利用できる。Wi-Fi設定がないdeviceはregistryへinstanceを登録しない。
- credential、peer endpoint、link policyはrevision/digest付きnamespaceへ保存し、socket/fd、
  DHCP lease、pointerはdurable化しない。

## Acceptance

1. NWB1 minimum-valid/zero-optional-fields/max KATと独立CRC32C oracle
2. 1-byte partial read/write、concatenated record、truncation、trailing、CRC/length mutation
3. per-direction sequence 0開始、exact +1、gap/duplicate/out-of-order close、
   `UINT32_MAX` emit 0、fresh-session restart
4. 2-process POSIX TCPで10,000 NFL1、backpressure、peer/process restart、24h soak
5. TLS1.3 exact suite/mTLS、両endpointが同じnon-zero session IDを導出する
   client/server-order exporter KAT、local/peer swapped-order negative、
   runtime/Attachment binding、full-handshake rotation
6. wrong peer、expired/revoked/stale credential、resumption/0-RTT attempt、session replay、
   exporter zero、auth failureでNFL1 delivery 0
7. disconnect at every header/payload byte、reconnect、same transaction/new attempt、false custody 0
8. Wi-Fi bulk中のcritical traffic fairnessとbounded memory
9. Wi-Fi断時、eligible fallbackの継続と不適格fallbackの明示拒否。
   LoRa fallback HILは別compact-radio mapping Accepted後だけ
10. ESP32-S3実AP/DHCP/TCP、強制AP断、IP変更、peer restart、sleep/wake、target metrics
11. ESP heap watermark、stack、watchdog、power/association/reconnect report
12. clean Linux/macOS example、ESP porting guide、diagnostic runbook、independent review

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

本ADRはProposed docs-onlyであり、NWB1採番、Wi-Fi/TCP/TLS実装、credential profile、
ESP target execution、HIL、security review、production supportを主張しない。

## Related

- [ADR-0017: Fabric Bearer Registry and Path Selection](0017-bearer-registry-path-selection.md)
- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [U6 Transport Custody](../26-u6-transport-custody.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
