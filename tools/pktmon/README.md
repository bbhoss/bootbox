# pktmon ETL decoder + Unreal Engine traffic analyzer

Two standalone, standard-library-only Python 3 tools:

| file | what it does |
| --- | --- |
| `pktmon_etl.py` | Reads a Windows **Packet Monitor** (`pktmon start --capture`) `.etl` file on any OS and writes **pcapng**, a per-packet text dump, or a component/drop summary. |
| `ue_netanalyze.py` | Finds and dissects **Unreal Engine** `UNetConnection` UDP traffic in a `.etl`, `.pcapng` or `.pcap`: stateless handshake, packet headers, loss/RTT/tick rate, channels, control messages, replicated asset names. |
| `test_pktmon_tools.py` | Unit tests (synthetic ETL files and bit-exact UE packets). |

```sh
# trace + component overview (NICs, filters, IPs/MACs per component, drop counters)
python3 pktmon_etl.py capture.etl --info

# pcapng for Wireshark: everything, or only what one component saw
python3 pktmon_etl.py capture.etl -o all.pcapng
python3 pktmon_etl.py capture.etl -c 181 -o nic.pcapng          # one copy of each frame
python3 pktmon_etl.py capture.etl --dedup --no-drops -o dedup.pcapng
python3 pktmon_etl.py capture.etl --drop-only --text              # what Windows dropped, and where

# Unreal Engine analysis (auto-detects UE flows; secrets redacted unless --no-redact)
python3 ue_netanalyze.py capture.etl --json report.json
python3 ue_netanalyze.py game.pcapng --server 1.2.3.4:7777

python3 -m unittest -v test_pktmon_tools.py
```

## pktmon ETL format notes

* An ETL file is a sequence of buffers, each with a 0x48-byte `WMI_BUFFER_HEADER`.
  The first buffer holds the `TRACE_LOGFILE_HEADER` (build, CPU count, clock type,
  QPC frequency, start/end time).
* Relogged or `EVENT_TRACE_COMPRESSED_MODE` files set `BufferFlag & 0x40` on data
  buffers. Their payload is **MS-XCA plain LZ77** ("LZXPRESS"). `BufferSize` is then
  the compressed size, and `Offset` is the decompressed size including the header.
  Buffers are written per CPU, so events are re-sorted by timestamp.
* Event records are 8-byte aligned `EVENT_HEADER`/`EVENT_TRACE_HEADER`/system
  records. QPC timestamps are converted with the log file `StartTime` and the header
  event's QPC value.
* `Microsoft-Windows-PktMon` `{4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC}` events.
  These layouts were worked out from real captures; Microsoft does not document them.

| id | meaning | user data |
| --- | --- | --- |
| 20 | component info | `u16 ComponentId, u16 Type, wstr Name, wstr Description` |
| 30/40/65/66/70/73/75 | component property | `u16 ComponentId, u16 PropertyId` + u32 / GUID / IPv4 / IPv6 / `u32 len`+bytes (MAC) / wstr / u16 |
| 90 | edge info | `u16 ComponentId, wstr Name, u16 EdgeId, ...` |
| 160 | packet fragment | `u64 PktGroupId, u16 PktNumber, u16 AppearanceCount, u16 DirTag, u16 PacketType, u16 ComponentId, u16 EdgeId, u16 FilterId, u32 DropReason, u32 DropLocation, u16 OriginalSize, u16 LoggedSize, payload` |
| 170 | dropped packet | same layout as 160 |

`DirTag` 3 = Rx, 4 = Tx (1/2 on older builds). `PacketType` 1 = Ethernet, 3 = raw IP.
pktmon logs a frame once **per component it crosses** (NIC driver, NDIS filters such
as npcap/WFP/QoS, TCPIP, …). `PktGroupId` is unique per log record, so it can't be
used to group copies. Pick one component with `-c`, or use the content-based `--dedup`.

## Unreal Engine dissection notes (UE 5.x layout)

* Optional constant `MagicHeader` bits (auto-detected), then `bHandshakePacket`.
* Handshake (`StatelessConnectHandlerComponent`, handshake version ≥ 2): `bRestart, MinVersion, CurVersion,
  PacketType, SentCount, u32 NetCLVersion, u16 RuntimeFeatures, SecretId, double Timestamp, 20-byte Cookie`,
  then random padding. Initial sequence numbers come from cookie bytes 0–1 (server) and 2–3 (client).
* Data packets: `u32 (Seq<<18 | AckedSeq<<4 | HistoryWords-1)`, history words,
  `bHasPacketInfo [JitterClock:10, bHasServerFrameTime, u8 FrameTimeMs(server only)]`, then bunches
  (`bControl [bOpen bClose [CloseReason]] bPaused bReliable ChIndex(packed) bExports bMustMap bPartial
  [ChSeq:10] [bPartialInitial bPartialFinal] [ChName] BunchBits(ReadInt(MaxPacket*8)) data`).
  The packet ends with the connection's termination bit, followed by the PacketHandler's own.
* Every packet is checked: the bunch walk has to land exactly on the termination bit,
  so a wrong layout assumption shows up as `unparsed` packets rather than bad data.
* Control messages decoded: Hello, Challenge, Login (URL options, base64-decoded),
  Welcome, Netspeed, Join, Failure, NetPing, Iris errors. Iris `DataStream` payloads are not decoded field
  by field. Instead, length-prefixed strings (asset paths, class, component and data-layer names) are pulled out
  at every bit alignment.
* Not handled: encrypted connections (`AESGCMHandlerComponent` / non-empty `EncryptionToken`), Oodle-compressed
  packets, and UE4 engine-version differences (e.g. `MaxPacket` 512, no packet info).
