# Capture analysis: `capture.etl` (pktmon, 2026-10-08)

Decoded with `pktmon_etl.py` and analyzed with `ue_netanalyze.py` (both in this directory).
The capture itself is not committed. This report leaves out personal identifiers that are in it
(Steam ID, public IP address, Pragma account IDs, the match join token, player display names).

## The trace

| | |
| --- | --- |
| Logger | `Relogger`, compressed mode (`LogFileMode 0x04010001`), 26 buffers / 25 LZ77-compressed (9.3 MB → 52 MB) |
| Host | Windows build **26200**, 24 logical CPUs @ 3.7 GHz, QPC clock 10 MHz |
| Time | 2026-10-08 05:35:44.6 → 05:37:33.0 UTC (packets span 104.6 s) |
| Events | 118,205 packet events (1,844 drops), 198 pktmon components |
| Wire capture | component **181**, `e2fn.sys` Intel I225-V NIC: **14,677 frames**, 5.3 MB |

Each frame was logged by up to seven components (NIC driver → netadaptercx → npcap → WFP → QoS → TCPIP).
The machine also has Npcap, Tailscale (wintun), several Hyper-V vSwitches and VMware VMnet adapters.
Teredo is active. Of the 1,844 drops, most (~1,450) are `tcpip.sys` L3/L4 discards of LAN broadcast/multicast
UDP. The rest are 130 ICMP and 176 `netadaptercx` discards (multicast, non-IP STP/LLDP/CDP frames, MLD).
**No game traffic was dropped.**

## What was running

Hostnames (from DNS answers and TLS/QUIC SNI) identify the session:

| Service | Evidence |
| --- | --- |
| **Game backend: Pragma Engine**, title *wardogs* by Bulkhead | `game.live.wardogs.bulkhead.pragmaengine.com`, `social.live.wardogs.bulkhead.pragmaengine.com` (AWS eu-west-1), `faa.bulkhead.net`, `tracks-m-wds.wardogs.com` |
| In-game voice: **Vivox** (title `wardxp`) | `wardxp.www.vivox.com`, `wardxp-mim.vivox.com` (TLS), RTP-like UDP to 85.236.102.12:54016 from T+37 s |
| Anti-cheat / player telemetry | `opm.elytra.ac` (Fastly), `deeep-storage.anybrain.gg`; the game also replicates an `AntiCheatPlayerComponent` and `AccountWatermark` |
| Epic Online Services | `api.epicgames.dev` |
| Steam | CM connection to 162.254.199.165:27018, `p2p-*.discovery.steamserver.net` |
| Region latency probes | DNS + TCP handshakes to `dynamodb.<region>.amazonaws.com` for 15 AWS regions (T+33–37 s), the usual GameLift-style ping-beacon pattern |
| Discord voice (not the game) | RTP PT 120/Opus to a Cloudflare-hosted RTC server on UDP 19327 for the whole capture. The socket was re-created at T+51.6 s, with an IP-discovery exchange |
| Other | Windows telemetry, Xbox/Game Pass catalog, Dropbox (162.125.x), Chromecast (8009) and mDNS/SSDP from other LAN devices |

## The Unreal Engine connection

`192.168.1.251:57033 ⇄ 54.115.159.171:4192/udp` (AWS EC2, in a `GLOBAL`-tagged prefix), T+30.4 s → end of capture.

**Engine / protocol**
* UE 5.x NetDriver, **not encrypted**: `NMT_Hello` carries an empty `EncryptionToken`, so there is no AES-GCM
  PacketHandler, and all 7,805 packets parse bit-exact.
* Every packet starts with the same **37-bit constant prefix** `0x4a6605d00` before `bHandshakePacket`,
  which matches a configured `StatelessConnectHandlerComponent` `MagicHeader`.
* Handshake version 4 (min 3): InitialPacket 54 B → Challenge 57 B → Response 54 B → Ack 52 B (randomized
  padding). `NetCLVersion 0x573a0e65`, `RuntimeFeatures 0x0001` (**Iris replication**).
* The server's challenge timestamp was 3091.6 s, so its net driver had been up ~51.5 minutes. Cookie-derived
  initial sequence numbers (server 12590, client 1693) match the first data packets.
* Only two channels: **Control** (ch 0) and **DataStream** (ch 2, hard-coded name 295). This fits Iris, which
  replaces actor channels with one data stream.

**Session**
| t (from handshake) | message |
| --- | --- |
| 0.050 | `NMT_Hello` little-endian, NetVersion `0x573a0e65`, no encryption token, features `0x0001` |
| 0.086 | `NMT_Challenge "C6DFF788"` |
| 0.092 | `NMT_Login` URL `?InvitedBy=<b64 Pragma id>?Token=<b64 GUID>?Name=<player>?PlatformId=<b64 SteamID64>?PlatformName=STEAM?GameDataVersions=8,5,11,8,12,34,15,5,17,8,0,2,9`; UniqueId type `Pragma` |
| 0.334 | `NMT_Welcome` map **`/Game/Maps/Worlds/Kavkazi/Kavkazi`**, game mode `/Game/GameMechanics/Gamemode/GM_Session.GM_Session_C` |
| 0.341 | `NMT_Netspeed 200000` |
| 1.736 | `NMT_Join` (≈1.4 s map load; the longest client send gap) |
| 6.986 | 3 × `NMT_IrisNetRefHandleError` (error 3) from the client |

The join token, Steam ID and account IDs travel in cleartext in the login URL. Anyone on the path (same Wi-Fi,
ISP, VPN exit) can read them and the player name.

**Network quality**
| | client → server | server → client |
| --- | --- | --- |
| packets / bytes | 3,540 / 236 kB | 4,265 / 3.12 MB |
| rate | 47.7 pkt/s (peak 64), 25 kbit/s | 57.5 pkt/s (peak 108), 337 kbit/s |
| size p50 / p95 / max | 70 / 113 / 969 B | 850 / 960 / 967 B (MaxPacket 1024) |

* Downstream bandwidth: about 600–720 kbit/s for the first ~6 s (initial world state) and again at T+13–19 s,
  then a steady 250–340 kbit/s, and about 150–170 kbit/s in the last 5 s.
* Loss: **0** of 4,265 server packets missing, reordered or duplicated. The server's ack history NAKed **5**
  client packets (0.14 %).
* Latency: handshake round trips **17.9 / 23.9 ms**. Ack-based RTT min 33.6 / p50 51.8 / p95 65 ms. That figure
  includes the wait for the server's next ~33 ms tick, so it overstates network latency.
* Server tick: reported frame time p50 **33 ms (≈30 Hz)**, p95 39 ms. Three frames ran over 50 ms: 56 ms (T+1.8 s),
  **213 ms (T+34.6 s)** and 74 ms (T+44.4 s).

**What the replicated data shows about the game** (strings in Iris exports)
* C++ modules: `WDGame`, `BHMover` (Mover 2.0), `NetworkPrediction`, `BHInventory`, `BHGameplayEffects`,
  `BHNetworkPersistence`, `BHMotionWarping`, `BuildablesRuntime`, `ControlZoneRuntime`, `HotZoneMagnetRuntime`,
  `MonkeyScoreRuntime`, `SpottingRuntime`, `SkinsInSessionRuntime`, `Crosstalk`, `Mechanized`.
* World: World Partition map *Kavkazi* (Caucasus setting; data layers `DL_BaghiSpawn`, `DL_ChutaSpawn`,
  `DL_KhevuliSpawn`, `DL_Bakurani`, `DL_Destruction`). The client reported 88 streamed `_Generated_` cells.
  The server replicated thousands of destructible objects (2,295 single and 782 double apartment windows,
  doors, houses, bungalows).
* Gameplay: three factions (`Meta_Alignment_Faction_Alpha/Bravo/Charlie`), squads, control zones / King-of-the-Hill
  (`Challenges_KOTH`, `Status_KOTH`), hot zones, persistent FOBs (`Lonestar`, `Manticore`, `Valkyra`) and
  base building (Hesco/H-block walls, Bremmer walls, bunkers, crow's nests, air-raid shelters, barbed wire, gates,
  repair station, radio, loudspeaker, mortar pit, Mistral AA). There are also vendors (equipment, garage, vehicle),
  an economy and investments, and supply crates/pallets.
* Equipment: Mosin, shotgun, "Judge" pistol, launcher, combat bow, machine gun, C4, IED, claymore, AT and land
  mines, explosive vest, smoke grenade, med kit, stim pen, bandages, binoculars, monocular, rangefinder,
  spotter scope, crowbar, large hammer.
* Vehicles: wheeled pickups with ring turret / minigun, tracked tank `TNK_01`, `SPW`, rotary-wing vehicle,
  drone (`STN_05`), plus A-10 / Su-30 fly-overs; the vehicle Hi-Fi has tapes (`MusicTape`).
* Season 1 skins and emotes, plus a `Taxi` skin set.

## Reproduce

```sh
python3 tools/pktmon/pktmon_etl.py capture.etl --info
python3 tools/pktmon/pktmon_etl.py capture.etl -c 181 -o nic.pcapng
python3 tools/pktmon/ue_netanalyze.py capture.etl --json ue_report.json
```
