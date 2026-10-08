#!/usr/bin/env python3
"""
pktmon_etl.py - decode Windows Packet Monitor (pktmon) .etl captures anywhere.

`pktmon start --capture` writes an ETW trace (.etl). Windows can convert it with
`pktmon etl2pcap`, but that needs a Windows box. This tool reads the ETL file
directly (pure Python, standard library only) and can:

  * print trace / component information             (--info)
  * print one line per packet, like `pktmon etl2txt` (--text)
  * write a pcapng file for Wireshark/tshark         (-o out.pcapng)

Supported input:
  * plain ETL files written by pktmon / any ETW real-time-to-file session
  * ETL files written in EVENT_TRACE_COMPRESSED_MODE (e.g. relogged files,
    `BufferFlag & 0x40`), whose buffers are MS-XCA "plain LZ77" compressed

Format notes (ETW on-disk layout):
  file   := WMI_BUFFER_HEADER-prefixed buffers, back to back
  buffer := 0x48 byte header, then 8-byte aligned event records
  record := one of SYSTEM/COMPACT/PERFINFO/FULL/INSTANCE/EVENT_HEADER records;
            the high byte of the first ULONG is the marker 0xC0 and the
            byte before it is the header type.

The Microsoft-Windows-PktMon provider ({4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC})
event layouts below were derived from real pktmon captures; event ids
160 (PacketFragment) and 170 (PacketMetadata / dropped packet) carry frames.
"""

import argparse
import collections
import signal
import struct
import sys
import uuid

PKTMON_PROVIDER = uuid.UUID('4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac')

BUFFER_HEADER_SIZE = 0x48
BUFFER_FLAG_COMPRESSED = 0x40

# TRACE_HEADER_TYPE_* values (high byte marker 0xC0 follows)
HT_SYSTEM32, HT_SYSTEM64 = 1, 2
HT_COMPACT32, HT_COMPACT64 = 3, 4
HT_FULL32, HT_INSTANCE32 = 10, 11
HT_PERFINFO32, HT_PERFINFO64 = 16, 17
HT_EVENT32, HT_EVENT64 = 18, 19
HT_FULL64, HT_INSTANCE64 = 20, 21
SIZE_AT_4 = {HT_SYSTEM32, HT_SYSTEM64, HT_COMPACT32, HT_COMPACT64, HT_PERFINFO32, HT_PERFINFO64}
HEADER_LEN = {
    HT_SYSTEM32: 0x20, HT_SYSTEM64: 0x20,
    HT_COMPACT32: 0x18, HT_COMPACT64: 0x18,
    HT_PERFINFO32: 0x10, HT_PERFINFO64: 0x10,
    HT_FULL32: 0x30, HT_FULL64: 0x30,
    HT_INSTANCE32: 0x48, HT_INSTANCE64: 0x48,
    HT_EVENT32: 0x50, HT_EVENT64: 0x50,
}

# PktMon event ids
EV_COMPONENT_INFO = 20
EV_PROP_UINT32 = 30
EV_PROP_GUID = 40
EV_PROP_IPV4 = 65
EV_PROP_IPV6 = 66
EV_PROP_BINARY = 70      # MAC addresses (ULONG length + bytes)
EV_PROP_STRING = 73      # e.g. vSwitch name
EV_PROP_UINT16 = 75      # e.g. EtherType
EV_PROP_COUNTERS = 80
EV_EDGE_INFO = 90
EV_PACKET_FRAGMENT = 160
EV_PACKET_DROP = 170

DIRECTION = {1: 'Rx', 2: 'Tx', 3: 'Rx', 4: 'Tx'}   # 3/4 seen on 2004+ builds
PACKET_TYPE_LINKTYPE = {1: 1, 3: 101}            # Ethernet, raw IP
PACKET_TYPE_NAME = {0: 'Unknown', 1: 'Ethernet', 2: 'WiFi', 3: 'IP', 4: 'HTTP'}
COMPONENT_TYPE_NAME = {
    2: 'Miniport', 3: 'Filter', 4: 'Protocol', 6: 'vSwitch port', 7: 'vSwitch',
    10: 'HTTP', 11: 'TCPIP L3/L4', 13: 'IPsec', 14: 'NetAdapterCx client', 15: 'HTTP message',
}

FILETIME_UNIX_EPOCH = 116444736000000000


class EtlError(Exception):
    pass


# --------------------------------------------------------------------------
# MS-XCA plain LZ77 ("LZXPRESS") decompression, [MS-XCA] section 2.4
# --------------------------------------------------------------------------

def lz77_decompress(src):
    out = bytearray()
    n = len(src)
    ip = 0
    flags = 0
    nflags = 0
    half = 0           # position of the shared length nibble byte, 0 = none
    while True:
        if nflags == 0:
            if ip + 4 > n:
                break
            flags = src[ip] | (src[ip + 1] << 8) | (src[ip + 2] << 16) | (src[ip + 3] << 24)
            ip += 4
            nflags = 32
        nflags -= 1
        if not (flags >> nflags) & 1:
            if ip >= n:
                break
            out.append(src[ip])
            ip += 1
            continue
        if ip + 2 > n:
            break
        token = src[ip] | (src[ip + 1] << 8)
        ip += 2
        length = token & 7
        offset = (token >> 3) + 1
        if length == 7:
            if half == 0:
                length = src[ip] & 0x0F
                half = ip
                ip += 1
            else:
                length = src[half] >> 4
                half = 0
            if length == 15:
                length = src[ip]
                ip += 1
                if length == 255:
                    length = src[ip] | (src[ip + 1] << 8)
                    ip += 2
                    if length == 0:
                        length = struct.unpack_from('<I', src, ip)[0]
                        ip += 4
                    if length < 15 + 7:
                        raise EtlError('corrupt LZ77 stream (bad extended length)')
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3
        start = len(out) - offset
        if start < 0:
            raise EtlError('corrupt LZ77 stream (offset before start of output)')
        if offset >= length:
            out += out[start:start + length]
        else:
            # overlapping copy: repeat the period
            chunk = out[start:]
            reps, rem = divmod(length, offset)
            out += chunk * reps + chunk[:rem]
    return bytes(out)


# --------------------------------------------------------------------------
# ETL container
# --------------------------------------------------------------------------

class Buffer:
    __slots__ = ('file_offset', 'size', 'saved_offset', 'offset', 'flags', 'type',
                 'sequence', 'processor', 'logger_id', 'timestamp', 'data')


def iter_buffers(raw):
    pos = 0
    while pos + BUFFER_HEADER_SIZE <= len(raw):
        (size, saved, _cur, _ref, ts, seq, _clock, ctx, _state, offset,
         bflags, btype) = struct.unpack_from('<IIIiqqQIIIHH', raw, pos)
        if size == 0 or size == 0xFFFFFFFF:
            break
        if pos + size > len(raw):
            raise EtlError('buffer at %#x runs past end of file' % pos)
        b = Buffer()
        b.file_offset, b.size, b.saved_offset, b.offset = pos, size, saved, offset
        b.flags, b.type, b.sequence, b.timestamp = bflags, btype, seq, ts
        b.processor, b.logger_id = ctx & 0xFFFF, ctx >> 16
        used = offset if 0 < offset <= max(size, saved) else saved
        if bflags & BUFFER_FLAG_COMPRESSED:
            b.data = lz77_decompress(raw[pos + BUFFER_HEADER_SIZE:pos + size])
            if used and len(b.data) != used - BUFFER_HEADER_SIZE:
                raise EtlError('buffer at %#x: decompressed %d bytes, expected %d'
                               % (pos, len(b.data), used - BUFFER_HEADER_SIZE))
        else:
            b.data = raw[pos + BUFFER_HEADER_SIZE:pos + min(used or size, size)]
        yield b
        pos += size


class Event:
    __slots__ = ('header_type', 'timestamp', 'provider', 'event_id', 'version', 'opcode',
                 'level', 'keyword', 'task', 'thread_id', 'process_id', 'processor',
                 'flags', 'raw', 'user_data')


def _parse_extended(rec, pos, end):
    """Skip EVENT_HEADER_EXTENDED_DATA_ITEMs; returns offset of user data."""
    while pos + 8 <= end:
        _reserved1, _ext_type, linkage, data_size = struct.unpack_from('<HHHH', rec, pos)
        pos += (8 + data_size + 7) & ~7
        if not linkage & 1:
            break
    return min(pos, end)


def iter_events(buffer):
    data = buffer.data
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        marker = data[pos + 3]
        htype = data[pos + 2]
        if marker & 0xC0 != 0xC0:
            # 0xFFFFFFFF padding or garbage -> end of this buffer
            break
        size = struct.unpack_from('<H', data, pos + (4 if htype in SIZE_AT_4 else 0))[0]
        if size < 8 or pos + size > n:
            break
        rec = data[pos:pos + size]
        ev = Event()
        ev.header_type = htype
        ev.raw = rec
        ev.processor = buffer.processor
        ev.provider = None
        ev.event_id = ev.version = ev.opcode = ev.level = ev.task = 0
        ev.keyword = ev.flags = 0
        ev.thread_id = ev.process_id = 0
        hl = HEADER_LEN.get(htype, 8)
        if htype in (HT_EVENT32, HT_EVENT64):
            (ev.flags, _prop, ev.thread_id, ev.process_id, ev.timestamp) = struct.unpack_from('<HHIIq', rec, 4)
            ev.provider = uuid.UUID(bytes_le=bytes(rec[0x18:0x28]))
            (ev.event_id, ev.version, _ch, ev.level, ev.opcode, ev.task,
             ev.keyword) = struct.unpack_from('<HBBBBHQ', rec, 0x28)
            ud = hl
            if ev.flags & 0x0001:   # EVENT_HEADER_FLAG_EXTENDED_INFO
                ud = _parse_extended(rec, hl, size)
            ev.user_data = rec[ud:]
        elif htype in (HT_FULL32, HT_FULL64, HT_INSTANCE32, HT_INSTANCE64):
            ev.opcode = rec[4]
            ev.level = rec[5]
            ev.version = struct.unpack_from('<H', rec, 6)[0]
            ev.thread_id, ev.process_id, ev.timestamp = struct.unpack_from('<IIq', rec, 8)
            ev.provider = uuid.UUID(bytes_le=bytes(rec[0x18:0x28]))
            ev.user_data = rec[hl:]
        elif htype in (HT_SYSTEM32, HT_SYSTEM64):
            ev.version = struct.unpack_from('<H', rec, 0)[0]
            ev.event_id = struct.unpack_from('<H', rec, 6)[0]    # HookId
            ev.thread_id, ev.process_id, ev.timestamp = struct.unpack_from('<IIq', rec, 8)
            ev.user_data = rec[hl:]
        elif htype in (HT_COMPACT32, HT_COMPACT64):
            ev.event_id = struct.unpack_from('<H', rec, 6)[0]
            ev.thread_id, ev.process_id, ev.timestamp = struct.unpack_from('<IIq', rec, 8)
            ev.user_data = rec[hl:]
        elif htype in (HT_PERFINFO32, HT_PERFINFO64):
            ev.event_id = struct.unpack_from('<H', rec, 6)[0]
            ev.timestamp = struct.unpack_from('<q', rec, 8)[0]
            ev.user_data = rec[hl:]
        else:
            ev.timestamp = 0
            ev.user_data = rec[8:]
        yield ev
        pos += (size + 7) & ~7


class LogfileHeader:
    """TRACE_LOGFILE_HEADER carried by the first event of the first buffer."""

    def __init__(self, ev):
        d = ev.user_data
        self.header_qpc = ev.timestamp
        (self.buffer_size, ver, self.provider_version, self.num_processors,
         self.end_time, self.timer_resolution, self.max_file_size, self.log_file_mode,
         self.buffers_written, self.start_buffers, self.pointer_size, self.events_lost,
         self.cpu_mhz) = struct.unpack_from('<IIIIqIIIIIIII', d, 0)
        self.version = (ver & 0xFF, (ver >> 8) & 0xFF, (ver >> 16) & 0xFF, ver >> 24)
        ptr = self.pointer_size if self.pointer_size in (4, 8) else 8
        tz = 0x38 + 2 * ptr                      # after LoggerName/LogFileName pointers
        tail = (tz + 172 + 7) & ~7               # TIME_ZONE_INFORMATION, 8-aligned
        (self.boot_time, self.perf_freq, self.start_time, self.clock_type,
         self.buffers_lost) = struct.unpack_from('<qqqII', d, tail)
        strings = d[tail + 32:].decode('utf-16le', 'replace').split('\x00')
        self.logger_name = strings[0] if strings else ''
        self.log_file_name = strings[1] if len(strings) > 1 else ''
        self.build = self.provider_version & 0xFFFF

    def to_filetime(self, ts):
        """Convert an event timestamp to FILETIME (100 ns since 1601)."""
        if self.clock_type == 2:                 # system time
            return ts
        freq = self.perf_freq or 10000000
        if self.clock_type == 3:                 # CPU cycle counter
            freq = (self.cpu_mhz or 1) * 1000000
        return self.start_time + (ts - self.header_qpc) * 10000000 // freq


# --------------------------------------------------------------------------
# PktMon decoding
# --------------------------------------------------------------------------

def _wstr(b, pos):
    end = pos
    while end + 1 < len(b) and (b[end] or b[end + 1]):
        end += 2
    return b[pos:end].decode('utf-16le', 'replace'), end + 2


class Component:
    def __init__(self, cid):
        self.id = cid
        self.type = None
        self.name = ''
        self.description = ''
        self.props = collections.OrderedDict()
        self.edges = {}

    @property
    def label(self):
        return '%s%s' % (self.description or self.name or 'component',
                         ' (%s)' % self.name if self.name and self.description else '')


class Packet:
    __slots__ = ('timestamp', 'filetime', 'group_id', 'pkt_number', 'appearance', 'direction',
                 'packet_type', 'component', 'edge', 'filter_id', 'drop_reason', 'drop_location',
                 'original_size', 'data', 'is_drop', 'processor')

    @property
    def dir_name(self):
        return DIRECTION.get(self.direction, 'Dir%d' % self.direction)


class PktmonTrace:
    def __init__(self, path_or_bytes):
        raw = path_or_bytes
        if not isinstance(raw, (bytes, bytearray)):
            with open(path_or_bytes, 'rb') as f:
                raw = f.read()
        self.header = None
        self.components = {}
        self.packets = []
        self.event_counts = collections.Counter()
        self.buffers = 0
        self.compressed_buffers = 0
        for buf in iter_buffers(raw):
            self.buffers += 1
            if buf.flags & BUFFER_FLAG_COMPRESSED:
                self.compressed_buffers += 1
            for ev in iter_events(buf):
                if self.header is None and ev.header_type in (HT_SYSTEM32, HT_SYSTEM64) and ev.event_id == 0:
                    self.header = LogfileHeader(ev)
                    continue
                if ev.provider != PKTMON_PROVIDER:
                    self.event_counts[('other', str(ev.provider), ev.event_id)] += 1
                    continue
                self.event_counts[('pktmon', ev.event_id)] += 1
                self._handle(ev)
        if self.header is None:
            raise EtlError('no TRACE_LOGFILE_HEADER found - not an ETL file?')
        self.packets.sort(key=lambda p: (p.timestamp, p.group_id))
        for p in self.packets:
            p.filetime = self.header.to_filetime(p.timestamp)

    def component(self, cid):
        c = self.components.get(cid)
        if c is None:
            c = self.components[cid] = Component(cid)
        return c

    def _handle(self, ev):
        d = ev.user_data
        eid = ev.event_id
        if eid in (EV_PACKET_FRAGMENT, EV_PACKET_DROP):
            if len(d) < 34:
                return
            p = Packet()
            (p.group_id, p.pkt_number, p.appearance, p.direction, p.packet_type, p.component,
             p.edge, p.filter_id, p.drop_reason, p.drop_location, p.original_size,
             logged) = struct.unpack_from('<QHHHHHHHIIHH', d, 0)
            p.data = bytes(d[34:34 + logged])
            p.is_drop = eid == EV_PACKET_DROP
            p.timestamp = ev.timestamp
            p.processor = ev.processor
            self.packets.append(p)
        elif eid == EV_COMPONENT_INFO and len(d) >= 4:
            cid, ctype = struct.unpack_from('<HH', d, 0)
            c = self.component(cid)
            c.type = ctype
            c.name, pos = _wstr(d, 4)
            c.description, _ = _wstr(d, pos)
        elif eid == EV_EDGE_INFO and len(d) >= 4:
            cid = struct.unpack_from('<H', d, 0)[0]
            name, pos = _wstr(d, 2)
            edge = struct.unpack_from('<H', d, pos)[0] if pos + 2 <= len(d) else 0
            self.component(cid).edges[edge] = name
        elif len(d) >= 4 and eid in (EV_PROP_UINT32, EV_PROP_GUID, EV_PROP_IPV4, EV_PROP_IPV6,
                                     EV_PROP_BINARY, EV_PROP_STRING, EV_PROP_UINT16, EV_PROP_COUNTERS):
            cid, prop = struct.unpack_from('<HH', d, 0)
            v = d[4:]
            if eid == EV_PROP_UINT32:
                val = ('uint32', struct.unpack_from('<I', v)[0])
            elif eid == EV_PROP_UINT16:
                val = ('uint16', '0x%04x' % struct.unpack_from('<H', v)[0])
            elif eid == EV_PROP_GUID:
                val = ('guid', str(uuid.UUID(bytes_le=bytes(v[:16]))))
            elif eid == EV_PROP_IPV4:
                val = ('ipv4', '.'.join(str(x) for x in v[:4]))
            elif eid == EV_PROP_IPV6:
                val = ('ipv6', fmt_ipv6(v[:16]))
            elif eid == EV_PROP_BINARY:
                ln = struct.unpack_from('<I', v)[0]
                blob = bytes(v[4:4 + ln])
                val = ('mac', ':'.join('%02x' % x for x in blob)) if ln == 6 else ('binary', blob.hex())
            elif eid == EV_PROP_STRING:
                val = ('string', _wstr(v, 0)[0])
            else:
                val = ('raw', bytes(v).hex())
            self.component(cid).props.setdefault(prop, []).append(val)


def fmt_ipv6(b):
    words = struct.unpack('>8H', bytes(b))
    # longest run of zero words -> '::'
    best, cur = (0, 0), None
    for i, w in enumerate(words + (1,)):
        if w == 0 and cur is None:
            cur = i
        elif w != 0 and cur is not None:
            if i - cur > best[1] - best[0]:
                best = (cur, i)
            cur = None
    if best[1] - best[0] > 1:
        left = ':'.join('%x' % w for w in words[:best[0]])
        right = ':'.join('%x' % w for w in words[best[1]:])
        return left + '::' + right
    return ':'.join('%x' % w for w in words)


# --------------------------------------------------------------------------
# Minimal L2-L4 summariser (for --text)
# --------------------------------------------------------------------------

def summarize(data, packet_type):
    try:
        if packet_type == 1:
            if len(data) < 14:
                return 'short ethernet frame'
            etype = struct.unpack_from('>H', data, 12)[0]
            off = 14
            if etype == 0x8100 and len(data) >= 18:
                etype = struct.unpack_from('>H', data, 16)[0]
                off = 18
            l3 = data[off:]
            if etype == 0x0806:
                return 'ARP'
            if etype not in (0x0800, 0x86DD):
                return 'ethertype 0x%04x' % etype
        else:
            l3 = data
        ver = l3[0] >> 4
        if ver == 4:
            ihl = (l3[0] & 15) * 4
            proto = l3[9]
            src, dst = '.'.join(map(str, l3[12:16])), '.'.join(map(str, l3[16:20]))
            l4 = l3[ihl:]
        elif ver == 6:
            proto = l3[6]
            src, dst = fmt_ipv6(l3[8:24]), fmt_ipv6(l3[24:40])
            l4 = l3[40:]
            while proto in (0, 43, 60) and len(l4) >= 8:     # hop-by-hop, routing, dest opts
                proto, l4 = l4[0], l4[(l4[1] + 1) * 8:]
            if proto == 58 and l4:
                return 'ICMPv6 type %d %s > %s' % (l4[0], src, dst)
        else:
            return 'non-IP payload'
        if proto in (6, 17) and len(l4) >= 4:
            sp, dp = struct.unpack_from('>HH', l4, 0)
            if proto == 6:
                fl = l4[13] if len(l4) > 13 else 0
                names = ''.join(c for c, bit in zip('FSRPAU', (1, 2, 4, 8, 16, 32)) if fl & bit)
                hl = (l4[12] >> 4) * 4 if len(l4) > 12 else 20
                return 'TCP %s:%d > %s:%d [%s] len=%d' % (src, sp, dst, dp, names, max(0, len(l4) - hl))
            return 'UDP %s:%d > %s:%d len=%d' % (src, sp, dst, dp, struct.unpack_from('>H', l4, 4)[0] - 8)
        if proto == 1 and l4:
            return 'ICMP type %d %s > %s' % (l4[0], src, dst)
        return 'IP proto %d %s > %s' % (proto, src, dst)
    except IndexError:
        return 'truncated'


# --------------------------------------------------------------------------
# pcapng writer
# --------------------------------------------------------------------------

def _opt(code, value):
    pad = (-len(value)) % 4
    return struct.pack('<HH', code, len(value)) + value + b'\x00' * pad


def _block(btype, body):
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


def write_pcapng(trace, packets, out, comments=True):
    shb_opts = _opt(4, b'pktmon_etl.py') + _opt(0, b'')
    if trace.header:
        shb_opts = _opt(3, ('Windows build %d' % trace.header.build).encode()) + shb_opts
    out.write(_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) + shb_opts))
    ifaces = {}
    for p in packets:
        key = (p.component, PACKET_TYPE_LINKTYPE.get(p.packet_type, 1))
        if key not in ifaces:
            ifaces[key] = len(ifaces)
            comp = trace.components.get(p.component)
            name = ('pktmon:%d' % p.component).encode()
            desc = (comp.label if comp else 'component %d' % p.component).encode('utf-8')
            opts = _opt(2, name) + _opt(3, desc) + _opt(9, b'\x07') + _opt(0, b'')
            out.write(_block(1, struct.pack('<HHI', key[1], 0, 0) + opts))
        ts = p.filetime - FILETIME_UNIX_EPOCH       # 100 ns ticks since 1970
        data = p.data
        pad = (-len(data)) % 4
        opts = b''
        flags = {'Rx': 1, 'Tx': 2}.get(p.dir_name, 0)
        if flags:
            opts += _opt(2, struct.pack('<I', flags))
        if comments:
            c = 'PktGroupId %d, PktNumber %d, Appearance %d, Direction %s, Type %s, Component %d, Edge %d' % (
                p.group_id, p.pkt_number, p.appearance, p.dir_name,
                PACKET_TYPE_NAME.get(p.packet_type, p.packet_type), p.component, p.edge)
            if p.is_drop:
                c += ', Drop: reason %d, location 0x%08x' % (p.drop_reason, p.drop_location)
            opts += _opt(1, c.encode())
        if opts:
            opts += _opt(0, b'')
        body = struct.pack('<IIIII', ifaces[(p.component, PACKET_TYPE_LINKTYPE.get(p.packet_type, 1))],
                           (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF, len(data),
                           max(p.original_size, len(data))) + data + b'\x00' * pad + opts
        out.write(_block(6, body))
    return len(ifaces)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def filetime_str(ft):
    import datetime
    t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    return t.strftime('%Y-%m-%d %H:%M:%S.') + '%07d' % (ft % 10000000) + 'Z'


def select_packets(trace, args):
    pk = trace.packets
    if args.component:
        wanted = set(args.component)
        pk = [p for p in pk if p.component in wanted]
    if args.drop_only:
        pk = [p for p in pk if p.is_drop]
    elif args.no_drops:
        pk = [p for p in pk if not p.is_drop]
    if args.dedup:
        # The same frame is logged once per component it crosses. Keep the
        # first copy of each (direction, bytes) seen within the window.
        window = int(args.dedup_window * 1e7)
        seen = {}
        res = []
        for p in pk:
            key = (p.dir_name, p.data)
            last = seen.get(key)
            seen[key] = p.timestamp
            if last is not None and p.timestamp - last <= window:
                continue
            res.append(p)
        pk = res
    return pk


def print_info(trace):
    h = trace.header
    print('Logger            : %s  (%s)' % (h.logger_name, h.log_file_name))
    print('Windows build     : %d   ETW version %d.%d.%d.%d   CPUs %d @ %d MHz' % (
        h.build, *h.version, h.num_processors, h.cpu_mhz))
    print('Log file mode     : 0x%08x%s' % (h.log_file_mode, '  (compressed)' if h.log_file_mode & 0x04000000 else ''))
    print('Clock             : %s, freq %d Hz' % ({1: 'QPC', 2: 'system time', 3: 'CPU cycles'}.get(h.clock_type, h.clock_type), h.perf_freq))
    print('Start / end (UTC) : %s  /  %s' % (filetime_str(h.start_time), filetime_str(h.end_time)))
    print('Buffers           : %d (%d compressed), events lost %d, buffers lost %d' % (
        trace.buffers, trace.compressed_buffers, h.events_lost, h.buffers_lost))
    if trace.packets:
        span = (trace.packets[-1].filetime - trace.packets[0].filetime) / 1e7
        print('Packets           : %d (%d drops) over %.3f s' % (
            len(trace.packets), sum(p.is_drop for p in trace.packets), span))
    print()
    per_comp = collections.Counter(p.component for p in trace.packets)
    print('%5s %-20s %-8s %s' % ('Id', 'Type', 'Packets', 'Component'))
    for cid in sorted(trace.components):
        c = trace.components[cid]
        props = []
        for prop, vals in c.props.items():
            for kind, v in vals:
                if kind in ('ipv4', 'ipv6', 'mac', 'string'):
                    props.append(str(v))
        print('%5d %-20s %-8s %s%s' % (
            cid, COMPONENT_TYPE_NAME.get(c.type, c.type), per_comp.get(cid, ''), c.label,
            ('  [' + ', '.join(props) + ']') if props else ''))
    print()
    drops = collections.Counter((p.component, p.drop_reason, p.drop_location) for p in trace.packets if p.is_drop)
    if drops:
        print('Drops (component, reason, location): count')
        for (cid, r, loc), n in drops.most_common():
            print('  %4d  reason %-5d location 0x%08x : %d' % (cid, r, loc, n))


def main(argv=None):
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser(description='Decode a Windows pktmon .etl capture (no Windows needed).')
    ap.add_argument('etl')
    ap.add_argument('-o', '--pcapng', help='write packets to this pcapng file')
    ap.add_argument('--info', action='store_true', help='print trace and component information')
    ap.add_argument('--text', action='store_true', help='print one line per packet')
    ap.add_argument('-c', '--component', type=int, action='append',
                    help='only packets logged by this component id (repeatable)')
    ap.add_argument('--drop-only', action='store_true', help='only dropped packets')
    ap.add_argument('--no-drops', action='store_true', help='exclude dropped packets')
    ap.add_argument('--dedup', action='store_true',
                    help='drop repeat copies of the same frame logged by several components')
    ap.add_argument('--dedup-window', type=float, default=0.05, metavar='SEC')
    ap.add_argument('--no-comments', action='store_true', help='omit per-packet pcapng comments')
    args = ap.parse_args(argv)

    trace = PktmonTrace(args.etl)
    if args.info or not (args.pcapng or args.text):
        print_info(trace)
    pk = select_packets(trace, args)
    if args.text:
        for i, p in enumerate(pk, 1):
            print('%6d %s %-4d %-2s %s%s' % (
                i, filetime_str(p.filetime)[11:], p.component, p.dir_name,
                summarize(p.data, p.packet_type), '  DROP %d' % p.drop_reason if p.is_drop else ''))
    if args.pcapng:
        with open(args.pcapng, 'wb') as f:
            nif = write_pcapng(trace, pk, f, comments=not args.no_comments)
        print('wrote %d packets on %d interfaces to %s' % (len(pk), nif, args.pcapng), file=sys.stderr)


if __name__ == '__main__':
    main()
