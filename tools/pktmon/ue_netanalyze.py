#!/usr/bin/env python3
"""
ue_netanalyze.py - dissect Unreal Engine (UE4/UE5) UNetConnection traffic.

Input: a pktmon .etl (decoded with pktmon_etl.py), or a .pcap/.pcapng file.

For every UDP flow that looks like UE NetDriver traffic it reports:
  * StatelessConnectHandlerComponent handshake (UE5 handshake versions,
    NetCL version, runtime features, server timestamp, cookie-derived
    initial sequence numbers)
  * packet header statistics: sequence/ack, loss in both directions
    (from FNetPacketNotify ack history), RTT, server frame time, send rates
  * channels and bunches (Control / Actor / Voice / Iris DataStream ...)
  * decoded control channel messages (NMT_Hello, Login, Welcome, ...)
  * asset / class / module paths replicated in clear text

The bit-level layout implemented here is that of UE 5.x (handshake version
>= 2, jitter clock in the packet info, packed channel index, channel names).
Each packet is validated by requiring the bunch walk to end exactly on the
termination bit, so a wrong guess shows up as parse failures, not garbage.

Secrets (join tokens, platform ids, encryption tokens) are redacted unless
--no-redact is given.
"""

import argparse
import base64
import collections
import json
import os
import re
import signal
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

NMT = {
    0: 'Hello', 1: 'Welcome', 2: 'Upgrade', 3: 'Challenge', 4: 'Netspeed', 5: 'Login',
    6: 'Failure', 9: 'Join', 10: 'JoinSplit', 12: 'Skip', 13: 'Abort', 15: 'PCSwap',
    16: 'ActorChannelFailure', 17: 'DebugText', 18: 'NetGUIDAssign', 19: 'SecurityViolation',
    20: 'GameSpecific', 21: 'EncryptionAck', 22: 'DestructionInfo', 23: 'CloseReason',
    24: 'NetPing', 25: 'BeaconWelcome', 26: 'BeaconJoin', 27: 'BeaconAssignGUID',
    28: 'BeaconNetGUIDAck', 29: 'IrisProtocolMismatch', 30: 'IrisNetRefHandleError',
    31: 'IrisNetRefHandleErrorAck',
}
# hard-coded EName indices used for channel names
HARDCODED_NAMES = {102: 'Actor', 255: 'Control', 256: 'Voice', 295: 'DataStream'}
HANDSHAKE_TYPES = {0: 'InitialPacket', 1: 'Challenge', 2: 'Response', 3: 'Ack',
                   4: 'RestartHandshake', 5: 'RestartResponse', 6: 'VersionUpgrade'}
CLOSE_REASONS = {0: 'Destroyed', 1: 'Dormancy', 2: 'LevelUnloaded', 3: 'Relevancy', 4: 'TearOff'}
# join tokens and account identifiers; shown only with --no-redact
SECRET_URL_OPTIONS = {'token', 'password', 'authticket', 'ticket', 'platformid', 'encryptiontoken', 'invitedby'}

SEQ_BITS = 14
SEQ_MASK = (1 << SEQ_BITS) - 1


# --------------------------------------------------------------------------
# input
# --------------------------------------------------------------------------

def read_pcap(path):
    """Yield (time_seconds, linktype, frame) from pcap or pcapng."""
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        nano = magic == b'\x4d\x3c\xb2\xa1'
        lt = struct.unpack_from('<I', data, 20)[0]
        pos = 24
        while pos + 16 <= len(data):
            sec, frac, incl, _orig = struct.unpack_from('<IIII', data, pos)
            pos += 16
            yield sec + frac / (1e9 if nano else 1e6), lt, data[pos:pos + incl]
            pos += incl
        return
    if magic != b'\x0a\x0d\x0d\x0a':
        raise SystemExit('%s: not a pcap/pcapng/etl file' % path)
    pos = 0
    ifaces = []
    while pos + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, pos)
        body = data[pos + 8:pos + blen - 4]
        if btype == 0x0A0D0D0A:
            ifaces = []
        elif btype == 1:
            lt = struct.unpack_from('<H', body, 0)[0]
            res = 1e-6
            op = 8
            while op + 4 <= len(body):
                code, ln = struct.unpack_from('<HH', body, op)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[op + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                op += 4 + ln + (-ln % 4)
            ifaces.append((lt, res))
        elif btype == 6:
            iid, hi, lo, incl = struct.unpack_from('<IIII', body, 0)
            lt, res = ifaces[iid]
            yield ((hi << 32) | lo) * res, lt, body[20:20 + incl]
        elif btype == 3:
            lt, _ = ifaces[0]
            yield 0.0, lt, body[4:]
        pos += blen


def read_etl(path, component=None):
    import pktmon_etl
    trace = pktmon_etl.PktmonTrace(path)
    if component is None:
        counts = collections.Counter(p.component for p in trace.packets if not p.is_drop)
        nic = [c for c in counts if trace.components.get(c) and trace.components[c].type in (2, 14)]
        component = max(nic or counts, key=lambda c: counts[c])
        comp = trace.components.get(component)
        print('[etl] using pktmon component %d (%s); use --component to override'
              % (component, comp.label if comp else '?'), file=sys.stderr)
    for p in trace.packets:
        if p.component == component and not p.is_drop:
            yield (p.filetime - pktmon_etl.FILETIME_UNIX_EPOCH) / 1e7, \
                pktmon_etl.PACKET_TYPE_LINKTYPE.get(p.packet_type, 1), p.data


def udp_datagrams(frames):
    """Yield (t, src, sport, dst, dport, payload) for IPv4/IPv6 UDP."""
    for t, lt, d in frames:
        try:
            if lt == 1:
                et = struct.unpack_from('>H', d, 12)[0]
                off = 14
                while et in (0x8100, 0x88A8):
                    et = struct.unpack_from('>H', d, off + 2)[0]
                    off += 4
                if et not in (0x0800, 0x86DD):
                    continue
                ip = d[off:]
            elif lt in (101, 228, 229, 12, 14):
                ip = d
            elif lt == 0 or lt == 108:     # null/loopback
                ip = d[4:]
            else:
                continue
            v = ip[0] >> 4
            if v == 4:
                if ip[9] != 17 or struct.unpack_from('>H', ip, 6)[0] & 0x1FFF:
                    continue
                ihl = (ip[0] & 15) * 4
                src, dst = '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20]))
                udp = ip[ihl:]
            elif v == 6:
                if ip[6] != 17:
                    continue
                import ipaddress
                src = str(ipaddress.IPv6Address(bytes(ip[8:24])))
                dst = str(ipaddress.IPv6Address(bytes(ip[24:40])))
                udp = ip[40:]
            else:
                continue
            sp, dp, ln = struct.unpack_from('>HHH', udp, 0)
            yield t, src, sp, dst, dp, bytes(udp[8:max(8, ln)])
        except (struct.error, IndexError):
            continue


# --------------------------------------------------------------------------
# bit reader (LSB first, as FBitReader)
# --------------------------------------------------------------------------

class BitReader:
    __slots__ = ('v', 'pos', 'end')

    def __init__(self, data, end, pos=0):
        self.v = int.from_bytes(data, 'little') if isinstance(data, (bytes, bytearray)) else data
        self.end = end
        self.pos = pos

    def left(self):
        return self.end - self.pos

    def bits(self, n):
        if self.pos + n > self.end:
            raise EOFError('read past end')
        r = (self.v >> self.pos) & ((1 << n) - 1)
        self.pos += n
        return r

    def bit(self):
        return self.bits(1)

    def read_int(self, max_value):
        """FBitReader::SerializeInt - variable width, LSB first."""
        v, mask = 0, 1
        while v + mask < max_value and mask:
            if self.pos >= self.end:
                raise EOFError('read past end')
            if (self.v >> self.pos) & 1:
                v |= mask
            self.pos += 1
            mask <<= 1
        return v

    def packed(self):
        """SerializeIntPacked - 7 bits per byte, low bit = 'more'."""
        v = 0
        for i in range(5):
            b = self.bits(8)
            v |= (b >> 1) << (7 * i)
            if not b & 1:
                return v
        raise ValueError('bad packed int')

    def raw(self, nbytes):
        return self.bits(nbytes * 8).to_bytes(nbytes, 'little') if nbytes else b''

    def fstring(self):
        n = self.bits(32)
        if n & 0x80000000:
            n -= 1 << 32
        if n == 0:
            return ''
        if n < 0:
            if -n > 0x10000:
                raise ValueError('bad string length')
            return self.raw(-n * 2).decode('utf-16le', 'replace').rstrip('\0')
        if n > 0x10000:
            raise ValueError('bad string length')
        return self.raw(n).decode('utf-8', 'replace').rstrip('\0')

    def double(self):
        return struct.unpack('<d', self.raw(8))[0]


def termination_bit(d):
    """Index of the highest set bit of the last byte (packet termination bit)."""
    if not d or d[-1] == 0:
        return None
    return (len(d) - 1) * 8 + d[-1].bit_length() - 1


def seq_diff(a, b):
    """a - b in 14-bit sequence space."""
    d = (a - b) & SEQ_MASK
    return d - (1 << SEQ_BITS) if d >= 1 << (SEQ_BITS - 1) else d


# --------------------------------------------------------------------------
# UE packet parsing
# --------------------------------------------------------------------------

class Config:
    def __init__(self, magic_bits=0, max_packet=1024):
        self.magic_bits = magic_bits
        self.max_packet = max_packet


def parse_handshake(d, cfg):
    end = termination_bit(d)
    r = BitReader(d, end, cfg.magic_bits + 1)
    hs = {'restart': r.bit()}
    if r.left() >= 80:
        hs['min_version'] = r.bits(8)
        hs['version'] = r.bits(8)
        hs['type_id'] = r.bits(8)
        hs['type'] = HANDSHAKE_TYPES.get(hs['type_id'], hs['type_id'])
        hs['sent_count'] = r.bits(8)
        if hs['version'] >= 2:
            hs['netcl'] = r.bits(32)
            hs['runtime_features'] = r.bits(16)
        if hs['type_id'] in (1, 2, 3, 5) and r.left() >= 1 + 64 + 160:
            hs['secret_id'] = r.bit()
            hs['timestamp'] = r.double()
            hs['cookie'] = r.raw(20).hex()
    hs['size'] = len(d)
    return hs


def parse_packet(d, direction, cfg):
    """Returns ('handshake', info) or ('data', header, bunches)."""
    ot = termination_bit(d)
    if ot is None:
        raise ValueError('no termination bit')
    v = int.from_bytes(d, 'little')
    m = cfg.magic_bits
    if (v >> m) & 1:
        return ('handshake', parse_handshake(d, cfg))
    if not (v >> (ot - 1)) & 1:
        raise ValueError('no inner termination bit')
    r = BitReader(v, ot - 1, m + 1)
    packed = r.bits(32)
    hdr = {
        'hist_words': (packed & 15) + 1,
        'ack': (packed >> 4) & SEQ_MASK,
        'seq': (packed >> 18) & SEQ_MASK,
    }
    hdr['history'] = r.bits(32 * hdr['hist_words'])
    hdr['info'] = r.bit()
    hdr['frame_time_ms'] = None
    hdr['jitter_clock'] = None
    if hdr['info']:
        hdr['jitter_clock'] = r.read_int(1024)
        has_ft = r.bit()
        hdr['frame_time_requested'] = has_ft
        if has_ft and direction == 'S':
            hdr['frame_time_ms'] = r.bits(8)
    bunches = []
    while r.pos < r.end:
        b = {}
        ctl = r.bit()
        b['open'] = r.bit() if ctl else 0
        b['close'] = r.bit() if ctl else 0
        b['close_reason'] = r.read_int(15) if b['close'] else None
        b['paused'] = r.bit()
        b['reliable'] = r.bit()
        b['ch'] = r.packed()
        b['exports'] = r.bit()
        b['must_map'] = r.bit()
        b['partial'] = r.bit()
        b['ch_seq'] = r.read_int(1024) if b['reliable'] else None
        b['partial_initial'] = r.bit() if b['partial'] else 0
        b['partial_final'] = r.bit() if b['partial'] else 0
        b['name'] = None
        if b['reliable'] or b['open']:
            if r.bit():
                idx = r.packed()
                b['name'] = HARDCODED_NAMES.get(idx, 'EName#%d' % idx)
            else:
                b['name'] = r.fstring()
                r.bits(32)
        b['nbits'] = r.read_int(cfg.max_packet * 8)
        b['start'] = r.pos
        r.pos += b['nbits']
        if r.pos > r.end:
            raise ValueError('bunch runs past end of packet')
        bunches.append(b)
    return ('data', hdr, bunches)


def detect_magic_bits(payloads):
    """Find the constant prefix length N such that bit N is bHandshakePacket
    and data packets carry consecutive 14-bit sequence numbers."""
    sample = [p for p in payloads[:400] if p]
    if len(sample) < 8:
        return None
    best = None
    for n in range(0, 65):
        ok = 0
        prev = None
        for p in sample:
            v = int.from_bytes(p, 'little')
            if (v >> n) & 1:
                continue
            seq = (v >> (n + 1 + 18)) & SEQ_MASK
            if prev is not None and seq_diff(seq, prev) == 1:
                ok += 1
            prev = seq
        if best is None or ok > best[1]:
            best = (n, ok)
    if best and best[1] >= len(sample) * 0.3:
        return best[0]
    return None


# --------------------------------------------------------------------------
# control channel
# --------------------------------------------------------------------------

def _b64(s):
    try:
        return base64.b64decode(s + '=' * (-len(s) % 4), validate=True).decode('utf-8')
    except Exception:
        return None


def redact(s, keep=4):
    return s if len(s) <= keep else s[:keep] + '…[%d chars redacted]' % (len(s) - keep)


def parse_url_options(url, do_redact):
    opts = []
    for part in url.split('?'):
        if not part:
            continue
        k, _, v = part.partition('=')
        dec = _b64(v) if v and re.fullmatch(r'[A-Za-z0-9+/=]{8,}', v) else None
        secret = k.lower() in SECRET_URL_OPTIONS
        shown = v
        if do_redact and secret:
            shown = redact(v)
            dec = redact(dec) if dec else None
        opts.append({'key': k, 'value': shown, 'base64_decoded': dec, 'secret': secret})
    return opts


def decode_control(r, do_redact):
    msgs = []
    while r.left() >= 8:
        t = r.bits(8)
        m = {'type': NMT.get(t, t)}
        try:
            if t == 0:
                m['little_endian'] = r.bits(8)
                m['network_version'] = '0x%08x' % r.bits(32)
                tok = r.fstring()
                m['encryption_token'] = redact(tok) if (do_redact and tok) else tok
                if r.left() >= 16:
                    m['runtime_features'] = '0x%04x' % r.bits(16)
            elif t == 1:
                m['map'], m['game_mode'], m['redirect_url'] = r.fstring(), r.fstring(), r.fstring()
            elif t == 2:
                m['remote_network_version'] = '0x%08x' % r.bits(32)
            elif t in (3, 6, 17, 19, 23):
                s = r.fstring()
                m['text'] = s
            elif t == 4:
                m['rate'] = r.bits(32)
            elif t == 5:
                m['client_response'] = r.fstring()
                url = r.fstring()
                m['url_options'] = parse_url_options(url, do_redact)
                flags = r.bits(8)
                uid = {'encoding_flags': '0x%02x' % flags}
                if flags & 1:          # encoded (compact) id
                    ln = r.bits(8)
                    uid['encoded'] = r.raw(ln).hex()
                else:
                    if (flags >> 3) == 31:
                        uid['type'] = r.fstring()
                    else:
                        uid['type_hash'] = flags >> 3
                    if not flags & 2:
                        uid['id'] = r.fstring()
                        if do_redact:
                            uid['id'] = redact(uid['id'])
                m['unique_id'] = uid
                if r.left() >= 32:
                    m['online_platform'] = r.fstring()
            elif t == 9:
                pass
            elif t == 20:
                m['message_type'] = r.bits(8)
                m['text'] = r.fstring()
            elif t == 24:
                m['ping_type'] = r.bits(8)
                m['text'] = r.fstring()
            elif t == 29:
                m['protocol_id'] = '0x%016x' % r.bits(64)
            elif t == 30:
                m['error'] = r.bits(32)
                m['ref_handle'] = r.bits(64)
                n = r.bits(32)
                m['extra'] = [r.bits(64) for _ in range(min(n, 64))]
            else:
                m['raw'] = r.raw(r.left() // 8).hex()
        except (EOFError, ValueError) as e:
            m['error'] = 'decode stopped: %s' % e
            msgs.append(m)
            break
        msgs.append(m)
    return msgs


# --------------------------------------------------------------------------
# string extraction
# --------------------------------------------------------------------------

PATH_RE = re.compile(r'^/?(?:[A-Za-z0-9_\-]+/)+[A-Za-z0-9_.\-]+$')
IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_. \-]*$')


def length_prefixed_strings(val, nbits, minlen=4):
    """Yield strings from a bunch payload.

    Iris (and classic FString) strings are length-prefixed. A string is
    accepted only if the 16 bits in front of a printable run hold its length
    (Iris: exact length; FString: length + NUL), at any bit alignment."""
    for shift in range(8):
        n = (nbits - shift) // 8
        if n < minlen:
            break
        bs = (val >> shift).to_bytes(n + 1, 'little')[:n]
        for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, bs):
            bitpos = shift + m.start() * 8
            if bitpos < 16:
                continue
            ln = (val >> (bitpos - 16)) & 0xFFFF
            run = m.group()
            if minlen <= ln <= len(run):
                yield run[:ln].decode()
            elif ln == len(run) + 1 and m.end() < len(bs) and bs[m.end()] == 0:
                yield run.decode()


INSTANCE_SUFFIX = re.compile(r'(_UAID_[0-9A-F]+_[0-9a-f]+_\d+|_\d+)$')


def group_names(counter):
    """Collapse per-instance object names (Foo_C_12, Foo_C_UAID_...) to class -> instance count."""
    groups = collections.defaultdict(set)
    for name in counter:
        groups[INSTANCE_SUFFIX.sub('', name)].add(name)
    return sorted(((k, len(v)) for k, v in groups.items()), key=lambda kv: (-kv[1], kv[0]))


def classify_strings(counter):
    paths, names = collections.Counter(), collections.Counter()
    for s, n in counter.items():
        if '/' in s and PATH_RE.match(s):
            paths[s] += n
        elif IDENT_RE.match(s) and (len(s) >= 6 or re.fullmatch(r'[A-Z][a-z]+', s)) and re.search(r'[a-z]{2}', s):
            names[s] += n
    return paths, names


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def analyze_flow(pkts, client, server, cfg, args):
    """pkts: list of (t, dir, payload); dir 'C' = client->server."""
    rep = {'client': '%s:%d' % client, 'server': '%s:%d' % server}
    t0 = pkts[0][0]
    rep['start'] = t0
    rep['duration_s'] = round(pkts[-1][0] - t0, 3)
    rep['magic_header_bits'] = cfg.magic_bits
    if cfg.magic_bits:
        mv = int.from_bytes(pkts[0][2], 'little') & ((1 << cfg.magic_bits) - 1)
        rep['magic_header'] = '0x%x (%d bits, LSB-first)' % (mv, cfg.magic_bits)
    handshakes, parsed, failures = [], [], 0
    for t, dr, d in pkts:
        try:
            res = parse_packet(d, dr, cfg)
        except Exception:
            failures += 1
            continue
        if res[0] == 'handshake':
            hs = res[1]
            hs['dir'] = dr
            hs['t'] = round(t - t0, 4)
            handshakes.append(hs)
        else:
            parsed.append((t, dr, d, res[1], res[2]))
    rep['packets'] = {'total': len(pkts), 'handshake': len(handshakes),
                      'data': len(parsed), 'unparsed': failures}
    for hs in handshakes:
        if 'cookie' in hs:
            c = bytes.fromhex(hs['cookie'])
            hs['server_initial_seq'] = struct.unpack_from('<H', c, 0)[0] & SEQ_MASK
            hs['client_initial_seq'] = struct.unpack_from('<H', c, 2)[0] & SEQ_MASK
            if args.redact:
                hs['cookie'] = redact(hs['cookie'], 8)
        if 'netcl' in hs:
            hs['netcl'] = '0x%08x' % hs['netcl']
            hs['runtime_features'] = '0x%04x' % hs['runtime_features']
    rep['handshake'] = handshakes
    hs_rtt = []
    for a, b in zip(handshakes, handshakes[1:]):
        if a['dir'] == 'C' and b['dir'] == 'S':
            hs_rtt.append(round((b['t'] - a['t']) * 1000, 1))
    rep['handshake_rtt_ms'] = hs_rtt

    # ---- per-direction stats
    stats = {}
    for dr, name in (('C', 'client_to_server'), ('S', 'server_to_client')):
        rows = [p for p in pkts if p[1] == dr]
        if not rows:
            continue
        sizes = [len(p[2]) for p in rows]
        times = [p[0] for p in rows]
        span = max(times[-1] - times[0], 1e-9)
        gaps = [(b - a) * 1000 for a, b in zip(times, times[1:])]
        per_sec = collections.Counter(int(t - t0) for t in times)
        stats[name] = {
            'packets': len(rows), 'bytes': sum(sizes),
            'avg_pps': round(len(rows) / span, 1),
            'avg_kbps_payload': round(sum(sizes) * 8 / span / 1000, 1),
            'size_bytes': {'min': min(sizes), 'p50': pct(sizes, 50), 'p95': pct(sizes, 95), 'max': max(sizes)},
            'interval_ms': {'p5': round(pct(gaps, 5), 2), 'p50': round(pct(gaps, 50), 2),
                            'p95': round(pct(gaps, 95), 2), 'max': round(max(gaps), 1)} if gaps else None,
            'peak_pps_1s': max(per_sec.values()),
        }
    rep['traffic'] = stats

    # ---- sequence analysis: downstream loss, upstream loss (ack history), RTT
    sent = {}          # client seq -> send time
    acked_status = {}  # client seq -> delivered?
    rtts = []
    srv_seqs = []
    frame_times = []
    ack_seen = None
    for t, dr, d, hdr, bunches in parsed:
        if dr == 'C':
            sent[hdr['seq']] = t      # latest send wins after 14-bit wrap
        else:
            srv_seqs.append(hdr['seq'])
            if hdr['frame_time_ms'] is not None:
                frame_times.append(hdr['frame_time_ms'])
            ack = hdr['ack']
            for i in range(32 * hdr['hist_words']):
                s = (ack - i) & SEQ_MASK
                if s in sent:
                    acked_status[s] = bool((hdr['history'] >> i) & 1)
            if ack_seen is None or seq_diff(ack, ack_seen) > 0:
                if ack in sent:
                    rtts.append((t - sent[ack]) * 1000)
                ack_seen = ack
    lost_down = dup_down = reordered = 0
    for a, b in zip(srv_seqs, srv_seqs[1:]):
        dd = seq_diff(b, a)
        if dd > 1:
            lost_down += dd - 1
        elif dd == 0:
            dup_down += 1
        elif dd < 0:
            reordered += 1
    naks = sum(1 for v in acked_status.values() if not v)
    rep['reliability'] = {
        'server_packets_missing_at_client': lost_down,
        'server_packet_loss_pct': round(100.0 * lost_down / max(1, len(srv_seqs) + lost_down), 3),
        'server_packets_reordered': reordered,
        'server_packets_duplicated': dup_down,
        'client_packets_nacked_by_server': naks,
        'client_packet_loss_pct': round(100.0 * naks / max(1, len(acked_status)), 3),
    }
    if rtts:
        rep['rtt_ms_from_acks'] = {'min': round(min(rtts), 1), 'p50': round(pct(rtts, 50), 1),
                                   'p95': round(pct(rtts, 95), 1), 'max': round(max(rtts), 1),
                                   'samples': len(rtts),
                                   'note': 'includes server-side delay until its next send'}
    if frame_times:
        rep['server_frame_time_ms'] = {
            'min': min(frame_times), 'p50': pct(frame_times, 50), 'p95': pct(frame_times, 95),
            'max': max(frame_times), 'samples': len(frame_times),
            'implied_tick_hz_p50': round(1000.0 / max(pct(frame_times, 50), 1), 1)}

    # ---- channels and control messages
    chans = collections.OrderedDict()
    control = []
    strings = collections.defaultdict(collections.Counter)
    for t, dr, d, hdr, bunches in parsed:
        v = int.from_bytes(d, 'little')
        for b in bunches:
            ch = chans.setdefault(b['ch'], {'name': None, 'opened_by': None, 'bunches': collections.Counter(),
                                            'bits': collections.Counter(), 'reliable': 0, 'partial': 0,
                                            'closes': []})
            if b['name'] and not ch['name']:
                ch['name'] = b['name']
            if b['open'] and not ch['opened_by']:
                ch['opened_by'] = dr
            ch['bunches'][dr] += 1
            ch['bits'][dr] += b['nbits']
            ch['reliable'] += b['reliable']
            ch['partial'] += b['partial']
            if b['close']:
                ch['closes'].append(CLOSE_REASONS.get(b['close_reason'], b['close_reason']))
            if not b['nbits']:
                continue
            if ch['name'] == 'Control' or (b['ch'] == 0 and ch['name'] is None):
                r = BitReader(v, b['start'] + b['nbits'], b['start'])
                for m in decode_control(r, args.redact):
                    m['dir'] = dr
                    m['t'] = round(t - t0, 4)
                    control.append(m)
            elif args.strings:
                payload = (v >> b['start']) & ((1 << b['nbits']) - 1)
                for s in length_prefixed_strings(payload, b['nbits']):
                    strings[dr][s] += 1
    rep['channels'] = [{
        'index': i, 'name': c['name'], 'opened_by': c['opened_by'],
        'bunches': dict(c['bunches']), 'kbytes': {k: round(x / 8192, 1) for k, x in c['bits'].items()},
        'reliable_bunches': c['reliable'], 'partial_bunches': c['partial'], 'closes': c['closes']}
        for i, c in chans.items()]
    rep['control_messages'] = control

    if args.strings:
        empty = (collections.Counter(), collections.Counter())
        found = {dr: classify_strings(strings[dr]) for dr in strings}
        allpaths = set(found.get('S', empty)[0]) | set(found.get('C', empty)[0])
        rep['strings'] = {
            'script_modules': sorted({p.split('/')[2].split('.')[0] for p in allpaths
                                      if p.startswith('/Script/') and len(p.split('/')) > 2}),
            'server_to_client_paths': sorted(found.get('S', empty)[0]),
            'client_to_server_paths': sorted(found.get('C', empty)[0]),
            'server_to_client_names': group_names(found.get('S', empty)[1]),
            'client_to_server_names': group_names(found.get('C', empty)[1]),
        }
    return rep


def find_flows(datagrams, args):
    flows = collections.defaultdict(list)
    for t, src, sp, dst, dp, pl in datagrams:
        a, b = (src, sp), (dst, dp)
        key = tuple(sorted((a, b)))
        flows[key].append((t, a, pl))
    out = []
    for key, rows in flows.items():
        if len(rows) < args.min_packets:
            continue
        if args.server:
            host, _, port = args.server.rpartition(':')
            srv = (host, int(port))
            if srv not in key:
                continue
        else:
            srv = None
        a, b = key
        if srv is None:
            # the server is the side with the lower (fixed) port if one side is ephemeral
            srv = b if (a[1] >= 49152 and b[1] < 49152) else a if (b[1] >= 49152 and a[1] < 49152) else \
                (rows[0][1] == a and b or a)
        cli = a if srv == b else b
        pk = [(t, 'C' if s == cli else 'S', pl) for t, s, pl in rows]
        magic = args.magic_bits if args.magic_bits is not None else detect_magic_bits([p[2] for p in pk if p[1] == 'C'])
        if magic is None:
            continue
        out.append((pk, cli, srv, magic))
    return out


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def print_report(rep, out=sys.stdout):
    w = out.write
    w('=' * 78 + '\n')
    w('Unreal Engine connection  client %s  <->  server %s\n' % (rep['client'], rep['server']))
    w('=' * 78 + '\n')
    p = rep['packets']
    w('duration %.1f s, %d packets (%d handshake, %d data, %d unparsed)\n'
      % (rep['duration_s'], p['total'], p['handshake'], p['data'], p['unparsed']))
    if rep.get('magic_header'):
        w('constant packet prefix (StatelessConnect MagicHeader): %s\n' % rep['magic_header'])
    w('\nHandshake (StatelessConnectHandlerComponent)\n')
    for hs in rep['handshake']:
        line = '  t=%7.3f %s %-14s %3d B' % (hs['t'], hs['dir'] + '>' + ('S' if hs['dir'] == 'C' else 'C'),
                                           hs.get('type', '?'), hs['size'])
        if 'version' in hs:
            line += '  ver %d (min %d)' % (hs['version'], hs['min_version'])
        if 'netcl' in hs:
            line += '  NetCL %s features %s' % (hs['netcl'], hs['runtime_features'])
        if 'timestamp' in hs and hs['timestamp'] > 0:
            line += '  server time %.3f s' % hs['timestamp']
        w(line + '\n')
    cookie = next((h for h in rep['handshake'] if 'server_initial_seq' in h), None)
    if cookie:
        w('  cookie-derived initial seq: server %d, client %d\n'
          % (cookie['server_initial_seq'], cookie['client_initial_seq']))
    if rep['handshake_rtt_ms']:
        w('  handshake round trips: %s ms\n' % ', '.join('%.1f' % x for x in rep['handshake_rtt_ms']))
    w('\nTraffic\n')
    for k, s in rep['traffic'].items():
        w('  %-17s %6d pkts %9d B  avg %5.1f pkt/s (peak %d)  %7.1f kbit/s  size p50 %s / p95 %s / max %d B\n'
          % (k, s['packets'], s['bytes'], s['avg_pps'], s['peak_pps_1s'], s['avg_kbps_payload'],
             s['size_bytes']['p50'], s['size_bytes']['p95'], s['size_bytes']['max']))
        if s['interval_ms']:
            w('  %-17s send interval p5 %.1f / p50 %.1f / p95 %.1f / max %.1f ms\n'
              % ('', s['interval_ms']['p5'], s['interval_ms']['p50'], s['interval_ms']['p95'], s['interval_ms']['max']))
    r = rep['reliability']
    w('\nReliability\n')
    w('  server->client: %d missing (%.3f%%), %d reordered, %d duplicated\n'
      % (r['server_packets_missing_at_client'], r['server_packet_loss_pct'],
         r['server_packets_reordered'], r['server_packets_duplicated']))
    w('  client->server: %d NAKed by server ack history (%.3f%%)\n'
      % (r['client_packets_nacked_by_server'], r['client_packet_loss_pct']))
    if 'rtt_ms_from_acks' in rep:
        x = rep['rtt_ms_from_acks']
        w('  RTT from acks: min %.1f / p50 %.1f / p95 %.1f / max %.1f ms (%d samples; %s)\n'
          % (x['min'], x['p50'], x['p95'], x['max'], x['samples'], x['note']))
    if 'server_frame_time_ms' in rep:
        x = rep['server_frame_time_ms']
        w('  server frame time: min %d / p50 %s / p95 %s / max %d ms  (~%.1f Hz tick)\n'
          % (x['min'], x['p50'], x['p95'], x['max'], x['implied_tick_hz_p50']))
    w('\nChannels\n')
    for c in rep['channels']:
        w('  ch %-4d %-12s opened by %-2s bunches C>S %-6d S>C %-6d  kB C>S %-8s S>C %-8s reliable %d%s\n'
          % (c['index'], c['name'] or '?', c['opened_by'] or '-', c['bunches'].get('C', 0), c['bunches'].get('S', 0),
             c['kbytes'].get('C', 0), c['kbytes'].get('S', 0), c['reliable_bunches'],
             ('  closed: ' + ','.join(map(str, c['closes']))) if c['closes'] else ''))
    w('\nControl channel messages\n')
    for m in rep['control_messages']:
        extra = {k: v for k, v in m.items() if k not in ('type', 'dir', 't', 'url_options')}
        w('  t=%7.3f %s NMT_%s %s\n' % (m['t'], m['dir'] + '>' + ('S' if m['dir'] == 'C' else 'C'), m['type'],
                                       json.dumps(extra, ensure_ascii=False) if extra else ''))
        for o in m.get('url_options', []):
            w('             ?%s=%s%s\n' % (o['key'], o['value'],
                                          ('   (base64: %s)' % o['base64_decoded']) if o['base64_decoded'] else ''))
    if 'strings' in rep:
        s = rep['strings']
        w('\nReplicated script modules (/Script/...): %s\n' % ', '.join(s['script_modules']))
        w('\nAsset paths seen server->client (%d):\n' % len(s['server_to_client_paths']))
        for x in s['server_to_client_paths']:
            w('  %s\n' % x)
        w('\nObject / component names seen server->client (%d classes; count = distinct instances):\n'
          % len(s['server_to_client_names']))
        for name, n in s['server_to_client_names'][:200]:
            w('  %4d  %s\n' % (n, name))
        w('\nAsset paths seen client->server (%d):\n' % len(s['client_to_server_paths']))
        for x in s['client_to_server_paths'][:40]:
            w('  %s\n' % x)
        if len(s['client_to_server_paths']) > 40:
            w('  ... %d more\n' % (len(s['client_to_server_paths']) - 40))
    w('\n')


def main(argv=None):
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser(description='Analyze Unreal Engine UDP game traffic in a capture.')
    ap.add_argument('capture', help='.etl (pktmon), .pcapng or .pcap')
    ap.add_argument('--server', help='server ip:port (default: auto-detect UE flows)')
    ap.add_argument('--component', type=int, help='pktmon component id for .etl input')
    ap.add_argument('--magic-bits', type=int, help='StatelessConnect MagicHeader length (default: detect)')
    ap.add_argument('--max-packet', type=int, default=1024, help='UNetConnection::MaxPacket (default 1024)')
    ap.add_argument('--min-packets', type=int, default=50)
    ap.add_argument('--no-strings', dest='strings', action='store_false', help='skip asset/name extraction')
    ap.add_argument('--no-redact', dest='redact', action='store_false',
                    help='show join tokens / platform ids / cookies in full')
    ap.add_argument('--json', help='also write the full report as JSON')
    args = ap.parse_args(argv)

    if args.capture.lower().endswith('.etl'):
        frames = read_etl(args.capture, args.component)
    else:
        frames = read_pcap(args.capture)
    flows = find_flows(udp_datagrams(frames), args)
    if not flows:
        print('no Unreal Engine flows found (try --server ip:port and/or --magic-bits N)')
        return 1
    reports = []
    for pk, cli, srv, magic in sorted(flows, key=lambda f: -len(f[0])):
        cfg = Config(magic, args.max_packet)
        rep = analyze_flow(pk, cli, srv, cfg, args)
        if rep['packets']['data'] < max(10, rep['packets']['total'] // 2):
            continue       # not really UE
        reports.append(rep)
        print_report(rep)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(reports, f, indent=1, default=str)
    return 0


if __name__ == '__main__':
    sys.exit(main())
