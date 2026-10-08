#!/usr/bin/env python3
"""Self-contained tests for pktmon_etl.py and ue_netanalyze.py.

Run:  python3 -m unittest -v tools/pktmon/test_pktmon_tools.py
"""

import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pktmon_etl as P          # noqa: E402
import ue_netanalyze as U       # noqa: E402


# --------------------------------------------------------------------------
# synthetic ETL builder
# --------------------------------------------------------------------------

QPC_FREQ = 10000000
START_FT = 0x01DD56E6DD4FD4A3
HEADER_QPC = 45097000612


def lz77_literals(data):
    """Valid MS-XCA plain LZ77 stream made only of literals."""
    out = bytearray()
    for i in range(0, len(data), 32):
        out += b'\x00\x00\x00\x00' + data[i:i + 32]
    return bytes(out)


def pad8(b):
    return b + b'\x00' * (-len(b) % 8)


def buffer(events, compressed=False, proc=0):
    payload = b''.join(pad8(e) for e in events)
    used = 0x48 + len(payload)
    body = lz77_literals(payload) if compressed else payload
    size = 0x48 + len(body)
    flags = 0x40 if compressed else 0
    hdr = struct.pack('<IIIiqqQIIIHH', size, used, 0, 0, 0, 1, 0, proc, 3, used, flags, 0) + b'\x00' * 16
    return hdr + body


def logfile_header_event():
    body = struct.pack('<IIIIqIIIIIIII', 0x10000, 0x0002000A, 26200, 4, START_FT + 50000000,
                       156250, 512, 0x04010001, 2, 1, 8, 0, 3700)
    body += b'\x00' * 16                      # LoggerName / LogFileName pointers
    body += b'\x00' * 172 + b'\x00' * 4       # TIME_ZONE_INFORMATION + align
    body += struct.pack('<qqqII', START_FT - 450000000000, QPC_FREQ, START_FT, 1, 0)
    body += 'Test Logger\x00X:\\test.etl\x00'.encode('utf-16le')
    hdr = struct.pack('<HBBHHIIqII', 2, 2, 0xC0, 0x20 + len(body), 0, 1, 4, HEADER_QPC, 0, 0)
    return hdr + body


def pktmon_event(event_id, user_data, ts):
    hdr = struct.pack('<HBBHHIIq', 0x50 + len(user_data), 0x13, 0xC0, 0, 0, 1, 4, ts)
    hdr += P.PKTMON_PROVIDER.bytes_le
    hdr += struct.pack('<HBBBBHQ', event_id, 0, 0, 4, 0, 0, 0)
    hdr += b'\x00' * 8 + b'\x00' * 16
    return hdr + user_data


def wstr(s):
    return (s + '\x00').encode('utf-16le')


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 128, 17, 0, bytes(src), bytes(dst))
    return b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00' + ip + udp


def build_etl(frames, compressed=False):
    """frames: list of (qpc_ts, direction_tag, frame bytes)."""
    events = [pktmon_event(20, struct.pack('<HH', 7, 14) + wstr('e2fn.sys') + wstr('Test NIC'), HEADER_QPC + 1),
              pktmon_event(70, struct.pack('<HHI', 7, 6, 6) + bytes.fromhex('02005e101234'), HEADER_QPC + 2)]
    for i, (ts, dirtag, fr) in enumerate(frames):
        ud = struct.pack('<QHHHHHHHIIHH', 1000 + i, 1, 0, dirtag, 1, 7, 1, 0, 0, 0, len(fr), len(fr)) + fr
        events.append(pktmon_event(160, ud, ts))
    # spread packets over two "processor" buffers, out of time order on purpose
    half = len(events) // 2
    return (buffer([logfile_header_event()]) +
            buffer(events[half:], compressed, proc=1) +
            buffer(events[:half], compressed, proc=0))


# --------------------------------------------------------------------------
# UE bit writer (mirror of FBitWriter)
# --------------------------------------------------------------------------

class BitWriter:
    def __init__(self):
        self.v = 0
        self.n = 0

    def bits(self, value, count):
        self.v |= (value & ((1 << count) - 1)) << self.n
        self.n += count

    def bit(self, b):
        self.bits(1 if b else 0, 1)

    def write_int(self, value, max_value):
        new, mask = 0, 1
        while new + mask < max_value and mask:
            if value & mask:
                new += mask
                self.bits(1, 1)
            else:
                self.bits(0, 1)
            mask <<= 1

    def packed(self, value):
        while True:
            b = (value & 0x7F) << 1
            value >>= 7
            if value:
                b |= 1
            self.bits(b, 8)
            if not value:
                break

    def raw(self, data):
        for x in data:
            self.bits(x, 8)

    def fstring(self, s):
        if not s:
            self.bits(0, 32)
        else:
            enc = s.encode() + b'\x00'
            self.bits(len(enc), 32)
            self.raw(enc)

    def append(self, other):
        self.bits(other.v, other.n)

    def finish(self, term_bits=2):
        for _ in range(term_bits):
            self.bit(1)
        nbytes = (self.n + 7) // 8
        return self.v.to_bytes(nbytes, 'little')


MAGIC = 0x4A6605D00
MAGIC_BITS = 37


def ue_data_packet(seq, ack, server=False, bunches=(), jitter=500, frame_time=33):
    w = BitWriter()
    w.bits(MAGIC, MAGIC_BITS)
    w.bit(0)                                   # bHandshakePacket
    w.bits((seq << 18) | (ack << 4) | 0, 32)   # 1 history word
    w.bits(0xFFFFFFFF, 32)
    w.bit(1)                                   # bHasPacketInfoPayload
    w.write_int(jitter, 1024)
    w.bit(1)                                   # bHasServerFrameTime
    if server:
        w.bits(frame_time, 8)
    for b in bunches:
        w.append(b)
    return w.finish()


def control_bunch(payload, ch_seq=1, open_=True):
    w = BitWriter()
    w.bit(1)          # bControl
    w.bit(open_)      # bOpen
    w.bit(0)          # bClose
    w.bit(0)          # bIsReplicationPaused
    w.bit(1)          # bReliable
    w.packed(0)       # ChIndex
    w.bit(0)
    w.bit(0)
    w.bit(0)          # bPartial
    w.write_int(ch_seq, 1024)
    w.bit(1)          # hardcoded name
    w.packed(255)     # NAME_Control
    w.write_int(payload.n, 8192)
    w.append(payload)
    return w


def handshake_packet(ptype, timestamp, cookie):
    w = BitWriter()
    w.bits(MAGIC, MAGIC_BITS)
    w.bit(1)          # bHandshakePacket
    w.bit(0)          # bRestartHandshake
    for v in (3, 4, ptype, 1):
        w.bits(v, 8)
    w.bits(0x573A0E65, 32)
    w.bits(1, 16)
    w.bit(0)          # SecretId
    w.raw(struct.pack('<d', timestamp))
    w.raw(cookie)
    w.raw(b'\x5a\xa5\x11')
    return w.finish(term_bits=1)


class Args:
    redact = True
    strings = True


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

class LZ77Tests(unittest.TestCase):
    def test_ms_xca_examples(self):
        # [MS-XCA] 3.1 examples
        self.assertEqual(P.lz77_decompress(bytes.fromhex('3f000000') + b'abcdefghijklmnopqrstuvwxyz'),
                         b'abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(P.lz77_decompress(bytes.fromhex('ffffff1f61626317000fff2601')), b'abc' * 100)

    def test_literal_stream(self):
        data = os.urandom(1000)
        self.assertEqual(P.lz77_decompress(lz77_literals(data)), data)


class EtlTests(unittest.TestCase):
    def setUp(self):
        self.frames = [(HEADER_QPC + 10000000 * (i + 1), 4 if i % 2 else 3,
                        udp_frame([192, 168, 1, 2], [54, 1, 2, 3], 50000, 7777, bytes([i]) * (i + 4)))
                       for i in range(10)]

    def check_trace(self, tr):
        self.assertEqual(tr.header.build, 26200)
        self.assertEqual(tr.header.perf_freq, QPC_FREQ)
        self.assertEqual(tr.header.logger_name, 'Test Logger')
        self.assertEqual(tr.components[7].name, 'e2fn.sys')
        self.assertEqual(tr.components[7].description, 'Test NIC')
        self.assertEqual(tr.components[7].props[6], [('mac', '02:00:5e:10:12:34')])
        self.assertEqual(len(tr.packets), 10)
        for i, p in enumerate(tr.packets):           # sorted back into time order
            self.assertEqual(p.data, self.frames[i][2])
            self.assertEqual(p.dir_name, 'Tx' if i % 2 else 'Rx')
            self.assertEqual(p.filetime, START_FT + 10000000 * (i + 1))

    def test_plain_etl(self):
        self.check_trace(P.PktmonTrace(build_etl(self.frames)))

    def test_compressed_etl(self):
        tr = P.PktmonTrace(build_etl(self.frames, compressed=True))
        self.assertEqual(tr.compressed_buffers, 2)
        self.check_trace(tr)

    def test_pcapng_roundtrip(self):
        tr = P.PktmonTrace(build_etl(self.frames, compressed=True))
        out = io.BytesIO()
        self.assertEqual(P.write_pcapng(tr, tr.packets, out), 1)
        with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as f:
            f.write(out.getvalue())
        try:
            got = list(U.read_pcap(f.name))
        finally:
            os.unlink(f.name)
        self.assertEqual([g[2] for g in got], [fr for _, _, fr in self.frames])
        unix0 = (START_FT - P.FILETIME_UNIX_EPOCH) / 1e7
        self.assertAlmostEqual(got[3][0], unix0 + 4, places=5)

    def test_summarize(self):
        self.assertEqual(P.summarize(self.frames[0][2], 1), 'UDP 192.168.1.2:50000 > 54.1.2.3:7777 len=4')


class UnrealTests(unittest.TestCase):
    cfg = U.Config(MAGIC_BITS, 1024)

    def test_handshake(self):
        cookie = bytes(range(20))
        kind, hs = U.parse_packet(handshake_packet(1, 3091.605, cookie), 'S', self.cfg)
        self.assertEqual(kind, 'handshake')
        self.assertEqual(hs['type'], 'Challenge')
        self.assertEqual((hs['min_version'], hs['version']), (3, 4))
        self.assertEqual(hs['netcl'], 0x573A0E65)
        self.assertAlmostEqual(hs['timestamp'], 3091.605)
        self.assertEqual(hs['cookie'], cookie.hex())

    def test_data_packet_and_control(self):
        hello = BitWriter()
        hello.bits(0, 8)                 # NMT_Hello
        hello.bits(1, 8)
        hello.bits(0x573A0E65, 32)
        hello.fstring('')
        hello.bits(1, 16)
        pkt = ue_data_packet(1693, 12589, bunches=[control_bunch(hello)])
        kind, hdr, bunches = U.parse_packet(pkt, 'C', self.cfg)
        self.assertEqual(kind, 'data')
        self.assertEqual((hdr['seq'], hdr['ack'], hdr['hist_words'], hdr['jitter_clock']), (1693, 12589, 1, 500))
        self.assertEqual(len(bunches), 1)
        b = bunches[0]
        self.assertEqual((b['ch'], b['name'], b['open'], b['reliable'], b['ch_seq']), (0, 'Control', 1, 1, 1))
        msgs = U.decode_control(U.BitReader(pkt, b['start'] + b['nbits'], b['start']), True)
        self.assertEqual(msgs, [{'type': 'Hello', 'little_endian': 1, 'network_version': '0x573a0e65',
                                 'encryption_token': '', 'runtime_features': '0x0001'}])

    def test_server_frame_time(self):
        _, hdr, bunches = U.parse_packet(ue_data_packet(5, 6, server=True, frame_time=33), 'S', self.cfg)
        self.assertEqual(hdr['frame_time_ms'], 33)
        self.assertEqual(bunches, [])

    def test_login_redaction(self):
        login = BitWriter()
        login.bits(5, 8)
        login.fstring('0')
        login.fstring('?Name=Player?Token=c2VjcmV0LXRva2VuLXZhbHVl')
        login.bits(0xF8, 8)
        login.fstring('Pragma')
        login.fstring('abc')
        login.fstring('Pragma')
        msgs = U.decode_control(U.BitReader(login.v, login.n, 0), True)
        opts = {o['key']: o for o in msgs[0]['url_options']}
        self.assertEqual(opts['Name']['value'], 'Player')
        self.assertNotIn('secret-token-value', opts['Token']['base64_decoded'])
        self.assertEqual(msgs[0]['unique_id']['type'], 'Pragma')
        msgs = U.decode_control(U.BitReader(login.v, login.n, 0), False)
        self.assertEqual({o['key']: o for o in msgs[0]['url_options']}['Token']['base64_decoded'],
                         'secret-token-value')

    def test_detect_magic(self):
        pk = [ue_data_packet(100 + i, 7) for i in range(40)]
        self.assertEqual(U.detect_magic_bits(pk), MAGIC_BITS)

    def test_length_prefixed_strings(self):
        w = BitWriter()
        w.bits(0x15, 5)                  # misalign
        s = b'/Script/WDGame'
        w.bits(len(s), 16)
        w.raw(s)
        w.raw(b'dR')                     # printable junk after the string
        self.assertIn('/Script/WDGame', list(U.length_prefixed_strings(w.v, w.n)))
        self.assertNotIn('/Script/WDGamedR', list(U.length_prefixed_strings(w.v, w.n)))

    def test_flow_analysis(self):
        cookie = struct.pack('<HH', 12590, 1693) + bytes(16)
        rows = [(0.0, 'C', handshake_packet(0, 0.0, bytes(20))),
                (0.02, 'S', handshake_packet(1, 10.0, cookie))]
        t = 0.05
        for i in range(30):
            rows.append((t, 'C', ue_data_packet((1693 + i) & U.SEQ_MASK, 12589 + i)))
            rows.append((t + 0.02, 'S', ue_data_packet(12590 + i, 1693 + i, server=True)))
            t += 0.033
        rep = U.analyze_flow(rows, ('192.168.1.2', 50000), ('54.1.2.3', 7777), self.cfg, Args())
        self.assertEqual(rep['packets'], {'total': 62, 'handshake': 2, 'data': 60, 'unparsed': 0})
        self.assertEqual(rep['handshake'][1]['server_initial_seq'], 12590)
        self.assertEqual(rep['reliability']['server_packets_missing_at_client'], 0)
        self.assertEqual(rep['reliability']['client_packets_nacked_by_server'], 0)
        self.assertEqual(rep['server_frame_time_ms']['p50'], 33)
        self.assertAlmostEqual(rep['rtt_ms_from_acks']['p50'], 20.0, places=3)


if __name__ == '__main__':
    unittest.main()
