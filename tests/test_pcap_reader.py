"""Synthetic classic PCAP fixtures only. No household captures or identifiers."""
import ast
import importlib.util
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('community_pcap_reader', ROOT / 'tools/pcap_reader.py')
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)
TARGET = '192.0.2.20'
PEER = '198.51.100.2'
V6_TARGET = '2001:db8::20'
V6_PEER = '2001:db8::2'


def udp(payload=b'example', length=None):
    return struct.pack('!HHHH', 50000, 9000, 8 + len(payload) if length is None else length, 0) + payload


def tcp(payload=b'example', seq=123, flags=0x18, offset=5, options=b''):
    return struct.pack('!HHIIHHHH', 50000, 9000, seq, 0,
                       (offset << 12) | flags, 4096, 0, 0) + options + payload


def ipv4(payload=None, protocol=17, src=PEER, dst=TARGET, fragment=0, options=b''):
    if payload is None:
        payload = udp()
    ihl = 5 + len(options) // 4
    return struct.pack('!BBHHHBBH4s4s', (4 << 4) | ihl, 0, ihl * 4 + len(payload),
                       1, fragment, 64, protocol, 0, ipaddress.ip_address(src).packed,
                       ipaddress.ip_address(dst).packed) + options + payload


def ipv6(payload=None, protocol=17):
    if payload is None:
        payload = udp()
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), protocol, 64,
                       ipaddress.ip_address(V6_PEER).packed,
                       ipaddress.ip_address(V6_TARGET).packed) + payload


def ethernet(packet, protocol=0x0800, vlan_tags=0):
    frame = b'\x01\x02\x03\x04\x05\x06' * 2
    for _ in range(vlan_tags):
        frame += struct.pack('!HH', 0x8100, 1)
    return frame + struct.pack('!H', protocol) + packet


def pktap(packet, inner=12, version=1, record=1, length=None, endian='<'):
    if version == 1:
        header = bytearray(108 if length is None else length)
        struct.pack_into(endian + 'III', header, 0, len(header), record, inner)
    else:
        header = bytearray(40 if length is None else length)
        header[0] = len(header)
        struct.pack_into(endian + 'H', header, 6, inner)
        struct.pack_into(endian + 'I', header, 36, 0x00080000)
    return bytes(header) + packet


def pcap(records, linktype=101, endian='<', nano=False, snaplen=262144, version=(2, 4)):
    magic = struct.pack(endian + 'I', 0xa1b23c4d if nano else 0xa1b2c3d4)
    output = magic + struct.pack(endian + 'HHiiII', *version, 0, 0, snaplen, linktype)
    for record in records:
        if isinstance(record, tuple):
            data, original = record
        else:
            data, original = record, len(record)
        output += struct.pack(endian + 'IIII', 100, 123456789 if nano else 123456,
                              len(data), original) + data
    return output


class PcapReaderTests(unittest.TestCase):
    def read(self, raw, target=TARGET):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'synthetic.pcap'
            source.write_bytes(raw)
            return reader.read_pcap(source, target)

    def test_tcp_packet_contract_and_flags(self):
        packet = self.read(pcap([ipv4(tcp(b'light', seq=0xffffffff, flags=0x112), protocol=6)]))['packets'][0]
        self.assertEqual(set(packet), {'packet_index', 'timestamp', 'src', 'dst', 'sport',
                                     'dport', 'transport', 'payload', 'seq', 'flags'})
        self.assertEqual(packet['packet_index'], 1)
        self.assertAlmostEqual(packet['timestamp'], 100.123456)
        self.assertEqual((packet['src'], packet['dst'], packet['sport'], packet['dport']),
                         (PEER, TARGET, 50000, 9000))
        self.assertEqual((packet['transport'], packet['payload'], packet['seq'], packet['flags']),
                         ('tcp', b'light', 0xffffffff, 0x112))

    def test_udp_packet_contract(self):
        result = self.read(pcap([ipv4(udp(b'light'))]))
        self.assertEqual(result['format'], 'pcap')
        self.assertEqual((result['packet_count'], result['target_packet_count']), (1, 1))
        packet = result['packets'][0]
        self.assertEqual((packet['transport'], packet['payload'], packet['seq'], packet['flags']),
                         ('udp', b'light', None, 0))
        self.assertEqual(result['issues'], [])

    def test_all_classic_magic_variants_and_timestamp_precision(self):
        for endian in ('<', '>'):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    result = self.read(pcap([ipv4()], endian=endian, nano=nano))
                    self.assertAlmostEqual(result['packets'][0]['timestamp'],
                                           100.123456789 if nano else 100.123456)
                    self.assertEqual(result['timestamp_precision'], 'nanosecond' if nano else 'microsecond')
                    self.assertEqual(result['byte_order'], 'little' if endian == '<' else 'big')

    def test_supported_outer_link_types(self):
        raw = ipv4()
        links = {
            0: struct.pack('<I', 2) + raw,
            1: ethernet(raw),
            12: raw,
            101: raw,
            108: struct.pack('!I', 2) + raw,
            113: struct.pack('!HHH8sH', 0, 1, 6, b'\0' * 8, 0x0800) + raw,
            276: struct.pack('!HHIHBB8s', 0x0800, 0, 1, 1, 0, 6, b'\0' * 8) + raw,
            258: pktap(raw),
        }
        for linktype, packet in links.items():
            with self.subTest(linktype=linktype):
                result = self.read(pcap([packet], linktype))
                self.assertEqual(result['linktype'], linktype)
                self.assertEqual(result['packets'][0]['payload'], b'example')
                self.assertFalse(result['issues'])

    def test_null_family_uses_pcap_byte_order_and_loop_uses_network_order(self):
        for linktype in (0, 108):
            result = self.read(pcap([struct.pack('!I', 2) + ipv4()], linktype, endian='>'))
            self.assertEqual(len(result['packets']), 1)

    def test_ipv6_direct_tcp_and_udp(self):
        for protocol, payload in ((6, tcp()), (17, udp())):
            with self.subTest(protocol=protocol):
                result = self.read(pcap([ipv6(payload, protocol)]), V6_TARGET)
                self.assertEqual(result['packets'][0]['dst'], V6_TARGET)
                self.assertEqual(result['packets'][0]['payload'], b'example')

    def test_ipv6_ethernet_and_bsd_null_families(self):
        self.assertEqual(len(self.read(pcap([ethernet(ipv6(), 0x86dd)], 1), V6_TARGET)['packets']), 1)
        for family in (10, 24, 28, 30):
            with self.subTest(family=family):
                self.assertEqual(len(self.read(pcap([struct.pack('<I', family) + ipv6()], 0),
                                               V6_TARGET)['packets']), 1)

    def test_ethernet_vlan_and_padding_not_returned_as_application_data(self):
        for tags in (1, 2, 4):
            result = self.read(pcap([ethernet(ipv4(), vlan_tags=tags) + b'padding'], 1))
            self.assertEqual(result['packets'][0]['payload'], b'example')
        result = self.read(pcap([ethernet(ipv4(), vlan_tags=5)], 1))
        self.assertIn('VLAN nesting', result['issues'][0])
        self.assertEqual(result['packets'], [])

    def test_pktap_v1_variable_header_and_v2_header(self):
        for packet in (pktap(ipv4(), length=156), pktap(ipv4(), version=2),
                       pktap(ethernet(ipv4()), inner=1, version=2)):
            result = self.read(pcap([packet], 258))
            self.assertEqual(result['packets'][0]['payload'], b'example')
            self.assertEqual(result['issues'], [])

    def test_pktap_little_endian_metadata_is_independent_of_pcap_file_order(self):
        result = self.read(pcap([pktap(ipv4())], 258, endian='>'))
        self.assertEqual(len(result['packets']), 1)

    def test_pktap_unknown_records_links_and_big_endian_not_guessed(self):
        for packet in (pktap(ipv4(), record=2), pktap(ipv4(), inner=999),
                       pktap(ipv4(), inner=258), pktap(ipv4(), endian='>')):
            with self.subTest(prefix=packet[:12]):
                result = self.read(pcap([packet], 258))
                self.assertEqual(result['packets'], [])
                self.assertIn('unsupported', result['issues'][0])

    def test_pktap_short_or_incomplete_headers_are_explicit(self):
        for packet in (b'x' * 20, pktap(ipv4(), length=40), pktap(ipv4())[:60]):
            result = self.read(pcap([packet], 258))
            self.assertEqual(result['packets'], [])
            self.assertTrue(result['issues'])

    def test_non_target_packets_are_not_returned(self):
        packets = [ipv4(dst=PEER, src=PEER), ipv4(src=TARGET, dst=PEER)]
        result = self.read(pcap(packets))
        self.assertEqual(result['packet_count'], 2)
        self.assertEqual(result['target_packet_count'], 1)
        self.assertEqual(result['packets'][0]['packet_index'], 2)

    def test_target_non_transport_ip_is_counted_but_not_returned(self):
        result = self.read(pcap([ipv4(b'not TCP/UDP', protocol=1)]))
        self.assertEqual(result['target_packet_count'], 1)
        self.assertEqual(result['packets'], [])

    def test_non_ip_ethernet_and_unknown_null_family_are_ignored(self):
        self.assertEqual(self.read(pcap([ethernet(b'ARP', 0x0806)], 1))['packets'], [])
        self.assertEqual(self.read(pcap([struct.pack('<I', 1234) + b'unknown'], 0))['packets'], [])

    def test_ipv4_and_tcp_options_are_skipped(self):
        packet = ipv4(tcp(b'example', offset=6, options=b'\x01' * 4), protocol=6,
                      options=b'\x01' * 4)
        self.assertEqual(self.read(pcap([packet]))['packets'][0]['payload'], b'example')

    def test_capture_truncation_does_not_return_partial_payload(self):
        packet = ipv4(tcp(), protocol=6)
        result = self.read(pcap([(packet[:-2], len(packet))]))
        self.assertEqual((result['packet_count'], result['target_packet_count'],
                          result['truncated_packet_count']), (1, 1, 1))
        self.assertEqual(result['packets'], [])
        self.assertTrue(any('truncated' in issue for issue in result['issues']))

    def test_truncated_capture_even_with_complete_ip_bytes_is_not_treated_as_complete(self):
        packet = ipv4()
        result = self.read(pcap([(packet, len(packet) + 4)]))
        self.assertEqual(result['packets'], [])
        self.assertEqual(result['truncated_packet_count'], 1)

    def test_truncated_ip_header_and_declared_lengths_are_counted(self):
        for packet in (ipv4()[:10], ipv4()[:-2], ipv6()[:-2]):
            result = self.read(pcap([packet]), V6_TARGET if packet[0] >> 4 == 6 else TARGET)
            self.assertEqual(result['packets'], [])
            self.assertEqual(result['truncated_packet_count'], 1)

    def test_ipv4_fragments_never_reach_transport_decoder(self):
        for fragment in (0x2000, 1, 0x2001):
            result = self.read(pcap([ipv4(fragment=fragment)]))
            self.assertEqual(result['packets'], [])
            self.assertEqual(result['target_packet_count'], 1)
            self.assertIn('fragmentation', result['issues'][0])
        self.assertEqual(len(self.read(pcap([ipv4(fragment=0x4000)]))['packets']), 1)

    def test_ipv6_extensions_and_fragments_are_not_guessed_as_udp(self):
        for protocol in (0, 43, 44, 50, 51, 60, 135, 139, 140):
            result = self.read(pcap([ipv6(udp(), protocol)]), V6_TARGET)
            self.assertEqual(result['packets'], [])
            self.assertIn('unsupported IPv6 extension', result['issues'][0])

    def test_ipv6_jumbogram_is_explicitly_unsupported(self):
        packet = bytearray(ipv6())
        packet[4:6] = b'\0\0'
        result = self.read(pcap([bytes(packet)]), V6_TARGET)
        self.assertIn('jumbogram', result['issues'][0])
        self.assertEqual(result['packets'], [])

    def test_bad_transport_lengths_do_not_produce_payload(self):
        for packet in (ipv4(tcp(offset=4), protocol=6), ipv4(udp(length=7)),
                       ipv4(udp(length=100)), ipv4(udp(length=8))):
            result = self.read(pcap([packet]))
            self.assertEqual(result['packets'], [])
            self.assertTrue(result['issues'])

    def test_bad_ip_version_header_lengths_and_link_mismatch(self):
        bad_ihl = bytearray(ipv4())
        bad_ihl[0] = 0x44
        bad_length = bytearray(ipv4())
        bad_length[2:4] = b'\0\x0a'
        for packet in (b'\x70' + b'x' * 30, bytes(bad_ihl), bytes(bad_length)):
            result = self.read(pcap([packet]))
            self.assertEqual(result['packets'], [])
            self.assertTrue(result['issues'])
        self.assertIn('does not match', self.read(pcap([ethernet(ipv6())], 1))['issues'][0])

    def test_bad_sll_address_lengths_and_sll2_reserved_field(self):
        sll = struct.pack('!HHH8sH', 0, 1, 9, b'\0' * 8, 0x0800) + ipv4()
        sll2 = struct.pack('!HHIHBB8s', 0x0800, 1, 1, 1, 0, 6, b'\0' * 8) + ipv4()
        for linktype, packet in ((113, sll), (276, sll2)):
            result = self.read(pcap([packet], linktype))
            self.assertEqual(result['packets'], [])
            self.assertIn('invalid Linux SLL', result['issues'][0])

    def test_empty_capture_is_valid(self):
        result = self.read(pcap([]))
        self.assertEqual(result['packet_count'], 0)
        self.assertEqual(result['issues'], [])

    def test_pcapng_and_unknown_magic_have_friendly_errors(self):
        for raw, pattern in ((b'\x0a\x0d\x0d\x0a' + b'x' * 30, 'PCAPNG'),
                             (b'this is not a capture', 'unknown magic'), (b'', 'unknown magic')):
            with self.assertRaisesRegex(reader.PcapError, pattern):
                self.read(raw)

    def test_partial_global_and_record_headers_or_data_fail_closed(self):
        raw = pcap([ipv4()])
        for short in (raw[:10], raw[:25], raw[:39], raw[:-1]):
            with self.subTest(length=len(short)), self.assertRaisesRegex(reader.PcapError, 'truncated'):
                self.read(short)

    def test_unsupported_global_version_linktype_metadata_and_snaplen(self):
        for raw, pattern in ((pcap([], version=(2, 3)), 'version'), (pcap([], linktype=999), 'link type'),
                             (pcap([], linktype=0x01000001), 'metadata'),
                             (pcap([], snaplen=0), 'snapshot'),
                             (pcap([], snaplen=reader.MAX_PACKET_SIZE + 1), 'snapshot')):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(reader.PcapError, pattern):
                self.read(raw)

    def test_bad_record_timestamp_and_lengths_are_errors(self):
        header = pcap([])
        for record, pattern in ((struct.pack('<IIII', 1, 1000000, 0, 0), 'timestamp'),
                                (struct.pack('<IIII', 1, 0, 10, 9), 'lengths'),
                                (struct.pack('<IIII', 1, 0, 1, reader.MAX_PACKET_SIZE + 1), 'packet limit')):
            with self.assertRaisesRegex(reader.PcapError, pattern):
                self.read(header + record)
        with self.assertRaisesRegex(reader.PcapError, 'lengths'):
            self.read(pcap([], snaplen=10) + struct.pack('<IIII', 1, 0, 11, 11))

    def test_resource_limits_are_enforced_without_allocating_large_fixtures(self):
        with mock.patch.object(reader, 'MAX_PACKETS', 1):
            with self.assertRaisesRegex(reader.PcapError, 'packet limit'):
                self.read(pcap([ipv4(), ipv4()]))
        with mock.patch.object(reader, 'MAX_FILE_SIZE', 30):
            with self.assertRaisesRegex(reader.PcapError, 'file limit'):
                self.read(pcap([ipv4()]))
        with mock.patch.object(reader, 'MAX_PACKET_SIZE', 100):
            with self.assertRaisesRegex(reader.PcapError, 'snapshot'):
                self.read(pcap([]))

    def test_issue_list_is_bounded(self):
        with mock.patch.object(reader, 'MAX_ISSUES', 2):
            result = self.read(pcap([b'\x70'] * 5))
            self.assertEqual(len(result['issues']), 3)
            self.assertIn('3 further packet issues suppressed', result['issues'][-1])

    def test_target_must_be_literal_and_local_file_must_be_regular(self):
        for target in (None, 1, '', 'example.test', V6_TARGET + '%en0'):
            with self.subTest(target=target), self.assertRaisesRegex(reader.PcapError, 'literal'):
                self.read(pcap([]), target)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(reader.PcapError, 'regular'):
                reader.read_pcap(directory, TARGET)
            with self.assertRaisesRegex(reader.PcapError, 'cannot read'):
                reader.read_pcap(Path(directory) / 'missing.pcap', TARGET)

    def test_no_network_device_or_subprocess_dependencies(self):
        source = (ROOT / 'tools/pcap_reader.py').read_text()
        tree = ast.parse(source)
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module)
        self.assertTrue(set(names) <= {'__future__', 'ipaddress', 'os', 'pathlib', 'stat', 'struct'})
        self.assertNotIn('subprocess', names)
        self.assertNotIn('socket', names)


if __name__ == '__main__':
    unittest.main()
