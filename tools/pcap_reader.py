"""Bounded, read-only classic PCAP reader for one explicitly supplied IP.

Only complete TCP/UDP packets are returned. This module does not reassemble
TCP or IP, verify checksums, decrypt traffic, or interpret vendor commands.
``target_packet_count`` counts packets whose readable IP header matches the
target, including omitted fragmented/truncated/non-TCP/UDP packets.

Format references (structure facts, independently implemented here):
https://github.com/the-tcpdump-group/libpcap/blob/master/sf-pcap.c
https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pktap.h
https://github.com/the-tcpdump-group/tcpdump/blob/master/print-pktap.c

PKTAP metadata is interpreted as little endian, as in tcpdump's documented
implementation. Unknown PKTAP record types/inner link types are omitted with
an issue; metadata itself is never included in the returned packet records.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import stat
import struct

MAX_FILE_SIZE = 128 * 1024 * 1024
MAX_PACKET_SIZE = 1024 * 1024
MAX_PACKETS = 200000
MAX_ISSUES = 1000
SUPPORTED_LINKTYPES = frozenset((0, 1, 12, 101, 108, 113, 258, 276))
_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1000000, 'microsecond'),
    b'\xa1\xb2\xc3\xd4': ('>', 1000000, 'microsecond'),
    b'\x4d\x3c\xb2\xa1': ('<', 1000000000, 'nanosecond'),
    b'\xa1\xb2\x3c\x4d': ('>', 1000000000, 'nanosecond'),
}


class PcapError(ValueError):
    """The supplied local capture cannot be safely read as classic PCAP."""


class _PacketIssue(Exception):
    def __init__(self, message, truncated=False):
        super().__init__(message)
        self.truncated = truncated


def _require(data, size, name):
    if len(data) < size:
        raise _PacketIssue('truncated ' + name, truncated=True)


def _ethernet_payload(data):
    _require(data, 14, 'Ethernet header')
    protocol = struct.unpack_from('!H', data, 12)[0]
    offset = 14
    tags = 0
    while protocol in (0x8100, 0x88a8, 0x9100):
        tags += 1
        if tags > 4:
            raise _PacketIssue('unsupported Ethernet VLAN nesting')
        _require(data, offset + 4, 'Ethernet VLAN header')
        protocol = struct.unpack_from('!H', data, offset + 2)[0]
        offset += 4
    return (data[offset:], protocol)


def _link_payload(data, linktype, byteorder, depth=0):
    """Return (IP bytes, expected IP version) or None for non-IP traffic."""
    if depth > 1:
        raise _PacketIssue('unsupported nested PKTAP headers')
    if linktype in (12, 101):
        _require(data, 1, 'raw IP header')
        version = data[0] >> 4
        if version not in (4, 6):
            raise _PacketIssue('invalid raw IP version')
        return data, version
    if linktype in (0, 108):
        _require(data, 4, 'NULL/LOOP header')
        order = '>' if linktype == 108 else byteorder
        family = struct.unpack_from(order + 'I', data)[0]
        # IPv6 address-family values differ between BSD operating systems.
        version = 4 if family == 2 else 6 if family in (10, 24, 28, 30) else None
        return (data[4:], version) if version else None
    if linktype == 1:
        data, protocol = _ethernet_payload(data)
    elif linktype == 113:
        _require(data, 16, 'Linux SLL header')
        if struct.unpack_from('!H', data, 4)[0] > 8:
            raise _PacketIssue('invalid Linux SLL address length')
        protocol = struct.unpack_from('!H', data, 14)[0]
        data = data[16:]
    elif linktype == 276:
        _require(data, 20, 'Linux SLL2 header')
        if data[2:4] != b'\0\0' or data[11] > 8:
            raise _PacketIssue('invalid Linux SLL2 header')
        protocol = struct.unpack_from('!H', data)[0]
        data = data[20:]
    elif linktype == 258:
        _require(data, 40, 'PKTAP header')
        flags = struct.unpack_from('<I', data, 36)[0]
        if flags & 0x00080000:
            header_length = data[0]
            inner_type = struct.unpack_from('<H', data, 6)[0]
            minimum = 40
        else:
            header_length, record_type, inner_type = struct.unpack_from('<III', data)
            minimum = 108  # Includes all fields in the original v1 header.
            if record_type != 1:
                raise _PacketIssue('unsupported PKTAP record type %d' % record_type)
        if header_length < minimum:
            raise _PacketIssue('invalid/unsupported PKTAP header length or byte order')
        _require(data, header_length, 'PKTAP metadata')
        if inner_type not in SUPPORTED_LINKTYPES or inner_type == 258:
            raise _PacketIssue('unsupported PKTAP inner link type %d' % inner_type)
        # PKTAP contains the indicated link-layer packet, not an IP offset to guess.
        return _link_payload(data[header_length:], inner_type, '<', depth + 1)
    else:
        raise _PacketIssue('unsupported link type %d' % linktype)
    version = 4 if protocol == 0x0800 else 6 if protocol == 0x86dd else None
    return (data, version) if version else None


def _network_packet(data, expected_version, target, context):
    _require(data, 1, 'IP header')
    version = data[0] >> 4
    if version != expected_version:
        raise _PacketIssue('IP version does not match link-layer protocol')
    if version == 4:
        _require(data, 20, 'IPv4 header')
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        context['target'] = target in (src, dst)
        header_length = (data[0] & 15) * 4
        total_length = struct.unpack_from('!H', data, 2)[0]
        if header_length < 20 or total_length < header_length:
            raise _PacketIssue('invalid IPv4 header/total length')
        _require(data, header_length, 'IPv4 options/header')
        _require(data, total_length, 'IPv4 packet')
        if struct.unpack_from('!H', data, 6)[0] & 0x3fff:
            raise _PacketIssue('unsupported IPv4 fragmentation; no reassembly attempted')
        protocol = data[9]
    else:
        _require(data, 40, 'IPv6 header')
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        context['target'] = target in (src, dst)
        payload_length = struct.unpack_from('!H', data, 4)[0]
        protocol = data[6]
        header_length = 40
        total_length = 40 + payload_length
        if payload_length == 0 and protocol != 59:
            raise _PacketIssue('unsupported IPv6 zero payload length/jumbogram')
        _require(data, total_length, 'IPv6 packet')
        if protocol in (0, 43, 44, 50, 51, 60, 135, 139, 140):
            raise _PacketIssue('unsupported IPv6 extension/fragment header %d' % protocol)
    if context['truncated'] or not context['target'] or protocol not in (6, 17):
        return None
    transport_data = data[header_length:total_length]
    if protocol == 6:
        _require(transport_data, 20, 'TCP header')
        sport, dport, seq = struct.unpack_from('!HHI', transport_data)
        transport_header_length = (transport_data[12] >> 4) * 4
        if transport_header_length < 20:
            raise _PacketIssue('invalid TCP data offset')
        _require(transport_data, transport_header_length, 'TCP options/header')
        flags = ((transport_data[12] & 1) << 8) | transport_data[13]
        payload = transport_data[transport_header_length:]
        transport = 'tcp'
    else:
        _require(transport_data, 8, 'UDP header')
        sport, dport, length = struct.unpack_from('!HHH', transport_data)
        if length < 8:
            raise _PacketIssue('invalid UDP length')
        if length != len(transport_data):
            raise _PacketIssue('UDP length does not match IP payload')
        payload = transport_data[8:length]
        seq, flags, transport = None, 0, 'udp'
    return {'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
            'transport': transport, 'payload': payload, 'seq': seq, 'flags': flags}


def read_pcap(path, target_ip):
    """Read a regular classic PCAP file without contacting the target IP.

    PCAPNG, unknown global link types, corrupt record boundaries and resource
    limit violations raise PcapError. Packet-level unsupported/malformed data
    is omitted and reported in ``issues``. Capture truncation is counted once
    per packet; no partial payload is returned. All counts are file-wide.
    """
    try:
        if not isinstance(target_ip, str) or '%' in target_ip:
            raise ValueError
        target = str(ipaddress.ip_address(target_ip))
    except ValueError:
        raise PcapError('target_ip must be an IPv4 or IPv6 literal, without a zone ID') from None
    path = Path(path)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PcapError('PCAP input must be a regular local file')
        if info.st_size > MAX_FILE_SIZE:
            raise PcapError('PCAP exceeds the 128 MiB file limit')
        with path.open('rb') as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_FILE_SIZE:
                raise PcapError('PCAP input changed or exceeds the file limit')
            return _read_stream(source, target)
    except OSError:
        raise PcapError('cannot read the local PCAP file') from None


def _read_stream(source, target):
    header = source.read(24)
    if header[:4] == b'\x0a\x0d\x0d\x0a':
        raise PcapError('PCAPNG is not supported; export as classic PCAP first')
    if header[:4] not in _MAGIC:
        raise PcapError('not a supported classic PCAP file (unknown magic)')
    if len(header) != 24:
        raise PcapError('truncated PCAP global header')
    order, scale, precision = _MAGIC[header[:4]]
    major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(order + 'HHiiII', header[4:])
    if (major, minor) != (2, 4):
        raise PcapError('unsupported PCAP version; expected 2.4')
    if not 0 < snaplen <= MAX_PACKET_SIZE:
        raise PcapError('invalid/unsupported PCAP snapshot length (limit 1 MiB)')
    # Upper network bits can describe FCS metadata; leave unsupported semantics explicit.
    if network & 0xffff0000:
        raise PcapError('unsupported PCAP link-type/FCS metadata bits')
    if network not in SUPPORTED_LINKTYPES:
        raise PcapError('unsupported PCAP link type %d' % network)
    result = {'format': 'pcap', 'linktype': network, 'packet_count': 0,
              'target_packet_count': 0, 'truncated_packet_count': 0,
              'issues': [], 'packets': [], 'timestamp_precision': precision,
              'byte_order': 'little' if order == '<' else 'big'}
    consumed = 24
    suppressed = 0

    def issue(index, message):
        nonlocal suppressed
        if len(result['issues']) < MAX_ISSUES:
            result['issues'].append('packet %d: %s' % (index, message))
        else:
            suppressed += 1

    while True:
        record = source.read(16)
        if not record:
            break
        if len(record) != 16:
            raise PcapError('truncated PCAP record header')
        if result['packet_count'] >= MAX_PACKETS:
            raise PcapError('PCAP exceeds the 200000 packet limit')
        seconds, fraction, included, original = struct.unpack(order + 'IIII', record)
        if fraction >= scale:
            raise PcapError('invalid PCAP timestamp fraction')
        if included > MAX_PACKET_SIZE or original > MAX_PACKET_SIZE:
            raise PcapError('PCAP record exceeds the 1 MiB packet limit')
        if included > original or included > snaplen:
            raise PcapError('invalid PCAP captured/original/snapshot lengths')
        consumed += 16 + included
        if consumed > MAX_FILE_SIZE:
            raise PcapError('PCAP exceeds the 128 MiB file limit')
        data = source.read(included)
        if len(data) != included:
            raise PcapError('truncated PCAP record data (file incomplete)')
        result['packet_count'] += 1
        index = result['packet_count']
        context = {'target': False, 'truncated': included < original}
        if context['truncated']:
            issue(index, 'capture truncated; partial packet payload omitted')
        try:
            linked = _link_payload(data, network, order)
            packet = _network_packet(*linked, target, context) if linked else None
            if packet is not None:
                packet.update(packet_index=index, timestamp=seconds + fraction / scale)
                result['packets'].append(packet)
        except _PacketIssue as problem:
            context['truncated'] = context['truncated'] or problem.truncated
            issue(index, str(problem))
        result['target_packet_count'] += int(context['target'])
        result['truncated_packet_count'] += int(context['truncated'])
    if suppressed:
        result['issues'].append('%d further packet issues suppressed (limit %d)' %
                                (suppressed, MAX_ISSUES))
    return result
