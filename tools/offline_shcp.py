#!/usr/bin/env python3
"""Offline plaintext SHCP research codec. No sockets, capture, upload or replay.

Only the explicitly described plaintext branch is supported. Encrypted frames,
authentication and household compatibility remain unverified. Inputs are raw
application payloads, not PCAP files. Constructed bytes never leave this process.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import struct
import uuid

PROTOCOL_NAME = b'dooyashcp'
MIN_FRAME_SIZE = 20
MAX_FRAME_SIZE = 65538

class ParseError(ValueError):
    """Unsupported plaintext frame, inconsistent length or ambiguous semantics."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ParseError(message)


def _raw_bytes(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ParseError(f'{name} must be explicit bytes')
    return bytes(value)


def _unsigned(value, maximum: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ParseError(f'{name} must be an integer in 0..{maximum}')
    return value


def parse_frame(data: bytes) -> dict:
    """Parse exactly one plaintext frame, preserving all TLVs and duplicates.

    Field values stay raw hexadecimal. A repeated type is legal in a device-list
    frame and is reported, never silently collapsed into a dictionary.
    """
    raw = _raw_bytes(data, 'frame')
    _require(len(raw) >= MIN_FRAME_SIZE, 'truncated frame: fewer than 20 bytes')
    _require(len(raw) <= MAX_FRAME_SIZE, 'frame exceeds u16 length capacity')
    _require(raw[0] == 0x23, 'invalid start flag')
    _require(raw[-1] == 0x23, 'invalid end flag')
    length = struct.unpack_from('<H', raw, 1)[0]
    _require(length >= 17, 'declared length smaller than fixed frame content')
    _require(length + 3 == len(raw), 'declared length differs from exact frame size')
    _require(raw[3:12] == PROTOCOL_NAME, 'unsupported plaintext protocol signature')
    data_length = struct.unpack_from('<H', raw, 17)[0]
    _require(data_length == length - 17 == len(raw) - MIN_FRAME_SIZE,
             'data length disagrees with frame length')
    fields = []
    cursor = 19
    body_end = len(raw) - 1
    while cursor < body_end:
        _require(cursor + 4 <= body_end, f'truncated TLV header at {cursor}')
        field_id, value_length = struct.unpack_from('<HH', raw, cursor)
        end = cursor + 4 + value_length
        _require(end <= body_end, f'TLV {field_id} value exceeds data boundary')
        fields.append({'id': field_id, 'length': value_length, 'offset': cursor,
                       'value_hex': raw[cursor + 4:end].hex()})
        cursor = end
    counts = Counter(field['id'] for field in fields)
    return {
        'scope': 'public plaintext SHCP candidate; home compatibility unverified',
        'length': length, 'full_length': len(raw), 'protocol_name': 'dooyashcp',
        'protocol_number': raw[12], 'protocol_type': raw[13], 'link_code': raw[14],
        'serial_number': struct.unpack_from('<H', raw, 15)[0],
        'data_length': data_length, 'fields': fields,
        'repeated_field_ids': sorted(k for k, count in counts.items() if count > 1),
    }


def unique_field(fields: list[dict], field_id: int, *, required: bool = False):
    """Return one TLV; reject ambiguity rather than selecting first or last."""
    matches = [field for field in fields if field['id'] == field_id]
    _require(len(matches) <= 1, f'duplicate TLV {field_id} in one semantic record')
    _require(bool(matches) or not required, f'missing required TLV {field_id}')
    return matches[0] if matches else None


def field_bytes(field: dict) -> bytes:
    return bytes.fromhex(field['value_hex'])


def build_frame(protocol_number: int, protocol_type: int, link_code: int,
                serial_number: int, fields: list[tuple[int, bytes]]) -> bytes:
    """Construct local bytes only; no transport exists in this module."""
    for name, value in [('protocol_number', protocol_number),
                        ('protocol_type', protocol_type), ('link_code', link_code)]:
        _unsigned(value, 255, name)
    _unsigned(serial_number, 65535, 'serial_number')
    body = bytearray()
    for field_id, value in fields:
        _unsigned(field_id, 65535, 'TLV type')
        raw = _raw_bytes(value, 'TLV value')
        _require(len(raw) <= 65535, 'TLV value exceeds u16 length capacity')
        body.extend(struct.pack('<HH', field_id, len(raw)))
        body.extend(raw)
    _require(len(body) <= 65535 - 17, 'data area exceeds frame length capacity')
    return (b'\x23' + struct.pack('<H', 17 + len(body)) + PROTOCOL_NAME
            + bytes([protocol_number, protocol_type, link_code])
            + struct.pack('<HH', serial_number, len(body)) + bytes(body) + b'\x23')


def build_candidate_light_frame(device_identifier: bytes, is_on: bool,
                                serial_number: int = 0) -> bytes:
    """Reproduce a public sample layout using an explicit 8-byte identifier.

    Accepting bytes does not validate an identifier for the home. There is no
    implicit conversion from configuration references or integer device keys.
    """
    device = _raw_bytes(device_identifier, 'device_identifier')
    _require(len(device) == 8, 'candidate Device_Mac must have exactly 8 bytes')
    _require(type(is_on) is bool, 'is_on must be an explicit boolean')
    return build_frame(1, 4, 9, serial_number,
                       [(16, b'\x01'), (4, device),
                        (9, b'light-on' if is_on else b'light-off')])


def read_state_records(packet: dict, *,
                       confirmed_ordinary_light_identifiers: tuple[bytes, ...] = ()) -> list[dict]:
    """Read raw state 11 for each device in a public update/query response.

    Only explicitly identified ordinary lights in device-detail responses or
    server updates with TLV 27=3 receive the bit-0 on/off interpretation. Other
    update categories retain raw status without guessing. Upper flags have
    unknown meaning. This does not establish the physical source of the status.
    """
    _require(packet['protocol_number'] == 1, 'unsupported protocol number for states')
    kind = (packet['protocol_type'], packet['link_code'])
    _require(kind in ((5, 12), (3, 8)), 'packet is not a candidate state response')
    ordinary_identifiers = set()
    for identifier in confirmed_ordinary_light_identifiers:
        raw_identifier = _raw_bytes(identifier, 'ordinary-light identifier')
        _require(len(raw_identifier) == 8, 'ordinary-light identifier must have 8 bytes')
        ordinary_identifiers.add(raw_identifier.hex())
    if kind == (3, 8):
        request = unique_field(packet['fields'], 15, required=True)
        _require(field_bytes(request) == b'\x04', 'response is not device details')
        status_context = {'packet_kind': 'device_details', 'datareq_type': 4,
                          'device_status_context_confirmed': True,
                          'reason': 'device-details response 3/8 and TLV 15=4'}
    else:
        update = unique_field(packet['fields'], 27)
        if update is not None:
            _require(update['length'] == 1, 'candidate update category must have one byte')
        update_kind = field_bytes(update)[0] if update is not None else None
        status_context = {'packet_kind': 'server_update', 'update_kind': update_kind,
                          'update_kind_raw_hex': update['value_hex'] if update else None,
                          'device_status_context_confirmed': update_kind == 3,
                          'reason': 'device update TLV 27=3' if update_kind == 3 else
                              'missing or other update category; raw fields only'}
    groups = []
    current = None
    for item in packet['fields']:
        _require(item['id'] != 11 or current is not None,
                 'orphan state TLV precedes its device identifier')
        if item['id'] == 4:
            if current is not None:
                groups.append(current)
            current = [item]
        elif current is not None and item['id'] not in (15, 17, 148):
            current.append(item)
    if current is not None:
        groups.append(current)
    result = []
    for fields in groups:
        device = unique_field(fields, 4, required=True)
        _require(device['length'] == 8, 'Device_Mac must have exactly 8 bytes')
        state = unique_field(fields, 11)
        state_raw = field_bytes(state) if state else None
        state_value = state_raw[0] if state_raw is not None and len(state_raw) == 1 else None
        if state is not None:
            _require(len(state_raw) == 1, 'candidate Device_State must have one byte')
        name = unique_field(fields, 6)
        name_text = None
        if name is not None:
            try:
                name_text = field_bytes(name).decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ParseError('invalid UTF-8 device name') from exc
        ordinary_light = device['value_hex'] in ordinary_identifiers
        result.append({
            'device_identifier_hex': device['value_hex'], 'device_name': name_text,
            'raw_state': state_value,
            'device_type_context': 'ordinary_light' if ordinary_light else 'unconfirmed',
            'status_context': dict(status_context),
            'candidate_is_on': bool(state_value & 1)
                if ordinary_light and state_value is not None
                and status_context['device_status_context_confirmed'] else None,
            'upper_status_flags_unknown': state_value & 0xfe
                if ordinary_light and state_value is not None else None,
            'state_present': state is not None, 'fields': fields,
            'repeated_field_ids': sorted(k for k, count in
                                        Counter(f['id'] for f in fields).items() if count > 1),
            'physical_feedback_verified': False,
        })
    return result


class FrameStreamDecoder:
    """Strict incremental plaintext splitting; never scans/resynchronizes silently."""
    def __init__(self, max_frame_size: int = MAX_FRAME_SIZE):
        _unsigned(max_frame_size, MAX_FRAME_SIZE, 'max_frame_size')
        _require(max_frame_size >= MIN_FRAME_SIZE, 'maximum frame size below minimum')
        self.max_frame_size = max_frame_size
        self.pending = bytearray()
        self.failed = False

    def feed(self, chunk: bytes) -> list[dict]:
        _require(not self.failed, 'decoder failed previously; create a new decoder')
        self.pending.extend(_raw_bytes(chunk, 'stream chunk'))
        frames = []
        try:
            while self.pending:
                _require(self.pending[0] == 0x23, 'stream start flag invalid; no resync')
                if len(self.pending) < 3:
                    break
                full_length = struct.unpack_from('<H', self.pending, 1)[0] + 3
                _require(MIN_FRAME_SIZE <= full_length <= self.max_frame_size,
                         'stream declares unsupported frame length')
                if len(self.pending) < full_length:
                    break
                frames.append(parse_frame(bytes(self.pending[:full_length])))
                del self.pending[:full_length]
        except ParseError:
            self.failed = True
            raise
        return frames

    def finish(self) -> None:
        _require(not self.failed, 'decoder failed previously')
        _require(not self.pending, f'truncated stream: {len(self.pending)} trailing bytes')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hex-file', required=True, type=Path,
        help='local UTF-8 HEX of reassembled plaintext application payload; not a PCAP')
    args = parser.parse_args(argv)
    try:
        raw = bytes.fromhex(args.hex_file.read_text(encoding='utf-8'))
        decoder = FrameStreamDecoder()
        packets = decoder.feed(raw)
        decoder.finish()
        if not packets:
            raise ParseError('empty application payload')
    except (OSError, ValueError) as error:
        parser.exit(2, 'No output generated: {}\n'.format(error))
    root = Path(__file__).resolve().parents[1] / 'private_reports'
    root.mkdir(mode=0o700, exist_ok=True)
    name = datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    destination = root / (name + '.json')
    data = {'scope':'local offline plaintext parse; not household validation',
            'frame_count':len(packets), 'frames':packets,
            'physical_feedback_verified':False, 'bytes_sent':0}
    descriptor = destination.open('x', encoding='utf-8')
    try:
        import os
        os.chmod(destination, 0o600)
        json.dump(data, descriptor, ensure_ascii=False, indent=2)
        descriptor.write('\n')
    finally:
        descriptor.close()
    print('Parsed {} frames locally; private report: {}'.format(len(packets), destination))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
