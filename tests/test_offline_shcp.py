"""Synthetic-only offline frame and state tests. No captured household data."""
import ast
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('community_codec',ROOT/'tools/offline_shcp.py')
codec=importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
SAMPLE_IDENTIFIER=bytes.fromhex('0102030405060708')  # Synthetic; not an address to send.

def state_frame(status=None, *, extra_fields=()):
    fields=[(27,b'\x03'),(4,SAMPLE_IDENTIFIER),(6,'合成测试灯'.encode('utf-8'))]
    if status is not None:fields.append((11,bytes([status])))
    fields.extend(extra_fields)
    return codec.build_frame(1,5,12,0,fields)

class FrameValidationTests(unittest.TestCase):
    def setUp(self):
        self.frame = codec.build_candidate_light_frame(SAMPLE_IDENTIFIER, True, 226)

    def change(self, offset, value):
        result = bytearray(self.frame)
        result[offset:offset + len(value)] = value
        return bytes(result)

    def test_every_proper_prefix_is_rejected_as_truncated(self):
        for length in range(len(self.frame)):
            with self.subTest(length=length), self.assertRaises(codec.ParseError):
                codec.parse_frame(self.frame[:length])

    def test_bad_start_and_end_flags(self):
        for data in [self.change(0, b'!'), self.change(len(self.frame) - 1, b'!')]:
            with self.assertRaises(codec.ParseError):
                codec.parse_frame(data)

    def test_declared_frame_length_too_small_or_large(self):
        for delta in (-1, 1):
            length = struct.unpack_from('<H', self.frame, 1)[0] + delta
            with self.assertRaises(codec.ParseError):
                codec.parse_frame(self.change(1, struct.pack('<H', length)))

    def test_declared_data_length_must_match_body(self):
        value = struct.unpack_from('<H', self.frame, 17)[0]
        for length in [0, value - 1, value + 1, 65535]:
            with self.assertRaises(codec.ParseError):
                codec.parse_frame(self.change(17, struct.pack('<H', length)))

    def test_unknown_protocol_signature_rejected(self):
        with self.assertRaises(codec.ParseError):
            codec.parse_frame(self.change(3, b'MOORGEN!!'))

    def test_exact_parser_rejects_trailing_bytes_and_glued_frames(self):
        for data in [self.frame + b'\x00', self.frame + self.frame]:
            with self.assertRaises(codec.ParseError):
                codec.parse_frame(data)

    def test_tlv_value_cannot_consume_end_marker(self):
        with self.assertRaises(codec.ParseError):
            codec.parse_frame(self.change(21, b'\xff\xff'))

    def test_truncated_tlv_header_rejected(self):
        # A structurally complete 21-byte frame whose data area has only one byte.
        malformed = b'\x23\x12\x00dooyashcp\x01\x05\x0c\x00\x00\x01\x00\x0b\x23'
        with self.assertRaisesRegex(codec.ParseError, 'TLV header'):
            codec.parse_frame(malformed)

    def test_unknown_and_duplicate_tlvs_preserved_in_order(self):
        packet = codec.parse_frame(codec.build_frame(1, 3, 8, 0,
            [(60000, b'\x00\xff'), (60000, b'other'), (7, b'')]))
        self.assertEqual([f['id'] for f in packet['fields']], [60000, 60000, 7])
        self.assertEqual([f['value_hex'] for f in packet['fields']], ['00ff', '6f74686572', ''])
        self.assertEqual(packet['repeated_field_ids'], [60000])
        with self.assertRaisesRegex(codec.ParseError, 'duplicate'):
            codec.unique_field(packet['fields'], 60000)

    def test_explicit_identifier_required_and_internal_reference_rejected(self):
        for identifier in [0x1234, b'\x34\x12\x00\x00', '0102030405060708', b'123456789']:
            with self.subTest(identifier=identifier), self.assertRaises(codec.ParseError):
                codec.build_candidate_light_frame(identifier, True)
        for state in [1, 0, None, 'on']:
            with self.assertRaises(codec.ParseError):
                codec.build_candidate_light_frame(SAMPLE_IDENTIFIER, state)

    def test_out_of_range_header_and_oversize_body_rejected(self):
        for args in [(256, 4, 9, 0), (1, -1, 9, 0), (1, 4, 9, 65536)]:
            with self.assertRaises(codec.ParseError):
                codec.build_frame(*args, [])
        with self.assertRaises(codec.ParseError):
            codec.build_frame(1, 4, 9, 0, [(4, b'x' * 65519)])
        with self.assertRaises(codec.ParseError):
            codec.build_frame(1, 4, 9, 0, [(65536, b'')])

class StreamTests(unittest.TestCase):
    def setUp(self):
        self.frames = [codec.build_candidate_light_frame(SAMPLE_IDENTIFIER, True, 226),
                       state_frame(1), codec.build_candidate_light_frame(SAMPLE_IDENTIFIER, False, 228),
                       state_frame(0)]

    def test_concatenated_frames_split_without_loss(self):
        stream = codec.FrameStreamDecoder()
        result = stream.feed(b''.join(self.frames))
        stream.finish()
        self.assertEqual([r['full_length'] for r in result], [len(f) for f in self.frames])

    def test_every_two_part_split_and_empty_chunks(self):
        raw = b''.join(self.frames)
        expected = [codec.parse_frame(f) for f in self.frames]
        for offset in range(len(raw) + 1):
            stream = codec.FrameStreamDecoder()
            result = stream.feed(raw[:offset]) + stream.feed(b'') + stream.feed(raw[offset:])
            stream.finish()
            self.assertEqual(result, expected, offset)

    def test_one_byte_fragmentation(self):
        stream = codec.FrameStreamDecoder()
        result = []
        for byte in b''.join(self.frames):
            result.extend(stream.feed(bytes([byte])))
        stream.finish()
        self.assertEqual(len(result), 4)

    def test_unfinished_stream_is_reported(self):
        for suffix in [b'\x23', b'\x23\x11', self.frames[0][:-1]]:
            stream = codec.FrameStreamDecoder()
            stream.feed(suffix)
            with self.assertRaisesRegex(codec.ParseError, 'truncated stream'):
                stream.finish()

    def test_garbage_is_never_silently_resynchronized(self):
        stream = codec.FrameStreamDecoder()
        with self.assertRaisesRegex(codec.ParseError, 'no resync'):
            stream.feed(b'garbage' + self.frames[0])
        with self.assertRaisesRegex(codec.ParseError, 'failed previously'):
            stream.feed(self.frames[0])

    def test_bad_length_and_bad_end_fail_closed(self):
        for raw in [b'\x23\x00\x00', self.frames[0][:-1] + b'!']:
            stream = codec.FrameStreamDecoder()
            with self.assertRaises(codec.ParseError):
                stream.feed(raw)
            self.assertTrue(stream.failed)

    def test_configured_maximum_frame_size(self):
        stream = codec.FrameStreamDecoder(max_frame_size=20)
        with self.assertRaises(codec.ParseError):
            stream.feed(self.frames[0][:3])

class StateSemanticsTests(unittest.TestCase):
    def decode(self, raw, *, ordinary=True):
        return codec.read_state_records(codec.parse_frame(raw),
            confirmed_ordinary_light_identifiers=(SAMPLE_IDENTIFIER,) if ordinary else ())

    def test_ordinary_light_uses_bit_zero_and_preserves_other_flags(self):
        for status in [0, 1, 2, 3, 254, 255]:
            with self.subTest(status=status):
                record = self.decode(state_frame(status))[0]
                self.assertEqual(record['raw_state'], status)
                self.assertEqual(record['candidate_is_on'], bool(status & 1))
                self.assertEqual(record['upper_status_flags_unknown'], status & 0xfe)
                self.assertFalse(record['physical_feedback_verified'])

    def test_unconfirmed_device_type_does_not_get_light_interpretation(self):
        for status in [0, 1, 2, 3]:
            record = self.decode(state_frame(status), ordinary=False)[0]
            self.assertEqual(record['raw_state'], status)
            self.assertIsNone(record['candidate_is_on'])
            self.assertIsNone(record['upper_status_flags_unknown'])

    def test_push_update_category_must_be_device_update_three(self):
        for update_kind in [None, 1, 2, 7, 255]:
            with self.subTest(update_kind=update_kind):
                fields = [] if update_kind is None else [(27, bytes([update_kind]))]
                fields.extend([(4, SAMPLE_IDENTIFIER), (11, b'\x01')])
                record = self.decode(codec.build_frame(1, 5, 12, 0, fields))[0]
                self.assertEqual(record['raw_state'], 1)
                self.assertIsNone(record['candidate_is_on'])
                self.assertEqual(record['status_context']['update_kind'], update_kind)
                self.assertFalse(record['status_context']['device_status_context_confirmed'])

    def test_duplicate_or_wide_update_category_rejected(self):
        for categories in [[(27, b'\x03'), (27, b'\x02')], [(27, b'\x03\x00')]]:
            with self.assertRaises(codec.ParseError):
                self.decode(codec.build_frame(1, 5, 12, 0,
                    categories + [(4, SAMPLE_IDENTIFIER), (11, b'\x01')]))

    def test_device_detail_context_allows_explicit_ordinary_light_bit_zero(self):
        raw = codec.build_frame(1, 3, 8, 0,
            [(15, b'\x04'), (17, b'\x01'), (4, SAMPLE_IDENTIFIER), (11, b'\x03'), (148, b'\x01')])
        record = self.decode(raw)[0]
        self.assertTrue(record['candidate_is_on'])
        self.assertEqual(record['status_context']['packet_kind'], 'device_details')

    def test_missing_status_remains_unknown(self):
        record = self.decode(state_frame())[0]
        self.assertIsNone(record['raw_state'])
        self.assertIsNone(record['candidate_is_on'])
        self.assertFalse(record['state_present'])

    def test_duplicate_status_in_same_device_rejected(self):
        with self.assertRaisesRegex(codec.ParseError, 'duplicate TLV 11'):
            self.decode(state_frame(1, extra_fields=[(11, b'\x00')]))

    def test_orphan_state_cannot_be_silently_discarded(self):
        with self.assertRaisesRegex(codec.ParseError, 'orphan state'):
            self.decode(codec.build_frame(1, 5, 12, 0,
                [(11, b'\x01'), (4, SAMPLE_IDENTIFIER), (11, b'\x00')]))

    def test_repeated_unknown_fields_are_preserved_inside_one_device(self):
        record = self.decode(state_frame(1, extra_fields=[(60000, b'a'), (60000, b'b')]))[0]
        self.assertEqual([f['value_hex'] for f in record['fields'] if f['id'] == 60000], ['61', '62'])
        self.assertEqual(record['repeated_field_ids'], [60000])

    def test_repeated_devices_preserve_each_record(self):
        raw = codec.build_frame(1, 5, 12, 0,
            [(4, SAMPLE_IDENTIFIER), (11, b'\x01'), (60000, b'first'),
             (4, SAMPLE_IDENTIFIER), (11, b'\x00'), (60000, b'second')])
        records = self.decode(raw)
        self.assertEqual([d['raw_state'] for d in records], [1, 0])
        self.assertEqual([d['fields'][-1]['value_hex'] for d in records],
                         [b'first'.hex(), b'second'.hex()])

    def test_bad_status_width_and_bad_identifier_width_rejected(self):
        for fields in [[(4, SAMPLE_IDENTIFIER), (11, b'')],
                       [(4, SAMPLE_IDENTIFIER), (11, b'\x01\x00')],
                       [(4, b'\x34\x12\x00\x00'), (11, b'\x01')]]:
            with self.assertRaises(codec.ParseError):
                self.decode(codec.build_frame(1, 5, 12, 0, fields))

    def test_non_device_response_rejected(self):
        for raw in [codec.build_frame(1, 4, 9, 0, []),
                    codec.build_frame(1, 3, 8, 0, [(15, b'\x0c')])]:
            with self.assertRaises(codec.ParseError):
                self.decode(raw)

if __name__ == "__main__": unittest.main()
