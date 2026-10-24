"""Offline profile eligibility tests use fabricated PCAPs, never home evidence.

Positive fixtures deliberately exercise the shape of an owner-origin declaration
inside a TemporaryDirectory. That declaration is not proof of a real household;
the profile always leaves live authentication and physical acceptance false.
"""
import hashlib
import io
import json
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import demo_sample as demo
import driver_profile as profiles
import offline_shcp as codec
import pcap_reader
import session_workbench as workbench
import single_light_driver

USERNAME = 'FICTIONAL_TEST_ACCOUNT'
PASSWORD = 'FICTIONAL_TEST_PASSWORD_2047'


class DriverProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in ((socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
                            (subprocess, 'run'), (subprocess, 'Popen')):
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.demo_first, self.demo_second = workbench.create_demo(self.root)
        (self.root / 'captures').mkdir()
        self.first, self.second = (self.root / 'captures' / 'FIXTURE_1', self.root / 'captures' / 'FIXTURE_2')
        for original, destination in ((self.demo_first, self.first), (self.demo_second, self.second)):
            shutil.copytree(original, destination)
            self.metadata(destination, lambda row: row.update(simulation=False, sample_origin='external_owner_household',
                script_version='UNIT_TEST_FABRICATED_NOT_HOUSEHOLD'))
            events = [json.loads(row) for row in (destination / 'events.jsonl').read_text().splitlines()]
            for row in events:
                row['simulation'] = False
            (destination / 'events.jsonl').write_text('\n'.join(json.dumps(row) for row in events) + '\n')
            def initialize(packet, row):
                pair = packet['protocol_type'], packet['link_code']
                if pair == (1, 3):
                    return self.build(packet, fields=[(160, b'\0')])
                if pair == (2, 4):
                    return self.build(packet, fields=[(12, USERNAME.encode()), (13, PASSWORD.encode())])
            self.rewrite(destination, initialize)

    def metadata(self, directory, function):
        path = directory / 'session.json'
        value = json.loads(path.read_text())
        function(value)
        path.write_text(json.dumps(value), encoding='utf-8')

    def build(self, packet, serial=None, fields=None):
        return codec.build_frame(packet['protocol_number'], packet['protocol_type'], packet['link_code'],
            packet['serial_number'] if serial is None else serial,
            [(row['id'], bytes.fromhex(row['value_hex'])) for row in packet['fields']] if fields is None else fields)

    def rewrite(self, directory, function, port=12345):
        captured = pcap_reader._read_stream(io.BytesIO((directory / 'traffic.pcap').read_bytes()), demo.HOST)
        sequences = {}
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for row in captured['packets']:
            payload, src, flags = row['payload'], row['src'], row['flags']
            if payload:
                try:
                    parsed = codec.parse_frame(payload)
                except codec.ParseError:
                    parsed = None
                if parsed:
                    replacement = function(parsed, row)
                    if replacement is not None:
                        payload = replacement
            if src not in sequences or flags & 2:
                sequences[src] = row['seq']
            packet = bytearray(demo.network_packet(src, demo.HOST if src == demo.PHONE else demo.PHONE,
                payload, sequences[src], flags))
            # A non-default, actually captured server port prevents a hidden
            # hard-coded 9000 assumption. Recompute the TCP checksum locally.
            struct.pack_into('!HH', packet, 20, 49152 if src == demo.PHONE else port,
                             port if src == demo.PHONE else 49152)
            packet[36:38] = b'\0\0'
            pseudo = bytes(packet[12:20]) + struct.pack('!BBH', 0, 6, len(packet) - 20)
            packet[36:38] = struct.pack('!H', demo.checksum(pseudo + bytes(packet[20:])))
            sequences[src] += len(payload) + bool(flags & 2) + bool(flags & 1)
            when = row['timestamp']
            seconds = int(when)
            raw.extend(struct.pack('<IIII', seconds, int(round((when - seconds) * 1000000)), len(packet), len(packet)))
            raw.extend(packet)
        (directory / 'traffic.pcap').write_bytes(raw)
        self.metadata(directory, lambda value: value.update(pcap=dict(file='traffic.pcap', size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest())))

    def create(self, credentials=None, second=True):
        return profiles.create_profile(self.first, self.root, comparison_directory=self.second if second else None,
            credentials=credentials)

    def credentials(self):
        return dict(username=USERNAME, password=PASSWORD)

    def task(self, record, key):
        return next(row for row in record['tasks'] if row['id'] == key)

    def assert_private_and_offline(self, path, record):
        encoded = path.read_text()
        for material in (USERNAME, PASSWORD, USERNAME.encode().hex(), PASSWORD.encode().hex(),
                         hashlib.md5(PASSWORD.encode()).hexdigest()):
            self.assertNotIn(material, encoded)
        for key in ('online_ready', 'runtime_authentication_verified', 'physical_feedback_verified',
                    'upload_performed', 'network_access_performed', 'credential_values_copied',
                    'credential_value_hashes_copied', 'raw_auth_fields_copied'):
            self.assertIs(record[key], False)
        self.assertEqual(record['bytes_sent'], 0)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_no_credentials_produces_exact_next_local_prompt_and_no_profile(self):
        path, record = self.create()
        self.assertTrue(record['wire_compatible'])
        self.assertFalse(record['package_eligible'])
        self.assertIsNone(record['profile'])
        self.assertEqual(record['status'], 'requires_local_credential_check')
        self.assertEqual(record['credential_verification']['status'], 'not_supplied')
        self.assert_private_and_offline(path, record)

    def test_matching_raw_input_enables_only_experimental_profile(self):
        path, record = self.create(self.credentials())
        self.assertTrue(record['wire_compatible'])
        self.assertTrue(record['package_eligible'])
        self.assertEqual(record['status'], 'source_matched_unverified')
        self.assertEqual(record['profile']['auth_password_transform'], 'raw_ascii')
        self.assertEqual(record['profile']['port'], 12345)
        self.assertEqual(record['profile']['target_identifier'], demo.DEVICE.hex())
        self.assertEqual(record['profile']['readback_correlation'], 'query_serial_echo')
        self.assertEqual(single_light_driver.validate_profile(record['profile']), record['profile'])
        self.assertFalse(self.task(record, 'ha_physical_acceptance')['supported'])
        self.assert_private_and_offline(path, record)
        self.assertEqual(profiles.validate_saved_profile(path, self.root), record)

    def test_md5_lower_and_upper_are_selected_only_by_unique_input_equality(self):
        for transform in ('md5_hex_lower', 'md5_hex_upper'):
            with self.subTest(transform=transform):
                digest = hashlib.md5(PASSWORD.encode()).hexdigest()
                if transform.endswith('upper'):
                    digest = digest.upper()
                for directory in (self.first, self.second):
                    self.rewrite(directory, lambda packet, row: self.build(packet,
                        fields=[(12, USERNAME.encode()), (13, digest.encode())])
                        if (packet['protocol_type'], packet['link_code']) == (2, 4) else None)
                path, record = self.create(self.credentials())
                self.assertTrue(record['package_eligible'])
                self.assertEqual(record['profile']['auth_password_transform'], transform)
                self.assert_private_and_offline(path, record)
                self.assertEqual(profiles.validate_saved_profile(path, self.root), record)

    def test_wrong_password_or_username_never_saves_input_or_guesses_transform(self):
        for credentials in (dict(username=USERNAME, password='WRONG_SECRET'),
                            dict(username='OTHER_ACCOUNT', password=PASSWORD)):
            with self.subTest(case=credentials['username'] == USERNAME):
                path, record = self.create(credentials)
                self.assertFalse(record['package_eligible'])
                self.assertEqual(record['credential_verification']['status'], 'no_match')
                self.assertIsNone(record['profile'])
                self.assertNotIn(credentials['username'], path.read_text())
                self.assertNotIn(credentials['password'], path.read_text())

    def test_one_different_auth_session_cannot_hide_behind_other_matching_sessions(self):
        changed = []
        def mutate(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (2, 4) and not changed:
                changed.append(True)
                return self.build(packet, fields=[(12, USERNAME.encode()), (13, b'UNMATCHED')])
        self.rewrite(self.second, mutate)
        _, record = self.create(self.credentials())
        self.assertTrue(record['wire_compatible'])
        self.assertFalse(record['package_eligible'])
        self.assertEqual(record['credential_verification']['status'], 'no_match')

    def test_indistinguishable_digest_encodings_do_not_choose_first_transform(self):
        digits = '1' * 32
        for directory in (self.first, self.second):
            self.rewrite(directory, lambda packet, row: self.build(packet,
                fields=[(12, USERNAME.encode()), (13, digits.encode())])
                if (packet['protocol_type'], packet['link_code']) == (2, 4) else None)
        # A numeric-only MD5 has identical lower/upper representations. A
        # stub creates this rare case deterministically; no cracking/search.
        with mock.patch.object(profiles.hashlib, 'md5', return_value=mock.Mock(hexdigest=lambda: digits)):
            _, record = self.create(self.credentials())
        self.assertEqual(record['credential_verification']['status'], 'ambiguous')
        self.assertFalse(record['package_eligible'])
        self.assertIsNone(record['profile'])

    def test_invalid_fresh_inputs_do_not_raise_or_echo_values(self):
        for credentials in ({'username': USERNAME, 'password': '非ASCII'}, {'username': ' user ', 'password': PASSWORD},
                            {'username': USERNAME, 'password': ''}, {'username': USERNAME, 'password': 'x' * 129},
                            {'username': USERNAME, 'password': '   '},
                            {'username': USERNAME, 'password': PASSWORD, 'token': 'SECRET'}):
            _, record = self.create(credentials)
            self.assertEqual(record['credential_verification']['status'], 'unsupported_input')
            self.assertFalse(record['package_eligible'])

    def test_whitespace_only_captured_credentials_cannot_match_runtime_schema(self):
        self.rewrite(self.first, lambda packet, row: self.build(packet,
            fields=[(12, USERNAME.encode()), (13, b'   ')])
            if (packet['protocol_type'], packet['link_code']) == (2, 4) else None)
        _, record = self.create(dict(username=USERNAME, password='   '))
        self.assertFalse(record['wire_compatible'])
        self.assertFalse(self.task(record, 'session_layout')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_missing_second_round_is_an_actionable_capture_gap(self):
        _, record = self.create(self.credentials(), second=False)
        self.assertEqual(record['status'], 'needs_sample')
        self.assertEqual(self.task(record, 'independent_round')['status'], 'needs_sample')
        self.assertFalse(record['package_eligible'])

    def test_copy_of_same_pcap_rejected_as_second_round(self):
        shutil.copyfile(self.first / 'traffic.pcap', self.second / 'traffic.pcap')
        raw = (self.second / 'traffic.pcap').read_bytes()
        self.metadata(self.second, lambda row: row.update(pcap=dict(file='traffic.pcap', size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest())))
        with self.assertRaisesRegex(ValueError, '复制件'):
            self.create(self.credentials())

    def test_synthetic_samples_remain_ineligible_and_never_probe_passwords(self):
        path, record = profiles.create_profile(self.demo_first, self.root,
            comparison_directory=self.demo_second, credentials=self.credentials())
        self.assertTrue(record['simulation'])
        self.assertFalse(record['package_eligible'])
        self.assertIsNone(record['profile'])
        self.assertEqual(record['credential_verification']['status'], 'not_checked_until_wire_and_real_sources_match')
        self.assert_private_and_offline(path, record)

    def test_unknown_or_encrypted_conn_schema_fails_closed(self):
        for fields in ([], [(160, b'\x01')], [(160, b'\0'), (93, b'PRIVATE_KEY_MATERIAL')],
                       [(160, b'\0'), (160, b'\0')], [(160, b'\0'), (531, b'APP_ID')]):
            with self.subTest(fields=[key for key, _ in fields]):
                self.rewrite(self.first, lambda packet, row: self.build(packet, fields=fields)
                    if (packet['protocol_type'], packet['link_code']) == (1, 3) else None)
                path, record = self.create(self.credentials())
                self.assertFalse(record['wire_compatible'])
                self.assertFalse(record['package_eligible'])
                self.assertFalse(self.task(record, 'session_layout')['supported'])
                self.assertNotIn('PRIVATE_KEY_MATERIAL', path.read_text())

    def test_extra_auth_field_and_unknown_token_strategy_are_not_absorbed(self):
        self.rewrite(self.first, lambda packet, row: self.build(packet,
            fields=[(12, USERNAME.encode()), (13, PASSWORD.encode()), (531, b'APP')])
            if (packet['protocol_type'], packet['link_code']) == (2, 4) else None)
        _, record = self.create(self.credentials())
        self.assertFalse(record['wire_compatible'])
        self.assertTrue(record['layout_issues'])

    def test_details_response_with_non_echo_serial_cannot_be_fresh_readback(self):
        self.rewrite(self.second, lambda packet, row: self.build(packet, serial=42)
            if (packet['protocol_type'], packet['link_code']) == (3, 8) else None)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'query_readback')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_authentication_response_must_echo_unique_request_serial(self):
        self.rewrite(self.second, lambda packet, row: self.build(packet, serial=42)
            if (packet['protocol_type'], packet['link_code']) == (2, 6) else None)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'session_layout')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_serial_counter_jump_does_not_become_a_reusable_seed(self):
        changed = []
        def mutate(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (4, 9) and not changed:
                changed.append(True)
                return self.build(packet, serial=777)
        self.rewrite(self.second, mutate)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'serial_policy')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_transport_loss_unknown_and_skipped_steps_block_profile(self):
        for mutation in (lambda row: row['capture_stop']['stats'].update(dropped_by_kernel=1),
                         lambda row: row['capture_stop']['stats'].update(dropped_by_kernel=None),
                         lambda row: row.update(skipped_steps=['App开1'])):
            with self.subTest(mutation=mutation.__code__.co_firstlineno):
                original = (self.first / 'session.json').read_bytes()
                self.metadata(self.first, mutation)
                _, record = self.create(self.credentials())
                self.assertFalse(record['package_eligible'])
                (self.first / 'session.json').write_bytes(original)

    def test_other_target_labels_do_not_merge_rounds(self):
        self.metadata(self.second, lambda row: row['target_context'].update(label='OTHER_TEST_LIGHT'))
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'ordinary_target')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_declaring_real_inside_demo_folder_cannot_enable_driver(self):
        for directory in (self.demo_first, self.demo_second):
            self.metadata(directory, lambda row: row.update(simulation=False, sample_origin='external_owner_household'))
        # This deliberately malformed source is rejected before its location
        # can be mistaken for a real capture: events retain synthetic flags.
        with self.assertRaises(ValueError):
            profiles.create_profile(self.demo_first, self.root, comparison_directory=self.demo_second,
                credentials=self.credentials())

    def test_source_location_policy_is_separate_from_simulation_fact(self):
        first = self.root / 'demo_runs' / 'DECLARATION_FIXTURE_1'
        second = self.root / 'demo_runs' / 'DECLARATION_FIXTURE_2'
        shutil.copytree(self.first, first)
        shutil.copytree(self.second, second)
        _, record = profiles.create_profile(first, self.root, comparison_directory=second,
            credentials=self.credentials())
        self.assertIs(record['simulation'], False)
        self.assertFalse(record['source_origin_eligible'])
        self.assertFalse(record['package_eligible'])
        self.assertEqual(record['credential_verification']['status'], 'not_checked_until_wire_and_real_sources_match')

    def test_originals_changed_during_credential_probe_do_not_save_match_record(self):
        original = profiles._credentials
        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            path = self.first / 'events.jsonl'
            path.write_bytes(path.read_bytes() + b' ')
            return result
        with mock.patch.object(profiles, '_credentials', side_effect=change):
            with self.assertRaises(ValueError):
                self.create(self.credentials())
        self.assertFalse((self.root / 'private_driver_profiles').exists())

    def test_foreign_light_commands_are_not_silently_ignored(self):
        foreign = bytes.fromhex('1112131415161718')
        self.rewrite(self.second, lambda packet, row: self.build(packet, fields=[(16, b'\1'), (4, foreign),
            (9, b'light-on')]) if (packet['protocol_type'], packet['link_code']) == (4, 9) else None)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'session_layout')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_business_before_authentication_success_cannot_qualify(self):
        changed = []
        def mutate(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (3, 7) and not changed:
                changed.append(True)
                # In the fabricated first connection auth is at base+.5/.7;
                # move the query from base+11.3 into that unsettled interval.
                row['timestamp'] -= 10.7
        self.rewrite(self.first, mutate)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'session_layout')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_duplicate_outstanding_queries_are_not_paired_by_a_convenient_serial(self):
        self.rewrite(self.second, lambda packet, row: self.build(packet) + self.build(packet)
            if (packet['protocol_type'], packet['link_code']) == (3, 7) else None)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'query_readback')['supported'])
        self.assertGreater(record['readback_checks']['ambiguous_response_count'], 0)
        self.assertFalse(record['package_eligible'])

    def test_unsolicited_client_heartbeat_response_is_not_a_known_heartbeat_strategy(self):
        changed = []
        def mutate(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (4, 9) and not changed:
                changed.append(True)
                return self.build(packet) + codec.build_frame(1, 6, 14,
                    (packet['serial_number'] + 1) % 65536, [])
        self.rewrite(self.first, mutate)
        _, record = self.create(self.credentials())
        self.assertTrue(record['heartbeat_observed'])
        self.assertFalse(self.task(record, 'session_layout')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_conflicting_state_after_matching_reopen_readback_remains_a_failure(self):
        self.rewrite(self.second, lambda packet, row: self.build(packet) + codec.build_frame(1, 5, 12, 501,
            [(27, b'\3'), (4, demo.DEVICE), (11, b'\0')])
            if (packet['protocol_type'], packet['link_code']) == (3, 8)
            and packet['fields'][-1]['value_hex'] == '01' else None)
        _, record = self.create(self.credentials())
        self.assertFalse(self.task(record, 'reopen_readback')['supported'])
        self.assertFalse(record['package_eligible'])

    def test_saved_profile_revalidation_accepts_safe_wizard_copy(self):
        path, record = self.create(self.credentials())
        directory = self.root / 'private_ha_wizards' / 'wizard_test'
        directory.mkdir(parents=True)
        copied = directory / 'builtin_profile_test.json'
        shutil.copyfile(path, copied)
        self.assertEqual(profiles.validate_saved_profile(copied, self.root), record)

    def test_saved_profile_change_or_unrecognized_extra_keys_rejected(self):
        path, record = self.create(self.credentials())
        original = path.read_bytes()
        for mutate in (lambda row: row['profile'].update(port=9000),
                       lambda row: row.update(package_eligible=1),
                       lambda row: row.update(secret='DO_NOT_PRINT'),
                       lambda row: row['profile'].update(credentials_verified_against_sources=1),
                       lambda row: row['credential_verification'].update(status='not_supplied'),
                       lambda row: row['tasks'][0].update(why='MODIFIED')):
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                value = json.loads(original)
                mutate(value)
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    profiles.validate_saved_profile(path, self.root)
                path.write_bytes(original)

    def test_changed_bound_event_or_report_rejected(self):
        path, record = self.create(self.credentials())
        for original in (self.first / 'events.jsonl', self.root / record['source_paths']['report_dir'] / 'report.json'):
            saved = original.read_bytes()
            original.write_bytes(saved + b' ')
            with self.assertRaises(ValueError):
                profiles.validate_saved_profile(path, self.root)
            original.write_bytes(saved)

    def test_symlink_outside_root_duplicate_json_and_oversized_records_rejected(self):
        path, _ = self.create(self.credentials())
        link = self.root / 'linked.json'
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            profiles.validate_saved_profile(link, self.root)
        original = path.read_bytes()
        path.write_bytes(b'{"package_eligible":true,"package_eligible":false}')
        with self.assertRaises(ValueError):
            profiles.validate_saved_profile(path, self.root)
        path.write_bytes(b' ' * (profiles.MAX_ARTIFACT_BYTES + 1))
        with self.assertRaises(ValueError):
            profiles.validate_saved_profile(path, self.root)
        path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
