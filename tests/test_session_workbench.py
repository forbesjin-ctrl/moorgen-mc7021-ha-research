"""The session workbench compares immutable transcripts and never goes online."""
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
import adapter_recipe as recipe
import demo_sample as demo
import offline_shcp as codec
import pcap_reader
import session_workbench as workbench


class SessionWorkbenchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in ((socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
                            (subprocess, 'run'), (subprocess, 'Popen')):
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.first, self.second = workbench.create_demo(self.root)

    def create(self, comparison=True, **values):
        return workbench.create_workbench(self.first, self.root,
            comparison_directory=self.second if comparison else None, **values)

    def rule(self, record, key):
        return next(row for row in record['serial_rules'] if row['id'] == key)

    def rewrite_metadata(self, directory, function):
        path = directory / 'session.json'
        value = json.loads(path.read_text())
        function(value)
        path.write_text(json.dumps(value), encoding='utf-8')

    def rewrite_packets(self, directory, function):
        original = pcap_reader._read_stream(io.BytesIO((directory / 'traffic.pcap').read_bytes()), demo.HOST)
        packets = original['packets']
        transformed = function(packets)
        transformed = packets if transformed is None else transformed
        sequences = {}
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for row in transformed:
            src, payload, flags, when = row['src'], row['payload'], row['flags'], row['timestamp']
            if src not in sequences or flags & 2:
                sequences[src] = row['seq']
            packet = demo.network_packet(src, demo.HOST if src == demo.PHONE else demo.PHONE,
                payload, sequences[src], flags)
            sequences[src] += len(payload) + bool(flags & 2) + bool(flags & 1)
            seconds = int(when)
            raw.extend(struct.pack('<IIII', seconds, int(round((when - seconds) * 1000000)), len(packet), len(packet)))
            raw.extend(packet)
        (directory / 'traffic.pcap').write_bytes(raw)
        self.rewrite_metadata(directory, lambda value: value.update(pcap=dict(file='traffic.pcap',
            size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())))

    def rewrite_frames(self, directory, function):
        def transform(packets):
            for row in packets:
                if row['payload'].startswith(b'#'):
                    try:
                        packet = codec.parse_frame(row['payload'])
                    except codec.ParseError:
                        continue  # Legacy demo deliberately splits requests.
                    replacement = function(packet, row)
                    if replacement is not None:
                        row['payload'] = replacement
        self.rewrite_packets(directory, transform)

    def build(self, packet, serial=None, fields=None):
        return codec.build_frame(packet['protocol_number'], packet['protocol_type'], packet['link_code'],
            packet['serial_number'] if serial is None else serial,
            [(f['id'], bytes.fromhex(f['value_hex'])) for f in packet['fields']] if fields is None else fields)

    def assert_offline(self, record):
        for key in ('online_ready', 'driver_generated', 'can_generate_live_driver', 'can_start_live_ha',
                    'physical_feedback_verified', 'executable_code', 'upload_performed',
                    'network_access_performed', 'credential_values_copied', 'credential_value_hashes_copied',
                    'raw_pcap_copied', 'causal_pairing_verified'):
            self.assertIs(record[key], False)
        self.assertEqual(record['bytes_sent'], 0)
        self.assertEqual(record['machine_sufficiency'], 'not_proven')
        self.assertTrue(all(not row['capture_allowed'] for row in record['tasks']))
        self.assertIsNone(record['candidate_strategy']['authentication_payload'])
        self.assertIsNone(record['candidate_strategy']['initial_serial'])

    def test_positive_independent_rounds_compute_real_predictions_and_never_ready(self):
        path, record = self.create()
        self.assertEqual(path.name, '会话适配.json')
        self.assertEqual(record['artifact'], 'private_mc7021_session_workbench')
        self.assertEqual(record['selected_identifier'], demo.DEVICE.hex())
        self.assertEqual(len(record['connections']), 4)
        self.assertEqual(record['session_rule']['status'], 'candidate_supported')
        self.assertEqual(self.rule(record, 'app_global_increment_mod65536')['status'], 'candidate_supported')
        self.assertEqual(self.rule(record, 'response_echo')['status'], 'candidate_supported')
        self.assertEqual(self.rule(record, 'constant_request_serial')['status'], 'conflict')
        self.assertTrue(record['independent_second_round'])
        self.assertTrue(all(row['status'] == 'candidate_supported' for row in record['reopen_checks']))
        self.assert_offline(record)

    def test_bidirectional_flows_pair_to_one_connection_not_two(self):
        _, record = self.create(False)
        self.assertEqual(len(record['connections']), 2)
        for connection in record['connections']:
            self.assertEqual(len(connection['flow_ids']), 2)
            self.assertTrue(connection['syn_visible'])
            self.assertTrue(connection['syn_ack_visible'])
        self.assertEqual(record['connections'][0]['generation'], 0)
        self.assertEqual(record['connections'][1]['generation'], 1)
        self.assertTrue(any(row['fin'] for row in record['connections'][0]['tcp_events']))

    def test_frame_indices_are_not_used_as_bidirectional_time_order(self):
        _, record = self.create()
        timeline = record['connections'][0]['session_timeline']
        self.assertEqual([(row['protocol_type'], row['link_code']) for row in timeline], [(1, 1), (1, 3), (2, 4), (2, 6)])
        self.assertNotEqual([r['frame_index'] for r in timeline], sorted(r['frame_index'] for r in timeline))
        self.assertEqual(record['session_rule']['status'], 'candidate_supported')

    def test_two_connections_can_provide_train_and_holdout_without_new_round(self):
        _, record = self.create(False)
        rule = self.rule(record, 'app_global_increment_mod65536')
        self.assertEqual(rule['status'], 'candidate_supported')
        self.assertEqual(rule['training']['connection_ids'], ['primary-connection-1'])
        self.assertEqual(rule['holdout']['connection_ids'], ['primary-connection-2'])
        boundary = rule['holdout']['predictions'][0]
        self.assertEqual(boundary['previous_connection_id'], 'primary-connection-1')
        self.assertEqual(boundary['connection_id'], 'primary-connection-2')

    def test_counter_wrap_uses_previous_value_not_current_observation(self):
        _, record = self.create()
        rule = self.rule(record, 'app_global_increment_mod65536')
        zero = [row for row in rule['predictions'] if row['expected_serial'] == 0]
        self.assertTrue(zero)
        self.assertTrue(all(row['observed_serial'] == 0 and row['matches'] for row in zero))
        self.assertTrue(all(row['prediction_basis'] == 'preceding_observation_plus_one_mod65536' for row in rule['predictions']))
        self.assertIsNone(rule['initial_serial'])

    def test_counter_jump_retains_real_conflict_and_fresh_next_prediction(self):
        changed = []
        def mutate(packet, row):
            if row['src'] == demo.PHONE and packet['protocol_type'] == 4 and not changed:
                changed.append(True)
                return self.build(packet, serial=123)
        self.rewrite_frames(self.second, mutate)
        _, record = self.create()
        rule = self.rule(record, 'app_global_increment_mod65536')
        self.assertEqual(rule['status'], 'conflict')
        failure = next(row for row in rule['conflicts'] if row['observed_serial'] == 123)
        self.assertNotEqual(failure['expected_serial'], 123)
        after = next(row for row in rule['predictions'] if row['previous_frame_index'] == failure['frame_index']
                     and row['round'] == 'holdout')
        self.assertEqual(after['expected_serial'], 124)
        self.assertIn('不证明全局计数器算法错误', rule['note'])

    def test_echo_checks_unique_prior_opposite_direction_request(self):
        _, record = self.create()
        rule = self.rule(record, 'response_echo')
        self.assertTrue(rule['predictions'])
        self.assertTrue(all(row['prediction_basis'] == 'uniquely_prior_opposite_direction_request' for row in rule['predictions']))
        self.assertTrue(all(row['request_frame_index'] != row['frame_index'] for row in rule['predictions']))

    def test_wrong_response_serial_is_counterexample_not_copy_as_prediction(self):
        changed = []
        def mutate(packet, row):
            if row['src'] == demo.HOST and packet['protocol_type'] == 2 and not changed:
                changed.append(True)
                return self.build(packet, serial=321)
        self.rewrite_frames(self.second, mutate)
        _, record = self.create()
        rule = self.rule(record, 'response_echo')
        self.assertEqual(rule['status'], 'conflict')
        conflict = next(row for row in rule['conflicts'] if row['observed_serial'] == 321)
        self.assertNotEqual(conflict['expected_serial'], 321)

    def test_constant_sequence_is_distinct_candidate_and_echo_is_ambiguous(self):
        for directory in (self.first, self.second):
            self.rewrite_frames(directory, lambda packet, row: self.build(packet, serial=7))
        _, record = self.create()
        self.assertEqual(self.rule(record, 'constant_request_serial')['status'], 'candidate_supported')
        self.assertEqual(self.rule(record, 'app_global_increment_mod65536')['status'], 'conflict')
        echo = self.rule(record, 'response_echo')
        self.assertEqual(echo['status'], 'insufficient')
        self.assertTrue(any('恒定值巧合' in row['reason'] for row in echo['insufficient']))

    def test_single_connection_without_holdout_remains_insufficient(self):
        def remove_second(rows):
            return [row for row in rows if row['timestamp'] < rows[0]['timestamp'] + 270]
        self.rewrite_packets(self.first, remove_second)
        _, record = self.create(False)
        self.assertEqual(len(record['connections']), 1)
        self.assertTrue(all(row['status'] != 'candidate_supported' for row in record['serial_rules']))

    def test_missing_syn_does_not_mean_no_authentication(self):
        for directory in (self.first, self.second):
            self.rewrite_packets(directory, lambda rows: [r for r in rows if not r['flags'] & 2])
        _, record = self.create()
        self.assertEqual(record['session_rule']['status'], 'insufficient')
        self.assertIsNone(record['authentication']['required'])
        self.assertTrue(record['quality_limitations'])
        self.assertTrue(all(c['initial_capture_status'] == 'initial_boundary_unknown' for c in record['connections']))

    def test_missing_auth_still_unknown_and_not_skip_policy(self):
        self.rewrite_frames(self.first, lambda packet, row: b'' if packet['protocol_type'] == 2 else None)
        _, record = self.create(False)
        self.assertEqual(record['session_rule']['status'], 'insufficient')
        self.assertIsNone(record['authentication']['required'])
        self.assertEqual(record['candidate_strategy']['authentication_algorithm'], 'unknown')
        self.assert_offline(record)

    def test_duplicate_auth_request_is_not_unique_success(self):
        def duplicate(rows):
            result = []
            for row in rows:
                result.append(row)
                if row['src'] == demo.PHONE and row['payload'].startswith(b'#'):
                    packet = codec.parse_frame(row['payload'])
                    if packet['protocol_type'] == 2:
                        copy = dict(row)
                        copy['timestamp'] += .01
                        result.append(copy)
            return result
        self.rewrite_packets(self.first, duplicate)
        _, record = self.create(False)
        self.assertEqual(record['session_rule']['status'], 'insufficient')
        self.assertTrue(any('重复' in reason for row in record['session_rule']['checks'] for reason in row['reasons']))
        self.assertTrue(self.rule(record, 'response_echo')['insufficient'])

    def test_auth_failure_is_visible_conflict_not_hidden_by_later_success(self):
        def mutate(packet, row):
            if row['src'] == demo.HOST and packet['protocol_type'] == 2:
                return codec.build_frame(1, 2, 5, packet['serial_number'], [])
        self.rewrite_frames(self.first, mutate)
        _, record = self.create(False)
        self.assertEqual(record['session_rule']['status'], 'conflict')
        self.assertTrue(any(row['failure_frame_indices'] for row in record['session_rule']['checks']))

    def test_credentials_only_shapes_and_in_memory_relations_never_values_or_hashes(self):
        path, record = self.create()
        auth = record['authentication']
        self.assertTrue(auth['observations'])
        self.assertTrue(any(row['relation'] == 'same' for row in auth['comparisons']))
        self.assertTrue(any(row['relation'] == 'different' for row in auth['comparisons']))
        text = path.read_text() + (path.parent / '会话适配说明.txt').read_text() + workbench.render_task_text(record, 'auth_fields')
        for marker in (b'SYNTHETIC_ONLY_NOT_A_CREDENTIAL_\0', b'SYNTHETIC_ONLY_NOT_A_CREDENTIAL_\1'):
            self.assertNotIn(marker.hex(), text)
            self.assertNotIn(hashlib.sha256(marker).hexdigest(), text)
        self.assertNotIn('SYNTHETIC_ONLY_NOT_A_CREDENTIAL', text)
        self.assertFalse(auth['values_copied'])
        self.assertFalse(auth['value_hashes_copied'])

    def test_auth_method_shapes_and_connection_key_shapes_remain_private(self):
        secret = b'PRIVATE_NAME_OR_PASSWORD_DO_NOT_EXPORT'
        def mutate(packet, row):
            if packet['protocol_type'] == 2 and row['src'] == demo.PHONE:
                return self.build(packet, fields=[(12, secret), (13, secret), (531, secret)])
            if (packet['protocol_type'], packet['link_code']) == (1, 1):
                return self.build(packet, fields=[(530, secret), (531, secret)])
        self.rewrite_frames(self.first, mutate)
        path, record = self.create(False)
        self.assertTrue(any('username_password_field_shape_candidate' in row['candidates'] for row in record['authentication']['method_candidates']))
        self.assertTrue(any({f['id'] for f in row['fields']} == {530, 531} for row in record['authentication']['observations']))
        self.assertNotIn(secret.decode(), path.read_text())
        self.assertNotIn(secret.hex(), path.read_text())

    def test_nonzero_encryption_choice_is_observed_not_decrypted(self):
        def mutate(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (1, 3):
                return self.build(packet, fields=[(160, b'\x01'), (93, b'SECRET_KEY')])
        self.rewrite_frames(self.first, mutate)
        path, record = self.create(False)
        choices = record['authentication']['encryption_observations']
        self.assertTrue(all(row['observed_enum'] == 1 and not row['decryption_performed'] for row in choices))
        self.assertEqual(next(t for t in record['tasks'] if t['id'] == 'opaque_support')['status'], 'software_required')
        self.assertNotIn(b'SECRET_KEY'.hex(), path.read_text())
        self.assert_offline(record)

    def test_absent_encryption_selector_is_unknown_not_plaintext_permission(self):
        _, record = self.create(False)
        choices = record['authentication']['encryption_observations']
        self.assertTrue(choices)
        self.assertTrue(all(row['observed_enum'] is None and row['status'] == 'unknown'
                            and not row['absence_means_no_encryption'] for row in choices))

    def test_query_request_48_and_response_04_are_not_confused(self):
        _, record = self.create()
        self.assertTrue(all(row['request_type'] == '48' and row['response_context'] == '04' for row in record['query_checks']))
        def mutate(packet, row):
            if packet['protocol_type'] == 3 and packet['link_code'] == 7:
                return self.build(packet, fields=[(15, b'\x04'), (4, demo.DEVICE)])
        self.rewrite_frames(self.first, mutate)
        _, record = self.create(False)
        self.assertTrue(all(row['request_type'] == 'other_or_unsupported' and row['status'] == 'insufficient' for row in record['query_checks']))
        self.assertTrue(all(row['status'] == 'insufficient' for row in record['reopen_checks']))

    def test_ack_cannot_replace_reopen_independent_state(self):
        def mutate(packet, row):
            if packet['protocol_type'] == 3 and packet['link_code'] == 8:
                return codec.build_frame(1, 4, 11, packet['serial_number'], [])
        self.rewrite_frames(self.first, mutate)
        _, record = self.create(False)
        self.assertTrue(all(row['status'] == 'insufficient' for row in record['reopen_checks']))
        self.assertTrue(all(row['status'] == 'insufficient' for row in record['query_checks']))

    def test_old_connection_state_does_not_prove_reconnect(self):
        original = demo.create_demo_sample(self.root / 'legacy')
        _, record = workbench.create_workbench(original, self.root)
        self.assertTrue(all(row['status'] == 'insufficient' for row in record['reopen_checks']))
        self.assert_offline(record)

    def test_same_pcap_wrong_host_wrong_id_and_mixed_simulation_rejected(self):
        clone = self.root / 'clone'
        shutil.copytree(self.first, clone)
        with self.assertRaisesRegex(ValueError, 'PCAP与第一轮相同'):
            workbench.create_workbench(self.first, self.root, comparison_directory=clone)
        self.rewrite_metadata(self.second, lambda v: v.update(target_ip='192.0.2.21'))
        with self.assertRaisesRegex(ValueError, '主机不同'):
            self.create()
        self.rewrite_metadata(self.second, lambda v: v.update(target_ip=demo.HOST))
        with self.assertRaisesRegex(ValueError, '完整标识未出现'):
            self.create(selected_identifier='1112131415161718')
        self.rewrite_metadata(self.second, lambda v: v.update(simulation=False))
        events = self.second / 'events.jsonl'
        events.write_text('\n'.join(json.dumps(dict(json.loads(s), simulation=False)) for s in events.read_text().splitlines()) + '\n')
        with self.assertRaisesRegex(ValueError, '混合真实与合成'):
            self.create()

    def test_pcap_original_tampering_is_rejected(self):
        path = self.first / 'traffic.pcap'
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            self.create(False)

    def test_mutation_before_final_verification_creates_no_strategy(self):
        original = recipe._verify_unchanged
        def changed(source, root):
            path = self.first / 'events.jsonl'
            path.write_text(path.read_text() + '\n')
            return original(source, root)
        with mock.patch.object(recipe, '_verify_unchanged', side_effect=changed):
            with self.assertRaisesRegex(ValueError, '变化|哈希不同'):
                self.create(False)
        self.assertFalse((self.root / 'private_session_workbenches').exists())

    def test_duplicate_json_symlink_oversize_and_outside_root_rejected(self):
        path = self.first / 'session.json'
        old = path.read_text()
        path.write_text(old[:-1] + ',"simulation":true}')
        with self.assertRaisesRegex(ValueError, '重复JSON'):
            self.create(False)
        path.write_text(old)
        moved = self.first / 'real.pcap'
        (self.first / 'traffic.pcap').rename(moved)
        (self.first / 'traffic.pcap').symlink_to(moved)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.create(False)
        with self.assertRaises(ValueError):
            workbench.create_workbench(self.first, self.root / 'demo_runs', selected_identifier='short')
        with mock.patch.dict(workbench.baseline.INPUT_LIMITS, {'traffic.pcap': 10}):
            with self.assertRaises(ValueError):
                self.create(False)

    def test_private_permissions_and_only_two_non_executable_artifacts(self):
        path, record = self.create()
        self.assertEqual(path.parent.parent, self.root / 'private_session_workbenches')
        self.assertEqual({p.name for p in path.parent.iterdir()}, {'会话适配.json', '会话适配说明.txt'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertFalse(record['candidate_strategy']['executable'])

    def test_opaque_tls_is_not_decrypted_or_repeated_until_pass(self):
        def mutate(rows):
            for row in rows:
                if row['payload']:
                    row['payload'] = b'\x16\x03\x03OPAQUE_PRIVATE_ENCRYPTED'
                    break
        self.rewrite_packets(self.first, mutate)
        path, record = self.create(False)
        self.assertTrue(record['primary']['opaque_flow_ids'])
        self.assertTrue(record['quality_limitations'])
        self.assertTrue(all(r['status'] != 'candidate_supported' for r in record['serial_rules']))
        self.assertNotIn('OPAQUE_PRIVATE_ENCRYPTED', path.read_text())
        self.assert_offline(record)

    def test_missing_real_identity_does_not_promote_or_guess_target(self):
        with self.assertRaisesRegex(ValueError, '完整8字节'):
            self.create(False, selected_identifier='01020304')
        self.rewrite_frames(self.first, lambda packet, row: b'' if any(f['id'] == 4 for f in packet['fields']) else None)
        _, record = self.create(False)
        self.assertIsNone(record['selected_identifier'])
        self.assert_offline(record)

    def test_chinese_reports_explain_supported_conflicts_and_no_unlock(self):
        _, record = self.create()
        text = workbench.render_text(record)
        self.assertIn('资料充分性尚未证明', text)
        self.assertIn('留出', text)
        detail = workbench.render_task_text(record, 'serial_policy')
        self.assertIn('预测详情', detail)
        self.assertIn('冲突', detail)
        self.assertIn('不会启动补采', detail)
        with self.assertRaisesRegex(ValueError, '未知'):
            workbench.render_task_text(record, '../anything')

    def test_overlapping_response_does_not_use_frame_index_to_resolve_order(self):
        def overlap(rows):
            first_request = next(r for r in rows if r['payload'] and r['src'] == demo.PHONE)
            response = next(r for r in rows if r['payload'] and r['src'] == demo.HOST)
            response['timestamp'] = first_request['timestamp']
            return sorted(rows, key=lambda r: (r['timestamp'], r['packet_index']))
        self.rewrite_packets(self.first, overlap)
        _, record = self.create(False)
        self.assertEqual(record['session_rule']['status'], 'insufficient')
        self.assertTrue(self.rule(record, 'response_echo')['insufficient'])

    def test_nonzero_drop_unknown_stats_or_interrupted_capture_limit_candidates(self):
        for mutate in (lambda v: v['capture_stop']['stats'].update(dropped_by_kernel=1),
                       lambda v: v['capture_stop']['stats'].update(dropped_by_kernel=False),
                       lambda v: v.update(status='interrupted')):
            with self.subTest(mutate=mutate):
                first, second = workbench.create_demo(self.root)
                self.rewrite_metadata(first, mutate)
                _, record = workbench.create_workbench(first, self.root, comparison_directory=second)
                self.assertTrue(record['quality_limitations'])
                self.assertEqual(record['session_rule']['status'], 'insufficient')
                self.assertTrue(all(r['status'] != 'candidate_supported' for r in record['serial_rules']))
                self.assertTrue(all(r['status'] == 'insufficient' for r in record['reopen_checks']))

    def test_closed_period_observation_and_previous_opposite_state_must_match(self):
        for step, field, value in (('App关闭期间面板开', 'physical_light', 'off'),
                                   ('App关闭期间面板开', 'app_display', 'on'),
                                   ('面板关', 'physical_light', 'on')):
            with self.subTest(step=step, field=field):
                first, second = workbench.create_demo(self.root)
                path = first / 'events.jsonl'
                rows = [json.loads(s) for s in path.read_text().splitlines()]
                for row in rows:
                    if row.get('step') == step and row.get('event') == 'observation':
                        row[field] = value
                path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
                _, record = workbench.create_workbench(first, self.root, comparison_directory=second)
                self.assertEqual(record['reopen_checks'][0]['status'], 'insufficient')
                self.assertTrue(record['reopen_checks'][0]['reasons'])

    def test_valid_increment_rule_does_not_request_repeats_for_rejected_constant_model(self):
        _, record = self.create(False)
        task = next(row for row in record['tasks'] if row['id'] == 'serial_policy')
        self.assertEqual(task['status'], 'manual_required')
        self.assertEqual(task['category'], 'manual_check')

    def test_two_rounds_without_session_or_new_readback_switch_to_software_gaps(self):
        first = demo.create_demo_sample(self.root / 'old')
        second = demo.create_demo_sample(self.root / 'old')
        self.rewrite_frames(second, lambda packet, row: self.build(packet, serial=(packet['serial_number'] + 10) % 65536))
        _, record = workbench.create_workbench(first, self.root, comparison_directory=second)
        tasks = {row['id']: row for row in record['tasks']}
        self.assertEqual(tasks['normal_start']['status'], 'software_required')
        self.assertEqual(tasks['fresh_reopen']['status'], 'software_required')
        self.assertIn('不要改网络', ''.join(tasks['fresh_reopen']['instructions']))

    def test_syn_after_query_is_not_proof_of_new_readback(self):
        def late_syn(rows):
            threshold = rows[0]['timestamp'] + 270
            for row in rows:
                if row['timestamp'] > threshold and row['flags'] & 2:
                    row['timestamp'] += 2
            return sorted(rows, key=lambda row: (row['timestamp'], row['packet_index']))
        self.rewrite_packets(self.first, late_syn)
        _, record = self.create(False)
        self.assertEqual(record['reopen_checks'][0]['status'], 'insufficient')

    def test_multiple_captured_identifiers_are_listed_without_selecting_first(self):
        other = bytes.fromhex('1112131415161718')
        def add_other(rows):
            for row in rows:
                if not row['payload'].startswith(b'#'):
                    continue
                packet = codec.parse_frame(row['payload'])
                if row['src'] == demo.PHONE and packet['protocol_type'] == 4:
                    fields = [(f['id'], other if f['id'] == 4 else bytes.fromhex(f['value_hex'])) for f in packet['fields']]
                    row['payload'] += self.build(packet, fields=fields)
        self.rewrite_packets(self.first, add_other)
        self.rewrite_packets(self.second, add_other)
        _, record = self.create(False)
        self.assertEqual(record['candidate_identifiers'], [demo.DEVICE.hex(), other.hex()])
        self.assertIsNone(record['selected_identifier'])
        self.assertEqual(record['selection_mode'], 'selection_required')
        _, selected = self.create(selected_identifier=other.hex())
        self.assertEqual(selected['selected_identifier'], other.hex())
        self.assertFalse(selected['candidate_identifiers_truncated'])
        self.assert_offline(selected)

    def test_matching_reopen_response_cannot_hide_opposite_or_unsupported_state(self):
        for unsupported in (False, True):
            with self.subTest(unsupported=unsupported):
                first, second = workbench.create_demo(self.root)
                seen = []
                def append_state(packet, row):
                    if (packet['protocol_type'], packet['link_code']) != (3, 8):
                        return None
                    seen.append(True)
                    if len(seen) != 2:
                        return None
                    fields = [(27, b'\x03'), (4, demo.DEVICE), (11, b'\x00')]
                    if unsupported:
                        fields.append((93, b'PRIVATE_UNKNOWN_STATE_FIELD'))
                    return self.build(packet) + codec.build_frame(1, 5, 12, 99, fields)
                self.rewrite_frames(first, append_state)
                path, record = workbench.create_workbench(first, self.root, comparison_directory=second)
                check = record['reopen_checks'][0]
                self.assertEqual(check['status'], 'insufficient')
                key = 'unsupported_state_frame_indices' if unsupported else 'conflicting_state_frame_indices'
                self.assertTrue(check[key])
                self.assertTrue(any('不能' in reason for reason in check['reasons']))
                self.assertNotIn(b'PRIVATE_UNKNOWN_STATE_FIELD'.hex(), path.read_text())

    def test_source_quality_routes_capture_failure_and_opaque_support_separately(self):
        self.rewrite_metadata(self.first, lambda row: row['capture_stop']['stats'].update(dropped_by_kernel=2))
        _, record = self.create()
        task = next(row for row in record['tasks'] if row['id'] == 'source_quality')
        self.assertEqual(task['category'], 'recapture')
        self.assertEqual(task['status'], 'needs_sample')
        self.assertIn('丢包', task['why'])
        self.assertIn('内核丢包未知或非零', workbench.render_text(record))
        self.assertIn('内核丢包未知或非零', workbench.render_task_text(record, 'source_quality'))
        self.assertEqual(next(row for row in record['tasks'] if row['id'] == 'normal_start')['category'], 'recapture')
        self.rewrite_metadata(self.first, lambda row: row['capture_stop']['stats'].update(dropped_by_kernel=0))
        def encrypt(packet, row):
            if (packet['protocol_type'], packet['link_code']) == (1, 3):
                return self.build(packet, fields=[(160, b'\x02')])
        self.rewrite_frames(self.first, encrypt)
        _, record = self.create()
        task = next(row for row in record['tasks'] if row['id'] == 'source_quality')
        self.assertEqual(task['category'], 'software_support')
        self.assertEqual(task['status'], 'software_required')
        self.assertIn('非零加密', task['why'])
        self.assertTrue(all(row['category'] == 'software_support' for row in record['quality_findings']))

    def test_only_missing_syn_gets_one_normal_round_then_strategy_support(self):
        def no_initial_syn(rows):
            end = rows[0]['timestamp'] + 270
            return [row for row in rows if row['timestamp'] < end and not row['flags'] & 2]
        for directory in (self.first, self.second):
            self.rewrite_packets(directory, no_initial_syn)
        _, single = self.create(False)
        self.assertEqual(single['primary']['sampling_transport_issue_count'], 0)
        self.assertGreater(single['primary']['initial_boundary_unknown_count'], 0)
        self.assertEqual(next(t for t in single['tasks'] if t['id'] == 'source_quality')['status'], 'needs_sample')
        _, both = self.create()
        self.assertTrue(both['quality_limitations'])
        self.assertEqual(next(t for t in both['tasks'] if t['id'] == 'source_quality')['category'], 'software_support')
        self.assertEqual(next(t for t in both['tasks'] if t['id'] == 'normal_start')['category'], 'software_support')


if __name__ == '__main__':
    unittest.main()
