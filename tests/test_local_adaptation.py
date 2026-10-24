"""Only local synthetic files; evidence never turns into a live driver."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture as analysis
import demo_sample as demo
import local_adaptation as adaptation
import offline_shcp as codec


class LocalAdaptationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS /var is itself a symlink; choose the actual temporary path.
        self.root = Path(self.temp.name).resolve()
        self.session = demo.create_demo_sample(self.root / 'demo_runs')
        self.reanalyze()

    def reanalyze(self):
        self.report_dir, self.old_report = analysis.analyze_session(self.session, self.root / 'private_reports')

    def run_analysis(self):
        return adaptation.analyze_adaptation(self.session, self.report_dir, self.root)

    def rewrite_pcap(self, frames):
        sequence = {demo.PHONE: 1000, demo.HOST: 8000}
        rows = []
        for offset, (src, payload) in enumerate([(demo.PHONE, b''), (demo.HOST, b'')] + frames):
            flags = 2 if offset == 0 else 18 if offset == 1 else 24
            packet = demo.network_packet(src, demo.HOST if src == demo.PHONE else demo.PHONE,
                                         payload, sequence[src], flags)
            sequence[src] += len(payload) + bool(flags & 2)
            rows.append((1767196800 + offset, packet))
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for when, packet in rows:
            raw.extend(struct.pack('<IIII', when, 0, len(packet), len(packet)))
            raw.extend(packet)
        path = self.session / 'traffic.pcap'
        path.write_bytes(raw)
        metadata_path = self.session / 'session.json'
        metadata = json.loads(metadata_path.read_text())
        metadata['pcap'] = dict(file='traffic.pcap', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        metadata_path.write_text(json.dumps(metadata), encoding='utf-8')
        self.reanalyze()

    def test_complete_synthetic_evidence_never_generates_or_unlocks_driver(self):
        destination, report = self.run_analysis()
        self.assertEqual(report['artifact'], 'private_mc7021_local_adaptation_evidence')
        self.assertEqual(report['summary']['frame_count'], 18)
        self.assertEqual(report['summary']['independent_state_candidate_count'], 8)
        self.assertEqual(report['summary']['repeated_candidate_count'], 1)
        self.assertTrue(report['simulation'])
        for key in ('driver_generated', 'can_generate_live_driver', 'online_ready', 'can_start_live_ha', 'physical_feedback_verified',
                    'compatibility_verified', 'upload_performed', 'network_access_performed'):
            self.assertIs(report[key], False)
        self.assertTrue(any('合成' in item for item in report['resample']))
        self.assertEqual(destination.parent, self.root / 'private_local_adaptations')
        self.assertEqual({path.name for path in destination.iterdir()}, {'适配分析.json', '适配分析.md'})
        self.assertIn('没有生成可用驱动', (destination / '适配分析.md').read_text())

    def test_commands_states_endpoints_and_raw_values_come_from_reassembly(self):
        _, report = self.run_analysis()
        candidate = report['device_candidates'][0]
        self.assertEqual(candidate['identifier_hex'], demo.DEVICE.hex())
        self.assertEqual(candidate['command_on_count'], 2)
        self.assertEqual(candidate['command_off_count'], 2)
        self.assertEqual(set(candidate['panel_state_windows']), {'面板开', '面板关'})
        self.assertEqual(len(candidate['state_evidence']), 8)
        for state in candidate['state_evidence']:
            self.assertEqual(state['direction'], 'from_host')
            self.assertIn(state['raw_state'], (0, 1))
            self.assertIsNone(state['candidate_is_on'])
            self.assertFalse(state['ordinary_light_type_verified'])
        self.assertEqual(report['transport']['observed_host_ports'], [9000])
        first = next(item for item in report['frame_observations'] if item['command'] == 'light-on')
        self.assertEqual((first['protocol_number'], first['protocol_type'], first['link_code']), (1, 4, 9))
        self.assertEqual(first['direction'], 'to_host')
        self.assertEqual(len(first['packet_indices']), 2)
        self.assertEqual(first['nearby_steps'], ['App开1'])

    def test_ack_execution_response_and_wrong_direction_are_not_independent_state(self):
        self.rewrite_pcap([(demo.HOST, codec.build_frame(1, 4, 11, 1, [])),
            (demo.HOST, codec.build_frame(1, 4, 10, 1, [])),
            (demo.PHONE, codec.build_frame(1, 5, 12, 1, [(27, b'\x03'), (4, demo.DEVICE), (11, b'\x01')]))])
        _, report = self.run_analysis()
        self.assertEqual(report['summary']['acknowledgement_count'], 2)
        self.assertEqual(report['summary']['independent_state_candidate_count'], 0)
        self.assertTrue(all(row['acknowledgement_is_state'] is False for row in report['frame_observations']))

    def test_command_from_host_cannot_be_treated_as_control_request(self):
        self.rewrite_pcap([(demo.HOST, codec.build_candidate_light_frame(demo.DEVICE, True))])
        _, report = self.run_analysis()
        candidate = report['device_candidates'][0]
        self.assertEqual(candidate['command_on_count'], 0)
        self.assertEqual(candidate['command_evidence'], [])

    def test_wrong_update_category_retains_raw_state_without_independent_status(self):
        self.rewrite_pcap([(demo.HOST, codec.build_frame(1, 5, 12, 1,
            [(27, b'\x02'), (4, demo.DEVICE), (11, b'\x81')]))])
        _, report = self.run_analysis()
        state = report['device_candidates'][0]['state_evidence'][0]
        self.assertEqual(state['raw_state'], 129)
        self.assertFalse(state['independent_state_candidate'])
        self.assertEqual(report['summary']['independent_state_candidate_count'], 0)

    def test_missing_auth_fields_never_establishes_authentication_not_required(self):
        _, report = self.run_analysis()
        auth = report['session_authentication']
        self.assertEqual(auth['observations'], [])
        self.assertEqual(auth['status'], 'unknown')
        self.assertIsNone(auth['authentication_required'])
        self.assertFalse(auth['verified'])
        self.assertTrue(any('不证明免认证' in item for item in report['pending']))

    def test_auth_field_values_are_not_copied_or_claimed_authenticated(self):
        secret = b'PRIVATE_AUTH_VALUE'
        self.rewrite_pcap([(demo.PHONE, codec.build_frame(1, 1, 2, 4, [(93, secret), (160, secret)]))])
        _, report = self.run_analysis()
        self.assertEqual({item['field_id'] for item in report['session_authentication']['observations']}, {93, 160})
        self.assertTrue(all(item['length'] == len(secret) for item in report['session_authentication']['observations']))
        output = json.dumps(report)
        self.assertNotIn(secret.decode(), output)
        self.assertNotIn(secret.hex(), output)
        self.assertIsNone(report['session_authentication']['authentication_required'])
        self.assertFalse(report['online_ready'])

    def test_request_values_are_observed_without_requiring_response_constant(self):
        self.rewrite_pcap([(demo.PHONE, codec.build_frame(1, 3, 7, 1, [(15, b'\x48'), (4, demo.DEVICE)])),
                          (demo.PHONE, codec.build_frame(1, 3, 7, 2, [(15, b'\x04')])),
                          (demo.PHONE, codec.build_frame(1, 3, 7, 3, [(15, b'\x7f')]))])
        _, report = self.run_analysis()
        requests = report['request_observations']
        self.assertEqual([row['request_type_hex'] for row in requests], ['48', '04', '7f'])
        self.assertEqual(requests[0]['identifier_hex'], demo.DEVICE.hex())
        self.assertEqual(requests[0]['classification'], 'single_device_details_request_candidate_static_unverified')
        self.assertTrue(all(row['classification'] == 'observed_request_value_unverified' for row in requests[1:]))
        self.assertFalse(any('未见主机方向的数据请求帧' in item for item in report['resample']))
        self.assertFalse(report['can_generate_live_driver'])

    def test_session_protocol_timeline_uses_triplets_without_payload_or_success_claim(self):
        secret = b'PRIVATE_LOGIN_PAYLOAD'
        pairs = [(1, 1), (1, 3), (2, 4), (2, 5), (2, 6), (2, 19)]
        self.rewrite_pcap([(demo.PHONE, codec.build_frame(1, kind, code, number, [(9, secret)]))
                           for number, (kind, code) in enumerate(pairs)])
        _, report = self.run_analysis()
        timeline = report['session_authentication']['session_protocol_timeline']
        self.assertEqual([(row['protocol_type'], row['link_code']) for row in timeline], pairs)
        self.assertNotIn(secret.hex(), json.dumps(report))
        self.assertFalse(report['session_authentication']['verified'])

    def test_tls_like_payload_is_not_scanned_for_embedded_valid_plaintext(self):
        self.rewrite_pcap([(demo.PHONE, b'\x16\x03\x03' + codec.build_candidate_light_frame(demo.DEVICE, True))])
        _, report = self.run_analysis()
        self.assertEqual(report['summary']['frame_count'], 0)
        self.assertTrue(report['session_authentication']['opaque_flow_ids'])
        self.assertTrue(any('TLS' in item for item in report['resample']))

    def test_serial_observations_preserve_order_without_inferring_rule(self):
        self.rewrite_pcap([(demo.PHONE, codec.build_candidate_light_frame(demo.DEVICE, True, 65535)),
                          (demo.PHONE, codec.build_candidate_light_frame(demo.DEVICE, False, 0)),
                          (demo.PHONE, codec.build_candidate_light_frame(demo.DEVICE, True, 0))])
        _, report = self.run_analysis()
        serial = report['serial_observations'][0]
        self.assertFalse(serial['rule_verified'])
        self.assertEqual([item['serial_number'] for item in serial['observations']], [65535, 0, 0])
        self.assertEqual([item['delta_modulo_65536'] for item in serial['observations']], [None, 1, 0])

    def test_untrusted_old_report_frames_are_not_used_as_wire_evidence(self):
        path = self.report_dir / 'report.json'
        report = json.loads(path.read_text())
        report['frames'] = [{'made_up': 'FORGED_FRAME'}]
        report['device_candidates'] = [{'identifier_hex': 'ffffffffffffffff'}]
        report['readiness']['can_start_live_ha'] = True
        path.write_text(json.dumps(report), encoding='utf-8')
        _, actual = self.run_analysis()
        self.assertEqual(actual['summary']['frame_count'], 18)
        self.assertEqual(actual['device_candidates'][0]['identifier_hex'], demo.DEVICE.hex())
        self.assertNotIn('FORGED_FRAME', json.dumps(actual))
        self.assertFalse(actual['can_start_live_ha'])

    def test_source_binding_mismatch_and_wrong_session_are_rejected(self):
        path = self.session / 'events.jsonl'
        path.write_text(path.read_text() + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '三文件哈希'):
            self.run_analysis()
        self.reanalyze()
        path = self.report_dir / 'report.json'
        report = json.loads(path.read_text())
        report['source']['folder'] = 'somebody_else'
        path.write_text(json.dumps(report), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '文件夹不对应'):
            self.run_analysis()

    def test_source_replaced_during_analysis_does_not_write_report(self):
        original = adaptation.build_evidence
        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            events = self.session / 'events.jsonl'
            events.write_bytes(events.read_bytes() + b'\n')
            return result
        with mock.patch.object(adaptation, 'build_evidence', side_effect=mutate):
            with self.assertRaises(ValueError):
                self.run_analysis()
        self.assertFalse((self.root / 'private_local_adaptations').exists())

    def test_symlink_input_output_and_oversize_json_are_rejected(self):
        target = self.root / 'outside.json'
        source = self.session / 'session.json'
        source.rename(target)
        source.symlink_to(target)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.run_analysis()
        source.unlink()
        target.rename(source)
        out = self.root / 'private_local_adaptations'
        out.symlink_to(self.session, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.run_analysis()
        out.unlink()
        with (self.report_dir / 'report.json').open('wb') as stream:
            stream.truncate(adaptation.MAX_REPORT + 1)
        with self.assertRaisesRegex(ValueError, '超过上限'):
            self.run_analysis()

    def test_duplicate_json_keys_and_missing_source_origin_are_rejected(self):
        path = self.session / 'session.json'
        raw = path.read_text()
        path.write_text(raw[:-1] + ', "simulation": true}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '重复JSON键'):
            self.run_analysis()

    def test_incomplete_capture_and_unknown_drops_are_explicit_resampling_gaps(self):
        path = self.session / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['status'] = 'interrupted'
        metadata.pop('capture_stop')
        path.write_text(json.dumps(metadata), encoding='utf-8')
        self.reanalyze()
        _, report = self.run_analysis()
        self.assertTrue(any('正常完成' in item for item in report['resample']))
        self.assertTrue(any('内核丢包' in item for item in report['resample']))
        self.assertIsNone(report['session_authentication']['authentication_required'])

    def test_real_source_declaration_does_not_generate_driver_or_verify_physical_state(self):
        path = self.session / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['simulation'] = False
        metadata['sample_origin'] = 'operator_declared_capture'
        path.write_text(json.dumps(metadata), encoding='utf-8')
        path = self.session / 'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row in rows:
            row['simulation'] = False
        path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        self.reanalyze()
        _, report = self.run_analysis()
        self.assertIs(report['simulation'], False)
        for key in ('can_generate_live_driver', 'can_start_live_ha', 'physical_feedback_verified'):
            self.assertIs(report[key], False)

    def test_saved_files_are_private_reproducible_and_inputs_unchanged(self):
        before = {path.name: path.read_bytes() for path in self.session.iterdir()}
        destination, report = self.run_analysis()
        _, again = self.run_analysis()
        self.assertEqual(report, again)
        self.assertEqual(json.loads((destination / '适配分析.json').read_text()), report)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir()))
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.session.iterdir()})
        for name, binding in report['source_bindings'].items():
            path = self.report_dir / name if name == 'report.json' else self.session / name
            self.assertEqual(binding, dict(size_bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest()))


if __name__ == '__main__':
    unittest.main()
