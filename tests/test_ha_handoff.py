"""Private local HA handoff tests using generated documentation-address packets."""
import hashlib
import json
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture as analysis
import baseline_review as baseline
import demo_sample as demo
import ha_handoff as handoff


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        # Export has no business invoking a process, network, capture or GUI
        # backend. Declarations below remain synthetic test inputs only.
        for owner, name in [(socket, 'socket'), (socket, 'create_connection'),
                            (socket, 'getaddrinfo'), (subprocess, 'run'),
                            (subprocess, 'Popen')]:
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('Offline export only'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def fixture(self, real_declaration=True, pending=False):
        directory = demo.create_demo_sample(self.root / 'captures')
        if real_declaration:
            path = directory / 'session.json'
            metadata = json.loads(path.read_text())
            metadata.update(simulation=False, script_version='test_real_declaration',
                sample_origin='test_operator_declaration', target_context=dict(label='合成声明灯',
                    room='合成声明房间', kind='ordinary_switch_light', collection_id='1' * 32))
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = directory / 'events.jsonl'
            rows = [dict(json.loads(line), simulation=False) for line in path.read_text().splitlines()]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        report_dir, report = analysis.analyze_session(directory, self.root / 'private_reports')
        form = baseline.draft_review(report)
        if real_declaration and not pending:
            form['decisions'] = {key: 'pass' for key in baseline.CRITERION_IDS}
            form['notes'] = {key: '合成fixture的人工声明：仅测试核对入口，未验证实物。'
                             for key in baseline.CRITERION_IDS}
            form['selected_identifier'] = demo.DEVICE.hex()
        review_file, _ = baseline.save_review(report_dir, directory, self.root, **form)
        return directory, report_dir, review_file

    def digest(self, path):
        raw = path.read_bytes()
        return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def test_passed_declaration_exports_private_verified_evidence_without_network(self):
        directory, report_dir, review_file = self.fixture()
        originals = {path.name: self.digest(path) for path in directory.iterdir()}
        destination, manifest = handoff.export_handoff(review_file, self.root, expected_host=demo.HOST)
        self.assertEqual(destination.parent, self.root / 'private_ha_handoffs')
        self.assertFalse(destination.name.startswith('.'))
        self.assertEqual(json.loads((destination / 'manifest.json').read_text()), manifest)
        self.assertEqual(set(path.name for path in destination.iterdir()), {
            'manifest.json', 'baseline_review.json', 'report.json', 'light_state_model.py', '开始HA接入.md'})
        self.assertEqual((destination / 'baseline_review.json').read_bytes(), review_file.read_bytes())
        self.assertEqual((destination / 'report.json').read_bytes(), (report_dir / 'report.json').read_bytes())
        self.assertEqual((destination / 'light_state_model.py').read_bytes(), handoff.STATE_MODEL_PATH.read_bytes())
        for name, expected in manifest['copied_files'].items():
            self.assertEqual(self.digest(destination / name), expected)
        for name, expected in manifest['local_originals'].items():
            self.assertEqual(self.digest(self.root / expected['path']),
                             {key: expected[key] for key in ('size_bytes', 'sha256')})
            self.assertFalse(Path(expected['path']).is_absolute())
        self.assertFalse(manifest['pcap_copied'])
        self.assertFalse(list(destination.rglob('*.pcap')))
        self.assertEqual(originals, {path.name: self.digest(path) for path in directory.iterdir()})
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in destination.iterdir()))

    def test_manifest_opens_research_and_keeps_every_live_parameter_unknown(self):
        _, _, review_file = self.fixture()
        destination, manifest = handoff.export_handoff(review_file, self.root)
        self.assertEqual(manifest['stage'], 'integration_research')
        self.assertTrue(manifest['can_start_integration_work'])
        self.assertFalse(manifest['live_control_enabled'])
        self.assertFalse(manifest['identity_authenticated'])
        self.assertFalse(manifest['physical_feedback_verified'])
        self.assertTrue(manifest['private'])
        self.assertFalse(manifest['automatic_upload_enabled'])
        self.assertEqual(manifest['selected_wire_identifier'], demo.DEVICE.hex())
        self.assertEqual(manifest['host_ip'], demo.HOST)
        self.assertEqual(manifest['target_context']['label'], '合成声明灯')
        self.assertTrue(all(value is None for value in manifest['unresolved_parameters'].values()))
        self.assertEqual({step['id'] for step in manifest['ha_steps']}, {
            'connection_authentication', 'command_session', 'independent_state',
            'unavailable_reconnect', 'single_light_acceptance'})
        self.assertTrue(all(step['status'] == 'pending' for step in manifest['ha_steps']))
        self.assertFalse(list(destination.glob('*.yaml')))
        self.assertNotIn(str(self.root), (destination / 'manifest.json').read_text())

    def test_chinese_guide_states_private_boundaries_and_single_light_acceptance(self):
        _, _, review_file = self.fixture()
        destination, _ = handoff.export_handoff(review_file, self.root)
        text = (destination / '开始HA接入.md').read_text()
        for phrase in ('私有', '认证', 'ACK', '物理反馈', '不可用', '重连', '面板', '逐组', '新类型',
                       '不是可运行适配器', '不会连接或扫描', '不操作物业安防', 'PCAP 没有复制'):
            self.assertIn(phrase, text)

    def test_pending_and_demo_reviews_cannot_open_ha_research(self):
        for real in (False, True):
            with self.subTest(real_declaration=real):
                _, _, review_file = self.fixture(real_declaration=real, pending=True)
                with self.assertRaises(ValueError):
                    handoff.export_handoff(review_file, self.root)
        self.assertFalse((self.root / 'private_ha_handoffs').exists())

    def test_other_host_is_rejected_before_output_creation(self):
        _, _, review_file = self.fixture()
        with self.assertRaises(ValueError):
            handoff.export_handoff(review_file, self.root, expected_host='192.0.2.21')
        self.assertFalse((self.root / 'private_ha_handoffs').exists())

    def test_changed_original_or_report_is_rejected_before_output_creation(self):
        for name in ('session.json', 'events.jsonl', 'traffic.pcap', 'report.json'):
            with self.subTest(changed=name):
                directory, report_dir, review_file = self.fixture()
                path = (report_dir if name == 'report.json' else directory) / name
                with path.open('ab') as stream:
                    stream.write(b' ')
                with self.assertRaises(ValueError):
                    handoff.export_handoff(review_file, self.root)
        self.assertFalse((self.root / 'private_ha_handoffs').exists())

    def test_symlink_review_model_or_destination_is_rejected(self):
        _, _, review_file = self.fixture()
        alias = review_file.with_name('review_link.json')
        alias.symlink_to(review_file)
        with self.assertRaises(ValueError):
            handoff.export_handoff(alias, self.root)
        model = self.root / 'model-link.py'
        model.symlink_to(handoff.STATE_MODEL_PATH)
        with mock.patch.object(handoff, 'STATE_MODEL_PATH', model):
            with self.assertRaises(ValueError):
                handoff.export_handoff(review_file, self.root)
        other = self.root / 'other-output'
        other.mkdir()
        (self.root / 'private_ha_handoffs').symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            handoff.export_handoff(review_file, self.root)
        self.assertEqual(list(other.iterdir()), [])

    def test_oversized_model_and_total_output_are_bounded(self):
        _, _, review_file = self.fixture()
        large = self.root / 'large.py'
        large.write_bytes(b'x' * (handoff.MAX_MODEL_BYTES + 1))
        with mock.patch.object(handoff, 'STATE_MODEL_PATH', large):
            with self.assertRaises(ValueError):
                handoff.export_handoff(review_file, self.root)
        with mock.patch.object(handoff, 'MAX_OUTPUT_BYTES', 10):
            with self.assertRaises(ValueError):
                handoff.export_handoff(review_file, self.root)
        self.assertFalse((self.root / 'private_ha_handoffs').exists())

    def test_copy_corruption_retains_failure_marker_without_success_folder(self):
        _, _, review_file = self.fixture()
        original_write = handoff._write
        def corrupt_report(path, raw):
            original_write(path, raw + b'corrupt' if path.name == 'report.json' else raw)
        with mock.patch.object(handoff, '_write', side_effect=corrupt_report):
            with self.assertRaises(ValueError):
                handoff.export_handoff(review_file, self.root)
        outputs = list((self.root / 'private_ha_handoffs').iterdir())
        self.assertEqual(len(outputs), 1)
        self.assertTrue(outputs[0].name.endswith('.incomplete'))
        self.assertTrue((outputs[0] / 'EXPORT_FAILED.txt').is_file())
        self.assertTrue(review_file.is_file())

    def test_original_change_during_export_prevents_final_rename(self):
        directory, _, review_file = self.fixture()
        original_write = handoff._write
        def change_after_copy(path, raw):
            original_write(path, raw)
            if path.name == 'manifest.json':
                with (directory / 'events.jsonl').open('a') as stream:
                    stream.write('{"event":"synthetic_change_during_export"}\n')
        with mock.patch.object(handoff, '_write', side_effect=change_after_copy):
            with self.assertRaises(ValueError):
                handoff.export_handoff(review_file, self.root)
        outputs = list((self.root / 'private_ha_handoffs').iterdir())
        self.assertEqual(len(outputs), 1)
        self.assertTrue(outputs[0].name.endswith('.incomplete'))
        self.assertTrue((outputs[0] / 'EXPORT_FAILED.txt').is_file())

    def test_two_exports_create_distinct_verified_packages_and_do_not_overwrite(self):
        _, _, review_file = self.fixture()
        first, _ = handoff.export_handoff(review_file, self.root)
        hashes = {path.name: self.digest(path) for path in first.iterdir()}
        second, _ = handoff.export_handoff(review_file, self.root)
        self.assertNotEqual(first, second)
        self.assertEqual(hashes, {path.name: self.digest(path) for path in first.iterdir()})


if __name__ == '__main__':
    unittest.main()
