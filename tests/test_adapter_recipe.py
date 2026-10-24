"""Generated fixtures prove offline rules only; no household compatibility claim."""
import hashlib
import json
from pathlib import Path
import shutil
import socket
import stat
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


class AdapterRecipeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in ((socket, 'socket'), (socket, 'create_connection'),
                            (socket, 'getaddrinfo'), (subprocess, 'run'), (subprocess, 'Popen')):
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('Offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def sample(self, real=False, variant=None):
        original = codec.build_frame
        def build(number, kind, link, serial, fields):
            fields = list(fields)
            if variant == 'extra' and (kind, link) == (4, 9):
                fields.append((93, b'not-an-authentication-token'))
            if variant == 'reorder' and (kind, link) == (4, 9):
                fields = list(reversed(fields))
            if variant == 'duplicate' and (kind, link) == (4, 9):
                fields.append((16, b'\x01'))
            if variant == 'ack_only' and (kind, link) in ((5, 12), (3, 8)):
                kind, link, fields = 4, 11, []
            if variant == 'wrong_state' and (kind, link) in ((5, 12), (3, 8)):
                fields = [(key, bytes([value[0] ^ 1]) if key == 11 else value) for key, value in fields]
            if variant == 'state_extra' and (kind, link) in ((5, 12), (3, 8)):
                fields.append((160, b'unknown-session-value'))
            return original(number, kind, link, serial + (100 if variant == 'fresh' else 0), fields)
        with mock.patch.object(codec, 'build_frame', side_effect=build):
            directory = demo.create_demo_sample(self.root / 'captures')
        if real:
            path = directory / 'session.json'
            metadata = json.loads(path.read_text())
            metadata.update(simulation=False, script_version='generated_test_declaration',
                target_context=dict(label='测试灯', room='测试房间', kind='ordinary_switch_light', collection_id='1' * 32))
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = directory / 'events.jsonl'
            rows = [dict(json.loads(line), simulation=False) for line in path.read_text().splitlines()]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return directory

    def create(self, directory, **kwargs):
        return recipe.create_recipe(directory, self.root, **kwargs)

    def test_synthetic_recipe_never_unlocks_or_creates_driver(self):
        path, record = self.create(self.sample())
        self.assertTrue(record['simulation'])
        self.assertFalse(record['online_ready'])
        self.assertFalse(record['driver_generated'])
        self.assertFalse(record['executable_code'])
        self.assertEqual(record['bytes_sent'], 0)
        self.assertEqual(record['status'], 'simulation')
        self.assertEqual(set(p.name for p in path.parent.iterdir()), {'recipe.json', '离线适配报告.html'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_four_fixed_encodings_and_per_case_independent_states(self):
        _, record = self.create(self.sample(True))
        first = record['primary']
        self.assertEqual(record['selected_identifier'], demo.DEVICE.hex())
        self.assertEqual(len(first['encoder_comparisons']), 4)
        self.assertTrue(all(row['byte_equal'] for row in first['encoder_comparisons']))
        self.assertTrue(all(row['status'] == 'consistent' for row in first['per_case_checks']))
        self.assertTrue(first['codec_consistency'])
        self.assertFalse(record['codec_consistency'])  # a fresh second round is still absent
        self.assertFalse(record['online_ready'])
        self.assertTrue(all(record['unverified'].values()))

    def test_unknown_extra_reordered_and_duplicate_fields_are_not_absorbed(self):
        for variant in ('extra', 'reorder', 'duplicate'):
            with self.subTest(variant=variant):
                _, record = self.create(self.sample(True, variant), selected_identifier=demo.DEVICE.hex())
                self.assertFalse(record['primary']['codec_consistency'])
                self.assertTrue(record['primary']['unsupported_frames'])
                self.assertTrue(all(not row['byte_equal'] for row in record['primary']['encoder_comparisons']))
                self.assertEqual(record['encoder']['ordered_field_ids'], [16, 4, 9])
                self.assertNotIn('not-an-authentication-token', json.dumps(record))

    def test_ack_or_wrong_state_cannot_substitute_independent_feedback(self):
        for variant in ('ack_only', 'wrong_state'):
            with self.subTest(variant=variant):
                _, record = self.create(self.sample(True, variant))
                self.assertFalse(record['primary']['codec_consistency'])
                self.assertTrue(any(row['status'] == 'needs_more_evidence' for row in record['primary']['per_case_checks']))

    def test_unknown_state_field_is_unsupported_and_not_copied_to_recipe(self):
        _, record = self.create(self.sample(True, 'state_extra'))
        self.assertFalse(record['primary']['codec_consistency'])
        self.assertTrue(record['primary']['unsupported_frames'])
        self.assertNotIn('unknown-session-value', json.dumps(record))

    def test_missing_or_inconsistent_observation_requires_specific_resample(self):
        directory = self.sample(True)
        path = directory / 'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row in rows:
            if row.get('step') == '面板开' and row.get('event') == 'observation':
                row['app_display'] = 'off'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        _, record = self.create(directory)
        panel = next(row for row in record['primary']['per_case_checks'] if row['step'] == '面板开')
        self.assertEqual(panel['status'], 'needs_more_evidence')
        self.assertTrue(any('App显示' in text for text in panel['reasons']))
        self.assertFalse(record['primary']['codec_consistency'])

    def test_same_pcap_copy_with_changed_metadata_is_rejected_as_holdout(self):
        first = self.sample(True)
        second = self.root / 'captures' / 'copy'
        shutil.copytree(first, second)
        path = second / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['extra_note'] = 'different metadata is not an independent sample'
        path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, '第二轮PCAP与第一轮相同'):
            self.create(first, holdout_directory=second)

    def test_fresh_second_round_only_establishes_offline_consistency(self):
        first, second = self.sample(True), self.sample(True, 'fresh')
        _, record = self.create(first, holdout_directory=second)
        self.assertTrue(record['codec_consistency'])
        self.assertEqual(record['status'], 'two_round_offline_consistent')
        self.assertFalse(record['online_ready'])
        self.assertFalse(record['state_decoder']['physical_feedback_verified'])
        self.assertNotEqual(record['primary']['source_bindings']['traffic.pcap']['sha256'],
                            record['holdout']['source_bindings']['traffic.pcap']['sha256'])

    def test_synthetic_second_round_does_not_promote_real_declaration(self):
        first, second = self.sample(True), self.sample(False, 'fresh')
        _, record = self.create(first, holdout_directory=second)
        self.assertTrue(record['simulation'])
        self.assertFalse(record['codec_consistency'])
        self.assertFalse(record['online_ready'])

    def test_other_host_second_round_is_not_combined(self):
        first, second = self.sample(True), self.sample(True, 'fresh')
        path = second / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['target_ip'] = '192.0.2.21'
        path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, '第二轮指定主机不同'):
            self.create(first, holdout_directory=second)

    def test_wrong_direction_is_rejected_even_when_bytes_are_valid(self):
        directory = self.sample(True)
        original = recipe.analysis.analyze_session
        def changed(*args, **kwargs):
            destination, report = original(*args, **kwargs)
            for frame in report['frames']:
                if frame['kind'] == 'light_command_candidate':
                    frame['direction'] = 'from_host'
            (destination / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            return destination, report
        with mock.patch.object(recipe.analysis, 'analyze_session', side_effect=changed):
            _, record = self.create(directory, selected_identifier=demo.DEVICE.hex())
        self.assertTrue(all(not row['supported'] for row in record['primary']['encoder_comparisons']))
        self.assertFalse(record['primary']['codec_consistency'])

    def test_matching_frame_does_not_hide_opposite_command_or_state_in_window(self):
        for kind in ('command', 'state'):
            directory = self.sample(True)
            original = recipe.analysis.analyze_session
            def changed(*args, **kwargs):
                destination, report = original(*args, **kwargs)
                window = next(row for row in report['events'] if row['step'] == 'App开1')
                opposite = next(frame for frame in report['frames']
                    if 'App关1' in frame['nearby_steps'] and frame['kind'] ==
                    ('light_command_candidate' if kind == 'command' else 'state_update_candidate'))
                # Include an actually captured opposite frame as additional
                # conflicting window evidence, alongside the matching frames.
                window['frame_indices'].append(opposite['index'])
                (destination / 'report.json').write_text(json.dumps(report), encoding='utf-8')
                return destination, report
            with self.subTest(kind=kind), mock.patch.object(recipe.analysis, 'analyze_session', side_effect=changed):
                _, record = self.create(directory)
            app_on = next(row for row in record['primary']['per_case_checks'] if row['step'] == 'App开1')
            self.assertTrue(app_on['command_frame_indices'])
            self.assertTrue(app_on['state_frame_indices'])
            self.assertEqual(app_on['status'], 'needs_more_evidence')
            self.assertTrue(any('相反' in text for text in app_on['reasons']))
            self.assertFalse(record['primary']['codec_consistency'])

    def test_symlink_and_changed_original_are_rejected(self):
        directory = self.sample(True)
        raw = directory / 'traffic.pcap'
        moved = directory / 'other.pcap'
        raw.rename(moved)
        raw.symlink_to(moved)
        with self.assertRaises(ValueError):
            self.create(directory)
        raw.unlink()
        moved.rename(raw)
        original = recipe._evaluate
        def changed(*args):
            result = original(*args)
            with raw.open('ab') as output:
                output.write(b'\0')
            return result
        with mock.patch.object(recipe, '_evaluate', side_effect=changed):
            with self.assertRaises(ValueError):
                self.create(directory)
        self.assertFalse((self.root / 'private_adapter_recipes').exists())

    def test_short_or_unobserved_identifier_is_not_accepted(self):
        directory = self.sample(True)
        for identifier in ('1', '0011223344556677'):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.create(directory, selected_identifier=identifier)

    def test_concise_render_keeps_stopping_conditions_visible(self):
        _, record = self.create(self.sample(True))
        text = recipe.render_text(record)
        self.assertIn('在线接入：未就绪', text)
        self.assertIn('第二轮：尚未提供', text)
        self.assertIn('认证、会话建立', text)
        self.assertIn('时间邻近不是因果', text)

    def test_missing_and_oversized_originals_do_not_create_recipe(self):
        directory = self.sample(True)
        (directory / 'events.jsonl').unlink()
        with self.assertRaises((OSError, ValueError)):
            self.create(directory)
        with (directory / 'events.jsonl').open('wb') as output:
            output.truncate(recipe.baseline.INPUT_LIMITS['events.jsonl'] + 1)
        with self.assertRaises(ValueError):
            self.create(directory)
        self.assertFalse((self.root / 'private_adapter_recipes').exists())


if __name__ == '__main__':
    unittest.main()
