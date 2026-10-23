"""Multi-round reports use generated documentation-address fixtures only."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import collection_report as collection
import demo_sample as demo


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.data = self.root / 'data'
        self.captures = self.data / 'captures'
        self.captures.mkdir(parents=True)
        self.output = self.root / 'reports'

    def sample(self, label=None, room='演示房间', collection_id='00000000000000000000000000000001'):
        folder = demo.create_demo_sample(self.captures)
        if label is not None:
            path = folder / 'session.json'
            value = json.loads(path.read_text())
            value['target_context'] = dict(label=label, room=room,
                kind='ordinary_switch_light', collection_id=collection_id)
            path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
        return folder

    def analyze(self):
        return collection.analyze_collection(self.data, self.output)

    def test_old_sample_without_context_remains_supported_and_unknown(self):
        self.sample()
        destination, report = self.analyze()
        row = report['rounds'][0]
        self.assertEqual(row['status'], 'analyzed')
        self.assertIsNone(row['target_context']['label'])
        self.assertIsNone(row['target_context']['kind'])
        self.assertFalse(row['target_context']['identity_verified'])
        self.assertEqual(row['steps']['complete_required_count'], 10)
        self.assertEqual(report['summary']['frame_count'], 18)
        self.assertTrue((destination / 'collection.html').is_file())
        self.assertTrue((destination / row['analysis_directory'] / 'report.json').is_file())

    def test_declared_context_does_not_confirm_physical_identity_or_wire_type(self):
        self.sample('合成灯一')
        _, report = self.analyze()
        row = report['rounds'][0]
        self.assertEqual(row['target_context']['declaration_source'], 'operator_declared')
        self.assertEqual(row['target_context']['label'], '合成灯一')
        self.assertFalse(row['target_context']['device_kind_verified'])
        self.assertFalse(row['device_candidates'][0]['ordinary_light_verified'])
        self.assertEqual(row['device_candidates'][0]['ordinary_light_context'], 'unconfirmed')
        self.assertFalse(report['readiness']['can_start_live_ha'])

    def test_labels_rooms_batch_ids_are_escaped_and_page_has_no_active_content(self):
        payload = '<script>alert("synthetic")</script>'
        self.sample(payload, payload)
        destination, report = self.analyze()
        html = (destination / 'collection.html').read_text()
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertNotIn('href=', html)
        self.assertNotIn('src=', html)
        self.assertIn("default-src 'none'", html)
        self.assertEqual(report['rounds'][0]['target_context']['label'], payload)

    def test_same_identifier_from_two_lights_never_merges_entities(self):
        self.sample('演示灯甲', collection_id='00000000000000000000000000000001')
        self.sample('演示灯乙', collection_id='00000000000000000000000000000002')
        _, report = self.analyze()
        self.assertEqual(report['summary']['round_count'], 2)
        self.assertEqual(report['summary']['candidate_occurrence_count'], 2)
        self.assertIsNone(report['summary']['device_count'])
        self.assertEqual(len(report['rounds']), 2)
        collision = report['identifier_collisions'][0]
        self.assertEqual(collision['identifier_hex'], demo.DEVICE.hex())
        self.assertEqual(len(collision['occurrences']), 2)
        self.assertFalse(collision['physical_entities_merged'])
        self.assertFalse(collision['identity_verified'])
        self.assertEqual(len({row['analysis_id'] for row in report['rounds']}), 2)

    def test_corrupt_round_stays_failed_and_successful_round_survives(self):
        self.sample('有效演示灯')
        broken = self.captures / 'broken'
        broken.mkdir()
        (broken / 'session.json').write_text('{invalid json')
        destination, report = self.analyze()
        self.assertEqual(report['summary']['analyzed_count'], 1)
        self.assertEqual(report['summary']['failed_count'], 1)
        self.assertEqual(report['quality']['level'], 'blocked')
        self.assertIsNone(report['summary']['packet_count'])
        row = next(row for row in report['rounds'] if row['status'] == 'failed')
        self.assertIn('JSONDecodeError', row['error'])
        self.assertEqual(row['summary'], {})
        self.assertIn('失败原因', (destination / 'collection.html').read_text())

    def test_blocked_single_analysis_not_masked_as_successful_coverage(self):
        folder = self.sample()
        (folder / 'events.jsonl').unlink()
        _, report = self.analyze()
        self.assertEqual(report['summary']['failed_count'], 0)
        self.assertEqual(report['summary']['blocked_count'], 1)
        self.assertEqual(report['quality']['level'], 'blocked')
        self.assertEqual(report['rounds'][0]['steps']['complete_required_count'], 0)
        self.assertEqual(len(report['rounds'][0]['steps']['missing']), 10)

    def test_inputs_remain_byte_identical(self):
        folder = self.sample('只读演示')
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.iterdir()}
        self.analyze()
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.iterdir()}
        self.assertEqual(before, after)

    def test_output_inside_captures_is_rejected_before_writes(self):
        self.sample()
        with self.assertRaisesRegex(ValueError, '只读'):
            collection.analyze_collection(self.data, self.captures / 'reports')
        self.assertFalse((self.captures / 'reports').exists())

    def test_one_level_only_deep_sample_not_discovered(self):
        self.sample('直属演示')
        deep_root = self.captures / 'nested' / 'deeper'
        demo.create_demo_sample(deep_root)
        _, report = self.analyze()
        self.assertEqual(report['summary']['round_count'], 1)
        self.assertIn('更深', report['ignored_entries'][0]['reason'])

    def test_deep_samples_alone_do_not_trigger_recursive_search(self):
        demo.create_demo_sample(self.captures / 'nested')
        with self.assertRaisesRegex(ValueError, '不递归'):
            self.analyze()
        self.assertFalse(self.output.exists())

    def test_symlinked_sample_directory_rejected_before_any_analysis(self):
        folder = self.sample()
        (self.captures / 'linked').symlink_to(folder, target_is_directory=True)
        with mock.patch.object(collection, 'analyze_session') as analyze:
            with self.assertRaisesRegex(ValueError, '符号链接'):
                self.analyze()
        analyze.assert_not_called()

    def test_symlinked_input_files_rejected(self):
        for name in ('session.json', 'events.jsonl', 'traffic.pcap'):
            with self.subTest(name=name):
                folder = self.sample()
                path = folder / name
                moved = self.root / (folder.name + '_' + name)
                path.rename(moved)
                path.symlink_to(moved)
                with self.assertRaisesRegex(ValueError, '符号链接'):
                    self.analyze()
                path.unlink()
                moved.rename(path)

    def test_symlinked_capture_root_or_ancestor_rejected(self):
        self.sample()
        alias = self.root / 'alias'
        alias.symlink_to(self.data, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            collection.analyze_collection(alias, self.output)
        captures = self.data / 'captures'
        original = self.data / 'original'
        captures.rename(original)
        captures.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.analyze()

    def test_symlinked_output_rejected(self):
        self.sample()
        actual = self.root / 'actual_reports'
        actual.mkdir()
        self.output.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.analyze()

    def test_session_limit_rejected_before_any_output(self):
        self.sample()
        self.sample()
        with mock.patch.object(collection, 'MAX_SESSIONS', 1):
            with self.assertRaisesRegex(ValueError, '轮数'):
                self.analyze()
        self.assertFalse(self.output.exists())

    def test_entry_limit_applies_even_to_ignored_directories(self):
        self.sample()
        (self.captures / 'ignored').mkdir()
        with mock.patch.object(collection, 'MAX_DIRECTORY_ENTRIES', 1):
            with self.assertRaisesRegex(ValueError, '条目'):
                self.analyze()
        self.assertFalse(self.output.exists())

    def test_total_byte_limit_applies_before_any_output(self):
        self.sample()
        with mock.patch.object(collection, 'MAX_TOTAL_BYTES', 1):
            with self.assertRaisesRegex(ValueError, '总大小'):
                self.analyze()
        self.assertFalse(self.output.exists())

    def test_single_file_size_limit_rejected(self):
        self.sample()
        with mock.patch.dict(collection.INPUT_LIMITS, {'session.json': 1}):
            with self.assertRaisesRegex(ValueError, '单文件'):
                self.analyze()

    def test_metadata_non_object_is_failed_round(self):
        folder = self.sample()
        (folder / 'session.json').write_text('[]')
        _, report = self.analyze()
        self.assertEqual(report['summary']['failed_count'], 1)
        self.assertIn('对象', report['rounds'][0]['error'])

    def test_unexpected_per_round_error_is_visible_and_next_round_runs(self):
        self.sample()
        self.sample()
        real = collection.analyze_session
        calls = []
        def analyze(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 1:
                raise RuntimeError('synthetic internal failure')
            return real(*args, **kwargs)
        with mock.patch.object(collection, 'analyze_session', side_effect=analyze):
            _, report = self.analyze()
        self.assertEqual(report['summary']['failed_count'], 1)
        self.assertEqual(report['summary']['analyzed_count'], 1)
        self.assertIn('RuntimeError', report['rounds'][0]['error'])

    def test_partial_summary_error_cannot_leave_success_status_or_counts(self):
        self.sample()
        real = collection.analyze_session
        def malformed(*args, **kwargs):
            destination, report = real(*args, **kwargs)
            report['quality']['checks'] = [None]
            return destination, report
        with mock.patch.object(collection, 'analyze_session', side_effect=malformed):
            _, report = self.analyze()
        row = report['rounds'][0]
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['summary'], {})
        self.assertEqual(row['quality']['level'], 'blocked')
        self.assertEqual(report['summary']['failed_count'], 1)
        self.assertIsNone(report['summary']['packet_count'])

    def test_synthetic_collection_remains_explicit_and_mixed_source_is_unknown(self):
        self.sample('演示一')
        second = self.sample('演示二')
        _, report = self.analyze()
        self.assertIs(report['simulation'], True)
        path = second / 'session.json'
        metadata = json.loads(path.read_text())
        metadata.pop('simulation')
        path.write_text(json.dumps(metadata))
        _, report = self.analyze()
        self.assertIsNone(report['simulation'])

    def test_invalid_context_values_are_unknown_rather_than_inferred(self):
        folder = self.sample()
        path = folder / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['target_context'] = dict(label=12, room='x' * 201, kind='other_device', collection_id=' ')
        path.write_text(json.dumps(metadata))
        _, report = self.analyze()
        context = report['rounds'][0]['target_context']
        self.assertEqual([context[key] for key in ('label', 'room', 'kind', 'collection_id')], [None] * 4)
        self.assertEqual(context['declaration_status'], 'invalid')
        self.assertEqual(context['declaration_source'], 'unknown')
        self.assertTrue(any('整组已忽略' in gap for gap in report['rounds'][0]['gaps']))

    def test_valid_optional_empty_room_is_preserved_without_missing_declaration_gap(self):
        self.sample('无房间声明的合成灯', room='')
        _, report = self.analyze()
        row = report['rounds'][0]
        self.assertEqual(row['target_context']['room'], '')
        self.assertEqual(row['target_context']['declaration_status'], 'declared')
        self.assertFalse(any('声明缺失' in gap for gap in row['gaps']))

    def test_single_round_rejected_context_is_not_accepted_by_collection(self):
        self.sample('合成声明')
        real = collection.analyze_session
        def rejected(*args, **kwargs):
            destination, report = real(*args, **kwargs)
            report['target_context'] = None
            return destination, report
        with mock.patch.object(collection, 'analyze_session', side_effect=rejected):
            _, report = self.analyze()
        row = report['rounds'][0]
        self.assertIsNone(row['target_context']['label'])
        self.assertEqual(row['target_context']['declaration_status'], 'invalid')
        self.assertTrue(any('单轮分析未采信' in gap for gap in row['gaps']))

    def test_invalid_context_is_discarded_as_a_whole_under_capture_validator(self):
        for invalid in (dict(label='合成灯', room='合成房间', kind='ordinary_switch_light', collection_id='invalid'),
                        dict(label='灯' * 81, room='', kind='ordinary_switch_light', collection_id='0' * 32),
                        dict(label='合成\n灯', room='', kind='ordinary_switch_light', collection_id='0' * 32)):
            with self.subTest(invalid=invalid):
                context = collection._context(dict(target_context=invalid))
                self.assertEqual(context['declaration_status'], 'invalid')
                self.assertTrue(all(context[key] is None for key in ('label', 'room', 'kind', 'collection_id')))

    def test_private_report_permissions_and_unique_destinations(self):
        self.sample()
        destination, _ = self.analyze()
        another, _ = self.analyze()
        self.assertNotEqual(destination, another)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        for name in ('collection.json', 'collection.html'):
            self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)

    def test_cli_uses_existing_local_samples_and_returns_failure_for_failed_round(self):
        folder = self.sample()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(collection.main(['--capture-root', str(self.data),
                                             '--output-root', str(self.output)]), 0)
        self.assertIn('私有多轮报告', output.getvalue())
        (folder / 'session.json').write_text('[]')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(collection.main(['--capture-root', str(self.data),
                                             '--output-root', str(self.output)]), 1)

    def test_no_network_process_upload_or_browser_dependencies(self):
        self.sample()
        # Running the entire offline workflow while forbidding subprocess/socket
        # construction catches accidental additions beyond the source allowlist.
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No process')):
            with mock.patch('socket.socket', side_effect=AssertionError('No socket')):
                self.analyze()


if __name__ == '__main__':
    unittest.main()
