"""Session strategy UI uses only local originals and never starts live work."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import demo_sample as demo
import gui_worker as worker
import session_workbench as workbench


class SessionWorkbenchWorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def call(self, arguments):
        output = io.StringIO()
        with mock.patch('socket.socket', side_effect=AssertionError('no network')), \
             mock.patch('socket.create_connection', side_effect=AssertionError('no network')), \
             mock.patch('socket.getaddrinfo', side_effect=AssertionError('no discovery')), \
             mock.patch('subprocess.run', side_effect=AssertionError('no system tools')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('no capture')):
            code = worker.run(['--data-dir', str(self.root), *arguments],
                protocol=worker.Protocol(io.StringIO(), output))
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def result(self, events):
        return next(event for event in events if event['type'] == 'session_workbench')

    def fixture(self, real_declaration=False):
        directory = demo.create_demo_sample(self.root / 'captures')
        if real_declaration:
            path = directory / 'session.json'
            metadata = json.loads(path.read_text(encoding='utf-8'))
            metadata.update(simulation=False, script_version='generated_test_declaration')
            metadata['target_context'] = dict(label='测试灯', room='测试房间',
                kind='ordinary_switch_light', collection_id='1' * 32)
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = directory / 'events.jsonl'
            rows = [dict(json.loads(line), simulation=False)
                for line in path.read_text(encoding='utf-8').splitlines()]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return directory

    def assert_offline_only(self, events):
        result = self.result(events)
        self.assertFalse(result['online_ready'])
        self.assertFalse(result['driver_generated'])
        self.assertFalse(any(task['capture_allowed'] for task in result['tasks']))
        self.assertFalse(any(event['type'] in (
            'sampling_plan', 'sampling_preparation', 'capture_preflight', 'ha_wizard') for event in events))
        self.assertFalse(list(self.root.rglob('driver.py')))
        self.assertTrue(events[-1]['ok'])

    def test_demo_reaches_two_round_workbench_without_network_or_gap_window(self):
        code, events = self.call(['session-workbench-demo'])
        self.assertEqual(code, 0, events)
        result = self.result(events)
        self.assertTrue(result['simulation'])
        self.assertTrue(Path(result['json_file']).is_file())
        self.assertEqual(Path(result['json_file']).parent, Path(result['directory']))
        self.assertTrue(Path(result['directory']).is_relative_to(self.root / 'private_session_workbenches'))
        self.assertTrue(Path(result['session_dir']).is_dir())
        self.assertTrue(Path(result['comparison_dir']).is_dir())
        self.assertNotEqual(result['session_dir'], result['comparison_dir'])
        self.assertEqual(result['selected_identifier'], demo.DEVICE.hex())
        self.assertTrue(result['tasks'])
        self.assertTrue(all(task['ui_text'] for task in result['tasks']))
        self.assert_offline_only(events)

    def test_explicit_real_declaration_is_not_a_driver_or_live_authorization(self):
        directory = self.fixture(real_declaration=True)
        code, events = self.call(['session-workbench', '--session-dir', str(directory),
            '--identifier', demo.DEVICE.hex()])
        self.assertEqual(code, 0, events)
        result = self.result(events)
        self.assertFalse(result['simulation'])
        self.assertEqual(Path(result['session_dir']), directory)
        self.assertIsNone(result['comparison_dir'])
        self.assert_offline_only(events)

    def test_missing_source_fails_without_result(self):
        code, events = self.call(['session-workbench', '--session-dir', str(self.root / 'missing')])
        self.assertEqual(code, 1)
        self.assertFalse(any(event['type'] == 'session_workbench' for event in events))
        self.assertFalse(events[-1]['ok'])

    def test_forged_capture_binding_fails_instead_of_trusting_source_declaration(self):
        directory = self.fixture(real_declaration=True)
        path = directory / 'session.json'
        metadata = json.loads(path.read_text(encoding='utf-8'))
        metadata['pcap']['sha256'] = '0' * 64
        path.write_text(json.dumps(metadata), encoding='utf-8')
        code, events = self.call(['session-workbench', '--session-dir', str(directory)])
        self.assertEqual(code, 1)
        self.assertFalse(any(event['type'] == 'session_workbench' for event in events))
        self.assertFalse(events[-1]['ok'])

    def test_guessed_identifier_and_duplicate_comparison_are_rejected(self):
        directory = self.fixture()
        for arguments in (
            ['--identifier', '1112131415161718'],
            ['--comparison-dir', str(directory)],
        ):
            with self.subTest(arguments=arguments):
                code, events = self.call(['session-workbench', '--session-dir', str(directory), *arguments])
                self.assertEqual(code, 1)
                self.assertFalse(any(event['type'] == 'session_workbench' for event in events))
                self.assertFalse(events[-1]['ok'])

    def test_symlink_source_is_rejected_without_capture(self):
        directory = self.fixture()
        path = directory / 'traffic.pcap'
        renamed = directory / 'traffic-original.pcap'
        path.rename(renamed)
        path.symlink_to(renamed)
        code, events = self.call(['session-workbench', '--session-dir', str(directory)])
        self.assertEqual(code, 1)
        self.assertFalse(any(event['type'] == 'session_workbench' for event in events))

    def test_ui_projection_stays_bounded_and_cannot_promote_saved_flags(self):
        directory = self.fixture()
        path, record = workbench.create_workbench(directory, self.root)
        record.update(online_ready=True, driver_generated=True)
        record['candidate_identifiers'] = [format(number + 1, '016x') for number in range(257)]
        record['tasks'] = [dict(id='task-' + str(number), title='测试任务',
            category='recapture', status='needs_sample', capture_allowed=True,
            arbitrary_payload='PRIVATE_RAW_VALUE') for number in range(40)]
        with mock.patch.object(workbench, 'create_workbench', return_value=(path, record)), \
             mock.patch.object(workbench, 'render_text', return_value='测' * 300000), \
             mock.patch.object(workbench, 'render_task_text', return_value='细' * 300000):
            code, events = self.call(['session-workbench', '--session-dir', str(directory)])
        self.assertEqual(code, 0, events)
        result = self.result(events)
        self.assertEqual(len(result['tasks']), 32)
        self.assertEqual(result['candidates'], record['candidate_identifiers'][:256])
        self.assertTrue(result['candidate_list_truncated'])
        self.assertNotEqual(result['selected_identifier'], result['candidates'][0])
        self.assertIn('达到上限', result['report_text'])
        self.assertIn('32项上限', result['report_text'])
        self.assertTrue(all('达到上限' in row['ui_text'] for row in result['tasks']))
        raw = json.dumps(result, ensure_ascii=False).encode('utf-8')
        self.assertLess(len(raw), 2 * 1024 * 1024)
        self.assertNotIn(b'PRIVATE_RAW_VALUE', raw)
        self.assert_offline_only(events)

    def test_candidate_projection_preserves_no_selection_and_explicit_nonfirst_choice(self):
        directory = self.fixture()
        path, record = workbench.create_workbench(directory, self.root)
        candidates = ['1112131415161718', demo.DEVICE.hex()]
        record['candidate_identifiers'] = candidates
        for selected in (None, candidates[1]):
            with self.subTest(selected=selected):
                record['selected_identifier'] = selected
                with mock.patch.object(workbench, 'create_workbench', return_value=(path, record)):
                    code, events = self.call(['session-workbench', '--session-dir', str(directory)])
                self.assertEqual(code, 0, events)
                result = self.result(events)
                self.assertEqual(result['candidates'], candidates)
                self.assertFalse(result['candidate_list_truncated'])
                self.assertEqual(result['selected_identifier'], selected or '')
                self.assertNotEqual(result['selected_identifier'], candidates[0])
                self.assert_offline_only(events)


if __name__ == '__main__':
    unittest.main()
