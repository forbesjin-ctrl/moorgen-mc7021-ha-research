"""Gap guidance may prepare a local form; it must never begin capture itself."""
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


class SamplingGapWorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def call(self, arguments):
        output = io.StringIO()
        with mock.patch('socket.socket', side_effect=AssertionError('no network')), \
             mock.patch('socket.create_connection', side_effect=AssertionError('no network')), \
             mock.patch('socket.getaddrinfo', side_effect=AssertionError('no discovery')), \
             mock.patch('subprocess.run', side_effect=AssertionError('no tools')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('no capture')):
            code = worker.run(['--data-dir', str(self.root), *arguments],
                              protocol=worker.Protocol(io.StringIO(), output))
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def fixture(self, real_declaration=False, context=True):
        directory = demo.create_demo_sample(self.root / 'captures')
        if real_declaration:
            path = directory / 'session.json'
            metadata = json.loads(path.read_text())
            metadata.update(simulation=False, script_version='generated_test_declaration')
            if context:
                metadata['target_context'] = dict(label='测试灯', room='测试房间',
                    kind='ordinary_switch_light', collection_id='1' * 32)
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = directory / 'events.jsonl'
            rows = [dict(json.loads(line), simulation=False) for line in path.read_text().splitlines()]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return directory

    def plan(self, directory):
        code, events = self.call(['sampling-plan', '--session-dir', str(directory)])
        self.assertEqual(code, 0, events)
        return next(event for event in events if event['type'] == 'sampling_plan')

    def prepare(self, directory, plan, task):
        return self.call(['sampling-prepare', '--session-dir', str(directory),
            '--plan-file', plan['plan_file'], '--task-id', task])

    def test_normal_analysis_automatically_adds_gap_plan(self):
        directory = self.fixture()
        code, events = self.call(['analyze', '--session-dir', str(directory)])
        self.assertEqual(code, 0, events)
        self.assertTrue(any(e['type'] == 'result' for e in events))
        plan = next(e for e in events if e['type'] == 'sampling_plan')
        self.assertFalse(plan['online_ready'])
        self.assertFalse(any(t['capture_allowed'] for t in plan['tasks']))

    def test_preparation_only_returns_same_target_no_process(self):
        directory = self.fixture(True)
        plan = self.plan(directory)
        task = next(t for t in plan['tasks'] if t['id'] == 'independent_round')
        self.assertTrue(task['capture_allowed'])
        code, events = self.prepare(directory, plan, 'independent_round')
        self.assertEqual(code, 0, events)
        prepared = next(e for e in events if e['type'] == 'sampling_preparation')
        self.assertEqual(prepared['target_ip'], demo.HOST)
        self.assertEqual(prepared['target_context']['label'], '测试灯')
        self.assertFalse(prepared['capture_started'])
        self.assertFalse(prepared['network_access_performed'])
        self.assertFalse(prepared['online_ready'])
        self.assertFalse(any(e['type'] == 'capture_preflight' for e in events))

    def test_synthetic_plan_cannot_prepare_real_capture(self):
        directory = self.fixture()
        plan = self.plan(directory)
        code, events = self.prepare(directory, plan, 'independent_round')
        self.assertEqual(code, 1)
        self.assertFalse(any(e['type'] == 'sampling_preparation' for e in events))

    def test_changed_source_requires_new_plan(self):
        directory = self.fixture(True)
        plan = self.plan(directory)
        path = directory / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['extra_test_note'] = 'changed-source'
        path.write_text(json.dumps(metadata), encoding='utf-8')
        code, events = self.prepare(directory, plan, 'independent_round')
        self.assertEqual(code, 1)
        self.assertFalse(any(e['type'] == 'sampling_preparation' for e in events))

    def test_forged_task_permission_does_not_unlock_software_gap(self):
        directory = self.fixture(True)
        plan = self.plan(directory)
        path = Path(plan['plan_file'])
        record = json.loads(path.read_text())
        for task in record['tasks']:
            task.update(category='recapture', capture_allowed=True, status='needs_sample')
        record.update(online_ready=True, driver_generated=True)
        path.write_text(json.dumps(record), encoding='utf-8')
        code, events = self.prepare(directory, plan, 'authentication_strategy')
        self.assertEqual(code, 1)
        self.assertFalse(any(e['type'] == 'sampling_preparation' for e in events))

    def test_unlabelled_source_is_readable_but_not_preparable(self):
        directory = self.fixture(True, context=False)
        plan = self.plan(directory)
        self.assertFalse(any(t['capture_allowed'] for t in plan['tasks']))
        code, events = self.prepare(directory, plan, 'independent_round')
        self.assertEqual(code, 1)
        self.assertFalse(any(e['type'] == 'sampling_preparation' for e in events))

    def test_missing_original_does_not_emit_plan(self):
        code, events = self.call(['sampling-plan', '--session-dir', str(self.root / 'missing')])
        self.assertEqual(code, 1)
        self.assertFalse(any(e['type'] == 'sampling_plan' for e in events))


if __name__ == '__main__':
    unittest.main()
