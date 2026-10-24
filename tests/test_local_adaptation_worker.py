"""Local no-code workflow boundaries, with synthetic input and no system tools."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import gui_worker as worker


class LocalAdaptationWorkerTests(unittest.TestCase):
    def call(self, root, arguments):
        output = io.StringIO()
        with mock.patch('socket.socket', side_effect=AssertionError('no network')), \
             mock.patch('subprocess.run', side_effect=AssertionError('no tools')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('no tools')):
            code = worker.run(['--data-dir', str(root), *arguments],
                              protocol=worker.Protocol(io.StringIO(), output))
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_demo_to_no_code_recipe_remains_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code, events = self.call(root, ['local-adapt-demo'])
            self.assertEqual(code, 0, events)
            result = next(e for e in events if e['type'] == 'local_adaptation')
            self.assertFalse(result['online_ready'])
            self.assertEqual(result['kind'], 'local_analysis')
            self.assertIn('0102030405060708', result['candidates'])
            self.assertTrue(Path(result['directory']).is_relative_to(root / 'private_local_adaptations'))
            code, events = self.call(root, ['local-recipe', '--session-dir', result['session_dir'],
                '--identifier', '0102030405060708'])
            self.assertEqual(code, 0, events)
            result = next(e for e in events if e['type'] == 'local_adaptation')
            self.assertEqual(result['kind'], 'codec_recipe')
            self.assertFalse(result['online_ready'])
            self.assertTrue(Path(result['recipe_file']).is_file())
            self.assertFalse(list(root.rglob('driver.py')))
            self.assertTrue(events[-1]['ok'])

    def test_missing_sample_fails_without_success_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code, events = self.call(root, ['local-adapt', '--session-dir', str(root / 'missing')])
            self.assertEqual(code, 1)
            self.assertFalse(any(e['type'] == 'local_adaptation' for e in events))
            self.assertFalse(events[-1]['ok'])

    def test_native_event_budget_has_visible_truncation(self):
        value = worker.bounded_local_text('测' * 300000)
        self.assertIn('达到上限', value)
        self.assertLess(len(value.encode('utf-8')), 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
