"""GUI worker tests with local synthetic files and mocked capture boundaries."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('gui_worker', ROOT / 'tools/gui_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
capture = worker.capture
IP = '192.0.2.20'
UDID = '00000001-0000000000000001'


def events(output):
    return [json.loads(line) for line in output.getvalue().splitlines()]


class ReplyStream:
    """A fake GUI which only answers the current emitted prompt."""

    def __init__(self, output, replies):
        self.output = output
        self.replies = iter(replies)

    def readline(self, limit):
        reply = next(self.replies, None)
        if reply is None:
            return ''
        prompt = [row for row in events(self.output) if row['type'] == 'prompt'][-1]
        if callable(reply):
            return reply(prompt)
        return json.dumps(dict(id=prompt['id'], value=reply)) + '\n'


class FakeCapture:
    def __init__(self):
        self.stopped = False

    def wait_ready(self, timeout=12):
        pass

    def check(self):
        pass

    def stop(self):
        self.stopped = True
        return dict(graceful=True, still_running=False, process_exit=0,
                    stats=dict(captured=1, received_by_filter=1, dropped_by_kernel=0))


class FakeBackend:
    simulated = False

    def __init__(self):
        self.capture = FakeCapture()
        self.calls = []

    def prepare(self):
        self.calls.append('prepare')

    def list_rvis(self):
        self.calls.append('list')
        return []

    def authorize(self):
        self.calls.append('authorize')

    def create_rvi(self, udid):
        self.calls.append('create')
        return True, 'Starting device {} [SUCCEEDED] with interface rvi0'.format(udid), 0

    def remove_rvi(self, udid):
        self.calls.append('remove')

    def start_capture(self, ip, interface, directory):
        self.calls.append('start')
        (directory / 'traffic.pcap').write_bytes(b'SYNTHETIC-MOCK-ONLY')
        return self.capture


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        for name in ('run', 'Popen'):
            patch = mock.patch.object(capture.subprocess, name,
                side_effect=AssertionError('Real process calls are forbidden in GUI worker tests'))
            patch.start()
            self.addCleanup(patch.stop)

    def protocol(self, replies=()):
        output = io.StringIO()
        return worker.Protocol(ReplyStream(output, replies), output), output

    def args(self, mode, *extra):
        return ['--data-dir', str(self.root / 'data'), mode] + list(extra)

    def capture_args(self):
        return self.args('capture', '--host-ip', IP, '--udid', UDID)

    def fake_analysis(self, directory, output_root=None, ordinary_ids=()):
        self.assertTrue((directory / 'session.json').is_file())
        destination = output_root / 'analysis_test'
        destination.mkdir(parents=True)
        (destination / '报告.html').write_text('<html>local test</html>', encoding='utf-8')
        return destination, dict(summary=dict(frame_count=0), quality=dict(level='blocked'), simulation=False)

    def short_flow(self, session):
        session.action('测试一步', '仅记录合成操作，不控制设备。', 0, observe=False)
        session.metadata['flow_completed'] = True

    def test_demo_produces_real_local_synthetic_report_and_one_final_event(self):
        protocol, output = self.protocol()
        with mock.patch.object(capture.SystemBackend, 'prepare', side_effect=AssertionError('No system backend')):
            result = worker.run(self.args('demo'), protocol)
        self.assertEqual(result, 0)
        rows = events(output)
        self.assertEqual(rows[-1], dict(type='finished', ok=True))
        self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)
        report_event = next(row for row in rows if row['type'] == 'result')
        self.assertTrue(Path(report_event['report_path']).is_file())
        self.assertTrue(report_event['simulation'])
        self.assertGreater(report_event['summary']['frame_count'], 0)
        report = json.loads((Path(report_event['report_dir']) / 'report.json').read_text())
        self.assertFalse(report['readiness']['can_start_live_ha'])
        self.assertFalse((self.root / 'data/captures').exists())
        self.assertEqual([row for row in rows if row['type'] == 'prompt'], [])

    def test_analyze_does_not_declare_any_real_device_as_ordinary_light(self):
        directory = worker.demo.create_demo_sample(self.root / 'samples')
        protocol, output = self.protocol()
        with mock.patch.object(worker, 'analyze_session', wraps=worker.analyze_session) as analyze:
            result = worker.run(self.args('analyze', '--session-dir', str(directory)), protocol)
        self.assertEqual(result, 0)
        self.assertEqual(analyze.call_args.kwargs['ordinary_ids'], ())
        self.assertEqual(analyze.call_args.kwargs['output_root'], self.root / 'data/private_reports')
        self.assertEqual(events(output)[-1]['type'], 'finished')

    def test_missing_sample_emits_error_without_traceback(self):
        protocol, output = self.protocol()
        code = worker.run(self.args('analyze', '--session-dir', str(self.root / 'missing')), protocol)
        self.assertEqual(code, 1)
        self.assertTrue(any(row['type'] == 'error' for row in events(output)))
        self.assertNotIn('Traceback', output.getvalue())
        self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_bad_args_are_json_and_do_not_echo_private_value(self):
        protocol, output = self.protocol()
        code = worker.run(self.args('capture', '--host-ip', IP, '--udid'), protocol)
        self.assertEqual(code, 1)
        self.assertEqual([r['type'] for r in events(output)], ['error', 'finished'])

    def test_invalid_ip_stops_before_backend_creation(self):
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('Should not reach backend'))
        code = worker.run(self.args('capture', '--host-ip', 'example.invalid', '--udid', UDID),
                          protocol, backend_factory=factory)
        self.assertEqual(code, 1)
        factory.assert_not_called()
        self.assertFalse((self.root / 'data/captures').exists())

    def test_capture_waits_for_gui_then_cleans_before_analysis(self):
        protocol, output = self.protocol(['', ''])
        backend = FakeBackend()
        def analyze(directory, output_root=None, ordinary_ids=()):
            self.assertTrue(backend.capture.stopped)
            self.assertEqual(backend.calls[-1], 'remove')
            metadata = json.loads((directory / 'session.json').read_text())
            self.assertEqual(metadata['sample_origin'], 'external_owner_household')
            self.assertFalse(metadata['project_household_verified'])
            self.assertEqual(metadata['household_control_commands_sent'], 0)
            self.assertEqual(metadata['user_confirmed_actions'], 1)
            return self.fake_analysis(directory, output_root, ordinary_ids)
        with mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=analyze):
            code = worker.run(self.capture_args(), protocol, backend_factory=lambda: backend)
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(backend.calls, ['prepare', 'list', 'authorize', 'list', 'create', 'start', 'remove'])
        rows = events(output)
        prompts = [row for row in rows if row['type'] == 'prompt']
        self.assertEqual(len(prompts), 2)
        self.assertEqual(prompts[0]['options'][0]['value'], '')
        self.assertEqual(prompts[1]['options'][0]['label'], '动作已完成')
        self.assertNotEqual(prompts[0]['id'], prompts[1]['id'])
        self.assertNotIn(UDID, output.getvalue())

    def test_stopping_or_eof_during_prompt_preserves_records_and_cleans(self):
        for replies in ([], ['q']):
            with self.subTest(replies=replies), tempfile.TemporaryDirectory() as sub:
                protocol, output = self.protocol(replies)
                backend = FakeBackend()
                args = ['--data-dir', sub, 'capture', '--host-ip', IP, '--udid', UDID]
                with mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                        mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
                    self.assertEqual(worker.run(args, protocol, backend_factory=lambda: backend), 1)
                self.assertTrue(backend.capture.stopped)
                self.assertIn('remove', backend.calls)
                metadata_path = next(Path(sub).glob('captures/*/session.json'))
                metadata = json.loads(metadata_path.read_text())
                self.assertEqual(metadata['status'], 'interrupted')
                self.assertEqual(metadata['user_confirmed_actions'], 0)
                self.assertTrue(any(row['type'] == 'result' for row in events(output)))
                self.assertFalse(events(output)[-1]['ok'])

    def test_sigint_uses_existing_capture_cleanup(self):
        protocol, output = self.protocol()
        backend = FakeBackend()
        def interrupted(session):
            session.signal_handler(signal.SIGINT, None)
        original_handler = signal.getsignal(signal.SIGINT)
        with mock.patch.object(worker.GuiGuidedSession, 'flow', interrupted), \
                mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
            self.assertEqual(worker.run(self.capture_args(), protocol, backend_factory=lambda: backend), 1)
        self.assertEqual(signal.getsignal(signal.SIGINT), original_handler)
        self.assertTrue(backend.capture.stopped)
        self.assertIn('remove', backend.calls)
        self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_prepare_failure_does_not_authorize_or_create_interface(self):
        protocol, output = self.protocol()
        backend = FakeBackend()
        backend.prepare = mock.Mock(side_effect=capture.CaptureError('需要安装系统工具。'))
        with mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
            code = worker.run(self.capture_args(), protocol, backend_factory=lambda: backend)
        self.assertEqual(code, 1)
        self.assertEqual(backend.calls, [])
        self.assertTrue(any(row['type'] == 'error' for row in events(output)))

    def test_library_prints_and_errors_are_json_logs_with_udid_redacted(self):
        protocol, output = self.protocol()
        backend = FakeBackend()
        def broken_prepare():
            print('private phone: ' + UDID.upper())
            print('diagnostic', file=sys.stderr)
            raise capture.CaptureError('Phone ' + UDID)
        backend.prepare = broken_prepare
        with mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
            worker.run(self.capture_args(), protocol, backend_factory=lambda: backend)
        self.assertNotIn(UDID, output.getvalue())
        self.assertNotIn(UDID.upper(), output.getvalue())
        self.assertIn('[已隐藏手机标识]', output.getvalue())
        self.assertTrue(all('type' in row for row in events(output)))

    def test_mismatched_prompt_stops_and_cleans_instead_of_advancing(self):
        protocol, output = self.protocol([lambda prompt: json.dumps(dict(id='stale', value='')) + '\n'])
        backend = FakeBackend()
        with mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
            self.assertEqual(worker.run(self.capture_args(), protocol, backend_factory=lambda: backend), 1)
        self.assertTrue(backend.capture.stopped)
        self.assertIn('remove', backend.calls)
        metadata = json.loads(next((self.root / 'data').glob('captures/*/session.json')).read_text())
        self.assertEqual(metadata['status'], 'failed')
        self.assertEqual(metadata['user_confirmed_actions'], 0)


class ProtocolTests(unittest.TestCase):
    def protocol(self, replies):
        output = io.StringIO()
        return worker.Protocol(ReplyStream(output, replies), output), output

    def test_bounded_json_responses_reject_malformed_or_unexpected_fields(self):
        replies = [lambda p: 'not json\n',
                   lambda p: json.dumps(dict(id=p['id'], value=1)) + '\n',
                   lambda p: json.dumps(dict(id=p['id'], value='', extra='unexpected')) + '\n',
                   lambda p: json.dumps(dict(id=p['id'], value='not-an-option')) + '\n',
                   lambda p: 'x' * (worker.MAX_INPUT_BYTES + 1) + '\n',
                   lambda p: json.dumps(dict(id=p['id'], value=''))]
        for reply in replies:
            with self.subTest(reply=reply):
                protocol, _ = self.protocol([reply])
                with self.assertRaises(worker.WorkerError):
                    protocol.request('test', [dict(value='', label='继续')])

    def test_chinese_utf8_limit_is_bytes_not_characters(self):
        reply = lambda p: json.dumps(dict(id=p['id'], value='灯' * 30000), ensure_ascii=False) + '\n'
        protocol, _ = self.protocol([reply])
        with self.assertRaises(worker.WorkerError):
            protocol.request('test', [])

    def test_eof_and_stop_are_explicit_cancellation(self):
        for replies in ([], ['q']):
            protocol, _ = self.protocol(replies)
            with self.assertRaises(worker.WorkerCancelled):
                protocol.request('test', [dict(value='q', label='结束')])

    def test_log_bridge_does_not_recurse_and_flushes_partial_lines(self):
        output = io.StringIO()
        protocol = worker.Protocol(io.StringIO(), output)
        sink = worker.JsonLog(protocol)
        with mock.patch.object(sys, 'stdout', sink):
            print('first')
            print('partial', end='', flush=True)
        self.assertEqual(events(output), [dict(type='log', text='first'), dict(type='log', text='partial')])

    def test_physical_app_and_boolean_choices_have_distinct_chinese_labels(self):
        self.assertEqual(worker.choice_label('实际灯', 'on'), '灯亮着')
        self.assertEqual(worker.choice_label('App显示', 'on'), '显示开')
        self.assertEqual(worker.choice_label('App是否自动更新', 'no'), '没有自动更新')
        self.assertEqual(worker.choice_label('刷新', False), '无或不刷新')
        self.assertEqual(worker.choice_label('恢复', True), '需要')

    def test_simulated_wait_skips_sleep_but_records_zero_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = capture.Journal(Path(temporary), True)
            self.addCleanup(journal.close)
            output = io.StringIO()
            protocol = worker.Protocol(io.StringIO(), output)
            session = worker.GuiGuidedSession(IP, UDID, journal, capture.DemoBackend(),
                protocol=protocol, sleep_fn=mock.Mock(side_effect=AssertionError('No wait in demo')))
            session.wait(20)
            self.assertEqual(events(output), [dict(type='progress', remaining_seconds=0)])
            self.assertEqual(journal.rows[-1]['event'], 'observation_wait_end')

    def test_observation_choices_record_physical_app_and_auto_update_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = capture.Journal(Path(temporary), True)
            self.addCleanup(journal.close)
            protocol, output = self.protocol(['1', '2', '3'])
            session = worker.GuiGuidedSession(IP, UDID, journal, capture.DemoBackend(), protocol=protocol)
            observation = session.observe('面板测试', update=True)
            self.assertEqual(observation['physical_light'], 'on')
            self.assertEqual(observation['app_display'], 'off')
            self.assertEqual(observation['update_observed'], 'unknown')
            self.assertEqual(journal.rows[-1]['evidence'], 'user_observation; not protocol-decoded state')
            self.assertEqual(sum(row['type'] == 'prompt' for row in events(output)), 3)

    def test_countdown_keeps_capture_checked_without_acting_for_user(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = capture.Journal(Path(temporary), False)
            self.addCleanup(journal.close)
            output = io.StringIO()
            protocol = worker.Protocol(io.StringIO(), output)
            sleep = mock.Mock()
            session = worker.GuiGuidedSession(IP, UDID, journal, FakeBackend(), protocol=protocol, sleep_fn=sleep)
            session.capture = mock.Mock()
            session.wait(2)
            self.assertEqual([row['remaining_seconds'] for row in events(output)], [2, 1, 0])
            self.assertEqual(session.capture.check.call_count, 2)
            self.assertEqual(sleep.call_args_list, [mock.call(1), mock.call(1)])
            self.assertFalse(any(row['event'] == 'action_confirmed' for row in journal.rows))


if __name__ == '__main__':
    unittest.main()
