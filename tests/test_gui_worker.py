"""GUI worker tests with local synthetic files and mocked capture boundaries."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
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

    def form_file(self, **updates):
        form = dict(decisions={}, notes={}, selected_identifier='', reviewer_label='')
        form.update(updates)
        path = self.root / 'data/private_reviews/forms/owner_form.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(form, ensure_ascii=False), encoding='utf-8')
        return path

    def review_fixture(self, declared_real=False):
        """Exercise declarations only: every packet and observation stays synthetic."""
        data = self.root / 'data'
        directory = worker.demo.create_demo_sample(data / 'captures')
        if declared_real:
            metadata_path = directory / 'session.json'
            metadata = json.loads(metadata_path.read_text())
            metadata.update(simulation=False, script_version='test_real_declaration',
                            sample_origin='test_operator_declaration')
            metadata_path.write_text(json.dumps(metadata), encoding='utf-8')
            event_path = directory / 'events.jsonl'
            rows = [json.loads(line) for line in event_path.read_text().splitlines()]
            for row in rows:
                row['simulation'] = False
            event_path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        destination, report = worker.analyze_session(directory, data / 'private_reports')
        return directory, destination, report

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

    def test_result_has_baseline_assessment_draft_and_private_source_context(self):
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('demo'), protocol), 0, output.getvalue())
        result = next(row for row in events(output) if row['type'] == 'result')
        report = json.loads((Path(result['report_dir']) / 'report.json').read_text())
        self.assertEqual(result['source'], report['source'])
        self.assertEqual(result['target_context'], report['target_context'])
        self.assertEqual(result['baseline_assessment'], worker.reviews.assess_report(report))
        self.assertEqual(result['review_draft'], worker.reviews.draft_review(report))
        self.assertFalse(result['baseline_assessment'].get('passed', False))

    def test_review_form_rejects_outside_selected_data_directory(self):
        outside = self.root / 'outside.json'
        outside.write_text('{}')
        with self.assertRaises(worker.WorkerError):
            worker.load_review_form(outside, self.root / 'data')

    def test_review_form_rejects_symlink_file_and_parent(self):
        path = self.form_file()
        symlink = path.with_name('link.json')
        symlink.symlink_to(path)
        with self.assertRaises(worker.WorkerError):
            worker.load_review_form(symlink, self.root / 'data')
        parent_link = self.root / 'data/linked_forms'
        parent_link.symlink_to(path.parent, target_is_directory=True)
        with self.assertRaises(worker.WorkerError):
            worker.load_review_form(parent_link / path.name, self.root / 'data')

    def test_review_form_requires_exact_fields_types_and_unique_json_keys(self):
        invalid = ['[]', '{}', '{"decisions":{},"decisions":{},"notes":{},'
                   '"selected_identifier":"","reviewer_label":""}',
                   '{"decisions":{},"notes":{},"selected_identifier":"",'
                   '"reviewer_label":"","extra":true}',
                   '{"decisions":[],"notes":{},"selected_identifier":"","reviewer_label":""}',
                   '{"decisions":{},"notes":{},"selected_identifier":null,"reviewer_label":""}',
                   '{"decisions":{},"notes":{},"selected_identifier":"","reviewer_label":NaN}']
        path = self.form_file()
        for payload in invalid:
            with self.subTest(payload=payload):
                path.write_text(payload)
                with self.assertRaises(worker.WorkerError):
                    worker.load_review_form(path, self.root / 'data')

    def test_review_form_rejects_oversize_and_non_regular_file(self):
        path = self.form_file()
        path.write_bytes(b' ' * (worker.MAX_REVIEW_FORM_BYTES + 1))
        with self.assertRaises(worker.WorkerError):
            worker.load_review_form(path, self.root / 'data')
        with self.assertRaises(worker.WorkerError):
            worker.load_review_form(path.parent, self.root / 'data')

    def test_review_save_pending_record_is_saved_but_does_not_report_pass(self):
        path = self.form_file(notes=dict(evidence='待离线检查'))
        record_path = self.root / 'data/private_reviews/pending.json'
        record = dict(status='pending', passed=False)
        validation = dict(valid=True, passed=False, errors=[], record=record, assessment={})
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No capture backend during review save'))
        with mock.patch.object(worker.reviews, 'save_review', return_value=(record_path, record)) as save, \
                mock.patch.object(worker.reviews, 'validate_review', return_value=validation) as validate:
            code = worker.run(self.args('review-save', '--report-dir', str(self.root / 'reports'),
                '--session-dir', str(self.root / 'samples'), '--form-file', str(path)), protocol,
                backend_factory=factory)
        self.assertEqual(code, 0, output.getvalue())
        factory.assert_not_called()
        self.assertEqual(save.call_args.kwargs['notes'], dict(evidence='待离线检查'))
        validate.assert_called_once_with(record_path, self.root / 'data')
        rows = events(output)
        saved = next(row for row in rows if row['type'] == 'review_saved')
        self.assertFalse(saved['passed'])
        self.assertEqual(saved['validation'], validation)
        self.assertEqual(rows[-1], dict(type='finished', ok=True))

    def test_synthetic_review_can_save_pending_and_restore_but_never_unlock(self):
        directory, destination, report = self.review_fixture()
        form = self.form_file(**worker.reviews.draft_review(report))
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('review-save', '--report-dir', str(destination),
            '--session-dir', str(directory), '--form-file', str(form)), protocol), 0,
            output.getvalue())
        saved = next(row for row in events(output) if row['type'] == 'review_saved')
        self.assertTrue(saved['validation']['valid'])
        self.assertFalse(saved['passed'])
        self.assertFalse(saved['record']['physical_feedback_verified'])
        self.assertFalse(saved['record']['can_start_live_ha'])
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('review-list'), protocol), 0, output.getvalue())
        loaded = next(row for row in events(output) if row['type'] == 'review-list')['records']
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]['review_file'], saved['record_path'])
        self.assertTrue(loaded[0]['valid'])
        self.assertFalse(loaded[0]['passed'])
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('Synthetic pending record cannot unlock capture'))
        self.assertEqual(worker.run(self.capture_args() + ['--review-file', saved['record_path']], protocol,
            backend_factory=factory), 1, output.getvalue())
        factory.assert_not_called()

    def test_declared_real_fixture_human_pass_is_bound_to_original_hashes(self):
        # This deliberately exercises operator declarations using generated
        # documentation-address packets; no real physical result is asserted.
        directory, destination, report = self.review_fixture(declared_real=True)
        self.assertTrue(worker.reviews.assess_report(report)['eligible_for_manual_review'])
        form = worker.reviews.draft_review(report)
        form['decisions'] = {key: 'pass' for key in worker.reviews.CRITERION_IDS}
        form['notes'] = {key: '合成测试声明：核对候选帧及现场记录，仅测试代码路径。'
                         for key in worker.reviews.CRITERION_IDS}
        form['selected_identifier'] = worker.demo.DEVICE.hex()
        form['reviewer_label'] = '合成测试复核人'
        form_path = self.form_file(**form)
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('Review save must stay offline'))
        self.assertEqual(worker.run(self.args('review-save', '--report-dir', str(destination),
            '--session-dir', str(directory), '--form-file', str(form_path)), protocol,
            backend_factory=factory), 0, output.getvalue())
        factory.assert_not_called()
        saved = next(row for row in events(output) if row['type'] == 'review_saved')
        self.assertTrue(saved['passed'])
        self.assertTrue(saved['validation']['valid'])
        self.assertFalse(saved['record']['physical_feedback_verified'])
        self.assertEqual(before, {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in directory.iterdir()})
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('review-validate', '--review-file', saved['record_path'],
            '--host-ip', '192.0.2.21'), protocol, backend_factory=factory), 0, output.getvalue())
        checked = next(row for row in events(output) if row['type'] == 'review_validation')
        self.assertFalse(checked['valid'])
        self.assertFalse(checked['passed'])
        # Any original-file edit makes the prior human declaration unusable.
        with (directory / 'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write('{"event":"synthetic_after_review_change"}\n')
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('review-validate', '--review-file', saved['record_path'],
            '--host-ip', IP), protocol, backend_factory=factory), 0, output.getvalue())
        checked = next(row for row in events(output) if row['type'] == 'review_validation')
        self.assertFalse(checked['valid'])
        self.assertFalse(checked['passed'])
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.capture_args() + ['--review-file', saved['record_path']], protocol,
            backend_factory=factory), 1, output.getvalue())
        self.assertFalse(any(row['type'] == 'capture_preflight' for row in events(output)))
        factory.assert_not_called()

    def test_synthetic_all_pass_decisions_report_error_and_never_saved_pass(self):
        directory, destination, report = self.review_fixture()
        form = worker.reviews.draft_review(report)
        form['decisions'] = {key: 'pass' for key in worker.reviews.CRITERION_IDS}
        form['notes'] = {key: '合成测试尝试通过，预期拒绝。' for key in worker.reviews.CRITERION_IDS}
        form['selected_identifier'] = worker.demo.DEVICE.hex()
        form_path = self.form_file(**form)
        protocol, output = self.protocol()
        self.assertEqual(worker.run(self.args('review-save', '--report-dir', str(destination),
            '--session-dir', str(directory), '--form-file', str(form_path)), protocol), 1,
            output.getvalue())
        self.assertTrue(any(row['type'] == 'error' for row in events(output)))
        self.assertFalse(any(row['type'] == 'review_saved' for row in events(output)))
        self.assertFalse((self.root / 'data/baseline_reviews').exists())
        self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_ha_handoff_mode_exports_one_private_research_event_without_backend_or_network(self):
        directory, destination, report = self.review_fixture(declared_real=True)
        form = worker.reviews.draft_review(report)
        form.update(decisions={key: 'pass' for key in worker.reviews.CRITERION_IDS},
                    notes={key: '合成测试声明：只有代码路径通过，未接触家庭设备。'
                           for key in worker.reviews.CRITERION_IDS},
                    selected_identifier=worker.demo.DEVICE.hex())
        review_file, _ = worker.reviews.save_review(destination, directory, self.root / 'data', **form)
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No capture backend for HA research export'))
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('No network')), \
                mock.patch.object(socket, 'getaddrinfo', side_effect=AssertionError('No DNS')):
            code = worker.run(self.args('ha-handoff', '--review-file', str(review_file),
                '--host-ip', IP), protocol, backend_factory=factory)
        self.assertEqual(code, 0, output.getvalue())
        factory.assert_not_called()
        rows = events(output)
        self.assertEqual(sum(row['type'] == 'ha_handoff' for row in rows), 1)
        self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)
        self.assertFalse(any(row['type'] == 'capture_preflight' for row in rows))
        result = next(row for row in rows if row['type'] == 'ha_handoff')
        manifest = result['manifest']
        self.assertEqual(manifest['stage'], 'integration_research')
        self.assertTrue(manifest['can_start_integration_work'])
        self.assertFalse(manifest['live_control_enabled'])
        self.assertTrue(manifest['private'])
        self.assertFalse(manifest['identity_authenticated'])
        self.assertTrue(all(value is None for value in manifest['unresolved_parameters'].values()))
        self.assertEqual(Path(result['directory']).parent, self.root / 'data/private_ha_handoffs')
        self.assertTrue((Path(result['directory']) / 'manifest.json').is_file())
        self.assertFalse(list(Path(result['directory']).rglob('*.pcap')))
        self.assertNotIn(str(self.root), json.dumps(manifest))
        self.assertEqual(rows[-1], dict(type='finished', ok=True))

    def test_ha_handoff_mode_rejects_pending_demo_changed_original_and_other_host(self):
        for reason in ('pending', 'demo', 'changed_original', 'other_host'):
            with self.subTest(reason=reason):
                directory, destination, report = self.review_fixture(declared_real=reason != 'demo')
                form = worker.reviews.draft_review(report)
                if reason not in ('pending', 'demo'):
                    form.update(decisions={key: 'pass' for key in worker.reviews.CRITERION_IDS},
                        notes={key: '合成fixture人工声明，未验证实物。' for key in worker.reviews.CRITERION_IDS},
                        selected_identifier=worker.demo.DEVICE.hex())
                review_file, _ = worker.reviews.save_review(destination, directory, self.root / 'data', **form)
                if reason == 'changed_original':
                    with (directory / 'events.jsonl').open('a') as stream:
                        stream.write('{"event":"synthetic_post_review_edit"}\n')
                protocol, output = self.protocol()
                factory = mock.Mock(side_effect=AssertionError('Failed HA export must not create capture backend'))
                with mock.patch.object(socket, 'socket', side_effect=AssertionError('No network')), \
                        mock.patch.object(socket, 'getaddrinfo', side_effect=AssertionError('No DNS')):
                    code = worker.run(self.args('ha-handoff', '--review-file', str(review_file),
                        '--host-ip', '192.0.2.21' if reason == 'other_host' else IP), protocol,
                        backend_factory=factory)
                self.assertEqual(code, 1, output.getvalue())
                factory.assert_not_called()
                rows = events(output)
                self.assertTrue(any(row['type'] == 'error' for row in rows))
                self.assertFalse(any(row['type'] in ('ha_handoff', 'capture_preflight') for row in rows))
                self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)
                self.assertEqual(rows[-1], dict(type='finished', ok=False))
                self.assertFalse((self.root / 'data/private_ha_handoffs').exists())

    def test_invalid_review_form_stops_before_any_save_or_backend(self):
        path = self.form_file()
        path.write_text('{broken')
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No backend'))
        with mock.patch.object(worker.reviews, 'save_review') as save:
            code = worker.run(self.args('review-save', '--report-dir', str(self.root / 'reports'),
                '--session-dir', str(self.root / 'samples'), '--form-file', str(path)), protocol,
                backend_factory=factory)
        self.assertEqual(code, 1)
        save.assert_not_called()
        factory.assert_not_called()
        self.assertFalse(any(row['type'] == 'review_saved' for row in events(output)))
        self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_review_list_and_validate_are_local_events_without_backend(self):
        record_path = self.root / 'data/private_reviews/verified.json'
        validation = dict(valid=True, passed=False, errors=[], record=dict(status='pending'), assessment={})
        listed = [dict(review_file=str(record_path), **validation)]
        factory = mock.Mock(side_effect=AssertionError('No capture backend in review commands'))
        protocol, output = self.protocol()
        with mock.patch.object(worker.reviews, 'load_reviews', return_value=listed) as load:
            self.assertEqual(worker.run(self.args('review-list', '--host-ip', IP), protocol,
                backend_factory=factory), 0, output.getvalue())
        load.assert_called_once_with(self.root / 'data', expected_host=IP)
        self.assertEqual(events(output)[0], dict(type='review-list',
                                               records=[worker.review_summary(item) for item in listed]))
        protocol, output = self.protocol()
        with mock.patch.object(worker.reviews, 'validate_review', return_value=validation) as validate:
            self.assertEqual(worker.run(self.args('review-validate', '--review-file', str(record_path)),
                protocol, backend_factory=factory), 0, output.getvalue())
        validate.assert_called_once_with(record_path, self.root / 'data', expected_host=None)
        self.assertEqual(events(output)[0], dict(type='review_validation', review_file=str(record_path),
                                               **validation))
        self.assertFalse(events(output)[0]['passed'])
        self.assertEqual(events(output)[-1], dict(type='finished', ok=True))
        factory.assert_not_called()

    def test_review_list_is_compact_and_never_promotes_invalid_pass(self):
        validation = dict(review_file='/synthetic/review.json', valid=False, passed=True,
            errors=['synthetic failure'], record=dict(review_id='test', host_ip=IP,
                target_context=dict(label='合成测试灯', room='合成房间', kind='ordinary_switch_light',
                                    collection_id='0' * 32, ignored='x' * 100000),
                created_at='test timestamp', notes={'large': 'x' * 100000}),
            assessment=dict(eligible_for_manual_review=False, confirmed=['x' * 100000],
                            pending=['x' * 100000], resample=['x' * 100000],
                            candidate_evidence=['x' * 100000]))
        summary = worker.review_summary(validation)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['assessment'], dict(eligible_for_manual_review=False,
                                                   confirmed_count=1, pending_count=1, resample_count=1))
        self.assertNotIn('notes', summary['record'])
        self.assertLess(len(json.dumps(summary)), 4096)

    def test_invalid_host_for_review_commands_stops_before_review_read(self):
        for mode, extra in [('review-list', []),
                            ('review-validate', ['--review-file', str(self.root / 'review.json')])]:
            with self.subTest(mode=mode):
                protocol, output = self.protocol()
                with mock.patch.object(worker.reviews, 'load_reviews') as load, \
                        mock.patch.object(worker.reviews, 'validate_review') as validate:
                    self.assertEqual(worker.run(self.args(mode, '--host-ip', 'example.invalid', *extra),
                        protocol), 1, output.getvalue())
                load.assert_not_called()
                validate.assert_not_called()
                self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_invalid_or_pending_review_never_constructs_backend_or_emits_preflight(self):
        for valid, passed in [(False, False), (True, False), (False, True)]:
            with self.subTest(valid=valid, passed=passed):
                protocol, output = self.protocol()
                factory = mock.Mock(side_effect=AssertionError('Invalid review must stop before backend'))
                validation = dict(valid=valid, passed=passed, errors=['synthetic mismatch'])
                with mock.patch.object(worker.reviews, 'validate_review', return_value=validation) as validate:
                    self.assertEqual(worker.run(self.capture_args() + ['--review-file',
                        str(self.root / 'record.json')], protocol, backend_factory=factory), 1,
                        output.getvalue())
                validate.assert_called_once_with(self.root / 'record.json', self.root / 'data', expected_host=IP)
                factory.assert_not_called()
                self.assertFalse((self.root / 'data/captures').exists())
                self.assertFalse(any(row['type'] == 'capture_preflight' for row in events(output)))
                self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_passed_review_is_revalidated_for_current_host_and_reference_recorded(self):
        protocol, output = self.protocol(['', ''])
        backend = FakeBackend()
        review_path = self.root / 'review.json'
        validation = dict(valid=True, passed=True, record=dict(review_id='synthetic-review'))
        def analyze(directory, output_root=None, ordinary_ids=()):
            rows = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
            reference = next(row for row in rows if row['event'] == 'baseline_review_reference')
            self.assertEqual(reference['review_file'], str(review_path))
            self.assertEqual(reference['review_id'], 'synthetic-review')
            self.assertTrue(reference['human_review_passed'])
            self.assertFalse(reference['physical_identity_verified_by_tool'])
            self.assertFalse(reference['independent_state_verified_by_tool'])
            return self.fake_analysis(directory, output_root, ordinary_ids)
        with mock.patch.object(worker.reviews, 'validate_review', return_value=validation) as validate, \
                mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=analyze):
            self.assertEqual(worker.run(self.capture_args() + ['--review-file', str(review_path)], protocol,
                backend_factory=lambda: backend), 0, output.getvalue())
        validate.assert_called_once_with(review_path, self.root / 'data', expected_host=IP)
        self.assertTrue(backend.capture.stopped)
        self.assertEqual(events(output)[-1], dict(type='finished', ok=True))

    def test_legacy_baseline_boolean_is_only_unverified_declaration(self):
        protocol, output = self.protocol(['', ''])
        backend = FakeBackend()
        def analyze(directory, output_root=None, ordinary_ids=()):
            rows = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
            declaration = next(row for row in rows if row['event'] == 'baseline_review_declared')
            self.assertFalse(declaration['unlocks_additional_sampling'])
            self.assertFalse(any(row['event'] == 'baseline_review_reference' for row in rows))
            return self.fake_analysis(directory, output_root, ordinary_ids)
        with mock.patch.object(worker.reviews, 'validate_review') as validate, \
                mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=analyze):
            self.assertEqual(worker.run(self.capture_args() + ['--baseline-reviewed'], protocol,
                backend_factory=lambda: backend), 0, output.getvalue())
        validate.assert_not_called()
        self.assertEqual(events(output)[-1], dict(type='finished', ok=True))

    def test_collection_demo_is_two_explicit_synthetic_rounds_without_backend_or_admin(self):
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No capture backend in collection demonstration'))
        with mock.patch.object(capture.SystemBackend, 'prepare',
                side_effect=AssertionError('No capture preparation')) as prepare, \
                mock.patch.object(capture.SystemBackend, 'authorize',
                side_effect=AssertionError('No administrator authorization')) as authorize, \
                mock.patch.object(worker, 'run_capture', side_effect=AssertionError('No capture run')) as run_capture:
            code = worker.run(self.args('collection-demo'), protocol, backend_factory=factory)
        self.assertEqual(code, 0, output.getvalue())
        factory.assert_not_called()
        prepare.assert_not_called()
        authorize.assert_not_called()
        run_capture.assert_not_called()
        rows = events(output)
        self.assertEqual(rows[-1], dict(type='finished', ok=True))
        self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)
        self.assertEqual(sum(row['type'] == 'result' for row in rows), 1)
        self.assertFalse(any(row['type'] == 'prompt' for row in rows))
        result = next(row for row in rows if row['type'] == 'result')
        self.assertEqual(result['report_kind'], 'collection')
        self.assertIs(result['simulation'], True)
        self.assertEqual(result['summary']['round_count'], 2)
        self.assertEqual(result['summary']['identifier_collision_count'], 1)
        report = json.loads((Path(result['report_dir']) / 'collection.json').read_text())
        self.assertFalse(report['readiness']['automatic_entity_mapping_enabled'])
        self.assertFalse(report['identifier_collisions'][0]['physical_entities_merged'])
        sample_paths = list((self.root / 'data/demo_collections').glob('*/captures/*/session.json'))
        self.assertEqual(len(sample_paths), 2)
        metadata = [json.loads(path.read_text()) for path in sample_paths]
        self.assertTrue(all(row['simulation'] is True for row in metadata))
        self.assertTrue(all(row['sample_origin'] == 'synthetic_fixture' for row in metadata))
        self.assertTrue(all(row['project_household_verified'] is False for row in metadata))
        self.assertEqual({row['target_context']['label'] for row in metadata}, {'合成普通灯A', '合成普通灯B'})
        self.assertEqual(len({row['target_context']['collection_id'] for row in metadata}), 1)
        self.assertTrue(all(row['target_context']['kind'] == 'ordinary_switch_light' for row in metadata))
        self.assertFalse((self.root / 'data/captures').exists())

    def test_collection_reads_existing_rounds_without_modifying_inputs(self):
        source = self.root / 'selected_data'
        directory = worker.demo.create_demo_sample(source / 'captures')
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No capture backend in existing collection analysis'))
        code = worker.run(self.args('collection', '--capture-root', str(source)),
                          protocol, backend_factory=factory)
        self.assertEqual(code, 0, output.getvalue())
        factory.assert_not_called()
        self.assertEqual(before, {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in directory.iterdir()})
        result = next(row for row in events(output) if row['type'] == 'result')
        self.assertEqual(result['summary']['round_count'], 1)
        self.assertTrue(Path(result['report_path']).is_file())
        self.assertEqual(Path(result['report_dir']).parent, self.root / 'data/private_reports')
        self.assertEqual(sum(row['type'] == 'finished' for row in events(output)), 1)

    def test_collection_failed_round_is_reported_as_blocked_and_not_zero_traffic(self):
        source = self.root / 'selected_data'
        worker.demo.create_demo_sample(source / 'captures')
        broken = source / 'captures/broken'
        broken.mkdir()
        (broken / 'session.json').write_text('{broken synthetic metadata')
        protocol, output = self.protocol()
        code = worker.run(self.args('collection', '--capture-root', str(source)), protocol)
        self.assertEqual(code, 0, output.getvalue())  # The collection report itself was generated.
        rows = events(output)
        result = next(row for row in rows if row['type'] == 'result')
        self.assertEqual(result['quality'], 'blocked')
        self.assertEqual(result['summary']['failed_count'], 1)
        self.assertEqual(result['summary']['analyzed_count'], 1)
        self.assertIsNone(result['summary']['packet_count'])
        report = json.loads((Path(result['report_dir']) / 'collection.json').read_text())
        failure = next(row for row in report['rounds'] if row['status'] == 'failed')
        self.assertIn('JSONDecodeError', failure['error'])
        self.assertEqual(failure['summary'], {})
        self.assertEqual(rows[-1], dict(type='finished', ok=True))
        self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)

    def test_collection_missing_directory_is_json_error_without_backend(self):
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No backend'))
        code = worker.run(self.args('collection', '--capture-root', str(self.root / 'missing')),
                          protocol, backend_factory=factory)
        self.assertEqual(code, 1)
        factory.assert_not_called()
        rows = events(output)
        self.assertEqual(rows[-1], dict(type='finished', ok=False))
        self.assertEqual(sum(row['type'] == 'finished' for row in rows), 1)
        self.assertTrue(any(row['type'] == 'error' for row in rows))
        self.assertFalse(any(row['type'] == 'result' for row in rows))
        self.assertNotIn('Traceback', output.getvalue())

    def test_capture_target_labels_are_private_metadata_without_device_verification(self):
        protocol, output = self.protocol(['', ''])
        backend = FakeBackend()
        args = self.capture_args() + ['--target-label', '合成测试标签', '--room-label', '合成房间',
                                      '--collection-id', '00000000000000000000000000000001']
        def analyze(directory, output_root=None, ordinary_ids=()):
            metadata = json.loads((directory / 'session.json').read_text())
            self.assertEqual(metadata['target_context'], dict(label='合成测试标签', room='合成房间',
                kind='ordinary_switch_light', collection_id='00000000000000000000000000000001'))
            self.assertFalse(metadata['project_household_verified'])
            self.assertEqual(ordinary_ids, ())
            self.assertTrue(backend.capture.stopped)
            return self.fake_analysis(directory, output_root, ordinary_ids)
        with mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=analyze):
            self.assertEqual(worker.run(args, protocol, backend_factory=lambda: backend), 0, output.getvalue())
        self.assertEqual(events(output)[-1], dict(type='finished', ok=True))

    def test_invalid_target_context_stops_before_backend_or_interface_creation(self):
        protocol, output = self.protocol()
        factory = mock.Mock(side_effect=AssertionError('No backend for invalid target'))
        args = self.capture_args() + ['--target-label', '合成\n测试']
        code = worker.run(args, protocol, backend_factory=factory)
        self.assertEqual(code, 1)
        factory.assert_not_called()
        self.assertFalse((self.root / 'data/captures').exists())
        self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_invalid_capture_inputs_never_emit_validated_preflight_marker(self):
        cases = [self.args('capture', '--host-ip', 'example.invalid', '--udid', UDID),
                 self.capture_args() + ['--target-label', '合成\n测试'],
                 self.args('capture', '--host-ip', IP, '--udid', 'invalid-synthetic-udid')]
        for args in cases:
            with self.subTest(args=args):
                protocol, output = self.protocol()
                factory = mock.Mock(side_effect=AssertionError('Invalid inputs must not construct a backend'))
                self.assertEqual(worker.run(args, protocol, backend_factory=factory), 1)
                factory.assert_not_called()
                self.assertFalse(any(row['type'] == 'capture_preflight' for row in events(output)))
                self.assertFalse((self.root / 'data/captures').exists())
                self.assertEqual(events(output)[-1], dict(type='finished', ok=False))

    def test_validated_preflight_marker_precedes_backend_construction(self):
        protocol, output = self.protocol(['', ''])
        backend = FakeBackend()
        observed = []
        def factory():
            rows = events(output)
            self.assertEqual(rows, [dict(type='capture_preflight', status='validated')])
            self.assertEqual(backend.calls, [])
            self.assertFalse((self.root / 'data/captures').exists())
            observed.append('backend_constructed_after_marker')
            return backend
        with mock.patch.object(worker.GuiGuidedSession, 'flow', lambda session: self.short_flow(session)), \
                mock.patch.object(worker, 'analyze_session', side_effect=self.fake_analysis):
            self.assertEqual(worker.run(self.capture_args(), protocol, backend_factory=factory), 0,
                             output.getvalue())
        self.assertEqual(observed, ['backend_constructed_after_marker'])
        self.assertEqual(sum(row['type'] == 'capture_preflight' for row in events(output)), 1)
        self.assertEqual(events(output)[-1], dict(type='finished', ok=True))
        self.assertTrue(backend.capture.stopped)
        self.assertEqual(backend.calls[-1], 'remove')

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
