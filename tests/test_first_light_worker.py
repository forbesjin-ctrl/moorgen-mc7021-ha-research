"""Private GUI journey and fixed-driver packaging, using fabricated PCAPs only."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import analyze_capture
import baseline_review
import demo_sample
import gui_worker
import ha_wizard
import test_driver_profile as fixtures


class FirstLightWorkerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.DriverProfileTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def baseline(self):
        directory, report = analyze_capture.analyze_session(self.fixture.first, self.root / 'private_reports')
        form = baseline_review.draft_review(report)
        form.update(decisions={key: 'pass' for key in baseline_review.CRITERION_IDS},
            notes={key: 'Fabricated unit-test declaration only, no physical observation.' for key in baseline_review.CRITERION_IDS},
            selected_identifier=demo_sample.DEVICE.hex())
        path, _ = baseline_review.save_review(directory, self.fixture.first, self.root, **form)
        return path

    def call(self, mode, review=None, credentials=None):
        arguments = ['--data-dir', str(self.root), mode]
        if mode != 'first-light-demo':
            arguments += ['--session-dir', str(self.fixture.first), '--comparison-dir', str(self.fixture.second),
                '--identifier', demo_sample.DEVICE.hex()]
        if review:
            arguments += ['--review-file', str(review)]
        output = io.StringIO()
        protocol = gui_worker.Protocol(io.StringIO(), output)
        with mock.patch.object(protocol, 'request_credentials', return_value=dict(credentials or self.fixture.credentials())) as prompt:
            code = gui_worker.run(arguments, protocol=protocol)
        return code, [json.loads(line) for line in output.getvalue().splitlines()], prompt.call_count

    def test_matching_sources_and_review_build_fixed_driver_without_upload_or_execution(self):
        code, events, prompts = self.call('first-light-adapt', self.baseline())
        self.assertEqual(code, 0, events)
        self.assertEqual(prompts, 1)
        result = next(row for row in events if row['type'] == 'ha_wizard')
        path, state = Path(result['wizard_file']), result['state']
        self.assertTrue(state['bundle'])
        self.assertFalse(state['assessment']['passed'])
        self.assertFalse(state['physical_feedback_verified'])
        with zipfile.ZipFile(path.parent / state['bundle']['file']) as archive:
            prefix = 'custom_components/mc7021_single_light/'
            binding = json.loads(archive.read(prefix + 'binding.json'))
            self.assertEqual(binding['builtin_profile']['port'], 12345)
            self.assertEqual(binding['builtin_profile']['auth_password_transform'], 'raw_ascii')
            self.assertEqual(archive.read(prefix + 'driver.py'),
                (Path(gui_worker.__file__).parent / 'single_light_driver.py').read_bytes())
            for raw in (archive.read(name) for name in archive.namelist()):
                self.assertNotIn(fixtures.USERNAME.encode(), raw)
                self.assertNotIn(fixtures.PASSWORD.encode(), raw)
        self.assertFalse(any(row['type'] in ('capture_preflight', 'sampling_preparation') for row in events))
        self.assertTrue(ha_wizard.load(path, self.root)['valid'])

    def test_no_baseline_does_not_ask_credentials_or_build_driver(self):
        code, events, prompts = self.call('first-light-adapt')
        self.assertEqual(code, 0, events)
        self.assertEqual(prompts, 0)
        self.assertFalse(any(row['type'] == 'ha_wizard' for row in events))
        self.assertFalse(list(self.root.rglob('*.zip')))

    def test_wrong_credentials_never_build_or_fallback_to_captured_password(self):
        code, events, prompts = self.call('first-light-adapt', self.baseline(),
            dict(username=fixtures.USERNAME, password='WRONG_KNOWN_TEST_INPUT'))
        self.assertEqual(code, 0, events)
        self.assertEqual(prompts, 1)
        result = next(row for row in events if row['type'] == 'driver_profile')
        self.assertFalse(result['package_eligible'])
        self.assertFalse(any(row['type'] == 'ha_wizard' for row in events))

    def test_flow_demo_shows_gaps_without_credentials_or_installable_package(self):
        code, events, prompts = self.call('first-light-demo')
        self.assertEqual(code, 0, events)
        self.assertEqual(prompts, 0)
        result = next(row for row in events if row['type'] == 'first_light_flow')
        self.assertTrue(result['simulation'])
        self.assertFalse(result['can_expand_to_other_lights'])
        self.assertEqual(len(result['stages']), 7)

    def test_builtin_profile_source_change_invalidates_wizard_and_package(self):
        code, events, _ = self.call('first-light-adapt', self.baseline())
        self.assertEqual(code, 0, events)
        result = next(row for row in events if row['type'] == 'ha_wizard')
        path = self.fixture.second / 'traffic.pcap'
        path.write_bytes(path.read_bytes() + b'changed')
        self.assertFalse(ha_wizard.load(Path(result['wizard_file']), self.root)['valid'])


class CredentialPipeTests(unittest.TestCase):
    def call(self, value):
        output = io.StringIO()
        identifier = 'a' * 32
        protocol = gui_worker.Protocol(io.StringIO(json.dumps(dict(id=identifier, value=value)) + '\n'), output)
        with mock.patch.object(gui_worker.uuid, 'uuid4', return_value=type('UUID', (), {'hex': identifier})()):
            credentials = protocol.request_credentials()
        return protocol, credentials, output.getvalue()

    def test_secure_prompt_never_echoes_input_and_redacts_later_errors(self):
        values = dict(username='FICTIONAL_USERNAME_PIPE', password='FICTIONAL_PASSWORD_PIPE')
        protocol, result, text = self.call(values)
        self.assertEqual(result, values)
        self.assertEqual(json.loads(text)['type'], 'credential_prompt')
        self.assertNotIn(values['password'], text)
        self.assertNotIn(values['username'], text)
        protocol.emit('error', message=values['password'])
        self.assertNotIn(values['password'], protocol.output.getvalue())

    def test_short_credentials_do_not_corrupt_protocol_paths_or_full_identifiers(self):
        protocol, _, _ = self.call(dict(username='admin', password='a'))
        protocol.emit('first_light_flow', json_file='/synthetic/admin/data/flow.json', selected_identifier='abcdef0123456789')
        result = json.loads(protocol.output.getvalue().splitlines()[-1])
        self.assertEqual(result['json_file'], '/synthetic/admin/data/flow.json')
        self.assertEqual(result['selected_identifier'], 'abcdef0123456789')

    def test_cancel_and_non_object_value_are_sanitized(self):
        with self.assertRaises(gui_worker.WorkerCancelled):
            self.call('q')
        for value in (None, [], dict(username='x', password=''), 'DO_NOT_ECHO_THIS'):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(gui_worker.WorkerError) as error:
                    self.call(value)
                self.assertNotIn('DO_NOT_ECHO_THIS', str(error.exception))


if __name__ == '__main__':
    unittest.main()
