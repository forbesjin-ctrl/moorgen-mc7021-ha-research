"""Native HA wizard bridge tests; no resident driver or network is executed."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('ha_wizard_gui_worker_tests', ROOT / 'tools/gui_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
import ha_wizard as engine


class WizardWorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data = self.root / 'data'
        self.data.mkdir()
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.backend = mock.Mock(side_effect=AssertionError('capture backend must not start'))
        for target, name in ((socket, 'socket'), (socket, 'create_connection'),
                             (subprocess, 'run'), (subprocess, 'Popen')):
            patch = mock.patch.object(target, name,
                side_effect=AssertionError('wizard must remain offline and not execute a process'))
            patch.start()
            self.addCleanup(patch.stop)
        self.wizard = self.data / 'private_ha_wizards/wizard_test/state.json'
        self.review = self.data / 'baseline_reviews/review_test.json'
        self.state = dict(stage='driver_required', simulation=False, observations={},
                          assessment=dict(passed=False, physical_feedback_verified=False))

    def invoke(self, action, *arguments):
        output = io.StringIO()
        protocol = worker.Protocol(io.StringIO(), output)
        code = worker.run(['--data-dir', str(self.data), 'ha-wizard-' + action,
                           *map(str, arguments)], protocol, backend_factory=self.backend)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.backend.assert_not_called()
        self.assertEqual(sum(event['type'] == 'finished' for event in events), 1)
        self.assertEqual(events[-1]['type'], 'finished')
        self.assertFalse(any(event['type'] in ('capture_preflight', 'prompt') for event in events))
        return code, events

    def form(self, value=None, raw=None, name='form.json'):
        path = self.data / 'private_ha_wizards/forms' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw if raw is not None else json.dumps(value, ensure_ascii=False).encode())
        return path

    def assert_success(self, code, events):
        self.assertEqual(code, 0)
        self.assertEqual(events[-1], dict(type='finished', ok=True))
        result = next(event for event in events if event['type'] == 'ha_wizard')
        self.assertTrue(result['valid'])
        self.assertEqual(result['state'], self.state)
        self.assertEqual(result['wizard_file'], str(self.wizard))
        self.assertFalse(result['state']['assessment']['passed'])
        return result

    def test_create_forwards_review_root_and_normalized_known_host(self):
        with mock.patch.object(engine, 'create', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('create', '--review-file', self.review, '--host-ip', '192.0.2.20')
        method.assert_called_once_with(self.review, self.data, expected_host='192.0.2.20')
        self.assert_success(code, events)

    def test_create_without_host_keeps_explicit_none(self):
        with mock.patch.object(engine, 'create', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('create', '--review-file', self.review)
        method.assert_called_once_with(self.review, self.data, expected_host=None)
        self.assert_success(code, events)

    def test_create_invalid_host_rejected_before_engine(self):
        with mock.patch.object(engine, 'create') as method:
            code, events = self.invoke('create', '--review-file', self.review, '--host-ip', 'not-an-ip')
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_demo_forwards_only_private_data_root(self):
        with mock.patch.object(engine, 'create_demo', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('demo')
        method.assert_called_once_with(self.data)
        self.assert_success(code, events)

    def test_load_forwards_engine_validity_and_does_not_promote_passed(self):
        value = dict(valid=True, state=self.state, errors=[], assessment=self.state['assessment'])
        with mock.patch.object(engine, 'load', return_value=value) as method:
            code, events = self.invoke('load', '--wizard-file', self.wizard)
        method.assert_called_once_with(self.wizard, self.data)
        self.assert_success(code, events)
        self.assertFalse(next(e for e in events if e['type'] == 'ha_wizard')['assessment']['passed'])

    def test_load_invalid_is_an_event_not_a_successful_acceptance(self):
        value = dict(valid=False, state=None, errors=['原件改变'], assessment=dict(passed=False))
        with mock.patch.object(engine, 'load', return_value=value) as method:
            code, events = self.invoke('load', '--wizard-file', self.wizard)
        method.assert_called_once_with(self.wizard, self.data)
        self.assertEqual(code, 0)
        self.assertEqual(events[-1], dict(type='finished', ok=True))
        result = next(event for event in events if event['type'] == 'ha_wizard')
        self.assertFalse(result['valid'])
        self.assertFalse(result['assessment']['passed'])
        self.assertEqual(result['errors'], ['原件改变'])

    def test_starter_forwards_without_importing_resident_code(self):
        with mock.patch.object(engine, 'export_starter', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('starter', '--wizard-file', self.wizard)
        method.assert_called_once_with(self.wizard, self.data)
        self.assert_success(code, events)

    def test_adapter_forwards_paths_without_executing_driver(self):
        marker = self.root / 'must-not-exist'
        driver = self.root / 'owner_driver.py'
        driver.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n'
                          'raise AssertionError("Mac must not import the resident driver")\n')
        manifest = self.root / 'driver_manifest.json'
        with mock.patch.object(engine, 'import_adapter', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('adapter', '--wizard-file', self.wizard,
                '--manifest-file', manifest, '--driver-file', driver)
        method.assert_called_once_with(self.wizard, manifest, driver, self.data)
        self.assertFalse(marker.exists())
        self.assertNotIn('owner_driver', sys.modules)
        self.assert_success(code, events)

    def test_bundle_uses_build_bundle_engine_interface(self):
        with mock.patch.object(engine, 'build_bundle', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('bundle', '--wizard-file', self.wizard)
        method.assert_called_once_with(self.wizard, self.data)
        self.assert_success(code, events)

    def test_driver_form_forwards_evidence_without_executing_code(self):
        driver = self.root / 'owner_driver.py'
        driver.write_text('raise AssertionError("Mac must not execute the driver")\n')
        evidence = dict(protocol='本户连接封装依据', session='本户当前会话依据',
                        commands='同灯开关字段依据', independent_state='面板独立反馈依据')
        form = self.form(evidence)
        with mock.patch.object(engine, 'import_driver', return_value=(self.wizard, self.state), create=True) as method:
            code, events = self.invoke('driver', '--wizard-file', self.wizard,
                                       '--driver-file', driver, '--form-file', form)
        method.assert_called_once_with(self.wizard, driver, self.data, evidence)
        self.assert_success(code, events)

    def test_install_forwards_exact_local_observations(self):
        value = dict(entity_id='light.owner_first_light', confirmed=True, notes='本人已在HA核对单灯实体')
        form = self.form(value)
        with mock.patch.object(engine, 'record_installation', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('install', '--wizard-file', self.wizard, '--form-file', form)
        method.assert_called_once_with(self.wizard, self.data, value)
        self.assert_success(code, events)

    def test_diagnostics_forwards_selected_file_without_network(self):
        selected = self.root / 'private_diagnostics.json'
        with mock.patch.object(engine, 'import_diagnostics', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('diagnostics', '--wizard-file', self.wizard,
                                       '--diagnostics-file', selected)
        method.assert_called_once_with(self.wizard, selected, self.data)
        self.assert_success(code, events)

    def test_acceptance_forwards_step_mapping_without_wrong_wrapper_key(self):
        value = dict(ha_on_1=dict(decision='pending', physical_light='unknown', ha_state='unknown',
                                  notes='', event_id=None))
        form = self.form(value)
        with mock.patch.object(engine, 'save_acceptance', return_value=(self.wizard, self.state)) as method:
            code, events = self.invoke('acceptance', '--wizard-file', self.wizard, '--form-file', form)
        method.assert_called_once_with(self.wizard, self.data, value)
        self.assert_success(code, events)

    def test_engine_refusal_emits_error_and_one_failed_finish(self):
        with mock.patch.object(engine, 'build_bundle', side_effect=ValueError('驱动尚未验证')):
            code, events = self.invoke('bundle', '--wizard-file', self.wizard)
        self.assertEqual(code, 1)
        self.assertEqual(events[-1], dict(type='finished', ok=False))
        self.assertFalse(any(event['type'] == 'ha_wizard' for event in events))
        self.assertEqual(next(event for event in events if event['type'] == 'error')['message'], '驱动尚未验证')

    def test_required_parser_arguments_rejected_before_engine(self):
        cases = [
            ('create', []), ('load', []), ('starter', []), ('bundle', []),
            ('adapter', ['--wizard-file', self.wizard, '--manifest-file', self.root / 'manifest.json']),
            ('install', ['--wizard-file', self.wizard]),
            ('diagnostics', ['--wizard-file', self.wizard]),
            ('acceptance', ['--wizard-file', self.wizard]),
        ]
        with mock.patch.object(engine, 'create') as create:
            for action, arguments in cases:
                with self.subTest(action=action):
                    code, events = self.invoke(action, *arguments)
                    self.assertEqual(code, 1)
                    self.assertFalse(events[-1]['ok'])
                    self.assertFalse(any(event['type'] == 'ha_wizard' for event in events))
        create.assert_not_called()

    def test_wizard_forms_outside_current_data_root_rejected(self):
        selected = self.root / 'external_form.json'
        selected.write_text('{}')
        for action, name in (('install', 'record_installation'), ('acceptance', 'save_acceptance')):
            with self.subTest(action=action), mock.patch.object(engine, name) as method:
                code, events = self.invoke(action, '--wizard-file', self.wizard, '--form-file', selected)
                self.assertEqual(code, 1)
                self.assertFalse(events[-1]['ok'])
                method.assert_not_called()

    def test_selected_form_symlink_rejected_before_engine(self):
        target = self.form({})
        selected = target.with_name('linked.json')
        selected.symlink_to(target)
        with mock.patch.object(engine, 'save_acceptance') as method:
            code, events = self.invoke('acceptance', '--wizard-file', self.wizard, '--form-file', selected)
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_parent_form_symlink_rejected_before_engine(self):
        folder = self.root / 'external_forms'
        folder.mkdir()
        (folder / 'form.json').write_text('{}')
        (self.data / 'linked_forms').symlink_to(folder, target_is_directory=True)
        with mock.patch.object(engine, 'record_installation') as method:
            code, events = self.invoke('install', '--wizard-file', self.wizard,
                                       '--form-file', self.data / 'linked_forms/form.json')
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_form_traversal_rejected_before_engine(self):
        selected = self.data / 'forms/../form.json'
        (self.data / 'forms').mkdir()
        (self.data / 'form.json').write_text('{}')
        with mock.patch.object(engine, 'record_installation') as method:
            code, events = self.invoke('install', '--wizard-file', self.wizard, '--form-file', selected)
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_directory_is_not_a_wizard_form(self):
        selected = self.data / 'form_directory'
        selected.mkdir()
        with mock.patch.object(engine, 'save_acceptance') as method:
            code, events = self.invoke('acceptance', '--wizard-file', self.wizard, '--form-file', selected)
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_large_form_rejected_before_engine(self):
        selected = self.form(raw=b' ' * (worker.MAX_REVIEW_FORM_BYTES + 1))
        with mock.patch.object(engine, 'save_acceptance') as method:
            code, events = self.invoke('acceptance', '--wizard-file', self.wizard, '--form-file', selected)
        self.assertEqual(code, 1)
        method.assert_not_called()
        self.assertFalse(events[-1]['ok'])

    def test_duplicate_nonfinite_malformed_and_nonobject_forms_rejected(self):
        for raw in (b'{"notes":"one","notes":"two"}', b'{"value":NaN}', b'{"value":Infinity}',
                    b'[]', b'not json', b'\xff'):
            with self.subTest(raw=raw), mock.patch.object(engine, 'record_installation') as method:
                selected = self.form(raw=raw)
                code, events = self.invoke('install', '--wizard-file', self.wizard, '--form-file', selected)
                self.assertEqual(code, 1)
                self.assertFalse(events[-1]['ok'])
                method.assert_not_called()

    def test_real_demo_creates_private_pending_state_and_loads_offline(self):
        code, events = self.invoke('demo')
        self.assertEqual(code, 0)
        result = next(event for event in events if event['type'] == 'ha_wizard')
        path = Path(result['wizard_file'])
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent.parent, self.data / 'private_ha_wizards')
        state = result['state']
        self.assertTrue(state['simulation'])
        self.assertFalse(state['assessment']['passed'])
        self.assertFalse(state['physical_feedback_verified'])
        self.assertEqual(set(state['observations']), set(engine.CASE_IDS))
        self.assertTrue(all(row['decision'] == 'pending' and row['event_id'] is None
                            for row in state['observations'].values()))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        loaded_code, loaded_events = self.invoke('load', '--wizard-file', path)
        self.assertEqual(loaded_code, 0)
        loaded = next(event for event in loaded_events if event['type'] == 'ha_wizard')
        self.assertTrue(loaded['valid'])
        self.assertFalse(loaded['assessment']['passed'])

    def test_real_demo_cannot_build_installable_bundle(self):
        _, events = self.invoke('demo')
        path = next(event['wizard_file'] for event in events if event['type'] == 'ha_wizard')
        code, failed = self.invoke('bundle', '--wizard-file', path)
        self.assertEqual(code, 1)
        self.assertFalse(failed[-1]['ok'])
        self.assertFalse(any(event['type'] == 'ha_wizard' for event in failed))
        self.assertFalse(list(Path(path).parent.glob('*.zip')))

    def test_real_invalid_load_keeps_finished_distinct_from_validity(self):
        code, events = self.invoke('load', '--wizard-file', self.wizard)
        self.assertEqual(code, 0)
        self.assertTrue(events[-1]['ok'])
        result = next(event for event in events if event['type'] == 'ha_wizard')
        self.assertFalse(result['valid'])
        self.assertFalse(result['assessment']['passed'])
        self.assertTrue(result['errors'])


if __name__ == '__main__':
    unittest.main()
