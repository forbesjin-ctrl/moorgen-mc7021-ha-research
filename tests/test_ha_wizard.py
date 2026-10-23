"""Offline HA wizard tests; all fixtures use generated documentation addresses.

False real-source declarations below exercise local gates only. They are never
evidence of an actual residence, actual driver or working physical light.
"""
import copy
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
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture as analysis
import baseline_review as baseline
import demo_sample as demo
import ha_wizard as wizard


FAKE_DRIVER = '''DRIVER_API_VERSION = 1
class Driver:
    async def async_connect(self, *, host, identifier, on_state, on_disconnect):
        self.callback = on_state
    async def async_set_power(self, power):
        self.requested = power
    async def async_request_state(self):
        return None
    async def async_disconnect(self):
        return None
'''


class WizardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in [(socket, 'socket'), (socket, 'create_connection'),
                            (socket, 'getaddrinfo'), (subprocess, 'run'), (subprocess, 'Popen')]:
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('Offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def baseline(self, real=True, pending=False):
        directory = demo.create_demo_sample(self.root / 'captures')
        if real:
            path = directory / 'session.json'
            metadata = json.loads(path.read_text())
            metadata.update(simulation=False, script_version='generated_test_declaration',
                target_context=dict(label='合成测试灯', room='合成测试室', kind='ordinary_switch_light', collection_id='1' * 32))
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = directory / 'events.jsonl'
            rows = [dict(json.loads(line), simulation=False) for line in path.read_text().splitlines()]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        report_dir, report = analysis.analyze_session(directory, self.root / 'private_reports')
        form = baseline.draft_review(report)
        if real and not pending:
            form.update(decisions={key: 'pass' for key in baseline.CRITERION_IDS},
                notes={key: '仅合成离线测试声明，未验证实物。' for key in baseline.CRITERION_IDS},
                selected_identifier=demo.DEVICE.hex())
        review, _ = baseline.save_review(report_dir, directory, self.root, **form)
        return directory, report_dir, review

    def create(self):
        directory, report_dir, review = self.baseline()
        path, state = wizard.create(review, self.root, expected_host=demo.HOST)
        return path, state, directory, report_dir, review

    def adapter(self, state, source=FAKE_DRIVER):
        driver = self.root / ('input_driver_' + str(len(list(self.root.glob('input_driver*')))) + '.py')
        driver.write_text(source, encoding='utf-8')
        manifest = dict(schema_version=wizard.VERSION, artifact='private_mc7021_driver_manifest', driver_api=1,
            host_ip=state['host_ip'], selected_identifier=state['selected_identifier'],
            baseline_review_sha256=state['baseline_review']['sha256'],
            baseline_input_integrity=state['baseline_input_integrity'],
            driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(), simulation=False,
            evidence={key: '仅合成测试声明，不能作为真实协议依据。' for key in wizard.EVIDENCE_KEYS})
        manifest_path = driver.with_suffix('.json')
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        return manifest_path, driver, manifest

    def installed(self):
        path, state, directory, report_dir, review = self.create()
        manifest, driver, _ = self.adapter(state)
        _, state = wizard.import_adapter(path, manifest, driver, self.root)
        _, state = wizard.build_bundle(path, self.root)
        _, state = wizard.record_installation(path, self.root,
            dict(entity_id='light.generated_test', confirmed=True, notes='合成安装声明；没有运行HA。'))
        return path, state

    def log(self, state):
        events, observations = [], wizard.draft_observations()
        window, window_id, generation, power = None, None, 0, False
        def event(kind, source, value=None, independent=False, pending=False):
            row = dict(event_id=len(events) + 1, kind=kind, source=source,
                step_id=window, window_case=window, window_id=window_id, generation=generation,
                state=value, independent=independent, pending_command=pending,
                at='2026-01-01T00:00:00+00:00')
            events.append(row)
            return row['event_id']
        event('session_started', 'local_marker')
        generation = 1
        event('connected', 'connected')
        event('state', 'independent_readback', False, True)
        for case_index, (case, _, expected) in enumerate(wizard.CASE_TITLES):
            window, window_id = case, format(case_index + 1, '032x')
            event('window_started', 'local_marker', power)
            if case == 'disconnect':
                chosen = event('unavailable', 'disconnected')
                observed, ha = 'on', 'unavailable'
                power = None
            else:
                if case.startswith('ha_'):
                    event('command_requested', 'command_requested', expected, pending=True)
                if case == 'reconnect':
                    generation += 1
                    event('connected', 'connected')
                power = expected
                chosen = event('state', 'independent_readback' if case == 'reconnect' else 'independent_push', power, True)
                observed = ha = 'on' if expected else 'off'
            observations[case] = dict(decision='pass', physical_light=observed, ha_state=ha,
                notes='合成离线日志与人工声明测试，不是实际设备验收。', event_id=chosen)
        log = dict(schema_version=wizard.VERSION, artifact='mc7021_ha_acceptance_diagnostics',
            wizard_id=state['wizard_id'], package_id=state['package_id'], host_ip=state['host_ip'],
            selected_identifier=state['selected_identifier'], driver_sha256=state['driver']['sha256'],
            baseline_review_sha256=state['baseline_review']['sha256'], simulation=False,
            session_id='generated_test_session', dropped_events=0, events=events)
        return log, observations

    def import_log(self, path, value):
        source = self.root / 'ha_diagnostics_input.json'
        source.write_text(json.dumps(value), encoding='utf-8')
        return wizard.import_diagnostics(path, source, self.root)

    def test_real_declaration_create_binds_four_originals_and_complete_baseline(self):
        path, state, _, _, review = self.create()
        self.assertEqual(state['stage'], 'adapter')
        self.assertFalse(state['assessment']['passed'])
        self.assertEqual(set(state['baseline_input_integrity']), {'traffic.pcap', 'session.json', 'events.jsonl', 'report.json'})
        self.assertEqual(state['baseline_review']['sha256'], hashlib.sha256(review.read_bytes()).hexdigest())
        self.assertTrue(wizard.load(path, self.root)['valid'])

    def test_pending_and_synthetic_baselines_cannot_open_real_wizard(self):
        for real in (False, True):
            _, _, review = self.baseline(real=real, pending=True)
            with self.assertRaises(ValueError):
                wizard.create(review, self.root)

    def test_demo_eight_steps_save_pending_and_never_enable_package_or_pass(self):
        path, state = wizard.create_demo(self.root)
        self.assertTrue(state['simulation'])
        self.assertEqual(len(state['assessment']['criteria']), 8)
        pending = dict(state['observations']['ha_on_1'], notes='演练笔记')
        _, state = wizard.save_acceptance(path, self.root, {'ha_on_1': pending})
        self.assertEqual(state['observations']['ha_on_1']['notes'], '演练笔记')
        self.assertFalse(state['assessment']['passed'])
        with self.assertRaises(ValueError):
            wizard.build_bundle(path, self.root)
        passing = dict(pending, decision='pass', event_id=1)
        with self.assertRaises(ValueError):
            wizard.save_acceptance(path, self.root, {'ha_on_1': passing})

    def test_all_four_original_changes_invalidate_every_downstream(self):
        for name in ('traffic.pcap', 'session.json', 'events.jsonl', 'report.json'):
            path, _, directory, report_dir, _ = self.create()
            source = (report_dir if name == 'report.json' else directory) / name
            source.write_bytes(source.read_bytes() + b' ')
            result = wizard.load(path, self.root)
            self.assertFalse(result['valid'])
            self.assertFalse(result['assessment']['passed'])
            with self.assertRaises(ValueError):
                wizard.save_acceptance(path, self.root, {'ha_on_1': wizard.draft_observations()['ha_on_1']})

    def test_review_record_change_and_host_mismatch_invalidate(self):
        path, _, _, _, review = self.create()
        self.assertFalse(wizard.load(path, self.root, '192.0.2.99')['valid'])
        review.write_bytes(review.read_bytes() + b' ')
        self.assertFalse(wizard.load(path, self.root)['valid'])

    def test_source_is_never_executed_during_static_driver_import(self):
        path, state, *_ = self.create()
        sentinel = self.root / 'MUST_NOT_EXIST'
        source = 'from pathlib import Path\nPath(' + repr(str(sentinel)) + ').write_text("EXECUTED")\n' + FAKE_DRIVER
        manifest, driver, _ = self.adapter(state, source)
        _, state = wizard.import_adapter(path, manifest, driver, self.root)
        self.assertFalse(sentinel.exists())
        self.assertEqual(state['stage'], 'bundle')
        self.assertTrue(wizard.load(path, self.root)['valid'])

    def test_manifest_scope_hash_api_evidence_and_simulation_are_strict(self):
        path, state, *_ = self.create()
        source, driver, manifest = self.adapter(state)
        changes = [('host_ip', '192.0.2.99'), ('selected_identifier', '0' * 16),
            ('baseline_review_sha256', '0' * 64), ('driver_sha256', '0' * 64),
            ('baseline_input_integrity', {}), ('driver_api', True), ('driver_api', '1'),
            ('simulation', True), ('evidence', {}), ('evidence', dict(manifest['evidence'], protocol=''))]
        for key, changed in changes:
            with self.subTest(key=key, changed=changed):
                source.write_text(json.dumps(dict(manifest, **{key: changed})))
                with self.assertRaises(ValueError):
                    wizard.import_adapter(path, source, driver, self.root)

    def test_gui_driver_import_automatically_binds_source_hash_without_manual_json(self):
        path, state, *_ = self.create()
        _, driver, manifest = self.adapter(state)
        _, state = wizard.import_driver(path, driver, self.root, manifest['evidence'])
        actual = json.loads((path.parent / state['adapter_manifest']['file']).read_text())
        self.assertEqual(actual['driver_sha256'], hashlib.sha256(driver.read_bytes()).hexdigest())
        self.assertEqual(actual['baseline_review_sha256'], state['baseline_review']['sha256'])
        self.assertEqual(actual['evidence'], manifest['evidence'])

    def test_gui_driver_import_rejects_missing_evidence_and_nonfunctional_stub(self):
        path, state, *_ = self.create()
        _, driver, manifest = self.adapter(state)
        with self.assertRaises(ValueError):
            wizard.import_driver(path, driver, self.root, dict(manifest['evidence'], protocol=''))
        with self.assertRaises(ValueError):
            wizard.import_driver(path, wizard.TEMPLATE_ROOT / 'driver.py', self.root, manifest['evidence'])

    def test_incomplete_stub_and_missing_async_contract_are_rejected(self):
        path, state, *_ = self.create()
        sources = [FAKE_DRIVER.replace('DRIVER_API_VERSION = 1', 'DRIVER_API_VERSION = True'),
            FAKE_DRIVER.replace('async def async_request_state', 'def async_request_state'),
            FAKE_DRIVER.replace('self.callback = on_state', 'raise NotImplementedError'),
            (wizard.TEMPLATE_ROOT / 'driver.py').read_text()]
        for source in sources:
            manifest, driver, _ = self.adapter(state, source)
            with self.assertRaises(ValueError):
                wizard.import_adapter(path, manifest, driver, self.root)

    def test_install_bundle_uses_only_fixed_templates_and_one_bound_driver(self):
        path, state = self.installed()
        bundle = Path(state['bundle_path'])
        with zipfile.ZipFile(bundle) as archive:
            names = set(archive.namelist())
            expected = {'custom_components/mc7021_single_light/' + name for name in wizard.TEMPLATE_FILES}
            expected |= {'custom_components/mc7021_single_light/driver.py', 'custom_components/mc7021_single_light/binding.json', '安装与验收.txt'}
            self.assertEqual(names, expected)
            binding = json.loads(archive.read('custom_components/mc7021_single_light/binding.json'))
            self.assertEqual(binding['target_identifier'], state['selected_identifier'])
            self.assertEqual(binding['wizard_id'], state['wizard_id'])
            self.assertEqual(binding['package_id'], state['package_id'])
            self.assertEqual(archive.read('custom_components/mc7021_single_light/driver.py').decode(), FAKE_DRIVER)
            self.assertFalse(any('.pcap' in name or name.startswith('/') or '..' in name for name in names))

    def test_starter_is_nonfunctional_private_template_never_online_bundle(self):
        path, _ = wizard.create_demo(self.root)
        _, state = wizard.export_starter(path, self.root)
        folder = Path(state['starter_directory'])
        self.assertEqual({item.name for item in folder.iterdir()}, {'driver.py.stub', 'driver_manifest.template.json', '开始编写.txt'})
        manifest = json.loads((folder / 'driver_manifest.template.json').read_text())
        self.assertIsNone(manifest['driver_sha256'])
        self.assertTrue(manifest['simulation'])
        self.assertFalse(state['assessment']['passed'])

    def test_install_declaration_requires_actual_light_entity_and_written_notes(self):
        path, state = self.installed()
        for value in ({'entity_id': 'switch.bad', 'confirmed': True, 'notes': 'x'},
                      {'entity_id': 'light.test', 'confirmed': 1, 'notes': 'x'},
                      {'entity_id': 'light.test', 'confirmed': True, 'notes': ''}):
            with self.assertRaises(ValueError):
                wizard.record_installation(path, self.root, value)
        self.assertEqual(state['stage'], 'acceptance')

    def test_full_log_and_eight_observations_form_local_manual_acceptance_only(self):
        path, state = self.installed()
        log, observations = self.log(state)
        _, state = self.import_log(path, log)
        self.assertEqual(len(state['diagnostic_events']), len(log['events']))
        self.assertNotIn('diagnostic_events', json.loads(path.read_text()))
        _, state = wizard.save_acceptance(path, self.root, observations)
        self.assertTrue(state['assessment']['passed'])
        self.assertEqual(state['stage'], 'complete')
        self.assertFalse(state['assessment']['physical_feedback_verified'])
        self.assertFalse(state['assessment']['identity_authenticated'])
        self.assertTrue(wizard.load(path, self.root)['assessment']['passed'])

    def test_partial_acceptance_save_preserves_other_observations(self):
        path, state = self.installed()
        log, observations = self.log(state)
        self.import_log(path, log)
        for key in wizard.CASE_IDS:
            _, state = wizard.save_acceptance(path, self.root, {key: observations[key]})
        self.assertEqual(state['observations'], observations)
        self.assertTrue(state['assessment']['passed'])

    def test_pass_checkbox_without_log_cannot_accept(self):
        path, state = self.installed()
        _, observations = self.log(state)
        _, state = wizard.save_acceptance(path, self.root, observations)
        self.assertFalse(state['assessment']['passed'])
        self.assertEqual(len(state['assessment']['criteria']), 8)
        self.assertTrue(state['assessment']['resample'])

    def test_observation_requires_nonempty_notes_integer_event_and_exact_states(self):
        path, state = self.installed()
        _, observations = self.log(state)
        for change in ({'notes': ''}, {'event_id': True}, {'event_id': None}, {'physical_light': 'cached'}):
            row = dict(observations['ha_on_1'], **change)
            with self.assertRaises(ValueError):
                wizard.save_acceptance(path, self.root, {'ha_on_1': row})

    def test_wrong_physical_or_ha_state_is_explicit_resample_not_pass(self):
        path, state = self.installed()
        log, observations = self.log(state)
        self.import_log(path, log)
        observations['panel_on']['physical_light'] = 'off'
        _, state = wizard.save_acceptance(path, self.root, observations)
        self.assertFalse(state['assessment']['passed'])
        self.assertTrue(any('肉眼' in gap for gap in state['assessment']['resample']))

    def test_ha_wrapper_diagnostics_supported_without_extra_private_data_preview(self):
        path, state = self.installed()
        log, _ = self.log(state)
        log['events'][0]['secret_extra'] = 'do not display'
        _, state = self.import_log(path, {'home_assistant': {'private': 'ignored'}, 'data': log})
        self.assertNotIn('secret_extra', state['diagnostic_events'][0])

    def test_wrong_diagnostic_scope_and_synthetic_are_rejected(self):
        path, state = self.installed()
        log, _ = self.log(state)
        for key in ('host_ip', 'selected_identifier', 'wizard_id', 'package_id', 'driver_sha256', 'baseline_review_sha256'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.import_log(path, dict(log, **{key: 'wrong'}))
        with self.assertRaises(ValueError):
            self.import_log(path, dict(log, simulation=True))

    def test_duplicate_ids_generation_rollback_bad_timestamp_and_truncated_log_rejected(self):
        path, state = self.installed()
        log, _ = self.log(state)
        variants = []
        bad = copy.deepcopy(log); bad['events'][4]['event_id'] = bad['events'][3]['event_id']; variants.append(bad)
        bad = copy.deepcopy(log); bad['events'].pop(4); variants.append(bad)
        bad = copy.deepcopy(log); bad['events'] = bad['events'][1:]; variants.append(bad)
        bad = copy.deepcopy(log); bad['events'][4]['generation'] = 0; variants.append(bad)
        bad = copy.deepcopy(log); bad['events'][4]['at'] = 'nan'; variants.append(bad)
        bad = copy.deepcopy(log); bad['events'][4]['at'] = '2025-01-01T00:00:00Z'; variants.append(bad)
        variants.append(dict(log, dropped_events=1))
        bad = dict(log); bad.pop('dropped_events'); variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError):
                self.import_log(path, bad)

    def test_ack_cached_command_and_bool_coercion_cannot_be_state(self):
        path, state = self.installed()
        log, observations = self.log(state)
        index = observations['ha_on_1']['event_id'] - 1
        for fields in ({'source': 'ack'}, {'source': 'command_requested'}, {'independent': False}, {'state': 1}):
            bad = copy.deepcopy(log)
            bad['events'][index].update(fields)
            with self.assertRaises(ValueError):
                self.import_log(path, bad)

    def test_window_id_and_pending_window_guards_reject_relabelled_events(self):
        path, state = self.installed()
        log, observations = self.log(state)
        target = observations['panel_on']['event_id'] - 1
        bad = copy.deepcopy(log); bad['events'][target]['window_id'] = 'f' * 32
        with self.assertRaises(ValueError): self.import_log(path, bad)
        bad = copy.deepcopy(log); bad['events'][target - 1]['pending_command'] = True
        with self.assertRaises(ValueError): self.import_log(path, bad)

    def test_panel_requires_prior_opposite_state_and_no_ha_request_in_window(self):
        path, state = self.installed()
        log, observations = self.log(state)
        target = observations['panel_on']['event_id'] - 1
        bad = copy.deepcopy(log)
        bad['events'][target - 1]['state'] = True
        self.import_log(path, bad)
        _, result = wizard.save_acceptance(path, self.root, observations)
        self.assertFalse(result['assessment']['passed'])
        bad = copy.deepcopy(log)
        bad['events'][target]['kind'] = 'command_requested'
        bad['events'][target]['source'] = 'command_requested'
        bad['events'][target]['independent'] = False
        bad['events'][target]['pending_command'] = True
        self.import_log(path, bad)
        _, result = wizard.save_acceptance(path, self.root, observations)
        self.assertFalse(result['assessment']['passed'])

    def test_reconnect_requires_new_generation_readback_after_unavailable(self):
        path, state = self.installed()
        log, observations = self.log(state)
        target = observations['reconnect']['event_id'] - 1
        for change in ({'source': 'independent_push'}, {'generation': 1}):
            bad = copy.deepcopy(log)
            if 'generation' in change:
                bad['events'][target - 1]['generation'] = 1
            bad['events'][target].update(change)
            self.import_log(path, bad)
            _, result = wizard.save_acceptance(path, self.root, observations)
            self.assertFalse(result['assessment']['passed'])

    def test_disconnect_can_observe_on_or_off_and_reconnect_must_match_readback(self):
        path, state = self.installed()
        log, observations = self.log(state)
        observations['disconnect']['physical_light'] = 'off'
        log['events'][observations['reconnect']['event_id'] - 1]['state'] = False
        observations['reconnect'].update(physical_light='off', ha_state='off')
        self.import_log(path, log)
        _, state = wizard.save_acceptance(path, self.root, observations)
        self.assertTrue(state['assessment']['passed'])

    def test_new_log_new_install_new_driver_and_new_package_clear_old_acceptance(self):
        path, state = self.installed()
        log, observations = self.log(state)
        self.import_log(path, log)
        _, state = wizard.save_acceptance(path, self.root, observations)
        self.assertTrue(state['assessment']['passed'])
        _, state = self.import_log(path, dict(log, session_id='another_session'))
        self.assertTrue(all(row['decision'] == 'pending' for row in state['observations'].values()))
        self.assertFalse(state['assessment']['passed'])
        _, state = wizard.build_bundle(path, self.root)
        self.assertIsNone(state['installation'])
        self.assertIsNone(state['diagnostics'])
        manifest, driver, _ = self.adapter(state, FAKE_DRIVER + '\n# replacement\n')
        _, state = wizard.import_adapter(path, manifest, driver, self.root)
        self.assertIsNone(state['bundle'])
        self.assertIsNone(state['package_id'])

    def test_changed_private_assets_invalidate_and_forged_passed_flag_is_ignored(self):
        for key in ('driver', 'adapter_manifest', 'bundle'):
            path, state = self.installed()
            asset = path.parent / state[key]['file']
            asset.write_bytes(asset.read_bytes() + b' ')
            self.assertFalse(wizard.load(path, self.root)['valid'])
        path, _ = self.installed()
        saved = json.loads(path.read_text())
        saved['assessment'] = {'passed': True, 'stage': 'complete'}
        saved['stage'] = 'complete'
        path.write_text(json.dumps(saved))
        self.assertFalse(wizard.load(path, self.root)['assessment']['passed'])

    def test_changed_diagnostics_invalidates_previous_acceptance(self):
        path, state = self.installed()
        log, observations = self.log(state)
        self.import_log(path, log)
        _, state = wizard.save_acceptance(path, self.root, observations)
        asset = path.parent / state['diagnostics']['file']
        asset.write_bytes(asset.read_bytes() + b' ')
        self.assertFalse(wizard.load(path, self.root)['valid'])

    def test_private_modes_all_wizard_assets_700_folders_600_files(self):
        path, state = self.installed()
        log, _ = self.log(state)
        self.import_log(path, log)
        wizard.export_starter(path, self.root)
        for item in (self.root / 'private_ha_wizards').rglob('*'):
            expected = 0o700 if item.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), expected, str(item))

    def test_symlink_input_state_asset_and_destination_are_rejected(self):
        path, state, *_ = self.create()
        manifest, driver, _ = self.adapter(state)
        alias = driver.with_name('alias.py'); alias.symlink_to(driver)
        with self.assertRaises(ValueError): wizard.import_adapter(path, manifest, alias, self.root)
        alias = path.with_name('alias.json'); alias.symlink_to(path)
        self.assertFalse(wizard.load(alias, self.root)['valid'])
        another = self.root / 'other'; another.mkdir()
        target = self.root / 'second_root'; target.mkdir()
        (target / 'private_ha_wizards').symlink_to(another)
        with self.assertRaises(ValueError): wizard.create_demo(target)
        self.assertEqual(list(another.iterdir()), [])

    def test_json_duplicate_keys_nan_and_oversized_inputs_are_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(ValueError): wizard._json(raw)
        path, state, *_ = self.create()
        manifest, driver, _ = self.adapter(state)
        driver.write_bytes(b'x' * (wizard.MAX_DRIVER + 1))
        with self.assertRaises(ValueError): wizard.import_adapter(path, manifest, driver, self.root)

    def test_list_is_bounded_and_reports_invalid_symlink_without_following(self):
        path, _ = wizard.create_demo(self.root)
        self.assertEqual(len(wizard.list_wizards(self.root)), 1)
        other = path.parent.with_name('wizard_' + 'f' * 32)
        other.symlink_to(path.parent)
        listed = wizard.list_wizards(self.root)
        self.assertEqual(len(listed), 2)
        self.assertFalse(all(item['valid'] for item in listed))


if __name__ == '__main__':
    unittest.main()
