"""Synthetic local journey lifecycle; never household or runtime evidence.

Real-source flags below are deliberate test declarations for gate coverage.
No actual Mac capture, home connection, HA instance or light is exercised.
"""
import hashlib
import json
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import adapter_recipe as recipe
import analyze_capture as analysis
import baseline_review as baseline
import demo_sample as demo
import first_light_flow as flow
import ha_wizard as wizard
import offline_shcp as codec
import session_workbench as sessions


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
NO_PROFILE = dict(status='software_required', wire_compatible=False, package_eligible=False,
                  credential_check_required=False, profile_id=None)


class FirstLightFlowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in ((socket, 'socket'), (socket, 'create_connection'),
                            (socket, 'getaddrinfo'), (subprocess, 'run'), (subprocess, 'Popen')):
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('Offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)
        # The matcher has its own raw-source compatibility and credential tests;
        # journey tests isolate navigation from that independently owned policy.
        patcher = mock.patch.object(flow, '_profile', return_value=(dict(NO_PROFILE), None))
        self.profile_patcher = patcher
        self.profile = patcher.start()
        self.addCleanup(patcher.stop)

    def sample(self, real=True, fresh=False):
        original = codec.build_frame
        def build(number, kind, link, serial, fields):
            return original(number, kind, link, serial + (100 if fresh else 0), fields)
        with mock.patch.object(codec, 'build_frame', side_effect=build):
            directory = demo.create_demo_sample(self.root / 'captures')
        self.declare(directory, real)
        return directory

    def declare(self, directory, real):
        path = directory / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['simulation'] = not real
        metadata['target_context'] = dict(label='合成测试灯', room='合成测试室',
            kind='ordinary_switch_light', collection_id='1' * 32)
        path.write_text(json.dumps(metadata), encoding='utf-8')
        path = directory / 'events.jsonl'
        path.write_text(''.join(json.dumps(dict(json.loads(line), simulation=not real)) + '\n'
            for line in path.read_text().splitlines()), encoding='utf-8')

    def rounds(self, real=True):
        generated = sessions.create_demo(self.root)
        captures = self.root / 'captures'
        captures.mkdir(exist_ok=True)
        result = []
        for directory in generated:
            destination = captures / directory.name
            directory.rename(destination)
            self.declare(destination, real)
            result.append(destination)
        return tuple(result)

    def refresh(self, directory=None, **kwargs):
        return flow.refresh_flow(directory, self.root, **kwargs)

    def review(self, directory, pending=False):
        report_dir, report = analysis.analyze_session(directory, self.root / 'private_reports')
        form = baseline.draft_review(report)
        form.update(selected_identifier=demo.DEVICE.hex(),
            decisions={key: 'pending' if pending else 'pass' for key in baseline.CRITERION_IDS},
            notes={key: '合成测试声明；没有验证实物。' for key in baseline.CRITERION_IDS})
        path, _ = baseline.save_review(report_dir, directory, self.root, **form)
        return path

    def stage(self, record, key):
        return next(row for row in record['stages'] if row['id'] == key)

    def assert_offline(self, record):
        for key in ('machine_physical_feedback_verified', 'physical_feedback_verified',
                    'can_generate_live_driver', 'can_start_live_ha', 'driver_executed',
                    'network_access_performed', 'upload_performed', 'raw_pcap_copied',
                    'credential_values_copied', 'credential_value_hashes_copied'):
            self.assertIs(record[key], False)
        self.assertEqual(record['bytes_sent'], 0)
        self.assertFalse(record['supported_profile']['package_eligible'])
        for task in record['tasks'] + [record['next_action']]:
            self.assertIn(task['action'], flow.ACTIONS)
            self.assertEqual(task['bytes_sent'], 0)
            self.assertTrue(task['preparation_only'])
            if task['action'] != 'prepare_capture' or task['status'] != 'needs_sample':
                self.assertFalse(task['capture_allowed'])

    def installed(self):
        directory = self.sample()
        review = self.review(directory)
        wizard_path, state = wizard.create(review, self.root)
        sentinel = self.root / 'MUST_NOT_EXECUTE'
        driver = self.root / 'synthetic_driver.py'
        driver.write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n' + FAKE_DRIVER)
        _, state = wizard.import_driver(wizard_path, driver, self.root,
            {key: '合成离线测试依据，未验证实物。' for key in wizard.EVIDENCE_KEYS})
        self.assertFalse(sentinel.exists())
        return directory, review, wizard_path, state

    def acceptance(self, state):
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
        for index, (case, _, expected) in enumerate(wizard.CASE_TITLES):
            window, window_id = case, format(index + 1, '032x')
            event('window_started', 'local_marker', power)
            if case == 'disconnect':
                chosen = event('unavailable', 'disconnected')
                observed, ha, power = 'on', 'unavailable', None
            else:
                if case.startswith('ha_'):
                    event('command_requested', 'command_requested', expected, pending=True)
                if case == 'reconnect':
                    generation += 1
                    event('connected', 'connected')
                power = expected
                chosen = event('state', 'independent_readback' if case == 'reconnect' else 'independent_push', power, True)
                observed = ha = 'on' if expected else 'off'
            observations[case] = dict(decision='pass', physical_light=observed,
                ha_state=ha, notes='合成离线测试声明，不是实际HA验收。', event_id=chosen)
        diagnostics = dict(schema_version=wizard.VERSION, artifact='mc7021_ha_acceptance_diagnostics',
            wizard_id=state['wizard_id'], package_id=state['package_id'], host_ip=state['host_ip'],
            selected_identifier=state['selected_identifier'], driver_sha256=state['driver']['sha256'],
            baseline_review_sha256=state['baseline_review']['sha256'], simulation=False,
            session_id='synthetic_journey_test', dropped_events=0, events=events)
        return diagnostics, observations

    def test_initial_launch_is_complete_capture_guide_and_private(self):
        path, record = self.refresh()
        self.assertEqual(record['next_action']['action'], 'prepare_capture')
        self.assertEqual(self.stage(record, 'capture')['status'], 'needs_sample')
        self.assertEqual(len(flow.CAPTURE_STEPS), 10)
        self.assertEqual({key for key, _ in flow.CAPTURE_STEPS}, baseline.REQUIRED_STEPS)
        self.assertIn('USB', flow.render_text(record))
        self.assertIn('不扫描', flow.render_text(record))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(path.parent.parent, self.root / 'private_first_light_flows')
        self.assertEqual({p.name for p in path.parent.iterdir()}, {'flow.json', '首组全过程.txt'})
        self.assert_offline(record)

    def test_no_downstream_only_launch(self):
        for key in ('review_file', 'wizard_file', 'comparison_directory'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '须先选择首组'):
                self.refresh(None, **{key: self.root / 'not_selected'})

    def test_simulation_stays_preview_not_capture_ready(self):
        _, record = self.refresh(self.sample(False))
        self.assertTrue(record['simulation'])
        self.assertEqual(record['next_action']['id'], 'real_capture')
        self.assertFalse(record['next_action']['capture_allowed'])
        self.assertFalse(record['can_expand_to_other_lights'])
        self.assertTrue(all(not task['capture_allowed'] for task in record['tasks']))
        self.assert_offline(record)

    def test_one_complete_declared_round_next_review_then_holdout(self):
        directory = self.sample()
        _, record = self.refresh(directory)
        self.assertEqual(record['next_action']['action'], 'review_baseline')
        self.assertEqual(record['selected_identifier'], demo.DEVICE.hex())
        self.assertEqual(set(record['source_bindings']), set(baseline.INPUT_LIMITS) | {'report.json'})
        _, record = self.refresh(directory, review_file=self.review(directory))
        self.assertEqual(record['next_action']['id'], 'sample_independent_round')
        self.assertTrue(record['review']['passed'])
        self.assertEqual(self.stage(record, 'baseline')['status'], 'confirmed')
        self.assert_offline(record)

    def test_two_valid_rounds_do_not_make_a_live_driver(self):
        first, second = self.rounds()
        _, record = self.refresh(first, comparison_directory=second, review_file=self.review(first))
        self.assertTrue(record['independent_second_round'])
        self.assertEqual(self.stage(record, 'codec')['status'], 'confirmed')
        self.assertEqual(record['next_action']['action'], 'software_support')
        self.assertFalse(record['owner_declared_acceptance_passed'])
        self.assert_offline(record)

    def test_matching_wire_routes_to_credential_form_not_live_grant(self):
        first, second = self.rounds()
        self.profile.return_value = (dict(NO_PROFILE, status='requires_local_credential_check',
            wire_compatible=True, credential_check_required=True), None)
        _, record = self.refresh(first, comparison_directory=second, review_file=self.review(first))
        self.assertEqual(record['next_action']['action'], 'match_driver')
        self.assertTrue(record['supported_profile']['credential_check_required'])
        self.assert_offline(record)

    def test_pending_review_is_not_a_pass(self):
        directory = self.sample()
        _, record = self.refresh(directory, review_file=self.review(directory, pending=True))
        self.assertTrue(record['review']['valid'])
        self.assertFalse(record['review']['passed'])
        self.assertEqual(record['next_action']['action'], 'review_baseline')
        self.assert_offline(record)

    def test_same_host_other_sample_review_is_not_reused(self):
        first, other = self.sample(), self.sample(fresh=True)
        _, record = self.refresh(first, review_file=self.review(other))
        self.assertFalse(record['review']['valid'])
        self.assertFalse(record['review']['passed'])
        self.assertEqual(record['review']['reason'], 'invalid_or_other_source')

    def test_changed_review_record_does_not_skip_downstream_gate(self):
        directory = self.sample()
        review = self.review(directory)
        value = json.loads(review.read_text())
        value['selected_identifier'] = '1112131415161718'
        review.write_text(json.dumps(value))
        _, record = self.refresh(directory, review_file=review)
        self.assertFalse(record['review']['valid'])
        self.assertFalse(record['can_expand_to_other_lights'])

    def test_invalid_selected_identifiers_cannot_be_guessed(self):
        for identifier in ('01020304', '0102030405060709', 'not_an_id'):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.refresh(self.sample(), selected_identifier=identifier)

    def test_same_capture_copy_is_not_an_independent_round(self):
        first = self.sample()
        second = first.with_name('copied_capture')
        shutil.copytree(first, second)
        with self.assertRaisesRegex(ValueError, 'PCAP相同'):
            self.refresh(first, comparison_directory=second)

    def test_mixed_sources_host_and_target_context_rejected(self):
        first, second = self.sample(), self.sample(False, fresh=True)
        with self.assertRaisesRegex(ValueError, '真实与合成'):
            self.refresh(first, comparison_directory=second)
        self.declare(second, True)
        path = second / 'session.json'
        value = json.loads(path.read_text())
        value['target_ip'] = '192.0.2.21'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, '主机不同'):
            self.refresh(first, comparison_directory=second)
        value['target_ip'] = demo.HOST
        value['target_context']['collection_id'] = '2' * 32
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, '标签或采集组不对应'):
            self.refresh(first, comparison_directory=second)

    def test_changed_raw_original_blocks_refresh(self):
        directory = self.sample()
        (directory / 'traffic.pcap').write_bytes((directory / 'traffic.pcap').read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            self.refresh(directory)

    def test_symlink_source_and_output_are_rejected(self):
        directory = self.sample()
        original = directory / 'events.jsonl'
        target = self.root / 'copied_events'
        original.rename(target)
        original.symlink_to(target)
        with self.assertRaises(ValueError):
            self.refresh(directory)
        output = self.root / 'private_first_light_flows'
        output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.refresh()

    def test_source_change_during_analysis_blocks_persisting_journey(self):
        directory = self.sample()
        original = sessions.create_workbench
        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            (directory / 'events.jsonl').write_bytes((directory / 'events.jsonl').read_bytes() + b' ')
            return result
        with mock.patch.object(sessions, 'create_workbench', side_effect=change), self.assertRaisesRegex(ValueError, '原件|改变|变化'):
            self.refresh(directory)
        self.assertFalse((self.root / 'private_first_light_flows').exists())

    def test_unknown_drop_statistic_directs_to_capture_not_checkbox(self):
        directory = self.sample()
        path = directory / 'session.json'
        value = json.loads(path.read_text())
        value['capture_stop']['stats']['dropped_by_kernel'] = None
        path.write_text(json.dumps(value))
        _, record = self.refresh(directory)
        self.assertEqual(record['next_action']['id'], 'sample_capture_loss')
        self.assertEqual(record['next_action']['status'], 'needs_sample')
        self.assertFalse(record['review']['passed'])

    def test_validated_imported_driver_continues_to_bundle_without_execution(self):
        directory, review, path, _ = self.installed()
        _, record = self.refresh(directory, review_file=review, wizard_file=path)
        self.assertEqual(record['next_action']['action'], 'build_ha_bundle')
        self.assertEqual(self.stage(record, 'driver')['status'], 'confirmed')
        self.assertFalse((self.root / 'MUST_NOT_EXECUTE').exists())
        self.assert_offline(record)

    def test_package_then_owner_installation_then_eight_acceptance_steps(self):
        directory, review, path, _ = self.installed()
        _, state = wizard.build_bundle(path, self.root)
        _, record = self.refresh(directory, review_file=review, wizard_file=path)
        self.assertEqual(record['next_action']['action'], 'record_installation')
        _, state = wizard.record_installation(path, self.root,
            dict(entity_id='light.synthetic_journey', confirmed=True, notes='仅合成测试声明。'))
        _, record = self.refresh(directory, review_file=review, wizard_file=path)
        self.assertEqual(record['next_action']['action'], 'record_ha_acceptance')
        self.assertEqual(len([row for row in record['tasks'] if row['stage_id'] == 'acceptance']), 8)
        self.assertFalse(record['can_expand_to_other_lights'])
        self.assert_offline(record)

    def test_complete_synthetic_artifact_lifecycle_preserves_manual_scope(self):
        directory, review, path, _ = self.installed()
        _, state = wizard.build_bundle(path, self.root)
        _, state = wizard.record_installation(path, self.root,
            dict(entity_id='light.synthetic_journey', confirmed=True, notes='仅合成测试声明。'))
        diagnostics, observations = self.acceptance(state)
        diagnostics_path = self.root / 'synthetic_diagnostics.json'
        diagnostics_path.write_text(json.dumps(diagnostics))
        wizard.import_diagnostics(path, diagnostics_path, self.root)
        wizard.save_acceptance(path, self.root, observations)
        _, record = self.refresh(directory, review_file=review, wizard_file=path)
        self.assertEqual(record['next_action']['action'], 'complete')
        self.assertTrue(record['owner_declared_acceptance_passed'])
        self.assertTrue(record['can_expand_to_other_lights'])
        self.assertEqual(self.stage(record, 'acceptance')['status'], 'confirmed')
        self.assert_offline(record)
        # A changed bundled driver invalidates the complete downstream chain.
        loaded = wizard.load(path, self.root)['state']
        driver_path = path.parent / loaded['driver']['file']
        driver_path.write_text(driver_path.read_text() + '\n# changed\n')
        _, invalid = self.refresh(directory, review_file=review, wizard_file=path)
        self.assertFalse(invalid['wizard']['valid'])
        self.assertFalse(invalid['can_expand_to_other_lights'])
        self.assertFalse(invalid['owner_declared_acceptance_passed'])

    def test_wrong_or_unselected_review_cannot_reuse_wizard(self):
        directory, review, path, _ = self.installed()
        _, record = self.refresh(directory, wizard_file=path)
        self.assertFalse(record['wizard']['valid'])
        self.assertEqual(record['next_action']['action'], 'review_baseline')
        self.assertFalse(record['can_expand_to_other_lights'])

    def test_opaque_traffic_routes_to_software_before_impossible_target_selection(self):
        directory = self.sample()
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for index, payload in enumerate((b'', b'\x16\x03\x03' + b'X' * 64)):
            packet = demo.network_packet(demo.PHONE, demo.HOST, payload, 1000 + index,
                2 if index == 0 else 24)
            raw.extend(struct.pack('<IIII', 1767196811 + index, 0, len(packet), len(packet)))
            raw.extend(packet)
        (directory / 'traffic.pcap').write_bytes(raw)
        path = directory / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['pcap'] = dict(file='traffic.pcap', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        path.write_text(json.dumps(metadata))
        _, record = self.refresh(directory)
        self.assertIsNone(record['selected_identifier'])
        self.assertEqual(record['next_action']['action'], 'open_session_workbench')
        self.assertEqual(record['next_action']['status'], 'software_required')
        self.assertFalse(record['next_action']['capture_allowed'])
        self.assert_offline(record)

    def test_profile_specific_missing_source_is_an_explicit_capture_task(self):
        first, second = self.rounds()
        profile = dict(NO_PROFILE, status='needs_sample', tasks=[dict(id='real_sources',
            title='真实本户原件声明', category='recapture', status='needs_sample',
            why='来源未知不可打包。', instructions=['另采真实正常单灯一轮，不修改来源标记。'])])
        self.profile.return_value = (profile, None)
        _, record = self.refresh(first, comparison_directory=second, review_file=self.review(first))
        self.assertEqual(record['next_action']['id'], 'profile_real_sources')
        self.assertEqual(record['next_action']['action'], 'prepare_capture')
        self.assertEqual(record['next_action']['source_task_kind'], 'driver_profile')
        self.assert_offline(record)

    def test_actual_matcher_integration_keeps_unknown_authentication_unsupported(self):
        self.profile_patcher.stop()
        first, second = self.rounds()
        _, record = self.refresh(first, comparison_directory=second, review_file=self.review(first))
        self.assertFalse(record['supported_profile']['wire_compatible'])
        self.assertIn('driver_profile_file', record['artifacts'])
        artifact = self.root / record['artifacts']['driver_profile_file']
        self.assertTrue(artifact.is_file())
        output = json.dumps(record, ensure_ascii=False) + flow.render_text(record)
        self.assertNotIn('SYNTHETIC_ONLY_NOT_A_CREDENTIAL_', output)
        self.assertNotIn(b'SYNTHETIC_ONLY_NOT_A_CREDENTIAL_'.hex(), output)
        self.assert_offline(record)

    def test_saved_overview_flags_are_never_inputs(self):
        directory = self.sample()
        path, first = self.refresh(directory)
        forged = json.loads(path.read_text())
        forged.update(owner_declared_acceptance_passed=True, can_expand_to_other_lights=True,
            can_start_live_ha=True, can_generate_live_driver=True)
        path.write_text(json.dumps(forged))
        _, second = self.refresh(directory)
        self.assertFalse(second['owner_declared_acceptance_passed'])
        self.assertFalse(second['can_expand_to_other_lights'])
        self.assert_offline(second)
        self.assertNotEqual(first['flow_id'], second['flow_id'])

    def test_worker_projection_is_a_display_and_cannot_grant_live_capability(self):
        _, record = self.refresh()
        record.update(can_start_live_ha=True, can_generate_live_driver=True, physical_feedback_verified=True)
        summary = flow.worker_summary(record)
        for key in ('can_start_live_ha', 'can_generate_live_driver', 'physical_feedback_verified', 'upload_performed'):
            self.assertIs(summary[key], False)
        self.assertEqual(summary['bytes_sent'], 0)
        self.assertNotIn('source_bindings', summary)
        self.assertIn('首组灯全过程', summary['report_text'])


if __name__ == '__main__':
    unittest.main()
