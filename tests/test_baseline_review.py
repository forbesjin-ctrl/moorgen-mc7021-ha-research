"""Local synthetic fixtures exercise review rules, never household devices."""
import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture as analysis
import baseline_review as baseline
import demo_sample as demo


class BaselineReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.session = demo.create_demo_sample(self.root / 'captures')

    def analyze(self, real_declaration=False):
        if real_declaration:
            path = self.session / 'session.json'
            metadata = json.loads(path.read_text())
            metadata.update(simulation=False, sample_origin='test_operator_declaration',
                script_version='test_real_declaration', target_context=dict(label='测试灯一',
                    room='测试房间', kind='ordinary_switch_light',
                    collection_id='00000000-0000-4000-8000-000000000001'))
            path.write_text(json.dumps(metadata), encoding='utf-8')
            path = self.session / 'events.jsonl'
            rows = [dict(json.loads(row), simulation=False) for row in path.read_text().splitlines()]
            path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        self.report_dir, self.report = analysis.analyze_session(self.session, self.root / 'private_reports')
        return self.report

    def all_pass(self):
        return dict(decisions={key: 'pass' for key in baseline.CRITERION_IDS},
            notes={key: '仅用于自动测试的人工声明，帧1及本轮现场记录需由真人核对' for key in baseline.CRITERION_IDS},
            selected_identifier=demo.DEVICE.hex(), reviewer_label='本机匿名复核者')

    def save(self, form=None):
        return baseline.save_review(self.report_dir, self.session, self.root,
                                    **(form if form is not None else self.all_pass()))

    def criterion(self, assessment, key):
        return next(row for row in assessment['criteria'] if row['id'] == key)

    def test_synthetic_is_never_eligible_or_automatically_passed(self):
        report = self.analyze()
        checked = baseline.assess_report(report)
        self.assertFalse(checked['passed'])
        self.assertFalse(checked['eligible_for_manual_review'])
        self.assertTrue(checked['resample'])
        self.assertTrue(all(row['manual_required'] for row in checked['criteria']))
        self.assertFalse(checked['physical_feedback_verified'])
        with self.assertRaises(ValueError):
            self.save()

    def test_real_declaration_is_only_eligible_machine_never_passes(self):
        checked = baseline.assess_report(self.analyze(True))
        self.assertTrue(checked['eligible_for_manual_review'])
        self.assertFalse(checked['passed'])
        self.assertEqual(checked['eligible_candidate_identifiers'], [demo.DEVICE.hex()])
        self.assertEqual(set(baseline.CRITERION_IDS), {row['id'] for row in checked['criteria']})
        self.assertTrue(any('帧' in text for row in checked['criteria'] for text in row['evidence']))
        self.assertIn('住宅身份', ' '.join(checked['confirmed']))

    def test_missing_skipped_partial_steps_require_specific_resample(self):
        for state in ('skipped', 'partial', 'missing'):
            with self.subTest(state=state):
                report = copy.deepcopy(self.analyze(True))
                row = next(item for item in report['events'] if item['step'] == '面板关')
                if state == 'missing':
                    report['events'].remove(row)
                else:
                    row['status'] = state
                checked = baseline.assess_report(report)
                self.assertFalse(checked['eligible_for_manual_review'])
                self.assertTrue(any('面板关' in text for text in checked['resample']))

    def test_only_ack_or_execution_response_cannot_be_panel_state(self):
        for kind in ('ack_not_state', 'execution_response_not_state'):
            report = copy.deepcopy(self.analyze(True))
            panel = [row['index'] for row in report['frames'] if set(row['nearby_steps']) & {'面板开', '面板关'}]
            for row in report['frames']:
                if row['index'] in panel:
                    row['kind'] = kind
                    # Even retained fraudulent summary/state lists are ignored.
            checked = baseline.assess_report(report)
            self.assertFalse(checked['eligible_for_manual_review'])
            self.assertEqual(self.criterion(checked, 'panel_feedback')['machine_status'], 'resample')

    def test_state_direction_context_fields_and_ambiguity_must_be_independent(self):
        for change in ('direction', 'context', 'field', 'ambiguous'):
            report = copy.deepcopy(self.analyze(True))
            for row in report['frames']:
                if '重进App读状态' not in row['nearby_steps']:
                    continue
                if change == 'direction':
                    row['direction'] = 'to_host'
                elif change == 'context':
                    for item in row['states']:
                        item['status_context']['device_status_context_confirmed'] = False
                elif change == 'field':
                    for item in row['states']:
                        item['fields'] = [field for field in item['fields'] if field['id'] != 11]
                else:
                    row['event_association_ambiguous'] = True
            checked = baseline.assess_report(report)
            self.assertEqual(self.criterion(checked, 'reopen_readback')['machine_status'], 'resample')

    def test_summary_counts_cannot_substitute_four_command_windows(self):
        report = self.analyze(True)
        next(row for row in report['frames'] if row['command'] == 'light-off')['nearby_steps'] = ['App关1', 'App关2']
        checked = baseline.assess_report(report)
        self.assertEqual(checked['candidate_identifiers'], [])
        self.assertEqual(self.criterion(checked, 'switch_semantics')['machine_status'], 'resample')

    def test_two_different_candidates_cannot_supply_union_of_evidence(self):
        report = self.analyze(True)
        new = '1112131415161718'
        report['device_candidates'].append(dict(report['device_candidates'][0], identifier_hex=new))
        command_frames = [row for row in report['frames'] if row['kind'] == 'light_command_candidate']
        for row in list(command_frames):
            duplicate = copy.deepcopy(row)
            duplicate['index'] += 100
            duplicate['device_identifiers'] = [new]
            report['frames'].append(duplicate)
            for window in report['events']:
                if row['index'] in window['frame_indices']:
                    window['frame_indices'].append(duplicate['index'])
        for row in report['frames']:
            if '重进App读状态' in row['nearby_steps']:
                for item in row['states']:
                    item['device_identifier_hex'] = new
        checked = baseline.assess_report(report)
        self.assertEqual(len(checked['candidate_identifiers']), 2)
        self.assertEqual(checked['eligible_candidate_identifiers'], [])
        self.assertFalse(checked['eligible_for_manual_review'])

    def test_zero_unknown_truncated_dropped_and_opaque_fail_closed(self):
        for change in ('zero', 'unknown', 'truncated', 'drop', 'opaque', 'gap'):
            report = copy.deepcopy(self.analyze(True))
            if change in ('zero', 'unknown'):
                report['summary']['target_packet_count'] = 0 if change == 'zero' else None
            elif change == 'truncated':
                report['quality']['checks'].append(dict(name='截断包', status='warn', detail='1包'))
            elif change == 'drop':
                next(row for row in report['quality']['checks'] if row['name'] == '内核丢包')['status'] = 'warn'
            elif change == 'opaque':
                report['flows'][0]['payload_classification'] = 'tls_like_not_decrypted'
            else:
                report['flows'][0]['issues'].append('TCP序号缺口：不能拼接')
            checked = baseline.assess_report(report)
            self.assertFalse(checked['eligible_for_manual_review'])
            self.assertTrue(checked['resample'])

    def test_unknown_physical_or_wrong_app_display_requires_observation(self):
        report = self.analyze(True)
        window = next(row for row in report['events'] if row['step'] == '面板开')
        window['physical_light'] = 'unknown'
        window['app_display'] = 'off'
        checked = baseline.assess_report(report)
        self.assertEqual(self.criterion(checked, 'panel_feedback')['machine_status'], 'resample')
        self.assertTrue(any('肉眼' in text for text in checked['resample']))
        self.assertTrue(any('App显示' in text for text in checked['resample']))

    def test_skip_warning_and_unknown_quality_block_automatic_eligibility(self):
        report = self.analyze(True)
        report['quality']['warnings'].append('采样包含跳过步骤，不能据此声称覆盖完整单灯闭环')
        checked = baseline.assess_report(report)
        self.assertFalse(checked['eligible_for_manual_review'])
        report['quality']['warnings'] = []
        report['quality']['level'] = 'unknown'
        self.assertFalse(baseline.assess_report(report)['eligible_for_manual_review'])

    def test_event_source_declaration_mismatch_rejects_binding(self):
        self.analyze(True)
        events_path = self.session / 'events.jsonl'
        events = [json.loads(row) for row in events_path.read_text().splitlines()]
        events[0]['simulation'] = True
        events_path.write_text('\n'.join(json.dumps(row) for row in events) + '\n')
        with self.assertRaises(ValueError):
            self.save(baseline.draft_review(self.report))

    def test_draft_has_all_pending_and_synthetic_draft_can_be_saved(self):
        self.analyze()
        form = baseline.draft_review(self.report)
        self.assertTrue(all(value == 'pending' for value in form['decisions'].values()))
        path, record = self.save(form)
        self.assertTrue(path.is_file())
        self.assertFalse(record['passed'])
        checked = baseline.load_review(path, self.root)
        self.assertTrue(checked['valid'])
        self.assertFalse(checked['passed'])

    def test_demo_runs_draft_allowed_but_real_declaration_outside_captures_cannot_pass(self):
        self.session = demo.create_demo_sample(self.root / 'demo_runs')
        self.analyze(True)
        path, _ = self.save(baseline.draft_review(self.report))
        self.assertTrue(baseline.load_review(path, self.root)['valid'])
        with self.assertRaises(ValueError):
            self.save()

    def test_each_of_five_decisions_and_pass_notes_are_required(self):
        self.analyze(True)
        for field in ('decisions', 'notes'):
            form = self.all_pass()
            del form[field]['panel_feedback']
            with self.assertRaises(ValueError):
                self.save(form)
        form = self.all_pass()
        form['notes']['panel_feedback'] = ' \n '
        with self.assertRaises(ValueError):
            self.save(form)
        form = self.all_pass()
        form['decisions']['panel_feedback'] = True
        with self.assertRaises(ValueError):
            self.save(form)

    def test_valid_local_human_declaration_binds_all_four_files(self):
        self.analyze(True)
        before = {name: (self.session / name).read_bytes() for name in baseline.INPUT_LIMITS}
        path, record = self.save()
        checked = baseline.validate_review(path, self.root, expected_host=demo.HOST,
                                          expected_target_context=self.report['target_context'])
        self.assertTrue(checked['valid'], checked['errors'])
        self.assertTrue(checked['passed'])
        self.assertTrue(record['manual_confirmation'])
        self.assertFalse(record['physical_feedback_verified'])
        self.assertFalse(record['can_start_live_ha'])
        self.assertEqual(set(record['input_integrity']), {'session.json', 'events.jsonl', 'traffic.pcap', 'report.json'})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(before, {name: (self.session / name).read_bytes() for name in baseline.INPUT_LIMITS})
        self.assertEqual(len(baseline.load_reviews(self.root)), 1)
        self.assertEqual(baseline.load_reviews(self.root)[0]['review_file'], str(path))

    def test_original_or_report_mutation_missing_invalidates(self):
        for name in ('session.json', 'events.jsonl', 'traffic.pcap', 'report.json'):
            self.analyze(True)
            path, _ = self.save()
            source = self.report_dir / name if name == 'report.json' else self.session / name
            original = source.read_bytes()
            source.write_bytes(original + b'\n')
            checked = baseline.validate_review(path, self.root)
            self.assertFalse(checked['valid'], name)
            self.assertFalse(checked['passed'])
            source.write_bytes(original)
            source.unlink()
            self.assertFalse(baseline.validate_review(path, self.root)['valid'])
            source.write_bytes(original)

    def test_modified_session_or_events_after_analysis_before_first_save_rejected(self):
        for name in ('session.json', 'events.jsonl'):
            self.analyze(True)
            path = self.session / name
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            with self.assertRaisesRegex(ValueError, '分析时三文件哈希'):
                self.save()
            path.write_bytes(original)

    def test_legacy_missing_analysis_hashes_can_save_pending_but_never_pass(self):
        self.analyze(True)
        self.report['source'].pop('input_files', None)
        (self.report_dir / 'report.json').write_text(json.dumps(self.report), encoding='utf-8')
        assessment = baseline.assess_report(self.report)
        self.assertFalse(assessment['eligible_for_manual_review'])
        self.assertTrue(any('重新分析已有原件' in row for row in assessment['resample']))
        path, record = self.save(baseline.draft_review(self.report))
        self.assertFalse(record['passed'])
        self.assertTrue(baseline.validate_review(path, self.root)['valid'])
        with self.assertRaises(ValueError):
            self.save()

    def test_report_is_parsed_from_same_bytes_as_its_bound_hash(self):
        self.analyze(True)
        original = baseline._read_file
        calls = []
        def observe(path, limit):
            calls.append(Path(path).name)
            return original(path, limit)
        from unittest import mock
        with mock.patch.object(baseline, '_read_file', side_effect=observe):
            baseline._snapshot(self.root, self.report_dir, self.session)
        self.assertEqual(calls.count('report.json'), 1)
        self.assertEqual(calls.count('session.json'), 1)
        self.assertEqual(calls.count('events.jsonl'), 1)
        self.assertEqual(calls.count('traffic.pcap'), 1)

    def test_different_host_and_target_cannot_reuse_pass(self):
        self.analyze(True)
        path, _ = self.save()
        self.assertFalse(baseline.validate_review(path, self.root, expected_host='192.0.2.21')['passed'])
        new_context = dict(self.report['target_context'], label='另一个灯路')
        self.assertFalse(baseline.validate_review(path, self.root, expected_target_context=new_context)['passed'])

    def test_bad_candidate_cannot_be_selected(self):
        self.analyze(True)
        for value in ('', '1112131415161718', '42', '../bad'):
            form = self.all_pass()
            form['selected_identifier'] = value
            with self.assertRaises(ValueError):
                self.save(form)

    def test_any_nonpass_item_keeps_saved_record_pending(self):
        self.analyze(True)
        for state in ('pending', 'resample'):
            form = self.all_pass()
            form['decisions']['panel_feedback'] = state
            form['notes']['panel_feedback'] = ''
            path, record = self.save(form)
            self.assertFalse(record['passed'])
            checked = baseline.validate_review(path, self.root)
            self.assertTrue(checked['valid'])
            self.assertFalse(checked['passed'])

    def test_incomplete_capture_cannot_pass_even_with_manual_all_pass(self):
        self.analyze(True)
        metadata_path = self.session / 'session.json'
        metadata = json.loads(metadata_path.read_text())
        metadata['status'] = 'cleanup_incomplete'
        metadata_path.write_text(json.dumps(metadata))
        self.report_dir, self.report = analysis.analyze_session(self.session, self.root / 'private_reports')
        with self.assertRaises(ValueError):
            self.save()

    def test_report_cannot_be_bound_to_other_session(self):
        self.analyze(True)
        second = demo.create_demo_sample(self.root / 'captures')
        with self.assertRaises(ValueError):
            baseline.save_review(self.report_dir, second, self.root, **self.all_pass())

    def test_path_traversal_and_external_paths_rejected(self):
        self.analyze(True)
        path, record = self.save()
        record['source']['session_dir'] = '../outside'
        self.assertFalse(baseline.validate_review(record, self.root)['valid'])
        record['source']['session_dir'] = str(self.session)
        self.assertFalse(baseline.validate_review(record, self.root)['valid'])
        external = self.root.parent / 'unrelated_report'
        with self.assertRaises(ValueError):
            baseline.save_review(external, self.session, self.root, **self.all_pass())

    def test_symlink_inputs_record_ancestor_and_save_folder_rejected(self):
        self.analyze(True)
        path, record = self.save()
        original = self.session / 'events.jsonl'
        saved = self.session / 'events.saved'
        original.rename(saved)
        original.symlink_to(saved)
        self.assertFalse(baseline.validate_review(path, self.root)['valid'])
        original.unlink()
        saved.rename(original)
        link = path.parent / 'review_link.json'
        link.symlink_to(path)
        self.assertFalse(baseline.load_review(link, self.root)['valid'])
        self.assertTrue(any(not row['valid'] for row in baseline.load_reviews(self.root)))
        linked_root = self.root / 'linked_root'
        linked_root.symlink_to(self.root, target_is_directory=True)
        self.assertFalse(baseline.validate_review(path, linked_root)['valid'])
        # Saving must reject a symlinked private destination as well.
        link.unlink()
        path.unlink()
        path.parent.rmdir()
        private = self.root / 'other_private'
        private.mkdir()
        (self.root / 'baseline_reviews').symlink_to(private, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.save()

    def test_changed_review_flags_cannot_grant_ha_or_synthetic_pass(self):
        self.analyze(True)
        _, record = self.save()
        for field in ('physical_feedback_verified', 'can_start_live_ha'):
            altered = copy.deepcopy(record)
            altered[field] = True
            self.assertFalse(baseline.validate_review(altered, self.root)['valid'])
        altered = copy.deepcopy(record)
        altered['assessment_version'] = 'older'
        self.assertFalse(baseline.validate_review(altered, self.root)['valid'])

    def test_record_bounded_plaintext_and_non_regular_input(self):
        self.analyze(True)
        form = self.all_pass()
        form['notes']['sample_quality'] = 'x' * 4001
        with self.assertRaises(ValueError):
            self.save(form)
        form = self.all_pass()
        form['reviewer_label'] = '\x00bad'
        with self.assertRaises(ValueError):
            self.save(form)
        source = self.session / 'events.jsonl'
        source.unlink()
        source.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.save()


if __name__ == '__main__':
    unittest.main()
