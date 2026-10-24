"""Source-bound plans are offline explanations, never a live driver gate."""
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
import demo_sample as demo
import offline_shcp as codec
import sampling_gaps as gaps


class SamplingGapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for owner, name in ((socket, 'socket'), (socket, 'create_connection'),
                            (socket, 'getaddrinfo'), (subprocess, 'run'), (subprocess, 'Popen')):
            patcher = mock.patch.object(owner, name, side_effect=AssertionError('Offline only'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def sample(self, real=True, fresh=False):
        original = codec.build_frame
        def build(number, kind, link, serial, fields):
            return original(number, kind, link, serial + (100 if fresh else 0), fields)
        with mock.patch.object(codec, 'build_frame', side_effect=build):
            directory = demo.create_demo_sample(self.root / 'captures')
        path = directory / 'session.json'
        metadata = json.loads(path.read_text())
        metadata['simulation'] = not real
        metadata['target_context'] = dict(label='测试灯', room='测试房间', kind='ordinary_switch_light', collection_id='1' * 32)
        path.write_text(json.dumps(metadata), encoding='utf-8')
        path = directory / 'events.jsonl'
        path.write_text(''.join(json.dumps(dict(json.loads(line), simulation=not real)) + '\n'
            for line in path.read_text().splitlines()), encoding='utf-8')
        return directory

    def rewrite_metadata(self, directory, transform):
        path = directory / 'session.json'
        metadata = json.loads(path.read_text())
        transform(metadata)
        path.write_text(json.dumps(metadata), encoding='utf-8')

    def rewrite_pcap(self, directory, frames):
        sequence = {demo.PHONE: 1000, demo.HOST: 8000}
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for index, (src, payload) in enumerate(frames):
            flags = 2 if index == 0 and src == demo.PHONE else 24
            packet = demo.network_packet(src, demo.HOST if src == demo.PHONE else demo.PHONE,
                payload, sequence[src], flags)
            sequence[src] += len(payload) + bool(flags & 2)
            raw.extend(struct.pack('<IIII', 1767196811 + index, 0, len(packet), len(packet)))
            raw.extend(packet)
        (directory / 'traffic.pcap').write_bytes(raw)
        self.rewrite_metadata(directory, lambda metadata: metadata.update(pcap=dict(file='traffic.pcap',
            size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())))

    def plan(self, directory, **kwargs):
        return gaps.create_plan(directory, self.root, **kwargs)

    def task(self, record, identifier):
        return next(row for row in record['tasks'] if row['id'] == identifier)

    def assert_offline(self, record):
        self.assertEqual(record['machine_sufficiency'], 'not_proven')
        for key in ('online_ready', 'driver_generated', 'can_generate_live_driver',
                    'can_start_live_ha', 'physical_feedback_verified', 'executable_code',
                    'upload_performed', 'network_access_performed', 'credential_values_copied', 'raw_pcap_copied'):
            self.assertIs(record[key], False)
        self.assertEqual(record['bytes_sent'], 0)
        for row in record['tasks']:
            self.assertEqual(row['bytes_sent'], 0)
            if row['category'] != 'recapture' or row['status'] != 'needs_sample':
                self.assertFalse(row['capture_allowed'])

    def test_complete_real_declaration_is_not_driver_ready(self):
        directory = self.sample()
        path, record = self.plan(directory)
        self.assert_offline(record)
        self.assertEqual(record['target_ip'], demo.HOST)
        self.assertEqual(record['session_path'], str(directory.relative_to(self.root)))
        self.assertEqual(record['target_context']['label'], '测试灯')
        self.assertEqual(record['selected_identifier'], demo.DEVICE.hex())
        self.assertEqual(set(record['source_bindings']), {'session.json', 'events.jsonl', 'traffic.pcap', 'report.json'})
        self.assertEqual(self.task(record, 'repeated_switches')['status'], 'evidence_present_unverified')
        self.assertEqual(self.task(record, 'authentication_strategy')['status'], 'software_required')
        self.assertEqual(self.task(record, 'driver_integration')['status'], 'software_required')
        self.assertEqual(self.task(record, 'ha_acceptance')['status'], 'manual_required')
        self.assertEqual(self.task(record, 'independent_round')['status'], 'needs_sample')
        self.assertTrue(self.task(record, 'independent_round')['capture_allowed'])
        self.assertEqual(path.parent.parent, self.root / 'private_sampling_plans')
        self.assertEqual({p.name for p in path.parent.iterdir()}, {'plan.json', '补采与能力缺口.txt'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertIn('资料充分性尚未证明', (path.parent / '补采与能力缺口.txt').read_text())

    def test_synthetic_never_prepares_capture_or_ha(self):
        _, record = self.plan(self.sample(False))
        self.assertTrue(record['simulation'])
        self.assertTrue(all(not task['capture_allowed'] for task in record['tasks']))
        self.assert_offline(record)

    def test_two_independent_rounds_only_close_round_gap(self):
        _, record = self.plan(self.sample(), comparison_directory=self.sample(fresh=True))
        self.assertTrue(record['independent_second_round'])
        self.assertEqual(self.task(record, 'independent_round')['status'], 'evidence_present_unverified')
        self.assertEqual(self.task(record, 'connection_comparison')['status'], 'evidence_present_unverified')
        self.assertEqual(self.task(record, 'normal_session_start')['category'], 'software_support')
        self.assertFalse(self.task(record, 'normal_session_start')['capture_allowed'])
        self.assert_offline(record)

    def test_same_pcap_with_new_metadata_does_not_count_as_progress(self):
        first = self.sample()
        second = self.root / 'captures' / 'copy'
        shutil.copytree(first, second)
        self.rewrite_metadata(second, lambda value: value.update(script_version='different'))
        with self.assertRaisesRegex(ValueError, 'PCAP与第一轮相同'):
            self.plan(first, comparison_directory=second)

    def test_comparison_wrong_host_rejected(self):
        first, second = self.sample(), self.sample(fresh=True)
        self.rewrite_metadata(second, lambda value: value.update(target_ip='192.0.2.21'))
        with self.assertRaisesRegex(ValueError, '主机不同'):
            self.plan(first, comparison_directory=second)

    def test_comparison_other_full_identifier_is_not_same_light(self):
        first = self.sample()
        with mock.patch.object(demo, 'DEVICE', bytes.fromhex('1112131415161718')):
            second = self.sample(fresh=True)
        with self.assertRaisesRegex(ValueError, '完整标识未出现'):
            self.plan(first, comparison_directory=second)

    def test_guessed_partial_or_other_identifier_rejected(self):
        for identifier in ('01020304', '0102030405060709', 'not-a-device'):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.plan(self.sample(), selected_identifier=identifier)

    def test_zero_target_packets_are_not_normal(self):
        directory = self.sample()
        self.rewrite_pcap(directory, [])
        _, record = self.plan(directory)
        self.assertEqual(record['primary']['summary']['target_packet_count'], 0)
        self.assertEqual(self.task(record, 'target_traffic')['status'], 'needs_sample')
        self.assertEqual(self.task(record, 'opaque_transport')['status'], 'software_required')
        self.assertIsNone(record['selected_identifier'])
        self.assertTrue(all(not row['capture_allowed'] for row in record['tasks']))
        self.assertTrue(self.task(record, 'target_traffic')['capture_preparation_blockers'])
        self.assert_offline(record)

    def test_unlabeled_legacy_sample_can_be_analyzed_but_not_prepared(self):
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.pop('target_context'))
        _, record = self.plan(directory)
        self.assertIsNone(record['target_context'])
        self.assertEqual(record['selected_identifier'], demo.DEVICE.hex())
        self.assertEqual(record['selection_mode'], 'unique_repeated_candidate')
        self.assertTrue(all(not row['capture_allowed'] for row in record['tasks']))
        self.assertTrue(any('普通灯标签' in reason for reason in
            self.task(record, 'independent_round')['capture_preparation_blockers']))
        self.assert_offline(record)

    def test_absent_positive_and_boolean_drop_statistics_are_unknown_or_bad(self):
        for statistic in (None, 2, False, -1, '0'):
            directory = self.sample()
            self.rewrite_metadata(directory, lambda value: value['capture_stop']['stats'].update(dropped_by_kernel=statistic))
            _, record = self.plan(directory)
            self.assertEqual(self.task(record, 'capture_loss')['status'], 'needs_sample')
            self.assertTrue(self.task(record, 'capture_loss')['capture_allowed'])
            if statistic != 2:
                self.assertIsNone(record['primary']['dropped_by_kernel'])
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.pop('capture_stop'))
        _, record = self.plan(directory)
        self.assertEqual(self.task(record, 'capture_loss')['status'], 'needs_sample')

    def test_missing_auth_does_not_mean_no_auth(self):
        _, record = self.plan(self.sample())
        self.assertEqual(record['primary']['auth_field_shapes'], [])
        self.assertIsNone(record['primary']['authentication_required'])
        self.assertFalse(record['primary']['authentication_verified'])
        self.assertEqual(self.task(record, 'normal_session_start')['status'], 'needs_sample')
        self.assertIn('字段缺失不证明免认证', self.task(record, 'authentication_strategy')['why'])

    def test_auth_shapes_are_observations_without_credentials_or_success(self):
        directory = self.sample()
        secret = b'PRIVATE_AUTHENTICATION_VALUE'
        self.rewrite_pcap(directory, [(demo.PHONE, b''), (demo.PHONE,
            codec.build_frame(1, 2, 4, 1, [(93, secret), (160, secret)]))])
        path, record = self.plan(directory)
        self.assertEqual({row['field_id'] for row in record['primary']['auth_field_shapes']}, {93, 160})
        self.assertEqual(self.task(record, 'normal_session_start')['status'], 'evidence_present_unverified')
        self.assertEqual(self.task(record, 'authentication_strategy')['status'], 'software_required')
        self.assertIsNone(record['primary']['authentication_required'])
        text = path.read_text() + (path.parent / '补采与能力缺口.txt').read_text()
        self.assertNotIn(secret.decode(), text)
        self.assertNotIn(secret.hex(), text)
        self.assert_offline(record)

    def test_tls_bytes_are_software_gap_not_decryption_by_sampling(self):
        directory = self.sample()
        self.rewrite_pcap(directory, [(demo.PHONE, b''), (demo.PHONE,
            b'\x16\x03\x03' + codec.build_candidate_light_frame(demo.DEVICE, True))])
        _, record = self.plan(directory)
        task = self.task(record, 'opaque_transport')
        self.assertEqual(task['category'], 'software_support')
        self.assertEqual(task['status'], 'software_required')
        self.assertFalse(task['capture_allowed'])
        self.assertEqual(record['primary']['summary']['frame_count'], 0)
        for key in ('repeated_switches', 'panel_feedback', 'reopen_readback', 'normal_queries'):
            self.assertEqual(self.task(record, key)['category'], 'software_support')
            self.assertFalse(self.task(record, key)['capture_allowed'])
        self.assert_offline(record)

    def test_unknown_command_fields_require_software_support_not_more_of_same_capture(self):
        original = codec.build_frame
        def build(number, kind, link, serial, fields):
            fields = list(fields)
            if (kind, link) == (4, 9):
                fields.append((93, b'PRIVATE_UNKNOWN_FIELD'))
            return original(number, kind, link, serial, fields)
        with mock.patch.object(codec, 'build_frame', side_effect=build):
            directory = self.sample()
        path, record = self.plan(directory)
        self.assertTrue(record['primary']['unsupported_frame_indices'])
        self.assertEqual(self.task(record, 'codec_support')['status'], 'software_required')
        self.assertEqual(self.task(record, 'repeated_switches')['status'], 'software_required')
        self.assertFalse(self.task(record, 'repeated_switches')['capture_allowed'])
        self.assertNotIn(b'PRIVATE_UNKNOWN_FIELD'.hex(), path.read_text())
        self.assert_offline(record)

    def test_incomplete_session_requests_full_same_light_capture(self):
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.update(status='interrupted'))
        _, record = self.plan(directory)
        task = self.task(record, 'capture_complete')
        self.assertEqual(task['status'], 'needs_sample')
        self.assertIn('只操作同一组普通开关灯', ''.join(task['instructions']))
        self.assertIn('原App和面板正常操作', gaps.SCOPE)

    def test_missing_panel_observation_is_a_specific_gap(self):
        directory = self.sample()
        path = directory / 'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [row for row in rows if not (row.get('step') == '面板开' and row.get('event') == 'observation')]
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        _, record = self.plan(directory)
        self.assertEqual(self.task(record, 'event_coverage')['status'], 'needs_sample')
        self.assertEqual(self.task(record, 'panel_feedback')['status'], 'needs_sample')
        self.assertEqual(self.task(record, 'physical_mapping')['status'], 'manual_required')

    def test_metadata_declared_skip_cannot_be_hidden_by_complete_windows(self):
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.update(skipped_steps=['面板关']))
        _, record = self.plan(directory)
        self.assertEqual(self.task(record, 'event_coverage')['status'], 'needs_sample')

    def test_tcp_gap_is_a_transport_sample_gap(self):
        directory = self.sample()
        raw = bytearray((directory / 'traffic.pcap').read_bytes())
        position, phone_payloads = 24, 0
        while position < len(raw):
            length = struct.unpack_from('<I', raw, position + 8)[0]
            start = position + 16
            source_ip = bytes(raw[start + 12:start + 16])
            if source_ip == socket.inet_aton(demo.PHONE) and length > 40:
                phone_payloads += 1
                if phone_payloads == 2:
                    sequence = struct.unpack_from('!I', raw, start + 24)[0]
                    struct.pack_into('!I', raw, start + 24, sequence + 10000)
                    break
            position = start + length
        (directory / 'traffic.pcap').write_bytes(raw)
        self.rewrite_metadata(directory, lambda value: value.update(pcap=dict(file='traffic.pcap',
            size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())))
        _, record = self.plan(directory, selected_identifier=demo.DEVICE.hex())
        self.assertGreater(record['primary']['transport_issue_count'], 0)
        self.assertEqual(self.task(record, 'transport_integrity')['status'], 'needs_sample')
        self.assertTrue(self.task(record, 'transport_integrity')['capture_allowed'])
        self.assert_offline(record)

    def test_originals_outside_root_or_symlink_are_rejected(self):
        directory = self.sample()
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaisesRegex(ValueError, '数据目录内'):
                gaps.create_plan(directory, Path(other).resolve())
        copy = self.root / 'outside-pcap'
        shutil.copyfile(directory / 'traffic.pcap', copy)
        (directory / 'traffic.pcap').unlink()
        (directory / 'traffic.pcap').symlink_to(copy)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.plan(directory)

    def test_unsafe_output_directory_rejected(self):
        directory = self.sample()
        (self.root / 'private_sampling_plans').symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '符号链接'):
            self.plan(directory)
        self.assertFalse(list(directory.glob('plan_*')))

    def test_oversize_input_is_rejected_before_analysis(self):
        directory = self.sample()
        with mock.patch.dict(recipe.baseline.INPUT_LIMITS, {'events.jsonl': 2}):
            with self.assertRaisesRegex(ValueError, '超过上限'):
                self.plan(directory)

    def test_mid_analysis_original_change_prevents_saved_plan(self):
        directory = self.sample()
        original = gaps._source_summary
        def changed(source, identifier):
            value = original(source, identifier)
            self.rewrite_metadata(directory, lambda metadata: metadata.update(script_version='changed-during-plan'))
            return value
        with mock.patch.object(gaps, '_source_summary', side_effect=changed):
            with self.assertRaisesRegex(ValueError, '变化|哈希不同'):
                self.plan(directory)
        self.assertFalse((self.root / 'private_sampling_plans').exists())

    def test_modifying_old_plan_does_not_unlock_recomputed_plan(self):
        directory = self.sample()
        path, record = self.plan(directory)
        record.update(online_ready=True, driver_generated=True, machine_sufficiency='proven')
        for task in record['tasks']:
            task.update(status='pass', capture_allowed=True)
        path.write_text(json.dumps(record), encoding='utf-8')
        _, new = self.plan(directory)
        self.assert_offline(new)
        self.assertEqual(self.task(new, 'driver_integration')['status'], 'software_required')

    def test_invalid_target_context_and_unknown_source_are_rejected(self):
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.update(target_context=dict(label='unsafe\nname')))
        with self.assertRaises(ValueError):
            self.plan(directory)
        directory = self.sample()
        self.rewrite_metadata(directory, lambda value: value.update(simulation=0))
        with self.assertRaises(ValueError):
            self.plan(directory)

    def test_task_text_chinese_status_uses_actual_reference_values(self):
        _, record = self.plan(self.sample())
        text = gaps.render_task_text(record, 'target_traffic')
        self.assertIn('当前状态：已有线索，未验证', text)
        self.assertIn('第一轮 · 指定主机相关包数：' + str(record['primary']['summary']['target_packet_count']), text)
        self.assertIn('操作重点：', text)
        self.assertIn('下一步期待的证据：', text)
        self.assertIn('不上传、不发包、不生成驱动', text)
        self.assertNotIn('summary.target_packet_count', text)
        self.assertIn('这是软件能力缺口，不提供补采准备按钮',
            gaps.render_task_text(record, 'authentication_strategy'))
        self.assertIn('这是人工核对项，不提供补采准备按钮',
            gaps.render_task_text(record, 'physical_mapping'))

    def test_task_text_unknown_id_fails_without_file_or_network_access(self):
        _, record = self.plan(self.sample())
        with self.assertRaisesRegex(ValueError, '没有这个'):
            gaps.render_task_text(record, '../../traffic.pcap')

    def test_task_text_projects_only_auth_shape_keys_not_payload_or_arbitrary_path(self):
        _, record = self.plan(self.sample())
        secret = 'PRIVATE_AUTHENTICATION_VALUE'
        record['primary']['auth_field_shapes'] = [dict(frame_index=7, flow_id='flow-2',
            direction='to_host', field_id=93, length=28, value=secret,
            value_hex=secret.encode().hex(), token=secret)]
        record['primary']['credential'] = secret
        task = self.task(record, 'authentication_strategy')
        task['evidence_refs'].extend([dict(round='primary', field='credential'),
            dict(round='primary', field='auth_field_shapes.0.value_hex'),
            dict(round='primary', field=['bad', secret])])
        text = gaps.render_task_text(record, 'authentication_strategy')
        self.assertIn('字段ID', text)
        self.assertIn('93', text)
        self.assertIn('字段长度', text)
        self.assertIn('28', text)
        self.assertNotIn(secret, text)
        self.assertNotIn(secret.encode().hex(), text)
        self.assertIn('不显示未列入白名单的字段', text)

    def test_task_text_large_reference_is_explicitly_truncated(self):
        _, record = self.plan(self.sample())
        record['primary']['candidate_frame_indices'] = list(range(1, 5001))
        text = gaps.render_task_text(record, 'target_selection')
        line = next(line for line in text.splitlines() if '候选帧号：' in line)
        payload = line.split('候选帧号：', 1)[1]
        self.assertIn('已截断', payload)
        self.assertLessEqual(len(payload.split('…〔已截断', 1)[0]), 1500)

    def test_task_text_session_tuple_and_hash_show_fixed_summary_values(self):
        _, record = self.plan(self.sample())
        record['primary']['session_protocol_timeline'] = [dict(frame_index=4, flow_id='flow-1',
            direction='to_host', protocol_number=1, protocol_type=2, link_code=4, payload='PRIVATE')]
        text = gaps.render_task_text(record, 'normal_session_start')
        self.assertIn('协议三元组', text)
        self.assertIn('[1, 2, 4]', text)
        self.assertNotIn('PRIVATE', text)
        text = gaps.render_task_text(record, 'independent_round')
        self.assertIn(record['primary']['source_bindings']['traffic.pcap']['sha256'], text)


if __name__ == '__main__':
    unittest.main()
