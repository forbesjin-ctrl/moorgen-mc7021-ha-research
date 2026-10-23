"""Post-capture analysis uses synthetic PCAP/events only; all I/O is local."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture as analysis
import demo_sample as demo
import offline_shcp as codec


def packet(index, seq, payload=b'', flags=24, when=None):
    return dict(packet_index=index, timestamp=float(index if when is None else when), src=demo.PHONE,
                dst=demo.HOST, sport=49152, dport=9000, transport='tcp', seq=seq,
                flags=flags, payload=payload)


class ReassemblyTests(unittest.TestCase):
    def setUp(self):
        self.frame = codec.build_candidate_light_frame(demo.DEVICE, True)

    def decode(self, packets):
        flows = analysis.split_flows(packets, demo.HOST)
        return flows, analysis.decode_flows(flows, ())

    def test_out_of_order_retransmission_and_fragmented_frame_have_one_result(self):
        packets = [packet(1, 100, flags=2), packet(2, 114, self.frame[13:]),
                   packet(3, 101, self.frame[:13]), packet(4, 101, self.frame[:13])]
        flows, frames = self.decode(packets)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]['command'], 'light-on')
        self.assertEqual(frames[0]['packet_indices'], [2, 3])
        self.assertTrue(any('去重' in x for x in flows[0]['issues']))

    def test_conflicting_overlap_fails_closed(self):
        flows, frames = self.decode([packet(1, 100, flags=2), packet(2, 101, self.frame), packet(3, 102, b'BAD')])
        self.assertEqual(frames, [])
        self.assertTrue(any('冲突' in x for x in flows[0]['issues']))

    def test_gap_never_joins_bytes_or_scans_later_valid_frame(self):
        flows, frames = self.decode([packet(1, 100, flags=2), packet(2, 101, self.frame[:10]),
                                    packet(3, 150, self.frame)])
        self.assertEqual(frames, [])
        self.assertTrue(any('缺口' in x for x in flows[0]['issues']))

    def test_midstream_previous_connection_is_separated_from_new_syn(self):
        flows, frames = self.decode([packet(1, 500, b'old opaque bytes'), packet(2, 100, flags=2),
                                    packet(3, 101, self.frame)])
        self.assertEqual(len(flows), 2)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]['flow_id'], flows[1]['id'])

    def test_syn_retransmission_does_not_create_new_generation(self):
        flows, frames = self.decode([packet(1, 100, flags=2), packet(2, 100, flags=2), packet(3, 101, self.frame)])
        self.assertEqual(len(flows), 1)
        self.assertEqual(len(frames), 1)

    def test_tcp_sequence_wrap_is_reassembled(self):
        start = 0xfffffff0
        _, frames = self.decode([packet(1, start - 1, flags=2), packet(2, start, self.frame[:20]),
                                packet(3, (start + 20) & 0xffffffff, self.frame[20:])])
        self.assertEqual(len(frames), 1)

    def test_initial_missing_tcp_bytes_are_not_silently_resynchronized(self):
        flows, frames = self.decode([packet(1, 100, flags=2), packet(2, 110, self.frame)])
        self.assertEqual(frames, [])
        self.assertTrue(any('起始数据缺失' in x for x in flows[0]['issues']))

    def test_udp_datagrams_are_never_joined(self):
        packets = [packet(1, 0, self.frame[:12]), packet(2, 0, self.frame[12:])]
        for item in packets:
            item.update(transport='udp', seq=None, flags=0)
        _, frames = self.decode(packets)
        self.assertEqual(frames, [])

    def test_tls_like_prefix_remains_opaque_and_no_scan(self):
        flows, frames = self.decode([packet(1, 1, b'\x16\x03\x03' + self.frame)])
        self.assertEqual(frames, [])
        self.assertIn('tls_like_not_decrypted', flows[0]['payload_classification'])

    def test_ack_and_execution_response_are_not_states_or_same_counter(self):
        raw = codec.build_frame(1, 4, 11, 1, []) + codec.build_frame(1, 4, 10, 1, [])
        _, frames = self.decode([packet(1, 100, raw, when=10)])
        window = dict(status='recorded', step='App开1', ready_at='1970-01-01T00:00:00+00:00',
                      window_end='1970-01-01T00:00:20+00:00', frame_indices=[])
        analysis.correlate([window], [], frames)
        self.assertEqual(window['ack_count'], 1)
        self.assertEqual(window['execution_response_count'], 1)
        self.assertEqual(window['state_count'], 0)

    def test_duplicate_device_records_are_counted_once_each(self):
        raw = codec.build_frame(1, 5, 12, 0, [(27,b'\x03'), (4,demo.DEVICE), (11,b'\x01'),
                                            (4,demo.DEVICE), (11,b'\x00')])
        item = packet(1, 100, raw)
        item.update(src=demo.HOST, dst=demo.PHONE)
        _, frames = self.decode([item])
        candidates = analysis.device_candidates(frames, [], ())
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['state_record_count'], 2)
        self.assertIsNone(frames[0]['states'][0]['candidate_is_on'])

    def test_ambiguous_state_does_not_fill_panel_or_reopen_evidence(self):
        raw = codec.build_frame(1,5,12,0,[(27,b'\x03'),(4,demo.DEVICE),(11,b'\x01')])
        item=packet(1,100,raw)
        item.update(src=demo.HOST,dst=demo.PHONE)
        _, frames=self.decode([item])
        frames[0]['event_association_ambiguous']=True
        windows=[dict(step=step,status='recorded',frame_indices=[1],command_count=0)
                 for step in ('面板开','面板关','重进App读状态')]
        candidate=analysis.device_candidates(frames,windows,())[0]
        self.assertEqual(candidate['state_record_count'],1)
        self.assertEqual(candidate['panel_state_windows'],[])
        self.assertEqual(candidate['reopen_state_windows'],[])


class SessionAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.session = demo.create_demo_sample(self.root / 'input')

    def change_metadata(self, **values):
        path = self.session / 'session.json'
        data = json.loads(path.read_text())
        data.update(values)
        path.write_text(json.dumps(data), encoding='utf-8')

    def analyze(self, **kwargs):
        return analysis.analyze_session(self.session, self.root / 'reports', **kwargs)

    def test_complete_synthetic_pipeline_has_evidence_but_never_ha_ready(self):
        destination, report = self.analyze(ordinary_ids=(demo.DEVICE,))
        self.assertEqual(report['summary']['frame_count'], 18)
        self.assertEqual(report['summary']['device_count'], 1)
        self.assertEqual(len(report['events']), 10)
        candidate = report['device_candidates'][0]
        self.assertTrue(candidate['repeated_command_candidate'])
        self.assertEqual(candidate['command_on_count'], 2)
        self.assertEqual(candidate['command_off_count'], 2)
        self.assertEqual(candidate['state_record_count'], 8)
        self.assertEqual(len(candidate['panel_state_windows']), 2)
        self.assertTrue(candidate['reopen_state_windows'])
        self.assertFalse(report['readiness']['can_start_live_ha'])
        self.assertFalse(candidate['physical_feedback_verified'])
        self.assertIn('合成', (destination/'报告.html').read_text())
        self.assertEqual({p.name for p in destination.iterdir()}, {'报告.html','report.json','匿名摘要.json','HA接入待验证.json'})

    def test_analysis_does_not_modify_inputs_and_sets_private_permissions(self):
        before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.session.iterdir()}
        destination, _ = self.analyze()
        self.assertEqual(before, {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.session.iterdir()})
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in destination.iterdir()))

    def test_missing_pcap_is_unknown_not_zero_or_fake_success(self):
        (self.session/'traffic.pcap').unlink()
        _, report = self.analyze()
        self.assertEqual(report['quality']['level'], 'blocked')
        self.assertIsNone(report['summary']['packet_count'])
        self.assertIsNone(analysis.anonymous_summary(report)['metrics']['packet_count'])

    def test_unsupported_pcapng_has_explicit_failure(self):
        (self.session/'traffic.pcap').write_bytes(b'\x0a\x0d\x0d\x0a' + b'\0'*24)
        _, report = self.analyze()
        self.assertIsNone(report['summary']['target_packet_count'])
        self.assertTrue(any('PCAPNG' in c['detail'] for c in report['quality']['checks']))

    def test_hash_mismatch_is_blocked_even_when_plaintext_decodes(self):
        self.change_metadata(pcap=dict(size_bytes=1,sha256='not-a-matching-hash'))
        _, report = self.analyze()
        self.assertEqual(report['quality']['level'], 'blocked')
        self.assertEqual(report['summary']['frame_count'], 18)

    def test_missing_core_steps_are_reported(self):
        path = self.session/'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [row for row in rows if row.get('step') == 'App开1']
        path.write_text('\n'.join(json.dumps(r) for r in rows), encoding='utf-8')
        _, report = self.analyze()
        check = next(c for c in report['quality']['checks'] if c['name'] == '单灯步骤覆盖')
        self.assertEqual(check['status'], 'warn')
        self.assertFalse(report['device_candidates'][0]['repeated_command_candidate'])

    def test_partial_step_is_not_recorded_as_complete(self):
        path = self.session/'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [row for row in rows if row.get('event') not in ('observation','step_finished')]
        path.write_text('\n'.join(json.dumps(r) for r in rows), encoding='utf-8')
        _, report = self.analyze()
        self.assertTrue(all(w['status'] == 'partial' for w in report['events']))
        self.assertEqual(report['quality']['level'], 'limited')

    def test_unaligned_events_are_not_assigned_to_packets(self):
        path = self.session/'events.jsonl'
        path.write_text(path.read_text().replace('2026-01-01','2026-01-02'),encoding='utf-8')
        _, report = self.analyze()
        self.assertTrue(all(not row['frame_indices'] for row in report['events']))
        self.assertEqual(next(c['status'] for c in report['quality']['checks'] if c['name']=='操作与报文时间对齐'), 'warn')

    def test_mixed_simulation_marker_is_rejected(self):
        self.change_metadata(simulation=False)
        _, report = self.analyze()
        self.assertEqual(report['quality']['level'], 'blocked')

    def test_device_type_is_not_inferred_from_command_or_name(self):
        _, report = self.analyze()
        self.assertTrue(all(state['candidate_is_on'] is None for f in report['frames'] for state in f['states']))
        self.assertTrue(all(not row['ordinary_light_verified'] for row in report['device_candidates']))

    def test_metadata_symlink_is_not_followed(self):
        path = self.session/'session.json'
        saved = path.read_bytes()
        path.unlink()
        outside=self.root/'outside.json'
        outside.write_bytes(saved)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'符号链接'):
            self.analyze()

    def test_anonymous_summary_only_has_safe_schema(self):
        _, report = self.analyze()
        report['source']['secret'] = 'do-not-copy'
        report['quality']['warnings'].append('do-not-copy')
        summary = analysis.anonymous_summary(report)
        text = json.dumps(summary)
        self.assertNotIn('do-not-copy',text)
        self.assertNotIn(demo.HOST,text)
        self.assertNotIn(demo.DEVICE.hex(),text)
        self.assertNotIn(str(self.session),text)
        self.assertEqual(summary['sample_kind'],'synthetic')
        self.assertFalse(summary['compatibility_verified'])

    def test_analyzer_and_fixture_never_invoke_network_or_processes(self):
        with mock.patch('socket.socket',side_effect=AssertionError('no network')), \
             mock.patch('subprocess.run',side_effect=AssertionError('no child process')), \
             mock.patch('subprocess.Popen',side_effect=AssertionError('no child process')):
            self.analyze()

    def test_bad_ordinary_identifier_is_never_filled_from_config_key(self):
        with self.assertRaisesRegex(ValueError,'8字节'):
            self.analyze(ordinary_ids=(b'\x12\x34',))


if __name__ == '__main__':
    unittest.main()
