"""Offline tests: every system-tool boundary is mocked; no RVI or packet capture.

The fake lifecycle files live only in TemporaryDirectory. Public/private IP
examples identify no device; subprocess is forbidden throughout demo tests.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('capture_mc7021_light', ROOT / 'tools/capture_mc7021_light.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
UDID = '00000001-0000000000000001'
OTHER_UDID = '1111111111111111111111111111111111111111'
IP = '192.0.2.20'
COLLECTION_ID = '00000000-0000-4000-8000-000000000001'


def target_context(**changes):
    value = dict(label='演练灯一', room='演练房间', kind='ordinary_switch_light',
                 collection_id=COLLECTION_ID)
    value.update(changes)
    return value


class InputValidationTests(unittest.TestCase):
    def test_single_literal_addresses_are_normalized(self):
        self.assertEqual(capture.validate_ip(' 192.0.2.20 '), IP)
        self.assertEqual(capture.validate_ip('2001:db8::0042'), '2001:db8::42')
        self.assertEqual(capture.validate_ip('::ffff:192.0.2.20'), IP)

    def test_domains_subnets_ports_and_injection_are_rejected(self):
        for value in ['host.local', '192.0.2.20/24', '192.0.2.20:9000',
                      '192.0.2.20;touch /tmp/unsafe', '$(id)', '`id`',
                      '192.0.2.20 or host 198.51.100.1', '-i en0', '',
                      '[2001:db8::42]', 'fe80::42%en0']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_ip(value)

    def test_non_unicast_addresses_are_rejected_including_ipv4_mapped(self):
        for value in ['0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255',
                      '::', '::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:224.0.0.1']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_ip(value)

    def test_udid_formats_and_trimming(self):
        for value in [UDID, OTHER_UDID, OTHER_UDID.upper()]:
            with self.subTest(value=value):
                self.assertEqual(capture.validate_udid(' ' + value + '\n'), value)

    def test_udid_injection_whitespace_nonhex_and_zero_are_rejected(self):
        for value in ['', '0' * 40, '00000000-0000000000000000',
                      UDID + ';id', UDID + '\n' + OTHER_UDID, '--help',
                      '../' + UDID, 'g' * 40, '1234', UDID.replace('-', ' ')]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_udid(value)

    def test_filter_has_one_literal_host_tcp_udp_no_port_restriction(self):
        self.assertEqual(capture.capture_filter(IP), 'host 192.0.2.20 and (tcp or udp)')
        self.assertEqual(capture.capture_filter('2001:db8::42'), 'host 2001:db8::42 and (tcp or udp)')
        with self.assertRaises(ValueError):
            capture.capture_filter('192.0.2.20 or host 198.51.100.1')


class TargetContextValidationTests(unittest.TestCase):
    def test_legacy_absence_does_not_create_labels_or_collection(self):
        self.assertIsNone(capture.validate_target_context(None))
        with mock.patch.object(capture.uuid, 'uuid4', side_effect=AssertionError('no grouping requested')):
            self.assertIsNone(capture.build_target_context())

    def test_exact_private_values_are_preserved_and_copied(self):
        original = target_context(label='  演练灯一  ', room='',
            collection_id='ABCDEF01020304050607080910111213')
        result = capture.validate_target_context(original)
        self.assertEqual(result, original)
        self.assertIsNot(result, original)
        original['label'] = '后续修改'
        self.assertEqual(result['label'], '  演练灯一  ')

    def test_missing_extra_and_non_mapping_fields_are_rejected(self):
        for value in [[], '', False, {}, target_context(device_id='0001')]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_target_context(value)
        for key in target_context():
            value = target_context()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                capture.validate_target_context(value)

    def test_label_room_bounds_types_and_control_characters(self):
        self.assertEqual(capture.validate_target_context(target_context(label='灯' * 80, room='室' * 80))['room'], '室' * 80)
        for key, values in [('label', ['', ' ' * 3, '灯' * 81, None, 1, True]),
                            ('room', ['室' * 81, None, 1, False])]:
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    capture.validate_target_context(target_context(**{key: value}))
        for key in ('label', 'room'):
            for char in ['\x00', '\t', '\r', '\n', '\x7f', '\x85', '\u200b', '\u202e', '\u2028', '\u2029', '\ud800']:
                with self.subTest(key=key, char=repr(char)), self.assertRaises(ValueError):
                    capture.validate_target_context(target_context(**{key: '演练' + char}))

    def test_only_owner_declared_ordinary_light_kind_is_accepted(self):
        for kind in ['verified_light', 'curtain', 'ordinary_switch_light ', '', None, True]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                capture.validate_target_context(target_context(kind=kind))

    def test_collection_id_is_uuid_or_32_hex_and_never_an_online_address(self):
        for value in [COLLECTION_ID, COLLECTION_ID.upper(), '0' * 32, 'abcdef0123456789' * 2]:
            with self.subTest(value=value):
                self.assertEqual(capture.validate_target_context(target_context(collection_id=value))['collection_id'], value)
        for value in ['192.0.2.20', '0001', 'g' * 32, '0' * 31, '0' * 33,
                      '{' + COLLECTION_ID + '}', 'urn:uuid:' + COLLECTION_ID,
                      COLLECTION_ID + '\n', None, 1, True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                capture.validate_target_context(target_context(collection_id=value))

    def test_builder_requires_label_and_only_fills_optional_defaults(self):
        with mock.patch.object(capture.uuid, 'uuid4') as identifier:
            identifier.return_value.hex = '0' * 31 + '1'
            self.assertEqual(capture.build_target_context('演练灯一'), target_context(
                room='', collection_id='0' * 31 + '1'))
            identifier.assert_called_once_with()
        self.assertEqual(capture.build_target_context('演练灯一', '演练房间', COLLECTION_ID), target_context())
        for kwargs in [dict(room='演练房间'), dict(collection_id=COLLECTION_ID),
                       dict(room='', collection_id=COLLECTION_ID)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                capture.build_target_context(**kwargs)


class RVIParserTests(unittest.TestCase):
    def test_recognized_empty_list(self):
        self.assertEqual(capture.parse_rvi_list('Current Active Devices:\n'), [])
        self.assertEqual(capture.parse_rvi_list('No devices found.\n'), [])

    def test_multiple_existing_interfaces(self):
        text = 'Current Active Devices:\n[1] {} (rvi3)\n[2] {} (rvi5)\n'.format(UDID, OTHER_UDID)
        self.assertEqual(capture.parse_rvi_list(text), [(UDID, 'rvi3'), (OTHER_UDID, 'rvi5')])

    def test_unknown_or_error_output_does_not_mean_no_interfaces(self):
        for value in ['', 'error: permission denied', 'Current Active Devices:\nunknown row',
                      'Current Active Devices:\n[1] {} (en0)'.format(UDID)]:
            with self.subTest(value=value), self.assertRaises(capture.CaptureError):
                capture.parse_rvi_list(value)

    def test_duplicate_udid_is_ambiguous_even_with_different_case(self):
        text = '[1] {} (rvi0)\n[2] {} (rvi1)'.format(OTHER_UDID, OTHER_UDID.upper())
        with self.assertRaises(capture.CaptureError):
            capture.parse_rvi_list(text)

    def test_creation_requires_unique_success_for_exact_udid(self):
        text = 'Starting device {} [SUCCEEDED] with interface rvi12'.format(UDID)
        self.assertEqual(capture.parse_created_rvi(text, UDID), 'rvi12')
        for bad in [text.replace(UDID, OTHER_UDID), text.replace('SUCCEEDED', 'FAILED'),
                    text.replace('rvi12', 'en0'), text + '\n' + text, '']:
            with self.subTest(text=bad), self.assertRaises(capture.CaptureError):
                capture.parse_created_rvi(bad, UDID)

    def test_capture_stats_do_not_invent_missing_zero(self):
        parsed = capture.parse_capture_stats('listening on rvi0\n0 packets captured\n2 packets received by filter\n1 packet dropped by kernel\n')
        self.assertEqual(parsed, {'captured': 0, 'received_by_filter': 2, 'dropped_by_kernel': 1})
        self.assertIsNone(capture.parse_capture_stats('permission denied')['captured'])


class FakeCapture:
    def __init__(self, *, startup_error=None, check_error=None, stop_result=None):
        self.startup_error = startup_error
        self.check_error = check_error
        self.stop_result = stop_result or dict(graceful=True, still_running=False, process_exit=0,
            stats=dict(captured=4, received_by_filter=4, dropped_by_kernel=0))
        self.stopped = 0

    def wait_ready(self, timeout=12):
        if self.startup_error:
            raise self.startup_error

    def check(self):
        if self.check_error:
            raise self.check_error

    def stop(self):
        self.stopped += 1
        return self.stop_result


class FakeBackend:
    simulated = False

    def __init__(self, *, existing=(), tool_capture=None, creation=None, remove_error=None,
                 write_mock_pcap=True):
        self.existing = existing
        self.capture = tool_capture or FakeCapture()
        self.creation = creation or (True, 'Starting device {} [SUCCEEDED] with interface rvi2'.format(UDID), 0)
        self.remove_error = remove_error
        self.write_mock_pcap = write_mock_pcap
        self.calls = []

    def prepare(self):
        self.calls.append(('prepare',))

    def list_rvis(self):
        self.calls.append(('list',))
        return self.existing

    def authorize(self):
        self.calls.append(('authorize',))

    def create_rvi(self, udid):
        self.calls.append(('create', udid))
        return self.creation

    def remove_rvi(self, udid):
        self.calls.append(('remove', udid))
        if self.remove_error:
            raise self.remove_error

    def start_capture(self, ip, interface, directory):
        self.calls.append(('capture', ip, interface))
        if self.write_mock_pcap:
            # Header only, no packets. Confined to TemporaryDirectory; never a
            # user-facing capture and never produced by the real backend.
            (directory / 'traffic.pcap').write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        return self.capture


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def session(self, backend=None, input_fn=lambda _: '', **kwargs):
        backend = backend or FakeBackend()
        journal = capture.Journal(self.parent, backend.simulated)
        session = capture.GuidedSession(IP, UDID, journal, backend, input_fn=input_fn,
            sleep_fn=lambda _: None, **kwargs)
        return session, backend

    def run_short(self, session):
        def short_flow():
            session.metadata['flow_completed'] = True
        session.flow = short_flow
        result = session.run()
        saved = json.loads((session.journal.directory / 'session.json').read_text())
        self.assertEqual(result, saved)
        return result

    def test_journal_initialization_and_immediate_durable_event(self):
        journal = capture.Journal(self.parent, True)
        try:
            journal.record('offline_test', detail='观察')
            rows = [json.loads(line) for line in (journal.directory / 'events.jsonl').read_text().splitlines()]
            self.assertEqual(rows[-1]['event'], 'offline_test')
            self.assertTrue(all(row['simulation'] for row in rows))
            self.assertTrue(rows[-1]['timestamp'].endswith('+08:00'))
        finally:
            journal.close()

    def test_context_is_private_declared_metadata_and_not_verified_identity(self):
        supplied = target_context()
        session, backend = self.session(target_context=supplied)
        supplied['label'] = '不应改变已存记录'
        result = self.run_short(session)
        self.assertEqual(result['target_context'], target_context())
        self.assertFalse(result['project_household_verified'])
        self.assertFalse(result['runtime_compatibility_verified'])
        rows = session.journal.rows
        self.assertNotIn('target_context', rows[0])
        declared = [row for row in rows if row['event'] == 'target_context_declared']
        self.assertEqual(len(declared), 1)
        self.assertEqual(declared[0]['target_context'], target_context())
        self.assertFalse(declared[0]['device_identity_verified'])
        self.assertFalse(declared[0]['device_type_verified'])
        self.assertIn('not protocol identity', declared[0]['evidence'])
        self.assertEqual([row for row in backend.calls if row[0] == 'capture'], [('capture', IP, 'rvi2')])

    def test_legacy_session_and_event_shape_remain_unlabeled(self):
        session, _ = self.session(capture.DemoBackend())
        result = self.run_short(session)
        self.assertNotIn('target_context', result)
        self.assertFalse(any(row['event'] == 'target_context_declared' for row in session.journal.rows))

    def test_invalid_context_cannot_reach_backend_or_summary_creation(self):
        backend = FakeBackend()
        journal = capture.Journal(self.parent, False)
        try:
            with self.assertRaises(ValueError):
                capture.GuidedSession(IP, UDID, journal, backend, target_context=target_context(kind='curtain'))
            self.assertEqual(backend.calls, [])
            self.assertFalse((journal.directory / 'session.json').exists())
        finally:
            journal.close()

    def test_separate_lights_share_only_local_collection_and_keep_distinct_sessions(self):
        results = []
        directories = []
        with mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('tool forbidden')), \
             mock.patch.object(capture.subprocess, 'Popen', side_effect=AssertionError('tool forbidden')):
            for label in ['演练灯一', '演练灯二']:
                session, _ = self.session(capture.DemoBackend(), target_context=target_context(label=label))
                results.append(self.run_short(session))
                directories.append(session.journal.directory)
        self.assertNotEqual(*directories)
        self.assertEqual([value['target_context']['label'] for value in results], ['演练灯一', '演练灯二'])
        self.assertEqual({value['target_context']['collection_id'] for value in results}, {COLLECTION_ID})
        self.assertTrue(all(value['target_ip'] == IP for value in results))
        self.assertTrue(all(not (directory / 'traffic.pcap').exists() for directory in directories))

    def test_existing_target_rvi_is_never_authorized_created_or_deleted(self):
        session, backend = self.session(FakeBackend(existing=[(UDID.lower(), 'rvi8')]))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['rvi_owned_by_this_session'])
        self.assertEqual(backend.calls, [('prepare',), ('list',)])

    def test_target_rvi_appearing_during_sudo_prompt_is_preserved(self):
        session, backend = self.session()
        backend.list_rvis = mock.Mock(side_effect=[[], [(UDID, 'rvi7')]])
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['rvi_owned_by_this_session'])
        self.assertFalse(any(row[0] in ('create', 'capture', 'remove') for row in backend.calls))

    def test_other_phone_existing_rvi_is_untouched(self):
        session, backend = self.session(FakeBackend(existing=[(OTHER_UDID, 'rvi9')]))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([row for row in backend.calls if row[0] == 'remove'], [('remove', UDID)])

    def test_successful_owned_interface_cleanup(self):
        session, backend = self.session()
        result = self.run_short(session)
        self.assertTrue(result['rvi_owned_by_this_session'])
        self.assertEqual(result['rvi_cleanup'], 'removed')
        self.assertEqual(backend.capture.stopped, 1)

    def test_creation_failed_never_deletes_interface(self):
        backend = FakeBackend(creation=(False, 'Starting device {} [FAILED]'.format(UDID), 1))
        session, backend = self.session(backend)
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['rvi_cleanup'], 'not_created')
        self.assertFalse(any(row[0] in ('capture', 'remove') for row in backend.calls))

    def test_success_followed_by_unknown_interface_still_cleans_owned_rvi(self):
        backend = FakeBackend(creation=(True, 'Starting device {} [SUCCEEDED] with unknown format'.format(UDID), 0))
        session, backend = self.session(backend)
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['rvi_cleanup'], 'removed')
        self.assertFalse(any(row[0] == 'capture' for row in backend.calls))

    def test_success_but_nonzero_exit_cleans_owned_rvi(self):
        backend = FakeBackend(creation=(True, 'Starting device {} [SUCCEEDED] with interface rvi2'.format(UDID), 1))
        session, backend = self.session(backend)
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['rvi_cleanup'], 'removed')

    def test_creation_timeout_without_proven_ownership_never_removes_unknown_interface(self):
        session, backend = self.session(FakeBackend(creation=(False, '', -2)))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'cleanup_incomplete')
        self.assertEqual(result['rvi_cleanup'], 'ownership_unknown')
        self.assertFalse(any(row[0] in ('capture', 'remove') for row in backend.calls))

    def test_creation_timeout_after_proven_success_cleans_owned_interface(self):
        text = 'Starting device {} [SUCCEEDED] with interface rvi2'.format(UDID)
        session, backend = self.session(FakeBackend(creation=(True, text, -2)))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['rvi_cleanup'], 'removed')

    def test_capture_startup_failure_prevents_guided_actions_but_saves_cleanup(self):
        session, backend = self.session(FakeBackend(tool_capture=FakeCapture(startup_error=capture.CaptureError('not listening'))))
        session.flow = mock.Mock()
        result = session.run()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['flow_completed'])
        self.assertFalse(result['capture_ready'])
        self.assertFalse(result['household_live_validation_performed'])
        self.assertEqual(result['rvi_cleanup'], 'removed')
        session.flow.assert_not_called()

    def test_user_quit_preserves_partial_events(self):
        session, _ = self.session(input_fn=lambda _: 'q')
        session.flow = lambda: session.action('测试动作', '不会执行真实动作')
        result = session.run()
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['stop_reason'], 'user_q')
        self.assertFalse(result['flow_completed'])
        self.assertEqual(result['rvi_cleanup'], 'removed')
        text = (session.journal.directory / 'events.jsonl').read_text()
        self.assertIn('stop_requested', text)
        self.assertIn('session_finished', text)

    def test_terminal_eof_is_saved_as_incomplete(self):
        def eof(_):
            raise EOFError
        session, _ = self.session(input_fn=eof)
        session.flow = lambda: session.ask('test')
        result = session.run()
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['stop_reason'], 'terminal_EOF')
        self.assertFalse(result['flow_completed'])

    def test_capture_disappearing_mid_flow_stops_actions(self):
        session, _ = self.session(FakeBackend(tool_capture=FakeCapture(check_error=capture.CaptureError('USB disconnected'))))
        session.flow = lambda: session.ask('test')
        result = session.run()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['flow_completed'])
        self.assertEqual(result['rvi_cleanup'], 'removed')

    def test_zero_packets_is_explicit_not_claimed_successful_protocol_validation(self):
        tool = FakeCapture(stop_result=dict(graceful=True, still_running=False, process_exit=0,
            stats=dict(captured=0, received_by_filter=0, dropped_by_kernel=0)))
        session, _ = self.session(FakeBackend(tool_capture=tool))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'completed_no_packets')
        self.assertFalse(result['runtime_compatibility_verified'])
        self.assertEqual(result['endpoint_probes_sent'], 0)
        self.assertEqual(result['device_configuration_writes'], 0)
        self.assertEqual(result['household_control_commands_sent'], 0)

    def test_nonzero_capture_exit_is_failure(self):
        session, _ = self.session(FakeBackend(tool_capture=FakeCapture(stop_result=dict(
            graceful=True, still_running=False, process_exit=1, stats=dict(captured=0)))))
        self.assertEqual(self.run_short(session)['status'], 'capture_failed')

    def test_no_file_on_otherwise_completed_capture_is_explicit(self):
        session, _ = self.session(FakeBackend(write_mock_pcap=False))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'capture_missing')
        self.assertNotIn('pcap', result)

    def test_missing_file_must_not_mask_running_capture_cleanup_risk(self):
        backend = FakeBackend(write_mock_pcap=False, tool_capture=FakeCapture(stop_result=dict(
            graceful=False, still_running=True, process_exit=None, stats={})))
        session, _ = self.session(backend)
        result = self.run_short(session)
        self.assertEqual(result['status'], 'cleanup_incomplete')
        self.assertEqual(result['rvi_cleanup'], 'deferred_capture_still_running')
        self.assertFalse(any(row[0] == 'remove' for row in backend.calls))

    def test_missing_stats_are_preserved_as_unknown(self):
        tool = FakeCapture(stop_result=dict(graceful=True, still_running=False, process_exit=0,
            stats=dict(captured=None, received_by_filter=None, dropped_by_kernel=None)))
        session, _ = self.session(FakeBackend(tool_capture=tool))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'completed_stats_unknown')

    def test_dropped_packets_are_retained_as_material_sample_limit(self):
        tool = FakeCapture(stop_result=dict(graceful=True, still_running=False, process_exit=0,
            stats=dict(captured=12, received_by_filter=20, dropped_by_kernel=8)))
        session, _ = self.session(FakeBackend(tool_capture=tool))
        result = self.run_short(session)
        self.assertTrue(result['packet_loss_observed'])
        self.assertEqual(result['capture_stop']['stats']['dropped_by_kernel'], 8)

    def test_still_running_capture_is_cleanup_incomplete(self):
        session, _ = self.session(FakeBackend(tool_capture=FakeCapture(stop_result=dict(
            graceful=False, still_running=True, process_exit=None, stats=dict(captured=1)))))
        self.assertEqual(self.run_short(session)['status'], 'cleanup_incomplete')

    def test_rvi_cleanup_failure_is_explicit_and_saved(self):
        session, _ = self.session(FakeBackend(remove_error=capture.CaptureError('cleanup failed')))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'cleanup_incomplete')
        self.assertEqual(result['rvi_cleanup'], 'failed')
        self.assertIn('cleanup failed', result['rvi_cleanup_error'])

    def test_stop_exception_still_saves_and_defers_rvi_removal(self):
        tool = FakeCapture()
        tool.stop = mock.Mock(side_effect=RuntimeError('stop mocked failure'))
        session, backend = self.session(FakeBackend(tool_capture=tool))
        result = self.run_short(session)
        self.assertEqual(result['status'], 'cleanup_incomplete')
        self.assertEqual(result['rvi_cleanup'], 'deferred_capture_still_running')
        self.assertIn('stop mocked failure', result['capture_stop']['stop_error'])
        self.assertFalse(any(row[0] == 'remove' for row in backend.calls))

    def test_eof_with_zero_packets_does_not_become_completed(self):
        tool = FakeCapture(stop_result=dict(graceful=True, still_running=False, process_exit=0,
            stats=dict(captured=0, received_by_filter=0, dropped_by_kernel=0)))
        def eof(_):
            raise EOFError
        session, _ = self.session(FakeBackend(tool_capture=tool), input_fn=eof)
        session.flow = lambda: session.ask('offline test')
        result = session.run()
        self.assertEqual(result['status'], 'interrupted')
        self.assertFalse(result['flow_completed'])

    def test_signal_after_capture_start_is_saved_as_interrupted(self):
        session, _ = self.session()
        session.flow = lambda: session.signal_handler(signal.SIGHUP, None)
        result = session.run()
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['stop_reason'], 'signal_SIGHUP')
        self.assertEqual(result['rvi_cleanup'], 'removed')

    def test_signal_during_capture_constructor_does_not_lose_process_handle(self):
        session, backend = self.session()
        original = backend.start_capture
        def interrupted_start(ip, interface, directory):
            session.signal_handler(signal.SIGTERM, None)
            return original(ip, interface, directory)
        backend.start_capture = interrupted_start
        result = self.run_short(session)
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['stop_reason'], 'signal_SIGTERM')
        self.assertEqual(backend.capture.stopped, 1)
        self.assertEqual(result['rvi_cleanup'], 'removed')
        self.assertFalse(result['capture_ready'])

    def test_event_write_failure_during_finish_does_not_prevent_owned_rvi_cleanup(self):
        session, backend = self.session()
        original = session.journal.record
        def partial_disk_failure(kind, **values):
            if kind == 'capture_stopped':
                raise OSError('mock disk full')
            return original(kind, **values)
        session.journal.record = partial_disk_failure
        result = self.run_short(session)
        self.assertEqual(result['status'], 'save_incomplete')
        self.assertEqual(result['rvi_cleanup'], 'removed')
        self.assertIn('mock disk full', result['persistence_errors'])
        self.assertIn(('remove', UDID), backend.calls)

    def test_final_summary_write_failure_cannot_report_completed(self):
        for backend in (FakeBackend(), capture.DemoBackend()):
            with self.subTest(simulation=backend.simulated):
                session, backend = self.session(backend)
                initial = json.loads((session.journal.directory / 'session.json').read_text())
                self.assertEqual(initial['status'], 'preparing')
                original = session.journal.save_summary
                saved_statuses = []
                def fail_final_summary(data):
                    if 'ended_at' in data:
                        raise OSError('mock final summary disk failure')
                    saved_statuses.append(data['status'])
                    return original(data)
                session.journal.save_summary = fail_final_summary
                def short_flow():
                    session.metadata['flow_completed'] = True
                session.flow = short_flow
                result = session.run()
                self.assertEqual(saved_statuses, ['preparing', 'capturing'])
                self.assertEqual(result['status'], 'save_incomplete')
                self.assertFalse(result['save_complete'])
                self.assertEqual(result['rvi_cleanup'], 'removed')
                self.assertIn('mock final summary disk failure', result['summary_write_error'])
                events = [json.loads(line) for line in
                          (session.journal.directory / 'events.jsonl').read_text().splitlines()]
                failure = next(row for row in events if row['event'] == 'summary_write_failed')
                self.assertEqual(failure['status'], 'save_incomplete')
                self.assertIn('mock final summary disk failure', failure['error'])
                if isinstance(backend, FakeBackend):
                    self.assertEqual(backend.calls.count(('remove', UDID)), 1)

    def test_finish_is_idempotent(self):
        session, backend = self.session()
        result = self.run_short(session)
        before = (session.journal.directory / 'events.jsonl').read_bytes()
        session.finish()
        self.assertEqual(backend.capture.stopped, 1)
        self.assertEqual(backend.calls.count(('remove', UDID)), 1)
        self.assertEqual((session.journal.directory / 'events.jsonl').read_bytes(), before)
        self.assertEqual(result['status'], 'completed')

    def test_simultaneous_same_udid_tool_copy_cannot_take_ownership(self):
        first, first_backend = self.session()
        second, second_backend = self.session()
        second_result = []
        def first_flow():
            second_result.append(second.run())
            first.metadata['flow_completed'] = True
        first.flow = first_flow
        first_result = first.run()
        self.assertEqual(first_result['status'], 'completed')
        self.assertEqual(second_result[0]['status'], 'failed')
        self.assertFalse(second_result[0]['rvi_owned_by_this_session'])
        self.assertEqual(second_backend.calls, [('prepare',)])
        self.assertEqual(first_backend.calls.count(('remove', UDID)), 1)

    def test_summary_hash_is_of_saved_file_and_is_local_only(self):
        import hashlib
        session, _ = self.session()
        result = self.run_short(session)
        data = (session.journal.directory / 'traffic.pcap').read_bytes()
        self.assertEqual(result['pcap']['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['pcap']['size_bytes'], len(data))

    def test_sigint_during_ownership_call_is_deferred_until_owned_saved(self):
        session, backend = self.session()
        original = backend.create_rvi
        def interrupted_creation(udid):
            session.signal_handler(signal.SIGINT, None)
            return original(udid)
        backend.create_rvi = interrupted_creation
        result = self.run_short(session)
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['stop_reason'], 'signal_SIGINT')
        self.assertEqual(result['rvi_cleanup'], 'removed')
        self.assertFalse(any(row[0] == 'capture' for row in backend.calls))

    def test_action_interval_observation_and_skip_are_distinct(self):
        replies = iter(['', '', '1', '2', '2', 's', '', 's'])
        session, _ = self.session(capture.DemoBackend(), input_fn=lambda _: next(replies))
        def flow():
            session.action('面板开', '离线动作', seconds=0, update=True)
            session.action('跳过动作', '离线跳过', seconds=0)
            session.action('准备后未做', '离线未做', seconds=0)
            session.metadata['flow_completed'] = True
        session.flow = flow
        result = session.run()
        rows = session.journal.rows
        confirmed = next(row for row in rows if row['event'] == 'action_confirmed')
        self.assertTrue(confirmed['exact_action_time_unknown'])
        self.assertIn('ready_at', confirmed)
        observation = next(row for row in rows if row['event'] == 'observation')
        self.assertEqual(observation['physical_light'], 'on')
        self.assertEqual(observation['app_display'], 'off')
        self.assertEqual(observation['update_observed'], 'no')
        self.assertIn('not protocol-decoded', observation['evidence'])
        skipped = [row for row in rows if row['event'] in ('step_skipped', 'action_not_executed')]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all(row['executed'] is False for row in skipped))
        self.assertEqual(result['skipped_steps'], ['跳过动作', '准备后未做'])

    def test_demo_entire_flow_cannot_invoke_any_process_or_sleep(self):
        def reply(prompt):
            if '实际灯' in prompt or 'App显示' in prompt or '自动更新' in prompt:
                return '2'
            if '刷新入口' in prompt or '是否需要' in prompt:
                return '2'
            return ''
        session, _ = self.session(capture.DemoBackend(), input_fn=reply)
        with mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('tool forbidden')), \
             mock.patch.object(capture.subprocess, 'Popen', side_effect=AssertionError('tool forbidden')), \
             mock.patch.object(capture.time, 'sleep', side_effect=AssertionError('sleep forbidden')):
            result = session.run()
        self.assertTrue(result['simulation'])
        self.assertEqual(result['status'], 'demo_completed')
        self.assertTrue(result['flow_completed'])
        self.assertFalse(result['household_live_validation_performed'])
        self.assertFalse((session.journal.directory / 'traffic.pcap').exists())
        self.assertTrue((session.journal.directory / '演练说明.txt').is_file())
        observed_steps = {row.get('step') for row in session.journal.rows if row['event'] == 'action_confirmed'}
        self.assertTrue({'App开1', 'App关1', 'App开2', 'App关2', '面板开', '面板关',
                         '关闭App', 'App关闭期间面板开', '重进App读状态'}.issubset(observed_steps))
        self.assertTrue(all(row['simulation'] for row in session.journal.rows))
        persisted = (session.journal.directory / 'session.json').read_text()
        self.assertNotIn(UDID, persisted)


class TargetContextCLITests(unittest.TestCase):
    def test_bad_context_is_rejected_before_phone_prompts_or_tool_calls(self):
        for arguments in [ ['--room-label', '演练房间'], ['--collection-id', COLLECTION_ID],
                           ['--target-label', '演练灯一', '--collection-id', 'not-a-uuid'],
                           ['--target-label', '演练\n灯一'] ]:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), \
                 mock.patch('builtins.input', side_effect=AssertionError('no phone prompt')), \
                 mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('tool forbidden')), \
                 mock.patch.object(capture.subprocess, 'Popen', side_effect=AssertionError('tool forbidden')):
                with self.assertRaises(SystemExit) as error:
                    capture.main(arguments)
                self.assertEqual(error.exception.code, 2)

    def test_cli_demo_records_declared_context_without_any_system_process(self):
        def reply(prompt):
            if 'MC7021 当前IP' in prompt:
                return IP
            if 'iPhone UDID' in prompt:
                return UDID
            if any(text in prompt for text in ['实际灯', 'App显示', '自动更新', '刷新入口', '是否需要']):
                return '2'
            return ''
        constructor = capture.GuidedSession
        def session_with_fake_input(*args, **kwargs):
            return constructor(*args, input_fn=reply, **kwargs)
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()), \
             mock.patch.object(capture, 'OUTPUTS', Path(temporary)), \
             mock.patch('builtins.input', side_effect=reply), \
             mock.patch.object(capture, 'GuidedSession', side_effect=session_with_fake_input), \
             mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('tool forbidden')), \
             mock.patch.object(capture.subprocess, 'Popen', side_effect=AssertionError('tool forbidden')):
            code = capture.main(['--demo', '--target-label', '演练灯一', '--room-label', '演练房间',
                                 '--collection-id', COLLECTION_ID])
            saved = list((Path(temporary) / 'demo_runs').glob('*/session.json'))
            self.assertEqual(len(saved), 1)
            result = json.loads(saved[0].read_text())
            self.assertEqual(code, 0)
            self.assertEqual(result['target_context'], target_context())
            self.assertEqual(result['status'], 'demo_completed')
            self.assertTrue(result['flow_completed'])
            self.assertFalse((saved[0].parent / 'traffic.pcap').exists())
            rows = [json.loads(line) for line in (saved[0].parent / 'events.jsonl').read_text().splitlines()]
            steps = [row['step'] for row in rows if row['event'] == 'action_confirmed']
            self.assertTrue({'App开1', 'App关1', 'App开2', 'App关2', '面板开', '面板关',
                '关闭App', 'App关闭期间面板开', '重进App读状态'}.issubset(steps))
            self.assertEqual(result['household_control_commands_sent'], 0)
            self.assertEqual(result['endpoint_probes_sent'], 0)
            self.assertEqual(result['device_configuration_writes'], 0)


class FakeProcess:
    def __init__(self, text):
        self.stderr = io.StringIO(text)
        self.returncode = None
        self.pid = 42424
        self.signals = []

    def poll(self):
        return self.returncode

    def send_signal(self, number):
        self.signals.append(number)

    def wait(self, timeout=None):
        self.returncode = 0
        return self.returncode


class CommandBoundaryTests(unittest.TestCase):
    def test_whole_script_running_as_root_is_refused_without_tool_call(self):
        with mock.patch.object(capture.sys, 'platform', 'darwin'), \
             mock.patch.object(capture.os, 'geteuid', return_value=0), \
             mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('tool forbidden')):
            with self.assertRaises(capture.CaptureError):
                capture.SystemBackend().prepare()

    def test_tcpdump_argv_has_exact_target_and_no_shell(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake = FakeProcess('tcpdump: listening on rvi2, link-type PKTAP\n0 packets captured\n')
            with mock.patch.object(capture.subprocess, 'Popen', return_value=fake) as popen, \
                 mock.patch.object(capture.subprocess, 'run', side_effect=AssertionError('unexpected extra tool')):
                tool = capture.TcpdumpCapture(IP, 'rvi2', directory / 'traffic.pcap', directory / 'tcpdump.log')
                tool.wait_ready(timeout=1)
                result = tool.stop()
            argv = popen.call_args.args[0]
            kwargs = popen.call_args.kwargs
            self.assertEqual(argv[:3], [capture.SUDO, '-n', capture.TCPDUMP])
            self.assertEqual(argv[-1], 'host 192.0.2.20 and (tcp or udp)')
            self.assertEqual(argv[argv.index('-i') + 1], 'rvi2')
            self.assertIn('-p', argv)
            self.assertIn('-n', argv[3:])
            self.assertEqual(argv[argv.index('-s') + 1], '0')
            self.assertTrue(argv[argv.index('-Z') + 1])
            self.assertNotEqual(argv[argv.index('-Z') + 1], 'root')
            self.assertFalse(kwargs.get('shell', False))
            self.assertEqual(kwargs['env']['LC_ALL'], 'C')
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(fake.signals, [signal.SIGINT])
            self.assertEqual(result['stats']['captured'], 0)

    def test_non_rvi_interface_rejected_before_any_process(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(capture.subprocess, 'Popen', side_effect=AssertionError('tool forbidden')):
            for interface in ['en0', 'rvi0;id', 'rvi0 extra', '-i en0', 'rvi']:
                with self.subTest(interface=interface), self.assertRaises(capture.CaptureError):
                    capture.TcpdumpCapture(IP, interface, Path(temp) / 'x', Path(temp) / 'log')

    def test_system_rvi_invocation_is_argument_list_and_no_shell(self):
        completed = subprocess.CompletedProcess([], 0, 'No devices found.\n', '')
        with mock.patch.object(capture.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(capture.SystemBackend().list_rvis(), [])
        self.assertEqual(run.call_args.args[0], [capture.RVICTL, '-l'])
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_kill_fallback_is_only_exact_child_pid_not_process_search_or_shell(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake = FakeProcess('tcpdump: listening on rvi2, link-type PKTAP\n0 packets captured\n')
            fake.send_signal = mock.Mock(side_effect=PermissionError('mock sudo signal permission'))
            with mock.patch.object(capture.subprocess, 'Popen', return_value=fake), \
                 mock.patch.object(capture.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                tool = capture.TcpdumpCapture(IP, 'rvi2', directory / 'traffic.pcap', directory / 'tcpdump.log')
                tool.wait_ready(timeout=1)
                tool.stop()
            self.assertEqual(run.call_args.args[0], [capture.SUDO, '-n', '/bin/kill', '-2', '42424'])
            self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_rvi_timeout_preserves_partial_output_as_unproven_or_proven_ownership(self):
        for text, expected in [(b'', False),
                ('Starting device {} [SUCCEEDED] with interface rvi2'.format(UDID).encode(), True)]:
            with self.subTest(proven=expected), mock.patch.object(capture.subprocess, 'run',
                    side_effect=subprocess.TimeoutExpired(['mock-rvictl'], 15, output=text)):
                success, output, code = capture.SystemBackend().create_rvi(UDID)
                self.assertEqual(success, expected)
                self.assertEqual(code, -2)
                self.assertIsInstance(output, str)


if __name__ == '__main__':
    unittest.main()
