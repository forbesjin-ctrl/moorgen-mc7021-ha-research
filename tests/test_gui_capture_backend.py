"""Offline GUI capture tests. No administrator prompt, RVI or real tcpdump.

Only the native helper's --self-test runs; that branch validates inputs and
statistics entirely in memory and returns before all capture/privilege code.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'tools') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('gui_capture_backend', ROOT / 'tools/gui_capture_backend.py')
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)


class AuthorizationTests(unittest.TestCase):
    def test_every_argument_survives_shell_and_applescript_quoting(self):
        arguments = ["/Applications/合成 工具's.app/capture-helper", '--capture', '501',
                     '20', 'synthetic_user', 'rvi1', '192.0.2.20',
                     "/private/tmp/synthetic `marker` $(never-run) ' quote", '123', 'f' * 32]
        script = gui.authorization_script(arguments)
        command_line = script.splitlines()[1].strip()
        encoded = command_line[len('do shell script '):-len(' with administrator privileges')]
        self.assertEqual(shlex.split(json.loads(encoded)), ['exec'] + arguments)
        self.assertNotIn(' password ', script)
        self.assertNotIn('sudo', script)
        self.assertIn('with timeout of 1200 seconds', script)

    def test_control_characters_rejected_before_dispatch(self):
        for value in ['line\nnext', 'bad\rpath', 'tab\there', 'nul\0end', 'del\x7f']:
            with self.subTest(value=value), self.assertRaises(gui.CaptureError):
                gui.authorization_script(['/synthetic/capture-helper', value])

    def test_authorize_never_calls_sudo_or_any_process(self):
        with mock.patch.object(gui.subprocess, 'run', side_effect=AssertionError('no system calls')), \
             mock.patch.object(gui.subprocess, 'Popen', side_effect=AssertionError('no system calls')):
            self.assertIsNone(gui.GuiSystemBackend().authorize())

    def test_prepare_checks_tools_without_authorizing_or_touching_rvi(self):
        backend = gui.GuiSystemBackend()
        with mock.patch.object(gui.sys, 'platform', 'darwin'), \
             mock.patch.object(gui.os, 'geteuid', return_value=501), \
             mock.patch.object(gui.os.path, 'isfile', return_value=True), \
             mock.patch.object(gui.os, 'access', return_value=True), \
             mock.patch.object(gui, 'locate_helper', return_value=Path('/synthetic/capture-helper')), \
             mock.patch.object(gui.subprocess, 'run', side_effect=AssertionError('no RVI')), \
             mock.patch.object(gui.subprocess, 'Popen', side_effect=AssertionError('no authorization')):
            backend.prepare()
        self.assertEqual(backend.helper, Path('/synthetic/capture-helper'))

    def test_prepare_rejects_root_or_non_mac(self):
        for platform, uid in [('linux', 501), ('darwin', 0)]:
            with self.subTest(platform=platform, uid=uid), \
                 mock.patch.object(gui.sys, 'platform', platform), \
                 mock.patch.object(gui.os, 'geteuid', return_value=uid), \
                 self.assertRaises(gui.CaptureError):
                gui.GuiSystemBackend().prepare()

    def test_missing_tool_is_not_auto_installed(self):
        with mock.patch.object(gui.sys, 'platform', 'darwin'), \
             mock.patch.object(gui.os, 'geteuid', return_value=501), \
             mock.patch.object(gui.os.path, 'isfile', return_value=False), \
             mock.patch.object(gui.subprocess, 'run', side_effect=AssertionError('no installation')), \
             self.assertRaises(gui.CaptureError):
            gui.GuiSystemBackend().prepare()

    def test_helper_requires_absolute_regular_executable_named_helper(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'capture-helper'
            path.write_text('synthetic, not executed\n')
            path.chmod(0o700)
            with mock.patch.dict(os.environ, MC7021_CAPTURE_HELPER=str(path)):
                self.assertEqual(gui.locate_helper(), path.resolve())
            for value in ['relative/capture-helper', str(path.with_name('wrong-name'))]:
                with mock.patch.dict(os.environ, MC7021_CAPTURE_HELPER=value), self.assertRaises(gui.CaptureError):
                    gui.locate_helper()
            link = Path(folder) / 'link' / 'capture-helper'
            link.parent.mkdir()
            link.symlink_to(path)
            with mock.patch.dict(os.environ, MC7021_CAPTURE_HELPER=str(link)), self.assertRaises(gui.CaptureError):
                gui.locate_helper()


class GuiCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.process = mock.Mock()
        self.process.poll.return_value = None
        self.process.communicate.return_value = ('', '')
        self.spawn = mock.patch.object(gui.subprocess, 'Popen', return_value=self.process)
        self.popen = self.spawn.start()
        self.addCleanup(self.spawn.stop)
        self.threads = mock.patch.object(gui.threading, 'Thread')
        self.thread_class = self.threads.start()
        self.addCleanup(self.threads.stop)
        self.indices = mock.patch.object(gui, 'interface_index', return_value=17)
        self.interface_index = self.indices.start()
        self.addCleanup(self.indices.stop)
        self.capture = gui.GuiTcpdumpCapture(Path('/synthetic/capture-helper'),
                                            '192.0.2.20', 'rvi7', self.directory)

    def state(self, **updates):
        value = dict(schema=1, nonce=self.capture.nonce, state='finished',
                     tcpdump_pid=123, reason='user_stop', process_exit=0,
                     graceful=True, still_running=False, cleanup_requires_review=False,
                     stats=dict(captured=11, received_by_filter=13, dropped_by_kernel=0))
        value.update(updates)
        gui.private_write(self.capture.control / 'status.json', json.dumps(value))
        return value

    def test_only_osascript_is_spawned_and_python_stays_unprivileged(self):
        arguments, keywords = self.popen.call_args
        self.assertEqual(arguments[0][:2], [gui.OSASCRIPT, '-e'])
        script = arguments[0][2]
        self.assertIn('capture-helper', script)
        self.assertIn('with administrator privileges', script)
        self.assertNotIn('sudo', script)
        self.assertNotIn('python', script.lower())
        self.assertEqual(keywords['stdin'], subprocess.DEVNULL)
        self.assertTrue(keywords['start_new_session'])
        self.assertNotIn('shell', keywords)

    def test_control_files_are_private_and_nonce_scoped(self):
        self.assertEqual(stat.S_IMODE(self.capture.control.stat().st_mode), 0o700)
        heartbeat = self.capture.control / 'heartbeat'
        self.assertEqual(stat.S_IMODE(heartbeat.stat().st_mode), 0o600)
        self.assertEqual(heartbeat.read_text().strip(), self.capture.nonce)
        self.assertRegex(self.capture.nonce, r'^[0-9a-f]{32}$')

    def test_expected_interface_generation_is_passed_to_native_helper(self):
        command_line = self.popen.call_args[0][0][2].splitlines()[1].strip()
        encoded = command_line[len('do shell script '):-len(' with administrator privileges')]
        self.assertEqual(shlex.split(json.loads(encoded))[-1], '17')

    def test_interface_recreated_during_authorization_never_becomes_ready(self):
        self.state(state='capturing', still_running=True, reason='ready')
        self.interface_index.return_value = 18
        with self.assertRaisesRegex(gui.CaptureError, '变化'):
            self.capture.wait_ready()
        with self.assertRaisesRegex(gui.CaptureError, '重建'):
            self.capture.check()

    def test_capture_only_becomes_ready_with_explicit_helper_confirmation(self):
        self.state(state='capturing', still_running=True, process_exit=None, reason='ready')
        self.capture.wait_ready()
        self.capture.check()

    def test_finished_capture_is_not_ready(self):
        self.state()
        with self.assertRaises(gui.CaptureError):
            self.capture.wait_ready()
        with self.assertRaises(gui.CaptureError):
            self.capture.check()

    def test_nonce_mismatch_rejects_other_sessions_state(self):
        self.state(nonce='e' * 32)
        with self.assertRaises(gui.CaptureError):
            self.capture.check()

    def test_symlink_or_public_state_file_is_rejected(self):
        self.state()
        status_path = self.capture.control / 'status.json'
        status_path.chmod(0o644)
        with self.assertRaises(gui.CaptureError):
            self.capture._state()
        status_path.unlink()
        target = self.capture.control / 'synthetic.json'
        gui.private_write(target, '{}')
        status_path.symlink_to(target)
        with self.assertRaises(gui.CaptureError):
            self.capture._state()

    def test_stop_waits_for_helper_final_stats_and_preserves_stop_marker(self):
        self.state()
        self.process.poll.return_value = 0
        result = self.capture.stop()
        self.assertEqual(result['stats'], dict(captured=11, received_by_filter=13, dropped_by_kernel=0))
        self.assertTrue(result['graceful'])
        self.assertFalse(result['still_running'])
        self.assertEqual(result['process_exit'], 0)
        self.assertEqual(stat.S_IMODE((self.capture.control / 'stop').stat().st_mode), 0o600)
        self.process.send_signal.assert_not_called()
        self.process.terminate.assert_not_called()
        self.assertEqual(self.capture.stop(), result)

    def test_unknown_helper_exit_does_not_claim_tcpdump_stopped(self):
        self.process.poll.return_value = 1
        result = self.capture.stop()
        self.assertTrue(result['still_running'])
        self.assertFalse(result['graceful'])
        self.assertTrue(result['cleanup_requires_review'])
        self.process.send_signal.assert_not_called()

    def test_authorization_cancel_is_clean_and_never_enters_light_flow(self):
        self.process.poll.return_value = 1
        self.process.communicate.return_value = ('', 'execution error: User canceled. (-128)\n')
        with self.assertRaisesRegex(gui.CaptureError, '取消'):
            self.capture.wait_ready()
        result = self.capture.stop()
        self.assertFalse(result['still_running'])
        self.assertTrue(result['graceful'])
        self.assertEqual(result['helper_reason'], 'authorization_cancelled')

    def test_cancel_message_after_helper_was_seen_does_not_prove_shutdown(self):
        self.state(state='capturing', still_running=True)
        self.capture.wait_ready()
        (self.capture.control / 'status.json').unlink()
        self.process.poll.return_value = 1
        self.process.communicate.return_value = ('', 'execution error: User canceled. (-128)\n')
        result = self.capture.stop()
        self.assertTrue(result['still_running'])
        self.assertTrue(result['cleanup_requires_review'])

    def test_capturing_state_and_cancel_message_remain_unconfirmed(self):
        self.state(state='capturing', still_running=True)
        self.process.poll.return_value = 1
        self.process.communicate.return_value = ('', 'execution error: User canceled. (-128)\n')
        with mock.patch.object(gui.time,'monotonic',side_effect=[0.0,0.0,21.0]), \
             mock.patch.object(gui.time,'sleep'):
            result = self.capture.stop()
        self.assertTrue(result['still_running'])
        self.assertFalse(result['graceful'])

    def test_helper_stop_timeout_is_conservative_even_after_osascript_termination(self):
        self.state(state='capturing', still_running=True)
        self.process.wait.side_effect = subprocess.TimeoutExpired('synthetic', 1)
        with mock.patch.object(gui.time, 'monotonic', side_effect=[0.0, 0.0, 21.0]), \
             mock.patch.object(gui.time, 'sleep'):
            result = self.capture.stop()
        self.assertTrue(result['still_running'])
        self.assertFalse(result['graceful'])
        self.process.terminate.assert_called_once()
        self.assertTrue((self.capture.control / 'stop').is_file())

    def test_signal_escalation_or_worker_loss_is_reported_honestly(self):
        self.state(graceful=False, process_exit=-15, reason='heartbeat_timeout', cleanup_requires_review=True)
        self.process.poll.return_value = 0
        result = self.capture.stop()
        self.assertFalse(result['graceful'])
        self.assertFalse(result['still_running'])
        self.assertEqual(result['process_exit'], -15)
        self.assertTrue(result['cleanup_requires_review'])

    def test_heartbeat_failure_prevents_continued_operations(self):
        self.capture._heartbeat_error = 'synthetic full disk'
        with self.assertRaises(gui.CaptureError):
            self.capture.check()
        with self.assertRaises(gui.CaptureError):
            self.capture.wait_ready()

    def test_invalid_interface_and_ip_never_spawn_authorization(self):
        count = self.popen.call_count
        for ip, interface in [('192.0.2.20', 'en0'), ('host.invalid', 'rvi0'),
                              ('192.0.2.20;id', 'rvi0')]:
            with self.subTest(ip=ip, interface=interface), self.assertRaises((ValueError, gui.CaptureError)):
                gui.GuiTcpdumpCapture('/synthetic/capture-helper', ip, interface, self.directory)
        self.assertEqual(self.popen.call_count, count)

    def test_directory_permissions_fail_closed(self):
        self.directory.chmod(0o755)
        try:
            with self.assertRaises(gui.CaptureError):
                gui.GuiTcpdumpCapture('/synthetic/capture-helper', '192.0.2.20', 'rvi0', self.directory)
        finally:
            self.directory.chmod(0o700)

    def test_spawn_failure_leaves_persistent_cancel_marker(self):
        self.popen.side_effect = OSError('synthetic launch failure')
        before = set(self.directory.iterdir())
        with self.assertRaises(OSError):
            gui.GuiTcpdumpCapture('/synthetic/capture-helper', '192.0.2.20', 'rvi0', self.directory)
        new = set(self.directory.iterdir()) - before
        self.assertEqual(len(new), 1)
        self.assertTrue((new.pop() / 'stop').is_file())

    def test_invalid_status_cannot_be_hidden_by_authorization_cancel(self):
        self.process.poll.return_value = 1
        self.process.communicate.return_value = ('', 'execution error (-128)')
        gui.private_write(self.capture.control / 'status.json', 'invalid json')
        result = self.capture.stop()
        self.assertTrue(result['still_running'])
        self.assertFalse(result['graceful'])
        self.assertIn('stop_error', result)


class RviGenerationTests(unittest.TestCase):
    UDID = '00000001-0000000000000001'

    def setUp(self):
        self.backend = gui.GuiSystemBackend()
        self.result = (True, 'Starting device {} [SUCCEEDED] with interface rvi7'.format(self.UDID), 0)
        self.indices = mock.patch.object(gui, 'interface_index', return_value=17)
        self.index = self.indices.start()
        self.addCleanup(self.indices.stop)

    def create(self):
        with mock.patch.object(gui.SystemBackend, 'create_rvi', return_value=self.result):
            return self.backend.create_rvi(self.UDID)

    def test_creation_records_local_index_before_authorization(self):
        self.assertEqual(self.create(), self.result)
        self.assertEqual(self.backend._rvi_lease,
                         dict(udid=self.UDID.lower(), interface='rvi7', index=17))

    def test_failed_index_read_returns_creation_result_to_preserve_session_ownership(self):
        self.index.side_effect = gui.CaptureError('synthetic local index failure')
        self.assertEqual(self.create(), self.result)
        self.assertIsNone(self.backend._rvi_lease)
        with self.assertRaises(gui.CaptureError), mock.patch.object(gui, 'GuiTcpdumpCapture') as spawn:
            self.backend.start_capture('192.0.2.20', 'rvi7', Path('/synthetic'))
        spawn.assert_not_called()

    def test_recreated_interface_is_never_started_or_removed(self):
        self.create()
        self.index.return_value = 18
        with mock.patch.object(gui.SystemBackend, 'remove_rvi') as remove, \
             mock.patch.object(gui, 'GuiTcpdumpCapture') as spawn:
            with self.assertRaises(gui.CaptureError):
                self.backend.start_capture('192.0.2.20', 'rvi7', Path('/synthetic'))
            with self.assertRaises(gui.CaptureError):
                self.backend.remove_rvi(self.UDID)
        remove.assert_not_called()
        spawn.assert_not_called()

    def test_changed_phone_mapping_prevents_removal(self):
        self.create()
        with mock.patch.object(self.backend, 'list_rvis', return_value=[(self.UDID, 'rvi8')]), \
             mock.patch.object(gui.SystemBackend, 'remove_rvi') as remove:
            with self.assertRaises(gui.CaptureError):
                self.backend.remove_rvi(self.UDID)
        remove.assert_not_called()

    def test_index_rechecked_after_mapping_read(self):
        self.create()
        self.index.side_effect = [17, 18]
        with mock.patch.object(self.backend, 'list_rvis', return_value=[(self.UDID, 'rvi7')]), \
             mock.patch.object(gui.SystemBackend, 'remove_rvi') as remove:
            with self.assertRaises(gui.CaptureError):
                self.backend.remove_rvi(self.UDID)
        remove.assert_not_called()

    def test_only_matching_phone_interface_and_generation_is_removed(self):
        self.create()
        with mock.patch.object(self.backend, 'list_rvis', return_value=[(self.UDID, 'rvi7')]), \
             mock.patch.object(gui.SystemBackend, 'remove_rvi') as remove:
            self.backend.remove_rvi(self.UDID)
        remove.assert_called_once_with(self.UDID)
        self.assertIsNone(self.backend._rvi_lease)


class NativeHelperOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which('clang')
        if not cls.compiler:
            raise unittest.SkipTest('clang unavailable; native self-test runs on macOS build host')
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / 'capture-helper'
        subprocess.run([cls.compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT / 'macos/capture_helper.c'), '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)

    def test_self_test_performs_no_capture_or_authorization(self):
        result = subprocess.run([str(self.binary), '--self-test'], check=True,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), dict(self_test='passed', capture_attempted=False))
        self.assertEqual(result.stderr, '')

    def test_invalid_arguments_fail_before_capture_or_privilege_handling(self):
        result = subprocess.run([str(self.binary), '--capture', '0', '20', 'synthetic_user',
                                 'en0', 'host.invalid', '/does-not-exist', '1', 'badnonce', '17'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 64)


if __name__ == '__main__':
    unittest.main()
