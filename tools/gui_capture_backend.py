"""GUI-only authorization bridge; never elevates Python or reads a password.

The bundled native helper supervises its own tcpdump child. All RVI creation
and removal remain in the existing, unprivileged GuidedSession lifecycle.
Tests mock every authorization/process boundary. Importing this module has no
system-tool, capture, filesystem or authorization side effect.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import shlex
from socket import if_nametoindex
import stat
import subprocess
import sys
import threading
import time
import uuid

from capture_mc7021_light import (CaptureError, RVICTL, TCPDUMP, SystemBackend,
                                  parse_created_rvi, validate_ip, validate_udid)


OSASCRIPT = '/usr/bin/osascript'
AUTHORIZATION_TIMEOUT = 150.0


def interface_index(interface):
    """Read one known local interface's generation; no endpoint or network IO."""
    try:
        value = if_nametoindex(interface)
    except (OSError, ValueError) as error:
        raise CaptureError('无法确认本次 RVI 接口代次：{}'.format(error))
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CaptureError('RVI 接口代次未知，保留接口并停止。')
    return value


def locate_helper():
    configured = os.environ.get('MC7021_CAPTURE_HELPER')
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            raise CaptureError('图形采样 helper 必须是绝对路径。')
        candidates = [candidate]
    else:
        here = Path(__file__).resolve()
        candidates = [here.parents[1] / 'capture-helper',
                      here.parents[1] / 'macos' / 'capture-helper',
                      here.parents[2] / 'capture-helper']
    for candidate in candidates:
        if candidate.name != 'capture-helper' or candidate.is_symlink():
            continue
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return candidate.resolve()
    raise CaptureError('缺少随图形应用附带的 capture-helper；未自动安装或修改系统。')


def authorization_script(arguments):
    """Exactly one shell dispatch, then the native helper uses fixed execve.

    shlex.quote protects every shell argument; JSON string escaping is also
    valid AppleScript string escaping for the quotes/backslashes encountered
    in POSIX paths. Control characters are rejected rather than interpolated.
    """
    values = [str(value) for value in arguments]
    if any(any(ord(character) < 32 or ord(character) == 127 for character in value)
           for value in values):
        raise CaptureError('采样路径或参数含控制字符，已停止。')
    command = 'exec ' + ' '.join(shlex.quote(value) for value in values)
    return 'with timeout of 1200 seconds\n  do shell script {} with administrator privileges\nend timeout\n'.format(
        json.dumps(command, ensure_ascii=False))


def private_write(path, data, replace=True):
    path = Path(path)
    name = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex) if replace else path
    descriptor = os.open(str(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if replace:
            name.replace(path)
    except BaseException:
        try:
            name.unlink()
        except OSError:
            pass
        raise


class GuiTcpdumpCapture:
    """Same wait_ready/check/stop contract as the terminal capture backend.

    Stopping touches a nonce-specific marker and waits for a signed-in helper
    result. It never signals the PID supplied by a writable state file.
    Unknown shutdown remains ``still_running=True`` so GuidedSession retains
    the RVI rather than claiming cleanup succeeded.
    """
    def __init__(self, helper, ip, interface, directory, expected_ifindex=None):
        if not re.fullmatch(r'rvi\d+', interface):
            raise CaptureError('拒绝非 RVI 接口。')
        ip = validate_ip(ip)
        self.interface = interface
        self.expected_ifindex = expected_ifindex if expected_ifindex is not None else interface_index(interface)
        if not isinstance(self.expected_ifindex, int) or isinstance(self.expected_ifindex, bool) or not 0 < self.expected_ifindex <= 2147483647:
            raise CaptureError('RVI 接口代次无效，未请求管理员授权。')
        if interface_index(interface) != self.expected_ifindex:
            raise CaptureError('RVI 接口已被移除或重建，停止采样并保留本次记录。')
        self.directory = Path(directory).resolve(strict=True)
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CaptureError('采样目录必须是本用户独占的 0700 目录。')
        self.nonce = uuid.uuid4().hex
        self.control = self.directory / ('.gui-capture-' + self.nonce)
        self.control.mkdir(mode=0o700)
        self._ending = threading.Event()
        self._heartbeat_error = None
        self._final_result = None
        self._helper_seen = False
        self._output = None
        self.process = None
        self._heartbeat_thread = None
        user = pwd.getpwuid(os.getuid())
        arguments = [str(helper), '--capture', str(os.getuid()), str(user.pw_gid),
                     user.pw_name, interface, ip, str(self.directory),
                     str(os.getpid()), self.nonce, str(self.expected_ifindex)]
        script = authorization_script(arguments)
        private_write(self.control / 'heartbeat', self.nonce + '\n')
        try:
            self.process = subprocess.Popen([OSASCRIPT, '-e', script],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True,
                env={**{key: os.environ[key] for key in
                        ('HOME', 'TMPDIR', 'USER', 'LOGNAME', 'DISPLAY',
                         'SECURITYSESSIONID', '__CF_USER_TEXT_ENCODING')
                        if key in os.environ},
                     'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'})
            self._heartbeat_thread = threading.Thread(target=self._heartbeat, daemon=True)
            self._heartbeat_thread.start()
        except BaseException:
            # A late authorization must see this marker and never start capture.
            private_write(self.control / 'stop', 'stop\n')
            self._ending.set()
            raise

    def _heartbeat(self):
        while not self._ending.wait(1.0):
            try:
                private_write(self.control / 'heartbeat', self.nonce + '\n')
            except OSError as error:
                self._heartbeat_error = str(error)
                return  # helper's independent timer will stop its child.

    def _state(self):
        path = self.control / 'status.json'
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
                raise CaptureError('采样状态文件权限或格式异常，停止并保留日志。')
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, encoding='utf-8') as source:
                value = json.load(source)
        except FileNotFoundError:
            return None
        except (ValueError, OSError) as error:
            raise CaptureError('无法读取采样 helper 状态：{}'.format(error))
        if not isinstance(value, dict) or value.get('schema') != 1 or value.get('nonce') != self.nonce or value.get('state') not in ('capturing', 'finished'):
            raise CaptureError('采样状态不属于本次会话或格式未知。')
        self._helper_seen = True
        return value

    def _authorization_output(self):
        if self._output is None and self.process is not None and self.process.poll() is not None:
            try:
                self._output = self.process.communicate(timeout=1)
            except (OSError, subprocess.SubprocessError):
                self._output = ('', '')
        return self._output or ('', '')

    def _cancelled_authorization(self):
        return self.process is not None and self.process.poll() not in (None, 0) and '(-128)' in self._authorization_output()[1]

    def wait_ready(self, timeout=12):
        # The user's time in the native authorization dialog is separate from
        # the helper's 12-second bounded tcpdump startup phase.
        deadline = time.monotonic() + max(AUTHORIZATION_TIMEOUT, float(timeout))
        while time.monotonic() < deadline:
            state = self._state()
            if state:
                if state['state'] == 'capturing' and state.get('still_running') is True:
                    if interface_index(self.interface) != self.expected_ifindex:
                        raise CaptureError('授权期间 RVI 接口已变化，停止并保留记录。')
                    return
                raise CaptureError('抓包未启动或已停止：{}。已有记录已保留。'.format(state.get('reason', 'unknown')))
            if self._ending.is_set():
                raise CaptureError('已取消采样，正在等待停止确认。')
            if self.process.poll() is not None:
                if self._cancelled_authorization():
                    raise CaptureError('已取消 Mac 系统管理员授权，未进入灯操作。')
                raise CaptureError('图形抓包 helper 未确认启动；停止并保留本次记录。')
            if self._heartbeat_error:
                raise CaptureError('采样心跳无法保存，已停止继续操作。')
            time.sleep(0.1)
        raise CaptureError('系统授权等待超时，未进入灯操作。')

    def check(self):
        state = self._state()
        if self._heartbeat_error or not state or state['state'] != 'capturing' or self.process.poll() is not None:
            raise CaptureError('抓包已停止或未确认继续运行，保存现有数据，不继续灯操作。')
        if interface_index(self.interface) != self.expected_ifindex:
            raise CaptureError('本次 RVI 接口已被移除或重建，停止采样，不继续灯操作。')

    @staticmethod
    def _stop_result(state):
        stats = state.get('stats') if isinstance(state.get('stats'), dict) else {}
        return dict(graceful=state.get('graceful') is True,
                    process_exit=state.get('process_exit'),
                    still_running=state.get('still_running') is not False,
                    stats={key: stats.get(key) for key in
                           ('captured', 'received_by_filter', 'dropped_by_kernel')},
                    helper_reason=state.get('reason'),
                    cleanup_requires_review=state.get('cleanup_requires_review') is True)

    def stop(self):
        if self._final_result is not None:
            return dict(self._final_result)
        error = None
        try:
            private_write(self.control / 'stop', 'stop\n')
        except OSError as caught:
            error = str(caught)
        self._ending.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)
        deadline = time.monotonic() + 20.0
        state = None
        while time.monotonic() < deadline:
            try:
                state = self._state()
            except CaptureError as caught:
                error = str(caught)
            if state and state['state'] == 'finished':
                result = self._stop_result(state)
                break
            if error is None and state is None and not self._helper_seen and self._cancelled_authorization():
                result = dict(graceful=True, process_exit=0, still_running=False,
                              stats=dict(captured=None, received_by_filter=None, dropped_by_kernel=None),
                              helper_reason='authorization_cancelled', cleanup_requires_review=False)
                break
            if self.process is not None and self.process.poll() is not None and state is None:
                result = dict(graceful=False, process_exit=None, still_running=True, stats={},
                              helper_reason='helper_exit_unconfirmed', cleanup_requires_review=True)
                break
            time.sleep(0.1)
        else:
            result = dict(graceful=False, process_exit=None, still_running=True,
                          stats={}, helper_reason='helper_stop_unconfirmed', cleanup_requires_review=True)
        if error:
            result.update(graceful=False, stop_error=error)
        # Terminate only our ordinary osascript process after placing the
        # persistent stop marker. Never treat that as proof tcpdump exited.
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.wait(timeout=1 if result.get('still_running') else 3)
            except subprocess.TimeoutExpired:
                if result.get('still_running'):
                    try:
                        self.process.terminate()
                        self.process.wait(timeout=2)
                    except (OSError, subprocess.SubprocessError):
                        pass
            except OSError:
                pass
        self._authorization_output()
        self._final_result = dict(result)
        return result


class GuiSystemBackend(SystemBackend):
    """Passive RVI lifecycle with native system authorization at capture start."""
    def prepare(self):
        if sys.platform != 'darwin':
            raise CaptureError('真实采样仅支持 macOS；演示和分析不需要管理员授权。')
        if os.geteuid() == 0:
            raise CaptureError('图形应用和 Python 必须由普通用户运行。')
        for binary in (RVICTL, TCPDUMP, OSASCRIPT):
            if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
                raise CaptureError('缺少系统工具：{}。未自动安装或修改系统。'.format(binary))
        self.helper = locate_helper()

    def authorize(self):
        # No sudo credential cache and no custom password field. The actual
        # native system dialog appears immediately before tcpdump starts.
        pass

    def create_rvi(self, udid):
        result = super().create_rvi(udid)
        success, text, _ = result
        self._rvi_lease = None
        self._rvi_generation_error = None
        if success:
            # Do not raise after a successful creation: GuidedSession must first
            # receive success and record ownership before any later exception.
            try:
                interface = parse_created_rvi(text, udid)
                self._rvi_lease = dict(udid=validate_udid(udid).lower(),
                                      interface=interface, index=interface_index(interface))
            except (CaptureError, ValueError) as error:
                self._rvi_generation_error = str(error)
        return result

    def _check_lease(self, udid=None, interface=None):
        lease = getattr(self, '_rvi_lease', None)
        if not lease:
            raise CaptureError('本次 RVI 代次未确认，保留接口并停止；请查看本次记录。')
        if udid is not None and validate_udid(udid).lower() != lease['udid']:
            raise CaptureError('RVI 不属于本次手机，不接管或移除。')
        if interface is not None and interface != lease['interface']:
            raise CaptureError('RVI 名称与本次创建结果不同，停止。')
        if interface_index(lease['interface']) != lease['index']:
            raise CaptureError('RVI 已被移除或重建，拒绝接管或删除新接口。')
        return lease

    def remove_rvi(self, udid):
        lease = self._check_lease(udid=udid)
        matching = [(phone.lower(), interface) for phone, interface in self.list_rvis()
                    if phone.lower() == lease['udid'] or interface == lease['interface']]
        if matching != [(lease['udid'], lease['interface'])]:
            raise CaptureError('RVI 手机映射已变化，拒绝移除，保留本次记录。')
        self._check_lease(udid=udid)  # recheck after the local mapping read
        super().remove_rvi(udid)
        self._rvi_lease = None

    def start_capture(self, ip, interface, directory):
        lease = self._check_lease(interface=interface)
        return GuiTcpdumpCapture(getattr(self, 'helper', None) or locate_helper(),
                                 ip, interface, directory, expected_ifindex=lease['index'])
