#!/usr/bin/env python3
"""Guided, user-started USB RVI capture for exactly one known MC7021 IP.

Standard-library Python 3.9+, macOS. No discovery, sockets, vendor protocol,
configuration writes, certificates, proxy or replay. Real mode requires an
already working iPhone/App/local connection. --demo never invokes system tools.
"""
from __future__ import annotations

import argparse
import fcntl
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

VERSION = '0.2.0-community'
OUTPUTS = Path(__file__).resolve().parents[1]
SHANGHAI = timezone(timedelta(hours=8), 'Asia/Shanghai')
RVICTL = '/Library/Apple/usr/bin/rvictl'
TCPDUMP = '/usr/sbin/tcpdump'
SUDO = '/usr/bin/sudo'
STATUS_LABELS = {
    'completed': '引导完成，抓包和事件记录已保存',
    'completed_with_skips': '引导结束，有跳过步骤；已有记录已保存',
    'completed_no_packets': '引导结束，但没有捕获到目标报文',
    'completed_stats_unknown': '引导结束，未取得完整抓包统计',
    'interrupted': '已提前结束，保留已有记录',
    'failed': '采样失败，保留失败原因和已有记录',
    'capture_failed': '抓包进程异常停止',
    'capture_missing': '未找到抓包文件',
    'capture_file_unreadable': '抓包文件暂时无法读取',
    'cleanup_incomplete': '清理未完成，请保留本次日志',
    'save_incomplete': '部分记录未能完整保存，请检查磁盘和本次目录',
    'demo_completed': '离线演练完成，没有实际抓包',
    'demo_completed_with_skips': '离线演练结束，有跳过步骤；没有实际抓包',
}


class CaptureError(RuntimeError):
    pass


class StopRequested(Exception):
    pass


def now():
    return datetime.now(SHANGHAI).isoformat(timespec='milliseconds')


def safe_print(*args, **kwargs):
    """A closed Terminal must not prevent capture/interface cleanup."""
    try:
        print(*args, **kwargs)
    except OSError:
        pass


def validate_ip(value):
    value = value.strip()
    if '%' in value:
        raise ValueError('请填单个IP，不带接口、端口或网段。')
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('需要已确认的数字IP地址，不接受域名、命令或网段。')
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or str(ip) == '255.255.255.255':
        raise ValueError('需要本户主机的单播IP，不能使用本机、组播或广播地址。')
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return validate_ip(str(ip.ipv4_mapped))
    return str(ip)


def validate_udid(value):
    value = value.strip()
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})', value):
        raise ValueError('UDID格式应为40位十六进制，或8位-16位十六进制。请从Finder复制。')
    if not value.replace('-', '').strip('0'):
        raise ValueError('UDID不能全为0。')
    return value


def capture_filter(ip):
    return 'host {} and (tcp or udp)'.format(validate_ip(ip))


def parse_rvi_list(text):
    """Fail closed on unfamiliar/error output; never interpret it as no RVI."""
    rows = []
    recognized = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r'(?:Current )?Active Devices\s*:', line, re.I):
            recognized = True
            continue
        if re.fullmatch(r'No (?:active )?devices? (?:found|connected)\.?', line, re.I):
            recognized = True
            continue
        match = re.fullmatch(r'\[\d+\]\s+([0-9a-fA-F-]+)\s+.*?\b(rvi\d+)\b.*', line)
        if not match:
            raise CaptureError('无法可靠识别已有RVI列表；保留原接口并停止。')
        rows.append((validate_udid(match.group(1)), match.group(2)))
        recognized = True
    if not recognized:
        raise CaptureError('RVI列表为空或格式未知，未创建或移除任何接口。')
    if len({u.lower() for u, _ in rows}) != len(rows):
        raise CaptureError('RVI列表有重复手机标识，停止。')
    return rows


def parse_created_rvi(text, udid):
    pattern = r'Starting device\s+{}\s+\[SUCCEEDED\]\s+with interface\s+(rvi\d+)\b'
    matches = re.findall(pattern.format(re.escape(udid)), text, flags=re.I)
    if len(matches) != 1:
        raise CaptureError('RVI创建结果缺少唯一成功接口；停止并进入清理。')
    return matches[0]


def parse_capture_stats(text):
    patterns = {
        'captured': r'(?m)^\s*(\d+) packets? captured\s*$',
        'received_by_filter': r'(?m)^\s*(\d+) packets? received by filter\s*$',
        'dropped_by_kernel': r'(?m)^\s*(\d+) packets? dropped by kernel\s*$',
    }
    return {key: int(re.findall(pattern, text)[-1]) if re.findall(pattern, text) else None
            for key, pattern in patterns.items()}


class Journal:
    def __init__(self, parent, simulated=False):
        parent.mkdir(parents=True, exist_ok=True)
        name = '{}_{}_{}'.format('DEMO' if simulated else 'MC7021',
                                datetime.now(SHANGHAI).strftime('%Y%m%d_%H%M%S'), uuid.uuid4().hex[:6])
        self.directory = parent / name
        self.directory.mkdir(mode=0o700)
        self.jsonl = (self.directory / 'events.jsonl').open('x', encoding='utf-8')
        self.readable = (self.directory / '事件记录.txt').open('x', encoding='utf-8')
        self.simulated = simulated
        self.rows = []
        self.record('session_created', timezone='Asia/Shanghai (+08:00)')

    def record(self, kind, **values):
        row = dict(timestamp=now(), event=kind, simulation=self.simulated, **values)
        self.rows.append(row)
        self.jsonl.write(json.dumps(row, ensure_ascii=False) + '\n')
        self.jsonl.flush()
        os.fsync(self.jsonl.fileno())
        self.readable.write('{}  {}  {}\n'.format(row['timestamp'], kind,
                            json.dumps(values, ensure_ascii=False)))
        self.readable.flush()
        os.fsync(self.readable.fileno())
        return row

    def save_summary(self, data):
        temp = self.directory / 'session.json.tmp'
        with temp.open('w', encoding='utf-8') as sink:
            sink.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
            sink.flush()
            os.fsync(sink.fileno())
        temp.replace(self.directory / 'session.json')

    def close(self):
        for stream in (self.jsonl, self.readable):
            try:
                stream.close()
            except OSError:
                pass


class TcpdumpCapture:
    """Only tcpdump is privileged, and it drops to the actual invoking user."""
    def __init__(self, ip, interface, output, log_path):
        if not re.fullmatch(r'rvi\d+', interface):
            raise CaptureError('拒绝非RVI接口。')
        username = pwd.getpwuid(os.getuid()).pw_name
        self.command = [SUDO, '-n', TCPDUMP, '-i', interface, '-n', '-p', '-s', '0', '-U',
                        '-Z', username, '-w', str(output), capture_filter(ip)]
        self.text = []
        self.ready = threading.Event()
        self.log = log_path.open('x', encoding='utf-8')
        self.process = None
        self.reader = None
        try:
            # New process group, SAME terminal session: keep sudo's tty cache,
            # but avoid delivering terminal Ctrl+C twice to tcpdump on macOS.
            self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                env=dict(os.environ, LC_ALL='C', LANG='C'), preexec_fn=os.setpgrp)
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.reader.start()
        except BaseException:
            if self.process is not None and self.process.poll() is None:
                try:
                    self._signal(signal.SIGINT)
                    self.process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
            self.log.close()
            raise

    def _read(self):
        try:
            for line in self.process.stderr:
                self.text.append(line)
                self.log.write(line)
                self.log.flush()
                if re.search(r'listening on rvi\d+\b', line):
                    self.ready.set()
        except (OSError, ValueError) as error:
            self.text.append('Log writer error: {}\n'.format(error))
        finally:
            try:
                self.log.flush()
            except (OSError, ValueError):
                pass

    def wait_ready(self, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.process.poll() is not None:
                raise CaptureError('tcpdump启动失败；详情已保存到tcpdump.log。')
            if self.ready.wait(0.1):
                return
        raise CaptureError('tcpdump未确认开始监听，未进入灯操作。')

    def check(self):
        if self.process.poll() is not None:
            raise CaptureError('tcpdump提前停止；保存现有数据，不继续灯操作。')

    def _signal(self, number):
        if self.process.poll() is not None:
            return
        try:
            self.process.send_signal(number)
        except ProcessLookupError:
            return
        except PermissionError:
            # Only the still-running, directly owned sudo child; no pkill,
            # process name search, group-wide kill or arbitrary root shell.
            if self.process.poll() is None:
                subprocess.run([SUDO, '-n', '/bin/kill', '-{}'.format(number),
                                str(self.process.pid)], check=True, timeout=5,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def stop(self):
        result = dict(graceful=True, process_exit=None)
        try:
            if self.process.poll() is None:
                self._signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    result['graceful'] = False
                    self._signal(signal.SIGTERM)
                    self.process.wait(timeout=4)
            result['process_exit'] = self.process.poll()
        except (OSError, subprocess.SubprocessError) as error:
            result.update(graceful=False, stop_error=str(error),
                          process_exit=self.process.poll())
        if self.reader is not None:
            self.reader.join(timeout=2)
        if self.reader is None or not self.reader.is_alive():
            try:
                self.log.close()
                self.process.stderr.close()
            except OSError as error:
                result['log_close_error'] = str(error)
        result['stats'] = parse_capture_stats(''.join(self.text))
        result['still_running'] = self.process.poll() is None
        return result


class SystemBackend:
    simulated = False

    def prepare(self):
        if sys.platform != 'darwin':
            raise CaptureError('真实采样仅支持macOS；演练使用 --demo。')
        if os.geteuid() == 0:
            raise CaptureError('请双击启动器或普通用户运行，不要sudo整个脚本。')
        for binary in (RVICTL, TCPDUMP, SUDO):
            if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
                raise CaptureError('缺少系统工具：{}。未自动安装或修改系统。'.format(binary))

    def _rvi(self, *args):
        return subprocess.run([RVICTL] + list(args), capture_output=True, text=True,
            env=dict(os.environ, LC_ALL='C', LANG='C'), timeout=15)

    def list_rvis(self):
        result = self._rvi('-l')
        if result.returncode:
            raise CaptureError('无法读取已有RVI列表；未改接口。')
        return parse_rvi_list(result.stdout + '\n' + result.stderr)

    def authorize(self):
        print('\n需要Mac管理员授权一次，用于打开抓包接口；密码由sudo读取，不进入事件日志。', flush=True)
        result = subprocess.run([SUDO, '-v'], timeout=120)
        if result.returncode:
            raise CaptureError('未获得抓包授权，停止。')

    def create_rvi(self, udid):
        try:
            result = self._rvi('-s', udid)
            text = result.stdout + '\n' + result.stderr
            code = result.returncode
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode('utf-8', 'replace') if isinstance(value, bytes) else value or ''
            text = decoded(error.stdout) + '\n' + decoded(error.stderr)
            code = -2  # Creation may have happened before the tool timed out.
        # Communicate ownership BEFORE strict parsing, including a successful
        # creation followed by an unrecognized interface/output error.
        success = bool(re.search(r'Starting device\s+{}\s+\[SUCCEEDED\]'.format(
            re.escape(udid)), text, flags=re.I))
        return success, text, code

    def remove_rvi(self, udid):
        result = self._rvi('-x', udid)
        if result.returncode or 'SUCCEEDED' not in (result.stdout + result.stderr):
            raise CaptureError('自动移除本次RVI失败；保留日志，勿操作MC7021。')

    def start_capture(self, ip, interface, directory):
        return TcpdumpCapture(ip, interface, directory / 'traffic.pcap', directory / 'tcpdump.log')


class DemoCapture:
    def wait_ready(self, timeout=12):
        pass

    def check(self):
        pass

    def stop(self):
        return dict(graceful=True, still_running=False, process_exit=0,
                    stats=dict(captured=0, received_by_filter=0, dropped_by_kernel=0))


class DemoBackend:
    simulated = True

    def prepare(self):
        pass

    def list_rvis(self):
        return []

    def authorize(self):
        pass

    def create_rvi(self, udid):
        return True, 'Starting device {} [SUCCEEDED] with interface rvi0'.format(udid), 0

    def remove_rvi(self, udid):
        pass

    def start_capture(self, ip, interface, directory):
        (directory / '演练说明.txt').write_text('离线演练：没有建立RVI、提权或抓包；没有PCAP样本。\n', encoding='utf-8')
        return DemoCapture()


class GuidedSession:
    def __init__(self, ip, udid, journal, backend, input_fn=input, sleep_fn=time.sleep,
                 sample_origin='external_owner_household'):
        self.ip, self.udid = validate_ip(ip), validate_udid(udid)
        self.journal, self.backend = journal, backend
        self.input, self.sleep = input_fn, sleep_fn
        self.capture = None
        self.owned_rvi = False
        self.interface = None
        self.cleaning = False
        self.defer_stop = False
        self.pending_stop = None
        self.skipped = []
        self.lock = None
        self.metadata = dict(script_version=VERSION, started_at=now(), simulation=backend.simulated,
            target_ip=self.ip, iphone_udid_sha256=hashlib.sha256(self.udid.lower().encode()).hexdigest(),
            iphone_udid_suffix=self.udid[-4:], capture_filter=capture_filter(self.ip),
            timezone='Asia/Shanghai (+08:00)', status='preparing', flow_completed=False,
            rvi_owned_by_this_session=False, rvi_cleanup='not_created',
            household_control_commands_sent=0, endpoint_probes_sent=0,
            device_configuration_writes=0, runtime_compatibility_verified=False,
            household_live_validation_performed=False,
            sample_origin=sample_origin, project_household_verified=False,
            action_timestamp_semantics='actual action is user-reported within ready_at..confirmed_at; not exact instrumented action time')
        self.journal.save_summary(self.metadata)

    def signal_handler(self, number, frame):
        if self.cleaning:
            return
        reason = 'signal_' + signal.Signals(number).name
        if self.defer_stop:
            self.pending_stop = reason
            return
        raise StopRequested(reason)

    def ask(self, prompt):
        if self.capture:
            self.capture.check()
        try:
            answer = self.input(prompt).strip()
        except EOFError:
            raise StopRequested('terminal_EOF')
        if answer.lower() == 'q':
            raise StopRequested('user_q')
        if self.capture:
            self.capture.check()
        return answer

    def choice(self, prompt, choices):
        while True:
            answer = self.ask(prompt)
            if answer in choices:
                self.journal.record('user_choice', prompt=prompt, value=choices[answer])
                return choices[answer]
            print('请输入列出的数字；输入q结束并保存。', flush=True)

    def wait(self, seconds):
        self.journal.record('observation_wait_start', planned_seconds=seconds,
                            simulation_wait_skipped=self.backend.simulated)
        if not self.backend.simulated:
            print('观察{}秒…（Control+C可随时保存结束）'.format(seconds), flush=True)
            for _ in range(seconds):
                self.capture.check()
                self.sleep(1)
        self.journal.record('observation_wait_end')

    def observe(self, step, update=False):
        physical = self.choice('实际灯：1亮 / 2灭 / 3不确定：', {'1': 'on', '2': 'off', '3': 'unknown'})
        app = self.choice('App显示：1开 / 2关 / 3未知 / 4当前未显示：',
                          {'1': 'on', '2': 'off', '3': 'unknown', '4': 'not_visible'})
        values = dict(step=step, physical_light=physical, app_display=app,
                      evidence='user_observation; not protocol-decoded state')
        if update:
            values['update_observed'] = self.choice('App是否自动更新：1是 / 2否 / 3不确定：',
                            {'1': 'yes', '2': 'no', '3': 'unknown'})
        self.journal.record('observation', **values)
        return values

    def action(self, step, instruction, seconds=15, observe=True, update=False):
        print('\n── {} ──\n{}'.format(step, instruction), flush=True)
        self.journal.record('instruction', step=step, instruction=instruction)
        command = self.ask('准备好按回车；s跳过此步；q结束保存：').lower()
        while command not in ('', 's'):
            command = self.ask('本步未执行。按回车开始；s跳过；q结束：').lower()
        if command == 's':
            self.skipped.append(step)
            self.journal.record('step_skipped', step=step, executed=False)
            return None
        ready = self.journal.record('action_ready', step=step)['timestamp']
        answer = self.ask('现在执行上面的动作，完成后立刻按回车；未做则输入s：').lower()
        if answer == 's':
            self.skipped.append(step)
            self.journal.record('action_not_executed', step=step, ready_at=ready, executed=False)
            return None
        if answer:
            self.journal.record('action_confirmation_uncertain', step=step, ready_at=ready)
            self.skipped.append(step)
            return None
        confirmed = self.journal.record('action_confirmed', step=step, ready_at=ready,
                    user_reports_executed=True, exact_action_time_unknown=True)['timestamp']
        if seconds:
            self.wait(seconds)
        values = self.observe(step, update) if observe else None
        self.journal.record('step_finished', step=step, ready_at=ready, confirmed_at=confirmed)
        return values

    def flow(self):
        print('\n抓包已开始。只用同一组已知普通灯和对应实体键；每步按提示操作。', flush=True)
        initial = self.action('初始同步', '正常打开原厂App，进入同一盏普通灯的页面；不要切换主机模式。', 20)
        if initial and initial['physical_light'] == 'on':
            self.action('准备关灯', '这盏灯目前已亮：用App正常关灯一次，为后面重复开关做准备。')
        for name, verb in [('App开1', '打开'), ('App关1', '关闭'), ('App开2', '打开'), ('App关2', '关闭')]:
            self.action(name, '只用App{}同一组普通灯。'.format(verb))
        for name, verb in [('面板开', '打开'), ('面板关', '关闭')]:
            observation = self.action(name, 'App留在目标灯页面，不点App开关。用你熟悉的实体键{}同一灯。'.format(verb), update=True)
            if observation and observation.get('update_observed') != 'yes':
                refresh = self.choice('App已有正常刷新入口吗？1有，记录一次刷新 / 2无或不刷新：',
                                      {'1': True, '2': False})
                if refresh:
                    self.action(name + '后手动刷新', '只使用App原有刷新功能一次，不改设置。', 5)
                else:
                    self.journal.record('manual_refresh_not_performed', step=name)
        self.action('关闭App', '正常划掉摩根App，不退出账号、不改变网络。', 0, observe=False)
        self.action('App关闭期间面板开', 'App保持关闭，用同一个已知实体键把同一灯打开。', 5)
        self.action('重进App读状态', '正常重新打开摩根App进入目标灯页面，观察能否读到当前状态。', 15, update=True)
        restore = self.choice('是否需要把这组灯恢复到开始时的亮灭？1需要 / 2不需要：', {'1': True, '2': False})
        if restore:
            self.action('结束恢复动作', '只用已知单灯键把同一组灯恢复到开始时的亮灭，不操作其它设备。', 5)
        self.wait(20)
        self.metadata['flow_completed'] = True

    def run(self):
        try:
            self.backend.prepare()
            # Locks only other copies of THIS tool, without persisting phone ID.
            locks = self.journal.directory.parent / '.locks'
            locks.mkdir(mode=0o700, exist_ok=True)
            lock_path = locks / (self.metadata['iphone_udid_sha256'] + '.lock')
            self.lock = lock_path.open('a')
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CaptureError('本工具已有同一手机的采样正在进行，本次停止。')
            existing = self.backend.list_rvis()
            if any(u.lower() == self.udid.lower() for u, _ in existing):
                raise CaptureError('这部手机已有RVI在用；为保留原采样会话，本次停止，不移除已有接口。')
            self.backend.authorize()
            # The user may have spent time at the sudo prompt: recheck ownership.
            existing = self.backend.list_rvis()
            if any(u.lower() == self.udid.lower() for u, _ in existing):
                raise CaptureError('授权期间这部手机出现已有RVI，本次不接管或移除它。')
            # Defer Ctrl+C/HUP during this short ownership-changing call. This
            # prevents losing a successful -s result before owned_rvi is saved.
            self.defer_stop = True
            try:
                success, text, code = self.backend.create_rvi(self.udid)
                self.owned_rvi = success
                self.metadata['rvi_owned_by_this_session'] = success
                self.metadata['rvi_cleanup'] = 'pending' if success else 'not_created'
                if code == -2 and not success:
                    self.metadata['rvi_cleanup'] = 'ownership_unknown'
                self.journal.record('rvi_creation_result', success=success, returncode=code,
                    tool_output=re.sub(re.escape(self.udid), '[本次iPhone]', text, flags=re.I)[:4096])
                self.journal.save_summary(self.metadata)
                if not success or code:
                    raise CaptureError('未确认RVI成功创建；检查USB/信任状态，不操作MC7021。')
                self.interface = parse_created_rvi(text, self.udid)
            finally:
                self.defer_stop = False
            if self.pending_stop:
                raise StopRequested(self.pending_stop)
            self.metadata['rvi_interface'] = self.interface
            self.metadata['household_capture_attempted'] = not self.backend.simulated
            self.defer_stop = True
            try:
                self.capture = self.backend.start_capture(self.ip, self.interface, self.journal.directory)
            finally:
                self.defer_stop = False
            if self.pending_stop:
                raise StopRequested(self.pending_stop)
            self.capture.wait_ready()
            self.metadata.update(status='capturing', capture_started_at=now())
            self.journal.record('capture_ready', interface=self.interface, filter=capture_filter(self.ip))
            self.journal.save_summary(self.metadata)
            self.flow()
            self.metadata['status'] = 'completed_with_skips' if self.skipped else 'completed'
        except StopRequested as error:
            self.metadata.update(status='interrupted', stop_reason=str(error))
            self.journal.record('stop_requested', reason=str(error))
        except Exception as error:
            self.metadata.update(status='failed', error=str(error))
            try:
                self.journal.record('failure', error=str(error))
            except OSError:
                pass
            safe_print('\n采样停止：{}'.format(error), flush=True)
        finally:
            self.finish()
        return self.metadata

    def finish(self):
        if self.cleaning:
            return
        self.cleaning = True
        safe_print('\n正在停止抓包、保存记录并清理本次接口…', flush=True)
        stop = None
        persistence_errors = []
        def record(kind, **values):
            try:
                self.journal.record(kind, **values)
            except OSError as error:
                persistence_errors.append(str(error))
        try:
            if self.capture:
                try:
                    stop = self.capture.stop()
                except Exception as error:
                    stop = dict(graceful=False, still_running=True, stop_error=str(error), stats={})
                self.metadata['capture_stop'] = stop
                record('capture_stopped', **stop)
                if not stop.get('graceful') or stop.get('still_running'):
                    self.metadata['status'] = 'cleanup_incomplete'
                elif stop.get('process_exit') not in (0, None):
                    self.metadata['status'] = 'capture_failed'
                elif (stop.get('stats', {}).get('captured') == 0 and self.metadata['flow_completed']
                      and not self.backend.simulated):
                    self.metadata['status'] = 'completed_no_packets'
            if self.owned_rvi and (not stop or not stop.get('still_running')):
                try:
                    self.backend.remove_rvi(self.udid)
                    self.metadata['rvi_cleanup'] = 'removed'
                    record('owned_rvi_removed')
                except (CaptureError, OSError, subprocess.SubprocessError) as error:
                    self.metadata.update(rvi_cleanup='failed', rvi_cleanup_error=str(error), status='cleanup_incomplete')
                    record('owned_rvi_cleanup_failed', error=str(error))
            elif self.owned_rvi:
                self.metadata.update(rvi_cleanup='deferred_capture_still_running', status='cleanup_incomplete')
                record('owned_rvi_cleanup_deferred', reason='capture process not confirmed stopped')
            elif self.metadata['rvi_cleanup'] == 'ownership_unknown':
                self.metadata['status'] = 'cleanup_incomplete'
            pcap = self.journal.directory / 'traffic.pcap'
            try:
                if pcap.is_file():
                    digest = hashlib.sha256()
                    with pcap.open('rb') as source:
                        for block in iter(lambda: source.read(1024 * 1024), b''):
                            digest.update(block)
                    self.metadata['pcap'] = dict(file='traffic.pcap', size_bytes=pcap.stat().st_size,
                                                 sha256=digest.hexdigest())
                elif not self.backend.simulated and self.metadata['flow_completed']:
                    self.metadata['pcap_missing'] = True
                    if self.metadata['status'].startswith('completed'):
                        self.metadata['status'] = 'capture_missing'
            except OSError as error:
                self.metadata['pcap_read_error'] = str(error)
                if self.metadata['status'].startswith('completed'):
                    self.metadata['status'] = 'capture_file_unreadable'
                persistence_errors.append(str(error))
            if stop and self.metadata['flow_completed'] and not self.backend.simulated:
                stats = stop.get('stats', {})
                if stats.get('captured') is None and self.metadata['status'].startswith('completed'):
                    self.metadata['status'] = 'completed_stats_unknown'
                self.metadata['packet_loss_observed'] = bool(stats.get('dropped_by_kernel'))
            self.metadata.update(ended_at=now(), skipped_steps=self.skipped,
                                 capture_ready='capture_started_at' in self.metadata,
                                 user_confirmed_actions=sum(r['event'] == 'action_confirmed' for r in self.journal.rows))
            # Creating a local capture does not itself validate the protocol.
            if persistence_errors:
                self.metadata['persistence_errors'] = persistence_errors
                self.metadata['save_complete'] = False
                if self.metadata['status'].startswith('completed'):
                    self.metadata['status'] = 'save_incomplete'
            if self.backend.simulated and self.metadata['status'].startswith('completed'):
                self.metadata['status'] = 'demo_' + self.metadata['status']
            record('session_finished', status=self.metadata['status'])
            if persistence_errors:
                self.metadata['persistence_errors'] = persistence_errors
                self.metadata['save_complete'] = False
                if self.metadata['status'].startswith(('completed', 'demo_completed')):
                    self.metadata['status'] = 'save_incomplete'
            try:
                self.journal.save_summary(self.metadata)
            except OSError as error:
                self.metadata.update(save_complete=False, summary_write_error=str(error))
                if self.metadata['status'].startswith(('completed', 'demo_completed')):
                    self.metadata['status'] = 'save_incomplete'
                record('summary_write_failed', error=str(error), status=self.metadata['status'])
                safe_print('摘要无法写入：{}。现有PCAP/事件文件仍保留。'.format(error), flush=True)
        finally:
            try:
                self.journal.close()
            except OSError:
                pass
            if self.lock:
                self.lock.close()
        safe_print('保存位置：{}'.format(self.journal.directory), flush=True)
        safe_print('结果：{}'.format(STATUS_LABELS.get(self.metadata['status'], self.metadata['status'])), flush=True)
        if self.metadata.get('capture_stop') and not self.backend.simulated:
            stats = self.metadata['capture_stop'].get('stats', {})
            safe_print('捕获包数：{}；内核丢包：{}'.format(stats.get('captured'), stats.get('dropped_by_kernel')), flush=True)
        if self.metadata['status'] == 'completed_no_packets':
            safe_print('0包：保留记录，核对现有IP/接口/是否云控；不要扫描或改配置。', flush=True)
        if self.metadata.get('rvi_cleanup') in ('failed', 'ownership_unknown', 'deferred_capture_still_running'):
            safe_print('接口未确认清理。先查看本次session.json/tcpdump.log；人工确认后可运行：{} -x 你的iPhoneUDID'.format(RVICTL), flush=True)


def read_value(prompt, validator):
    while True:
        try:
            value = input(prompt).strip()
        except EOFError:
            raise StopRequested('terminal_EOF_before_capture')
        if value.lower() == 'q':
            raise StopRequested('user_q_before_capture')
        try:
            return validator(value)
        except ValueError as error:
            print(error, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='offline rehearsal, no tools or network; no PCAP produced')
    parser.add_argument('--analyze-after', action='store_true', help='write a private offline report after cleanup')
    parser.add_argument('--peer-owner', action='store_true',
                        help='label this as another owner household; never project-home evidence')
    args = parser.parse_args(argv)
    os.umask(0o077)
    print('MC7021 单组普通灯采样  v{}\n只记录已知主机IP的双向TCP/UDP；不扫描、不发研究命令、不改设备/路由配置。'.format(VERSION), flush=True)
    print('iPhone接USB、解锁并信任Mac，沿用现有正常Wi-Fi/本地控制。先划掉摩根App，不退出账号。\n输入q或Control+C可结束；过程中按数字记录你实际看到的状态。', flush=True)
    if args.demo:
        print('【离线演练】不建立RVI、不提权、不抓包；等待时间略过，结果在demo_runs。', flush=True)
    print('【独立住户样本】仅用于你自己家的一组普通灯；来源单独记录，不代表其它住户已验证。', flush=True)
    try:
        ip = read_value('MC7021 当前IP（从现有信息取得）：', validate_ip)
        udid = read_value('iPhone UDID（从Finder复制）：', validate_udid)
    except (StopRequested, KeyboardInterrupt):
        print('\n已退出，尚未建立接口或抓包。')
        return 0
    backend = DemoBackend() if args.demo else SystemBackend()
    parent = OUTPUTS / 'demo_runs' if args.demo else OUTPUTS / 'captures'
    journal = Journal(parent, args.demo)
    session = GuidedSession(ip, udid, journal, backend,
        sample_origin='external_owner_household')
    previous = {}
    try:
        for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            previous[number] = signal.signal(number, session.signal_handler)
        result = session.run()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    if args.analyze_after:
        try:
            try:
                from .analyze_capture import analyze_session
                from .research_tool import show_report
            except ImportError:
                from analyze_capture import analyze_session
                from research_tool import show_report
            destination, report = analyze_session(journal.directory)
            show_report(destination, report, open_browser=not args.demo)
        except (OSError, ValueError) as error:
            print('采样文件已保留，后续离线分析未完成：{}'.format(error), flush=True)
    return 0 if result['status'] in ('completed', 'completed_with_skips', 'completed_no_packets',
                                    'demo_completed', 'demo_completed_with_skips', 'interrupted') else 1


if __name__ == '__main__':
    sys.exit(main())
