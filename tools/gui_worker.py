#!/usr/bin/env python3
"""Local JSON-lines worker for the native Mac research interface.

No GUI web server or upload endpoint. Demonstration and analysis use local files
only. Capture delegates to the existing guided lifecycle and a separately
scoped GUI capture backend; it never sends a household control command.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading
import uuid

try:
    from . import capture_mc7021_light as capture
    from .analyze_capture import analyze_session
    from . import demo_sample as demo
except ImportError:
    import capture_mc7021_light as capture
    from analyze_capture import analyze_session
    import demo_sample as demo


MAX_INPUT_BYTES = 64 * 1024
MAX_LOG_CHARS = 16 * 1024


class WorkerError(RuntimeError):
    """An actionable error which may be shown in the local user interface."""


class WorkerCancelled(Exception):
    pass


class Protocol:
    """One flushed UTF-8 JSON object per output line, without raw stdout prints.

    The only accepted input is a bounded JSON response for the current prompt.
    Phone identifiers are redacted even if an underlying exception echoes one.
    """

    def __init__(self, input_stream=None, output_stream=None, secrets=()):
        self.input = input_stream if input_stream is not None else sys.stdin
        self.output = output_stream if output_stream is not None else sys.stdout
        self.secrets = [str(value) for value in secrets if value]
        self._output_lock = threading.Lock()

    def _clean(self, value):
        if isinstance(value, str):
            for secret in self.secrets:
                value = re.sub(re.escape(secret), '[已隐藏手机标识]', value, flags=re.I)
            return value
        if isinstance(value, dict):
            return {str(key): self._clean(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._clean(item) for item in value]
        return value

    def emit(self, type, **fields):
        payload = self._clean(dict(type=type, **fields))
        line = json.dumps(payload, ensure_ascii=False, allow_nan=False) + '\n'
        with self._output_lock:
            self.output.write(line)
            self.output.flush()

    def request(self, text, options, default_value=None):
        identifier = uuid.uuid4().hex
        fields = dict(id=identifier, text=str(text), options=options)
        if default_value is not None:
            fields['default_value'] = default_value
        self.emit('prompt', **fields)
        line = self.input.readline(MAX_INPUT_BYTES + 1)
        if not line:
            raise WorkerCancelled('gui_input_EOF')
        if len(line.encode('utf-8')) > MAX_INPUT_BYTES or not line.endswith('\n'):
            raise WorkerError('界面响应超过大小限制或不完整；本次已停止。')
        try:
            response = json.loads(line)
        except (ValueError, RecursionError):
            raise WorkerError('界面响应格式无效；本次已停止。')
        if (not isinstance(response, dict) or set(response) != {'id', 'value'}
                or response.get('id') != identifier or not isinstance(response.get('value'), str)):
            raise WorkerError('界面响应与当前步骤不匹配；本次已停止。')
        value = response['value']
        if value.strip().lower() == 'q':
            raise WorkerCancelled('gui_stop')
        if options and value not in {item['value'] for item in options}:
            raise WorkerError('界面选择无效；本次已停止。')
        return value


class JsonLog(io.TextIOBase):
    """Bridge library print output to the saved original protocol stream."""

    def __init__(self, protocol):
        self.protocol = protocol
        self.pending = ''

    @property
    def encoding(self):
        return 'utf-8'

    def writable(self):
        return True

    def write(self, value):
        value = str(value)
        self.pending += value
        while '\n' in self.pending:
            line, self.pending = self.pending.split('\n', 1)
            if line:
                self.protocol.emit('log', text=line)
        while len(self.pending) > MAX_LOG_CHARS:
            self.protocol.emit('log', text=self.pending[:MAX_LOG_CHARS])
            self.pending = self.pending[MAX_LOG_CHARS:]
        return len(value)

    def flush(self):
        if self.pending:
            self.protocol.emit('log', text=self.pending)
            self.pending = ''


def choice_label(prompt, value):
    if isinstance(value, bool):
        if '刷新' in prompt:
            return '有，记录一次刷新' if value else '无或不刷新'
        return '需要' if value else '不需要'
    if '实际灯' in prompt:
        return {'on': '灯亮着', 'off': '灯灭了', 'unknown': '不确定'}.get(value, str(value))
    if 'App显示' in prompt:
        return {'on': '显示开', 'off': '显示关', 'unknown': '未知',
                'not_visible': '当前未显示'}.get(value, str(value))
    return {'yes': '是，自动更新了', 'no': '没有自动更新',
            'unknown': '不确定'}.get(value, str(value))


class GuiGuidedSession(capture.GuidedSession):
    """Change interaction only; keep original recording and ownership cleanup."""

    def __init__(self, *args, protocol, **kwargs):
        self.protocol = protocol
        super().__init__(*args, **kwargs)

    def _request(self, text, options, default_value=None):
        if self.capture:
            self.capture.check()
        try:
            answer = self.protocol.request(text, options, default_value)
        except WorkerCancelled as error:
            raise capture.StopRequested(str(error))
        if self.capture:
            self.capture.check()
        return answer

    def ask(self, prompt):
        confirming = '现在执行' in prompt
        options = [dict(value='', label='动作已完成' if confirming else '准备好了，继续'),
                   dict(value='s', label='未执行，跳过' if confirming else '跳过本步'),
                   dict(value='q', label='结束并保存')]
        return self._request(prompt, options, default_value='')

    def choice(self, prompt, choices):
        options = [dict(value=key, label=choice_label(prompt, value))
                   for key, value in choices.items()]
        options.append(dict(value='q', label='结束并保存'))
        answer = self._request(prompt, options)
        value = choices[answer]
        self.journal.record('user_choice', prompt=prompt, value=value)
        return value

    def action(self, step, instruction, seconds=15, observe=True, update=False):
        self.protocol.emit('step', title=step, instruction=instruction)
        return super().action(step, instruction, seconds, observe, update)

    def wait(self, seconds):
        self.journal.record('observation_wait_start', planned_seconds=seconds,
                            simulation_wait_skipped=self.backend.simulated)
        if not self.backend.simulated:
            for remaining in range(seconds, 0, -1):
                self.capture.check()
                self.protocol.emit('progress', remaining_seconds=remaining)
                self.sleep(1)
        self.protocol.emit('progress', remaining_seconds=0)
        self.journal.record('observation_wait_end')


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default message may include a private argument value.
        raise WorkerError('启动参数无效，请从图形界面重新选择功能。')


def make_parser():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', required=True, type=Path)
    modes = parser.add_subparsers(dest='mode', required=True,
                                parser_class=SafeArgumentParser)
    modes.add_parser('demo')
    modes.add_parser('collection-demo')
    analysis = modes.add_parser('analyze')
    analysis.add_argument('--session-dir', required=True, type=Path)
    sampling = modes.add_parser('capture')
    sampling.add_argument('--host-ip', required=True)
    sampling.add_argument('--udid', required=True)
    sampling.add_argument('--target-label')
    sampling.add_argument('--room-label')
    sampling.add_argument('--collection-id')
    sampling.add_argument('--baseline-reviewed', action='store_true')
    collection = modes.add_parser('collection')
    collection.add_argument('--capture-root', required=True, type=Path)
    return parser


@contextlib.contextmanager
def signal_handlers(handler):
    previous = {}
    try:
        for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            previous[number] = signal.signal(number, handler)
        yield
    finally:
        for number, old_handler in previous.items():
            signal.signal(number, old_handler)


def stop_worker(number, frame):
    raise WorkerCancelled('signal_' + signal.Signals(number).name)


def analyze_and_emit(protocol, directory, data_dir, ordinary_ids=(), capture_status=None):
    protocol.emit('step', title='离线分析', instruction='只读取本地采样，生成私有中文报告；不重放报文。')
    destination, report = analyze_session(directory,
        output_root=data_dir / 'private_reports', ordinary_ids=ordinary_ids)
    protocol.emit('result', report_path=str((destination / '报告.html').resolve()),
        report_dir=str(destination.resolve()), session_dir=str(Path(directory).resolve()),
        summary=report['summary'], quality=report['quality']['level'],
        simulation=report['simulation'], capture_status=capture_status)
    return report


def run_capture(args, protocol, backend_factory=None):
    ip, udid = capture.validate_ip(args.host_ip), capture.validate_udid(args.udid)
    context = capture.build_target_context(args.target_label, args.room_label, args.collection_id)
    protocol.emit('capture_preflight', status='validated')
    protocol.secrets.append(udid)
    if backend_factory is None:
        try:
            from .gui_capture_backend import GuiSystemBackend
        except ImportError:
            from gui_capture_backend import GuiSystemBackend
        backend_factory = GuiSystemBackend
    backend = backend_factory()
    journal = capture.Journal(args.data_dir / 'captures', False)
    if args.baseline_reviewed:
        journal.record('baseline_review_declared', owner_declaration=True,
            physical_identity_verified_by_tool=False, independent_state_verified_by_tool=False)
    session = GuiGuidedSession(ip, udid, journal, backend, protocol=protocol,
        sample_origin='external_owner_household', target_context=context)
    with signal_handlers(session.signal_handler):
        metadata = session.run()
    # Cleanup has finished before any analysis is attempted, including on EOF,
    # cancellation and failure. No analyzer can keep a capture interface alive.
    status = metadata['status']
    protocol.emit('log', text='本次采样记录已保存：' + str(journal.directory))
    completed_statuses = ('completed', 'completed_with_skips', 'completed_no_packets',
                          'completed_stats_unknown')
    if status not in completed_statuses + ('interrupted',):
        protocol.emit('error', message=capture.STATUS_LABELS.get(status, '本次采样未完成'))
    try:
        analyze_and_emit(protocol, journal.directory, args.data_dir, capture_status=status)
    except (OSError, ValueError) as error:
        protocol.emit('error', message='采样原件已保留，离线分析未完成：' + str(error),
                      session_dir=str(journal.directory))
        return False
    return status in completed_statuses


def run(argv=None, protocol=None, backend_factory=None):
    """Return an exit code; dependency injection is for offline tests only."""
    protocol = protocol if protocol is not None else Protocol()
    sink = JsonLog(protocol)
    ok = False
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            args = make_parser().parse_args(argv)
            if getattr(args, 'udid', None):
                protocol.secrets.append(args.udid)
            args.data_dir = args.data_dir.expanduser().resolve()
            os.umask(0o077)
            args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with signal_handlers(stop_worker):
                if args.mode == 'demo':
                    protocol.emit('step', title='完整离线演示',
                        instruction='自动生成合成通信和事件记录，无需手机；不会建立接口或连接家庭设备。')
                    directory = demo.create_demo_sample(args.data_dir / 'demo_runs')
                    analyze_and_emit(protocol, directory, args.data_dir, ordinary_ids=(demo.DEVICE,))
                    ok = True
                elif args.mode in ('collection', 'collection-demo'):
                    try:
                        from .collection_report import analyze_collection
                    except ImportError:
                        from collection_report import analyze_collection
                    collection_root = args.capture_root if args.mode == 'collection' else (
                        args.data_dir / 'demo_collections' / uuid.uuid4().hex)
                    if args.mode == 'collection-demo':
                        identifier = uuid.uuid4().hex
                        for name in ('合成普通灯A', '合成普通灯B'):
                            directory = demo.create_demo_sample(collection_root / 'captures')
                            path = directory / 'session.json'
                            metadata = json.loads(path.read_text(encoding='utf-8'))
                            metadata['target_context'] = capture.build_target_context(name, '合成房间', identifier)
                            path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
                    protocol.emit('step', title='多轮离线汇总',
                        instruction='逐轮读取并分析，不合并设备身份；完整报告仅存本机。')
                    destination, report = analyze_collection(collection_root, args.data_dir / 'private_reports')
                    protocol.emit('result', report_path=str(destination / 'collection.html'),
                        report_dir=str(destination), summary=report['summary'],
                        quality=report['quality']['level'], simulation=report.get('simulation'),
                        capture_status=None, report_kind='collection')
                    ok = True
                elif args.mode == 'analyze':
                    analyze_and_emit(protocol, args.session_dir, args.data_dir)
                    ok = True
                else:
                    ok = run_capture(args, protocol, backend_factory)
    except (WorkerCancelled, KeyboardInterrupt):
        protocol.emit('log', text='操作已结束；已生成的本地文件保留。')
    except Exception as error:
        # A concise local error is useful; a traceback can expose argv/private
        # identifiers and is never sent to the GUI protocol or stderr.
        protocol.emit('error', message=str(error) or '本次操作未完成，请保留现有文件。')
    finally:
        sink.flush()
        protocol.emit('finished', ok=ok)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(run())
