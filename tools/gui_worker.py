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
import stat
import sys
import threading
import uuid

try:
    from . import capture_mc7021_light as capture
    from .analyze_capture import analyze_session
    from . import demo_sample as demo
    from . import baseline_review as reviews
except ImportError:
    import capture_mc7021_light as capture
    from analyze_capture import analyze_session
    import demo_sample as demo
    import baseline_review as reviews


MAX_INPUT_BYTES = 64 * 1024
MAX_LOG_CHARS = 16 * 1024
MAX_REVIEW_FORM_BYTES = 4 * 1024 * 1024
REVIEW_FORM_FIELDS = {'decisions', 'notes', 'selected_identifier', 'reviewer_label'}


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
    adaptation = modes.add_parser('local-adapt')
    adaptation.add_argument('--session-dir', required=True, type=Path)
    modes.add_parser('local-adapt-demo')
    workbench = modes.add_parser('session-workbench')
    workbench.add_argument('--session-dir', required=True, type=Path)
    workbench.add_argument('--identifier', default='')
    workbench.add_argument('--comparison-dir', type=Path)
    modes.add_parser('session-workbench-demo')
    recipe = modes.add_parser('local-recipe')
    recipe.add_argument('--session-dir', required=True, type=Path)
    recipe.add_argument('--identifier', required=True)
    recipe.add_argument('--holdout-dir', type=Path)
    for action in ('plan', 'prepare'):
        gap = modes.add_parser('sampling-' + action)
        gap.add_argument('--session-dir', required=True, type=Path)
        gap.add_argument('--identifier', default='')
        gap.add_argument('--comparison-dir', type=Path)
        if action == 'prepare':
            gap.add_argument('--task-id', required=True)
            gap.add_argument('--plan-file', required=True, type=Path)
    sampling = modes.add_parser('capture')
    sampling.add_argument('--host-ip', required=True)
    sampling.add_argument('--udid', required=True)
    sampling.add_argument('--target-label')
    sampling.add_argument('--room-label')
    sampling.add_argument('--collection-id')
    sampling.add_argument('--baseline-reviewed', action='store_true')
    sampling.add_argument('--review-file', type=Path)
    collection = modes.add_parser('collection')
    collection.add_argument('--capture-root', required=True, type=Path)
    handoff = modes.add_parser('ha-handoff')
    handoff.add_argument('--review-file', required=True, type=Path)
    handoff.add_argument('--host-ip')
    wizard_create = modes.add_parser('ha-wizard-create')
    wizard_create.add_argument('--review-file', required=True, type=Path)
    wizard_create.add_argument('--host-ip')
    modes.add_parser('ha-wizard-demo')
    for action in ('load', 'starter', 'adapter', 'driver', 'bundle', 'install', 'diagnostics', 'acceptance'):
        wizard = modes.add_parser('ha-wizard-' + action)
        wizard.add_argument('--wizard-file', required=True, type=Path)
        if action == 'adapter':
            wizard.add_argument('--manifest-file', required=True, type=Path)
            wizard.add_argument('--driver-file', required=True, type=Path)
        if action == 'driver':
            wizard.add_argument('--driver-file', required=True, type=Path)
        if action in ('install', 'acceptance', 'driver'):
            wizard.add_argument('--form-file', required=True, type=Path)
        if action == 'diagnostics':
            wizard.add_argument('--diagnostics-file', required=True, type=Path)
    review_save = modes.add_parser('review-save')
    review_save.add_argument('--report-dir', required=True, type=Path)
    review_save.add_argument('--session-dir', required=True, type=Path)
    review_save.add_argument('--form-file', required=True, type=Path)
    review_list = modes.add_parser('review-list')
    review_list.add_argument('--host-ip')
    review_validate = modes.add_parser('review-validate')
    review_validate.add_argument('--review-file', required=True, type=Path)
    review_validate.add_argument('--host-ip')
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
        simulation=report['simulation'], capture_status=capture_status,
        source=report.get('source', {}), target_context=report.get('target_context'),
        baseline_assessment=reviews.assess_report(report),
        review_draft=reviews.draft_review(report))
    maybe_emit_sampling_plan(protocol, directory, data_dir)
    return report


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise WorkerError('核对表单含重复字段，请重新保存。')
        value[key] = item
    return value


def load_review_form(path, data_root, fields=REVIEW_FORM_FIELDS):
    """Read a bounded local form without following a selected symlink.

    Forms are private evidence. They must live beneath the user-selected data
    folder, not within the application or a public source checkout.
    """
    root = Path(data_root).resolve()
    path = Path(path).expanduser().absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise WorkerError('核对表单必须保存在当前本机数据文件夹内。')
    if not relative.parts or any(part in ('.', '..') for part in relative.parts):
        raise WorkerError('核对表单路径无效。')
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise WorkerError('核对表单及其父目录不能是符号链接。')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_REVIEW_FORM_BYTES:
            raise WorkerError('核对表单必须是大小不超过 4 MiB 的普通 JSON 文件。')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            payload = source.read(MAX_REVIEW_FORM_BYTES + 1)
        if len(payload) > MAX_REVIEW_FORM_BYTES:
            raise WorkerError('核对表单超过 4 MiB，请重新保存。')
    finally:
        os.close(descriptor)
    try:
        form = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique_json_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite number')))
    except (UnicodeError, ValueError, RecursionError):
        raise WorkerError('核对表单不是有效 JSON，请重新保存。')
    if not isinstance(form, dict) or (fields is not None and set(form) != fields):
        raise WorkerError('核对表单字段不完整或含未知字段，请重新保存。')
    if fields == REVIEW_FORM_FIELDS and (not isinstance(form['decisions'], dict) or not isinstance(form['notes'], dict)
            or not isinstance(form['selected_identifier'], str)
            or not isinstance(form['reviewer_label'], str)):
        raise WorkerError('核对表单字段类型无效，请重新保存。')
    return form


def run_local_adaptation(args, protocol):
    """Fixed local analyzers only; never load plugins, drivers or cloud models."""
    try:
        from . import local_adaptation as adaptation
        from . import adapter_recipe as recipe
    except ImportError:
        import local_adaptation as adaptation
        import adapter_recipe as recipe
    protocol.emit('step', title='本机无代码适配研究',
        instruction='从原件重新计算候选并离线比较，不连接设备、不上传、不输出可联网驱动。')
    if args.mode == 'local-recipe':
        path, record = recipe.create_recipe(args.session_dir, args.data_dir,
            selected_identifier=args.identifier, holdout_directory=args.holdout_dir)
        protocol.emit('local_adaptation', directory=str(path.parent),
            session_dir=str(args.session_dir.absolute()), recipe_file=str(path),
            report_text=bounded_local_text(recipe.render_text(record)), candidates=[args.identifier],
            online_ready=False, kind='codec_recipe')
        maybe_emit_sampling_plan(protocol, args.session_dir, args.data_dir,
            args.identifier, args.holdout_dir)
        return
    directory = (demo.create_demo_sample(args.data_dir / 'demo_runs')
                 if args.mode == 'local-adapt-demo' else args.session_dir)
    directory = reviews._safe_path(directory)
    if not reviews._under(directory, args.data_dir):
        raise WorkerError('请选择本机数据目录内的完整采样；可用Finder复制完整原件到该目录，不修改文件内容。')
    report_dir, _ = analyze_session(directory, output_root=args.data_dir / 'private_reports')
    destination, record = adaptation.analyze_adaptation(directory, report_dir, args.data_dir)
    candidates = [item.get('identifier_hex') for item in record.get('device_candidates', [])
                  if isinstance(item, dict) and reviews._identifier(item.get('identifier_hex'))]
    protocol.emit('local_adaptation', directory=str(destination),
        session_dir=str(Path(directory).absolute()), report_text=bounded_local_text(adaptation.render_text(record)),
        candidates=candidates[:256], candidate_list_truncated=len(candidates) > 256,
        online_ready=False, kind='local_analysis')
    maybe_emit_sampling_plan(protocol, directory, args.data_dir)


def emit_sampling_plan(protocol, directory, root, identifier='', comparison=None, prepare_task=None, prior_plan=None):
    try:
        from . import sampling_gaps as gaps
    except ImportError:
        import sampling_gaps as gaps
    previous = None
    if prepare_task is not None:
        previous = read_sampling_plan(prior_plan, root)
        selected = reviews._identifier(previous.get('selected_identifier'))
        if selected is None or (identifier and identifier.lower() != selected):
            raise WorkerError('原计划没有唯一完整对象或选择已经变化；请先重新分析和核对本组标识。')
        identifier = selected
    path, record = gaps.create_plan(directory, root, selected_identifier=identifier,
        comparison_directory=comparison)
    if prepare_task is not None:
        for key in ('primary', 'comparison'):
            old, new = previous.get(key), record.get(key)
            if (old is None) != (new is None):
                raise WorkerError('补采比较来源已改变，请先生成新的缺口计划。')
            if old is None:
                continue
            if not isinstance(old, dict) or not isinstance(new, dict):
                raise WorkerError('原计划来源格式无效，请重新生成。')
            if old.get('source_paths', {}).get('session_dir') != new.get('source_paths', {}).get('session_dir'):
                raise WorkerError('补采原件目录与原计划不同，请先重新分析。')
            for name in capture_input_names():
                if old.get('source_bindings', {}).get(name) != new.get('source_bindings', {}).get(name):
                    raise WorkerError('原计划绑定的采样原件已改变，请重新分析；未准备补采。')
        context = capture.validate_target_context(record.get('target_context'))
        if context is None or reviews._identifier(record.get('selected_identifier')) is None:
            raise WorkerError('缺少完整对象或有效普通灯标签，不能自动准备；请先人工确认同组来源。')
        task = next((item for item in record['tasks'] if item['id'] == prepare_task), None)
        if (record.get('simulation') is not False or task is None
                or task.get('category') != 'recapture' or task.get('capture_allowed') is not True):
            raise WorkerError('此项不能用自动补采准备解决：合成、人工核对或软件尚未支持的项目不会解锁采样。')
        protocol.emit('sampling_preparation', session_dir=str(Path(directory).absolute()),
            plan_file=str(path), target_ip=capture.validate_ip(record['target_ip']),
            target_context=context,
            task_id=task['id'], task_title=task['title'], instructions=task['instructions'],
            capture_started=False, network_access_performed=False, online_ready=False)
        return
    protocol.emit('sampling_plan', session_dir=str(Path(directory).absolute()), plan_file=str(path),
        selected_identifier=record.get('selected_identifier') or '', comparison_dir=str(Path(comparison).absolute()) if comparison else None,
        report_text=bounded_local_text(gaps.render_text(record)),
        tasks=[dict(task, ui_text=gaps.render_task_text(record, task['id'])) for task in record['tasks']],
        simulation=record['simulation'], online_ready=False)


def run_session_workbench(args, protocol):
    """Analyze bounded local session candidates; never import or run a driver."""
    try:
        from . import session_workbench as workbench
    except ImportError:
        import session_workbench as workbench
    protocol.emit('step', title='本机会话策略工作台',
        instruction='重新读取本机原件，对照会话、认证、序号和重连候选；不联网、不上传、不生成可用驱动。')
    if args.mode == 'session-workbench-demo':
        directory, comparison = workbench.create_demo(args.data_dir)
        identifier = ''
    else:
        directory, comparison, identifier = args.session_dir, args.comparison_dir, args.identifier
    path, record = workbench.create_workbench(directory, args.data_dir,
        selected_identifier=identifier, comparison_directory=comparison)
    # Keep the native JSON line bounded. Full evidence remains in the private
    # artifact; UI task text is a fixed projection, never arbitrary TLV values.
    tasks = []
    text_budget = 180000
    for task in record['tasks'][:32]:
        value = str(workbench.render_task_text(record, task['id']))
        limit = min(20000, text_budget)
        text_budget -= min(len(value), limit)
        if len(value) > limit:
            value = value[:limit] + '\n界面任务内容达到上限；请在Finder查看完整本机档案，不能把截断视为通过。'
        tasks.append(dict(id=task['id'], title=str(task.get('title', '待验证项目'))[:500],
            category=str(task.get('category', 'software_support'))[:80],
            status=str(task.get('status', 'software_required'))[:80],
            capture_allowed=False, ui_text=value))
    report_text = bounded_local_text(workbench.render_text(record))
    if len(record['tasks']) > len(tasks):
        report_text += '\n界面任务列表达到32项上限；请在Finder查看完整本机档案，不自动忽略其余缺口。'
    holdout = record.get('holdout')
    comparison_path = (args.data_dir / holdout['source_paths']['session_dir']
                       if isinstance(holdout, dict) else None)
    protocol.emit('session_workbench', json_file=str(path), directory=str(Path(path).parent),
        session_dir=str(args.data_dir / record['primary']['source_paths']['session_dir']),
        comparison_dir=str(comparison_path) if comparison_path is not None else None,
        selected_identifier=record.get('selected_identifier') or '',
        candidates=record.get('candidate_identifiers', [])[:256],
        candidate_list_truncated=len(record.get('candidate_identifiers', [])) > 256,
        report_text=report_text, tasks=tasks, simulation=record['simulation'],
        online_ready=False, driver_generated=False)


def capture_input_names():
    return ('session.json', 'events.jsonl', 'traffic.pcap')


def read_sampling_plan(path, root):
    """Use the previous record only as a source binding, never as permission."""
    if path is None:
        raise WorkerError('缺少原缺口计划，请先重新分析。')
    path, root = reviews._safe_path(path), reviews._safe_path(root)
    if (path.name != 'plan.json' or path.parent.parent != root / 'private_sampling_plans'
            or not re.fullmatch(r'plan_[0-9a-f]{32}', path.parent.name)):
        raise WorkerError('请选择本机private_sampling_plans直属计划文件。')
    raw = reviews._read_file(path, 16 * 1024 * 1024)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_json_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('无效计划数值')))
    if not isinstance(value, dict) or value.get('artifact') != 'private_mc7021_sampling_gap_plan':
        raise WorkerError('本机计划格式不正确，请重新生成。')
    return value


def maybe_emit_sampling_plan(protocol, directory, root, identifier='', comparison=None):
    """A gap-plan failure must not erase or relabel a completed sample report."""
    try:
        emit_sampling_plan(protocol, directory, root, identifier, comparison)
    except (ValueError, OSError) as error:
        protocol.emit('log', text='原报告已保留，未生成补采计划：' + str(error))


def bounded_local_text(value):
    """Keep one worker event within the native UI's line-size budget."""
    text = str(value)
    return (text[:200000] + '\n\n界面内容达到上限；请在Finder查看本机完整档案，不能把截断部分视为通过。'
            if len(text) > 200000 else text)


def run_ha_wizard(args, protocol):
    try:
        from . import ha_wizard as wizard
    except ImportError:
        import ha_wizard as wizard
    action = args.mode.removeprefix('ha-wizard-')
    root = args.data_dir
    if action == 'create':
        expected = capture.validate_ip(args.host_ip) if args.host_ip else None
        path, state = wizard.create(args.review_file, root, expected_host=expected)
    elif action == 'demo':
        path, state = wizard.create_demo(root)
    elif action == 'load':
        result = wizard.load(args.wizard_file, root)
        protocol.emit('ha_wizard', wizard_file=str(args.wizard_file), **result)
        return
    elif action == 'starter':
        path, state = wizard.export_starter(args.wizard_file, root)
    elif action == 'adapter':
        path, state = wizard.import_adapter(args.wizard_file, args.manifest_file, args.driver_file, root)
    elif action == 'driver':
        form = load_review_form(args.form_file, root, fields=None)
        path, state = wizard.import_driver(args.wizard_file, args.driver_file, root, form)
    elif action == 'bundle':
        path, state = wizard.build_bundle(args.wizard_file, root)
    elif action == 'install':
        form = load_review_form(args.form_file, root, fields=None)
        path, state = wizard.record_installation(args.wizard_file, root, form)
    elif action == 'diagnostics':
        path, state = wizard.import_diagnostics(args.wizard_file, args.diagnostics_file, root)
    elif action == 'acceptance':
        form = load_review_form(args.form_file, root, fields=None)
        path, state = wizard.save_acceptance(args.wizard_file, root, form)
    else:
        raise WorkerError('未知HA向导操作。')
    protocol.emit('ha_wizard', wizard_file=str(path), state=state, valid=True, errors=[])


def run_review_save(args, protocol):
    form = load_review_form(args.form_file, args.data_dir)
    record_path, record = reviews.save_review(args.report_dir, args.session_dir,
        args.data_dir, decisions=form['decisions'], notes=form['notes'],
        selected_identifier=form['selected_identifier'], reviewer_label=form['reviewer_label'])
    validation = reviews.validate_review(record_path, args.data_dir)
    protocol.emit('review_saved', record_path=str(record_path), record=record,
                  validation=validation, passed=validation.get('passed') is True)


def review_summary(validation):
    """Bound list output; opening one chosen file revalidates its full record."""
    if not isinstance(validation, dict):
        raise WorkerError('本机核对记录列表格式无效，请直接选择一条记录重新检查。')
    record = validation.get('record') if isinstance(validation.get('record'), dict) else {}
    assessment = validation.get('assessment') if isinstance(validation.get('assessment'), dict) else {}
    def text(value, limit=256):
        return value[:limit] if isinstance(value, str) else None
    context = record.get('target_context')
    context = ({key: text(context.get(key)) for key in ('label', 'room', 'kind', 'collection_id')}
               if isinstance(context, dict) else None)
    valid = validation.get('valid') is True
    return dict(review_file=text(validation.get('review_file'), 4096), valid=valid,
        passed=valid and validation.get('passed') is True,
        errors=[text(item, 512) for item in validation.get('errors', [])[:4] if isinstance(item, str)]
               if isinstance(validation.get('errors'), list) else ['本机核对记录错误信息无效'],
        record=dict(review_id=text(record.get('review_id')), host_ip=text(record.get('host_ip')),
                    target_context=context, created_at=text(record.get('created_at'))),
        assessment=dict(eligible_for_manual_review=assessment.get('eligible_for_manual_review') is True,
                        confirmed_count=len(assessment.get('confirmed', [])) if isinstance(assessment.get('confirmed'), list) else 0,
                        pending_count=len(assessment.get('pending', [])) if isinstance(assessment.get('pending'), list) else 0,
                        resample_count=len(assessment.get('resample', [])) if isinstance(assessment.get('resample'), list) else 0))


def run_capture(args, protocol, backend_factory=None):
    ip, udid = capture.validate_ip(args.host_ip), capture.validate_udid(args.udid)
    context = capture.build_target_context(args.target_label, args.room_label, args.collection_id)
    baseline_validation = None
    if args.review_file is not None:
        baseline_validation = reviews.validate_review(args.review_file, args.data_dir,
                                                      expected_host=ip)
        if baseline_validation.get('valid') is not True or baseline_validation.get('passed') is not True:
            raise WorkerError('首组核对记录未通过、原件发生变化或主机不匹配；请先在“首组核对”重新检查。')
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
    if baseline_validation is not None:
        record = baseline_validation.get('record', {})
        journal.record('baseline_review_reference', review_file=str(args.review_file.resolve()),
            review_id=record.get('review_id'), human_review_passed=True,
            physical_identity_verified_by_tool=False, independent_state_verified_by_tool=False)
    if args.baseline_reviewed:
        journal.record('baseline_review_declared', owner_declaration=True,
            unlocks_additional_sampling=False, physical_identity_verified_by_tool=False,
            independent_state_verified_by_tool=False)
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
                elif args.mode in ('local-adapt', 'local-adapt-demo', 'local-recipe'):
                    run_local_adaptation(args, protocol)
                    ok = True
                elif args.mode in ('session-workbench', 'session-workbench-demo'):
                    run_session_workbench(args, protocol)
                    ok = True
                elif args.mode in ('sampling-plan', 'sampling-prepare'):
                    emit_sampling_plan(protocol, args.session_dir, args.data_dir,
                        args.identifier, args.comparison_dir,
                        args.task_id if args.mode == 'sampling-prepare' else None,
                        args.plan_file if args.mode == 'sampling-prepare' else None)
                    ok = True
                elif args.mode.startswith('ha-wizard-'):
                    run_ha_wizard(args, protocol)
                    ok = True
                elif args.mode == 'ha-handoff':
                    try:
                        from .ha_handoff import export_handoff
                    except ImportError:
                        from ha_handoff import export_handoff
                    expected = capture.validate_ip(args.host_ip) if args.host_ip else None
                    directory, manifest = export_handoff(args.review_file, args.data_dir, expected_host=expected)
                    protocol.emit('ha_handoff', directory=str(directory), manifest=manifest)
                    ok = True
                elif args.mode == 'review-save':
                    run_review_save(args, protocol)
                    ok = True
                elif args.mode == 'review-list':
                    host = capture.validate_ip(args.host_ip) if args.host_ip is not None else None
                    records = [review_summary(item) for item in
                               reviews.load_reviews(args.data_dir, expected_host=host)]
                    protocol.emit('review-list', records=records)
                    ok = True
                elif args.mode == 'review-validate':
                    host = capture.validate_ip(args.host_ip) if args.host_ip is not None else None
                    validation = reviews.validate_review(args.review_file, args.data_dir,
                                                          expected_host=host)
                    protocol.emit('review_validation', review_file=str(args.review_file), **validation)
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
