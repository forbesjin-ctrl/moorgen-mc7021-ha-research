"""Private, offline HA single-light installation and acceptance workflow.

No user adapter is imported or executed here.  Driver declarations, local
operator observations and HA log exports are evidence claims, not authenticated
identity or machine proof of a physical lamp.  The only generated online code
comes from the separately reviewed, fixed Home Assistant component templates.
"""
from __future__ import annotations

import ast
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import uuid
import zipfile
from datetime import datetime, timezone

try:
    from . import baseline_review as baseline
except ImportError:
    import baseline_review as baseline

VERSION = '0.6.0'
MAX_JSON = 16 * 1024 * 1024
MAX_DRIVER = 256 * 1024
MAX_BUNDLE = 16 * 1024 * 1024
MAX_EVENTS = 2000
SHA = re.compile(r'^[0-9a-f]{64}$')
IDENTIFIER = re.compile(r'^[0-9a-f]{16}$')
CASE_TITLES = (
    ('ha_on_1', 'HA开1', True), ('ha_off_1', 'HA关1', False),
    ('ha_on_2', 'HA开2', True), ('ha_off_2', 'HA关2', False),
    ('panel_on', '面板开', True), ('panel_off', '面板关', False),
    ('disconnect', '本适配断开后面板开灯，HA仍不可用', None),
    ('reconnect', '重连后读回当前实际状态', True),
)
CASE_IDS = tuple(key for key, _, _ in CASE_TITLES)
EVIDENCE_KEYS = ('protocol', 'session', 'commands', 'independent_state')
TEMPLATE_ROOT = Path(__file__).absolute().parent.parent / 'ha_component_templates' / 'custom_components' / 'mc7021_single_light'
# This is an allowlist, never a recursive copy of a resident's working tree.
TEMPLATE_FILES = ('__init__.py', 'manifest.json', 'config_flow.py', 'const.py',
                  'contract.py', 'bridge.py', 'light.py', 'select.py', 'button.py',
                  'diagnostics.py', 'strings.json', 'translations/en.json',
                  'translations/zh-Hans.json')
SCOPE = ('本机流程只核对不变材料和人工声明；不认证复核人、驱动作者或住宅身份，'
         '不证明机器已验证物理灯亮灭。安装包执行业主自行审阅的驱动；'
         '仅限绑定主机及一组普通灯，不能扩大成全屋或其它设备。')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _digest(raw):
    return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _raw_json(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('不接受重复JSON键：' + key)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('不接受非有限JSON值')))
    except RecursionError as error:
        raise ValueError('JSON嵌套超过解析上限') from error
    if not isinstance(value, dict):
        raise ValueError('JSON须为对象')
    return value


def _text(value, label, limit=4000, required=False):
    clean = baseline._text(value, label, limit)
    if required and not clean:
        raise ValueError(label + '须填写依据')
    return clean


def _folder(path):
    path = baseline._safe_path(path)
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise ValueError('私有保存位置不是目录')
    path.chmod(0o700)
    return path


def _write(path, raw, replace=False):
    path = baseline._safe_path(path)
    if len(raw) > MAX_BUNDLE:
        raise ValueError('私有文件超过大小上限')
    if not replace:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    _write(temporary, raw)
    # Existing state must remain a direct regular, non-symlink file.
    if path.exists():
        baseline._read_file(path, MAX_JSON)
    os.replace(temporary, path)
    path.chmod(0o600)


def _location(wizard_file, root):
    root, path = baseline._safe_path(root), baseline._safe_path(wizard_file)
    if (not root.is_dir() or path.name != 'state.json' or
            path.parent.parent != root / 'private_ha_wizards' or
            not re.fullmatch(r'wizard_[0-9a-f]{32}', path.parent.name)):
        raise ValueError('请选择本机private_ha_wizards直属向导文件夹内的state.json')
    return root, path


def _asset_path(state, key, path):
    ref = state.get(key)
    if not isinstance(ref, dict) or not isinstance(ref.get('file'), str) or Path(ref['file']).name != ref['file']:
        raise ValueError('缺少或无效的私有材料索引：' + key)
    candidate = baseline._safe_path(path.parent / ref['file'])
    raw = baseline._read_file(candidate, MAX_BUNDLE if key == 'bundle' else MAX_JSON)
    if _digest(raw) != {name: ref.get(name) for name in ('size_bytes', 'sha256')}:
        raise ValueError('私有材料已改变：' + key)
    return candidate, raw


def _real_review(state, root):
    ref = state.get('baseline_review')
    if not isinstance(ref, dict) or not isinstance(ref.get('file'), str):
        raise ValueError('缺少首组核对来源')
    value = Path(ref['file'])
    if value.is_absolute() or '..' in value.parts:
        raise ValueError('首组来源路径越界')
    path = baseline._safe_path(root / value)
    raw = baseline._read_file(path, MAX_JSON)
    if _digest(raw) != {name: ref.get(name) for name in ('size_bytes', 'sha256')}:
        raise ValueError('首组核对记录改变，需重新启动向导')
    validation = baseline.validate_review(path, root, expected_host=state.get('host_ip'))
    record = validation.get('record')
    if (validation.get('valid') is not True or validation.get('passed') is not True or
            not isinstance(record, dict) or record.get('simulation') is not False or
            record.get('selected_identifier') != state.get('selected_identifier') or
            record.get('input_integrity') != state.get('baseline_input_integrity') or
            record.get('target_context') != state.get('target_context')):
        raise ValueError('首组核对未通过、原件改变或主机/灯路不对应；下游步骤失效')
    return path, record


def _manifest(manifest, driver_raw, state):
    if (manifest.get('artifact') != 'private_mc7021_driver_manifest' or
            manifest.get('schema_version') != VERSION or type(manifest.get('driver_api')) is not int or
            manifest['driver_api'] != 1 or manifest.get('simulation') is not False):
        raise ValueError('驱动声明版本/API或真实来源声明不符；演示不可作为真实驱动')
    expected = dict(host_ip=state['host_ip'], selected_identifier=state['selected_identifier'],
        baseline_review_sha256=state['baseline_review']['sha256'],
        baseline_input_integrity=state['baseline_input_integrity'],
        driver_sha256=hashlib.sha256(driver_raw).hexdigest())
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError('驱动未绑定本机不变首组原件、主机、完整标识和当前代码SHA256')
    evidence = manifest.get('evidence')
    if not isinstance(evidence, dict) or set(evidence) != set(EVIDENCE_KEYS):
        raise ValueError('驱动声明须分别给出协议、会话、开关和独立状态证据')
    for key in EVIDENCE_KEYS:
        _text(evidence[key], key + '证据', required=True)
    try:
        tree = ast.parse(driver_raw.decode('utf-8'), filename='driver.py')
        compile(tree, 'driver.py', 'exec')  # Syntax validation only; never exec.
    except (SyntaxError, UnicodeError) as error:
        raise ValueError('驱动不是可解析UTF-8 Python源码：' + str(error)) from error
    api = [node for node in tree.body if isinstance(node, ast.Assign) and
           any(isinstance(target, ast.Name) and target.id == 'DRIVER_API_VERSION' for target in node.targets)]
    if len(api) != 1 or not isinstance(api[0].value, ast.Constant) or type(api[0].value.value) is not int or api[0].value.value != 1:
        raise ValueError('驱动源码须直接声明DRIVER_API_VERSION = 1')
    if any(isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'DRIVER_IS_PLACEHOLDER' for target in node.targets)
           and isinstance(node.value, ast.Constant) and node.value.value is True for node in tree.body):
        raise ValueError('驱动仍声明DRIVER_IS_PLACEHOLDER，不能作为真实驱动')
    drivers = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Driver']
    if len(drivers) != 1:
        raise ValueError('驱动源码须定义唯一Driver类')
    methods = {node.name: node for node in drivers[0].body if isinstance(node, ast.AsyncFunctionDef)}
    if not {'async_connect', 'async_set_power', 'async_request_state', 'async_disconnect'} <= set(methods):
        raise ValueError('Driver缺少规定的四个异步接口')
    connect = methods['async_connect'].args
    if ([arg.arg for arg in connect.args] != ['self'] or connect.posonlyargs or
            not {'host', 'identifier', 'on_state', 'on_disconnect'} <= {arg.arg for arg in connect.kwonlyargs}):
        raise ValueError('async_connect须接受host、identifier、on_state、on_disconnect关键字参数')
    if [arg.arg for arg in methods['async_set_power'].args.args] != ['self', 'power']:
        raise ValueError('async_set_power须接受(self, power)')
    for name in ('async_request_state', 'async_disconnect'):
        if [arg.arg for arg in methods[name].args.args] != ['self'] or methods[name].args.posonlyargs:
            raise ValueError(name + '须接受(self)')
    for name in ('async_connect', 'async_set_power', 'async_request_state', 'async_disconnect'):
        body = [node for node in methods[name].body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))]
        if not body or all(isinstance(node, ast.Pass) or (isinstance(node, ast.Raise) and
                isinstance(node.exc, (ast.Name, ast.Call)) and
                ((isinstance(node.exc, ast.Name) and node.exc.id == 'NotImplementedError') or
                 (isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'NotImplementedError')))
                for node in body):
            raise ValueError('驱动{}仍是未实现模板；不能生成在线安装包'.format(name))
    # Parsing is intentionally not exec/import. A matching API is not a safety,
    # authorship or protocol correctness certification.
    return manifest


def _diagnostics(value, state):
    if (value.get('schema_version') != VERSION or value.get('artifact') != 'mc7021_ha_acceptance_diagnostics' or
            value.get('simulation') is not False):
        raise ValueError('请选择真实HA单灯组件的0.6.0诊断导出；演示日志不能验收')
    expected = dict(wizard_id=state['wizard_id'], package_id=state['package_id'],
        host_ip=state['host_ip'], selected_identifier=state['selected_identifier'],
        driver_sha256=state['driver']['sha256'], baseline_review_sha256=state['baseline_review']['sha256'])
    if any(value.get(key) != item for key, item in expected.items()):
        raise ValueError('HA诊断与当前向导、安装包、驱动或单灯首组不对应')
    _text(value.get('session_id'), 'HA验收会话', 128, required=True)
    if type(value.get('dropped_events')) is not int or value['dropped_events'] != 0:
        raise ValueError('HA日志发生截断/淘汰或缺少完整性统计；重置验收日志后重测整轮')
    rows = value.get('events')
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_EVENTS:
        raise ValueError('HA诊断须有1至2000个事件')
    last_id, last_time, current_window, window_id, last_generation = 0, None, None, None, 0
    kinds = {'command_requested', 'connected', 'disconnected', 'unavailable', 'reconnect', 'window_started', 'state', 'session_started'}
    sources = {'command_requested', 'independent_readback', 'independent_push', 'disconnected', 'stale',
               'connected', 'reconnect', 'window_started', 'manual_marker', 'local_marker'}
    for event in rows:
        if not isinstance(event, dict):
            raise ValueError('HA事件须为对象')
        event_id, generation = event.get('event_id'), event.get('generation')
        if (type(event_id) is not int or event_id != last_id + 1 or type(generation) is not int or
                generation < last_generation or generation < 0 or
                (generation == 0 and event.get('kind') in ('state', 'command_requested'))):
            raise ValueError('HA事件ID须从1连续完整递增，generation不可倒退且状态/命令须为正代次')
        if (event_id == 1 and (event.get('kind') != 'session_started' or event.get('step_id') is not None or event.get('window_id') is not None)) or (event_id != 1 and event.get('kind') == 'session_started'):
            raise ValueError('HA完整日志须从唯一session_started开始；不能拼接或删去部分事件')
        last_id = event_id
        last_generation = generation
        if event.get('kind') not in kinds or event.get('source') not in sources or type(event.get('independent')) is not bool:
            raise ValueError('HA事件类别、来源或独立标记不符')
        if event.get('state') is not None and type(event.get('state')) is not bool:
            raise ValueError('HA状态只能为严格布尔值或null')
        try:
            at = datetime.fromisoformat(event.get('at', '').replace('Z', '+00:00'))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError('HA事件需有限、带时区的ISO时间') from error
        if at.tzinfo is None or (last_time is not None and at < last_time):
            raise ValueError('HA事件时间缺少时区或倒序')
        last_time = at
        step = event.get('step_id')
        if step is not None and step not in CASE_IDS:
            raise ValueError('HA事件步骤未知')
        if event.get('window_case') != step:
            raise ValueError('HA事件window_case与step_id不对应')
        if event['kind'] == 'window_started':
            if step not in CASE_IDS:
                raise ValueError('开始窗口须明确选择八项单灯步骤之一')
            current_window = step
            window_id = event.get('window_id')
            if not isinstance(window_id, str) or not re.fullmatch(r'[0-9a-f]{32}', window_id):
                raise ValueError('每次开始步骤须包含独立window_id')
        elif step is not None and step != current_window:
            raise ValueError('HA事件缺少先行的当前步骤开始标记')
        if event.get('window_id') != window_id:
            raise ValueError('HA事件不属于当前显式开始的窗口')
        if type(event.get('pending_command')) is not bool:
            raise ValueError('HA事件缺少待处理命令标记')
        if event['kind'] == 'window_started' and event['pending_command'] is not False:
            raise ValueError('尚有未确认命令时不可开启新验收窗口')
        if event['kind'] == 'state' and (event.get('independent') is not True or
                event.get('source') not in ('independent_readback', 'independent_push') or type(event.get('state')) is not bool):
            raise ValueError('state事件必须是独立状态；ACK、请求与缓存不能导入为状态')
        if event['kind'] != 'state' and event.get('independent') is not False:
            raise ValueError('非状态事件不得声明独立状态')
        if event['kind'] == 'command_requested' and (event['source'] != 'command_requested' or type(event['state']) is not bool or event['pending_command'] is not True):
            raise ValueError('HA请求须含真实布尔目标及待处理标记，不得伪装独立状态')
        if event['kind'] in ('session_started', 'window_started') and event['source'] != 'local_marker':
            raise ValueError('会话和步骤须由组件本地标记明确开始')
        if event['kind'] in ('unavailable', 'disconnected') and (event['source'] not in ('disconnected', 'stale') or event['state'] is not None):
            raise ValueError('不可用日志须独立记录断线或过期，状态必须null')
    return value


def _preview(state, diagnostics):
    keys = ('event_id', 'kind', 'step_id', 'window_case', 'window_id', 'generation',
            'state', 'source', 'independent', 'pending_command', 'at')
    state['diagnostic_events'] = [{key: event.get(key) for key in keys}
                                  for event in diagnostics.get('events', [])] if diagnostics else []
    return state


def _observations(value):
    if not isinstance(value, dict) or set(value) != set(CASE_IDS):
        raise ValueError('请逐项填写八个单灯验收步骤')
    result = {}
    for key in CASE_IDS:
        row = value[key]
        if not isinstance(row, dict) or set(row) != {'decision', 'physical_light', 'ha_state', 'notes', 'event_id'}:
            raise ValueError('每步须包含判断、肉眼亮灭、HA显示、依据与具体日志事件ID')
        if row['decision'] not in ('pass', 'pending', 'resample') or row['physical_light'] not in ('on', 'off', 'unknown') or row['ha_state'] not in ('on', 'off', 'unavailable', 'unknown'):
            raise ValueError('验收判断或状态选项不符')
        if row['event_id'] is not None and (type(row['event_id']) is not int or row['event_id'] < 1):
            raise ValueError('日志事件ID须为正整数或null')
        result[key] = dict(row, notes=_text(row['notes'], '现场验收依据', required=row['decision'] == 'pass'))
        if row['decision'] == 'pass' and row['event_id'] is None:
            raise ValueError('标记通过须明确对应具体HA日志事件')
    return result


def draft_observations():
    return {key: dict(decision='pending', physical_light='unknown', ha_state='unknown', notes='', event_id=None)
            for key in CASE_IDS}


def assess(state, diagnostics=None):
    """Recompute three-way facts; never trust a saved `passed` flag."""
    confirmed, pending, resample, criteria = [], [], [], []
    simulation = state.get('simulation') is not False
    if simulation:
        pending.append('合成演练不绑定本户真实首组；不能导入真实驱动、生成在线包或正式验收。')
    else:
        confirmed.append('首组、主机和完整灯标识已通过当前本机原件哈希重新核对。')
    if state.get('driver'):
        confirmed.append('已静态核对驱动源码API、声明证据和SHA256；源码未在Mac执行，未认证作者或协议正确性。')
    else:
        pending.append('有能力的业主先按模板补齐本户驱动及协议/会话/独立状态依据；未知参数不得猜填。')
    if state.get('bundle'):
        confirmed.append('固定组件模板、私有驱动和单灯绑定已打包并核对SHA256；尚须在HA界面安装配置。')
    installation = state.get('installation')
    installed = isinstance(installation, dict) and installation.get('confirmed') is True
    if installed:
        confirmed.append('操作者声明已在HA安装且选定实体{}；这是人工安装声明。'.format(installation.get('entity_id')))
    else:
        pending.append('按安装向导放入HA自定义组件、重启并在设置中添加集成；本工具不自动修改HA。')
    observations = _observations(state.get('observations', draft_observations()))
    events = diagnostics.get('events', []) if isinstance(diagnostics, dict) else []
    by_id = {row['event_id']: row for row in events}
    marker_by_case = {}
    for index, event in enumerate(events):
        if event['kind'] == 'window_started':
            marker_by_case[event['step_id']] = (index, event['event_id'])
    previous_event, disconnect_generation, selected_ids = 0, None, set()
    for key, title, expected in CASE_TITLES:
        row = observations[key]
        gaps, facts = [], []
        event = by_id.get(row['event_id'])
        marker = marker_by_case.get(key)
        if event is None:
            gaps.append('请选择这一操作对应的具体HA日志事件；不能只勾选通过。')
        elif marker is None or event['event_id'] <= marker[1] or event.get('step_id') != key:
            gaps.append('所选事件不在本步骤最近一次显式开始窗口内。')
        elif event['event_id'] <= previous_event or event['event_id'] in selected_ids:
            gaps.append('八项选定事件须按操作顺序递增且不能重复使用。')
        else:
            before = [item for item in events if item['event_id'] < event['event_id']]
            window_events = [item for item in events[marker[0] + 1:] if item['event_id'] <= event['event_id']]
            if key == 'disconnect':
                if event['kind'] not in ('unavailable', 'disconnected') or event['state'] is not None or event['source'] not in ('disconnected', 'stale') or event['independent'] is not False:
                    gaps.append('断开步骤须实际记录HA不可用；命令或旧状态不够。')
                else:
                    disconnect_generation = event['generation']
                    facts.append('HA诊断记录本适配不可用；这不证明主机断电。')
            else:
                if event['kind'] != 'state' or event['independent'] is not True or event['source'] not in ('independent_readback', 'independent_push') or (key != 'reconnect' and event['state'] is not expected):
                    gaps.append('需要同灯路预期亮灭的独立状态；ACK、请求和本地缓存不算。')
                elif key.startswith('ha_'):
                    matching = [item for item in window_events if item['kind'] == 'command_requested' and item['generation'] == event['generation'] and item['state'] is expected]
                    if not matching:
                        gaps.append('所选独立状态之前缺少本窗口同代次、同亮灭HA请求。')
                elif key.startswith('panel_'):
                    if any(item['kind'] == 'command_requested' for item in window_events):
                        gaps.append('面板窗口出现HA控制请求，不能据此证明面板独立反馈。')
                    prior_states = [item for item in before if item['kind'] == 'state' and item['generation'] == event['generation']]
                    if not prior_states or prior_states[-1]['state'] is expected:
                        gaps.append('面板变化前须有同代次相反状态；不能把迟到或重复状态当变化。')
                    started = events[marker[0]]
                    if started['state'] is expected or type(started['state']) is not bool:
                        gaps.append('面板开始窗口须已有相反的独立状态，不能从未知状态直接判为面板变化。')
                    outstanding = None
                    for item in before:
                        if item['generation'] != event['generation']:
                            continue
                        if item['kind'] == 'command_requested':
                            outstanding = item['state']
                        elif item['kind'] == 'state' and item['state'] is outstanding:
                            outstanding = None
                    if outstanding is not None:
                        gaps.append('面板操作之前仍有未获得独立状态的HA请求，需排除迟到响应后重测。')
                elif key == 'reconnect':
                    if (disconnect_generation is None or event['generation'] <= disconnect_generation or
                            event['source'] != 'independent_readback'):
                        gaps.append('重连须在不可用之后，以新代次独立读回当前亮灯状态；旧回调或推送不够。')
                    if not any(item['kind'] == 'connected' and item['generation'] == event['generation']
                               for item in window_events):
                        gaps.append('新代次读回之前须有本重连窗口实际连接成功的日志。')
            previous_event = event['event_id']
            selected_ids.add(event['event_id'])
            facts.append('选定日志事件#{}，代次{}，来源{}。'.format(event['event_id'], event['generation'], event['source']))
        physical = 'on' if expected is True else 'off'
        ha = 'unavailable' if key == 'disconnect' else physical
        if key == 'disconnect':
            if row['physical_light'] not in ('on', 'off') or row['ha_state'] != 'unavailable':
                gaps.append('断开期间须记录肉眼实际on/off与HA不可用；断开适配不表示灯熄灭。')
        elif key == 'reconnect':
            wanted = 'on' if event is not None and event.get('state') is True else 'off'
            if row['physical_light'] not in ('on', 'off') or row['ha_state'] != row['physical_light'] or row['physical_light'] != wanted:
                gaps.append('重连时须独立读回与肉眼亮灭及HA显示一致的当前状态。')
        elif row['physical_light'] != physical or row['ha_state'] != ha:
            gaps.append('须现场记录肉眼{}和HA{}。'.format(physical, ha))
        if row['decision'] == 'resample':
            gaps.append('操作者标记本步骤需重测；保留失败记录并重新执行这一轮。')
        passed = not gaps and row['decision'] == 'pass' and bool(row['notes']) and not simulation and installed
        criteria.append(dict(id=key, title=title, status='confirmed' if passed else 'resample' if row['decision'] != 'pending' and gaps else 'pending',
                             event_id=row['event_id'], evidence=facts, gaps=gaps, observation=row))
        if passed:
            confirmed.append(title + '：日志与人工现场声明对齐。')
        elif row['decision'] != 'pending' and gaps:
            resample.extend(title + '：' + gap for gap in gaps)
        else:
            pending.append(title + '：待完成对应日志、现场观察和逐项依据。')
    passed = bool(not simulation and state.get('driver') and state.get('bundle') and installed and diagnostics and
                  all(item['status'] == 'confirmed' for item in criteria))
    stage = ('complete' if passed else 'adapter' if not state.get('driver') else
             'bundle' if not state.get('bundle') else 'installation' if not installed else 'acceptance')
    return dict(schema_version=VERSION, artifact='single_light_ha_acceptance_assessment',
        stage=stage, passed=passed, simulation=simulation, confirmed=confirmed, pending=pending,
        resample=resample, criteria=criteria, physical_feedback_verified=False,
        identity_authenticated=False, scope_note=SCOPE)


def _validated(path, root, expected_host=None):
    root, path = _location(path, root)
    raw = baseline._read_file(path, MAX_JSON)
    state = _json(raw)
    if (state.get('schema_version') != VERSION or state.get('artifact') != 'private_single_light_ha_wizard' or
            state.get('wizard_id') != path.parent.name[7:] or type(state.get('simulation')) is not bool or
            state.get('physical_feedback_verified') is not False):
        raise ValueError('HA向导格式或ID不符')
    _observations(state.get('observations'))
    if state['simulation']:
        if any(state.get(key) for key in ('driver', 'adapter_manifest', 'bundle', 'diagnostics', 'installation', 'baseline_review')):
            raise ValueError('演示不得包含真实基线、驱动、安装包、诊断或安装通过声明')
    else:
        address = ipaddress.ip_address(state.get('host_ip'))
        if address.version != 4 or address.is_loopback or address.is_multicast or address.is_unspecified or str(address) != state['host_ip'] or state['host_ip'] == '255.255.255.255':
            raise ValueError('当前HA单灯模板须绑定已知的规范单播IPv4地址')
        if not isinstance(state.get('selected_identifier'), str) or not IDENTIFIER.fullmatch(state['selected_identifier']):
            raise ValueError('缺少完整八字节灯标识')
        if expected_host is not None and str(ipaddress.ip_address(expected_host)) != state['host_ip']:
            raise ValueError('当前主机与HA向导不对应')
        _real_review(state, root)
    if state.get('driver') or state.get('adapter_manifest'):
        _, driver = _asset_path(state, 'driver', path)
        _, manifest = _asset_path(state, 'adapter_manifest', path)
        _manifest(_json(manifest), driver, state)
    if state.get('bundle'):
        _asset_path(state, 'bundle', path)
        if not state.get('driver') or not isinstance(state.get('package_id'), str) or not re.fullmatch(r'[0-9a-f]{32}', state['package_id']):
            raise ValueError('安装包缺少当前驱动或package_id')
    if state.get('starter_directory'):
        starter = baseline._safe_path(state['starter_directory'])
        if starter.parent != path.parent or not re.fullmatch(r'starter_[0-9a-f]{32}', starter.name) or not starter.is_dir():
            raise ValueError('驱动模板目录改变、越界或缺失')
    installation = state.get('installation')
    if installation is not None:
        _installation(installation)
        if not state.get('bundle'):
            raise ValueError('未生成本轮安装包，不能保存安装声明')
    diagnostics = None
    if state.get('diagnostics'):
        _, raw_diagnostics = _asset_path(state, 'diagnostics', path)
        if not state.get('bundle') or not installation or installation['confirmed'] is not True:
            raise ValueError('诊断须对应已声明安装的当前包')
        diagnostics = _diagnostics(_json(raw_diagnostics), state)
    state['assessment'] = assess(state, diagnostics)
    state['stage'] = state['assessment']['stage']
    state['baseline'] = dict(host_ip=state.get('host_ip'), target_identifier=state.get('selected_identifier'))
    if state.get('bundle'):
        state['bundle_path'] = str(path.parent / state['bundle']['file'])
        state['output_directory'] = str(path.parent)
    _preview(state, diagnostics)
    return root, path, raw, state


def load(wizard_file, data_root, expected_host=None):
    state = None
    try:
        _, path = _location(wizard_file, data_root)
        state = _json(baseline._read_file(path, MAX_JSON))
        _, _, _, state = _validated(path, data_root, expected_host)
        return dict(valid=True, errors=[], state=state, assessment=state['assessment'])
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        assessment = dict(stage='invalid', passed=False, confirmed=[], pending=[], resample=[str(error)],
                          criteria=[], physical_feedback_verified=False, identity_authenticated=False, scope_note=SCOPE)
        if isinstance(state, dict):
            state['assessment'] = assessment
        return dict(valid=False, errors=[str(error)], state=state, assessment=assessment)


def _save(path, root, old_raw, state):
    _, _, current_raw, _ = _validated(path, root)
    if current_raw != old_raw:
        raise ValueError('保存期间向导记录已改变，请重新载入')
    diagnostics = _json(_asset_path(state, 'diagnostics', path)[1]) if state.get('diagnostics') else None
    state['assessment'] = assess(state, diagnostics)
    state['stage'] = state['assessment']['stage']
    state['baseline'] = dict(host_ip=state.get('host_ip'), target_identifier=state.get('selected_identifier'))
    if state.get('bundle'):
        state['bundle_path'] = str(path.parent / state['bundle']['file'])
        state['output_directory'] = str(path.parent)
    state['updated_at'] = _now()
    _write(path, _raw_json({key: value for key, value in state.items() if key != 'diagnostic_events'}), replace=True)
    return path, _preview(state, diagnostics)


def _new(root, state):
    root = baseline._safe_path(root)
    if not root.is_dir():
        raise ValueError('请选择现有本机数据目录')
    folder = _folder(_folder(root / 'private_ha_wizards') / ('wizard_' + state['wizard_id']))
    path = folder / 'state.json'
    state['assessment'] = assess(state)
    state['stage'] = state['assessment']['stage']
    state['baseline'] = dict(host_ip=state.get('host_ip'), target_identifier=state.get('selected_identifier'))
    _write(path, _raw_json(state))
    return path, _preview(state, None)


def create(review_file, data_root, expected_host=None):
    root, review_file = baseline._safe_path(data_root), baseline._safe_path(review_file)
    validation = baseline.validate_review(review_file, root, expected_host=expected_host)
    record = validation.get('record')
    if validation.get('valid') is not True or validation.get('passed') is not True or record.get('simulation') is not False:
        raise ValueError('首组真实核对须通过且原件不变，才能开始单灯HA向导')
    raw = baseline._read_file(review_file, MAX_JSON)
    if _json(raw) != record:
        raise ValueError('首组核对记录读取期间改变')
    state = dict(schema_version=VERSION, artifact='private_single_light_ha_wizard', wizard_id=uuid.uuid4().hex,
        created_at=_now(), updated_at=_now(), simulation=False, host_ip=record['host_ip'],
        selected_identifier=record['selected_identifier'], target_context=record.get('target_context'),
        baseline_review=dict(file=str(review_file.relative_to(root)), **_digest(raw)),
        baseline_input_integrity=record['input_integrity'], driver=None, adapter_manifest=None,
        bundle=None, package_id=None, installation=None, diagnostics=None,
        observations=draft_observations(), physical_feedback_verified=False, scope_note=SCOPE)
    _real_review(state, root)
    return _new(root, state)


def create_demo(data_root):
    return _new(data_root, dict(schema_version=VERSION, artifact='private_single_light_ha_wizard',
        wizard_id=uuid.uuid4().hex, created_at=_now(), updated_at=_now(), simulation=True,
        host_ip=None, selected_identifier=None, target_context=dict(label='合成HA向导演练灯'),
        baseline_review=None, baseline_input_integrity=None, driver=None, adapter_manifest=None,
        bundle=None, package_id=None, installation=None, diagnostics=None,
        observations=draft_observations(), physical_feedback_verified=False, scope_note=SCOPE))


def export_starter(wizard_file, data_root):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    folder = _folder(path.parent / ('starter_' + uuid.uuid4().hex))
    stub = (TEMPLATE_ROOT / 'driver.py')
    source = baseline._read_file(stub, MAX_DRIVER)
    manifest = dict(schema_version=VERSION, artifact='private_mc7021_driver_manifest', driver_api=1,
        host_ip=state['host_ip'], selected_identifier=state['selected_identifier'],
        baseline_review_sha256=(state.get('baseline_review') or {}).get('sha256'),
        baseline_input_integrity=state.get('baseline_input_integrity'), driver_sha256=None,
        simulation=state['simulation'], evidence={key: '' for key in EVIDENCE_KEYS},
        note='未完成模板，不能直接导入或运行；请自行审阅和实现真实驱动，不猜参数、不重放旧样本。')
    _write(folder / 'driver.py.stub', source)
    _write(folder / 'driver_manifest.template.json', _raw_json(manifest))
    _write(folder / '开始编写.txt', ('这是尚未实现的驱动模板。Mac不会执行它。\n请逐项核对本户连接、认证、会话、开关和独立状态后实现Driver四个异步接口。\n'
        '驱动可执行任意Python，API与SHA匹配不证明代码安全或协议正确性，请自行审阅。\n不得用ACK/缓存/本地命令更新真实状态。驱动完成后回图形工具选择driver.py并填写四项证据；工具自动计算SHA并绑定当前基线。\n').encode('utf-8'))
    state['starter_directory'] = str(folder)
    return _save(path, root, old_raw, state)


def import_adapter(wizard_file, manifest_path, driver_path, data_root):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if state['simulation']:
        raise ValueError('合成向导不可导入真实驱动')
    manifest_raw = baseline._read_file(manifest_path, MAX_JSON)
    driver_raw = baseline._read_file(driver_path, MAX_DRIVER)
    _manifest(_json(manifest_raw), driver_raw, state)
    return _store_adapter(root, path, old_raw, state, manifest_raw, driver_raw)


def _store_adapter(root, path, old_raw, state, manifest_raw, driver_raw):
    token = uuid.uuid4().hex
    manifest_name, driver_name = 'adapter_' + token + '.json', 'driver_' + token + '.py'
    _write(path.parent / manifest_name, manifest_raw)
    _write(path.parent / driver_name, driver_raw)
    state.update(adapter_manifest=dict(file=manifest_name, **_digest(manifest_raw)),
        driver=dict(file=driver_name, **_digest(driver_raw)), bundle=None, package_id=None,
        installation=None, diagnostics=None, observations=draft_observations())
    return _save(path, root, old_raw, state)


def import_driver(wizard_file, driver_path, data_root, evidence):
    """Bind GUI-entered evidence and source SHA without requiring JSON editing."""
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if state['simulation']:
        raise ValueError('合成向导不可导入真实驱动')
    if not isinstance(evidence, dict) or set(evidence) != set(EVIDENCE_KEYS):
        raise ValueError('须分别填写协议、会话、开关和独立状态四项依据')
    clean = {key: _text(evidence[key], key + '证据', required=True) for key in EVIDENCE_KEYS}
    driver_raw = baseline._read_file(driver_path, MAX_DRIVER)
    manifest = dict(schema_version=VERSION, artifact='private_mc7021_driver_manifest', driver_api=1,
        host_ip=state['host_ip'], selected_identifier=state['selected_identifier'],
        baseline_review_sha256=state['baseline_review']['sha256'],
        baseline_input_integrity=state['baseline_input_integrity'],
        driver_sha256=hashlib.sha256(driver_raw).hexdigest(), simulation=False, evidence=clean)
    _manifest(manifest, driver_raw, state)
    return _store_adapter(root, path, old_raw, state, _raw_json(manifest), driver_raw)


def build_bundle(wizard_file, data_root):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if state['simulation'] or not state.get('driver'):
        raise ValueError('须先导入本户已审阅并完成证据声明的真实驱动，才能生成安装包')
    copied = {}
    for name in TEMPLATE_FILES:
        copied['custom_components/mc7021_single_light/' + name] = baseline._read_file(TEMPLATE_ROOT / name, MAX_DRIVER)
    copied['custom_components/mc7021_single_light/driver.py'] = _asset_path(state, 'driver', path)[1]
    package_id = uuid.uuid4().hex
    binding = dict(schema_version=VERSION, host_ip=state['host_ip'], target_identifier=state['selected_identifier'],
        driver_sha256=state['driver']['sha256'], baseline_review_sha256=state['baseline_review']['sha256'],
        package_id=package_id, wizard_id=state['wizard_id'], simulation=False)
    copied['custom_components/mc7021_single_light/binding.json'] = _raw_json(binding)
    copied['安装与验收.txt'] = ('只针对本户这一组普通灯；保留原主机和面板。\n'
        '1. 完整解压，将custom_components/mc7021_single_light复制到HA配置目录的custom_components中；如已有同名组件，先备份并人工审阅差异。\n'
        '2. 在HA界面重启HA；设置→设备与服务→添加集成→MC7021 单灯业主验收（MC7021 Owner-reviewed Single Light）。核对屏幕上的固定主机和完整灯标识、驱动SHA后再明确确认连接。\n'
        '3. 记录生成的light实体ID，返回Mac填写安装声明。\n'
        '4. 在HA设备页面按八步选择验收步骤并开始记录。每次观察实际灯与HA显示；断开只断本适配连接，在断开期间用面板开灯，然后重连读回。\n'
        '5. 下载HA集成诊断，私下回Mac导入，逐项选事件和写现场依据；失败保留日志，不用ACK或缓存替代状态。\n'
        '此包包含业主自行提供的可执行驱动。静态API/SHA校验不认证作者、不证明代码安全或控制正确。\n'
        'HA安装后只有明确添加集成并确认时才连接固定主机；Mac打包不连接设备、不修改HA。\n').encode('utf-8')
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in copied.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o100600 << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw)
    raw_bundle = stream.getvalue()
    name = 'MC7021-HA-single-light-' + package_id + '.zip'
    _write(path.parent / name, raw_bundle)
    state.update(package_id=package_id, bundle=dict(file=name, **_digest(raw_bundle)),
        installation=None, diagnostics=None, observations=draft_observations())
    return _save(path, root, old_raw, state)


def _installation(observations):
    if not isinstance(observations, dict) or set(observations) != {'entity_id', 'confirmed', 'notes'}:
        raise ValueError('安装声明须包含entity_id、confirmed和notes')
    if type(observations['confirmed']) is not bool:
        raise ValueError('安装确认须为严格布尔值')
    entity = _text(observations['entity_id'], 'HA实体ID', 255, required=observations['confirmed'])
    if entity and not re.fullmatch(r'light\.[a-z0-9_]+', entity):
        raise ValueError('请填写HA实际生成的light实体ID')
    return dict(entity_id=entity, confirmed=observations['confirmed'],
        notes=_text(observations['notes'], '安装依据', required=observations['confirmed']))


def record_installation(wizard_file, data_root, observations):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if state['simulation'] or not state.get('bundle'):
        raise ValueError('须先生成本轮真实单灯安装包')
    state.update(installation=_installation(observations), diagnostics=None, observations=draft_observations())
    return _save(path, root, old_raw, state)


def import_diagnostics(wizard_file, diagnostics_path, data_root):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if state['simulation'] or not state.get('bundle') or not (state.get('installation') or {}).get('confirmed'):
        raise ValueError('先完成当前安装包的HA安装声明，再导入真实验收诊断')
    raw = baseline._read_file(diagnostics_path, MAX_JSON)
    value = _json(raw)
    # HA diagnostics API may wrap its component payload under data.
    if value.get('artifact') is None and isinstance(value.get('data'), dict):
        value = value['data']
    _diagnostics(value, state)
    copied_raw = _raw_json(value)
    name = 'diagnostics_' + uuid.uuid4().hex + '.json'
    _write(path.parent / name, copied_raw)
    state.update(diagnostics=dict(file=name, **_digest(copied_raw)), observations=draft_observations())
    return _save(path, root, old_raw, state)


def save_acceptance(wizard_file, data_root, observations):
    root, path, old_raw, state = _validated(wizard_file, data_root)
    if not isinstance(observations, dict) or not set(observations) <= set(CASE_IDS) or not observations:
        raise ValueError('请提交至少一个已知验收步骤')
    merged = dict(state['observations'])
    merged.update(observations)
    normalized = _observations(merged)
    if state['simulation'] and any(row['decision'] == 'pass' for row in normalized.values()):
        raise ValueError('合成演练可保存待验证/需重测，但永不正式通过')
    state['observations'] = normalized
    return _save(path, root, old_raw, state)


def list_wizards(data_root, expected_host=None):
    root = baseline._safe_path(data_root)
    folder = baseline._safe_path(root / 'private_ha_wizards')
    if not folder.exists():
        return []
    if not folder.is_dir():
        raise ValueError('HA向导保存位置不是目录')
    paths = list(folder.iterdir())
    if len(paths) > 256:
        raise ValueError('HA向导超过256个，请明确选择文件')
    result = []
    for item in sorted(paths):
        if not re.fullmatch(r'wizard_[0-9a-f]{32}', item.name):
            continue
        value = load(item / 'state.json', root, expected_host)
        value['wizard_file'] = str(item / 'state.json')
        result.append(value)
    return result
