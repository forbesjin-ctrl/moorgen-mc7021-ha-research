#!/usr/bin/env python3
"""Offline first-light checks and private, content-bound human review records.

No network, replay, device discovery or HA configuration is provided. Passing a
review records a local person's explicit statements for one unchanged sample;
it is neither household identity authentication nor proof of physical feedback.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid
from datetime import datetime, timezone

VERSION = '0.5.0'
CRITERIA = (
    ('sample_quality', '样本与操作记录完整性'),
    ('target_identity', '同一完整标识与实际灯路'),
    ('switch_semantics', '重复开关含义'),
    ('panel_feedback', '面板操作与独立状态'),
    ('reopen_readback', '关闭后重进App回读'),
)
CRITERION_IDS = tuple(key for key, _ in CRITERIA)
REQUIRED_STEPS = frozenset(('初始同步', 'App开1', 'App关1', 'App开2', 'App关2', '面板开',
                            '面板关', '关闭App', 'App关闭期间面板开', '重进App读状态'))
COMMAND_STEPS = frozenset(('App开1', 'App关1', 'App开2', 'App关2'))
IDENTIFIER = re.compile(r'^[0-9a-fA-F]{16}$')
MAX_JSON = 16 * 1024 * 1024
INPUT_LIMITS = {'session.json': 4 * 1024 * 1024, 'events.jsonl': 4 * 1024 * 1024,
                'traffic.pcap': 128 * 1024 * 1024}
SCOPE_NOTE = ('通过仅表示本机人工对这一组灯、这轮不变原件完成采样核对声明；'
              '不认证住宅或复核人身份，不证明机器已验证物理反馈，不授权HA控制，'
              '不能套用到其它主机、灯路、会话或住宅。')


def _rows(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _unique(values):
    return list(dict.fromkeys(values))


def _identifier(value):
    return value.lower() if isinstance(value, str) and IDENTIFIER.fullmatch(value) else None


def _positive(value):
    return type(value) is int and value > 0


def _frame_id(frame):
    value = frame.get('index')
    return value if type(value) is int and value > 0 else None


def _candidate_evidence(report):
    """Recount direction- and event-specific evidence; summaries/ACKs cannot fill it."""
    candidates = {}
    declared = {_identifier(item.get('identifier_hex')) for item in _rows(report.get('device_candidates'))}
    declared.discard(None)
    for identifier in sorted(declared):
        candidates[identifier] = dict(identifier_hex=identifier, on_frames=[], off_frames=[],
            command_event_steps=[], panel_open_frames=[], panel_close_frames=[], reopen_frames=[],
            state_raw_fields=[])
    windows = {row.get('step'): row for row in _rows(report.get('events'))
               if row.get('status') == 'recorded'}
    for frame in _rows(report.get('frames')):
        index = _frame_id(frame)
        if index is None or frame.get('event_association_ambiguous') is not False:
            continue
        steps = frame.get('nearby_steps')
        if not isinstance(steps, list) or len(steps) != 1 or steps[0] not in windows:
            continue
        step = steps[0]
        window = windows[step]
        if index not in window.get('frame_indices', []):
            continue
        if frame.get('direction') == 'to_host' and frame.get('kind') == 'light_command_candidate':
            command = frame.get('command')
            matches = ((step in ('App开1', 'App开2') and command == 'light-on') or
                       (step in ('App关1', 'App关2') and command == 'light-off'))
            if not matches:
                continue
            for value in frame.get('device_identifiers', []):
                identifier = _identifier(value)
                if identifier not in candidates:
                    continue
                item = candidates[identifier]
                item['on_frames' if command == 'light-on' else 'off_frames'].append(index)
                item['command_event_steps'].append(step)
        if (frame.get('direction') != 'from_host' or
                frame.get('kind') not in ('state_update_candidate', 'device_details_candidate')):
            continue
        for state_row in _rows(frame.get('states')):
            identifier = _identifier(state_row.get('device_identifier_hex'))
            if identifier not in candidates or state_row.get('state_present') is not True:
                continue
            context = state_row.get('status_context')
            if not isinstance(context, dict) or context.get('device_status_context_confirmed') is not True:
                continue
            raw = state_row.get('raw_state')
            fields = _rows(state_row.get('fields'))
            rawfields = [field for field in fields if field.get('id') == 11 and field.get('length') == 1]
            if type(raw) is not int or not 0 <= raw <= 255 or len(rawfields) != 1 or rawfields[0].get('value_hex') != format(raw, '02x'):
                continue
            item = candidates[identifier]
            item['state_raw_fields'].append('帧{}：TLV11={}；{}；尚未确认物理含义'.format(
                index, rawfields[0]['value_hex'], context.get('reason', '设备状态上下文')))
            # Explicitly exclude App execution requests within a panel window.
            if step in ('面板开', '面板关') and window.get('command_count') == 0:
                item['panel_open_frames' if step == '面板开' else 'panel_close_frames'].append(index)
            if step == '重进App读状态':
                item['reopen_frames'].append(index)
    for item in candidates.values():
        for key in ('on_frames', 'off_frames', 'command_event_steps', 'panel_open_frames',
                    'panel_close_frames', 'reopen_frames', 'state_raw_fields'):
            item[key] = _unique(item[key])
        item['repeated_command_candidate'] = (len(item['on_frames']) >= 2 and len(item['off_frames']) >= 2
            and set(item['command_event_steps']) == COMMAND_STEPS)
    return list(candidates.values())


def assess_report(report):
    """Return machine facts, unresolved human checks and explicit resampling gaps."""
    if not isinstance(report, dict):
        raise ValueError('报告必须是JSON对象')
    confirmed, pending, resample, blockers = [], [], [], []
    details = {key: [] for key in CRITERION_IDS}
    status = {key: 'ready' for key in CRITERION_IDS}

    def gap(criterion, message):
        status[criterion] = 'resample'
        details[criterion].append(message)
        resample.append(message)
        blockers.append(message)

    simulation = report.get('simulation') if type(report.get('simulation')) is bool else None
    source = report.get('source') if isinstance(report.get('source'), dict) else {}
    summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}
    source_files = source.get('input_files')
    complete_source_files = isinstance(source_files, dict) and set(source_files) == set(INPUT_LIMITS)
    if complete_source_files:
        complete_source_files = all(isinstance(source_files.get(name), dict)
            and type(source_files[name].get('size_bytes')) is int and source_files[name]['size_bytes'] >= 0
            and isinstance(source_files[name].get('sha256'), str)
            and re.fullmatch(r'[0-9a-f]{64}', source_files[name]['sha256'])
            for name in INPUT_LIMITS)
    if not complete_source_files:
        gap('sample_quality', '缺少分析时三份原件的完整哈希绑定；请重新分析已有原件后再复核，无须因此重新操作灯或重新采样。')
    else:
        confirmed.append('报告记录了分析时session.json、events.jsonl与traffic.pcap的大小和SHA256；保存复核时会再次核对。')
    quality = report.get('quality') if isinstance(report.get('quality'), dict) else {}
    if simulation is not False:
        text = '合成演示或来源未知，只能演练核对；需另采本户真实单灯样本，不能解除后续采集门槛。'
        gap('sample_quality', text)
    else:
        confirmed.append('报告和会话声明为真实采样；这一声明不是住宅身份认证。')
    if source.get('capture_status') != 'completed':
        gap('sample_quality', '本轮采样不是完整completed状态；保留本轮记录，补采完整首组流程并等待保存和清理完成。')
    if not _positive(summary.get('packet_count')) or not _positive(summary.get('target_packet_count')):
        gap('sample_quality', '未读到有效目标主机通信；核对原件、已知IP及原App本地控制后重采，不扫描设备。')
    else:
        confirmed.append('离线读到{}包，其中指定主机相关{}包。'.format(
            summary['packet_count'], summary['target_packet_count']))
    if quality.get('level') not in ('limited', 'reviewable'):
        gap('sample_quality', '报告质量受阻或未知；先解决报告列出的原件或解析问题，再核对首组。')
    for warning in quality.get('warnings', []) if isinstance(quality.get('warnings'), list) else []:
        if '跳过步骤' in str(warning):
            gap('sample_quality', '采样摘要记录有跳过步骤；需补齐对应动作并重新生成报告，不能用完整窗口计数覆盖这一缺口。')
    checks = _rows(quality.get('checks'))
    for check in checks:
        name, state, detail = str(check.get('name', '质量检查')), check.get('status'), str(check.get('detail', '未知'))
        if state == 'fail':
            gap('sample_quality', '{}未通过：{}；核对原件后补采，不能据此通过首组。'.format(name, detail))
        elif name in ('截断包', '内核丢包') and state != 'pass':
            gap('sample_quality', '{}存在缺失或未知：{}；需取得不截断、可核对丢包统计的完整样本。'.format(name, detail))
        elif name == 'PCAP大小与哈希' and state != 'pass':
            gap('sample_quality', '缺少采样时完整哈希或哈希不一致；保留原件并补采含完整保存摘要的一轮。')
    if not any(check.get('name') == '内核丢包' and check.get('status') == 'pass' for check in checks):
        gap('sample_quality', '未确认内核丢包为0；补采并保留停止后的抓包统计。')
    for flow in _rows(report.get('flows')):
        issues = flow.get('issues') if isinstance(flow.get('issues'), list) else []
        for issue in issues:
            if any(word in str(issue) for word in ('缺口', '冲突', '缺失', '不完整', '停止严格解码', '未捕获SYN')):
                gap('sample_quality', '{}：{}；需要完整连接与连续报文，补采前先由人工核对该解析缺口。'.format(flow.get('id', '流'), issue))
        classification = str(flow.get('payload_classification', ''))
        if 'opaque' in classification or 'tls_like' in classification:
            gap('sample_quality', '存在不透明或类似TLS载荷；私下提供本轮原件离线核对封装或会话，不能把ACK或乱码当状态，不要求重放或改配置。')
    if not _positive(summary.get('frame_count')):
        gap('sample_quality', '没有可读完整帧；先私下提供原始PCAP、事件和日志核对解析支持，再决定补采，不能假定协议。')
    else:
        confirmed.append('严格解析得到{}帧完整明文候选；解析成功不证明设备类型或物理反馈。'.format(summary['frame_count']))
    windows = _rows(report.get('events'))
    complete = {row.get('step') for row in windows if row.get('status') == 'recorded'}
    missing = sorted(REQUIRED_STEPS - complete)
    if missing:
        gap('sample_quality', '缺少、跳过或未完整记录步骤：{}；只补齐或重采这一组灯对应步骤。'.format('、'.join(missing)))
    else:
        confirmed.append('核心10个动作窗口均有完整事件记录；动作与报文仅有时间区间关联。')
    expected = {'App开1': 'on', 'App开2': 'on', 'App关1': 'off', 'App关2': 'off',
                '面板开': 'on', '面板关': 'off', 'App关闭期间面板开': 'on', '重进App读状态': 'on'}
    for step, physical in expected.items():
        matching = [row for row in windows if row.get('step') == step and row.get('status') == 'recorded']
        if matching and any(row.get('physical_light') != physical for row in matching):
            criterion = 'panel_feedback' if step.startswith('面板') else 'reopen_readback' if step in ('App关闭期间面板开', '重进App读状态') else 'switch_semantics'
            gap(criterion, '{}：肉眼亮灭记录缺失、未知或未达到提示状态；核对原因后补采这一动作与现场观察。'.format(step))
        if matching and step != 'App关闭期间面板开' and any(row.get('app_display') != physical for row in matching):
            criterion = 'panel_feedback' if step.startswith('面板') else 'reopen_readback' if step == '重进App读状态' else 'switch_semantics'
            gap(criterion, '{}：App显示缺失、未知或与现场状态不一致；保留失败记录，补采显示与实际亮灭的同步观察。'.format(step))
    evidence = _candidate_evidence(report)
    repeated = [item for item in evidence if item['repeated_command_candidate']]
    if not repeated:
        gap('target_identity', '未找到同一完整8字节标识覆盖App开两次、关两次及四个独立动作窗口；补采首组重复开关，勿自动选第一个设备。')
        gap('switch_semantics', '开关候选不足2次开和2次关，或窗口重叠/缺失；补采App开1、关1、开2、关2并如实观察亮灭。')
    else:
        confirmed.append('找到{}个覆盖四次重复App开关窗口的完整标识候选；仍须人选定并核对实际灯路。'.format(len(repeated)))
    for item in repeated:
        identifier = item['identifier_hex']
        details['target_identity'].append('{}：开候选帧{}；关候选帧{}；这些是时间窗口邻近，尚不证明因果。'.format(
            identifier, item['on_frames'], item['off_frames']))
        details['switch_semantics'].append('{}：四个动作窗口{}；须人工逐帧核对原字段、执行方向与现场亮灭。'.format(identifier, '、'.join(item['command_event_steps'])))
        details['panel_feedback'].append('{}：面板开状态候选帧{}；面板关状态候选帧{}；ACK及执行应答未计入。'.format(
            identifier, item['panel_open_frames'], item['panel_close_frames']))
        details['reopen_readback'].append('{}：重新进入App的主机独立状态/详情候选帧{}；仍需排除缓存和轮询干扰。'.format(
            identifier, item['reopen_frames']))
        details['panel_feedback'].extend(item['state_raw_fields'])
    if not any(item['panel_open_frames'] and item['panel_close_frames'] for item in repeated):
        gap('panel_feedback', '没有同一重复开关候选同时覆盖面板开、关窗口的主机独立状态字段；仅ACK/执行应答不够，补采面板开关及App显示、肉眼亮灭。')
    if not any(item['reopen_frames'] for item in repeated):
        gap('reopen_readback', '没有重复开关候选在重进App窗口的主机独立状态/详情字段；补采关闭App→面板改变灯→重新进入读状态。')
    # A single chosen candidate must satisfy all evidence, not a union of devices.
    eligible_candidates = [item['identifier_hex'] for item in repeated if item['panel_open_frames'] and item['panel_close_frames'] and item['reopen_frames']]
    if repeated and not eligible_candidates:
        blockers.append('不能把不同设备各自的开关、面板和回读证据拼成一组灯；需要同一完整标识的全套候选。')
    pending.extend([
        '人工核对采样确属同一住宅、已知MC7021、本次操作及同一普通灯路；灯名和来源均为操作者声明。',
        '人工确认所选完整标识与实际灯路和普通开关灯类型对应；配置文件偏移不是通信地址。',
        '逐帧核对开与关的原字段、方向和四次现场亮灭，区分请求、ACK、执行应答与独立状态。',
        '逐帧对照面板开关、肉眼亮灭、App显示及主机独立状态；时间邻近不能排除轮询或其它操作。',
        '人工确认关闭App期间已用面板改变灯；重进App确实读回当前状态，排除缓存、刷新和其它操作。',
    ])
    criteria = []
    for key, title in CRITERIA:
        if key == 'sample_quality':
            details[key] = list(confirmed) + details[key]
        details[key].append('需人工写明核对结论与报文帧号/现场依据，工具不会自动确认物理状态。')
        criteria.append(dict(id=key, title=title, machine_status=status[key],
                             evidence=_unique(details[key]), manual_required=True))
    return dict(schema_version=VERSION, artifact='first_light_baseline_assessment',
        simulation=simulation, confirmed=_unique(confirmed), pending=_unique(pending),
        resample=_unique(resample), criteria=criteria,
        eligible_for_manual_review=not blockers and bool(eligible_candidates), passed=False,
        blockers=_unique(blockers), candidate_identifiers=[item['identifier_hex'] for item in repeated],
        eligible_candidate_identifiers=eligible_candidates, candidate_evidence=evidence,
        physical_feedback_verified=False, can_start_live_ha=False, note=SCOPE_NOTE)


def draft_review(report):
    """An explicit five-item pending draft, never a single approval checkbox."""
    assess_report(report)
    return dict(decisions={key: 'pending' for key in CRITERION_IDS},
                notes={key: '' for key in CRITERION_IDS}, selected_identifier='', reviewer_label='')


def _safe_path(value):
    path = Path(os.path.abspath(os.path.expanduser(str(value))))
    if any(part.is_symlink() for part in (path,) + tuple(path.parents)):
        raise ValueError('不接受符号链接目录或文件：' + path.name)
    return path


def _under(path, root):
    return path != root and root in path.parents


def _read_file(path, limit):
    path = _safe_path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('文件不是普通文件或超过上限：' + path.name)
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if len(data) > limit or (info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('读取期间文件发生变化：' + path.name)
        return data
    finally:
        os.close(descriptor)


def _json_file(path, limit=MAX_JSON):
    data = json.loads(_read_file(path, limit).decode('utf-8'))
    if not isinstance(data, dict):
        raise ValueError('JSON必须为对象：' + Path(path).name)
    return data


def _snapshot(root, report_dir, session_dir):
    root, report_dir, session_dir = map(_safe_path, (root, report_dir, session_dir))
    if not root.is_dir() or not report_dir.is_dir() or not session_dir.is_dir():
        raise ValueError('数据、报告和采样目录须已存在')
    if not _under(report_dir, root) or not _under(session_dir, root):
        raise ValueError('报告和采样必须在所选本机数据目录内')
    # Drafts from demo_runs may be saved; only direct captures can pass.
    if report_dir.parent != root / 'private_reports':
        raise ValueError('只能核对数据目录内private_reports直属单轮报告')
    report_path = report_dir / 'report.json'
    # Parse exactly the bytes whose hashes are bound below. Re-reading report or
    # metadata to parse them could otherwise mix two different file versions.
    raw_files = {}
    binding = {}
    for name, limit in list(INPUT_LIMITS.items()) + [('report.json', MAX_JSON)]:
        path = report_path if name == 'report.json' else session_dir / name
        raw = _read_file(path, limit)
        raw_files[name] = raw
        binding[name] = dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    report = json.loads(raw_files['report.json'].decode('utf-8'))
    metadata = json.loads(raw_files['session.json'].decode('utf-8'))
    if not isinstance(report, dict) or not isinstance(metadata, dict):
        raise ValueError('report.json与session.json必须为JSON对象')
    source = report.get('source')
    if not isinstance(source, dict) or source.get('folder') != session_dir.name:
        raise ValueError('报告与采样文件夹不对应')
    if source.get('target_ip') != metadata.get('target_ip'):
        raise ValueError('报告与采样主机不对应')
    ipaddress.ip_address(source.get('target_ip'))
    if report.get('simulation') is not metadata.get('simulation') or source.get('capture_status') != metadata.get('status'):
        raise ValueError('报告与采样的来源或完成状态不对应')
    if report.get('target_context') != metadata.get('target_context'):
        raise ValueError('报告与采样灯路声明不对应；需要重新分析原件')
    events_raw = raw_files['events.jsonl']
    event_rows = [json.loads(line) for line in events_raw.decode('utf-8').splitlines() if line.strip()]
    if len(event_rows) > 10000:
        raise ValueError('事件数超过核对上限')
    if any(not isinstance(row, dict) or row.get('simulation') is not metadata.get('simulation') for row in event_rows):
        raise ValueError('事件与会话来源声明不一致，不能绑定这一核对记录')
    pcap = metadata.get('pcap')
    if not isinstance(pcap, dict) or any(pcap.get(key) != value for key, value in binding['traffic.pcap'].items()):
        raise ValueError('原始PCAP与采样时哈希或大小不一致')
    analysis_files = source.get('input_files')
    if analysis_files is not None and analysis_files != {name: binding[name] for name in INPUT_LIMITS}:
        raise ValueError('原件与分析时三文件哈希不同；请重新分析原件后再复核，不能把旧报告首次绑定到新原件')
    integrity = source.get('input_integrity')
    if integrity != binding['traffic.pcap']:
        raise ValueError('报告PCAP绑定与本轮原件不一致')
    return report, metadata, binding, dict(report_dir=str(report_dir.relative_to(root)),
        session_dir=str(session_dir.relative_to(root)))


def _text(value, name, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in '\n\r\t' for c in value):
        raise ValueError(name + '须为有限长度的普通文本')
    return value.strip()


def _normalize(decisions, notes, selected_identifier, reviewer_label):
    if not isinstance(decisions, dict) or set(decisions) != set(CRITERION_IDS):
        raise ValueError('人工核对必须逐项填写全部五个判断，不接受单一通过开关')
    if not isinstance(notes, dict) or set(notes) != set(CRITERION_IDS):
        raise ValueError('人工核对必须包含五项独立说明字段')
    decisions = dict(decisions)
    clean = {}
    for key in CRITERION_IDS:
        if decisions[key] not in ('pass', 'pending', 'resample'):
            raise ValueError('核对判断只接受pass、pending或resample')
        clean[key] = _text(notes[key], '核对说明', 4000)
        if decisions[key] == 'pass' and not clean[key]:
            raise ValueError('标记通过的每一项必须写明人工依据与帧号/现场记录')
    value = _text(selected_identifier, '设备标识', 16)
    if value and _identifier(value) is None:
        raise ValueError('所选完整标识须为16位十六进制，不能填配置偏移或灯名')
    return decisions, clean, value.lower(), _text(reviewer_label, '复核人标签', 100)


def _passed(report, metadata, session_dir, root, assessment, decisions, selected):
    return bool(all(decisions[key] == 'pass' for key in CRITERION_IDS)
        and assessment['eligible_for_manual_review'] and report.get('simulation') is False
        and metadata.get('simulation') is False and metadata.get('status') == 'completed'
        and not metadata.get('skipped_steps')
        and Path(session_dir).parent == Path(root) / 'captures'
        and selected in assessment['eligible_candidate_identifiers'])


def save_review(report_dir, session_dir, data_root, decisions, notes, selected_identifier, reviewer_label=''):
    """Save a private draft or five-item human declaration; return (Path, record).

    Pending/resample records are valid drafts. A save cannot manufacture a pass:
    all pass decisions with machine blockers raise ValueError, leaving no file.
    """
    root = _safe_path(data_root)
    report, metadata, binding, paths = _snapshot(root, report_dir, session_dir)
    decisions, notes, selected, reviewer = _normalize(decisions, notes, selected_identifier, reviewer_label)
    assessment = assess_report(report)
    if selected and selected not in assessment['candidate_identifiers']:
        raise ValueError('所选标识不是本轮覆盖两次开和两次关的候选')
    passed = _passed(report, metadata, session_dir, root, assessment, decisions, selected)
    if all(value == 'pass' for value in decisions.values()) and not passed:
        raise ValueError('本轮仍有机器缺口、为演示/非直属真实样本、或所选标识缺独立状态，不能全部标记通过')
    # Snapshot a second time so a changed source cannot be blessed mid-save.
    _, _, current, _ = _snapshot(root, report_dir, session_dir)
    if current != binding:
        raise ValueError('保存期间原件或报告发生变化，请重新核对')
    review_id = uuid.uuid4().hex
    record = dict(schema_version=VERSION, artifact='private_first_light_manual_review',
        review_id=review_id, created_at=datetime.now(timezone.utc).isoformat(),
        assessment_version=VERSION, source=paths, input_integrity=binding,
        host_ip=report['source']['target_ip'], target_context=report.get('target_context'),
        analysis_id=report.get('analysis_id'), simulation=report.get('simulation'),
        decisions=decisions, notes=notes, selected_identifier=selected, reviewer_label=reviewer,
        passed=passed, manual_confirmation=bool(passed),
        physical_feedback_verified=False, can_start_live_ha=False, scope_note=SCOPE_NOTE)
    folder = _safe_path(root / 'baseline_reviews')
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError('人工核对保存位置不是目录')
    folder.chmod(0o700)
    path = folder / ('review_' + review_id + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as destination:
        destination.write(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    return path, record


def validate_review(record_or_path, data_root, expected_host=None, expected_target_context=None):
    """Revalidate hashes, scope and every pass criterion; invalidation is explicit."""
    record, assessment = None, None
    try:
        root = _safe_path(data_root)
        if isinstance(record_or_path, dict):
            record = record_or_path
        else:
            record_path = _safe_path(record_or_path)
            if record_path.parent != root / 'baseline_reviews':
                raise ValueError('只能读取本机baseline_reviews直属复核记录')
            record = _json_file(record_path)
        if record.get('schema_version') != VERSION or record.get('assessment_version') != VERSION or record.get('artifact') != 'private_first_light_manual_review':
            raise ValueError('人工核对版本不匹配，需要重新核对')
        if not isinstance(record.get('source'), dict):
            raise ValueError('缺少原件目录绑定')
        paths = {}
        for key in ('report_dir', 'session_dir'):
            value = record['source'].get(key)
            if not isinstance(value, str) or Path(value).is_absolute() or '..' in Path(value).parts:
                raise ValueError('原件相对路径无效或越界')
            paths[key] = _safe_path(root / value)
            if not _under(paths[key], root):
                raise ValueError('原件路径越界')
        report, metadata, binding, normalized_paths = _snapshot(root, paths['report_dir'], paths['session_dir'])
        if normalized_paths != record['source'] or binding != record.get('input_integrity'):
            raise ValueError('原件或report.json已改变、缺失或路径不对应，旧核对失效')
        if record.get('host_ip') != report['source']['target_ip'] or record.get('target_context') != report.get('target_context') or record.get('analysis_id') != report.get('analysis_id'):
            raise ValueError('核对记录不能复用于另一主机、灯路或报告')
        if expected_host is not None and str(ipaddress.ip_address(expected_host)) != record['host_ip']:
            raise ValueError('当前主机与已核对首组主机不同，不能复用')
        if expected_target_context is not None and expected_target_context != record.get('target_context'):
            raise ValueError('当前目标与已核对灯路声明不同，不能复用')
        decisions, notes, selected, reviewer = _normalize(record.get('decisions'), record.get('notes'),
            record.get('selected_identifier'), record.get('reviewer_label', ''))
        assessment = assess_report(report)
        if selected and selected not in assessment['candidate_identifiers']:
            raise ValueError('保存的设备标识不再是本轮重复开关候选')
        passed = _passed(report, metadata, paths['session_dir'], root, assessment, decisions, selected)
        if type(record.get('passed')) is not bool or record['passed'] != passed or record.get('manual_confirmation') is not passed:
            raise ValueError('保存的通过声明与当前五项核对或样本条件不符')
        if record.get('simulation') is not report.get('simulation'):
            raise ValueError('保存的样本来源不符')
        if record.get('physical_feedback_verified') is not False or record.get('can_start_live_ha') is not False:
            raise ValueError('复核记录不得声明机器已证明物理反馈或授权HA控制')
        return dict(valid=True, passed=passed, errors=[], record=record, assessment=assessment)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        return dict(valid=False, passed=False, errors=[str(error)], record=record, assessment=assessment)


def load_review(record_path, data_root, expected_host=None, expected_target_context=None):
    return validate_review(record_path, data_root, expected_host, expected_target_context)


def load_reviews(data_root, expected_host=None, expected_target_context=None):
    """Load only bounded direct JSON records; no recursive search or symlink follow."""
    root = _safe_path(data_root)
    folder = _safe_path(root / 'baseline_reviews')
    if not folder.exists():
        return []
    if not folder.is_dir():
        raise ValueError('人工核对记录位置不是目录')
    paths = []
    with os.scandir(folder) as entries:
        for entry in entries:
            paths.append(Path(entry.path))
            if len(paths) > 256:
                raise ValueError('人工核对记录超过256个上限，请显式选择较小数据集合')
    paths.sort(key=lambda item: item.name)
    result = []
    for path in paths:
        if path.is_symlink():
            result.append(dict(valid=False, passed=False, errors=['人工核对记录为符号链接：' + path.name], record=None, assessment=None, review_file=str(path)))
        elif path.name.startswith('review_') and path.suffix == '.json':
            item = load_review(path, root, expected_host, expected_target_context)
            item['review_file'] = str(path)
            result.append(item)
    return result
