#!/usr/bin/env python3
"""Local, non-executable SHCP codec recipes derived from unchanged capture files.

This module has no transport, credentials, driver loading or code generation.
An offline byte match cannot establish authentication, safe online sequencing,
causation or physical state. Every result keeps online_ready explicitly false.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import io
import json
import os
from pathlib import Path
import uuid

try:
    from . import analyze_capture as analysis
    from . import baseline_review as baseline
    from . import offline_shcp as codec
    from . import pcap_reader
except ImportError:
    import analyze_capture as analysis
    import baseline_review as baseline
    import offline_shcp as codec
    import pcap_reader

VERSION = '0.7.0'
CASES = (('App开1', 'on'), ('App关1', 'off'), ('App开2', 'on'), ('App关2', 'off'),
         ('面板开', 'on'), ('面板关', 'off'), ('重进App读状态', 'on'))
UNVERIFIED = ('authentication', 'session_establishment', 'independent_state_request',
              'serial_number_policy', 'online_reconnect', 'physical_feedback')
SCOPE = ('只验证本机原件中的公开明文SHCP编码与已记录观察的一致性；'
         '时间邻近不是因果，现场记录是操作者声明，不证明物理反馈。'
         '不生成可执行驱动，不认证住宅，不授权联网或重放。')


def _hash(raw):
    return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _raw_frames(raw, target, frames):
    """Recover the exact captured application bytes, not a lossy frame summary."""
    capture = pcap_reader._read_stream(io.BytesIO(raw), target)
    flows = {row['id']: row for row in analysis.split_flows(capture['packets'], target)}
    streams = {}
    result = {}
    for frame in frames:
        flow = flows[frame['flow_id']]
        if flow['transport'] == 'tcp':
            if flow['id'] not in streams:
                streams[flow['id']] = analysis.tcp_prefix(flow['packets'])[0]
            payload = streams[flow['id']]
        else:
            contributors = [p for p in flow['packets'] if p['packet_index'] in frame['packet_indices']]
            if len(contributors) != 1:
                raise ValueError('UDP帧未绑定唯一来源包')
            payload = contributors[0]['payload']
        start = frame['stream_offset']
        raw_frame = payload[start:start + frame['parsed_frame']['full_length']]
        if codec.parse_frame(raw_frame) != frame['parsed_frame']:
            raise ValueError('帧内容与绑定PCAP不一致，不能复用修改后的报告')
        result[frame['index']] = raw_frame
    return result


def _read_source(directory, root):
    directory = baseline._safe_path(directory)
    if not directory.is_dir() or not baseline._under(directory, root):
        raise ValueError('采样文件夹须位于所选本机数据目录内')
    # Reject unsafe inputs before analyze_session can resolve any path.
    for name, limit in baseline.INPUT_LIMITS.items():
        baseline._read_file(directory / name, limit)
    reports = baseline._safe_path(root / 'private_reports')
    reports.mkdir(mode=0o700, exist_ok=True)
    report_dir, _ = analysis.analyze_session(directory, reports)
    report, metadata, binding, paths = baseline._snapshot(root, report_dir, directory)
    raw = baseline._read_file(directory / 'traffic.pcap', baseline.INPUT_LIMITS['traffic.pcap'])
    if _hash(raw) != binding['traffic.pcap']:
        raise ValueError('PCAP读取期间变化，请重新分析不变原件')
    return dict(report=report, metadata=metadata, binding=binding, paths=paths,
                raw_frames=_raw_frames(raw, report['source']['target_ip'], report['frames']))


def _select(source, selected):
    candidates = source['report']['device_candidates']
    declared = {row['identifier_hex'] for row in candidates}
    # A malformed command may intentionally have no semantic summary. Permit
    # explicit inspection of an actually captured full identifier without
    # promoting that identifier to a compatible command or an ordinary light.
    declared.update(field['value_hex'] for frame in source['report']['frames']
                    for field in frame['parsed_frame']['fields']
                    if field['id'] == 4 and field['length'] == 8)
    if selected:
        identifier = baseline._identifier(selected)
        if identifier is None:
            raise ValueError('标识必须是完整8字节、16位十六进制；不是配置偏移')
        if identifier not in declared:
            raise ValueError('所选完整标识未出现在本轮可解码设备候选中，不能猜填')
        return identifier, 'explicit_selection'
    repeated = {row['identifier_hex'] for row in candidates if row.get('repeated_command_candidate') is True}
    return (next(iter(repeated)), 'unique_repeated_candidate') if len(repeated) == 1 else (None, 'selection_required')


def _has_target(packet, identifier):
    return identifier is not None and any(f['id'] == 4 and f['value_hex'] == identifier for f in packet['fields'])


def _command_check(frame, raw, identifier):
    packet = frame['parsed_frame']
    fields = packet['fields']
    result = dict(frame_index=frame['index'], direction=frame['direction'],
                  serial_number=packet['serial_number'], captured_sha256=hashlib.sha256(raw).hexdigest(),
                  supported=False, byte_equal=False, reasons=[])
    reasons = result['reasons']
    if frame['direction'] != 'to_host':
        reasons.append('执行请求方向不是App到指定主机')
    if (packet['protocol_number'], packet['protocol_type'], packet['link_code']) != (1, 4, 9):
        reasons.append('不是已支持的明文1/4/9执行请求')
    if [f['id'] for f in fields] != [16, 4, 9]:
        reasons.append('字段必须恰好按16、4、9排列；额外、重复或不同顺序字段不吸收入模板')
    elif (fields[0]['value_hex'] != '01' or fields[0]['length'] != 1 or
          fields[1]['value_hex'] != identifier or fields[1]['length'] != 8 or
          fields[2]['value_hex'] not in (b'light-on'.hex(), b'light-off'.hex())):
        reasons.append('已知字段的长度或编码不同，不猜补参数')
    if not reasons:
        is_on = fields[2]['value_hex'] == b'light-on'.hex()
        # The encoder has a fixed public profile. Only the observed serial is
        # supplied for this local comparison; no online serial policy follows.
        generated = codec.build_candidate_light_frame(bytes.fromhex(identifier), is_on,
                                                       packet['serial_number'])
        result.update(command='light-on' if is_on else 'light-off',
                      generated_sha256=hashlib.sha256(generated).hexdigest(),
                      byte_equal=generated == raw, supported=generated == raw)
        if generated != raw:
            reasons.append('固定编码器输出与原始捕获字节不一致')
    return result


def _state_check(frame, identifier):
    """Accept one narrow public state layout; ACKs never enter this function."""
    packet = frame['parsed_frame']
    fields = packet['fields']
    result = dict(frame_index=frame['index'], direction=frame['direction'], supported=False,
                  candidate_state=None, reasons=[])
    reasons = result['reasons']
    if frame['direction'] != 'from_host':
        reasons.append('状态方向不是指定主机到App')
    pair = packet['protocol_type'], packet['link_code']
    context = (27, '03') if pair == (5, 12) else (15, '04') if pair == (3, 8) else None
    if packet['protocol_number'] != 1 or context is None:
        reasons.append('不是独立状态更新1/5/12或详情应答1/3/8；ACK及执行应答不计为状态')
    else:
        ids = [f['id'] for f in fields]
        allowed = ([context[0], 4, 11], [context[0], 4, 6, 11])
        if ids not in allowed:
            reasons.append('状态含额外、重复、多设备或不同顺序字段；当前窄配方不支持')
        elif (fields[0]['value_hex'] != context[1] or fields[0]['length'] != 1 or
              fields[1]['value_hex'] != identifier or fields[1]['length'] != 8 or
              fields[-1]['length'] != 1):
            reasons.append('状态上下文、完整标识或状态长度不符')
    if not reasons:
        try:
            rows = codec.read_state_records(packet,
                confirmed_ordinary_light_identifiers=(bytes.fromhex(identifier),))
            if len(rows) != 1 or rows[0]['candidate_is_on'] is None:
                raise codec.ParseError('缺少唯一可解释的状态字段')
            state = rows[0]
            result.update(supported=True, candidate_state='on' if state['candidate_is_on'] else 'off',
                          raw_state=state['raw_state'], upper_flags_unknown=state['upper_status_flags_unknown'],
                          context=state['status_context']['reason'])
        except codec.ParseError as error:
            reasons.append(str(error))
    return result


def _evaluate(source, identifier):
    report = source['report']
    commands, states = [], []
    by_command, by_state = {}, {}
    for frame in report['frames']:
        packet = frame['parsed_frame']
        if not _has_target(packet, identifier):
            continue
        pair = packet['protocol_type'], packet['link_code']
        if pair == (4, 9):
            row = _command_check(frame, source['raw_frames'][frame['index']], identifier)
            commands.append(row)
            by_command[frame['index']] = row
        elif pair in ((5, 12), (3, 8)):
            row = _state_check(frame, identifier)
            states.append(row)
            by_state[frame['index']] = row
    cases = []
    for step, expected in CASES:
        windows = [w for w in report['events'] if w['step'] == step]
        window = windows[0] if len(windows) == 1 else None
        reasons, command_indices, state_indices = [], [], []
        if window is None or window.get('status') != 'recorded':
            reasons.append('缺少唯一、完整且记录了现场观察的操作窗口')
        else:
            if window.get('physical_light') != expected or window.get('app_display') != expected:
                reasons.append('现场亮灭与App显示记录缺失、未知或不匹配提示状态')
            window_frames = [f for f in report['frames'] if f['index'] in window['frame_indices']]
            frames = [f for f in window_frames
                      if f.get('event_association_ambiguous') is False and f.get('nearby_steps') == [step]]
            command_indices = [f['index'] for f in frames if f['index'] in by_command
                and by_command[f['index']]['supported'] and by_command[f['index']]['command'] ==
                ('light-on' if expected == 'on' else 'light-off')]
            state_indices = [f['index'] for f in frames if f['index'] in by_state
                and by_state[f['index']]['supported'] and by_state[f['index']]['candidate_state'] == expected]
            conflicting_commands = [f['index'] for f in window_frames if f['index'] in by_command
                and by_command[f['index']]['supported'] and by_command[f['index']]['command'] !=
                ('light-on' if expected == 'on' else 'light-off')]
            conflicting_states = [f['index'] for f in window_frames if f['index'] in by_state
                and by_state[f['index']]['supported'] and by_state[f['index']]['candidate_state'] != expected]
            if conflicting_commands:
                reasons.append('同一窗口有同目标的相反开关请求帧{}；不能只选匹配帧忽略冲突'.format(conflicting_commands))
            if conflicting_states:
                reasons.append('同一窗口有同目标的相反独立状态帧{}或状态翻转；需核对原因后补采'.format(conflicting_states))
            if step in baseline.COMMAND_STEPS and not command_indices:
                reasons.append('没有同一完整标识、正确方向且字节完全匹配的开关请求')
            if not state_indices:
                reasons.append('没有同一标识的独立状态bit0与观察一致；ACK、执行应答或另一灯状态不能替代')
            if step in ('面板开', '面板关') and window.get('command_count') != 0:
                reasons.append('面板窗口同时存在App执行请求，不能作为独立面板反馈证据')
        cases.append(dict(step=step, expected=expected, status='consistent' if not reasons else 'needs_more_evidence',
                          command_frame_indices=command_indices, state_frame_indices=state_indices,
                          reasons=reasons, physical_feedback_verified=False))
    assessment = baseline.assess_report(report)
    unsupported = [r for r in commands + states if not r['supported']]
    reasons = list(assessment['resample'])
    reasons.extend(reason for row in cases + unsupported for reason in row['reasons'])
    if identifier is None:
        reasons.append('重复开关候选不是唯一完整标识；请本机逐帧核对，不自动选择第一个设备')
    consistent = (identifier is not None and bool(commands) and bool(states) and not unsupported
                  and all(row['status'] == 'consistent' for row in cases)
                  and assessment['eligible_for_manual_review'])
    return dict(simulation=report['simulation'], host=report['source']['target_ip'],
                source_paths=source['paths'], source_bindings=source['binding'],
                per_case_checks=cases, encoder_comparisons=commands, independent_states=states,
                codec_consistency=bool(consistent),
                status='simulation' if report['simulation'] is not False else
                    'offline_consistent' if consistent else 'needs_more_evidence',
                unsupported_frames=[row['frame_index'] for row in unsupported],
                needs_more_evidence=list(dict.fromkeys(reasons)), physical_feedback_verified=False)


def _verify_unchanged(source, root):
    paths = source['paths']
    _, _, current, normalized = baseline._snapshot(root, root / paths['report_dir'], root / paths['session_dir'])
    if current != source['binding'] or normalized != paths:
        raise ValueError('分析完成前原件或报告变化，未生成配方；请重新分析不变原件')


def _write_private(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        output.write(content)


def render_text(record):
    """Concise local UI summary. This summary cannot unlock another workflow."""
    labels = {'simulation': '仅合成演示', 'two_round_offline_consistent': '两轮离线一致，仍不可联网',
              'needs_more_evidence': '待验证或需补采'}
    lines = ['本机离线适配：' + labels.get(record.get('status'), '待验证'), SCOPE,
             '所选完整标识：' + (record.get('selected_identifier') or '尚未选定唯一候选'),
             '在线接入：未就绪；没有生成或执行驱动；没有发送任何数据。']
    for key, title in (('primary', '第一轮'), ('holdout', '第二轮')):
        source = record.get(key)
        if source is None:
            lines.append(title + '：尚未提供独立新采样。')
            continue
        lines.append('{}：{}；固定编码字节匹配 {}/{}。'.format(title,
            '离线一致' if source.get('codec_consistency') else '有待验证或需补采项',
            sum(row['byte_equal'] for row in source['encoder_comparisons']),
            len(source['encoder_comparisons'])))
        for row in source['per_case_checks']:
            lines.append('  {}：{}{}'.format(row['step'],
                '离线一致' if row['status'] == 'consistent' else '需补采/核对',
                '；' + '；'.join(row['reasons']) if row['reasons'] else ''))
    lines.append('下一步：')
    lines.extend('• ' + str(value) for value in record.get('next_actions', []))
    return '\n'.join(lines)


def create_recipe(session_directory, output_root, selected_identifier='', holdout_directory=None):
    """Analyze one capture and optional fresh round; return (recipe_path, record).

    Session directories must already be inside output_root. Empty selection is
    allowed only for a unique repeated candidate. A second-round PCAP must differ
    in content, not just folder names or JSON metadata. No driver is produced.
    """
    root = baseline._safe_path(output_root)
    if not root.is_dir():
        raise ValueError('请先选择已存在的本机数据目录')
    primary = _read_source(session_directory, root)
    identifier, selection_mode = _select(primary, selected_identifier)
    holdout = None
    if holdout_directory is not None:
        holdout = _read_source(holdout_directory, root)
        if primary['binding']['traffic.pcap']['sha256'] == holdout['binding']['traffic.pcap']['sha256']:
            raise ValueError('第二轮PCAP与第一轮相同；改文件夹或元数据不能作为独立第二轮')
        if primary['report']['source']['target_ip'] != holdout['report']['source']['target_ip']:
            raise ValueError('第二轮指定主机不同；不可合并不同主机或住宅的证据')
        if identifier is None:
            raise ValueError('先在第一轮核对唯一完整标识，不能用第二轮补拼目标')
        _select(holdout, identifier)
    first = _evaluate(primary, identifier)
    second = _evaluate(holdout, identifier) if holdout is not None else None
    ready = bool(first['codec_consistency'] and second and second['codec_consistency']
                 and first['simulation'] is False and second['simulation'] is False)
    simulation = first['simulation'] is not False or (second is not None and second['simulation'] is not False)
    next_actions = list(first['needs_more_evidence'])
    if second:
        next_actions.extend('第二轮：' + text for text in second['needs_more_evidence'])
    else:
        next_actions.append('另采同一已知主机、同一组灯的完整第二轮原App正常操作；保持原件不变并记录现场亮灭。')
    next_actions.extend([
        '本机人工逐帧核对完整标识与实际普通灯路、面板反馈、App重进回读；排除缓存、轮询和其它操作。',
        '认证、会话建立与过期、独立读状态请求、序号生成策略仍未验证；不得猜填、照抄会话字段或直接重放。',
        '只有获得匹配且验证过的驱动并另行完成HA单灯现场验收后，才可继续HA接入；本配方不解除任何在线门槛。'])
    record = dict(schema_version=VERSION, recipe_id=uuid.uuid4().hex,
        created_at=datetime.now(timezone.utc).isoformat(), scope=SCOPE,
        simulation=simulation, selected_identifier=identifier, selection_mode=selection_mode,
        profile='public_plain_shcp_single_light_v1' if identifier else None,
        encoder=dict(protocol_number=1, protocol_type=4, link_code=9,
                     ordered_field_ids=[16, 4, 9], subtype_hex='01',
                     command_values=['light-on', 'light-off'], serial_policy='unverified'),
        state_decoder=dict(contexts=['1/5/12 with TLV27=3', '1/3/8 with TLV15=4'],
                           identifier_bytes=8, state_field=11, state_bytes=1, on_mask=1,
                           upper_flags='unknown', physical_feedback_verified=False),
        primary=first, holdout=second, independent_second_round=second is not None,
        codec_consistency=ready, status='simulation' if simulation else
            'two_round_offline_consistent' if ready else 'needs_more_evidence',
        unverified={name: True for name in UNVERIFIED}, online_ready=False,
        driver_generated=False, executable_code=False, bytes_sent=0,
        next_actions=list(dict.fromkeys(next_actions)))
    _verify_unchanged(primary, root)
    if holdout is not None:
        _verify_unchanged(holdout, root)
    parent = baseline._safe_path(root / 'private_adapter_recipes')
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    destination = parent / ('recipe_' + record['recipe_id'])
    destination.mkdir(mode=0o700)
    raw = json.dumps(record, ensure_ascii=False, indent=2) + '\n'
    path = destination / 'recipe.json'
    _write_private(path, raw)
    title = '仅合成演示' if simulation else '两轮离线一致，仍不可联网' if ready else '待验证或需补采'
    page = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>本机离线适配核对</title>'
        '<style>body{font:16px system-ui;max-width:1000px;margin:36px auto;padding:0 20px;line-height:1.6}'
        'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f6;padding:20px}</style>'
        '<h1>本机离线适配核对：' + html.escape(title) + '</h1><p>' + html.escape(SCOPE) + '</p>'
        '<p>资料保存在本机；没有上传、扫描、联网、驱动执行或生成。已知明文配方只用于离线字节核对。</p>'
        '<h2>下一步</h2><ul>' + ''.join('<li>' + html.escape(s) + '</li>' for s in record['next_actions']) +
        '</ul><h2>逐步证据与原件绑定</h2><pre>' + html.escape(raw) + '</pre></html>\n')
    _write_private(destination / '离线适配报告.html', page)
    return path, record
