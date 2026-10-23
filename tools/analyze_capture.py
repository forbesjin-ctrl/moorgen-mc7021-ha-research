#!/usr/bin/env python3
"""Read local MC7021 captures and write private research reports. No transport.

Packet/event proximity is a candidate association, not causation. A generated
report never authorizes controls or declares physical feedback verified.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import uuid

try:
    from . import offline_shcp as codec
    from .pcap_reader import read_pcap, PcapError
    from .report_view import render_report
    from .capture_mc7021_light import validate_target_context
except ImportError:
    import offline_shcp as codec
    from pcap_reader import read_pcap, PcapError
    from report_view import render_report
    from capture_mc7021_light import validate_target_context

VERSION = '0.2.0'
MAX_METADATA = 4 * 1024 * 1024
MAX_EVENTS = 10000
MAX_FLOWS = 1024
MAX_FRAMES = 5000
ROOT = Path(__file__).resolve().parents[1]
REQUIRED_STEPS = frozenset(('初始同步', 'App开1', 'App关1', 'App开2', 'App关2', '面板开',
                            '面板关', '关闭App', 'App关闭期间面板开', '重进App读状态'))


def timestamp(value):
    value = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('事件时间缺少时区')
    return value.timestamp()


def load_small(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA:
        raise ValueError('元数据缺失、为符号链接或超过4MiB：' + path.name)
    return path.read_text(encoding='utf-8')


def read_events(path):
    rows = []
    for line in load_small(path).splitlines():
        if not line.strip():
            continue
        if len(rows) >= MAX_EVENTS:
            raise ValueError('事件数超过离线分析上限')
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError('事件必须为JSON对象')
        row['_time'] = timestamp(row.get('timestamp'))
        rows.append(row)
    if any(a['_time'] > b['_time'] for a, b in zip(rows, rows[1:])):
        raise ValueError('事件时间倒退，不能可靠关联')
    return rows


def event_windows(rows):
    result, current = [], {}
    for row in rows:
        step, kind = row.get('step'), row.get('event')
        if not isinstance(step, str):
            continue
        if kind == 'instruction':
            item = dict(step=step, ready_at=None, confirmed_at=None, window_end=None,
                        physical_light='unknown', app_display='unknown', status='incomplete',
                        frame_indices=[], packet_count=0, command_count=0, state_count=0, ack_count=0,
                        execution_response_count=0, step_finished=False, observation_recorded=False)
            result.append(item)
            current[step] = item
        item = current.get(step)
        if item is None:
            continue
        if kind == 'action_ready':
            item['ready_at'] = row['timestamp']
        elif kind == 'action_confirmed':
            start = timestamp(row.get('ready_at'))
            if row.get('user_reports_executed') is not True or start > row['_time']:
                raise ValueError('动作确认记录不一致')
            if item['ready_at'] != row.get('ready_at'):
                raise ValueError('动作准备与确认记录不一致')
            item.update(confirmed_at=row['timestamp'], window_end=row['timestamp'], status='recorded')
        elif kind == 'observation' and item['confirmed_at'] is not None:
            if row['_time'] < timestamp(item['confirmed_at']):
                raise ValueError('观察时间早于动作确认')
            for key in ('physical_light', 'app_display', 'update_observed'):
                if key in row:
                    item[key] = row[key]
            item['window_end'] = row['timestamp']
            item['observation_recorded'] = True
        elif kind == 'step_finished' and item['confirmed_at'] is not None:
            if row['_time'] < timestamp(item['window_end']):
                raise ValueError('步骤结束时间早于观察')
            if row.get('confirmed_at') != item['confirmed_at'] or row.get('ready_at') != item['ready_at']:
                raise ValueError('步骤结束与动作区间不一致')
            item['window_end'] = row['timestamp']
            item['step_finished'] = True
        elif kind in ('step_skipped', 'action_not_executed', 'action_confirmation_uncertain'):
            item['status'] = 'skipped'
    for item in result:
        if item['status'] == 'recorded' and (not item['step_finished'] or
                (item['step'] != '关闭App' and not item['observation_recorded'])):
            item['status'] = 'partial'
        item['association_note'] = '动作位于准备至确认区间；报文时间邻近不证明因果，观察等待也包含在窗口内'
    return result


def split_flows(packets, target):
    """Separate directions and TCP generations; do not mix reused connections."""
    flows, connections = {}, {}
    for packet in packets:
        endpoints = tuple(sorted(((packet['src'], packet['sport']), (packet['dst'], packet['dport']))))
        connection_key = (packet['transport'], endpoints)
        state = connections.setdefault(connection_key, {'generation': 0, 'syn': None, 'closed': False, 'seen': False})
        flags = packet.get('flags', 0)
        if packet['transport'] == 'tcp' and flags & 2 and not flags & 16:
            syn = (packet['src'], packet['sport'], packet['seq'])
            if state['seen'] and (state['syn'] != syn or state['closed']):
                state['generation'] += 1
            state.update(syn=syn, closed=False)
        key = (connection_key, state['generation'], packet['src'], packet['sport'])
        if key not in flows:
            if len(flows) >= MAX_FLOWS:
                raise ValueError('连接方向数超过离线分析上限')
            flows[key] = dict(id='flow-{}'.format(len(flows) + 1), transport=packet['transport'],
                direction='from_host' if packet['src'] == target else 'to_host',
                src=packet['src'], dst=packet['dst'], sport=packet['sport'], dport=packet['dport'],
                generation=state['generation'], packets=[], issues=[], frame_count=0,
                payload_classification='no_payload')
        flows[key]['packets'].append(packet)
        state['seen'] = True
        if packet['transport'] == 'tcp' and flags & (1 | 4):
            state['closed'] = True
    return list(flows.values())


def tcp_prefix(packets):
    """Reassemble only the first contiguous run; conflicting overlaps fail closed."""
    data_packets = [p for p in packets if p['payload']]
    if not data_packets:
        return b'', [], []
    syns = [p for p in packets if p.get('flags', 0) & 2]
    anchor = ((syns[0]['seq'] + 1) & 0xffffffff) if syns else data_packets[0]['seq']
    issues = [] if syns else ['TCP未捕获SYN：流首边界仅为候选']
    segments = []
    for packet in data_packets:
        sequence = (packet['seq'] + bool(packet.get('flags', 0) & 2)) & 0xffffffff
        offset = ((sequence - anchor + 2**31) % 2**32) - 2**31
        segments.append((offset, packet['packet_index'], packet))
    segments.sort(key=lambda item: (item[0], item[1]))
    base = segments[0][0]
    if syns and base != 0:
        return b'', [], issues + ['TCP起始数据缺失或SYN序号矛盾，未尝试恢复帧边界']
    data, spans, retransmitted = bytearray(), [], 0
    for offset, _, packet in segments:
        start = offset - base
        payload = packet['payload']
        if start > len(data):
            issues.append('TCP序号缺口：仅解码缺口前连续前缀，不拼接后续数据')
            break
        overlap = min(len(payload), len(data) - start)
        if bytes(data[start:start + overlap]) != payload[:overlap]:
            return b'', [], issues + ['TCP重叠内容冲突：整条方向流不解码']
        retransmitted += overlap
        if overlap < len(payload):
            new_start = len(data)
            data.extend(payload[overlap:])
            spans.append((new_start, len(data), packet))
    if retransmitted:
        issues.append('已去重TCP重传/重叠字节：{}'.format(retransmitted))
    return bytes(data), spans, issues


def classify_payload(raw):
    if raw.startswith(b'#'):
        return 'plaintext_candidate'
    if len(raw) >= 3 and raw[0] in (20, 21, 22, 23) and raw[1] == 3 and raw[2] <= 4:
        return 'tls_like_not_decrypted'
    return 'opaque_or_unrecognized'


def frame_semantics(packet, ordinary_ids):
    kind, command, identifiers, states, notes = 'unknown', None, [], [], []
    if packet['protocol_number'] != 1:
        return kind, command, identifiers, states, ['未知protocol_number，保留原字段']
    pair = packet['protocol_type'], packet['link_code']
    fields = packet['fields']
    if pair == (4, 9):
        kind = 'execution_request'
        subtype = codec.unique_field(fields, 16)
        device = codec.unique_field(fields, 4)
        value = codec.unique_field(fields, 9)
        if device and device['length'] == 8:
            identifiers.append(device['value_hex'])
        if (subtype and codec.field_bytes(subtype) == b'\x01' and device
                and device['length'] == 8 and value and codec.field_bytes(value) in (b'light-on', b'light-off')):
            command = codec.field_bytes(value).decode('ascii')
            kind = 'light_command_candidate'
    elif pair == (4, 10):
        kind = 'execution_response_not_state'
    elif pair == (4, 11):
        kind = 'ack_not_state'
    elif pair in ((5, 12), (3, 8)):
        kind = 'state_update_candidate' if pair == (5, 12) else 'device_details_candidate'
        states = codec.read_state_records(packet, confirmed_ordinary_light_identifiers=ordinary_ids)
        identifiers = [state['device_identifier_hex'] for state in states]
    elif pair == (3, 7):
        kind = 'data_request'
    if any(field['id'] in (93, 160) for field in fields):
        notes.append('含原厂静态分析所见会话字段；是否认证成功及真实会话条件仍未知')
    return kind, command, identifiers, states, notes


def decode_flows(flows, ordinary_ids):
    frames = []
    for flow in flows:
        packets = flow.pop('packets')
        flow['payload_bytes'] = sum(len(p['payload']) for p in packets)
        flow['packet_count'] = len(packets)
        if flow['transport'] == 'tcp':
            raw, spans, issues = tcp_prefix(packets)
            flow['issues'].extend(issues)
            streams = [(raw, spans)] if raw else []
        else:
            streams = [(p['payload'], [(0, len(p['payload']), p)]) for p in packets if p['payload']]
        classifications = set()
        for raw, spans in streams:
            classification = classify_payload(raw)
            classifications.add(classification)
            if classification != 'plaintext_candidate':
                flow['issues'].append('载荷未识别为已支持明文，不扫描偏移、不猜解密')
                continue
            cursor = 0
            while cursor < len(raw):
                if len(frames) >= MAX_FRAMES:
                    raise ValueError('完整帧数超过离线分析上限')
                try:
                    if len(raw) - cursor < 3:
                        raise codec.ParseError('流尾帧头不完整')
                    size = struct.unpack_from('<H', raw, cursor + 1)[0] + 3
                    packet = codec.parse_frame(raw[cursor:cursor + size])
                except codec.ParseError as error:
                    flow['issues'].append('偏移{}停止严格解码：{}'.format(cursor, error))
                    break
                contributors = [p for start, end, p in spans if start < cursor + size and end > cursor]
                if not contributors:
                    raise ValueError('重组帧缺少来源包证据')
                kind, command, identifiers, states, notes = 'unknown', None, [], [], []
                try:
                    kind, command, identifiers, states, notes = frame_semantics(packet, ordinary_ids)
                except codec.ParseError as error:
                    notes.append('语义未解析：' + str(error))
                frames.append(dict(index=len(frames) + 1, flow_id=flow['id'], direction=flow['direction'],
                    packet_indices=sorted({p['packet_index'] for p in contributors}),
                    timestamp_start=min(p['timestamp'] for p in contributors),
                    timestamp_end=max(p['timestamp'] for p in contributors), stream_offset=cursor,
                    kind=kind, command=command, device_identifiers=identifiers, states=states,
                    notes=notes, parsed_frame=packet, physical_feedback_verified=False))
                flow['frame_count'] += 1
                cursor += size
        flow['payload_classification'] = ', '.join(sorted(classifications)) or 'no_payload'
    return frames


def correlate(windows, packets, frames):
    for window in windows:
        if window['status'] not in ('recorded', 'partial'):
            continue
        start, end = timestamp(window['ready_at']), timestamp(window['window_end'])
        window['packet_count'] = sum(start <= p['timestamp'] <= end for p in packets)
        near = [f for f in frames if f['timestamp_start'] <= end and f['timestamp_end'] >= start]
        window['frame_indices'] = [f['index'] for f in near]
        window['command_count'] = sum(f['kind'] == 'light_command_candidate' and f['direction'] == 'to_host' for f in near)
        window['state_count'] = sum(any(s['state_present'] and s['status_context']['device_status_context_confirmed'] for s in f['states'])
                                    and f['direction'] == 'from_host' for f in near)
        window['ack_count'] = sum(f['kind'] == 'ack_not_state' for f in near)
        window['execution_response_count'] = sum(f['kind'] == 'execution_response_not_state' for f in near)
    for frame in frames:
        frame['nearby_steps'] = [w['step'] for w in windows if frame['index'] in w['frame_indices']]
        frame['event_association_ambiguous'] = len(frame['nearby_steps']) != 1


def device_candidates(frames, windows, ordinary_ids):
    result = {}
    declared = {value.hex() for value in ordinary_ids}
    for frame in frames:
        for identifier in dict.fromkeys(frame['device_identifiers']):
            item = result.setdefault(identifier, dict(identifier_hex=identifier, command_on_count=0,
                command_off_count=0, state_record_count=0, panel_state_windows=[], reopen_state_windows=[],
                ordinary_light_verified=False, ordinary_light_context='operator_declared' if identifier in declared else 'unconfirmed',
                physical_feedback_verified=False, command_event_steps=[]))
            if frame['direction'] == 'to_host' and frame['kind'] == 'light_command_candidate':
                item['command_on_count' if frame['command'] == 'light-on' else 'command_off_count'] += 1
                if not frame.get('event_association_ambiguous', True):
                    for step in frame.get('nearby_steps', []):
                        if ((step in ('App开1', 'App开2') and frame['command'] == 'light-on') or
                                (step in ('App关1', 'App关2') and frame['command'] == 'light-off')):
                            item['command_event_steps'].append(step)
            for state in frame['states']:
                if state['device_identifier_hex'] != identifier or not state['state_present'] or not state['status_context']['device_status_context_confirmed']:
                    continue
                if frame['direction'] != 'from_host':
                    continue
                item['state_record_count'] += 1
                if frame.get('event_association_ambiguous', True):
                    continue
                for window in windows:
                    if window['status'] != 'recorded' or frame['index'] not in window['frame_indices']:
                        continue
                    if window['step'] in ('面板开', '面板关') and not window['command_count']:
                        item['panel_state_windows'].append(window['step'])
                    if window['step'] == '重进App读状态':
                        item['reopen_state_windows'].append(window['step'])
    for item in result.values():
        for key in ('panel_state_windows', 'reopen_state_windows'):
            item[key] = sorted(set(item[key]))
        item['command_event_steps'] = sorted(set(item['command_event_steps']))
        item['repeated_command_candidate'] = set(item['command_event_steps']) == {'App开1', 'App开2', 'App关1', 'App关2'}
    return sorted(result.values(), key=lambda row: (-int(row['repeated_command_candidate']), -row['command_on_count'], row['identifier_hex']))


def anonymous_summary(report):
    """An explicit safe schema; never copy paths, IDs, timestamps or warnings."""
    metrics = {}
    for key in ('packet_count', 'target_packet_count', 'payload_packets', 'frame_count', 'device_count'):
        value = report.get('summary', {}).get(key)
        metrics[key] = value if type(value) is int and value >= 0 else None
    level = report.get('quality', {}).get('level')
    return dict(schema_version=VERSION, artifact='anonymous_research_summary',
        sample_kind='synthetic' if report.get('simulation') is True else 'actual_capture' if report.get('simulation') is False else 'unknown',
        quality_level=level if level in ('blocked', 'limited', 'reviewable') else 'unknown', metrics=metrics,
        host_model='MC7021_user_selected_not_verified', firmware_version=None, app_version=None,
        compatibility_verified=False, physical_feedback_verified=False, contains_raw_capture=False,
        note='只含固定字段与汇总数量；公开前仍需本人审阅，不能代替原始样本或兼容性证明')


def analyze_session(directory, output_root=None, ordinary_ids=()):
    directory = Path(directory).expanduser().resolve()
    metadata = json.loads(load_small(directory / 'session.json'))
    if not isinstance(metadata, dict):
        raise ValueError('session.json必须为对象')
    target = str(ipaddress.ip_address(metadata.get('target_ip')))
    for identifier in ordinary_ids:
        if not isinstance(identifier, bytes) or len(identifier) != 8:
            raise ValueError('普通灯标识须为显式8字节，不接受配置引用')
    checks, warnings, unknowns = [], [], []
    def check(name, status, detail):
        checks.append(dict(name=name, status=status, detail=detail))
    # Labels remain local research notes. Never use a room/name/kind declaration
    # to select an online identifier or to populate confirmed ordinary_ids.
    target_context = None
    try:
        target_context = validate_target_context(metadata.get('target_context'))
    except ValueError:
        check('业主自填标签（私有）', 'warn', '标签格式无效，未采信；保留原始会话文件供本机核对。')
        warnings.append('本轮业主自填标签格式无效，未采信。')
        unknowns.append('无效标签已忽略；本轮名称、房间、批次与实际设备的对应关系仍未知。')
    if target_context is not None:
        check('业主自填标签（私有）', 'warn',
            '本轮灯光：{}；房间：{}。仅为业主自填描述，设备身份及普通灯类型尚未核验；'
            '名称、房间和批次不是通信地址。'.format(target_context['label'], target_context['room'] or '未填写'))
        unknowns.append('本轮私有灯光标签仅为业主声明；与通信标识、实际灯路及设备类型的对应关系尚未核验。')
    simulation = metadata.get('simulation') if type(metadata.get('simulation')) is bool else None
    check('样本来源', 'warn' if simulation is not False else 'pass',
          '合成/演练，不能用于住户验证' if simulation else '来源为真实采样声明，尚未经住宅身份核验' if simulation is False else '缺少来源标志')
    source_status = metadata.get('status', 'unknown')
    check('采样完成情况', 'pass' if source_status == 'completed' else 'warn', str(source_status))
    if metadata.get('skipped_steps'):
        warnings.append('采样包含跳过步骤，不能据此声称覆盖完整单灯闭环')
    try:
        events = read_events(directory / 'events.jsonl')
        if any(row.get('simulation') is not simulation for row in events):
            raise ValueError('事件与会话的模拟标志不一致或缺失')
        windows = event_windows(events)
        complete = bool(windows) and all(w['status'] == 'recorded' for w in windows)
        check('事件记录', 'pass' if complete else 'warn', '{}个操作步骤；完整{}个'.format(
            len(windows), sum(w['status'] == 'recorded' for w in windows)))
        missing = REQUIRED_STEPS - {w['step'] for w in windows if w['status'] == 'recorded'}
        check('单灯步骤覆盖', 'warn' if missing else 'pass', '缺少：' + '、'.join(sorted(missing)) if missing else '核心10步均有完整记录')
    except (OSError, ValueError) as error:
        windows = []
        check('事件记录', 'fail', str(error))
    pcap_path = directory / 'traffic.pcap'
    capture = dict(format='unavailable', linktype=None, packet_count=None, target_packet_count=None,
                   truncated_packet_count=0, issues=[], packets=[])
    input_integrity = {}
    if pcap_path.is_symlink():
        check('PCAP原件', 'fail', '不接受指向其它文件的符号链接')
    elif not pcap_path.is_file():
        check('PCAP原件', 'fail', '没有traffic.pcap；普通提示演练本来不生成报文')
    elif pcap_path.stat().st_size > 128 * 1024 * 1024:
        check('PCAP原件', 'fail', '超过128MiB上限；保留原件，另行离线处理')
    else:
        digest = hashlib.sha256()
        with pcap_path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        input_integrity = dict(size_bytes=pcap_path.stat().st_size, sha256=digest.hexdigest())
        expected = metadata.get('pcap')
        if isinstance(expected, dict):
            match = expected.get('size_bytes') == input_integrity['size_bytes'] and expected.get('sha256') == input_integrity['sha256']
            check('PCAP大小与哈希', 'pass' if match else 'fail', '与采样摘要一致' if match else '与采样摘要不一致，不能视为同一原件')
        else:
            check('PCAP大小与哈希', 'warn', '未提供采样时哈希，只记录本次读取值')
        try:
            capture = read_pcap(pcap_path, target)
            check('PCAP读取', 'pass', '{}包，目标主机相关{}包'.format(capture['packet_count'], capture['target_packet_count']))
        except (PcapError, OSError, ValueError) as error:
            check('PCAP读取', 'fail', str(error))
    warnings.extend(capture['issues'])
    check('目标主机通信', 'pass' if capture['target_packet_count'] else 'fail',
          '未知：PCAP未成功读取' if capture['target_packet_count'] is None else str(capture['target_packet_count']) + '包')
    if capture['truncated_packet_count']:
        check('截断包', 'warn', str(capture['truncated_packet_count']) + '包被跳过')
    stopped = metadata.get('capture_stop')
    stats = stopped.get('stats') if isinstance(stopped, dict) else None
    stats = stats if isinstance(stats, dict) else {}
    dropped = stats.get('dropped_by_kernel')
    check('内核丢包', 'pass' if dropped == 0 else 'warn', '未报告丢包' if dropped == 0 else '未知或存在丢包：' + str(dropped))
    packets = capture['packets']
    try:
        flows = split_flows(packets, target)
        frames = decode_flows(flows, ordinary_ids)
    except ValueError as error:
        flows, frames = [], []
        check('重组和解析', 'fail', str(error))
    correlate(windows, packets, frames)
    if packets and windows:
        check('操作与报文时间对齐', 'pass' if any(w['packet_count'] for w in windows) else 'warn',
              '只作区间关联，不证明因果' if any(w['packet_count'] for w in windows) else '没有包落在操作窗口内，可能不是同一轮样本')
    check('完整明文候选', 'pass' if frames else 'warn', '{}帧；未解析不代表没有通信'.format(len(frames)))
    candidates = device_candidates(frames, windows, ordinary_ids)
    for flow in flows:
        warnings.extend(flow['id'] + '：' + issue for issue in flow['issues'])
    if not frames:
        unknowns.append('没有完整、受支持的明文帧；不能据此判定主机协议或兼容性')
    if any('opaque' in f['payload_classification'] or 'tls_like' in f['payload_classification'] for f in flows):
        unknowns.append('存在不透明或类似TLS的载荷：本工具不解密、不安装证书、不猜测认证')
    unknowns.extend(['目标完整标识与实际灯路的对应关系仍需人工复核，配置偏移不是通信地址',
        '认证、会话过期、加密分支及可重复控制条件尚未验证',
        '面板窗口里的状态报文可能伴随轮询；时间邻近和ACK都不能证明真实物理反馈'])
    repeated = [c for c in candidates if c['repeated_command_candidate']]
    next_actions = []
    if not packets:
        next_actions.append('先核对原件、已知IP及是否本地控制；不扫描或改配置，保留失败记录')
    elif not frames:
        next_actions.append('私下提供原始PCAP与日志，离线核对封装/会话；不要先重放任何字节')
    elif len(repeated) != 1:
        next_actions.append('人工核对重复开关对应的完整标识；不能自动选择第一个设备')
    else:
        next_actions.append('逐包复核唯一重复开关候选与同一实际灯路，确认设备类型及会话条件')
    next_actions.extend(['逐步对照面板操作、肉眼亮灭、App显示和重进App回读；排除手动刷新与周期查询',
        '证据确认后才开发单灯HA适配：独立状态、掉线不可用、重连回读；需要另行安排实机验证'])
    level = 'blocked' if any(c['status'] == 'fail' for c in checks) else 'limited' if warnings or any(c['status'] == 'warn' for c in checks) else 'reviewable'
    gates = [dict(name='真实样本', status='pass' if simulation is False else 'pending', detail='合成数据不能验证任何住户'),
        dict(name='重复开关对象', status='candidate' if len(repeated) == 1 else 'pending', detail='仅为协议候选，实际灯路和类型待核对'),
        dict(name='面板与重连独立状态', status='candidate' if any(c['panel_state_windows'] and c['reopen_state_windows'] for c in candidates) else 'pending', detail='须人工排除轮询、缓存与其它操作'),
        dict(name='会话与安全控制条件', status='pending', detail='认证、加密及在线稳定性未验证'),
        dict(name='HA单灯适配及现场测试', status='pending', detail='尚未实现可用的在线适配器')]
    report = dict(schema_version=VERSION, analysis_id=uuid.uuid4().hex, simulation=simulation,
        target_context=target_context,
        source=dict(folder=directory.name, capture_status=source_status, target_ip=target,
                    sample_origin=metadata.get('sample_origin', 'unknown'), input_integrity=input_integrity,
                    linktype=capture['linktype'], format=capture['format']),
        quality=dict(level=level, checks=checks, warnings=sorted(set(warnings))),
        summary=dict(packet_count=capture['packet_count'], target_packet_count=capture['target_packet_count'],
                     payload_packets=sum(bool(p['payload']) for p in packets) if capture['format'] == 'pcap' else None,
                     frame_count=len(frames), device_count=len(candidates)),
        events=windows, flows=flows, frames=frames, device_candidates=candidates,
        readiness=dict(can_start_live_ha=False, physical_feedback_verified=False, gates=gates),
        unknowns=unknowns, next_actions=next_actions)
    root = Path(output_root) if output_root else ROOT / 'private_reports'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = root / ('analysis_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    artifacts = {'report.json': json.dumps(report, ensure_ascii=False, indent=2), '报告.html': render_report(report),
        '匿名摘要.json': json.dumps(anonymous_summary(report), ensure_ascii=False, indent=2),
        'HA接入待验证.json': json.dumps(dict(schema_version=VERSION, live_control_enabled=False,
            transport=None, authentication=None, wire_identifier=None, on_command=None, off_command=None,
            independent_state_decoder=None, gates=gates,
            note='这是待验证清单，不是可加载的HA配置；不自动填入配置键或推断命令'), ensure_ascii=False, indent=2)}
    for name, content in artifacts.items():
        path = destination / name
        with path.open('x', encoding='utf-8') as output:
            path.chmod(0o600)
            output.write(content + '\n')
    return destination, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session-dir', required=True, type=Path)
    parser.add_argument('--output-root', type=Path)
    parser.add_argument('--ordinary-light-id', action='append', default=[],
        help='operator-declared 16 hex digits; does not verify the physical light')
    args = parser.parse_args(argv)
    try:
        identifiers = tuple(bytes.fromhex(value) for value in args.ordinary_light_id)
        destination, report = analyze_session(args.session_dir, args.output_root, identifiers)
    except (OSError, ValueError) as error:
        parser.exit(2, '离线分析未完成：{}\n原始采样未修改。\n'.format(error))
    print('私有报告：{}\n样本级别：{}；完整明文候选帧：{}；HA实机接入仍未验证。'.format(
        destination / '报告.html', report['quality']['level'], report['summary']['frame_count']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
